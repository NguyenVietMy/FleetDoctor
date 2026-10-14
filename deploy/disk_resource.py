#!/usr/bin/env python3
"""Root-only bounded ext4 loop resource and independent injector/watchdog.

No arbitrary path arguments: this helper operates only its private lab directory.
Preparation retains the mount for agent recovery. No host root filesystem is filled.
"""

import argparse
import fcntl
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

BASE = Path("/var/lib/fleetdoctor/chaos")
MOUNT = BASE / "disk"
RESOURCE = BASE / "resource.json"
IDENTITY = BASE / "identity.json"
LEASE = BASE / "disk-lease.json"
CAPACITY = 384 * 1024 * 1024


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True, timeout=15).strip()


def save(path: Path, value: dict[str, Any], *, mode: int = 0o600) -> None:
    temp = path.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
    os.chmod(temp, mode)
    os.replace(temp, path)


def safe_directory() -> None:
    if os.geteuid() != 0:
        raise ValueError("root required for verified loop resource helper")
    for path in (Path("/var"), Path("/var/lib"), BASE.parent, BASE, BASE / "runs"):
        if path.is_symlink():
            raise ValueError("symlink in lab directory refused")
        path.mkdir(exist_ok=True)
    if BASE.stat().st_uid != 0 or BASE.stat().st_mode & 0o022:
        raise ValueError("lab directory must be root-owned and not writable by others")
    if MOUNT.is_symlink() or RESOURCE.is_symlink() or LEASE.is_symlink():
        raise ValueError("symlink resource refused")


def mapping() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        command(
            "findmnt", "--json", "--mountpoint", str(MOUNT), "-o", "TARGET,SOURCE,FSTYPE,MAJ:MIN"
        )
    )["filesystems"][0]
    if (
        data["target"] != str(MOUNT)
        or data["fstype"] != "ext4"
        or not re.fullmatch(r"/dev/loop\d+", data["source"])
    ):
        raise ValueError("only the exact owned ext4 loop mount is allowed")
    loop = json.loads(
        command("losetup", "--json", "--list", "--output", "NAME,BACK-FILE", data["source"])
    )["loopdevices"][0]
    data["backing_file"] = str(Path(loop["back-file"]).resolve())
    # Mount ID also detects an unmount/remount onto the same device.
    data["mount_id"] = next(
        line.split()[0]
        for line in Path("/proc/self/mountinfo").read_text().splitlines()
        if line.split()[4] == str(MOUNT)
    )
    data["f_fsid"] = os.statvfs(MOUNT).f_fsid
    return data


def verify() -> dict[str, Any]:
    safe_directory()
    resource: dict[str, Any] = json.loads(RESOURCE.read_text())
    image = Path(resource["image"])
    if (
        image.parent != BASE
        or not re.fullmatch(r"disk-[a-f0-9]{32}\.img", image.name)
        or image.is_symlink()
    ):
        raise ValueError("unowned backing file refused")
    stat = image.stat()
    if stat.st_uid != 0 or stat.st_ino != resource["image_inode"] or stat.st_size != CAPACITY:
        raise ValueError("backing image ownership/size changed")
    actual = mapping()
    if actual != resource["mapping"] or actual["backing_file"] != str(image):
        raise ValueError("mount/device/backing-file identity changed")
    blocks = os.statvfs(MOUNT)
    total = blocks.f_blocks * blocks.f_frsize
    if not 256 * 1024 * 1024 <= total <= 512 * 1024 * 1024:
        raise ValueError("test filesystem capacity outside bounded range")
    resource["statvfs"] = {
        key: getattr(blocks, key) for key in ("f_blocks", "f_bfree", "f_bavail", "f_frsize")
    }
    resource["kernel"] = platform.release()
    resource["os"] = platform.platform()
    resource["utc"] = datetime.now(UTC).isoformat()
    root = os.statvfs("/")
    resource["root_available_bytes"] = root.f_bavail * root.f_frsize
    return resource


def image_devices(image: Path) -> list[str]:
    loops = json.loads(command("losetup", "--json", "--list", "--output", "NAME,BACK-FILE"))[
        "loopdevices"
    ]
    return [loop["name"] for loop in loops if str(Path(loop["back-file"]).resolve()) == str(image)]


def rollback_mount(image: Path, inode: int, devices: list[str], *, delete_image: bool) -> None:
    """Refuse rollback if identity changed; only undo this invocation's resources."""
    if image.is_symlink() or image.stat().st_ino != inode:
        raise ValueError("rollback image identity changed")
    if os.path.ismount(MOUNT):
        mounted = mapping()
        if mounted["backing_file"] != str(image) or mounted["source"] not in devices:
            raise ValueError("rollback refuses an unrelated mount")
        command("umount", str(MOUNT))
    for device in devices:
        if device in image_devices(image):
            if any(
                line.split(" - ", 1)[1].split()[1] == device
                for line in Path("/proc/self/mountinfo").read_text().splitlines()
            ):
                raise ValueError("owned loop is mounted elsewhere; refuse detach")
            command("losetup", "--detach", device)
    if delete_image and not image_devices(image):
        image.unlink()
        if RESOURCE.exists() and json.loads(RESOURCE.read_text()).get("image") == str(image):
            RESOURCE.unlink()


def prepare() -> dict[str, Any]:
    resource: dict[str, Any]
    safe_directory()
    if RESOURCE.exists():
        if os.path.ismount(MOUNT):
            resource = verify()
            save(IDENTITY, resource["mapping"], mode=0o644)
            return resource
        resource = json.loads(RESOURCE.read_text())
        image = Path(resource["image"])
        if (
            image.parent != BASE
            or not re.fullmatch(r"disk-[a-f0-9]{32}\.img", image.name)
            or image.is_symlink()
        ):
            raise ValueError("unowned retained image refused")
        st = image.stat()
        if st.st_uid != 0 or st.st_ino != resource["image_inode"] or st.st_size != CAPACITY:
            raise ValueError("retained image identity changed")
        if not MOUNT.is_dir() or any(MOUNT.iterdir()):
            raise ValueError("underlying directory must be empty before remount")
        existing = image_devices(image)
        if len(existing) > 1:
            raise ValueError("ambiguous loop image mapping")
        newly_attached: list[str] = []
        try:
            device = existing[0] if existing else command("losetup", "--find", "--show", str(image))
            if not existing:
                newly_attached.append(device)
            if any(
                line.split(" - ", 1)[1].split()[1] == device
                for line in Path("/proc/self/mountinfo").read_text().splitlines()
            ):
                raise ValueError("retained device already mounted elsewhere")
            command("mount", "-t", "ext4", device, str(MOUNT))
            resource["mapping"] = mapping()
            save(RESOURCE, resource)
            resource = verify()
            save(IDENTITY, resource["mapping"], mode=0o644)
            return resource
        except BaseException:
            # A failed mount may have succeeded before interruption; unmount our target,
            # but detach only devices newly attached in this invocation.
            created = newly_attached or [d for d in image_devices(image) if d not in existing]
            if os.path.ismount(MOUNT):
                mounted = mapping()
                if mounted["backing_file"] != str(image):
                    raise ValueError("remount rollback refuses unrelated mount") from None
                command("umount", str(MOUNT))
            rollback_mount(image, st.st_ino, created, delete_image=False)
            raise
    if os.path.ismount(MOUNT):
        raise ValueError("existing unowned mount refused")
    MOUNT.mkdir(exist_ok=True)
    if any(MOUNT.iterdir()):
        raise ValueError("nonempty mount directory refused")
    root = os.statvfs("/")
    if root.f_bavail * root.f_frsize < CAPACITY + 2 * 1024**3:
        raise ValueError("root reserve below image plus 2GiB")
    image = BASE / f"disk-{uuid4().hex}.img"
    inode: int | None = None
    devices: list[str] = []
    try:
        fd = os.open(image, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        inode = os.fstat(fd).st_ino
        try:
            os.posix_fallocate(fd, 0, CAPACITY)
        finally:
            os.close(fd)
        device = command("losetup", "--find", "--show", str(image))
        devices.append(device)
        if image_devices(image) != devices:
            raise ValueError("allocated loop identity mismatch")
        command("mkfs.ext4", "-F", "-m", "0", device)
        command("mount", "-t", "ext4", device, str(MOUNT))
        os.chmod(MOUNT, 0o755)
        resource = {
            "image": str(image),
            "image_inode": inode,
            "mapping": mapping(),
            "capacity_bytes": CAPACITY,
        }
        save(RESOURCE, resource)
        resource = verify()
        save(IDENTITY, resource["mapping"], mode=0o644)
        return resource
    except BaseException:
        if inode is not None:
            rollback_mount(image, inode, devices or image_devices(image), delete_image=True)
        raise


def run_path(token: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}", token):
        raise ValueError("invalid run token")
    return BASE / "runs" / (token + ".json")


def process_identity(pid: int) -> str:
    return Path(f"/proc/{pid}/stat").read_text().split(")", 1)[1].split()[19]


def boot_identity() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def owned_process(record: dict[str, Any], mode: str) -> bool:
    try:
        pid = record[mode + "_pid"]
        started = record[mode + "_start"]
        token = record["token"]
        if (
            type(pid) is not int
            or pid <= 0
            or not isinstance(started, str)
            or not started.isdigit()
            or not isinstance(token, str)
        ):
            return False
        command_line = [
            part for part in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if part
        ]
        return (
            process_identity(pid) == started
            and mode.encode() in command_line
            and token.encode() in command_line
        )
    except (IndexError, KeyError, OSError, ProcessLookupError, TypeError, ValueError):
        return False


def owned_pid(record: dict[str, Any]) -> bool:
    return owned_process(record, "worker")


def owned_regular(path: Path, expected_inode: object, label: str) -> int:
    if type(expected_inode) is not int or expected_inode <= 0:
        raise ValueError(label + " identity metadata invalid")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ValueError(label + " unavailable") from exc
    value = os.fstat(fd)
    if value.st_uid != 0 or value.st_ino != expected_inode or not stat.S_ISREG(value.st_mode):
        os.close(fd)
        raise ValueError(label + " ownership identity changed")
    return fd


def status(token: str) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(run_path(token).read_text())
    if record.get("token") != token:
        raise ValueError("run token identity changed")
    if record.get("cleanup_complete") is True:
        return record
    if record.get("cleanup_complete") is not False:
        raise ValueError("active run completion metadata invalid")
    resource = verify()
    if record.get("boot_id") != boot_identity():
        raise ValueError("active run boot identity changed")
    if record.get("mapping") != resource.get("mapping"):
        raise ValueError("active run mount identity changed")

    lease_fd = owned_regular(LEASE, record.get("lease_inode"), "lease")
    try:
        with os.fdopen(lease_fd, encoding="utf-8") as stream:
            lease = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("lease metadata invalid") from exc
    if not isinstance(lease, dict) or lease.get("token") != token:
        raise ValueError("lease token identity changed")

    filler = MOUNT / ("filler-" + token)
    filler_fd = owned_regular(filler, record.get("filler_inode"), "filler")
    os.close(filler_fd)
    for mode in ("worker", "watchdog"):
        if not owned_process(record, mode):
            raise ValueError(mode + " process identity is not live")
    return record


def cleanup(token: str, *, reboot: bool = False) -> dict[str, Any]:
    verify()
    path = run_path(token)
    record: dict[str, Any] = json.loads(path.read_text())
    if reboot:
        if record.get("boot_id") == boot_identity():
            raise ValueError("reboot cleanup requires a prior boot run")
        if record["mapping"]["backing_file"] != mapping()["backing_file"]:
            raise ValueError("orphan backing identity changed")
    elif record["mapping"] != mapping():
        raise ValueError("run mount identity changed; refuse deletion")
    filler = MOUNT / ("filler-" + token)
    if not reboot and owned_pid(record) and record["worker_pid"] != os.getpid():
        os.kill(record["worker_pid"], signal.SIGTERM)
        deadline = time.monotonic() + 3
        while owned_pid(record) and time.monotonic() < deadline:
            time.sleep(0.1)
        if owned_pid(record):
            os.kill(record["worker_pid"], signal.SIGKILL)
    if filler.is_symlink():
        raise ValueError("filler symlink refused")
    if filler.exists():
        if filler.stat().st_uid != 0 or filler.stat().st_ino != record.get("filler_inode"):
            raise ValueError("filler ownership changed")
        filler.unlink()
    if LEASE.exists() and json.loads(LEASE.read_text())["token"] == token:
        LEASE.unlink()
    record["cleanup_complete"] = True
    record["cleanup_utc"] = datetime.now(UTC).isoformat()
    save(path, record)
    return record


def launch(mode: str, token: str, duration: int) -> subprocess.Popen[bytes]:
    with (BASE / "runs" / (token + ".log")).open("ab") as log:
        return subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                mode,
                "--token",
                token,
                "--duration",
                str(duration),
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
            close_fds=True,
        )


def start(token: str, duration: int) -> dict[str, Any]:
    resource = verify()
    if resource["root_available_bytes"] < 2 * 1024**3:
        raise ValueError("root reserve below 2GiB; injection refused")
    path = run_path(token)
    if path.exists():
        raise ValueError("run token already exists; use explicit cleanup")
    filler = MOUNT / ("filler-" + token)
    lease_inode = filler_inode = None
    launched: list[subprocess.Popen[bytes]] = []
    try:
        fd = os.open(LEASE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        lease_inode = os.fstat(fd).st_ino
        with os.fdopen(fd, "w") as stream:
            json.dump({"token": token}, stream)
        fd = os.open(filler, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        filler_inode = os.fstat(fd).st_ino
        os.close(fd)
        record = {
            "token": token,
            "boot_id": boot_identity(),
            "mapping": resource["mapping"],
            "lease_inode": lease_inode,
            "filler_inode": filler_inode,
            "max_duration_seconds": duration,
            "started_utc": datetime.now(UTC).isoformat(),
            "cleanup_complete": False,
        }
        save(path, record)
        # Watchdog starts first and is detached from the controller and worker.
        watchdog = launch("watchdog", token, duration)
        launched.append(watchdog)
        record["watchdog_pid"] = watchdog.pid
        record["watchdog_start"] = process_identity(watchdog.pid)
        save(path, record)
        worker = launch("worker", token, duration)
        launched.append(worker)
        record["worker_pid"] = worker.pid
        record["worker_start"] = process_identity(worker.pid)
        save(path, record)
        return record
    except BaseException:
        for process in launched:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        # Roll back only files created by this invocation, even if save never succeeded.
        if mapping() == resource["mapping"]:
            if (
                filler_inode is not None
                and not filler.is_symlink()
                and filler.exists()
                and filler.stat().st_ino == filler_inode
            ):
                filler.unlink()
            if (
                lease_inode is not None
                and not LEASE.is_symlink()
                and LEASE.exists()
                and LEASE.stat().st_ino == lease_inode
            ):
                LEASE.unlink()
        raise


def worker(token: str, duration: int) -> None:
    def interrupted(signum: int, frame: object) -> None:
        raise InterruptedError("injector interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    deadline = time.monotonic() + duration
    filler = MOUNT / ("filler-" + token)
    try:
        verify()
        record = json.loads(run_path(token).read_text())
        fd = os.open(filler, os.O_RDWR | os.O_NOFOLLOW)
        if os.fstat(fd).st_ino != record["filler_inode"]:
            os.close(fd)
            raise ValueError("filler inode changed before writing")
        with os.fdopen(fd, "r+b", buffering=0) as stream:
            count = 0
            while time.monotonic() < deadline:
                verify()
                fs = os.statvfs(MOUNT)
                used = fs.f_blocks - fs.f_bfree
                usage = used / (used + fs.f_bavail) * 100
                if usage < 97 and count < CAPACITY:
                    chunk = min(1024 * 1024, fs.f_bavail * fs.f_frsize, CAPACITY - count)
                    if chunk <= 0:
                        raise ValueError("no available blocks")
                    stream.write(b"x" * chunk)
                    count += chunk
                else:
                    time.sleep(0.25)
    finally:
        main_cleanup(token)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "prepare",
            "probe",
            "start",
            "cleanup",
            "cleanup-reboot",
            "status",
            "worker",
            "watchdog",
        ),
    )
    parser.add_argument("--token", default="")
    parser.add_argument("--duration", type=int, default=180)
    args = parser.parse_args()

    def interrupted(signum: int, frame: object) -> None:
        raise InterruptedError("resource helper interrupted")

    if args.action != "watchdog":
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
    if not 2 <= args.duration <= 240:
        parser.error("duration must be 2..240 seconds")
    safe_directory()
    # Serialize metadata/deletion, including watchdog racing normal cleanup.
    if args.action in ("worker", "watchdog"):
        if args.action == "worker":
            worker(args.token, args.duration)
        else:
            time.sleep(args.duration + 2)
            main_cleanup(args.token)
        return
    with (BASE / "control.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = (
            prepare()
            if args.action == "prepare"
            else verify()
            if args.action == "probe"
            else start(args.token, args.duration)
            if args.action == "start"
            else cleanup(args.token, reboot=args.action == "cleanup-reboot")
            if args.action in ("cleanup", "cleanup-reboot")
            else status(args.token)
        )
        print(json.dumps(result))


def main_cleanup(token: str) -> None:
    with (BASE / "control.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cleanup(token)


if __name__ == "__main__":
    main()
