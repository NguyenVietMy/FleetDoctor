#!/usr/bin/env python3
"""Root-only bounded dm-delay I/O fixture with exact identity-safe cleanup."""

from __future__ import annotations

import argparse
import fcntl
import json
import mmap
import os
import platform
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STATE = Path("/var/lib/fleetdoctor/io-resource")
TARGET = Path("/var/lib/fleetdoctor/io-target")
REFERENCE_TARGET = Path("/var/lib/fleetdoctor/io-reference")
LOCK = STATE / "lock"
LEASE = STATE / "lease.json"
LEASE_PENDING = STATE / "lease.pending"
IMAGE_BYTES = 384 * 1024 * 1024
REFERENCE_IMAGE_BYTES = 128 * 1024 * 1024
FILE_BYTES = 16 * 1024 * 1024
MAX_DURATION = 120
WORKERS = 4


def command(*args: str, timeout: int = 90) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)}: {result.stderr[-1000:]}")
    return result.stdout.strip()


def atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(path.name + ".new")
    encoded = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    if temporary.exists():
        info = temporary.lstat()
        if temporary.is_symlink() or not temporary.is_file() or info.st_uid != 0:
            raise ValueError("foreign atomic temporary file")
        temporary.unlink()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(encoded)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("short atomic metadata write")
            written += count
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def validate_owned_parent(path: Path) -> None:
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError(f"unsafe fixed parent: {path}")


def safe_roots() -> None:
    if os.geteuid() != 0:
        raise PermissionError("I/O fixture requires root")
    for parent in (Path("/var"), Path("/var/lib"), Path("/var/lib/fleetdoctor")):
        if parent.exists():
            validate_owned_parent(parent)
    if not STATE.parent.exists():
        STATE.parent.mkdir(mode=0o755)
    for path, mode in ((STATE, 0o700), (TARGET, 0o755), (REFERENCE_TARGET, 0o755)):
        if path.exists():
            info = path.lstat()
            if (
                not path.is_dir()
                or path.is_symlink()
                or info.st_uid != 0
                or info.st_mode & 0o777 != mode
            ):
                raise ValueError(f"unsafe owned directory: {path}")
        else:
            path.mkdir(mode=mode, parents=False)


@contextmanager
def locked() -> Iterator[None]:
    safe_roots()
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != 0 or info.st_mode & 0o777 != 0o600:
            raise ValueError("unsafe lock identity or mode")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def token_path(token: str) -> Path:
    if len(token) != 32 or any(character not in "0123456789abcdef" for character in token):
        raise ValueError("token must be 32 lowercase hexadecimal characters")
    return STATE / f"run-{token}.json"


def marker_paths(token: str) -> dict[str, Path]:
    token_path(token)
    return {
        "watchdog_ready_inode": STATE / f"watchdog-{token}.ready",
        "watchdog_active_inode": STATE / f"watchdog-{token}.active",
        "worker_activation_inode": STATE / f"worker-{token}.activate",
        "worker_active_inode": STATE / f"worker-{token}.active",
        "lease_pending_inode": LEASE_PENDING,
    }


def owned_regular(path: Path, *, token: str, inode: object | None = None) -> os.stat_result:
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_uid != 0
        or info.st_mode & 0o777 != 0o600
        or (inode is not None and info.st_ino != inode)
    ):
        raise ValueError(f"marker identity changed: {path}")
    value = json.loads(path.read_text())
    if value.get("token") != token:
        raise ValueError(f"marker token changed: {path}")
    return info


def process_facts(pid: int) -> tuple[str, int, str]:
    value = Path(f"/proc/{pid}/stat").read_text()
    fields = value[value.rfind(")") + 2 :].split()
    return fields[19], int(fields[2]), fields[0]


def process_start(pid: int) -> str:
    return process_facts(pid)[0]


def process_owned(pid: object, start: object, pgid: object | None = None) -> bool:
    if not isinstance(pid, int) or not isinstance(start, str) or not Path(f"/proc/{pid}").exists():
        return False
    actual_start, actual_pgid, state = process_facts(pid)
    return actual_start == start and state != "Z" and (pgid is None or pgid == actual_pgid == pid)


def boot() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def load(token: str) -> dict[str, Any]:
    path = token_path(token)
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_uid != 0:
        raise ValueError("unsafe run record")
    value: dict[str, Any] = json.loads(path.read_text())
    if value.get("token") != token:
        raise ValueError("run record token mismatch")
    return value


def _token_bound_resource_names(record: dict[str, Any]) -> str:
    token = record.get("token")
    if not isinstance(token, str) or token_path(token) != STATE / f"run-{token}.json":
        raise ValueError("record token/path is not canonical")
    if (
        record.get("image") != str(STATE / f"image-{token}.img")
        or record.get("reference_image") != str(STATE / f"reference-image-{token}.img")
        or record.get("dm_name") != f"fd11-{token[:12]}"
        or record.get("dm_uuid") != f"FLEETDOCTOR-IO-{token}"
    ):
        raise ValueError("resource names are not token-bound")
    return token


def image_state(record: dict[str, Any], key: str) -> str:
    if key not in ("image", "reference_image"):
        raise ValueError("unrecognized image stage")
    _token_bound_resource_names(record)
    intended = bool(record.get(f"{key}_create_intended") or record.get(f"{key}_owned"))
    if not intended:
        return "not_acquired"
    path_value = record.get(key)
    inode = record.get(f"{key}_inode")
    device = record.get(f"{key}_dev")
    owner = record.get(f"{key}_uid")
    size = record.get(f"{key}_identity_size", record.get(f"{key}_size"))
    if (
        not isinstance(path_value, str)
        or not isinstance(inode, int)
        or not isinstance(device, int)
        or not isinstance(owner, int)
        or owner != 0
        or not isinstance(size, int)
    ):
        raise ValueError(f"{key} recorded identity is incomplete")
    path = Path(path_value)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "absent"
    if (
        path.parent != STATE
        or path.is_symlink()
        or not path.is_file()
        or info.st_uid != owner
        or info.st_dev != device
        or info.st_ino != inode
        or info.st_size != size
    ):
        raise ValueError(f"{key} identity changed")
    return "owned"


def _loop_backing(loop: str) -> str | None:
    result = subprocess.run(
        ("losetup", "--noheadings", "--output", "BACK-FILE", loop),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 0:
        backing = result.stdout.strip()
        if backing:
            return backing
    inventory = subprocess.run(
        ("losetup", "--json", "--list", "--output", "NAME,BACK-FILE"),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if inventory.returncode:
        raise RuntimeError(f"loop inventory failed: {inventory.stderr[-1000:]}")
    try:
        devices = json.loads(inventory.stdout)["loopdevices"]
        if not isinstance(devices, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]
            for item in devices
        ):
            raise ValueError("loop inventory has invalid device names")
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("loop inventory readback malformed") from exc
    if any(item["name"] == loop for item in devices):
        raise RuntimeError(f"loop backing readback failed or empty: {loop}")
    return None


def loop_state(record: dict[str, Any], key: str) -> str:
    if key not in ("loop", "reference_loop"):
        raise ValueError("unrecognized loop stage")
    intended = bool(record.get(f"{key}_attach_intended") or record.get(f"{key}_owned"))
    if not intended:
        return "not_acquired"
    loop = record.get(key)
    if (
        not isinstance(loop, str)
        or Path(loop).parent != Path("/dev")
        or not Path(loop).name.startswith("loop")
    ):
        raise ValueError(f"{key} recorded identity is incomplete")
    backing = _loop_backing(loop)
    if backing is None:
        return "absent"
    image_key = "reference_image" if key == "reference_loop" else "image"
    if image_state(record, image_key) != "owned":
        raise ValueError(f"{key} backing image is not owned")
    if backing != record.get(image_key):
        raise ValueError(f"{key} backing identity changed")
    return "owned"


def _dm_names() -> set[str]:
    result = subprocess.run(
        ("dmsetup", "info", "-c", "--noheadings", "-o", "name"),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode:
        raise RuntimeError(f"device-mapper inventory failed: {result.stderr[-1000:]}")
    return {line.split()[0] for line in result.stdout.splitlines() if line.split()}


def dm_state(record: dict[str, Any]) -> str:
    intended = bool(record.get("dm_create_intended") or record.get("dm_owned"))
    if not intended:
        return "not_acquired"
    _token_bound_resource_names(record)
    name = record.get("dm_name")
    uuid = record.get("dm_uuid")
    table = record.get("dm_table")
    if not isinstance(name, str) or not isinstance(uuid, str) or not isinstance(table, str):
        raise ValueError("device-mapper recorded identity is incomplete")
    info = subprocess.run(
        ("dmsetup", "info", "-c", "--noheadings", "-o", "uuid", name),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if info.returncode:
        if name not in _dm_names():
            return "absent"
        raise RuntimeError(f"device-mapper UUID readback failed: {info.stderr[-1000:]}")
    table_result = subprocess.run(
        ("dmsetup", "table", name), capture_output=True, text=True, timeout=10
    )
    if table_result.returncode:
        raise RuntimeError(f"device-mapper table readback failed: {table_result.stderr[-1000:]}")
    if info.stdout.strip() != uuid:
        raise ValueError("device-mapper UUID changed")
    if " ".join(table_result.stdout.split()) != " ".join(table.split()):
        raise ValueError("device-mapper table changed")
    return "owned"


def _mount_fields(record: dict[str, Any], path: Path) -> tuple[str, str, str, bool]:
    if path == TARGET:
        return (
            "mount_id",
            "mount_source",
            "mount_intended",
            bool(record.get("mount_intended") or record.get("mounted")),
        )
    if path == REFERENCE_TARGET:
        return (
            "reference_mount_id",
            "reference_mount_source",
            "reference_mount_intended",
            bool(record.get("reference_mount_intended") or record.get("reference_mounted")),
        )
    raise ValueError("unrecognized owned mount path")


def _mount_snapshot(path: Path) -> tuple[str, str] | None:
    def mount_id() -> str | None:
        matches = [
            line.split()
            for line in Path("/proc/self/mountinfo").read_text().splitlines()
            if len(line.split()) > 4 and line.split()[4] == str(path)
        ]
        if not matches:
            return None
        if len(matches) != 1:
            raise ValueError(f"ambiguous mount inventory: {path}")
        return matches[0][0]

    before_id = mount_id()
    if before_id is None:
        return None
    result = subprocess.run(
        ("findmnt", "--json", "--mountpoint", str(path), "-o", "SOURCE,TARGET"),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode:
        raise RuntimeError(f"mount source readback failed: {path}: {result.stderr[-1000:]}")
    try:
        filesystems = json.loads(result.stdout)["filesystems"]
        mount = filesystems[0]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"mount source readback malformed: {path}") from exc
    if mount.get("target") != str(path) or not isinstance(mount.get("source"), str):
        raise ValueError(f"mount source readback changed: {path}")
    after_id = mount_id()
    if after_id != before_id:
        raise ValueError(f"mount inventory changed during source readback: {path}")
    return before_id, mount["source"]


def mount_state(record: dict[str, Any], path: Path) -> str:
    id_key, source_key, _intent_key, intended = _mount_fields(record, path)
    if not intended:
        return "not_acquired"
    expected_namespace = record.get("mount_namespace")
    expected_id = record.get(id_key)
    expected_source = record.get(source_key)
    if (
        not isinstance(expected_namespace, str)
        or not isinstance(expected_id, str)
        or not isinstance(expected_source, str)
    ):
        raise ValueError(f"mount recorded identity is incomplete: {path}")
    if expected_namespace != os.readlink("/proc/self/ns/mnt"):
        raise ValueError("mount namespace identity changed")
    snapshot = _mount_snapshot(path)
    if snapshot is None:
        return "absent"
    if snapshot != (expected_id, expected_source):
        raise ValueError(f"mounted resource identity changed: {path}")
    return "owned"


def _require_owned(state: str, label: str) -> None:
    if state != "owned":
        raise ValueError(f"{label} is not currently owned: {state}")


def _release_state(record: dict[str, Any], state: Callable[[], str]) -> str:
    expected_boot = record.get("boot_id")
    if not isinstance(expected_boot, str):
        raise ValueError("release record boot identity is incomplete")
    if expected_boot != boot():
        raise ValueError("resource belongs to another boot")
    return state()


def worker_files_identity(record: dict[str, Any]) -> None:
    for item in record.get("files", []):
        file = Path(item.get("path", ""))
        if file.parent != TARGET:
            raise ValueError("worker file path escaped fixed target")
        info = file.lstat()
        if (
            file.is_symlink()
            or not file.is_file()
            or info.st_uid != 0
            or info.st_ino != item.get("inode")
            or item.get("size") != FILE_BYTES
            or info.st_size != item["size"]
        ):
            raise ValueError("worker file identity changed")


def resource_identity(record: dict[str, Any], *, mounted: bool = True) -> None:
    _token_bound_resource_names(record)
    if record.get("boot_id") != boot():
        raise ValueError("resource belongs to another boot")
    _require_owned(image_state(record, "image"), "image")
    _require_owned(image_state(record, "reference_image"), "reference image")
    _require_owned(loop_state(record, "loop"), "loop")
    _require_owned(loop_state(record, "reference_loop"), "reference loop")
    _require_owned(dm_state(record), "device-mapper mapping")
    if mounted:
        _require_owned(mount_state(record, TARGET), "target mount")
        _require_owned(mount_state(record, REFERENCE_TARGET), "reference mount")
        worker_files_identity(record)


def mount_identity(record: dict[str, Any], path: Path) -> None:
    _require_owned(mount_state(record, path), f"mount {path}")


def _release_command(
    label: str,
    state: Callable[[], str],
    argv: tuple[str, ...],
    *,
    timeout: float = 3.0,
) -> str:
    deadline = time.monotonic() + timeout
    while True:
        current = state()
        if current in ("not_acquired", "absent"):
            return current
        _require_owned(current, label)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            after = state()
            if after == "absent":
                return "released"
            raise RuntimeError(f"{label} release was not confirmed absent: {after}")
        if "busy" not in result.stderr.lower() or time.monotonic() >= deadline:
            raise RuntimeError(f"{' '.join(argv)}: {result.stderr[-1000:]}")
        time.sleep(0.1)


def release_mount(record: dict[str, Any], path: Path, *, timeout: float = 3.0) -> str:
    return _release_command(
        f"mount {path}",
        lambda: _release_state(record, lambda: mount_state(record, path)),
        ("umount", str(path)),
        timeout=timeout,
    )


def release_dm(record: dict[str, Any], *, timeout: float = 3.0) -> str:
    name = record.get("dm_name")
    if not isinstance(name, str):
        raise ValueError("device-mapper name is not recorded")
    return _release_command(
        "device-mapper mapping",
        lambda: _release_state(record, lambda: dm_state(record)),
        ("dmsetup", "remove", name),
        timeout=timeout,
    )


def release_loop(record: dict[str, Any], key: str, *, timeout: float = 3.0) -> str:
    loop = record.get(key)
    if not isinstance(loop, str) and bool(
        record.get(f"{key}_attach_intended") or record.get(f"{key}_owned")
    ):
        raise ValueError(f"{key} path is not recorded")
    if not isinstance(loop, str):
        return _release_state(record, lambda: "not_acquired")
    return _release_command(
        key,
        lambda: _release_state(record, lambda: loop_state(record, key)),
        ("losetup", "--detach", loop),
        timeout=timeout,
    )


def release_image(record: dict[str, Any], key: str) -> str:
    state = _release_state(record, lambda: image_state(record, key))
    if state in ("not_acquired", "absent"):
        return state
    _require_owned(state, key)
    path = Path(record[key])
    path.unlink()
    after = _release_state(record, lambda: image_state(record, key))
    if after != "absent":
        raise RuntimeError(f"{key} unlink was not confirmed absent: {after}")
    return "released"


def _persist_release(record: dict[str, Any], current_errors: list[str]) -> None:
    try:
        atomic(token_path(record["token"]), record)
    except BaseException as exc:
        error = f"record_persistence:{exc!r}"
        current_errors.append(error)
        history = record.setdefault("cleanup_error_history", [])
        if error not in history:
            history.append(error)


def release_resource_stages(record: dict[str, Any], *, final_phase: str) -> dict[str, Any]:
    stages: dict[str, str] = {}
    current_errors: list[str] = []
    history = record.setdefault("cleanup_error_history", [])
    terminal = {"not_acquired", "absent", "released"}

    def attempt(label: str, action: Callable[[], str], blockers: tuple[str, ...] = ()) -> None:
        blocked = [name for name in blockers if stages.get(name) not in terminal]
        if blocked:
            stages[label] = "blocked"
            error = f"{label}:blocked_by:{','.join(blocked)}"
            current_errors.append(error)
            if error not in history:
                history.append(error)
        else:
            try:
                stages[label] = action()
            except BaseException as exc:
                stages[label] = "refused"
                error = f"{label}:{exc!r}"
                current_errors.append(error)
                if error not in history:
                    history.append(error)
        record["release_stages"] = dict(stages)
        record["current_cleanup_errors"] = list(current_errors)
        record["cleanup_complete"] = False
        _persist_release(record, current_errors)

    attempt("reference_mount", lambda: release_mount(record, REFERENCE_TARGET))
    attempt("mount", lambda: release_mount(record, TARGET))
    attempt("dm", lambda: release_dm(record), ("mount",))
    attempt("reference_loop", lambda: release_loop(record, "reference_loop"), ("reference_mount",))
    attempt("loop", lambda: release_loop(record, "loop"), ("mount", "dm"))
    attempt(
        "reference_image",
        lambda: release_image(record, "reference_image"),
        ("reference_mount", "reference_loop"),
    )
    attempt("image", lambda: release_image(record, "image"), ("mount", "dm", "loop"))

    complete = not current_errors and all(value in terminal for value in stages.values())
    record.update(
        phase=final_phase
        if complete
        else ("prepare_failed" if final_phase == "prepare_failed" else "cleanup_failed"),
        cleanup_complete=complete,
        cleanup_errors=list(current_errors),
        release_stages=dict(stages),
    )
    if complete and final_phase == "destroyed":
        record["destroyed_at"] = datetime.now(UTC).isoformat()
    try:
        atomic(token_path(record["token"]), record)
    except BaseException as exc:
        error = f"final_record_persistence:{exc!r}"
        current_errors.append(error)
        if error not in history:
            history.append(error)
        record.update(
            phase="prepare_failed" if final_phase == "prepare_failed" else "cleanup_failed",
            cleanup_complete=False,
            cleanup_errors=list(current_errors),
        )
        try:
            atomic(token_path(record["token"]), record)
        except BaseException:
            pass
    return record


def unmount_owned(record: dict[str, Any], path: Path, *, timeout: float = 3.0) -> None:
    release_mount(record, path, timeout=timeout)


def allocate_owned_image(
    record: dict[str, Any], key: str, descriptor: int, size: int, record_path: Path
) -> None:
    allocation_error: BaseException | None = None
    try:
        os.posix_fallocate(descriptor, 0, size)
        os.fsync(descriptor)
    except BaseException as exc:
        allocation_error = exc
    try:
        info = os.fstat(descriptor)
        record.update(
            {
                f"{key}_inode": info.st_ino,
                f"{key}_dev": info.st_dev,
                f"{key}_uid": info.st_uid,
                f"{key}_identity_size": info.st_size,
            }
        )
        atomic(record_path, record)
    except BaseException as identity_exc:
        if allocation_error is None:
            raise
        record.setdefault("setup_stage_errors", []).append(
            f"{key}_failure_identity_persistence:{identity_exc!r}"
        )
    if allocation_error is not None:
        raise allocation_error


def prepare(token: str) -> dict[str, Any]:
    path = token_path(token)
    if path.exists() or LEASE.exists():
        raise ValueError("owned I/O resource or lease already exists")
    for fixed_target in (TARGET, REFERENCE_TARGET):
        if (
            subprocess.run(
                ["mountpoint", "-q", str(fixed_target)], capture_output=True, timeout=5
            ).returncode
            == 0
        ):
            raise ValueError(f"fixed I/O target is already mounted: {fixed_target}")
    image = STATE / f"image-{token}.img"
    reference_image = STATE / f"reference-image-{token}.img"
    dm_name = f"fd11-{token[:12]}"
    dm_uuid = f"FLEETDOCTOR-IO-{token}"
    loop = ""
    reference_loop = ""
    record: dict[str, Any] = {
        "token": token,
        "phase": "rollback_intent",
        "boot_id": boot(),
        "mount_namespace": os.readlink("/proc/self/ns/mnt"),
        "image": str(image),
        "image_size": IMAGE_BYTES,
        "reference_image": str(reference_image),
        "reference_image_size": REFERENCE_IMAGE_BYTES,
        "dm_name": dm_name,
        "dm_uuid": dm_uuid,
        "mount": str(TARGET),
        "files": [],
        "cleanup_complete": False,
    }
    atomic(path, record)
    try:
        record["image_create_intended"] = True
        atomic(path, record)
        descriptor = os.open(image, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            image_info = os.fstat(descriptor)
            record.update(
                image_inode=image_info.st_ino,
                image_dev=image_info.st_dev,
                image_uid=image_info.st_uid,
                image_identity_size=image_info.st_size,
                image_owned=True,
            )
            atomic(path, record)
            _require_owned(image_state(record, "image"), "image before allocation")
            allocate_owned_image(record, "image", descriptor, IMAGE_BYTES, path)
        finally:
            os.close(descriptor)
        _require_owned(image_state(record, "image"), "image after allocation")
        record["loop_attach_intended"] = True
        atomic(path, record)
        loop = command("losetup", "--find", "--show", str(image))
        record.update(loop=loop, loop_owned=True)
        atomic(path, record)
        _require_owned(loop_state(record, "loop"), "loop after attachment")
        record["reference_image_create_intended"] = True
        atomic(path, record)
        descriptor = os.open(
            reference_image,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        try:
            reference_info = os.fstat(descriptor)
            record.update(
                reference_image_inode=reference_info.st_ino,
                reference_image_dev=reference_info.st_dev,
                reference_image_uid=reference_info.st_uid,
                reference_image_identity_size=reference_info.st_size,
                reference_image_owned=True,
            )
            atomic(path, record)
            _require_owned(
                image_state(record, "reference_image"), "reference image before allocation"
            )
            allocate_owned_image(record, "reference_image", descriptor, REFERENCE_IMAGE_BYTES, path)
        finally:
            os.close(descriptor)
        _require_owned(image_state(record, "reference_image"), "reference image after allocation")
        record["reference_loop_attach_intended"] = True
        atomic(path, record)
        reference_loop = command("losetup", "--find", "--show", str(reference_image))
        record.update(reference_loop=reference_loop, reference_loop_owned=True)
        atomic(path, record)
        _require_owned(loop_state(record, "reference_loop"), "reference loop before formatting")
        command("mkfs.ext4", "-q", "-F", "-m", "0", reference_loop)
        _require_owned(loop_state(record, "reference_loop"), "reference loop before mount")
        record.update(
            reference_mount_intended=True,
            reference_mount_source=reference_loop,
        )
        atomic(path, record)
        command("mount", "-o", "noatime", reference_loop, str(REFERENCE_TARGET))
        reference_snapshot = _mount_snapshot(REFERENCE_TARGET)
        if (
            record.get("mount_namespace") != os.readlink("/proc/self/ns/mnt")
            or reference_snapshot is None
            or reference_snapshot[1] != reference_loop
        ):
            raise ValueError("reference mount readback does not match acquired identity")
        record.update(
            reference_mounted=True,
            reference_mount_id=reference_snapshot[0],
        )
        atomic(path, record)
        sectors = IMAGE_BYTES // 512
        loop_major_minor = command("lsblk", "-dn", "-o", "MAJ:MIN", loop)
        create_table = f"0 {sectors} delay {loop} 0 40"
        record.update(
            dm_create_intended=True,
            dm_table=f"0 {sectors} delay {loop_major_minor} 0 40",
        )
        atomic(path, record)
        _require_owned(loop_state(record, "loop"), "loop before device-mapper creation")
        command("dmsetup", "create", dm_name, "--uuid", dm_uuid, "--table", create_table)
        _require_owned(dm_state(record), "device-mapper after creation")
        record["dm_owned"] = True
        atomic(path, record)
        _require_owned(dm_state(record), "device-mapper before formatting")
        _require_owned(loop_state(record, "loop"), "loop before mapped formatting")
        command("mkfs.ext4", "-q", "-F", "-m", "0", f"/dev/mapper/{dm_name}")
        _require_owned(dm_state(record), "device-mapper before mount")
        record.update(
            mount_intended=True,
            mount_source=f"/dev/mapper/{dm_name}",
        )
        atomic(path, record)
        command("mount", "-o", "noatime", f"/dev/mapper/{dm_name}", str(TARGET))
        target_snapshot = _mount_snapshot(TARGET)
        if (
            record.get("mount_namespace") != os.readlink("/proc/self/ns/mnt")
            or target_snapshot is None
            or target_snapshot[1] != f"/dev/mapper/{dm_name}"
        ):
            raise ValueError("target mount readback does not match acquired identity")
        record.update(
            mounted=True,
            mount_id=target_snapshot[0],
        )
        atomic(path, record)
        files = []
        for index in range(WORKERS):
            file = TARGET / f"worker-{index}.bin"
            _require_owned(mount_state(record, TARGET), "target mount before file creation")
            descriptor = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                _require_owned(mount_state(record, TARGET), "target mount before file allocation")
                os.posix_fallocate(descriptor, 0, FILE_BYTES)
                os.fsync(descriptor)
                files.append(
                    {"path": str(file), "inode": os.fstat(descriptor).st_ino, "size": FILE_BYTES}
                )
            finally:
                os.close(descriptor)
            record["files"] = list(files)
            atomic(path, record)
        _require_owned(mount_state(record, TARGET), "target mount before sync")
        command("sync", "-f", str(TARGET))
        _require_owned(mount_state(record, TARGET), "target mount before free-space check")
        stats = os.statvfs(TARGET)
        if stats.f_bavail * stats.f_frsize < 128 * 1024 * 1024 or stats.f_ffree < 100:
            raise ValueError("fixture safety free-space threshold unavailable")
        record.update(
            phase="prepared",
            kernel=platform.release(),
            prepared_at=datetime.now(UTC).isoformat(),
        )
        atomic(path, record)
        return record
    except BaseException as exc:
        record.setdefault("original_error", repr(exc))
        release_resource_stages(record, final_phase="prepare_failed")
        raise


def launch(action: str, token: str, duration: int) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), action, token, "--duration", str(duration)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def start(
    token: str,
    duration: int,
    controller: tuple[int, str] | None = None,
) -> dict[str, Any]:
    if not 1 <= duration <= MAX_DURATION:
        raise ValueError("duration must be 1..120 seconds")
    record = load(token)
    resource_identity(record)
    markers = marker_paths(token)
    occupied = [str(path) for path in markers.values() if path.exists() or path.is_symlink()]
    if record.get("phase") not in ("prepared", "stopped") or LEASE.exists() or occupied:
        if occupied:
            raise ValueError(f"foreign or stale marker refused: {occupied[0]}")
        raise ValueError("resource is not exclusively prepared")
    for key in markers:
        record.pop(key, None)
    controller_pid, controller_start = controller or (
        os.getpid(),
        process_start(os.getpid()),
    )
    record.update(
        phase="rollback_intent",
        controller_pid=controller_pid,
        controller_start=controller_start,
        controller_source="caller_parent" if controller is not None else "in_process",
        duration=duration,
        deadline_monotonic=time.monotonic() + duration,
        lease_published=False,
    )
    atomic(token_path(token), record)
    watchdog: subprocess.Popen[bytes] | None = None
    worker_process: subprocess.Popen[bytes] | None = None
    try:
        watchdog = launch("watchdog", token, duration)
        record.update(
            watchdog_pid=watchdog.pid,
            watchdog_start=process_start(watchdog.pid),
            watchdog_pgid=os.getpgid(watchdog.pid),
            watchdog_ready_intended=True,
        )
        atomic(token_path(token), record)
        ready = STATE / f"watchdog-{token}.ready"
        limit = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < limit:
            if watchdog.poll() is not None:
                raise RuntimeError("watchdog exited before readiness")
            time.sleep(0.05)
        if not ready.exists():
            raise TimeoutError("watchdog readiness deadline")
        ready_info = owned_regular(ready, token=token)
        if not process_owned(
            record["watchdog_pid"], record["watchdog_start"], record["watchdog_pgid"]
        ):
            raise RuntimeError("watchdog died after readiness")
        ready_value = json.loads(ready.read_text())
        if (
            ready_value.get("pid") != record["watchdog_pid"]
            or ready_value.get("start") != record["watchdog_start"]
        ):
            raise ValueError("watchdog readiness identity changed")
        record["watchdog_ready_inode"] = ready_info.st_ino
        atomic(token_path(token), record)
        worker_process = launch("worker", token, duration)
        record.update(
            worker_pid=worker_process.pid,
            worker_start=process_start(worker_process.pid),
            worker_pgid=os.getpgid(worker_process.pid),
        )
        atomic(token_path(token), record)
        lease = {
            "token": token,
            "boot_id": boot(),
            "dm_uuid": record["dm_uuid"],
            "watchdog_pid": watchdog.pid,
        }
        record["lease_pending_intended"] = True
        atomic(token_path(token), record)
        atomic(LEASE_PENDING, lease)
        pending_info = owned_regular(LEASE_PENDING, token=token)
        record.update(
            lease_inode=pending_info.st_ino,
            lease_pending_inode=pending_info.st_ino,
            watchdog_ready=True,
        )
        atomic(token_path(token), record)
        os.replace(LEASE_PENDING, LEASE)
        directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
        os.fsync(directory)
        os.close(directory)
        record.update(
            phase="authority_registered",
            lease_published=True,
            watchdog_active_intended=True,
        )
        atomic(token_path(token), record)
        active_ack = STATE / f"watchdog-{token}.active"
        limit = time.monotonic() + 3
        while not active_ack.exists() and time.monotonic() < limit:
            if not process_owned(
                record["watchdog_pid"], record["watchdog_start"], record["watchdog_pgid"]
            ):
                raise RuntimeError("watchdog died before activation acknowledgement")
            time.sleep(0.05)
        if not active_ack.exists():
            raise TimeoutError("watchdog activation deadline")
        active_info = owned_regular(active_ack, token=token)
        record["watchdog_active_inode"] = active_info.st_ino
        atomic(token_path(token), record)
        activation = STATE / f"worker-{token}.activate"
        record.update(worker_activation_intended=True, worker_active_intended=True)
        atomic(token_path(token), record)
        atomic(
            activation,
            {
                "token": token,
                "lease_inode": record["lease_inode"],
                "pid": record["worker_pid"],
                "start": record["worker_start"],
            },
        )
        activation_info = owned_regular(activation, token=token)
        record["worker_activation_inode"] = activation_info.st_ino
        atomic(token_path(token), record)
        worker_ack = STATE / f"worker-{token}.active"
        limit = time.monotonic() + 3
        while not worker_ack.exists() and time.monotonic() < limit:
            if not process_owned(
                record["worker_pid"], record["worker_start"], record["worker_pgid"]
            ):
                raise RuntimeError("worker died before activation")
            time.sleep(0.05)
        if not worker_ack.exists():
            raise TimeoutError("worker activation deadline")
        worker_info = owned_regular(worker_ack, token=token)
        worker_value = json.loads(worker_ack.read_text())
        if worker_value.get("pid") != record["worker_pid"]:
            raise ValueError("worker acknowledgement identity changed")
        record.update(
            phase="running",
            watchdog_activated=True,
            worker_activated=True,
            worker_active_inode=worker_info.st_ino,
            started_at=datetime.now(UTC).isoformat(),
        )
        atomic(token_path(token), record)
        return record
    except BaseException as exc:
        for child in (worker_process, watchdog):
            if child is not None and child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                    child.wait(timeout=3)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        try:
            cleanup_workload(token, original_error=repr(exc), record_override=record)
        except BaseException as cleanup_exc:
            record.update(
                phase="cleanup_failed",
                cleanup_complete=False,
                original_error=repr(exc),
                cleanup_errors=[repr(cleanup_exc)],
            )
            try:
                atomic(token_path(token), record)
            except BaseException:
                pass
            raise RuntimeError(
                f"start failed: {exc!r}; exact cleanup also failed: {cleanup_exc!r}"
            ) from exc
        raise


def status(token: str) -> dict[str, Any]:
    record = load(token)
    resource_identity(record)
    if record.get("phase") == "running":
        if not process_owned(
            record.get("worker_pid"), record.get("worker_start"), record.get("worker_pgid")
        ):
            raise ValueError("owned worker is not live")
        if not process_owned(
            record.get("watchdog_pid"),
            record.get("watchdog_start"),
            record.get("watchdog_pgid"),
        ):
            raise ValueError("owned watchdog is not live")
        if (
            not LEASE.exists()
            or LEASE.is_symlink()
            or LEASE.stat().st_ino != record.get("lease_inode")
        ):
            raise ValueError("authoritative lease is missing or replaced")
        lease = json.loads(LEASE.read_text())
        if lease.get("token") != token or lease.get("dm_uuid") != record.get("dm_uuid"):
            raise ValueError("authoritative lease identity changed")
    stats = os.statvfs(TARGET)
    record["free_bytes"] = stats.f_bavail * stats.f_frsize
    record["free_inodes"] = stats.f_ffree
    return record


def stop_process(record: dict[str, Any], name: str) -> None:
    pid, started, pgid = (
        record.get(f"{name}_pid"),
        record.get(f"{name}_start"),
        record.get(f"{name}_pgid"),
    )
    if process_owned(pid, started, pgid):
        assert isinstance(pid, int)
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        limit = time.monotonic() + 3
        while process_owned(pid, started, pgid) and time.monotonic() < limit:
            time.sleep(0.05)
        if process_owned(pid, started, pgid):
            os.killpg(pid, signal.SIGKILL)


def cleanup_workload(
    token: str,
    *,
    original_error: str | None = None,
    record_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = dict(record_override) if record_override is not None else load(token)
    if record.get("phase") == "destroyed" and record.get("cleanup_complete") is True:
        return record
    resource_identity(record)
    stop_process(record, "worker")
    if record.get("phase") != "watchdog_cleanup":
        stop_process(record, "watchdog")
    if LEASE.exists():
        info = LEASE.lstat()
        lease = json.loads(LEASE.read_text())
        if (
            info.st_uid != 0
            or LEASE.is_symlink()
            or lease.get("token") != token
            or info.st_ino != record.get("lease_inode")
        ):
            raise ValueError("lease replacement refused")
        LEASE.unlink()
    for key, marker in marker_paths(token).items():
        if not marker.exists() and not marker.is_symlink():
            continue
        expected_inode = record.get(key)
        if expected_inode is not None:
            owned_regular(marker, token=token, inode=expected_inode)
        else:
            if not record.get(key.replace("_inode", "_intended")):
                raise ValueError(f"foreign marker refused without durable intent: {marker}")
            info = owned_regular(marker, token=token)
            value = json.loads(marker.read_text())
            if key.startswith("watchdog_") and (
                value.get("pid") != record.get("watchdog_pid")
                or value.get("start") != record.get("watchdog_start")
            ):
                raise ValueError(f"foreign watchdog marker refused: {marker}")
            if key.startswith("worker_") and (
                value.get("pid") != record.get("worker_pid")
                or value.get("start") != record.get("worker_start")
            ):
                raise ValueError(f"foreign worker marker refused: {marker}")
            if key == "lease_pending_inode" and (
                value.get("dm_uuid") != record.get("dm_uuid")
                or (
                    record.get("lease_inode") is not None
                    and info.st_ino != record.get("lease_inode")
                )
            ):
                raise ValueError("foreign pending lease refused")
        marker.unlink()
    record.update(
        phase="stopped",
        workload_cleanup_complete=True,
        stopped_at=datetime.now(UTC).isoformat(),
        original_error=original_error or record.get("original_error"),
    )
    atomic(token_path(token), record)
    return record


def destroy(token: str) -> dict[str, Any]:
    existing = load(token)
    if existing.get("phase") == "destroyed" and existing.get("cleanup_complete") is True:
        return existing
    workload_already_cleaned = existing.get("workload_cleanup_complete") is True
    if workload_already_cleaned:
        for key in ("worker", "watchdog"):
            if process_owned(
                existing.get(f"{key}_pid"),
                existing.get(f"{key}_start"),
                existing.get(f"{key}_pgid"),
            ):
                raise ValueError("completed workload cleanup still has an owned process")
        if (
            LEASE.exists()
            or LEASE.is_symlink()
            or any(path.exists() or path.is_symlink() for path in marker_paths(token).values())
        ):
            raise ValueError("completed workload cleanup still has authority markers")
        target_state = _release_state(existing, lambda: mount_state(existing, TARGET))
        if target_state == "owned":
            worker_files_identity(existing)
    workload_registered = any(
        key in existing
        for key in (
            "controller_pid",
            "watchdog_pid",
            "worker_pid",
            "lease_published",
            "workload_cleanup_complete",
        )
    )
    if not workload_already_cleaned and (
        workload_registered or existing.get("phase") in ("prepared", "running", "stopped")
    ):
        record = cleanup_workload(token)
    else:
        record = existing
    release_resource_stages(record, final_phase="destroyed")
    if record.get("cleanup_complete") is not True:
        raise RuntimeError(
            "resource cleanup refused or incomplete: "
            + "; ".join(str(item) for item in record.get("cleanup_errors", []))
        )
    return record


def worker(token: str, duration: int) -> None:
    record = load(token)
    resource_identity(record)
    activation = STATE / f"worker-{token}.activate"
    limit = time.monotonic() + 5
    while not activation.exists() and time.monotonic() < limit:
        time.sleep(0.05)
    if not activation.exists() or activation.is_symlink():
        raise TimeoutError("worker activation unavailable")
    activation_limit = time.monotonic() + 3
    current: dict[str, Any] = {}
    while time.monotonic() < activation_limit:
        activated = json.loads(activation.read_text())
        current = load(token)
        if (
            current.get("worker_activation_inode") == activation.stat().st_ino
            and activated.get("token") == token
            and activated.get("lease_inode") == current.get("lease_inode")
            and activated.get("pid") == os.getpid() == current.get("worker_pid")
            and activated.get("start") == process_start(os.getpid())
            and current.get("phase") == "authority_registered"
            and LEASE.exists()
            and not LEASE.is_symlink()
            and LEASE.stat().st_ino == current.get("lease_inode")
            and process_owned(
                current.get("watchdog_pid"),
                current.get("watchdog_start"),
                current.get("watchdog_pgid"),
            )
        ):
            break
        time.sleep(0.05)
    else:
        raise ValueError("worker activation authority invalid")
    active = STATE / f"worker-{token}.active"
    atomic(
        active,
        {"token": token, "pid": os.getpid(), "start": process_start(os.getpid())},
    )
    running_limit = time.monotonic() + 3
    while time.monotonic() < running_limit:
        current = load(token)
        if (
            current.get("phase") == "running"
            and current.get("worker_active_inode") == active.stat().st_ino
        ):
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("worker running authority was not durably published")
    record = current
    stop = threading.Event()
    errors: list[str] = []

    def write(file_record: dict[str, Any]) -> None:
        try:
            path = Path(file_record["path"])
            info = path.lstat()
            if (
                path.is_symlink()
                or info.st_ino != file_record["inode"]
                or info.st_size != file_record["size"]
            ):
                raise ValueError("worker file identity changed")
            descriptor = os.open(path, os.O_WRONLY | os.O_DIRECT | os.O_DSYNC | os.O_NOFOLLOW)
            try:
                with mmap.mmap(-1, 65536) as buffer:
                    offset = 0
                    while not stop.is_set() and time.monotonic() < record["deadline_monotonic"]:
                        os.pwrite(descriptor, buffer, offset)
                        offset = (offset + 65536) % FILE_BYTES
            finally:
                os.close(descriptor)
        except BaseException as exc:
            errors.append(repr(exc))
            stop.set()

    threads = [threading.Thread(target=write, args=(item,)) for item in record["files"]]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise RuntimeError(errors[0])


def watchdog(token: str, _duration: int) -> None:
    registration_limit = time.monotonic() + 3
    record: dict[str, Any] = {}
    while time.monotonic() < registration_limit:
        record = load(token)
        if (
            record.get("phase") == "rollback_intent"
            and record.get("watchdog_ready_intended") is True
            and record.get("watchdog_pid") == os.getpid()
            and record.get("watchdog_start") == process_start(os.getpid())
        ):
            break
        time.sleep(0.05)
    else:
        raise ValueError("watchdog requires durable rollback registration")
    ready = STATE / f"watchdog-{token}.ready"
    atomic(ready, {"token": token, "pid": os.getpid(), "start": process_start(os.getpid())})
    while time.monotonic() < record["deadline_monotonic"]:
        current = load(token)
        if current.get("phase") in ("stopped", "destroyed"):
            return
        active_ack = STATE / f"watchdog-{token}.active"
        if current.get("phase") in ("authority_registered", "running") and not active_ack.exists():
            if (
                not LEASE.exists()
                or LEASE.is_symlink()
                or LEASE.stat().st_ino != current.get("lease_inode")
                or not process_owned(
                    current.get("worker_pid"),
                    current.get("worker_start"),
                    current.get("worker_pgid"),
                )
            ):
                time.sleep(0.05)
                continue
            atomic(
                active_ack,
                {
                    "token": token,
                    "pid": os.getpid(),
                    "start": process_start(os.getpid()),
                    "activated": True,
                },
            )
        if not process_owned(current.get("controller_pid"), current.get("controller_start")):
            break
        if current.get("phase") == "running" and not process_owned(
            current.get("worker_pid"),
            current.get("worker_start"),
            current.get("worker_pgid"),
        ):
            break
        time.sleep(0.2)
    with locked():
        current = load(token)
        if current.get("phase") not in ("stopped", "destroyed"):
            current["phase"] = "watchdog_cleanup"
            atomic(token_path(token), current)
            cleanup_workload(token, original_error="controller_exit_or_deadline")


def caller_controller_identity() -> tuple[int, str]:
    pid = os.getppid()
    path = Path(f"/proc/{pid}")
    if pid <= 1 or not path.is_dir() or path.stat().st_uid != 0:
        raise PermissionError("start requires a live root caller parent")
    started = process_start(pid)
    if not process_owned(pid, started):
        raise RuntimeError("start caller parent changed before registration")
    return pid, started


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("prepare", "start", "status", "cleanup", "destroy", "worker", "watchdog")
    )
    parser.add_argument("token")
    parser.add_argument("--duration", type=int, default=30)
    args = parser.parse_args()
    if args.action in ("worker", "watchdog"):
        globals()[args.action](args.token, args.duration)
        return
    controller = caller_controller_identity() if args.action == "start" else None
    with locked():
        result = (
            prepare(args.token)
            if args.action == "prepare"
            else start(args.token, args.duration, controller)
            if args.action == "start"
            else status(args.token)
            if args.action == "status"
            else cleanup_workload(args.token)
            if args.action == "cleanup"
            else destroy(args.token)
        )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
