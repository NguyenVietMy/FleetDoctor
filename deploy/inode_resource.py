#!/usr/bin/env python3
"""Root-only bounded inode injector for FleetDoctor's owned ext4 loop mount."""

import argparse
import ctypes
import fcntl
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import disk_resource as disk

BASE = disk.BASE
MOUNT = disk.MOUNT
LEASE = BASE / "inode-lease.json"
DISK_LEASE = disk.LEASE
RUNS = BASE / "inode-runs"
MAX_INODES = 4096
TARGET_PERCENT = 97.0
HEALTHY_PERCENT = 90.0
BLOCK_GUARD_PERCENT = 95.0
CREATION_BATCH = 16
OWNER_XATTR = b"user.fleetdoctor.owner"
AT_EMPTY_PATH = 0x1000


@contextmanager
def deferred_start_signals() -> Iterator[None]:
    """Defer INT/TERM until a newly created effect has exact recovery state."""
    blocked = {signal.SIGINT, signal.SIGTERM}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def safe_directory() -> None:
    disk.safe_directory()
    if RUNS.is_symlink() or LEASE.is_symlink():
        raise ValueError("symlink inode metadata refused")
    RUNS.mkdir(exist_ok=True)
    if RUNS.stat().st_uid != 0 or RUNS.stat().st_mode & 0o022:
        raise ValueError("inode run directory must be root-owned and not writable by others")


def run_path(token: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}", token):
        raise ValueError("invalid run token")
    return RUNS / (token + ".json")


def token_directory(token: str) -> Path:
    return MOUNT / ("inode-" + token)


def counters() -> dict[str, int | float]:
    values = os.statvfs(MOUNT)
    if values.f_files <= 0 or values.f_files > MAX_INODES:
        raise ValueError("inode budget outside 1..4096; retained resource must not be reformatted")
    inode_usage = 100 * (values.f_files - values.f_ffree) / values.f_files
    block_used = values.f_blocks - values.f_bfree
    block_denominator = block_used + values.f_bavail
    if block_denominator <= 0:
        raise ValueError("block capacity unavailable")
    return {
        "inodes_total": values.f_files,
        "inodes_free": values.f_ffree,
        "inode_usage_percent": inode_usage,
        "total_bytes": values.f_blocks * values.f_frsize,
        "available_bytes": values.f_bavail * values.f_frsize,
        "block_usage_percent": 100 * block_used / block_denominator,
    }


def probe() -> dict[str, Any]:
    resource = disk.verify()
    resource["inode_statvfs"] = counters()
    return resource


def load_record(token: str) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(run_path(token).read_text(encoding="utf-8"))
    if value.get("token") != token:
        raise ValueError("run token identity changed")
    return value


def owned_process(record: dict[str, Any], mode: str) -> bool:
    """Bind PID reuse checks to this helper, its mode, token, boot, and start time."""
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
        helper_path = str(Path(__file__).resolve()).encode()
        return (
            disk.process_identity(pid) == started
            and len(command_line) >= 3
            and command_line[1] == helper_path
            and mode.encode() in command_line
            and token.encode() in command_line
        )
    except (IndexError, KeyError, OSError, ProcessLookupError, TypeError, ValueError):
        return False


def owned_directory(path: Path, record: dict[str, Any]) -> os.stat_result:
    if path.is_symlink():
        raise ValueError("owned inode directory symlink refused")
    value = path.stat(follow_symlinks=False)
    if (
        value.st_uid != 0
        or not stat.S_ISDIR(value.st_mode)
        or value.st_mode & 0o077
        or value.st_dev != record.get("directory_dev")
        or value.st_ino != record.get("directory_inode")
    ):
        raise ValueError("owned inode directory identity changed")
    if ownership_marker(path) != record.get("directory_marker"):
        raise ValueError("owned inode directory marker identity changed")
    return value


def ownership_marker(path: Path) -> str:
    try:
        marker = os.getxattr(path, OWNER_XATTR, follow_symlinks=False).decode("ascii")
    except (OSError, UnicodeError) as exc:
        raise ValueError("owned inode marker identity changed") from exc
    if not re.fullmatch(r"[a-f0-9]{32}", marker):
        raise ValueError("owned inode marker identity changed")
    return marker


def validate_active(token: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    record = load_record(token)
    if record.get("cleanup_complete") is not False:
        raise ValueError("run is not active")
    resource = disk.verify()
    if record.get("boot_id") != disk.boot_identity():
        raise ValueError("active run boot identity changed")
    if record.get("mapping") != resource.get("mapping"):
        raise ValueError("active run mount identity changed")
    validate_lease(record, allow_absent=False)
    directory = token_directory(token)
    owned_directory(directory, record)
    return record, resource, directory


def validate_lease(record: dict[str, Any], *, allow_absent: bool) -> bool:
    if LEASE.is_symlink():
        raise ValueError("inode lease symlink refused")
    if not LEASE.exists():
        if allow_absent:
            return False
        raise ValueError("inode lease is missing")
    lease_fd = disk.owned_regular(LEASE, record.get("lease_inode"), "inode lease")
    try:
        with os.fdopen(lease_fd, encoding="utf-8") as stream:
            lease = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("inode lease metadata invalid") from exc
    if not isinstance(lease, dict) or lease.get("token") != record.get("token"):
        raise ValueError("inode lease token identity changed")
    if ownership_marker(LEASE) != record.get("lease_marker"):
        raise ValueError("inode lease marker identity changed")
    return True


def validate_files(directory: Path, record: dict[str, Any]) -> list[Path]:
    expected = record.get("files")
    if not isinstance(expected, list) or len(expected) > MAX_INODES:
        raise ValueError("owned file manifest invalid")
    expected_names = {item.get("name") for item in expected if isinstance(item, dict)}
    actual = {item.name for item in directory.iterdir()}
    required_names = {
        item.get("name")
        for item in expected
        if isinstance(item, dict) and item.get("state") == "created"
    }
    if (
        len(expected_names) != len(expected)
        or not actual.issubset(expected_names)
        or not required_names.issubset(actual)
    ):
        raise ValueError("unexpected or missing inode files; refuse cleanup")
    paths: list[Path] = []
    for item in expected:
        name = item["name"]
        if not isinstance(name, str) or not re.fullmatch(r"f-[0-9]{4}", name):
            raise ValueError("owned inode filename invalid")
        state = item.get("state")
        if state not in ("pending", "created", "deleting"):
            raise ValueError("owned inode file state invalid")
        path = directory / name
        if state in ("pending", "deleting") and name not in actual:
            continue
        if path.is_symlink():
            raise ValueError("owned inode file symlink refused")
        value = path.stat(follow_symlinks=False)
        if (
            value.st_uid != 0
            or not stat.S_ISREG(value.st_mode)
            or value.st_nlink != 1
            or value.st_size != 0
            or value.st_mode & 0o077
            or value.st_dev
            != (
                item.get("dev") if state in ("created", "deleting") else record.get("directory_dev")
            )
            or (state in ("created", "deleting") and value.st_ino != item.get("inode"))
            or (state in ("created", "deleting") and value.st_ctime_ns != item.get("ctime_ns"))
        ):
            raise ValueError("owned inode file identity changed")
        if state in ("created", "deleting") and ownership_marker(path) != item.get("marker"):
            raise ValueError("owned inode file marker identity changed")
        if state == "pending" and item.get("marker") is not None:
            if ownership_marker(path) != item["marker"]:
                raise ValueError("pending inode file marker identity changed")
        paths.append(path)
    return paths


def cleanup_file_present(path: Path, item: dict[str, Any]) -> bool:
    """Recheck one deletion-authorized file immediately before its unlink."""
    if path.is_symlink():
        raise ValueError("owned inode file symlink refused")
    if not path.exists():
        return False
    value = path.stat(follow_symlinks=False)
    if (
        value.st_uid != 0
        or not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or value.st_size != 0
        or value.st_mode & 0o077
        or value.st_dev != item.get("dev")
        or value.st_ino != item.get("inode")
        or value.st_ctime_ns != item.get("ctime_ns")
        or ownership_marker(path) != item.get("marker")
    ):
        raise ValueError("owned inode file identity changed")
    return True


def create_owned_file(directory: Path, item: dict[str, Any]) -> os.stat_result:
    """Mark an unnamed inode before atomically making its ledger name visible."""
    name = item.get("name")
    marker = item.get("marker")
    if not isinstance(name, str) or not re.fullmatch(r"f-[0-9]{4}", name):
        raise ValueError("owned inode filename invalid")
    if not isinstance(marker, str) or not re.fullmatch(r"[a-f0-9]{32}", marker):
        raise ValueError("owned inode marker invalid")
    unnamed_flag = getattr(os, "O_TMPFILE", 0)
    if not unnamed_flag:
        raise RuntimeError("atomic unnamed inode creation is unavailable")
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    file_fd = -1
    try:
        value = os.fstat(directory_fd)
        path_value = directory.stat(follow_symlinks=False)
        if (value.st_dev, value.st_ino) != (path_value.st_dev, path_value.st_ino):
            raise ValueError("owned inode directory changed during creation")
        file_fd = os.open(".", os.O_WRONLY | unnamed_flag, 0o600, dir_fd=directory_fd)
        os.setxattr(file_fd, OWNER_XATTR, marker.encode("ascii"))
        library = ctypes.CDLL(None, use_errno=True)
        library.linkat.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        library.linkat.restype = ctypes.c_int
        linked = library.linkat(file_fd, b"", directory_fd, name.encode("ascii"), AT_EMPTY_PATH)
        if linked != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(directory / name))
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(directory_fd)


def status(token: str) -> dict[str, Any]:
    record = load_record(token)
    if record.get("cleanup_complete") is True:
        return record
    record, _, directory = validate_active(token)
    validate_files(directory, record)
    for mode in ("worker", "watchdog"):
        if not owned_process(record, mode):
            raise ValueError(mode + " process identity is not live")
    result = dict(record)
    result["statvfs"] = counters()
    return result


def stop_owned(record: dict[str, Any], mode: str) -> None:
    if owned_process(record, mode) and record[mode + "_pid"] != os.getpid():
        os.kill(record[mode + "_pid"], signal.SIGTERM)
        deadline = time.monotonic() + 3
        while owned_process(record, mode) and time.monotonic() < deadline:
            time.sleep(0.05)
        if owned_process(record, mode):
            os.kill(record[mode + "_pid"], signal.SIGKILL)
            deadline = time.monotonic() + 3
            while owned_process(record, mode) and time.monotonic() < deadline:
                time.sleep(0.05)
            if owned_process(record, mode):
                raise TimeoutError(mode + " process did not exit after SIGKILL")


def cleanup_partial_start(token: str, record: dict[str, Any]) -> dict[str, Any]:
    """Resume cleanup of exact startup effects recorded before activation."""
    resource = disk.verify()
    if record.get("boot_id") != disk.boot_identity():
        raise ValueError("partial run boot identity changed")
    if record.get("mapping") != resource.get("mapping"):
        raise ValueError("partial run mount identity changed")
    for field in (
        "lease_created",
        "lease_marker_applied",
        "lease_token_written",
        "directory_created",
        "directory_marker_applied",
    ):
        if type(record.get(field)) is not bool:
            raise ValueError("partial startup recovery metadata invalid")
    for mode in ("worker", "watchdog"):
        stop_owned(record, mode)
    if disk.mapping() != resource["mapping"]:
        raise ValueError("mount changed during partial startup cleanup")

    directory = token_directory(token)
    if record["directory_created"]:
        if directory.is_symlink():
            raise ValueError("partial inode directory symlink refused")
        if directory.exists():
            value = directory.stat(follow_symlinks=False)
            if (
                value.st_uid != 0
                or not stat.S_ISDIR(value.st_mode)
                or value.st_mode & 0o077
                or value.st_dev != record.get("directory_dev")
                or value.st_ino != record.get("directory_inode")
                or (
                    record["directory_marker_applied"]
                    and ownership_marker(directory) != record.get("directory_marker")
                )
            ):
                raise ValueError("partial inode directory identity changed")
            if any(directory.iterdir()):
                raise ValueError("unexpected partial inode directory contents; refuse cleanup")
            directory.rmdir()
        if directory.is_symlink() or directory.exists():
            raise ValueError("partial inode directory replacement refused after removal")

    if record["lease_created"]:
        if LEASE.is_symlink():
            raise ValueError("partial inode lease symlink refused")
        if LEASE.exists():
            value = LEASE.stat(follow_symlinks=False)
            if (
                value.st_uid != 0
                or not stat.S_ISREG(value.st_mode)
                or value.st_nlink != 1
                or value.st_mode & 0o077
                or value.st_dev != record.get("lease_dev")
                or value.st_ino != record.get("lease_inode")
                or (
                    record["lease_marker_applied"]
                    and ownership_marker(LEASE) != record.get("lease_marker")
                )
            ):
                raise ValueError("partial inode lease identity changed")
            if record["lease_token_written"]:
                try:
                    lease = json.loads(LEASE.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    raise ValueError("partial inode lease metadata invalid") from exc
                if not isinstance(lease, dict) or lease.get("token") != token:
                    raise ValueError("partial inode lease token identity changed")
            LEASE.unlink()
        if LEASE.is_symlink() or LEASE.exists():
            raise ValueError("partial inode lease replacement refused after removal")

    record["cleanup_complete"] = True
    record["cleanup_utc"] = datetime.now(UTC).isoformat()
    record["cleanup_reason"] = "partial_start_recovery"
    record["recovery_statvfs"] = counters()
    disk.save(run_path(token), record)
    return record


def cleanup(token: str) -> dict[str, Any]:
    record = load_record(token)
    if record.get("cleanup_complete") is True:
        return record
    if record.get("startup_partial") is True:
        return cleanup_partial_start(token, record)
    phases = {
        None,
        "files_authorized_for_deletion",
        "directory_removal_authorized",
        "lease_removal_authorized",
    }
    phase = record.get("cleanup_phase")
    if phase not in phases:
        raise ValueError("unknown inode cleanup phase")
    resource = disk.verify()
    if record.get("boot_id") != disk.boot_identity():
        raise ValueError("active run boot identity changed")
    if record.get("mapping") != resource.get("mapping"):
        raise ValueError("active run mount identity changed")
    lease_present = validate_lease(record, allow_absent=phase == "lease_removal_authorized")
    directory = token_directory(token)
    if directory.is_symlink():
        raise ValueError("owned inode directory symlink refused")
    directory_present = directory.exists()
    if directory_present:
        owned_directory(directory, record)
        if phase == "lease_removal_authorized":
            raise ValueError("owned inode directory was replaced after removal")
    elif phase not in ("directory_removal_authorized", "lease_removal_authorized"):
        raise ValueError("owned inode directory is missing before authorized removal")
    for mode in ("worker", "watchdog"):
        stop_owned(record, mode)
    if disk.mapping() != resource["mapping"]:
        raise ValueError("mount changed during cleanup")
    if directory_present:
        validate_files(directory, record)
        # Authorize the entire already-validated manifest in one atomic ledger write.
        # After this point each exact file may be present or absent, so a retry can
        # resume linearly after any unlink acknowledgement or signal failure.
        for item in record["files"]:
            path = directory / item["name"]
            if item["state"] == "pending":
                if not path.exists():
                    item["state"] = "deleting"
                    continue
                marker = item.get("marker") or secrets.token_hex(16)
                if item.get("marker") is None:
                    os.setxattr(path, OWNER_XATTR, marker.encode("ascii"), follow_symlinks=False)
                value = path.stat(follow_symlinks=False)
                item.update(
                    state="deleting",
                    dev=value.st_dev,
                    inode=value.st_ino,
                    ctime_ns=value.st_ctime_ns,
                    marker=marker,
                )
            else:
                item["state"] = "deleting"
        record["cleanup_phase"] = "files_authorized_for_deletion"
        disk.save(run_path(token), record)
        validate_files(directory, record)
        for item in record["files"]:
            path = directory / item["name"]
            if cleanup_file_present(path, item):
                path.unlink()
        validate_files(directory, record)
        owned_directory(directory, record)
        record["cleanup_phase"] = "directory_removal_authorized"
        disk.save(run_path(token), record)
        directory.rmdir()
    if directory.is_symlink() or directory.exists():
        raise ValueError("owned inode directory replacement refused after removal")
    if record.get("cleanup_phase") != "lease_removal_authorized":
        record["cleanup_phase"] = "lease_removal_authorized"
        disk.save(run_path(token), record)
    if lease_present:
        validate_lease(record, allow_absent=False)
        LEASE.unlink()
    if LEASE.is_symlink() or LEASE.exists():
        raise ValueError("inode lease replacement refused after removal")
    record["cleanup_complete"] = True
    record["cleanup_utc"] = datetime.now(UTC).isoformat()
    record["recovery_statvfs"] = counters()
    disk.save(run_path(token), record)
    return record


def launch(mode: str, token: str, duration: int) -> subprocess.Popen[bytes]:
    with (RUNS / (token + ".log")).open("ab") as log:
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
    if type(duration) is not int or not 2 <= duration <= 240:
        raise ValueError("duration must be 2..240 seconds")
    path = run_path(token)
    resource = disk.verify()
    baseline = counters()
    if baseline["inode_usage_percent"] >= HEALTHY_PERCENT:
        raise ValueError("fresh healthy inode baseline required")
    if baseline["block_usage_percent"] >= BLOCK_GUARD_PERCENT:
        raise ValueError("block headroom below inode guard")
    if path.exists():
        raise ValueError("run token already exists; use explicit cleanup")
    if DISK_LEASE.exists():
        raise ValueError("disk injection lease is active")
    directory = token_directory(token)
    lease_dev = lease_inode = directory_inode = directory_dev = None
    lease_fd = lease_authority_fd = directory_authority_fd = -1
    lease_created = directory_created = False
    lease_marker_applied = lease_token_written = directory_marker_applied = False
    record: dict[str, Any] = {
        "token": token,
        "boot_id": disk.boot_identity(),
        "mapping": resource["mapping"],
        "files": [],
        "baseline_statvfs": baseline,
        "max_duration_seconds": duration,
        "started_utc": datetime.now(UTC).isoformat(),
        "cleanup_complete": False,
    }
    launched: list[subprocess.Popen[bytes]] = []

    def startup_interrupted(signum: int, frame: object) -> None:
        raise InterruptedError(f"inode startup interrupted by signal {signum}")

    previous_handlers = {
        current: signal.signal(current, startup_interrupted)
        for current in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        lease_marker = secrets.token_hex(16)
        with deferred_start_signals():
            lease_fd = os.open(
                LEASE,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            lease_created = True
            lease_value = os.fstat(lease_fd)
            lease_dev, lease_inode = lease_value.st_dev, lease_value.st_ino
            record.update(
                lease_dev=lease_dev,
                lease_inode=lease_inode,
                lease_marker=lease_marker,
            )
            lease_authority_fd = os.dup(lease_fd)
        with deferred_start_signals():
            os.setxattr(lease_fd, OWNER_XATTR, lease_marker.encode("ascii"))
            lease_marker_applied = True
        with deferred_start_signals():
            token_bytes = json.dumps({"token": token}).encode("utf-8")
            if os.write(lease_fd, token_bytes) != len(token_bytes):
                raise OSError("short inode lease write")
            lease_token_written = True
        directory_marker = secrets.token_hex(16)
        record["directory_marker"] = directory_marker
        with deferred_start_signals():
            directory.mkdir(mode=0o700)
            directory_created = True
            directory_value = directory.stat(follow_symlinks=False)
            directory_inode, directory_dev = directory_value.st_ino, directory_value.st_dev
            record.update(directory_inode=directory_inode, directory_dev=directory_dev)
            os.setxattr(
                directory,
                OWNER_XATTR,
                directory_marker.encode("ascii"),
                follow_symlinks=False,
            )
            directory_marker_applied = True
            directory_authority_fd = os.open(
                directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            authority = os.fstat(directory_authority_fd)
            if (authority.st_dev, authority.st_ino) != (directory_dev, directory_inode):
                raise ValueError("inode directory changed during authority acquisition")
        disk.save(path, record)
        with deferred_start_signals():
            watchdog = launch("watchdog", token, duration)
            launched.append(watchdog)
            record["watchdog_pid"] = watchdog.pid
            record["watchdog_start"] = disk.process_identity(watchdog.pid)
            disk.save(path, record)
        with deferred_start_signals():
            worker_process = launch("worker", token, duration)
            launched.append(worker_process)
            record["worker_pid"] = worker_process.pid
            record["worker_start"] = disk.process_identity(worker_process.pid)
            disk.save(path, record)
        os.close(directory_authority_fd)
        directory_authority_fd = -1
        os.close(lease_authority_fd)
        lease_authority_fd = -1
        os.close(lease_fd)
        lease_fd = -1
        for current, previous in previous_handlers.items():
            signal.signal(current, previous)
        return record
    except BaseException as start_error:
        for current, previous in previous_handlers.items():
            signal.signal(current, previous)
        for process in launched:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        rollback_proven = False
        try:
            if disk.mapping() == resource["mapping"]:
                directory_effect_absent = not directory_created
                if directory_created:
                    if not directory.is_symlink() and directory.exists():
                        value = directory.stat(follow_symlinks=False)
                        authority_identity = (directory_dev, directory_inode)
                        if directory_authority_fd >= 0:
                            authority = os.fstat(directory_authority_fd)
                            authority_identity = (authority.st_dev, authority.st_ino)
                        exact_directory = (
                            (value.st_dev, value.st_ino) == authority_identity
                            and value.st_uid == 0
                            and stat.S_ISDIR(value.st_mode)
                            and not value.st_mode & 0o077
                            and (
                                not directory_marker_applied
                                or ownership_marker(directory) == record["directory_marker"]
                            )
                        )
                        if exact_directory and not any(directory.iterdir()):
                            directory.rmdir()
                    directory_effect_absent = not directory.is_symlink() and not directory.exists()
                lease_effect_absent = not lease_created
                if directory_effect_absent and lease_created:
                    if not LEASE.is_symlink() and LEASE.exists():
                        value = LEASE.stat(follow_symlinks=False)
                        authority_identity = (lease_dev, lease_inode)
                        authority_fd = lease_authority_fd if lease_authority_fd >= 0 else lease_fd
                        if authority_fd >= 0:
                            authority = os.fstat(authority_fd)
                            authority_identity = (authority.st_dev, authority.st_ino)
                        exact_lease = (
                            (value.st_dev, value.st_ino) == authority_identity
                            and value.st_uid == 0
                            and stat.S_ISREG(value.st_mode)
                            and value.st_nlink == 1
                            and not value.st_mode & 0o077
                            and (
                                not lease_marker_applied
                                or ownership_marker(LEASE) == record["lease_marker"]
                            )
                        )
                        if exact_lease and lease_token_written:
                            exact_lease = json.loads(LEASE.read_text()).get("token") == token
                        if exact_lease:
                            LEASE.unlink()
                    lease_effect_absent = not LEASE.is_symlink() and not LEASE.exists()
                rollback_proven = directory_effect_absent and lease_effect_absent
        except (OSError, TypeError, ValueError):
            rollback_proven = False
        finally:
            if directory_authority_fd >= 0:
                os.close(directory_authority_fd)
                directory_authority_fd = -1
            if lease_authority_fd >= 0:
                os.close(lease_authority_fd)
                lease_authority_fd = -1
            if lease_fd >= 0:
                os.close(lease_fd)
                lease_fd = -1
        record.update(
            lease_created=lease_created,
            lease_marker_applied=lease_marker_applied,
            lease_token_written=lease_token_written,
            directory_created=directory_created,
            directory_marker_applied=directory_marker_applied,
        )
        if rollback_proven:
            record["cleanup_phase"] = "lease_removal_authorized"
            record["cleanup_complete"] = True
            record["cleanup_utc"] = datetime.now(UTC).isoformat()
            record["cleanup_reason"] = "partial_start_rollback"
            record["recovery_statvfs"] = counters()
            try:
                disk.save(path, record)
            except BaseException as save_error:
                start_error.add_note(f"completed rollback record was not saved: {save_error}")
        else:
            record["startup_partial"] = True
            record["startup_error"] = f"{type(start_error).__name__}: {start_error}"
            try:
                disk.save(path, record)
            except BaseException as save_error:
                start_error.add_note(f"partial startup recovery record was not saved: {save_error}")
        raise


def save_worker_files(token: str, files: list[dict[str, Any]]) -> None:
    with (BASE / "control.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        record, _, directory = validate_active(token)
        owned_directory(directory, record)
        record["files"] = files
        record["injected_statvfs"] = counters()
        disk.save(run_path(token), record)


def worker(token: str, duration: int) -> None:
    def interrupted(signum: int, frame: object) -> None:
        raise InterruptedError("inode injector interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    deadline = time.monotonic() + duration
    files: list[dict[str, Any]] = []
    try:
        record, _, directory = validate_active(token)
        while time.monotonic() < deadline:
            current = counters()
            if current["block_usage_percent"] >= BLOCK_GUARD_PERCENT:
                raise ValueError("block guard lost during inode injection")
            if current["inode_usage_percent"] >= TARGET_PERCENT:
                save_worker_files(token, files)
                while time.monotonic() < deadline:
                    record, resource, directory = validate_active(token)
                    if resource["mapping"] != record["mapping"]:
                        raise ValueError("active inode mount identity changed")
                    validate_files(directory, record)
                    held = counters()
                    if held["block_usage_percent"] >= BLOCK_GUARD_PERCENT:
                        raise ValueError("block guard lost while holding inode injection")
                    if held["inode_usage_percent"] < TARGET_PERCENT:
                        break
                    time.sleep(0.25)
                else:
                    return
                continue
            pending: list[dict[str, Any]] = [
                item
                for item in files
                if item["state"] == "pending" and not (directory / item["name"]).exists()
            ]
            if not pending:
                remaining = MAX_INODES - len(files)
                if remaining <= 0:
                    raise ValueError("bounded inode file limit reached before target")
                for _ in range(min(CREATION_BATCH, remaining)):
                    name = f"f-{len(files):04d}"
                    planned: dict[str, Any] = {
                        "name": name,
                        "state": "pending",
                        "marker": secrets.token_hex(16),
                    }
                    files.append(planned)
                    pending.append(planned)
                # Persist the bounded batch of exact names and markers before any create.
                save_worker_files(token, files)
            for item in pending:
                current = counters()
                if current["block_usage_percent"] >= BLOCK_GUARD_PERCENT:
                    raise ValueError("block guard lost during inode injection")
                if current["inode_usage_percent"] >= TARGET_PERCENT:
                    break
                value = create_owned_file(directory, item)
                item.update(
                    state="created",
                    dev=value.st_dev,
                    inode=value.st_ino,
                    ctime_ns=value.st_ctime_ns,
                )
                time.sleep(0.002)
            save_worker_files(token, files)
        raise TimeoutError("inode target not reached before deadline")
    finally:
        try:
            save_worker_files(token, files)
        finally:
            main_cleanup(token)


def main_cleanup(token: str) -> None:
    with (BASE / "control.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cleanup(token)


def request_cleanup(token: str) -> dict[str, Any]:
    """Let the worker perform its owned cleanup without deadlocking on control.lock."""
    with (BASE / "control.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        record = load_record(token)
        if record.get("cleanup_complete") is True:
            return record
        if record.get("cleanup_phase") is not None:
            return cleanup(token)
        validate_active(token)
        if owned_process(record, "worker"):
            os.kill(record["worker_pid"], signal.SIGTERM)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        latest = load_record(token)
        if latest.get("cleanup_complete") is True:
            return latest
        time.sleep(0.05)
    with (BASE / "control.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return cleanup(token)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("probe", "start", "status", "cleanup", "worker", "watchdog")
    )
    parser.add_argument("--token", default="")
    parser.add_argument("--duration", type=int, default=180)
    args = parser.parse_args()
    if not 2 <= args.duration <= 240:
        parser.error("duration must be 2..240 seconds")

    def interrupted(signum: int, frame: object) -> None:
        raise InterruptedError("inode helper interrupted")

    if args.action != "watchdog":
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
    safe_directory()
    if args.action in ("worker", "watchdog"):
        if args.action == "worker":
            worker(args.token, args.duration)
        else:
            time.sleep(args.duration + 2)
            main_cleanup(args.token)
        return
    if args.action == "cleanup":
        print(json.dumps(request_cleanup(args.token)))
        return
    with (BASE / "control.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = (
            probe()
            if args.action == "probe"
            else start(args.token, args.duration)
            if args.action == "start"
            else status(args.token)
            if args.action == "status"
            else probe()
        )
        print(json.dumps(result))


if __name__ == "__main__":
    main()
