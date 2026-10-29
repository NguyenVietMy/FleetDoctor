#!/usr/bin/env python3
"""Root-only durable resolver fault helper for disposable Linux namespaces."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

BASE = Path("/run/fleetdoctor/dns")
LEASE = BASE / "lease.json"
LOCK = BASE / "control.lock"
RUNS = BASE / "runs"
RESOLV_CONF = Path("/etc/resolv.conf")
MAX_FILE = 32 * 1024
MAX_METADATA = 64 * 1024


def _now() -> str:
    return datetime.now(UTC).isoformat()


def run_path(token: str) -> Path:
    if re.fullmatch(r"[a-f0-9]{32}", token) is None:
        raise ValueError("token must contain exactly 32 lowercase hexadecimal characters")
    return RUNS / f"{token}.json"


def _trusted_directory(path: Path, mode: int) -> None:
    if path.is_symlink():
        raise ValueError("DNS helper directory symlink refused")
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    value = path.stat(follow_symlinks=False)
    if value.st_uid != 0 or not stat.S_ISDIR(value.st_mode) or value.st_mode & 0o077:
        raise ValueError("DNS helper directory must be root-only")


def safe_base() -> None:
    if os.geteuid() != 0:
        raise PermissionError("DNS helper requires root")
    for ancestor in (Path("/run"), BASE.parent):
        if ancestor.is_symlink():
            raise ValueError("DNS helper ancestor symlink refused")
        if ancestor.exists():
            value = ancestor.stat(follow_symlinks=False)
            if value.st_uid != 0 or not stat.S_ISDIR(value.st_mode) or value.st_mode & 0o022:
                raise ValueError("DNS helper ancestor is not trusted")
    BASE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _trusted_directory(BASE, 0o700)
    _trusted_directory(RUNS, 0o700)
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    value = LOCK.stat(follow_symlinks=False)
    if value.st_uid != 0 or not stat.S_ISREG(value.st_mode) or value.st_mode & 0o077:
        raise ValueError("DNS helper lock must be root-only")


@contextmanager
def locked() -> Iterator[None]:
    fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW)
    try:
        deadline = time.monotonic() + 2
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError("DNS helper lock deadline exceeded") from exc
                time.sleep(0.02)
        yield
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path: Path, value: dict[str, Any]) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_METADATA:
        raise ValueError("DNS helper metadata exceeds 64KiB")
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short DNS helper metadata write")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def load(path: Path) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        value = os.fstat(fd)
        if value.st_uid != 0 or not stat.S_ISREG(value.st_mode) or value.st_mode & 0o077:
            raise ValueError("untrusted DNS helper metadata")
        data = os.read(fd, MAX_METADATA + 1)
        if len(data) > MAX_METADATA:
            raise ValueError("DNS helper metadata exceeds 64KiB")
    finally:
        os.close(fd)
    decoded = json.loads(data)
    if not isinstance(decoded, dict):
        raise ValueError("DNS helper metadata must be an object")
    return decoded


def process_identity(pid: int) -> dict[str, int | str] | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()
        argv = Path(f"/proc/{pid}/cmdline").read_bytes()
        return {
            "pid": pid,
            "starttime": int(fields[19]),
            "argv_sha256": hashlib.sha256(argv).hexdigest(),
            "proc_state": fields[0],
        }
    except (FileNotFoundError, IndexError, OSError, ValueError):
        return None


def _owned_process_state(pid: int, expected: dict[str, Any]) -> str:
    """Return absent, foreign, zombie, or live for one retained PID/start/argv identity."""
    current = process_identity(pid)
    if current is None or any(
        current.get(field) != expected.get(field) for field in ("pid", "starttime")
    ):
        return "absent"
    if current.get("proc_state") == "Z":
        return "zombie"
    expected_argv = expected.get("argv_sha256")
    if expected_argv is not None and current.get("argv_sha256") != expected_argv:
        return "foreign"
    return "live"


def namespace_identity() -> dict[str, Any]:
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    result: dict[str, Any] = {"boot_id": boot}
    for name in ("mnt", "net"):
        value = os.stat(f"/proc/self/ns/{name}")
        result[name] = {"device": value.st_dev, "inode": value.st_ino}
    return result


def _read_exact(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        chunks: list[bytes] = []
        remaining = MAX_FILE + 1
        while remaining:
            chunk = os.read(fd, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE:
        raise ValueError("resolver exceeds 32KiB")
    return data


def _stat_identity(value: os.stat_result) -> dict[str, int]:
    return {
        "mode": stat.S_IMODE(value.st_mode),
        "uid": value.st_uid,
        "gid": value.st_gid,
        "device": value.st_dev,
        "inode": value.st_ino,
        "links": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _read_symlink_target(path: Path) -> tuple[bytes, dict[str, int]]:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise ValueError("resolver symlink target must be a trusted regular file")
        chunks: list[bytes] = []
        remaining = MAX_FILE + 1
        while remaining:
            chunk = os.read(fd, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > MAX_FILE:
            raise ValueError("resolver target exceeds 32KiB")
        after = os.fstat(fd)
        if _stat_identity(after) != _stat_identity(before):
            raise RuntimeError("resolver symlink target changed during snapshot")
        return content, _stat_identity(before)
    finally:
        os.close(fd)


def _unescape_mount(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _mount_identity(path: Path) -> dict[str, Any]:
    """Return the exact longest mount entry owning path without resolving symlinks."""
    absolute = os.path.abspath(path)
    matches: list[tuple[int, dict[str, Any]]] = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        fields, after = left.split(), right.split()
        if len(fields) < 6 or len(after) < 2:
            continue
        mountpoint = _unescape_mount(fields[4])
        if absolute == mountpoint or absolute.startswith(mountpoint.rstrip("/") + "/"):
            matches.append(
                (
                    len(mountpoint),
                    {
                        "mount_id": int(fields[0]),
                        "parent_id": int(fields[1]),
                        "major_minor": fields[2],
                        "root": _unescape_mount(fields[3]),
                        "mountpoint": mountpoint,
                        "filesystem": after[0],
                        "source": _unescape_mount(after[1]),
                    },
                )
            )
    if not matches:
        raise RuntimeError("resolver mount identity unavailable")
    return max(matches, key=lambda item: item[0])[1]


def snapshot() -> dict[str, Any]:
    entry = RESOLV_CONF.lstat()
    if entry.st_nlink != 1 or entry.st_uid != 0:
        raise ValueError("resolver entry must be root-owned and singly linked")
    entry_type = "symlink" if RESOLV_CONF.is_symlink() else "regular"
    if entry_type == "regular" and not stat.S_ISREG(entry.st_mode):
        raise ValueError("unsupported resolver entry type")
    link_target = os.readlink(RESOLV_CONF) if entry_type == "symlink" else None
    if entry_type == "symlink":
        content, target = _read_symlink_target(RESOLV_CONF)
        entry_after = RESOLV_CONF.lstat()
        if (
            _stat_identity(entry_after) != _stat_identity(entry)
            or os.readlink(RESOLV_CONF) != link_target
        ):
            raise RuntimeError("resolver symlink entry changed during snapshot")
    else:
        content = _read_exact(RESOLV_CONF)
        target = None
    return {
        "entry_type": entry_type,
        "link_target": link_target,
        "target": target,
        "mode": stat.S_IMODE(entry.st_mode),
        "uid": entry.st_uid,
        "gid": entry.st_gid,
        "device": entry.st_dev,
        "inode": entry.st_ino,
        "links": entry.st_nlink,
        "mount": _mount_identity(RESOLV_CONF),
        "content_hex": content.hex(),
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "namespace": namespace_identity(),
    }


def _current_entry() -> dict[str, Any]:
    try:
        value = snapshot()
    except (FileNotFoundError, OSError, ValueError):
        return {"entry_type": "missing", "content_sha256": None}
    return value


def _write_regular(content: bytes, metadata: dict[str, Any]) -> None:
    replacing_symlink = RESOLV_CONF.is_symlink()
    if replacing_symlink:
        RESOLV_CONF.unlink()
        fd = os.open(RESOLV_CONF, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    else:
        fd = os.open(RESOLV_CONF, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    try:
        offset = 0
        while offset < len(content):
            written = os.write(fd, content[offset:])
            if written <= 0:
                raise OSError("short resolver write")
            offset += written
        os.fsync(fd)
        os.fchmod(fd, 0o644 if replacing_symlink else int(metadata["mode"]))
        os.fchown(
            fd,
            0 if replacing_symlink else int(metadata["uid"]),
            0 if replacing_symlink else int(metadata["gid"]),
        )
    finally:
        os.close(fd)


def _restore_entry(original: dict[str, Any]) -> None:
    content = bytes.fromhex(str(original["content_hex"]))
    if original["entry_type"] == "regular":
        _write_regular(content, original)
    else:
        if RESOLV_CONF.exists() or RESOLV_CONF.is_symlink():
            RESOLV_CONF.unlink()
        os.symlink(str(original["link_target"]), RESOLV_CONF)
        os.lchown(RESOLV_CONF, int(original["uid"]), int(original["gid"]))
    _fsync_directory(RESOLV_CONF.parent)


def _matching_namespace(record: dict[str, Any]) -> bool:
    return bool(record.get("original", {}).get("namespace") == namespace_identity())


def _owned_lease(record: dict[str, Any]) -> bool:
    if not LEASE.exists():
        return False
    try:
        lease = load(LEASE)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return bool(
        lease.get("token") == record.get("token")
        and lease.get("intent_sha256") == record.get("intent_sha256")
        and lease.get("namespace") == record.get("original", {}).get("namespace")
        and lease.get("complete") is True
    )


def _lease_value(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "complete": True,
        "token": record["token"],
        "intent_sha256": record["intent_sha256"],
        "namespace": record["original"]["namespace"],
    }


def _remove_owned_candidate(record: dict[str, Any]) -> None:
    name = record.get("lease_candidate")
    expected = f"lease.{record.get('token')}.prepared"
    if name != expected:
        return
    candidate = BASE / expected
    if not candidate.exists():
        return
    value = candidate.stat(follow_symlinks=False)
    if (
        value.st_uid != 0
        or not stat.S_ISREG(value.st_mode)
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_nlink not in {1, 2}
        or load(candidate) != _lease_value(record)
    ):
        raise RuntimeError("foreign DNS lease candidate refused")
    if LEASE.exists() and os.path.samestat(value, LEASE.stat(follow_symlinks=False)) is False:
        raise RuntimeError("DNS lease candidate identity mismatch")
    candidate.unlink()
    _fsync_directory(BASE)


def _same_fields(
    current: dict[str, Any], expected: dict[str, Any], fields: tuple[str, ...]
) -> bool:
    return all(current.get(field) == expected.get(field) for field in fields)


def _exact_entry(current: dict[str, Any], expected: dict[str, Any]) -> bool:
    return _same_fields(
        current,
        expected,
        (
            "entry_type",
            "link_target",
            "target",
            "mode",
            "uid",
            "gid",
            "device",
            "inode",
            "links",
            "mount",
            "content_sha256",
            "namespace",
        ),
    )


def _restored_entry(current: dict[str, Any], original: dict[str, Any]) -> bool:
    fields = (
        "entry_type",
        "link_target",
        "target",
        "mode",
        "uid",
        "gid",
        "links",
        "mount",
        "content_sha256",
        "namespace",
    )
    if not _same_fields(current, original, fields):
        return False
    return original["entry_type"] == "symlink" or _same_fields(
        current, original, ("device", "inode")
    )


def _permitted_partial(record: dict[str, Any], current: dict[str, Any]) -> bool:
    if record.get("phase") not in {"write_intent", "start_failed"}:
        return False
    original = record["original"]
    if current.get("entry_type") == "missing":
        return bool(
            original.get("entry_type") == "symlink"
            and record.get("symlink_unlink_authorized") is True
            and original.get("namespace") == namespace_identity()
            and original.get("mount") == _mount_identity(RESOLV_CONF)
        )
    try:
        content = bytes.fromhex(str(current["content_hex"]))
        injected = bytes.fromhex(str(record["injected_hex"]))
    except (KeyError, ValueError):
        return False
    if current.get("entry_type") != "regular" or not injected.startswith(content):
        return False
    if current.get("namespace") != original.get("namespace") or current.get(
        "mount"
    ) != original.get("mount"):
        return False
    if current.get("links") != 1:
        return False
    if original["entry_type"] == "regular":
        return _same_fields(current, original, ("device", "inode", "mode", "uid", "gid"))
    return (
        current.get("uid") == 0
        and current.get("gid") == 0
        and current.get("mode")
        in {
            0o600,
            0o644,
        }
    )


def _permitted_current(record: dict[str, Any]) -> bool:
    current = _current_entry()
    if _exact_entry(current, record["original"]):
        return True
    restored = record.get("restored_entry")
    if isinstance(restored, dict) and _exact_entry(current, restored):
        return True
    active = record.get("active_entry")
    if isinstance(active, dict) and _exact_entry(current, active):
        return True
    return _permitted_partial(record, current)


def _watchdog_update(
    path: Path, expected_phases: set[str], **changes: Any
) -> dict[str, Any] | None:
    """Serialize a child update and refuse to resurrect completed or newer state."""
    try:
        with locked():
            current = load(path)
            if current.get("cleanup_complete") or current.get("phase") not in expected_phases:
                return None
            current.update(changes)
            save(path, current)
            return current
    except (FileNotFoundError, OSError, TimeoutError, ValueError, json.JSONDecodeError):
        return None


def cleanup_locked(record: dict[str, Any], *, reason: str) -> dict[str, Any]:
    resuming_after_unlink = record.get("cleanup_phase") == "lease_removal_pending"
    if LEASE.exists():
        if not _owned_lease(record):
            raise RuntimeError("foreign DNS lease refused")
    elif not resuming_after_unlink:
        raise RuntimeError("owned DNS lease missing; cleanup refused")
    if not _matching_namespace(record):
        raise RuntimeError("DNS helper namespace identity changed")
    if not _permitted_current(record):
        raise RuntimeError("foreign resolver change refused")
    original = record["original"]
    current = _current_entry()
    if (
        current.get("content_sha256") != original["content_sha256"]
        or current.get("entry_type") != original["entry_type"]
    ):
        _restore_entry(original)
    restored = _current_entry()
    if not _restored_entry(restored, original):
        raise RuntimeError("resolver restoration verification failed")
    record.update(cleanup_phase="lease_removal_pending", restored_entry=restored)
    save(run_path(str(record["token"])), record)
    if LEASE.exists():
        LEASE.unlink()
        _fsync_directory(BASE)
    _remove_owned_candidate(record)
    record.update(
        phase="cleaned",
        cleanup_phase="complete",
        cleanup_complete=True,
        cleanup_reason=reason,
        cleaned_at=_now(),
        completed_monotonic=time.monotonic(),
    )
    save(run_path(str(record["token"])), record)
    return record


def _watchdog(token: str, parent_pid: int, ready_fd: int, control_fd: int) -> int:
    path = run_path(token)
    try:
        prepared = load(path)
        if (
            prepared.get("phase") != "prepared"
            or _owned_process_state(parent_pid, prepared.get("parent", {})) != "live"
            or not _matching_namespace(prepared)
        ):
            return 9
        os.write(ready_fd, b"READY\n")
        try:
            _wait_line(control_fd, b"IDENTITY\n", time.monotonic() + 2)
        except (OSError, TimeoutError):
            if _owned_process_state(parent_pid, prepared.get("parent", {})) != "live":
                _watchdog_update(
                    path,
                    {"prepared"},
                    phase="abandoned_prelease",
                    cleanup_complete=True,
                    cleanup_reason="parent_lost_before_identity_handoff",
                )
                return 0
            raise
        record = load(path)
        if record.get("phase") != "watchdog_identity_pending" or not _matching_namespace(record):
            return 10
        identity = process_identity(os.getpid())
        if (
            identity is None
            or _owned_process_state(os.getpid(), record.get("watchdog", {})) != "live"
        ):
            return 11
        os.write(ready_fd, b"ARMED\n")
        os.close(ready_fd)
        active = False
        deadline = float(record["deadline_monotonic"])
        while True:
            if time.monotonic() >= deadline:
                reason = "deadline"
                break
            try:
                command = os.read(control_fd, 16)
            except BlockingIOError:
                command = b""
            if command == b"AUTHORITY\n":
                current = load(path)
                if not _owned_lease(current):
                    return 12
                os.write(control_fd, b"AUTHORIZED\n")
            elif command == b"ACTIVE\n":
                active = True
            elif command == b"CLEANUP\n":
                reason = "explicit"
                break
            current = load(path)
            if current.get("cleanup_complete"):
                return 0
            parent_alive = _owned_process_state(parent_pid, current.get("parent", {})) == "live"
            if not active and not parent_alive:
                reason = "parent_lost_during_establishment"
                break
            time.sleep(0.05)
        with locked():
            current = load(path)
            if current.get("cleanup_complete"):
                return 0
            if not LEASE.exists():
                _remove_owned_candidate(current)
                current.update(
                    phase="abandoned_prelease", cleanup_complete=True, cleanup_reason=reason
                )
                save(path, current)
                return 0
            if _owned_lease(current):
                cleanup_locked(current, reason=reason)
                return 0
            return 13
    except BaseException as exc:
        _watchdog_update(
            path,
            {
                "prepared",
                "watchdog_identity_pending",
                "watchdog_armed",
                "lease_publication_pending",
                "write_intent",
                "active",
                "start_failed",
            },
            watchdog_error=f"{type(exc).__name__}:{exc}"[:512],
            watchdog_failed_at=_now(),
        )
        return 14
    finally:
        for fd in (ready_fd, control_fd):
            try:
                os.close(fd)
            except OSError:
                pass


def _wait_line(fd: int, expected: bytes, deadline: float) -> None:
    ready, _, _ = select.select([fd], [], [], max(0.0, deadline - time.monotonic()))
    if not ready or os.read(fd, len(expected)) != expected:
        raise TimeoutError("DNS watchdog handshake failed")


def _send_control(fd: int, value: bytes) -> None:
    if os.write(fd, value) != len(value):
        raise OSError("short DNS watchdog control write")


def _terminate_watchdog(
    record: dict[str, Any], process: subprocess.Popen[bytes] | None = None
) -> None:
    identity = record.get("watchdog")
    if process is not None:
        if isinstance(identity, dict) and process.pid != int(identity.get("pid", 0)):
            raise RuntimeError("watchdog process handle identity mismatch")
        if process.poll() is not None:
            process.wait(timeout=0)
            return
        if isinstance(identity, dict):
            state = _owned_process_state(process.pid, identity)
            if state == "foreign":
                raise RuntimeError("watchdog PID/start identity now belongs to foreign argv")
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
        return
    if not isinstance(identity, dict):
        return
    pid = int(identity.get("pid", 0))
    state = _owned_process_state(pid, identity)
    if state == "absent":
        return
    if state == "foreign":
        raise RuntimeError("watchdog PID/start identity now belongs to foreign argv")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 1
    while _owned_process_state(pid, identity) != "absent" and time.monotonic() < deadline:
        time.sleep(0.02)
    if _owned_process_state(pid, identity) != "absent":
        os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 1
        while _owned_process_state(pid, identity) != "absent" and time.monotonic() < deadline:
            time.sleep(0.02)
        remaining = _owned_process_state(pid, identity)
        if remaining != "absent":
            raise RuntimeError(f"owned DNS watchdog not reaped: {remaining}")


def start(token: str, invalid_resolver: str, duration: int) -> dict[str, Any]:
    import ipaddress

    address = ipaddress.ip_address(invalid_resolver)
    if str(address) != invalid_resolver or address.is_unspecified or address.is_multicast:
        raise ValueError("invalid resolver injection must be a canonical numeric address")
    if not 1 <= duration <= 300:
        raise ValueError("duration must be 1..300 seconds")
    safe_base()
    path = run_path(token)
    injected = f"nameserver {invalid_resolver}\n".encode("ascii")
    ready_read = ready_write = parent_control = child_control = -1
    process: subprocess.Popen[bytes] | None = None
    candidate: Path | None = None
    record: dict[str, Any]
    with locked():
        if LEASE.exists():
            raise RuntimeError("DNS helper lease already exists")
        if path.exists():
            raise RuntimeError("DNS helper token already exists")
        original = snapshot()
        parent = process_identity(os.getpid())
        if parent is None:
            raise RuntimeError("parent process identity unavailable")
        record = {
            "version": 1,
            "token": token,
            "phase": "prepared",
            "cleanup_complete": False,
            "created_at": _now(),
            "deadline_monotonic": time.monotonic() + duration,
            "parent": parent,
            "original": original,
            "injected_hex": injected.hex(),
            "injected_sha256": hashlib.sha256(injected).hexdigest(),
        }
        intent = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        record["intent_sha256"] = hashlib.sha256(intent).hexdigest()
        save(path, record)
        try:
            ready_read, ready_write = os.pipe()
            parent_socket, child_socket = socket.socketpair()
            parent_control, child_control = parent_socket.detach(), child_socket.detach()
            os.set_blocking(parent_control, False)
            os.set_blocking(child_control, False)
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "watchdog",
                    "--token",
                    token,
                    "--parent-pid",
                    str(os.getpid()),
                    "--ready-fd",
                    str(ready_write),
                    "--control-fd",
                    str(child_control),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(ready_write, child_control),
            )
            os.close(ready_write)
            ready_write = -1
            os.close(child_control)
            child_control = -1
            _wait_line(ready_read, b"READY\n", time.monotonic() + 2)
            identity = process_identity(process.pid)
            if identity is None:
                raise RuntimeError("watchdog identity unavailable")
            record.update(phase="watchdog_identity_pending", watchdog=identity)
            save(path, record)
            _send_control(parent_control, b"IDENTITY\n")
            _wait_line(ready_read, b"ARMED\n", time.monotonic() + 2)
            record.update(phase="watchdog_armed", watchdog_armed_at=_now())
            save(path, record)
            lease = _lease_value(record)
            candidate = BASE / f"lease.{token}.prepared"
            record.update(
                phase="lease_publication_pending",
                lease_candidate=candidate.name,
            )
            save(path, record)
            save(candidate, lease)
            os.link(candidate, LEASE)
            candidate.unlink()
            _fsync_directory(BASE)
            if not _owned_lease(record):
                raise RuntimeError("DNS lease authority verification failed")
            _send_control(parent_control, b"AUTHORITY\n")
            _wait_line(parent_control, b"AUTHORIZED\n", time.monotonic() + 2)
            record.update(
                phase="write_intent",
                lease_published=True,
                authority_confirmed=True,
                symlink_unlink_authorized=original["entry_type"] == "symlink",
            )
            save(path, record)
            if (
                not _permitted_current(record)
                or _current_entry()["content_sha256"] != original["content_sha256"]
            ):
                raise RuntimeError("resolver changed before owned mutation")
            _write_regular(injected, original)
            active_entry = _current_entry()
            if active_entry["content_sha256"] != record["injected_sha256"]:
                raise RuntimeError("resolver injection verification failed")
            record.update(phase="active", active_at=_now(), active_entry=active_entry)
            save(path, record)
            _send_control(parent_control, b"ACTIVE\n")
            return record
        except BaseException as exc:
            secondary_errors: list[str] = []
            record.update(phase="start_failed", start_error=f"{type(exc).__name__}:{exc}"[:512])
            try:
                if LEASE.exists() and _owned_lease(record):
                    cleanup_locked(record, reason="start_failed")
                elif LEASE.exists():
                    record.update(
                        cleanup_complete=False,
                        cleanup_error="foreign DNS lease prevents start rollback",
                    )
                    save(path, record)
                elif record.get("lease_published"):
                    record.update(
                        cleanup_complete=False,
                        cleanup_error="owned DNS lease missing during start rollback",
                    )
                    save(path, record)
                else:
                    _remove_owned_candidate(record)
                    record.update(cleanup_complete=True, cleanup_reason="failed_before_lease")
                    save(path, record)
            except BaseException as cleanup_exc:
                secondary_errors.append(f"cleanup:{type(cleanup_exc).__name__}:{cleanup_exc}"[:512])
                record.update(
                    cleanup_complete=False,
                    cleanup_error=f"{type(cleanup_exc).__name__}:{cleanup_exc}"[:512],
                )
                try:
                    save(path, record)
                except BaseException as save_exc:
                    secondary_errors.append(
                        f"failure_save:{type(save_exc).__name__}:{save_exc}"[:512]
                    )
            owned_unresolved = (
                LEASE.exists() and _owned_lease(record) and not record.get("cleanup_complete")
            )
            if owned_unresolved:
                record["watchdog_retained_for_recovery"] = True
            elif process is not None:
                try:
                    _terminate_watchdog(record, process)
                except BaseException as reap_exc:
                    secondary_errors.append(
                        f"watchdog_reap:{type(reap_exc).__name__}:{reap_exc}"[:512]
                    )
            if secondary_errors:
                record["secondary_errors"] = secondary_errors
                try:
                    save(path, record)
                except BaseException:
                    pass
            raise
        finally:
            if candidate is not None and candidate.exists():
                try:
                    candidate.unlink()
                    _fsync_directory(BASE)
                except BaseException:
                    pass
            for fd in (ready_read, ready_write, parent_control, child_control):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass


def cleanup(token: str) -> dict[str, Any]:
    safe_base()
    path = run_path(token)
    with locked():
        record = load(path)
        if record.get("cleanup_complete"):
            return record
        result = cleanup_locked(record, reason="explicit")
    _terminate_watchdog(result)
    return result


def status(token: str) -> dict[str, Any]:
    safe_base()
    with locked():
        return load(run_path(token))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "cleanup", "status", "watchdog"))
    parser.add_argument("--token", required=True)
    parser.add_argument("--invalid-resolver", default="203.0.113.254")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--parent-pid", type=int)
    parser.add_argument("--ready-fd", type=int)
    parser.add_argument("--control-fd", type=int)
    args = parser.parse_args()
    if args.action == "watchdog":
        if args.parent_pid is None or args.ready_fd is None or args.control_fd is None:
            raise ValueError("watchdog identity and descriptors are required")
        raise SystemExit(_watchdog(args.token, args.parent_pid, args.ready_fd, args.control_fd))
    value = (
        start(args.token, args.invalid_resolver, args.duration)
        if args.action == "start"
        else cleanup(args.token)
        if args.action == "cleanup"
        else status(args.token)
    )
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
