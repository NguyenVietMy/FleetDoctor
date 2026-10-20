#!/usr/bin/env python3
"""Root-owned controller for one bounded unprivileged FD-pressure worker."""

import argparse
import ctypes
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:
    import fcntl
    import pwd
except ImportError:  # pragma: no cover - Windows fixture import
    fcntl = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

STATE_ROOT = Path("/run/fleetdoctor-fd")
AUTHORITY_NAME = "active.json"
TOKEN = re.compile(r"^[a-f0-9]{16,64}$")
USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
MIN_LIMIT = 32
MAX_LIMIT = 1024
MIN_SECONDS = 20
MAX_SECONDS = 180
STATE_OWNER_UID = 0
BoundaryHook = Callable[[str], None]


class SpawnRollbackError(RuntimeError):
    def __init__(self, message: str, identity: dict[str, Any] | None) -> None:
        super().__init__(message)
        self.identity = identity


def state_path(token: str) -> Path:
    if not TOKEN.fullmatch(token):
        raise ValueError("token must be 16..64 lowercase hexadecimal characters")
    return STATE_ROOT / AUTHORITY_NAME


def current_boot_id(proc: Path = Path("/proc")) -> str:
    value = (proc / "sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if not value:
        raise ValueError("empty boot ID")
    return value


def process_starttime(pid: int, proc: Path = Path("/proc")) -> int:
    text = (proc / str(pid) / "stat").read_text(encoding="utf-8")
    closing = text.rfind(")")
    fields = text[closing + 2 :].split()
    if closing < 1 or len(fields) < 20:
        raise ValueError("malformed process stat")
    return int(fields[19])


def process_state(pid: int, proc: Path = Path("/proc")) -> str:
    text = (proc / str(pid) / "stat").read_text(encoding="utf-8")
    closing = text.rfind(")")
    fields = text[closing + 2 :].split()
    if closing < 1 or not fields:
        raise ValueError("malformed process stat")
    return fields[0]


def process_uid(pid: int, proc: Path = Path("/proc")) -> int:
    for line in (proc / str(pid) / "status").read_text(encoding="utf-8").splitlines():
        if line.startswith("Uid:"):
            fields = line.split()
            if len(fields) >= 2:
                return int(fields[1])
    raise ValueError("process status has no real UID")


def process_identity(pid: int, proc: Path = Path("/proc")) -> dict[str, Any]:
    return {
        "pid": pid,
        "starttime_ticks": process_starttime(pid, proc),
        "uid": process_uid(pid, proc),
        "boot_id": current_boot_id(proc),
    }


def process_measurement(
    pid: int,
    expected_start: int,
    expected_uid: int | None = None,
    expected_boot: str | None = None,
    proc: Path = Path("/proc"),
) -> dict[str, Any]:
    identity = process_identity(pid, proc)
    if identity["starttime_ticks"] != expected_start:
        raise ValueError("FD worker identity was replaced")
    if expected_uid is not None and identity["uid"] != expected_uid:
        raise ValueError("FD worker ownership changed")
    if expected_boot is not None and identity["boot_id"] != expected_boot:
        raise ValueError("FD worker boot changed")
    if process_state(pid, proc) == "Z":
        raise ProcessLookupError("FD worker is a zombie")
    limits = (proc / str(pid) / "limits").read_text(encoding="utf-8")
    soft = None
    for line in limits.splitlines():
        if line.startswith("Max open files"):
            value = line[len("Max open files") :].split()[0]
            soft = None if value == "unlimited" else int(value)
            break
    if soft is None or soft <= 0:
        raise ValueError("FD worker does not have a finite positive soft limit")
    with os.scandir(proc / str(pid) / "fd") as entries:
        count = sum(entry.name.isdigit() for entry in entries)
    after = process_identity(pid, proc)
    if after != identity:
        raise ValueError("FD worker changed during measurement")
    return identity | {
        "descriptor_count": count,
        "soft_limit": soft,
        "pressure_ratio": count / soft,
    }


def _require_posix() -> None:
    if os.name != "posix" or pwd is None or fcntl is None:
        raise OSError("FD helper requires POSIX pidfd and ownership controls")
    if not hasattr(os, "pidfd_open"):
        raise OSError("FD helper requires pidfd_open")


def _preflight_pidfd() -> None:
    descriptor = os.pidfd_open(os.getpid())
    try:
        _pidfd_send(descriptor, 0)
    finally:
        os.close(descriptor)


def _validate_root() -> None:
    try:
        root_stat = STATE_ROOT.lstat()
    except FileNotFoundError:
        STATE_ROOT.mkdir(mode=0o700, parents=True)
        root_stat = STATE_ROOT.lstat()
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("FD authority root is not a directory")
    if root_stat.st_uid != STATE_OWNER_UID or root_stat.st_mode & 0o077:
        raise ValueError("untrusted FD authority root")


def _read_locked(descriptor: int) -> dict[str, Any]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, 65536)
    if not raw:
        return {"phase": "inactive"}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid FD authority record")
    return value


def _write_locked(descriptor: int, record: dict[str, Any]) -> None:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > 32768:
        raise ValueError("FD authority record exceeds bound")
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.write(descriptor, encoded)
    os.ftruncate(descriptor, len(encoded))
    os.fsync(descriptor)


def _validate_authority(root_descriptor: int, descriptor: int) -> None:
    opened = os.fstat(descriptor)
    named = os.stat(AUTHORITY_NAME, dir_fd=root_descriptor, follow_symlinks=False)
    if not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode):
        raise ValueError("FD authority is not a regular file")
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        raise ValueError("FD authority was replaced")
    if opened.st_uid != STATE_OWNER_UID or opened.st_mode & 0o077:
        raise ValueError("untrusted FD authority file")


@contextmanager
def locked_authority() -> Iterator[tuple[int, int, dict[str, Any]]]:
    _require_posix()
    _validate_root()
    root_descriptor = os.open(
        STATE_ROOT, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(
            AUTHORITY_NAME,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=root_descriptor,
        )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _validate_authority(root_descriptor, descriptor)
        yield root_descriptor, descriptor, _read_locked(descriptor)
    finally:
        if descriptor >= 0:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        os.close(root_descriptor)


def trusted_state(token: str) -> dict[str, Any] | None:
    state_path(token)
    with locked_authority() as (_, _, record):
        if record.get("phase") in {None, "inactive", "cleaned"}:
            return None
        if record.get("token") != token:
            raise ValueError("a different token owns the node FD lease")
        return record


def _pidfd_send(descriptor: int, signum: int) -> None:
    sender = getattr(signal, "pidfd_send_signal", None)
    if sender is not None:
        sender(descriptor, signum)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "pidfd_send_signal", None)
    if function is None:
        raise OSError("FD helper requires pidfd_send_signal")
    result = function(descriptor, signum, ctypes.c_void_p(), 0)
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def open_bound_pidfd(identity: dict[str, Any]) -> int:
    _require_posix()
    if identity["boot_id"] != current_boot_id():
        raise ValueError("refusing stale-boot process authority")
    before = process_identity(int(identity["pid"]))
    for key in ("starttime_ticks", "uid", "boot_id"):
        if before[key] != identity[key]:
            raise ValueError("refusing replaced process authority")
    descriptor = os.pidfd_open(int(identity["pid"]))
    try:
        after = process_identity(int(identity["pid"]))
        if after != before:
            raise ValueError("process changed while acquiring pidfd")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def signal_owned(identity: dict[str, Any], signum: int) -> str:
    descriptor = open_bound_pidfd(identity)
    try:
        _pidfd_send(descriptor, signum)
        return "pidfd"
    finally:
        os.close(descriptor)


def wait_absent(identity: dict[str, Any], timeout: float = 5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            current = process_identity(int(identity["pid"]))
        except (FileNotFoundError, ProcessLookupError):
            return True
        if current != identity or process_state(int(identity["pid"])) == "Z":
            return True
        time.sleep(0.05)
    return False


def _record_identity(record: dict[str, Any], prefix: str) -> dict[str, Any]:
    return {
        "pid": int(record[prefix + "_pid"]),
        "starttime_ticks": int(record[prefix + "_starttime_ticks"]),
        "uid": int(record[prefix + "_uid"]),
        "boot_id": str(record["boot_id"]),
    }


def _terminate(identity: dict[str, Any]) -> list[str]:
    methods: list[str] = []
    try:
        methods.append(signal_owned(identity, signal.SIGTERM))
    except (FileNotFoundError, ProcessLookupError):
        methods.append("already_absent")
    if not wait_absent(identity):
        methods.append(signal_owned(identity, signal.SIGKILL))
        if not wait_absent(identity):
            raise RuntimeError("owned FD process did not stop")
    return methods


@contextmanager
def _controller_interrupts() -> Iterator[None]:
    previous: dict[signal.Signals, Any] = {}

    def interrupted(signum: int, frame: object) -> None:
        raise InterruptedError(f"FD controller interrupted by signal {signum}")

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, interrupted)
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _spawn_pidfd(
    command: list[str], *, preexec_fn: Callable[[], None] | None = None
) -> tuple[subprocess.Popen[bytes], int]:
    blocked = {signal.SIGINT, signal.SIGTERM}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    child: subprocess.Popen[bytes] | None = None
    descriptor: int | None = None
    try:
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            preexec_fn=preexec_fn,
        )
        descriptor = os.pidfd_open(child.pid)
    except BaseException as exc:
        rollback_failure: SpawnRollbackError | None = None
        if child is not None:
            identity = None
            try:
                identity = process_identity(child.pid)
            except (OSError, ValueError):
                pass
            if descriptor is None:
                rollback_failure = SpawnRollbackError(
                    "spawned FD process has no pidfd authority", identity
                )
            else:
                try:
                    _pidfd_send(descriptor, signal.SIGKILL)
                    child.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired) as rollback_exc:
                    rollback_failure = SpawnRollbackError(
                        f"spawn pidfd rollback failed: {type(rollback_exc).__name__}", identity
                    )
                finally:
                    os.close(descriptor)
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        except BaseException:
            if rollback_failure is not None:
                raise rollback_failure from exc
            raise
        if rollback_failure is not None:
            raise rollback_failure from exc
        raise
    assert child is not None and descriptor is not None
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    except BaseException as exc:
        identity = None
        try:
            identity = process_identity(child.pid)
        except (OSError, ValueError):
            pass
        try:
            _pidfd_send(descriptor, signal.SIGKILL)
            child.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as rollback_exc:
            raise SpawnRollbackError(
                f"pending-unmask pidfd rollback failed: {type(rollback_exc).__name__}", identity
            ) from exc
        finally:
            os.close(descriptor)
        raise
    return child, descriptor


def _unblock_lifecycle_signals() -> None:
    """Drop the controller's inherited spawn mask after the child has exec'd."""
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT, signal.SIGTERM})


def start(
    token: str,
    limit: int,
    seconds: int,
    worker_user: str = "fleetdoctor",
    *,
    watchdog_seconds: int | None = None,
    boundary_hook: BoundaryHook | None = None,
) -> dict[str, Any]:
    state_path(token)
    if not MIN_LIMIT <= limit <= MAX_LIMIT or not MIN_SECONDS <= seconds <= MAX_SECONDS:
        raise ValueError("limit must be 32..1024 and seconds 20..180")
    if not USER.fullmatch(worker_user) or worker_user == "root":
        raise ValueError("worker user must be a bounded unprivileged account name")
    _require_posix()
    _preflight_pidfd()
    account = pwd.getpwnam(worker_user)
    if account.pw_uid == 0:
        raise ValueError("worker account must have a non-root UID")
    hook = boundary_hook or (lambda _: None)
    watchdog_lifetime = seconds + 5 if watchdog_seconds is None else watchdog_seconds
    if not 5 <= watchdog_lifetime <= seconds + 5:
        raise ValueError("watchdog seconds must be 5..worker seconds + 5")
    child: subprocess.Popen[bytes] | None = None
    worker_pidfd: int | None = None
    watchdog_process: subprocess.Popen[bytes] | None = None
    watchdog_pidfd: int | None = None
    worker_identity: dict[str, Any] | None = None
    watchdog_identity: dict[str, Any] | None = None
    failure: BaseException | None = None
    with _controller_interrupts(), locked_authority() as (root_fd, authority_fd, old):
        reusable_failure = old.get("phase") == "failed" and old.get("rollback_verified") is True
        if old.get("phase") not in {None, "inactive", "cleaned"} and not reusable_failure:
            raise ValueError("node FD lease is already owned")
        record: dict[str, Any] = {
            "token": token,
            "phase": "preparing",
            "boot_id": current_boot_id(),
            "worker_user": worker_user,
            "worker_uid": account.pw_uid,
            "limit": limit,
            "seconds": seconds,
            "watchdog_seconds": watchdog_lifetime,
            "started_monotonic": time.monotonic(),
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "boundaries": ["controller_handlers_installed"],
        }
        _write_locked(authority_fd, record)

        def persist(boundary: str) -> None:
            record["boundaries"].append(boundary)
            record["phase"] = "preparing"
            _validate_authority(root_fd, authority_fd)
            _write_locked(authority_fd, record)
            hook(boundary)

        def demote() -> None:
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

        try:
            child, worker_pidfd = _spawn_pidfd(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "worker",
                    "--limit",
                    str(limit),
                    "--seconds",
                    str(seconds),
                ],
                preexec_fn=demote,
            )
            persist("worker_spawn_pidfd")
            worker_identity = process_identity(child.pid)
            if worker_identity["uid"] != account.pw_uid or worker_identity["uid"] == 0:
                raise ValueError("worker did not assume the configured non-root UID")
            record.update(
                {
                    "worker_pid": child.pid,
                    "worker_starttime_ticks": worker_identity["starttime_ticks"],
                }
            )
            persist("worker_identity")
            watchdog_process, watchdog_pidfd = _spawn_pidfd(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "watchdog",
                    "--pid",
                    str(child.pid),
                    "--starttime",
                    str(worker_identity["starttime_ticks"]),
                    "--uid",
                    str(worker_identity["uid"]),
                    "--boot-id",
                    str(worker_identity["boot_id"]),
                    "--seconds",
                    str(watchdog_lifetime),
                ]
            )
            persist("watchdog_spawn_pidfd")
            watchdog_identity = process_identity(watchdog_process.pid)
            record.update(
                {
                    "watchdog_pid": watchdog_process.pid,
                    "watchdog_starttime_ticks": watchdog_identity["starttime_ticks"],
                    "watchdog_uid": watchdog_identity["uid"],
                }
            )
            persist("watchdog_identity")
            deadline = time.monotonic() + 5
            measurement = None
            while time.monotonic() < deadline:
                try:
                    candidate = process_measurement(
                        child.pid,
                        int(worker_identity["starttime_ticks"]),
                        int(worker_identity["uid"]),
                        str(worker_identity["boot_id"]),
                    )
                except (FileNotFoundError, PermissionError, ValueError):
                    time.sleep(0.05)
                    continue
                if candidate["soft_limit"] == limit and candidate["pressure_ratio"] < 0.8:
                    measurement = candidate
                    break
                time.sleep(0.05)
            if measurement is None:
                raise TimeoutError("FD worker did not reach measured low preparation phase")
            record["phase"] = "prepared"
            record["prepared_monotonic"] = time.monotonic()
            _validate_authority(root_fd, authority_fd)
            _write_locked(authority_fd, record)
            hook("prepared")
            return record | {"measurement": measurement, "owned": True}
        except BaseException as exc:
            failure = exc
            cleanup_methods: list[str] = []
            rollback_verified = not isinstance(exc, SpawnRollbackError)
            rollback_identities: list[dict[str, Any]] = []
            if isinstance(exc, SpawnRollbackError) and exc.identity is not None:
                rollback_identities.append(exc.identity)
            for descriptor, process, _identity in (
                (watchdog_pidfd, watchdog_process, watchdog_identity),
                (worker_pidfd, child, worker_identity),
            ):
                if descriptor is None:
                    continue
                try:
                    _pidfd_send(descriptor, signal.SIGTERM)
                    cleanup_methods.append("pidfd")
                    if process is not None:
                        process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        _pidfd_send(descriptor, signal.SIGKILL)
                        if process is not None:
                            process.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        cleanup_methods.append("rollback_failed")
                        rollback_verified = False
                        if _identity is not None:
                            rollback_identities.append(_identity)
            record.update(
                {
                    "phase": "failed" if rollback_verified else "rollback_uncertain",
                    "failure": f"{type(exc).__name__}: {exc}",
                    "rollback": cleanup_methods,
                    "rollback_verified": rollback_verified,
                    "rollback_identities": rollback_identities,
                    "failed_monotonic": time.monotonic(),
                }
            )
            _validate_authority(root_fd, authority_fd)
            _write_locked(authority_fd, record)
        finally:
            for descriptor in (watchdog_pidfd, worker_pidfd):
                if descriptor is not None:
                    os.close(descriptor)
    assert failure is not None
    raise failure


def status(token: str) -> dict[str, Any]:
    state_path(token)
    with locked_authority() as (root_fd, authority_fd, record):
        if record.get("phase") in {None, "inactive", "cleaned"}:
            return {"token": token, "state": "absent", "owned": False}
        if record.get("token") != token:
            raise ValueError("a different token owns the node FD lease")
        if record.get("phase") == "failed":
            return record | {"state": "failed", "owned": False}
        if record.get("phase") == "rollback_uncertain":
            return record | {"state": "rollback_uncertain", "owned": True}
        _validate_authority(root_fd, authority_fd)
        identity = _record_identity(record, "worker")
        measurement = process_measurement(
            identity["pid"],
            identity["starttime_ticks"],
            identity["uid"],
            identity["boot_id"],
        )
        return record | {"state": "active", "owned": True, "measurement": measurement}


def _action(token: str, signum: int, action: str, target: str | None) -> dict[str, Any]:
    state_path(token)
    with locked_authority() as (root_fd, authority_fd, record):
        if record.get("token") != token or record.get("phase") in {
            None,
            "inactive",
            "cleaned",
            "failed",
            "rollback_uncertain",
        }:
            raise ValueError("owned FD worker is absent")
        _validate_authority(root_fd, authority_fd)
        identity = _record_identity(record, "worker")
        method = signal_owned(identity, signum)
        measurement: dict[str, Any] | None
        if target is None:
            measurement = process_measurement(
                identity["pid"],
                identity["starttime_ticks"],
                identity["uid"],
                identity["boot_id"],
            )
            record["phase"] = action
            record[action + "_monotonic"] = time.monotonic()
            _validate_authority(root_fd, authority_fd)
            _write_locked(authority_fd, record)
            return record | {
                action: True,
                "signal_method": method,
                "measurement": measurement,
            }
        deadline = time.monotonic() + 7
        measurement = None
        while time.monotonic() < deadline:
            measurement = process_measurement(
                identity["pid"],
                identity["starttime_ticks"],
                identity["uid"],
                identity["boot_id"],
            )
            ratio = float(measurement["pressure_ratio"])
            if (target == "high" and ratio >= 0.9) or (target == "low" and ratio < 0.8):
                break
            time.sleep(0.05)
        ratio = -1.0 if measurement is None else float(measurement["pressure_ratio"])
        if (target == "high" and ratio < 0.9) or (target == "low" and ratio >= 0.8):
            raise TimeoutError(f"FD worker did not reach measured {target} phase")
        record["phase"] = action
        record[action + "_monotonic"] = time.monotonic()
        _validate_authority(root_fd, authority_fd)
        _write_locked(authority_fd, record)
        return record | {
            action: True,
            "signal_method": method,
            "measurement": measurement,
        }


def pressure(token: str) -> dict[str, Any]:
    return _action(token, signal.SIGUSR2, "pressuring", None)


def release(token: str) -> dict[str, Any]:
    return _action(token, signal.SIGUSR1, "released", "low")


def cleanup(token: str, *, boundary_hook: BoundaryHook | None = None) -> dict[str, Any]:
    state_path(token)
    hook = boundary_hook or (lambda _: None)
    with _controller_interrupts(), locked_authority() as (root_fd, authority_fd, record):
        if record.get("phase") in {None, "inactive", "cleaned"}:
            return {"token": token, "state": "absent", "owned": False, "cleaned": True}
        if record.get("token") != token:
            raise ValueError("a different token owns the node FD lease")
        if record.get("phase") == "rollback_uncertain":
            identities = record.get("rollback_identities")
            if not isinstance(identities, list) or not identities:
                raise RuntimeError("uncertain FD rollback has no exact cleanup authority")
            rollback_methods: list[str] = []
            for identity in identities:
                if not isinstance(identity, dict):
                    raise RuntimeError("uncertain FD rollback identity is invalid")
                _validate_authority(root_fd, authority_fd)
                try:
                    current = process_identity(int(identity["pid"]))
                except (FileNotFoundError, ProcessLookupError):
                    rollback_methods.append("already_absent")
                    continue
                if current != identity or process_state(int(identity["pid"])) == "Z":
                    rollback_methods.append("already_terminated_or_replaced")
                    continue
                rollback_methods.extend(_terminate(identity))
            record["phase"] = "cleaned"
            record["rollback_verified"] = True
            record["cleanup_methods"] = rollback_methods
            record["cleaned_monotonic"] = time.monotonic()
            _validate_authority(root_fd, authority_fd)
            _write_locked(authority_fd, record)
            return record | {
                "owned": True,
                "cleaned": True,
                "signal_methods": rollback_methods,
            }
        if record.get("phase") == "failed":
            if record.get("rollback_verified") is not True:
                raise RuntimeError("failed FD rollback is not verified clean")
            record["phase"] = "cleaned"
            record["cleaned_monotonic"] = time.monotonic()
            _validate_authority(root_fd, authority_fd)
            _write_locked(authority_fd, record)
            return record | {"owned": False, "cleaned": True, "signal_methods": []}
        _validate_authority(root_fd, authority_fd)
        hook("cleanup_before_signal")
        methods: list[str] = []
        for prefix in ("watchdog", "worker"):
            _validate_authority(root_fd, authority_fd)
            methods.extend(_terminate(_record_identity(record, prefix)))
        record["phase"] = "cleaned"
        record["cleaned_monotonic"] = time.monotonic()
        record["cleanup_methods"] = methods
        _validate_authority(root_fd, authority_fd)
        _write_locked(authority_fd, record)
        return record | {"owned": True, "cleaned": True, "signal_methods": methods}


def worker(limit: int, seconds: int) -> None:
    import resource

    _unblock_lifecycle_signals()
    deadline = time.monotonic() + seconds
    stopped = False
    requested: str | None = None

    def stop(signum: int, frame: object) -> None:
        nonlocal stopped
        stopped = True

    def request_release(signum: int, frame: object) -> None:
        nonlocal requested
        requested = "release"

    def request_pressure(signum: int, frame: object) -> None:
        nonlocal requested
        requested = "pressure"

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGUSR1, request_release)
    signal.signal(signal.SIGUSR2, request_pressure)
    resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))
    opened: list[int] = []

    def adjust(ratio: float) -> None:
        target = int(limit * ratio)
        while len(os.listdir("/proc/self/fd")) < target:
            opened.append(os.open("/dev/null", os.O_RDONLY))
        while opened and len(os.listdir("/proc/self/fd")) > target:
            os.close(opened.pop())

    try:
        adjust(0.25)
        while not stopped and time.monotonic() < deadline:
            action = requested
            requested = None
            if action == "release":
                adjust(0.5)
            elif action == "pressure":
                for ratio in (0.65, 0.8, 0.95):
                    if stopped or time.monotonic() >= deadline:
                        break
                    adjust(ratio)
                    if ratio < 0.95:
                        end = min(deadline, time.monotonic() + 5)
                        while not stopped and requested != "release" and time.monotonic() < end:
                            time.sleep(0.05)
                        if requested == "release":
                            requested = None
                            adjust(0.5)
                            break
            time.sleep(0.05)
    finally:
        while opened:
            os.close(opened.pop())


def watchdog(pid: int, starttime: int, uid: int, boot_id: str, seconds: int) -> None:
    _unblock_lifecycle_signals()
    identity = {
        "pid": pid,
        "starttime_ticks": starttime,
        "uid": uid,
        "boot_id": boot_id,
    }
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if process_identity(pid) != identity:
                return
        except FileNotFoundError:
            return
        time.sleep(0.1)
    try:
        signal_owned(identity, signal.SIGTERM)
    except (FileNotFoundError, ProcessLookupError, ValueError):
        return
    wait_absent(identity)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("start", "status", "pressure", "release", "cleanup"):
        command = sub.add_parser(action)
        command.add_argument("--token", required=True)
        if action == "start":
            command.add_argument("--limit", type=int, default=128)
            command.add_argument("--seconds", type=int, default=120)
            command.add_argument("--worker-user", default="fleetdoctor")
            command.add_argument("--watchdog-seconds", type=int)
    worker_command = sub.add_parser("worker")
    worker_command.add_argument("--limit", type=int, required=True)
    worker_command.add_argument("--seconds", type=int, required=True)
    watchdog_command = sub.add_parser("watchdog")
    watchdog_command.add_argument("--pid", type=int, required=True)
    watchdog_command.add_argument("--starttime", type=int, required=True)
    watchdog_command.add_argument("--uid", type=int, required=True)
    watchdog_command.add_argument("--boot-id", required=True)
    watchdog_command.add_argument("--seconds", type=int, required=True)
    args = parser.parse_args()
    if args.action == "worker":
        worker(args.limit, args.seconds)
        return
    if args.action == "watchdog":
        watchdog(args.pid, args.starttime, args.uid, args.boot_id, args.seconds)
        return
    if os.geteuid() != 0:
        raise PermissionError("FD controller must run as root")
    if args.action == "start":
        result = start(
            args.token,
            args.limit,
            args.seconds,
            args.worker_user,
            watchdog_seconds=args.watchdog_seconds,
        )
    elif args.action == "status":
        result = status(args.token)
    elif args.action == "pressure":
        result = pressure(args.token)
    elif args.action == "release":
        result = release(args.token)
    else:
        result = cleanup(args.token)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
