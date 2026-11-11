"""Bounded Linux-only DistributedKVStore trace and direct-sampling controller.

The public CLI is intentionally inert on non-Linux hosts except for ``--help``.
Actual capture requires a root controller; KV processes and the production direct
sampler run as one explicitly selected non-root user.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import importlib.util
import json
import math
import os
import platform
import re
import select
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TextIO
from uuid import UUID, uuid4

pwd_module: Any | None = importlib.import_module("pwd") if sys.platform == "linux" else None

DEFAULT_PORTS = (9101, 9102, 9103)
EXPECTED_ARCHIVE_SHA256 = "2a024a69840f1ece82b92be448c9431113ca663c1126b89bd5a9a7e04fb5fd36"
MAX_TEXT_BYTES = 64 * 1024
MAX_TRACE_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_PCAP_BYTES = 16 * 1024 * 1024
MAX_DECODE_BYTES = 8 * 1024 * 1024
MAX_CONTROL_BYTES = 1024 * 1024
PCAP_HEADER_BYTES = 24
PCAP_RECORD_HEADER_BYTES = 16
TCPDUMP_SNAPLEN = 512
TCPDUMP_PACKET_LIMIT = 30_000
TCPDUMP_CAPACITY_BYTES = PCAP_HEADER_BYTES + TCPDUMP_PACKET_LIMIT * (
    PCAP_RECORD_HEADER_BYTES + TCPDUMP_SNAPLEN
)
LISTEN_STATE = "0A"
LOOPBACK_HEX_V4 = "0100007F"
RUN_STATUS = Literal["running", "finalizing", "passed", "failed"]


class HarnessError(RuntimeError):
    """A bounded, user-facing harness failure."""


@dataclass(frozen=True)
class UserIdentity:
    name: str
    uid: int
    gid: int
    home: str


@dataclass(frozen=True)
class ProcessIdentity:
    kind: str
    pid: int
    starttime: int
    pgid: int
    uid: int


@dataclass(frozen=True)
class ListenerIdentity:
    address: str
    port: int
    inode: int
    pid: int
    starttime: int


@dataclass(frozen=True)
class ProcSnapshot:
    pid: int
    starttime: int
    ppid: int
    pgid: int
    sid: int
    uid: int


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float


@dataclass(frozen=True)
class RunConfig:
    node_binary: Path
    client_binary: Path
    source_archive: Path
    source_archive_sha256: str
    kv_revision: str
    output: Path
    ports: tuple[int, int, int]
    run_user: UserIdentity
    pairs: int
    pace_seconds: float
    max_runtime_seconds: int
    gate_path: Path | None
    gate_timeout_seconds: int
    max_output_bytes: int


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def effective_uid() -> int:
    return int(getattr(os, "geteuid", lambda: -1)())


def effective_gid() -> int:
    return int(getattr(os, "getegid", lambda: -1)())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def write_json_exclusive(
    path: Path,
    value: Any,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int,
) -> None:
    """Create one protected JSON file without following or replacing a leaf."""
    if sys.platform != "linux":
        raise HarnessError("protected JSON creation is available only on Linux")
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise HarnessError(f"refused protected JSON path: {path.name}") from exc
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, owner_uid, owner_gid)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def publish_json_no_replace(
    path: Path,
    value: Any,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int = 0o600,
) -> None:
    """Publish complete JSON at an absent final path without a partial-file window."""
    if sys.platform != "linux":
        raise HarnessError("atomic no-replace JSON publication is available only on Linux")
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode()
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, mode)
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, owner_uid, owner_gid)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise HarnessError("final JSON path already exists; refuse replacement") from exc
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise HarnessError(f"atomic JSON publication failed: {path.name}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def bounded_owned_text(
    path: Path,
    *,
    expected_uid: int,
    maximum: int = MAX_TEXT_BYTES,
) -> str:
    """Read a bounded regular file without following a leaf or blocking on a FIFO."""
    if sys.platform != "linux":
        raise HarnessError("protected file reads are available only on Linux")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HarnessError(f"refused protected read: {path.name}") from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise HarnessError(f"protected input is not a regular file: {path.name}")
        if details.st_uid != expected_uid:
            raise HarnessError(f"protected input has unexpected owner: {path.name}")
        if details.st_size > maximum:
            raise HarnessError(f"{path.name} exceeds {maximum} bytes")
        body = bytearray()
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > maximum:
                raise HarnessError(f"{path.name} exceeds {maximum} bytes")
        return bytes(body).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HarnessError(f"protected input is not UTF-8: {path.name}") from exc
    finally:
        os.close(descriptor)


def bounded_owned_json(
    path: Path,
    *,
    expected_uid: int,
    maximum: int = MAX_CONTROL_BYTES,
) -> Any:
    try:
        return json.loads(bounded_owned_text(path, expected_uid=expected_uid, maximum=maximum))
    except json.JSONDecodeError as exc:
        raise HarnessError(f"protected JSON is malformed: {path.name}") from exc


def _protected_chain(path: Path, *, label: str, leaf_directory: bool) -> Path:
    """Require a canonical root-owned chain with no group/world writable component."""
    if sys.platform != "linux":
        raise HarnessError("protected path validation is available only on Linux")
    if not path.is_absolute():
        raise HarnessError(f"{label} must be absolute")
    lexical = Path(os.path.abspath(path))
    current = Path("/")
    components = lexical.parts[1:]
    for index, component in enumerate(components):
        current /= component
        try:
            details = os.lstat(current)
        except OSError as exc:
            raise HarnessError(f"{label} is unavailable: {current}") from exc
        is_leaf = index == len(components) - 1
        if stat.S_ISLNK(details.st_mode):
            raise HarnessError(f"{label} contains a symlink: {current}")
        expected_directory = not is_leaf or leaf_directory
        if expected_directory and not stat.S_ISDIR(details.st_mode):
            raise HarnessError(f"{label} component is not a directory: {current}")
        if not expected_directory and not stat.S_ISREG(details.st_mode):
            raise HarnessError(f"{label} is not a regular file: {current}")
        if details.st_uid != 0 or details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise HarnessError(f"{label} is not root-owned and protected: {current}")
    return lexical


def require_protected_directory(path: Path, label: str) -> Path:
    return _protected_chain(path, label=label, leaf_directory=True)


def require_protected_file(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise HarnessError(f"{label} must be absolute")
    lexical = Path(os.path.abspath(path))
    require_protected_directory(lexical.parent, f"{label} parent")
    try:
        details = os.lstat(lexical)
    except OSError as exc:
        raise HarnessError(f"{label} is unavailable: {lexical}") from exc
    if stat.S_ISLNK(details.st_mode):
        if details.st_uid != 0:
            raise HarnessError(f"{label} symlink is not root-owned: {lexical}")
        try:
            resolved = lexical.resolve(strict=True)
        except OSError as exc:
            raise HarnessError(f"{label} symlink target is unavailable: {lexical}") from exc
        _protected_chain(resolved, label=f"{label} target", leaf_directory=False)
        return lexical
    return _protected_chain(lexical, label=label, leaf_directory=False)


def bounded_text(path: Path, maximum: int = MAX_TEXT_BYTES) -> str:
    with path.open("rb") as stream:
        body = stream.read(maximum + 1)
    if len(body) > maximum:
        raise HarnessError(f"{path.name} exceeds {maximum} bytes")
    return body.decode("utf-8", errors="replace")


def _validate_hex(value: str, length: int, label: str) -> str:
    if len(value) != length or re.fullmatch(r"[0-9a-f]+", value) is None:
        raise HarnessError(f"{label} must be {length} lowercase hexadecimal characters")
    return value


def validate_ports(values: list[int] | tuple[int, ...]) -> tuple[int, int, int]:
    if len(values) != 3:
        raise HarnessError("exactly three ports are required")
    ports = tuple(values)
    if len(set(ports)) != 3 or any(
        type(port) is not int or not 1024 <= port <= 65535 for port in ports
    ):
        raise HarnessError("ports must be three distinct integers in 1024..65535")
    return ports[0], ports[1], ports[2]


def resolve_user(name: str) -> UserIdentity:
    if pwd_module is None:
        raise HarnessError("run-user lookup is available only on Linux")
    try:
        record = pwd_module.getpwnam(name)
    except KeyError as exc:
        raise HarnessError(f"run user does not exist: {name}") from exc
    if record.pw_uid == 0:
        raise HarnessError("run user must be non-root")
    return UserIdentity(record.pw_name, record.pw_uid, record.pw_gid, record.pw_dir)


def require_executable(path: Path, label: str) -> Path:
    try:
        details = path.stat()
    except OSError as exc:
        raise HarnessError(f"{label} is unavailable: {path}") from exc
    if not stat.S_ISREG(details.st_mode) or not os.access(path, os.X_OK):
        raise HarnessError(f"{label} must be an executable regular file: {path}")
    return path.resolve()


def require_tool(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise HarnessError(f"required tool is unavailable: {name}")
    return value


def refuse_existing_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise HarnessError(f"output path already exists: {path}")
    if not path.is_absolute():
        raise HarnessError("output path must be absolute")
    parent = path.parent
    if not parent.is_dir():
        raise HarnessError(f"output parent does not exist: {parent}")


def protected_runtime_files() -> list[Path]:
    result = [Path(sys.executable), Path(__file__)]
    specification = importlib.util.find_spec("fleetdoctor")
    if specification is None or specification.origin is None:
        raise HarnessError("fleetdoctor import origin is unavailable")
    result.append(Path(specification.origin))
    return result


def validate_runtime_trust(
    *,
    output: Path,
    gate_path: Path | None,
    node_binary: Path,
    client_binary: Path,
    source_archive: Path,
) -> None:
    require_protected_directory(output.parent, "output parent")
    if gate_path is not None:
        if not gate_path.is_absolute():
            raise HarnessError("start gate must be absolute")
        require_protected_directory(gate_path.parent, "start gate parent")
    for path, label in (
        (node_binary, "node binary"),
        (client_binary, "client binary"),
        (source_archive, "source archive"),
        *[(path, "controller runtime file") for path in protected_runtime_files()],
    ):
        require_protected_file(path, label)
    for raw in sys.path:
        candidate = Path.cwd() if not raw else Path(raw)
        if not candidate.exists():
            continue
        if candidate.is_dir():
            require_protected_directory(candidate.absolute(), "Python import path")
        else:
            require_protected_file(candidate.absolute(), "Python import path")


def audit_protected_runtime(root: Path, venv_python: Path, run_uid: int) -> dict[str, Any]:
    """Recursively audit staged root runtime bytes before any privileged venv use."""
    if sys.platform != "linux" or effective_uid() != 0:
        raise HarnessError("protected runtime audit requires Linux root")
    if run_uid <= 0:
        raise HarnessError("protected runtime audit requires a non-root run UID")
    root = require_protected_directory(root, "runtime audit root")
    lexical_python = Path(os.path.abspath(venv_python))
    try:
        lexical_python.relative_to(root)
    except ValueError as exc:
        raise HarnessError("venv Python must be inside the audited runtime") from exc
    required = (
        root / "venv",
        root / "venv" / "bin",
        root / "scripts",
        root / "src",
    )
    for path in required:
        require_protected_directory(path, "required runtime directory")

    entries = 0
    symlinks = 0
    for path in (root, *sorted(root.rglob("*"))):
        try:
            details = os.lstat(path)
        except OSError as exc:
            raise HarnessError(f"runtime entry became unavailable: {path}") from exc
        entries += 1
        if stat.S_ISLNK(details.st_mode):
            symlinks += 1
            if details.st_uid != 0:
                raise HarnessError(f"runtime symlink is not root-owned: {path}")
            try:
                resolved = path.resolve(strict=True)
            except OSError as exc:
                raise HarnessError(f"runtime symlink target is unavailable: {path}") from exc
            if resolved.is_dir():
                try:
                    resolved.relative_to(root)
                except ValueError as exc:
                    raise HarnessError(
                        f"runtime directory symlink escapes the audited tree: {path}"
                    ) from exc
                require_protected_directory(resolved, "runtime symlink target")
            else:
                require_protected_file(resolved, "runtime symlink target")
            continue
        if not (stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode)):
            raise HarnessError(f"runtime entry is not a regular file or directory: {path}")
        if details.st_uid != 0 or details.st_uid == run_uid:
            raise HarnessError(f"runtime entry is not root-owned: {path}")
        if details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise HarnessError(f"runtime entry is group/world writable: {path}")

    require_protected_file(lexical_python, "audited venv Python")
    if not os.access(lexical_python, os.X_OK):
        raise HarnessError("audited venv Python is not executable")
    return {
        "runtime": str(root),
        "venv_python": str(lexical_python),
        "resolved_python": str(lexical_python.resolve(strict=True)),
        "run_uid": run_uid,
        "entries": entries,
        "symlinks": symlinks,
        "passed": True,
    }


def ports_available(ports: tuple[int, int, int]) -> None:
    probes: list[socket.socket] = []
    try:
        for port in ports:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probes.append(probe)
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as exc:
                raise HarnessError(f"localhost port is occupied or unavailable: {port}") from exc
    finally:
        for probe in probes:
            probe.close()


def ports_released(ports: tuple[int, int, int]) -> bool:
    listening: set[int] = set()
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = path.read_text(encoding="ascii").splitlines()[1:]
        except FileNotFoundError:
            continue
        except OSError:
            return False
        for line in lines:
            fields = line.split()
            if len(fields) >= 4 and fields[3] == LISTEN_STATE:
                try:
                    listening.add(int(fields[1].rsplit(":", 1)[1], 16))
                except (IndexError, ValueError):
                    return False
    if any(port in listening for port in ports):
        return False

    probes: list[socket.socket] = []
    try:
        for port in ports:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probes.append(probe)
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        for probe in probes:
            probe.close()
    return True


def proc_snapshot(pid: int) -> ProcSnapshot:
    text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    closing = text.rfind(")")
    if closing < 0:
        raise HarnessError(f"invalid proc stat for PID {pid}")
    fields = text[closing + 2 :].split()
    if len(fields) < 20:
        raise HarnessError(f"short proc stat for PID {pid}")
    return ProcSnapshot(
        pid=pid,
        starttime=int(fields[19]),
        ppid=int(fields[1]),
        pgid=int(fields[2]),
        sid=int(fields[3]),
        uid=proc_uid(pid),
    )


def proc_stat(pid: int) -> tuple[int, int]:
    value = proc_snapshot(pid)
    return value.starttime, value.pgid


def proc_uid(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1])
    raise HarnessError(f"UID unavailable for PID {pid}")


def capture_identity(kind: str, pid: int) -> ProcessIdentity:
    value = proc_snapshot(pid)
    return ProcessIdentity(kind, pid, value.starttime, value.pgid, value.uid)


def identity_matches(identity: ProcessIdentity) -> bool:
    try:
        value = proc_snapshot(identity.pid)
        return (
            value.starttime == identity.starttime
            and value.pgid == identity.pgid
            and value.uid == identity.uid
        )
    except (OSError, ProcessLookupError, HarnessError, ValueError):
        return False


def is_descendant_of(pid: int, ancestor: ProcessIdentity) -> bool:
    """Validate current PPID ancestry without trusting caller-supplied UID fields."""
    if pid == ancestor.pid or not identity_matches(ancestor):
        return False
    seen: set[int] = set()
    current = pid
    while current > 1 and current not in seen:
        seen.add(current)
        try:
            value = proc_snapshot(current)
        except (OSError, ProcessLookupError, HarnessError, ValueError):
            return False
        if value.ppid == ancestor.pid:
            return value.uid == ancestor.uid
        current = value.ppid
    return False


def discover_descendants(ancestor: ProcessIdentity, expected_uid: int) -> list[ProcessIdentity]:
    if not identity_matches(ancestor) or ancestor.uid != expected_uid:
        return []
    result: list[ProcessIdentity] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == ancestor.pid:
            continue
        try:
            value = proc_snapshot(pid)
        except (OSError, ProcessLookupError, HarnessError, ValueError):
            continue
        if value.uid != expected_uid or not is_descendant_of(pid, ancestor):
            continue
        result.append(
            ProcessIdentity("sampler-descendant", pid, value.starttime, value.pgid, value.uid)
        )
    return result


def signal_owned(identity: ProcessIdentity, signum: int) -> bool:
    if not identity_matches(identity):
        return False
    try:
        if identity.pgid == identity.pid:
            os.killpg(identity.pgid, signum)
        else:
            os.kill(identity.pid, signum)
    except ProcessLookupError:
        return False
    return True


def wait_identity_exit(identity: ProcessIdentity, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not identity_matches(identity):
            return True
        time.sleep(0.02)
    return not identity_matches(identity)


def terminate_owned(identity: ProcessIdentity, first_signal: int, grace: float = 1.0) -> bool:
    if not identity_matches(identity):
        return True
    signal_owned(identity, first_signal)
    if wait_identity_exit(identity, grace):
        return True
    signal_owned(identity, signal.SIGTERM)
    if wait_identity_exit(identity, grace):
        return True
    signal_owned(identity, signal.SIGKILL)
    return wait_identity_exit(identity, grace)


def terminate_popen(
    process: subprocess.Popen[Any],
    identity: ProcessIdentity,
    first_signal: int,
    grace: float = 1.0,
) -> bool:
    if process.poll() is not None:
        return True
    if not signal_owned(identity, first_signal):
        return process.poll() is not None
    try:
        process.wait(timeout=grace)
        return True
    except subprocess.TimeoutExpired:
        pass
    signal_owned(identity, signal.SIGTERM)
    try:
        process.wait(timeout=grace)
        return True
    except subprocess.TimeoutExpired:
        pass
    signal_owned(identity, signal.SIGKILL)
    try:
        process.wait(timeout=grace)
        return True
    except subprocess.TimeoutExpired:
        return False


@contextmanager
def blocked_termination_signals() -> Any:
    if sys.platform != "linux":
        yield None
        return
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        yield previous
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _set_parent_death_signal(signum: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signum, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _child_setup(
    user: UserIdentity | None,
    inherited_mask: set[signal.Signals] | None,
    parent_pid: int,
    parent_starttime: int,
    parent_death_signal: int | None,
    exec_expiry_seconds: float | None,
) -> None:
    try:
        observed_parent_starttime = proc_snapshot(parent_pid).starttime
    except BaseException:
        observed_parent_starttime = -1
    os.setsid()
    if user is not None:
        if os.geteuid() == 0:
            os.initgroups(user.name, user.gid)
            os.setgid(user.gid)
            os.setuid(user.uid)
        elif os.geteuid() != user.uid or os.getegid() != user.gid:
            raise PermissionError("cannot switch to requested run user")
    if parent_death_signal is not None:
        _set_parent_death_signal(parent_death_signal)
        if os.getppid() != parent_pid or observed_parent_starttime != parent_starttime:
            os._exit(125)
    if inherited_mask is not None:
        signal.pthread_sigmask(signal.SIG_SETMASK, inherited_mask)
    if exec_expiry_seconds is not None:
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
        signal.setitimer(signal.ITIMER_REAL, exec_expiry_seconds)


def _spawn_captured(
    argv: list[str],
    *,
    kind: str,
    user: UserIdentity | None,
    stdin: Any,
    stdout: Any,
    stderr: Any,
    text: bool,
    register: Callable[[subprocess.Popen[Any], ProcessIdentity], None] | None,
    parent_death_signal: int | None,
    exec_expiry_seconds: float | None,
) -> tuple[subprocess.Popen[Any], ProcessIdentity]:
    if exec_expiry_seconds is not None and exec_expiry_seconds <= 0:
        raise HarnessError(f"invalid exec expiry for {kind}")
    process: subprocess.Popen[Any] | None = None
    identity: ProcessIdentity | None = None
    with blocked_termination_signals() as inherited_mask:
        parent_pid = os.getpid()
        parent_starttime = proc_snapshot(parent_pid).starttime
        try:
            process = subprocess.Popen(
                argv,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                text=text,
                close_fds=True,
                preexec_fn=lambda: _child_setup(
                    user,
                    inherited_mask,
                    parent_pid,
                    parent_starttime,
                    parent_death_signal,
                    exec_expiry_seconds,
                ),
            )
            identity = capture_identity(kind, process.pid)
            expected_uid = 0 if user is None else user.uid
            if identity.pgid != identity.pid or identity.uid != expected_uid:
                raise HarnessError(f"unexpected identity for {kind}")
            if register is not None:
                register(process, identity)
        except BaseException:
            if process is not None:
                if identity is not None:
                    terminate_popen(process, identity, signal.SIGTERM)
                else:
                    process.kill()
                    process.wait(timeout=2)
            raise
    if process is None or identity is None:
        raise HarnessError(f"failed to spawn owned process: {kind}")
    return process, identity


def spawn_owned(
    argv: list[str],
    *,
    kind: str,
    user: UserIdentity | None,
    stdin: int | TextIO | None,
    stdout: Any,
    stderr: Any,
    register: Callable[[subprocess.Popen[Any], ProcessIdentity], None] | None = None,
    parent_death_signal: int | None = signal.SIGTERM,
    exec_expiry_seconds: float | None = None,
) -> tuple[subprocess.Popen[str], ProcessIdentity]:
    process, identity = _spawn_captured(
        argv,
        kind=kind,
        user=user,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        text=True,
        register=register,
        parent_death_signal=parent_death_signal,
        exec_expiry_seconds=exec_expiry_seconds,
    )
    return process, identity


def _decode_mount_field(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def containing_mount(
    path: Path,
    mountinfo: Path = Path("/proc/self/mountinfo"),
    *,
    resolve_path: bool = True,
) -> str:
    resolved = str(path.resolve()) if resolve_path else str(path)
    return select_containing_mount(resolved, mountinfo.read_text(encoding="utf-8"))


def select_containing_mount(resolved: str, mountinfo_text: str) -> str:
    candidates: list[str] = []
    for line in mountinfo_text.splitlines():
        fields = line.split()
        if len(fields) < 6 or "-" not in fields:
            continue
        mount = _decode_mount_field(fields[4])
        if resolved == mount or resolved.startswith(mount.rstrip("/") + "/"):
            candidates.append(mount)
    if not candidates:
        raise HarnessError(f"no containing mount found for {resolved}")
    return max(candidates, key=len)


def parse_listeners(path: Path = Path("/proc/net/tcp")) -> dict[int, tuple[str, int]]:
    listeners: dict[int, tuple[str, int]] = {}
    try:
        lines = path.read_text(encoding="ascii").splitlines()[1:]
    except OSError as exc:
        raise HarnessError(f"cannot read listener inventory: {path}") from exc
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or fields[3] != LISTEN_STATE:
            continue
        address_hex, port_hex = fields[1].split(":", 1)
        if address_hex != LOOPBACK_HEX_V4:
            continue
        listeners[int(port_hex, 16)] = ("127.0.0.1", int(fields[9]))
    return listeners


def socket_inodes(pid: int) -> set[int]:
    result: set[int] = set()
    try:
        descriptors = Path(f"/proc/{pid}/fd").iterdir()
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            matched = re.fullmatch(r"socket:\[(\d+)\]", target)
            if matched:
                result.add(int(matched.group(1)))
    except OSError as exc:
        raise HarnessError(f"cannot inspect sockets for PID {pid}") from exc
    return result


def verify_listener_ownership(
    nodes: list[ProcessIdentity], ports: tuple[int, int, int]
) -> list[ListenerIdentity]:
    if len(nodes) != 3:
        raise HarnessError("three node identities are required")
    listeners = parse_listeners()
    result: list[ListenerIdentity] = []
    for node, port in zip(nodes, ports, strict=True):
        if not identity_matches(node):
            raise HarnessError(f"node exited or changed identity: PID {node.pid}")
        listener = listeners.get(port)
        if listener is None:
            raise HarnessError(f"owned listener not ready on port {port}")
        address, inode = listener
        if inode not in socket_inodes(node.pid):
            raise HarnessError(f"port {port} listener is not owned by PID {node.pid}")
        result.append(ListenerIdentity(address, port, inode, node.pid, node.starttime))
    return result


def tree_size(path: Path) -> int:
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def run_bounded_command(
    argv: list[str],
    *,
    user: UserIdentity | None,
    timeout: float,
    kind: str,
    stdout_limit: int = MAX_TEXT_BYTES,
    stderr_limit: int = MAX_TEXT_BYTES,
    register: Callable[[subprocess.Popen[Any], ProcessIdentity], None] | None = None,
    unregister: Callable[[ProcessIdentity], None] | None = None,
    failure_output: Path | None = None,
) -> CommandResult:
    started = time.monotonic()
    process, identity = _spawn_captured(
        argv,
        kind=kind,
        user=user,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        register=register,
        parent_death_signal=signal.SIGTERM,
        exec_expiry_seconds=None,
    )
    if process.stdout is None or process.stderr is None:
        terminate_popen(process, identity, signal.SIGTERM)
        raise HarnessError(f"command pipes unavailable: {kind}")
    watcher = selectors.DefaultSelector()
    watcher.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout_limit))
    watcher.register(process.stderr, selectors.EVENT_READ, ("stderr", stderr_limit))
    chunks: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while watcher.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            events = watcher.select(min(0.1, remaining))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in watcher.get_map().values()]
            for key, _ in events:
                name, maximum = key.data
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    watcher.unregister(key.fileobj)
                    continue
                chunks[name].extend(chunk)
                if len(chunks[name]) > maximum:
                    raise HarnessError(f"command {name} exceeded bound: {kind}")
        returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return CommandResult(
            argv,
            returncode,
            bytes(chunks["stdout"]).decode("utf-8", errors="replace"),
            bytes(chunks["stderr"]).decode("utf-8", errors="replace"),
            time.monotonic() - started,
        )
    except subprocess.TimeoutExpired as exc:
        terminate_popen(process, identity, signal.SIGTERM)
        if failure_output is not None:
            atomic_json(
                failure_output,
                {
                    "argv": argv,
                    "error": f"command timed out: {kind}",
                    "stdout_prefix": bytes(chunks["stdout"]).decode("utf-8", errors="replace"),
                    "stderr_prefix": bytes(chunks["stderr"]).decode("utf-8", errors="replace"),
                },
            )
        raise HarnessError(f"command timed out: {kind}") from exc
    except BaseException as exc:
        terminate_popen(process, identity, signal.SIGTERM)
        if failure_output is not None:
            atomic_json(
                failure_output,
                {
                    "argv": argv,
                    "error": f"{type(exc).__name__}: {exc}",
                    "stdout_prefix": bytes(chunks["stdout"]).decode("utf-8", errors="replace"),
                    "stderr_prefix": bytes(chunks["stderr"]).decode("utf-8", errors="replace"),
                },
            )
        raise
    finally:
        watcher.close()
        if unregister is not None and process.poll() is not None:
            unregister(identity)


def run_bounded_file_command(
    argv: list[str],
    *,
    stdout_path: Path,
    stderr_path: Path,
    stdout_limit: int,
    stderr_limit: int,
    timeout: float,
    kind: str,
    register: Callable[[subprocess.Popen[Any], ProcessIdentity], None] | None = None,
    unregister: Callable[[ProcessIdentity], None] | None = None,
) -> CommandResult:
    started = time.monotonic()
    stderr_chunks = bytearray()
    with stdout_path.open("wb") as output:
        process, identity = _spawn_captured(
            argv,
            kind=kind,
            user=None,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.PIPE,
            text=False,
            register=register,
            parent_death_signal=signal.SIGTERM,
            exec_expiry_seconds=None,
        )
        if process.stderr is None:
            terminate_popen(process, identity, signal.SIGTERM)
            raise HarnessError(f"command stderr unavailable: {kind}")
        os.set_blocking(process.stderr.fileno(), False)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(argv, timeout)
                if stdout_path.stat().st_size > stdout_limit:
                    raise HarnessError(f"command stdout exceeded bound: {kind}")
                ready, _, _ = select.select([process.stderr], [], [], 0.05)
                if ready:
                    chunk = os.read(process.stderr.fileno(), 8192)
                    stderr_chunks.extend(chunk)
                    if len(stderr_chunks) > stderr_limit:
                        raise HarnessError(f"command stderr exceeded bound: {kind}")
            os.set_blocking(process.stderr.fileno(), True)
            while True:
                chunk = os.read(process.stderr.fileno(), 8192)
                if not chunk:
                    break
                stderr_chunks.extend(chunk)
                if len(stderr_chunks) > stderr_limit:
                    raise HarnessError(f"command stderr exceeded bound: {kind}")
            output.flush()
            if stdout_path.stat().st_size > stdout_limit:
                raise HarnessError(f"command stdout exceeded bound: {kind}")
            return CommandResult(
                argv,
                int(process.returncode),
                "",
                bytes(stderr_chunks).decode("utf-8", errors="replace"),
                time.monotonic() - started,
            )
        except subprocess.TimeoutExpired as exc:
            terminate_popen(process, identity, signal.SIGTERM)
            raise HarnessError(f"command timed out: {kind}") from exc
        except BaseException:
            terminate_popen(process, identity, signal.SIGTERM)
            raise
        finally:
            stderr_path.write_text(
                bytes(stderr_chunks).decode("utf-8", errors="replace"), encoding="utf-8"
            )
            if unregister is not None and process.poll() is not None:
                unregister(identity)


def validate_decoder_result(result: CommandResult) -> None:
    if result.returncode != 0:
        raise HarnessError(f"tcpdump decoder failed with exit code {result.returncode}")


def capture_process_states(
    processes: list[tuple[subprocess.Popen[Any], ProcessIdentity]],
) -> list[dict[str, Any]]:
    states: list[dict[str, Any]] = []
    for process, identity in processes:
        returncode = process.poll()
        states.append(
            {
                "kind": identity.kind,
                "pid": identity.pid,
                "starttime": identity.starttime,
                "running": returncode is None and identity_matches(identity),
                "returncode": returncode,
            }
        )
    return states


def validate_capture_process_states(states: list[dict[str, Any]]) -> None:
    failed = [state for state in states if state.get("running") is not True]
    if failed:
        summary = ", ".join(f"{state.get('kind')}={state.get('returncode')}" for state in failed)
        raise HarnessError(f"capture process exited or changed identity before shutdown: {summary}")


def expected_capture_stop(returncode: int | None) -> bool:
    return returncode in {0, -signal.SIGINT, 128 + signal.SIGINT}


def client_argv(config: RunConfig, operation: list[str]) -> list[str]:
    return [str(config.client_binary), *(str(port) for port in config.ports), *operation]


def strace_prefix(strace: str, output: Path) -> list[str]:
    return [
        strace,
        "-ff",
        "-ttt",
        "-T",
        "-yy",
        "-s",
        "256",
        "-e",
        "trace=%file,%network,fsync,fdatasync,pwrite64,ftruncate",
        "-o",
        str(output),
    ]


def run_client(
    config: RunConfig,
    operation: list[str],
    *,
    strace: str | None = None,
    trace_output: Path | None = None,
    register: Callable[[subprocess.Popen[Any], ProcessIdentity], None] | None = None,
    unregister: Callable[[ProcessIdentity], None] | None = None,
    failure_output: Path | None = None,
) -> CommandResult:
    argv = client_argv(config, operation)
    user: UserIdentity | None = config.run_user
    if strace is not None:
        if trace_output is None:
            raise HarnessError("traced client requires an output prefix")
        argv = [*strace_prefix(strace, trace_output), "-u", config.run_user.name, "--", *argv]
        user = None
    return run_bounded_command(
        argv,
        user=user,
        timeout=12,
        kind="traced-client" if strace is not None else "client",
        register=register,
        unregister=unregister,
        failure_output=failure_output,
    )


def validate_status(result: CommandResult) -> None:
    if result.returncode != 0:
        raise HarnessError(f"STATUS failed with exit code {result.returncode}")
    lines = [line for line in result.stdout.splitlines() if line]
    if len(lines) != 3 or any(
        re.match(r"^node [123] role (leader|candidate|follower) term \d+ leader ", line) is None
        for line in lines
    ):
        raise HarnessError("STATUS output is not three valid node snapshots")


def validate_put(result: CommandResult, request_id: str) -> None:
    if result.returncode != 0:
        raise HarnessError(f"PUT {request_id} failed with exit code {result.returncode}")
    if re.fullmatch(r"committed term \d+ index \d+\n?", result.stdout) is None:
        raise HarnessError(f"PUT {request_id} did not report committed")
    if f"request id {request_id}" not in result.stderr:
        raise HarnessError(f"PUT {request_id} did not echo its request ID")


def validate_get(result: CommandResult, expected: str) -> None:
    if result.returncode != 0:
        raise HarnessError(f"GET failed with exit code {result.returncode}")
    if result.stdout != expected + "\n":
        raise HarnessError("GET returned a different value")


def run_workload(
    config: RunConfig,
    phase: str,
    *,
    strace: str | None,
    trace_dir: Path,
    register: Callable[[subprocess.Popen[Any], ProcessIdentity], None] | None = None,
    unregister: Callable[[ProcessIdentity], None] | None = None,
) -> dict[str, Any]:
    started_utc = utc_now()
    started = time.monotonic()
    records: list[dict[str, Any]] = []
    operation_log = config.output / "logs" / f"workload-{phase}.jsonl"
    run_tag = hashlib.sha256(str(config.output).encode()).hexdigest()[:12]
    for index in range(config.pairs):
        key = f"task13-{run_tag}-{phase}-{index}"
        value = f"fleetdoctor-{phase}-value-{index:02d}"
        request_id = hashlib.sha256(key.encode()).hexdigest()[:32]
        put_trace = trace_dir / f"client-{phase}-{index:02d}-put"
        get_trace = trace_dir / f"client-{phase}-{index:02d}-get"
        put = run_client(
            config,
            ["put", key, value, request_id],
            strace=strace,
            trace_output=put_trace if strace else None,
            register=register,
            unregister=unregister,
            failure_output=config.output / "logs" / f"client-{phase}-{index:02d}-put-failure.json",
        )
        put_record = {
            "phase": phase,
            "operation": "put",
            "index": index,
            "key": key,
            "expected_value": value,
            "request_id": request_id,
            "result": asdict(put),
        }
        with operation_log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(put_record, separators=(",", ":")) + "\n")
        try:
            validate_put(put, request_id)
        except HarnessError as exc:
            with operation_log.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {"semantic_failure": str(exc), "operation": put_record},
                        separators=(",", ":"),
                    )
                    + "\n"
                )
            raise
        get = run_client(
            config,
            ["get", key],
            strace=strace,
            trace_output=get_trace if strace else None,
            register=register,
            unregister=unregister,
            failure_output=config.output / "logs" / f"client-{phase}-{index:02d}-get-failure.json",
        )
        get_record = {
            "phase": phase,
            "operation": "get",
            "index": index,
            "key": key,
            "expected_value": value,
            "result": asdict(get),
        }
        with operation_log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(get_record, separators=(",", ":")) + "\n")
        try:
            validate_get(get, value)
        except HarnessError as exc:
            with operation_log.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {"semantic_failure": str(exc), "operation": get_record},
                        separators=(",", ":"),
                    )
                    + "\n"
                )
            raise
        records.append(
            {
                "index": index,
                "key": key,
                "value": value,
                "request_id": request_id,
                "put": asdict(put),
                "get": asdict(get),
            }
        )
        if index + 1 < config.pairs:
            time.sleep(config.pace_seconds)
    remaining = 15.0 - (time.monotonic() - started)
    if remaining > 0:
        time.sleep(remaining)
    ended = time.monotonic()
    return {
        "phase": phase,
        "started_utc": started_utc,
        "started_monotonic": started,
        "ended_utc": utc_now(),
        "ended_monotonic": ended,
        "elapsed_seconds": ended - started,
        "pairs": records,
    }


def parse_pcap(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size > MAX_PCAP_BYTES:
            return {"valid": False, "classification": "oversize", "size_bytes": size}
        data = path.read_bytes()
    except OSError as exc:
        return {"valid": False, "classification": "unreadable", "error": type(exc).__name__}
    if size == 0:
        return {"valid": False, "classification": "empty", "size_bytes": 0}
    if len(data) < PCAP_HEADER_BYTES:
        return {"valid": False, "classification": "truncated", "size_bytes": size}
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
        b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
        b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
        b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
    }
    selected = formats.get(magic)
    if selected is None:
        return {"valid": False, "classification": "invalid_magic", "size_bytes": size}
    endian, timestamp_precision = selected
    major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(
        endian + "HHIIII", data[4:PCAP_HEADER_BYTES]
    )
    if (major, minor) != (2, 4) or not 1 <= snaplen <= 262144 or linktype == 0:
        return {
            "valid": False,
            "classification": "invalid_header",
            "size_bytes": size,
            "version": [major, minor],
            "snaplen": snaplen,
            "linktype": linktype,
        }
    offset = PCAP_HEADER_BYTES
    packets = 0
    payload_truncations = 0
    while offset < len(data):
        if len(data) - offset < 16:
            return {
                "valid": False,
                "classification": "truncated_packet_header",
                "size_bytes": size,
                "packets": packets,
                "payload_truncations": payload_truncations,
            }
        _seconds, fraction, included, original = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        if (
            included > snaplen
            or included > original
            or (timestamp_precision == "microseconds" and fraction >= 1_000_000)
            or (timestamp_precision == "nanoseconds" and fraction >= 1_000_000_000)
        ):
            return {
                "valid": False,
                "classification": "invalid_packet_header",
                "size_bytes": size,
                "packets": packets,
                "payload_truncations": payload_truncations,
            }
        if included < original:
            payload_truncations += 1
        offset += 16
        if len(data) - offset < included:
            return {
                "valid": False,
                "classification": "truncated_packet_data",
                "size_bytes": size,
                "packets": packets,
                "payload_truncations": payload_truncations,
            }
        offset += included
        packets += 1
    return {
        "valid": packets > 0,
        "classification": "valid" if packets > 0 else "header_only",
        "size_bytes": size,
        "packets": packets,
        "payload_truncations": payload_truncations,
        "timestamp_precision": timestamp_precision,
        "snaplen": snaplen,
        "linktype": linktype,
    }


def classify_pcap(
    path: Path, decoded: str, tcpdump_stderr: str, ports: tuple[int, int, int]
) -> dict[str, Any]:
    structure = parse_pcap(path)
    if not structure.get("valid"):
        return {"usable": False, **structure}
    captured_match = re.search(r"(\d+) packets captured", tcpdump_stderr)
    dropped_match = re.search(r"(\d+) packets dropped by kernel", tcpdump_stderr)
    captured = int(captured_match.group(1)) if captured_match else None
    dropped = int(dropped_match.group(1)) if dropped_match else None
    payload_truncations = structure.get("payload_truncations")
    port_evidence = any(f".{port}" in decoded or f":{port}" in decoded for port in ports)
    timestamped = any(
        re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+", line)
        for line in decoded.splitlines()
    )
    usable = bool(
        decoded.strip()
        and timestamped
        and port_evidence
        and captured
        and dropped == 0
        and payload_truncations == 0
    )
    return {
        "usable": usable,
        "classification": "usable" if usable else "partial",
        "structure": structure,
        "captured_packets": captured,
        "kernel_drops": dropped,
        "payload_truncations": payload_truncations,
        "decoded_nonempty": bool(decoded.strip()),
        "decoded_timestamped": timestamped,
        "configured_port_evidence": port_evidence,
    }


def classify_traces(directory: Path) -> dict[str, Any]:
    paths = sorted(item for item in directory.glob("*") if item.is_file())
    total = sum(item.stat().st_size for item in paths)
    if not paths:
        return {"usable": False, "classification": "empty", "files": 0, "size_bytes": 0}
    if total > MAX_TRACE_BYTES:
        return {
            "usable": False,
            "classification": "oversize",
            "files": len(paths),
            "size_bytes": total,
        }
    fragments: list[str] = []
    for path in paths:
        with path.open("rb") as stream:
            fragments.append(stream.read(2 * 1024 * 1024).decode("utf-8", errors="replace"))
    text = "\n".join(fragments)
    successful_lines = [
        line
        for line in text.splitlines()
        if re.match(r"^\d+\.\d+ ", line) and re.search(r"= (?!-1(?:\s|$))", line)
    ]
    successful = "\n".join(successful_lines)
    storage = re.search(r"\b(pwrite64|fdatasync|fsync|ftruncate)\(", successful) is not None
    network = re.search(
        r"\b(connect|accept|accept4|sendto|sendmsg|recvfrom|recvmsg)\(", successful
    ) is not None and ("127.0.0.1" in successful or "TCP" in successful)
    return {
        "usable": storage and network,
        "classification": "usable" if storage and network else "partial",
        "files": len(paths),
        "size_bytes": total,
        "representative_storage_syscall": storage,
        "representative_tcp_syscall": network,
        "successful_timestamped_lines": len(successful_lines),
    }


def _sample_container(value: dict[str, Any], key: str, kind: type[Any], label: str) -> Any:
    item = value.get(key)
    if not isinstance(item, kind):
        raise HarnessError(f"direct sample {label}.{key} has invalid type")
    return item


def validate_sample_record(value: Any, line_number: int) -> dict[str, Any]:
    """Validate every nested container and typed value consumed by assessment."""
    label = f"line {line_number}"
    if not isinstance(value, dict):
        raise HarnessError(f"direct sample {label} is not an object")
    monotonic = value.get("monotonic")
    if (
        isinstance(monotonic, bool)
        or not isinstance(monotonic, (int, float))
        or not math.isfinite(float(monotonic))
    ):
        raise HarnessError(f"direct sample {label}.monotonic is invalid")
    result = _sample_container(value, "result", dict, label)
    sections: dict[str, dict[str, Any]] = {}
    for section_name in ("cpu", "memory", "fd", "network", "io"):
        section = _sample_container(result, section_name, dict, f"{label}.result")
        errors = section.get("errors", [])
        if not isinstance(errors, list):
            raise HarnessError(
                f"direct sample {label}.result.{section_name}.errors has invalid type"
            )
        if any(not isinstance(item, str) or len(item) > 512 for item in errors):
            raise HarnessError(f"direct sample {label}.result.{section_name}.errors is invalid")
        sections[section_name] = section

    cpu_processes = _sample_container(sections["cpu"], "processes", list, f"{label}.result.cpu")
    for index, process in enumerate(cpu_processes):
        process_label = f"{label}.result.cpu.processes[{index}]"
        if not isinstance(process, dict):
            raise HarnessError(f"direct sample {process_label} is not an object")
        identity = _sample_container(process, "identity", dict, process_label)
        if type(identity.get("pid")) is not int or type(identity.get("starttime_ticks")) is not int:
            raise HarnessError(f"direct sample {process_label}.identity is invalid")
        if type(process.get("configured")) is not bool:
            raise HarnessError(f"direct sample {process_label}.configured is invalid")
        rss = process.get("rss_bytes")
        if rss is not None and (type(rss) is not int or rss < 0):
            raise HarnessError(f"direct sample {process_label}.rss_bytes is invalid")
        cpu = process.get("cpu_percent")
        if cpu is not None and (
            isinstance(cpu, bool)
            or not isinstance(cpu, (int, float))
            or not math.isfinite(float(cpu))
        ):
            raise HarnessError(f"direct sample {process_label}.cpu_percent is invalid")

    fd_observations = _sample_container(sections["fd"], "observations", list, f"{label}.result.fd")
    for index, process in enumerate(fd_observations):
        process_label = f"{label}.result.fd.observations[{index}]"
        if not isinstance(process, dict):
            raise HarnessError(f"direct sample {process_label} is not an object")
        identity = _sample_container(process, "identity", dict, process_label)
        if type(identity.get("pid")) is not int or type(identity.get("starttime_ticks")) is not int:
            raise HarnessError(f"direct sample {process_label}.identity is invalid")
        if not isinstance(process.get("status"), str):
            raise HarnessError(f"direct sample {process_label}.status is invalid")
        if type(process.get("configured")) is not bool:
            raise HarnessError(f"direct sample {process_label}.configured is invalid")
        count = process.get("descriptor_count")
        if count is not None and (type(count) is not int or count < 0):
            raise HarnessError(f"direct sample {process_label}.descriptor_count is invalid")

    io_processes = _sample_container(sections["io"], "processes", list, f"{label}.result.io")
    for index, process in enumerate(io_processes):
        process_label = f"{label}.result.io.processes[{index}]"
        if not isinstance(process, dict):
            raise HarnessError(f"direct sample {process_label} is not an object")
        if type(process.get("pid")) is not int:
            raise HarnessError(f"direct sample {process_label} identity is invalid")
        status = process.get("status")
        rate_status = process.get("rate_status")
        starttime = process.get("starttime")
        if status not in {"available", "unavailable"}:
            raise HarnessError(f"direct sample {process_label}.status is invalid")
        if rate_status not in {"available", "baseline", "reset", "gap", "unavailable"}:
            raise HarnessError(f"direct sample {process_label}.rate_status is invalid")
        if (status == "available" and type(starttime) is not int) or (
            status == "unavailable" and starttime is not None
        ):
            raise HarnessError(f"direct sample {process_label}.starttime is invalid")
    return value


def parse_sample_records(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise HarnessError(f"direct sample line {line_number} is empty")
        try:
            value = json.loads(
                line,
                parse_constant=lambda constant: (_ for _ in ()).throw(
                    ValueError(f"non-finite JSON constant: {constant}")
                ),
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise HarnessError(
                f"direct sample line {line_number} is malformed or non-finite JSON"
            ) from exc
        records.append(validate_sample_record(value, line_number))
    return records


def sample_assessment(
    records: list[dict[str, Any]],
    nodes: list[ProcessIdentity],
    phases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    records = [
        validate_sample_record(record, index) for index, record in enumerate(records, start=1)
    ]
    expected = {(item.pid, item.starttime) for item in nodes}
    cpu_seen: set[tuple[int, int]] = set()
    rss_seen: set[tuple[int, int]] = set()
    fd_seen: set[tuple[int, int]] = set()
    io_nonbaseline: set[tuple[int, int]] = set()
    cpu_nonbaseline: set[tuple[int, int]] = set()
    replacements: set[tuple[int, int]] = set()
    unrelated_cpu_context = 0
    errors: list[str] = []
    for record in records:
        result = record.get("result", {})
        for process in result.get("cpu", {}).get("processes", []):
            identity = process.get("identity", {})
            key = (identity.get("pid"), identity.get("starttime_ticks"))
            if all(type(value) is int for value in key):
                typed_key = int(key[0]), int(key[1])
                if typed_key in expected:
                    cpu_seen.add(typed_key)
                    if process.get("configured") is True and process.get("rss_bytes") is not None:
                        rss_seen.add(typed_key)
                    if process.get("cpu_percent") is not None:
                        cpu_nonbaseline.add(typed_key)
                elif any(item.pid == typed_key[0] for item in nodes):
                    replacements.add(typed_key)
                else:
                    unrelated_cpu_context += 1
        for process in result.get("fd", {}).get("observations", []):
            identity = process.get("identity", {})
            key = (identity.get("pid"), identity.get("starttime_ticks"))
            if all(type(value) is int for value in key):
                typed_key = int(key[0]), int(key[1])
                if (
                    typed_key in expected
                    and process.get("status") == "present"
                    and process.get("configured") is True
                    and process.get("descriptor_count") is not None
                ):
                    fd_seen.add(typed_key)
                elif any(item.pid == typed_key[0] for item in nodes) and typed_key not in expected:
                    replacements.add(typed_key)
        for process in result.get("io", {}).get("processes", []):
            key = (process.get("pid"), process.get("starttime"))
            if all(type(value) is int for value in key):
                typed_key = int(key[0]), int(key[1])
                if typed_key in expected and process.get("rate_status") == "available":
                    io_nonbaseline.add(typed_key)
                elif any(item.pid == typed_key[0] for item in nodes) and typed_key not in expected:
                    replacements.add(typed_key)
        for section in ("cpu", "memory", "fd", "network", "io"):
            errors.extend(str(item) for item in result.get(section, {}).get("errors", []))
    identity_stable = not replacements and expected.issubset(cpu_seen)
    phase_coverage: dict[str, int] = {}
    for phase in phases or []:
        name = str(phase.get("phase"))
        start = phase.get("started_monotonic")
        end = phase.get("ended_monotonic")
        if isinstance(start, (int, float)) and isinstance(end, (int, float)):
            phase_coverage[name] = sum(
                isinstance(record.get("monotonic"), (int, float))
                and float(start) <= float(record["monotonic"]) <= float(end)
                for record in records
            )
    missing = {
        "cpu_identity": sorted(expected - cpu_seen),
        "cpu_nonbaseline": sorted(expected - cpu_nonbaseline),
        "rss": sorted(expected - rss_seen),
        "fd_present_count": sorted(expected - fd_seen),
        "io_nonbaseline": sorted(expected - io_nonbaseline),
    }
    complete = (
        identity_stable
        and all(not values for values in missing.values())
        and all(count >= 3 for count in phase_coverage.values())
    )
    return {
        "sample_count": len(records),
        "expected_identities": sorted(expected),
        "cpu_seen_identities": sorted(cpu_seen),
        "identity_stable": identity_stable,
        "replacement_identities": sorted(replacements),
        "unrelated_cpu_context_rows": unrelated_cpu_context,
        "cpu_nonbaseline_identities": sorted(cpu_nonbaseline),
        "rss_identities": sorted(rss_seen),
        "fd_present_count_identities": sorted(fd_seen),
        "io_nonbaseline_identities": sorted(io_nonbaseline),
        "phase_sample_counts": phase_coverage,
        "missing": missing,
        "coverage": "available" if complete else "partial",
        "errors": sorted(set(errors)),
    }


def _load_processes(value: Any) -> list[ProcessIdentity]:
    if not isinstance(value, list):
        return []
    result: list[ProcessIdentity] = []
    for item in value:
        try:
            result.append(ProcessIdentity(**item))
        except (TypeError, ValueError):
            continue
    return result


def _load_root_state(path: Path) -> dict[str, Any]:
    try:
        value = bounded_owned_json(path, expected_uid=effective_uid())
    except (OSError, HarnessError):
        return {}
    return value if isinstance(value, dict) else {}


def watchdog_targets(state_path: Path, learned_path: Path | None = None) -> list[ProcessIdentity]:
    state = _load_root_state(state_path)
    result = _load_processes(state.get("processes"))
    run_uid = state.get("run_uid")
    sampler_values = _load_processes([state.get("sampler")])
    sampler = sampler_values[0] if sampler_values else None
    learned: list[ProcessIdentity] = []
    if learned_path is not None:
        learned = _load_processes(_load_root_state(learned_path).get("processes"))
    for item in learned:
        if type(run_uid) is not int or item.uid != run_uid or not identity_matches(item):
            continue
        if (
            sampler is not None
            and identity_matches(sampler)
            and not is_descendant_of(item.pid, sampler)
        ):
            continue
        result.append(item)
    unique = {(item.pid, item.starttime): item for item in result}
    return list(unique.values())


def watchdog_cleanup(
    state_path: Path,
    learned_path: Path | None = None,
    extra_targets: list[ProcessIdentity] | None = None,
) -> None:
    targets = watchdog_targets(state_path, learned_path)
    for item in extra_targets or []:
        if (item.pid, item.starttime) not in {(value.pid, value.starttime) for value in targets}:
            targets.append(item)
    for item in reversed(targets):
        signal_owned(item, signal.SIGTERM)
    deadline = time.monotonic() + 1.5
    while time.monotonic() < deadline and any(identity_matches(item) for item in targets):
        time.sleep(0.05)
    for item in reversed(targets):
        if identity_matches(item):
            signal_owned(item, signal.SIGKILL)


def watchdog_main(state_path: Path, learned_path: Path, deadline_monotonic: float) -> int:
    direct_cache: dict[tuple[int, int], ProcessIdentity] = {}
    learned_cache: dict[tuple[int, int], ProcessIdentity] = {}

    def refresh() -> None:
        state = _load_root_state(state_path)
        direct = _load_processes(state.get("processes"))
        for item in direct:
            if identity_matches(item):
                direct_cache[(item.pid, item.starttime)] = item
        run_uid = state.get("run_uid")
        samplers = _load_processes([state.get("sampler")])
        if type(run_uid) is int and samplers:
            sampler = samplers[0]
            for item in discover_descendants(sampler, run_uid):
                learned_cache[(item.pid, item.starttime)] = item
        atomic_json(
            learned_path,
            {
                "processes": [asdict(item) for item in learned_cache.values()],
                "updated_utc": utc_now(),
            },
        )

    while True:
        refresh()
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            watchdog_cleanup(
                state_path, learned_path, [*direct_cache.values(), *learned_cache.values()]
            )
            return 2
        ready, _, _ = select.select([sys.stdin], [], [], min(0.5, remaining))
        if not ready:
            continue
        line = sys.stdin.readline()
        if line == "DISARM\n":
            return 0
        if line == "":
            refresh()
            watchdog_cleanup(
                state_path, learned_path, [*direct_cache.values(), *learned_cache.values()]
            )
            return 1


def _sampler_result(value: Any) -> Any:
    if isinstance(value, list):
        return [item.model_dump(mode="json") for item in value]
    return value.model_dump(mode="json")


def sampler_main(config_path: Path) -> int:
    from fleetdoctor.supervisor import CollectionSupervisor

    settings = bounded_owned_json(config_path, expected_uid=0)
    if not isinstance(settings, dict):
        raise HarnessError("direct sampler configuration is not an object")
    expected_uid = int(settings["uid"])
    if os.geteuid() != expected_uid:
        raise HarnessError("direct sampler UID does not match KV run UID")
    nodes = _load_processes(settings["nodes"])
    if len(nodes) != 3 or any(
        item.uid != expected_uid or not identity_matches(item) for item in nodes
    ):
        raise HarnessError("direct sampler received unstable node identities")
    output = Path(settings["samples"])
    ready = Path(settings["ready"])
    auxiliary = Path(settings["aux_state"])
    stopped = False

    def stop_sampler(_signum: int, _frame: object) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop_sampler)
    signal.signal(signal.SIGINT, stop_sampler)
    supervisor = CollectionSupervisor()
    if not supervisor.wait_ready(1.0) or supervisor.process is None:
        raise HarnessError("production collection supervisor did not become ready")

    def publish_children() -> None:
        processes: list[dict[str, Any]] = []
        if supervisor.process is not None and supervisor.process.pid is not None:
            processes.append(
                asdict(capture_identity("collection-supervisor", supervisor.process.pid))
            )
        atomic_json(auxiliary, {"processes": processes, "updated_utc": utc_now()})

    publish_children()
    atomic_json(
        ready,
        {
            "status": "ready",
            "uid": os.geteuid(),
            "nodes": [asdict(item) for item in nodes],
            "mount": settings["mount"],
            "updated_utc": utc_now(),
        },
    )
    boot = UUID(Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip())
    session = uuid4()
    sequence = 0
    next_tick = time.monotonic()
    terminal: dict[str, Any] = {"status": "running"}
    try:
        with output.open("a", encoding="utf-8") as stream:
            while not stopped and time.monotonic() < float(settings["deadline_monotonic"]):
                if any(not identity_matches(item) for item in nodes):
                    raise HarnessError("node identity changed during direct sampling")
                collected = supervisor.collect_all(
                    boot,
                    session,
                    sequence,
                    (str(settings["mount"]),),
                    tuple(item.pid for item in nodes),
                    (),
                    (),
                    "unavailable",
                    None,
                    "direct_sampler_no_collector_watch",
                    None,
                    None,
                    (str(settings["mount"]),),
                    tuple(item.pid for item in nodes),
                )
                record = {
                    "observed_at": utc_now(),
                    "monotonic": time.monotonic(),
                    "sequence": sequence,
                    "collection_mode": "direct_production_supervisor",
                    "result": {
                        "filesystems": _sampler_result(collected.filesystems),
                        "cpu": _sampler_result(collected.cpu),
                        "memory": _sampler_result(collected.memory),
                        "fd": _sampler_result(collected.fd),
                        "network": _sampler_result(collected.network),
                        "dns": _sampler_result(collected.dns)
                        if collected.dns is not None
                        else None,
                        "io": _sampler_result(collected.io),
                    },
                }
                encoded = json.dumps(record, separators=(",", ":"))
                if len(encoded.encode()) > 512 * 1024:
                    raise HarnessError("direct sample exceeds 512KiB")
                stream.write(encoded + "\n")
                stream.flush()
                sequence += 1
                publish_children()
                next_tick += 5.0
                while not stopped and time.monotonic() < next_tick:
                    time.sleep(min(0.1, next_tick - time.monotonic()))
        terminal = {"status": "stopped", "samples": sequence, "updated_utc": utc_now()}
        return 0
    except BaseException as exc:
        terminal = {
            "status": "failed",
            "samples": sequence,
            "error": f"{type(exc).__name__}: {exc}",
            "updated_utc": utc_now(),
        }
        raise
    finally:
        supervisor.close(time.monotonic() + 2.0)
        atomic_json(auxiliary, {"processes": [], "terminal": terminal})


def wait_for_owned_json(
    path: Path,
    timeout: float,
    *,
    expected_uid: int,
    process: subprocess.Popen[str] | None = None,
) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.lexists(path):
            return bounded_owned_json(path, expected_uid=expected_uid)
        if process is not None and process.poll() is not None:
            raise HarnessError(f"process exited before readiness file: {path.name}")
        time.sleep(0.05)
    raise HarnessError(f"timed out waiting for readiness file: {path.name}")


def validate_sampler_ready(
    value: Any,
    *,
    expected_uid: int,
    expected_nodes: list[ProcessIdentity],
    expected_mount: str,
) -> dict[str, Any]:
    expected_keys = {"status", "uid", "nodes", "mount", "updated_utc"}
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise HarnessError("sampler readiness has unexpected fields")
    expected_node_values = [asdict(item) for item in expected_nodes]
    if (
        value.get("status") != "ready"
        or value.get("uid") != expected_uid
        or value.get("nodes") != expected_node_values
        or value.get("mount") != expected_mount
    ):
        raise HarnessError("sampler readiness does not bind the expected scope")
    updated = value.get("updated_utc")
    if not isinstance(updated, str) or len(updated) > 64:
        raise HarnessError("sampler readiness timestamp is invalid")
    try:
        datetime.fromisoformat(updated)
    except ValueError as exc:
        raise HarnessError("sampler readiness timestamp is invalid") from exc
    return {
        "status": "ready",
        "uid": expected_uid,
        "nodes": expected_node_values,
        "mount": expected_mount,
        "updated_utc": updated,
    }


def wait_for_gate(
    path: Path,
    readiness_sha256: str,
    timeout: int,
    *,
    expected_uid: int = 0,
) -> dict[str, Any]:
    if os.path.lexists(path):
        raise HarnessError("start gate already exists; refuse stale release")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.lexists(path):
            if sys.platform == "linux":
                value = bounded_owned_json(path, expected_uid=expected_uid)
            else:
                try:
                    value = json.loads(bounded_text(path))
                except json.JSONDecodeError as exc:
                    raise HarnessError("start gate is unreadable or malformed") from exc
            if not isinstance(value, dict) or value != {
                "release": True,
                "readiness_sha256": readiness_sha256,
            }:
                raise HarnessError("start gate does not bind the current readiness file")
            return dict(value)
        time.sleep(0.1)
    raise HarnessError("start gate timed out")


def wait_for_log(path: Path, pattern: str, process: subprocess.Popen[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise HarnessError(f"process exited before readiness: {path.name}")
        try:
            text = bounded_text(path)
        except FileNotFoundError:
            text = ""
        if pattern in text:
            return
        time.sleep(0.05)
    raise HarnessError(f"readiness text not observed in {path.name}: {pattern}")


def parse_config(args: argparse.Namespace) -> RunConfig:
    if sys.platform != "linux":
        raise HarnessError("actual capture is supported only on Linux")
    if os.geteuid() != 0:
        raise HarnessError("actual capture requires a root controller")
    ports = validate_ports(args.ports)
    revision = _validate_hex(args.kv_revision, 40, "KV revision")
    archive_hash = _validate_hex(args.source_archive_sha256, 64, "source archive SHA256")
    if not 1 <= args.pairs <= 16:
        raise HarnessError("pairs must be in 1..16")
    if not 0 <= args.pace_seconds <= 10 or args.pairs * args.pace_seconds < 15:
        raise HarnessError("phase pacing must cover at least three five-second sample windows")
    if not 45 <= args.max_runtime_seconds <= 600:
        raise HarnessError("max runtime must be in 45..600 seconds")
    if not 1 <= args.gate_timeout_seconds <= args.max_runtime_seconds:
        raise HarnessError("gate timeout must fit inside max runtime")
    if not 1024 * 1024 <= args.max_output_bytes <= 256 * 1024 * 1024:
        raise HarnessError("max output bytes must be in 1MiB..256MiB")
    requested_output = Path(args.output)
    refuse_existing_output(requested_output)
    output = Path(os.path.abspath(requested_output))
    node_path = Path(args.node_binary)
    client_path = Path(args.client_binary)
    archive_path = Path(args.source_archive)
    if args.start_gate and not Path(args.start_gate).is_absolute():
        raise HarnessError("start gate must be absolute")
    gate_path = Path(os.path.abspath(args.start_gate)) if args.start_gate else None
    validate_runtime_trust(
        output=output,
        gate_path=gate_path,
        node_binary=node_path,
        client_binary=client_path,
        source_archive=archive_path,
    )
    node = require_executable(node_path, "node binary")
    client = require_executable(client_path, "client binary")
    archive = archive_path
    if not archive.is_file() or sha256_file(archive) != archive_hash:
        raise HarnessError("source archive hash mismatch")
    ports_available(ports)
    return RunConfig(
        node,
        client,
        archive,
        archive_hash,
        revision,
        output,
        ports,
        resolve_user(args.run_user),
        args.pairs,
        args.pace_seconds,
        args.max_runtime_seconds,
        gate_path,
        args.gate_timeout_seconds,
        args.max_output_bytes,
    )


class Controller:
    def __init__(self, config: RunConfig) -> None:
        self.config = config
        started_utc = utc_now()
        started_monotonic = time.monotonic()
        self.manifest: dict[str, Any] = {
            "schema_version": 1,
            "status": "running",
            "started_utc": started_utc,
            "started_monotonic": started_monotonic,
            "clock_correlation": {"utc": started_utc, "monotonic": started_monotonic},
            "source": {
                "revision": config.kv_revision,
                "archive": str(config.source_archive),
                "archive_sha256": config.source_archive_sha256,
                "node_binary": str(config.node_binary),
                "node_sha256": sha256_file(config.node_binary),
                "client_binary": str(config.client_binary),
                "client_sha256": sha256_file(config.client_binary),
            },
            "topology": {
                "placement": "one_linux_host",
                "listen_address": "127.0.0.1",
                "ports": list(config.ports),
                "shared_host_limit": True,
            },
            "controller": {"uid": effective_uid(), "gid": effective_gid()},
            "run_user": asdict(config.run_user),
            "commands": [],
            "processes": [],
            "cleanup": [],
        }
        self.processes: list[tuple[subprocess.Popen[Any], ProcessIdentity]] = []
        self.node_processes: list[tuple[subprocess.Popen[str], ProcessIdentity]] = []
        self.open_files: list[TextIO] = []
        self.watchdog: subprocess.Popen[str] | None = None
        self.watchdog_identity: ProcessIdentity | None = None
        self.sampler_identity: ProcessIdentity | None = None
        self.learned_sampler_descendants: dict[tuple[int, int], ProcessIdentity] = {}
        self.deadline_monotonic = time.monotonic() + config.max_runtime_seconds

    @property
    def manifest_path(self) -> Path:
        return self.config.output / "manifest.json"

    @property
    def watchdog_state_path(self) -> Path:
        return self.config.output / "control" / "watchdog-state.json"

    @property
    def watchdog_learned_path(self) -> Path:
        return self.config.output / "control" / "watchdog-learned.json"

    def save(self) -> None:
        atomic_json(self.manifest_path, self.manifest)
        atomic_json(
            self.watchdog_state_path,
            {
                "processes": [asdict(identity) for _, identity in self.processes],
                "run_uid": self.config.run_user.uid,
                "sampler": asdict(self.sampler_identity) if self.sampler_identity else None,
                "updated_utc": utc_now(),
            },
        )

    def prepare_output(self) -> None:
        self.config.output.mkdir(mode=0o750)
        os.chown(self.config.output, 0, self.config.run_user.gid)
        os.chmod(self.config.output, 0o750)
        for name in ("control", "data", "logs", "traces", "captures", "samples"):
            (self.config.output / name).mkdir(mode=0o750)
            os.chown(self.config.output / name, 0, self.config.run_user.gid)
            os.chmod(self.config.output / name, 0o750)
        for node in range(1, 4):
            path = self.config.output / "data" / f"node-{node}"
            path.mkdir(mode=0o750)
            os.chown(path, self.config.run_user.uid, self.config.run_user.gid)
        sampler_control = self.config.output / "control" / "sampler"
        sampler_control.mkdir(mode=0o750)
        os.chown(sampler_control, self.config.run_user.uid, self.config.run_user.gid)
        for name in ("data", "samples"):
            os.chown(self.config.output / name, self.config.run_user.uid, self.config.run_user.gid)
        self.manifest["environment"] = {
            "platform": platform.platform(),
            "uname": list(platform.uname()),
            "python": sys.version,
            "tools": {},
        }
        runtime_files = [
            *protected_runtime_files(),
            self.config.node_binary,
            self.config.client_binary,
            self.config.source_archive,
        ]
        probe = run_bounded_command(
            [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; import sys; "
                    "[(Path(p)/'.uid-probe').write_text('ok') for p in sys.argv[1:4]]; "
                    "[(Path(p)/'.uid-probe').unlink() for p in sys.argv[1:4]]; "
                    "[open(p,'rb').read(1) for p in sys.argv[4:]]"
                ),
                str(self.config.output / "data"),
                str(self.config.output / "samples"),
                str(sampler_control),
                *(str(path) for path in runtime_files),
            ],
            user=self.config.run_user,
            timeout=3,
            kind="run-user-path-probe",
        )
        if probe.returncode != 0:
            raise HarnessError("run user cannot traverse/read/write required owned paths")
        self.manifest["run_user_path_probe"] = asdict(probe)
        self.save()

    def start_watchdog(self) -> None:
        log = (self.config.output / "logs" / "watchdog.log").open("w", encoding="utf-8")
        self.open_files.append(log)
        argv = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--_watchdog-state",
            str(self.watchdog_state_path),
            "--_watchdog-learned",
            str(self.watchdog_learned_path),
            "--_watchdog-deadline",
            str(self.deadline_monotonic),
        ]

        def register_watchdog(process: subprocess.Popen[Any], identity: ProcessIdentity) -> None:
            self.watchdog, self.watchdog_identity = process, identity

        process, identity = spawn_owned(
            argv,
            kind="watchdog",
            user=None,
            stdin=subprocess.PIPE,
            stdout=log,
            stderr=log,
            register=register_watchdog,
            parent_death_signal=None,
        )
        self.manifest["commands"].append({"kind": "watchdog", "argv": argv})
        self.manifest["watchdog"] = asdict(identity) | {
            "deadline_monotonic": self.deadline_monotonic
        }

    def add_process(self, process: subprocess.Popen[Any], identity: ProcessIdentity) -> None:
        self.processes.append((process, identity))
        self.manifest["processes"].append(asdict(identity))
        self.save()

    def start_nodes(self) -> list[ListenerIdentity]:
        for node_id in range(1, 4):
            stdout = (self.config.output / "logs" / f"node-{node_id}.stdout.log").open(
                "w", encoding="utf-8"
            )
            stderr = (self.config.output / "logs" / f"node-{node_id}.stderr.log").open(
                "w", encoding="utf-8"
            )
            self.open_files.extend((stdout, stderr))
            argv = [
                str(self.config.node_binary),
                str(node_id),
                str(self.config.output / "data" / f"node-{node_id}"),
                *(str(port) for port in self.config.ports),
            ]

            def register_node(process: subprocess.Popen[Any], identity: ProcessIdentity) -> None:
                self.add_process(process, identity)
                self.node_processes.append((process, identity))

            process, identity = spawn_owned(
                argv,
                kind=f"dkv-node-{node_id}",
                user=self.config.run_user,
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=stderr,
                register=register_node,
            )
            self.manifest["commands"].append({"kind": f"dkv-node-{node_id}", "argv": argv})
        self.manifest["owned_node_identities"] = [
            asdict(identity) for _, identity in self.node_processes
        ]
        deadline = time.monotonic() + 8
        last_error = "listeners not ready"
        while time.monotonic() < deadline:
            try:
                listeners = verify_listener_ownership(
                    [identity for _, identity in self.node_processes], self.config.ports
                )
                self.manifest["listener_checks"] = [
                    {"stage": "startup", "values": [asdict(item) for item in listeners]}
                ]
                self.save()
                return listeners
            except HarnessError as exc:
                last_error = str(exc)
                if any(process.poll() is not None for process, _ in self.node_processes):
                    break
                time.sleep(0.05)
        raise HarnessError(f"partial node launch: {last_error}")

    def start_sampler(self, mount: str) -> None:
        sampler_control = self.config.output / "control" / "sampler"
        sampler_config = self.config.output / "control" / "sampler-config.json"
        ready = sampler_control / "sampler-ready.json"
        auxiliary = sampler_control / "sampler-owned.json"
        samples = self.config.output / "samples" / "direct-samples.jsonl"
        for path in (sampler_config, ready, auxiliary, samples):
            if os.path.lexists(path):
                raise HarnessError(f"unexpected pre-existing sampler path: {path}")
        write_json_exclusive(
            sampler_config,
            {
                "uid": self.config.run_user.uid,
                "nodes": [asdict(identity) for _, identity in self.node_processes],
                "mount": mount,
                "samples": str(samples),
                "ready": str(ready),
                "aux_state": str(auxiliary),
                "deadline_monotonic": self.deadline_monotonic,
            },
            owner_uid=0,
            owner_gid=self.config.run_user.gid,
            mode=0o640,
        )
        log = (self.config.output / "logs" / "sampler.log").open("w", encoding="utf-8")
        self.open_files.append(log)
        argv = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--_sampler-config",
            str(sampler_config),
        ]

        def register_sampler(process: subprocess.Popen[Any], identity: ProcessIdentity) -> None:
            self.sampler_identity = identity
            self.add_process(process, identity)

        process, identity = spawn_owned(
            argv,
            kind="direct-sampler",
            user=self.config.run_user,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            register=register_sampler,
        )
        self.manifest["commands"].append({"kind": "direct-sampler", "argv": argv})
        raw_value = wait_for_owned_json(
            ready, 8, expected_uid=self.config.run_user.uid, process=process
        )
        value = validate_sampler_ready(
            raw_value,
            expected_uid=self.config.run_user.uid,
            expected_nodes=[identity for _, identity in self.node_processes],
            expected_mount=mount,
        )
        self.manifest["direct_sampler"] = value | {
            "mode": "production_CollectionSupervisor",
            "network_target": None,
            "cgroups": [],
            "watches": [],
            "watch_coverage": "unavailable",
            "watch_error": "direct_sampler_no_collector_watch",
        }
        self.save()

    def status_snapshot(self, label: str) -> dict[str, Any]:
        result = run_client(
            self.config,
            ["status"],
            register=self.add_process,
            unregister=self.remove_process,
            failure_output=self.config.output / "logs" / f"status-{label}-failure.json",
        )
        value = {"label": label, "observed_utc": utc_now(), **asdict(result)}
        self.manifest.setdefault("status_snapshots", []).append(value)
        self.save()
        try:
            validate_status(result)
        except HarnessError as exc:
            value["semantic_failure"] = str(exc)
            self.save()
            raise
        return value

    def readiness(self, mount: str, listeners: list[ListenerIdentity]) -> str:
        path = self.config.output / "readiness.json"
        value = {
            "status": "ready",
            "observed_utc": utc_now(),
            "kv_revision": self.config.kv_revision,
            "nodes": [asdict(identity) for _, identity in self.node_processes],
            "listeners": [asdict(item) for item in listeners],
            "data_mount": mount,
            "controller_uid": os.geteuid(),
            "sampler_uid": self.config.run_user.uid,
            "monitoring_scope": {
                "configured_pids": [identity.pid for _, identity in self.node_processes],
                "io_pids": [identity.pid for _, identity in self.node_processes],
                "io_mounts": [mount],
                "cgroups": [],
                "network_target": None,
            },
        }
        atomic_json(path, value)
        digest = sha256_file(path)
        self.manifest["readiness"] = {"path": str(path), "sha256": digest}
        self.save()
        return digest

    def listener_check(self, stage: str) -> list[ListenerIdentity]:
        listeners = verify_listener_ownership(
            [identity for _, identity in self.node_processes], self.config.ports
        )
        self.manifest.setdefault("listener_checks", []).append(
            {"stage": stage, "values": [asdict(item) for item in listeners]}
        )
        self.save()
        return listeners

    def run_untraced_after_gate(self) -> dict[str, Any]:
        self.listener_check("after_gate_before_untraced")
        return run_workload(
            self.config,
            "untraced",
            strace=None,
            trace_dir=self.config.output / "traces",
            register=self.add_process,
            unregister=self.remove_process,
        )

    def start_tcpdump(
        self, tcpdump: str
    ) -> tuple[subprocess.Popen[str], ProcessIdentity, Path, Path]:
        if TCPDUMP_CAPACITY_BYTES > MAX_PCAP_BYTES:
            raise HarnessError("tcpdump capacity exceeds the PCAP artifact bound")
        pcap = self.config.output / "captures" / "kv-loopback.pcap"
        stderr_path = self.config.output / "logs" / "tcpdump.stderr.log"
        stderr = stderr_path.open("w", encoding="utf-8")
        stdout = (self.config.output / "logs" / "tcpdump.stdout.log").open("w", encoding="utf-8")
        self.open_files.extend((stdout, stderr))
        filter_tokens = ["tcp", "and", "("]
        for index, port in enumerate(self.config.ports):
            if index:
                filter_tokens.append("or")
            filter_tokens.extend(("port", str(port)))
        filter_tokens.append(")")
        expiry_seconds = max(1, math.ceil(self.deadline_monotonic - time.monotonic()))
        argv = [
            tcpdump,
            "-i",
            "lo",
            "-nn",
            "-s",
            str(TCPDUMP_SNAPLEN),
            "-U",
            "-Z",
            "root",
            "-c",
            str(TCPDUMP_PACKET_LIMIT),
            "-w",
            str(pcap),
            *filter_tokens,
        ]
        process, identity = spawn_owned(
            argv,
            kind="tcpdump",
            user=None,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            register=self.add_process,
            exec_expiry_seconds=expiry_seconds,
        )
        self.manifest["capture_limits"] = {
            "snaplen_bytes": TCPDUMP_SNAPLEN,
            "packet_limit": TCPDUMP_PACKET_LIMIT,
            "worst_case_pcap_bytes": TCPDUMP_CAPACITY_BYTES,
            "pcap_artifact_bound_bytes": MAX_PCAP_BYTES,
            "payload_truncations_allowed": 0,
            "independent_elapsed_expiry_seconds": expiry_seconds,
            "independent_elapsed_expiry_mechanism": "pre_exec_ITIMER_REAL_SIGALRM",
        }
        self.manifest["commands"].append({"kind": "tcpdump", "argv": argv})
        wait_for_log(stderr_path, "listening on lo", process, 5)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and (
            not pcap.exists() or pcap.stat().st_size < PCAP_HEADER_BYTES
        ):
            if process.poll() is not None:
                raise HarnessError("tcpdump exited before writing a PCAP header")
            time.sleep(0.05)
        if not pcap.exists() or pcap.stat().st_size < PCAP_HEADER_BYTES:
            raise HarnessError("tcpdump did not open a nonempty PCAP header")
        return process, identity, pcap, stderr_path

    def attach_tracers(self, strace: str) -> list[tuple[subprocess.Popen[str], ProcessIdentity]]:
        tracers: list[tuple[subprocess.Popen[str], ProcessIdentity]] = []
        for index, (_, node) in enumerate(self.node_processes, start=1):
            stderr_path = self.config.output / "logs" / f"strace-node-{index}.stderr.log"
            stderr = stderr_path.open("w", encoding="utf-8")
            stdout = (self.config.output / "logs" / f"strace-node-{index}.stdout.log").open(
                "w", encoding="utf-8"
            )
            self.open_files.extend((stdout, stderr))
            argv = [
                *strace_prefix(strace, self.config.output / "traces" / f"node-{index}"),
                "-p",
                str(node.pid),
            ]
            process, identity = spawn_owned(
                argv,
                kind=f"strace-node-{index}",
                user=None,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                register=self.add_process,
            )
            self.manifest["commands"].append({"kind": f"strace-node-{index}", "argv": argv})
            tracers.append((process, identity))
            wait_for_log(stderr_path, f"Process {node.pid} attached", process, 5)
        return tracers

    def remove_process(self, identity: ProcessIdentity) -> None:
        self.processes = [(process, item) for process, item in self.processes if item != identity]
        if self.sampler_identity == identity:
            self.sampler_identity = None
        self.save()

    def refresh_sampler_descendants(self) -> None:
        if self.sampler_identity is not None:
            for item in discover_descendants(self.sampler_identity, self.config.run_user.uid):
                self.learned_sampler_descendants[(item.pid, item.starttime)] = item
        for item in watchdog_targets(self.watchdog_state_path, self.watchdog_learned_path):
            if item.kind == "sampler-descendant" and item.uid == self.config.run_user.uid:
                self.learned_sampler_descendants[(item.pid, item.starttime)] = item

    def stop_process(
        self, process: subprocess.Popen[Any], identity: ProcessIdentity, signum: int
    ) -> bool:
        clean = terminate_popen(process, identity, signum, 1.5)
        self.manifest["cleanup"].append(
            {"kind": identity.kind, "pid": identity.pid, "clean": clean, "observed_utc": utc_now()}
        )
        if clean:
            self.remove_process(identity)
        return clean

    def require_capture_processes_running(
        self,
        stage: str,
        processes: list[tuple[subprocess.Popen[Any], ProcessIdentity]],
    ) -> None:
        states = capture_process_states(processes)
        self.manifest.setdefault("capture_process_checks", []).append(
            {"stage": stage, "observed_utc": utc_now(), "states": states}
        )
        self.save()
        validate_capture_process_states(states)

    def stop_capture_process(
        self, process: subprocess.Popen[Any], identity: ProcessIdentity
    ) -> bool:
        before = capture_process_states([(process, identity)])[0]
        escalated = False
        if before["running"]:
            if not signal_owned(identity, signal.SIGINT):
                escalated = True
            else:
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    escalated = True
                    terminate_popen(process, identity, signal.SIGTERM, 1.0)
        clean = process.poll() is not None
        acceptable = clean and not escalated and expected_capture_stop(process.returncode)
        record = {
            "kind": identity.kind,
            "pid": identity.pid,
            "clean": clean,
            "deliberate_sigint": bool(before["running"]),
            "escalated": escalated,
            "returncode": process.returncode,
            "acceptable_exit": acceptable,
            "observed_utc": utc_now(),
        }
        self.manifest["cleanup"].append(record)
        self.manifest.setdefault("capture_stops", []).append(record)
        if clean:
            self.remove_process(identity)
        return acceptable

    def cleanup(self) -> bool:
        self.refresh_sampler_descendants()
        # Stop tracers/capture/sampler before asking nodes to exit.
        for process, identity in list(reversed(self.processes)):
            if identity.kind.startswith("strace") or identity.kind == "tcpdump":
                self.stop_process(process, identity, signal.SIGINT)
        for process, identity in list(reversed(self.processes)):
            if identity.kind == "direct-sampler":
                self.stop_process(process, identity, signal.SIGTERM)
        for process, identity in self.node_processes:
            if identity_matches(identity) and process.stdin is not None:
                try:
                    process.stdin.write("quit\n")
                    process.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
        for process, _ in self.node_processes:
            if process.poll() is None:
                try:
                    process.wait(timeout=0.75)
                except subprocess.TimeoutExpired:
                    pass
        for process, identity in list(reversed(self.node_processes)):
            self.stop_process(process, identity, signal.SIGTERM)
        self.node_processes.clear()
        for process, identity in list(reversed(self.processes)):
            self.stop_process(process, identity, signal.SIGTERM)
        for identity in reversed(list(self.learned_sampler_descendants.values())):
            clean = terminate_owned(identity, signal.SIGTERM, 1.0)
            self.manifest["cleanup"].append(
                {
                    "kind": identity.kind,
                    "pid": identity.pid,
                    "clean": clean,
                    "observed_utc": utc_now(),
                }
            )
        released = ports_released(self.config.ports)
        self.manifest["port_release_verified"] = released
        survivors = [
            identity
            for identity in watchdog_targets(self.watchdog_state_path, self.watchdog_learned_path)
            if identity_matches(identity)
        ]
        self.manifest["cleanup_survivors_before_watchdog"] = [asdict(item) for item in survivors]
        if self.watchdog is not None and self.watchdog.stdin is not None:
            try:
                if not survivors:
                    self.watchdog.stdin.write("DISARM\n")
                    self.watchdog.stdin.flush()
                self.watchdog.stdin.close()
                self.watchdog.wait(timeout=4)
            except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
                if self.watchdog_identity is not None:
                    terminate_popen(self.watchdog, self.watchdog_identity, signal.SIGTERM)
            self.manifest["watchdog_disarmed"] = not survivors and self.watchdog.returncode == 0
            self.manifest["watchdog_expiry_cleanup_used"] = bool(survivors)
        final_survivors = [
            identity
            for identity in watchdog_targets(self.watchdog_state_path, self.watchdog_learned_path)
            if identity_matches(identity)
        ]
        self.manifest["cleanup_survivors"] = [asdict(item) for item in final_survivors]
        for stream in self.open_files:
            try:
                stream.close()
            except OSError:
                pass
        return (
            released
            and not final_survivors
            and all(item.get("clean") for item in self.manifest["cleanup"])
        )

    def execute(self, tools: dict[str, str]) -> None:
        self.prepare_output()
        self.manifest["environment"]["tools"] = {
            name: asdict(
                run_bounded_command(
                    [path, "--version"], user=None, timeout=3, kind=f"{name}-version"
                )
            )
            for name, path in tools.items()
        }
        self.start_watchdog()
        listeners = self.start_nodes()
        mount = containing_mount(self.config.output / "data")
        self.start_sampler(mount)
        self.status_snapshot("before_untraced_phase")
        readiness_hash = self.readiness(mount, listeners)
        if self.config.gate_path is not None:
            self.manifest["gate"] = wait_for_gate(
                self.config.gate_path, readiness_hash, self.config.gate_timeout_seconds
            )
        untraced = self.run_untraced_after_gate()
        self.manifest["phases"] = [untraced]
        self.status_snapshot("after_untraced_before_attach")
        self.listener_check("before_traced")
        tcp_process, tcp_identity, pcap, tcp_stderr = self.start_tcpdump(tools["tcpdump"])
        tracers = self.attach_tracers(tools["strace"])
        self.status_snapshot("after_attach_before_traced_phase")
        traced = run_workload(
            self.config,
            "traced",
            strace=tools["strace"],
            trace_dir=self.config.output / "traces",
            register=self.add_process,
            unregister=self.remove_process,
        )
        self.manifest["phases"].append(traced)
        self.status_snapshot("after_traced_phase")
        capture_processes = [(tcp_process, tcp_identity), *tracers]
        self.require_capture_processes_running(
            "after_traced_before_deliberate_stop", capture_processes
        )
        capture_stop_results: list[bool] = []
        for process, identity in reversed(tracers):
            capture_stop_results.append(self.stop_capture_process(process, identity))
        capture_stop_results.append(self.stop_capture_process(tcp_process, tcp_identity))
        if not all(capture_stop_results):
            raise HarnessError("capture tool did not exit cleanly after deliberate shutdown")
        decoded_path = self.config.output / "captures" / "kv-loopback.txt"
        decode_stderr = self.config.output / "logs" / "tcpdump-decode.stderr.log"
        decoded = run_bounded_file_command(
            [tools["tcpdump"], "-nn", "-tttt", "-r", str(pcap)],
            stdout_path=decoded_path,
            stderr_path=decode_stderr,
            stdout_limit=MAX_DECODE_BYTES,
            stderr_limit=MAX_TEXT_BYTES,
            timeout=10,
            kind="tcpdump-decode",
            register=self.add_process,
            unregister=self.remove_process,
        )
        self.manifest["decoder"] = asdict(decoded) | {
            "stdout_path": str(decoded_path),
            "stderr_path": str(decode_stderr),
        }
        validate_decoder_result(decoded)
        decoded_text = bounded_text(decoded_path, MAX_DECODE_BYTES)
        pcap_result = classify_pcap(pcap, decoded_text, bounded_text(tcp_stderr), self.config.ports)
        trace_result = classify_traces(self.config.output / "traces")
        self.manifest["capture_validation"] = {"pcap": pcap_result, "strace": trace_result}
        if not pcap_result["usable"] or not trace_result["usable"]:
            raise HarnessError("capture validation did not find usable PCAP and syscall evidence")
        self.manifest["descriptive_timing"] = {
            "ordered_pair_only": True,
            "causal_or_benchmark_claim": False,
            "untraced_elapsed_seconds": untraced["elapsed_seconds"],
            "traced_elapsed_seconds": traced["elapsed_seconds"],
        }

    def finalize(self, candidate_passed: bool) -> None:
        failed = not candidate_passed
        if candidate_passed:
            self.manifest["status"] = "finalizing"
            try:
                self.save()
            except BaseException as exc:
                failed = True
                self.manifest["status"] = "failed"
                self.manifest["finalizing_save_exception"] = f"{type(exc).__name__}: {exc}"
                self.manifest["error"] = "could not persist nonterminal finalizing state"

        try:
            cleanup_ok = self.cleanup()
        except BaseException as exc:
            cleanup_ok = False
            failed = True
            self.manifest["cleanup_exception"] = f"{type(exc).__name__}: {exc}"
            self.manifest["error"] = "owned process cleanup raised an exception"

        try:
            samples_path = self.config.output / "samples" / "direct-samples.jsonl"
            records: list[dict[str, Any]] = []
            if os.path.lexists(samples_path):
                samples_text = bounded_owned_text(
                    samples_path,
                    expected_uid=self.config.run_user.uid,
                    maximum=self.config.max_output_bytes,
                )
                records = parse_sample_records(samples_text)
            nodes = _load_processes(self.manifest.get("owned_node_identities", []))
            assessment = sample_assessment(records, nodes, self.manifest.get("phases", []))
            self.manifest["direct_sample_assessment"] = assessment
            if assessment["coverage"] != "available":
                failed = True
                if candidate_passed:
                    self.manifest["error"] = (
                        "direct sampler lacked complete intended-PID/phase coverage"
                    )
        except BaseException as exc:
            failed = True
            self.manifest["sample_finalization_exception"] = f"{type(exc).__name__}: {exc}"
            self.manifest["error"] = "direct samples failed schema validation or assessment"

        try:
            size = tree_size(self.config.output)
            self.manifest["artifact_bytes"] = size
            if size > self.config.max_output_bytes:
                failed = True
                self.manifest["error"] = f"artifact bound exceeded: {size}"
            if not self.manifest.get("port_release_verified", False):
                failed = True
                self.manifest["error"] = "owned ports were not released"
            if not cleanup_ok:
                failed = True
                self.manifest["error"] = "owned process cleanup was incomplete"
        except BaseException as exc:
            failed = True
            self.manifest["artifact_finalization_exception"] = f"{type(exc).__name__}: {exc}"
            self.manifest["error"] = "artifact finalization raised an exception"

        self.manifest["status"] = "failed" if failed else "passed"
        self.manifest["finished_utc"] = utc_now()
        self.manifest["elapsed_seconds"] = time.monotonic() - self.manifest["started_monotonic"]
        try:
            self.save()
        except BaseException as exc:
            self.manifest["status"] = "failed"
            self.manifest["terminal_save_exception"] = f"{type(exc).__name__}: {exc}"
            self.manifest["error"] = "terminal manifest save raised an exception"
            atomic_json(self.manifest_path, self.manifest)

    def run(self, tools: dict[str, str]) -> int:
        candidate_passed = False
        previous_handlers: dict[signal.Signals, Any] = {}

        def interrupted(signum: int, _frame: object) -> None:
            raise KeyboardInterrupt(f"received signal {signum}")

        try:
            for signal_number in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[signal_number] = signal.getsignal(signal_number)
                signal.signal(signal_number, interrupted)
            try:
                self.execute(tools)
                candidate_passed = True
            except BaseException as exc:
                self.manifest["status"] = "failed"
                self.manifest["error"] = f"{type(exc).__name__}: {exc}"
            try:
                self.finalize(candidate_passed)
            except BaseException as exc:
                self.manifest["status"] = "failed"
                self.manifest["finalization_exception"] = f"{type(exc).__name__}: {exc}"
                self.manifest["error"] = "terminal finalization raised an exception"
                self.manifest["finished_utc"] = utc_now()
                self.manifest["elapsed_seconds"] = (
                    time.monotonic() - self.manifest["started_monotonic"]
                )
                try:
                    atomic_json(self.manifest_path, self.manifest)
                except BaseException:
                    pass
        finally:
            for signal_number, handler in previous_handlers.items():
                signal.signal(signal_number, handler)
        if self.manifest["status"] != "passed":
            print(self.manifest.get("error", "controller failed"), file=sys.stderr)
        return 0 if self.manifest["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-binary", help="exact dkv_node executable", required=True)
    parser.add_argument("--client-binary", help="exact dkv_client executable", required=True)
    parser.add_argument(
        "--source-archive", help="retained source archive used for the build", required=True
    )
    parser.add_argument(
        "--source-archive-sha256",
        default=EXPECTED_ARCHIVE_SHA256,
        help="expected SHA256 of the retained source archive",
    )
    parser.add_argument("--kv-revision", help="exact 40-hex KV source revision", required=True)
    parser.add_argument("--output", help="exclusive new absolute output directory", required=True)
    parser.add_argument(
        "--ports", type=int, nargs=3, default=DEFAULT_PORTS, metavar=("P1", "P2", "P3")
    )
    parser.add_argument(
        "--run-user", default="vietmynguyen", help="non-root user for KV and direct sampler"
    )
    parser.add_argument("--pairs", type=int, default=8, help="PUT/GET pairs per phase (1..16)")
    parser.add_argument("--pace-seconds", type=float, default=2.0, help="delay between pairs")
    parser.add_argument(
        "--max-runtime-seconds", type=int, default=240, help="independent expiry (45..600)"
    )
    parser.add_argument("--start-gate", help="optional initially absent JSON release gate")
    parser.add_argument("--gate-timeout-seconds", type=int, default=120)
    parser.add_argument("--max-output-bytes", type=int, default=MAX_OUTPUT_BYTES)
    return parser


def _internal_main(argv: list[str]) -> int | None:
    if "--_audit-protected-runtime" in argv:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--_audit-protected-runtime", required=True)
        parser.add_argument("--_audit-venv-python", required=True)
        parser.add_argument("--_audit-run-uid", required=True, type=int)
        args = parser.parse_args(argv)
        result = audit_protected_runtime(
            Path(args._audit_protected_runtime),
            Path(args._audit_venv_python),
            args._audit_run_uid,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    if "--_watchdog-state" in argv:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--_watchdog-state", required=True)
        parser.add_argument("--_watchdog-learned", required=True)
        parser.add_argument("--_watchdog-deadline", required=True, type=float)
        args = parser.parse_args(argv)
        return watchdog_main(
            Path(args._watchdog_state),
            Path(args._watchdog_learned),
            args._watchdog_deadline,
        )
    if "--_sampler-config" in argv:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--_sampler-config", required=True)
        args = parser.parse_args(argv)
        return sampler_main(Path(args._sampler_config))
    return None


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    internal = _internal_main(values)
    if internal is not None:
        return internal
    parser = build_parser()
    args = parser.parse_args(values)
    try:
        config = parse_config(args)
        tools = {"strace": require_tool("strace"), "tcpdump": require_tool("tcpdump")}
        for name, path in tools.items():
            require_protected_file(Path(path), f"{name} executable")
        controller = Controller(config)
        return controller.run(tools)
    except HarnessError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
