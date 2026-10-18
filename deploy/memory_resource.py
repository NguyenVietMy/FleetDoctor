#!/usr/bin/env python3
"""Root-owned delegated-systemd helper for one retained, bounded OOM cgroup."""

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Literal

STATE_ROOT = Path("/run/fleetdoctor-oom")
CGROUP_ROOT = Path("/sys/fs/cgroup")
TOKEN = re.compile(r"^[a-f0-9]{16,64}$")
USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
MIN_LIMIT = 32 * 1024 * 1024
MAX_LIMIT = 64 * 1024 * 1024
MAX_CHILD_SECONDS = 180
MAX_LEASE_SECONDS = 360
STATE_OWNER_UID = 0
MIN_AVAILABLE_BYTES = 512 * 1024 * 1024
PREPARE_READY_SECONDS = 10.0
ProofFault = Literal[
    "prelaunch_interrupt",
    "prelaunch_signal_wait",
    "supervisor_early_exit",
    "supervisor_not_ready",
    "cleanup_failure",
]


def unit_name(token: str) -> str:
    if not TOKEN.fullmatch(token):
        raise ValueError("token must be 16..64 lowercase hexadecimal characters")
    return "fleetdoctor-oom-" + token[:32] + ".service"


def state_path(token: str) -> Path:
    unit_name(token)
    return STATE_ROOT / (token + ".json")


def gate_path(token: str) -> Path:
    unit_name(token)
    return STATE_ROOT / (token + ".gate")


def boot_identity() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def source_hash() -> str:
    return hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()


def available_memory() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "MemAvailable:" and fields[2] == "kB":
            return int(fields[1]) * 1024
    raise RuntimeError("host available memory is unavailable")


def current_cgroup() -> str:
    return Path("/proc/self/cgroup").read_text()


def unified_cgroup(value: str) -> str:
    paths = [line[3:] for line in value.splitlines() if line.startswith("0::")]
    if len(paths) != 1 or not paths[0].startswith("/"):
        raise ValueError("exact unified cgroup placement is unavailable")
    return paths[0]


def process_cgroup(pid: int) -> str:
    return unified_cgroup(Path(f"/proc/{pid}/cgroup").read_text())


def command(argv: list[str], timeout: float = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)


def _trusted_file(path: Path) -> dict[str, Any] | None:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, encoding="utf-8") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)
            or metadata.st_nlink != 1
            or metadata.st_uid != STATE_OWNER_UID
            or metadata.st_mode & 0o077
        ):
            raise ValueError("untrusted OOM helper state")
        value: dict[str, Any] = json.load(stream)
    return value


def trusted_state(token: str) -> dict[str, Any] | None:
    record = _trusted_file(state_path(token))
    if record is None:
        return None
    if record.get("token") != token or record.get("unit") != unit_name(token):
        raise ValueError("OOM helper state identity mismatch")
    if record.get("boot_id") != boot_identity():
        raise ValueError("OOM helper state belongs to another boot")
    if record.get("script_sha256") != source_hash():
        raise ValueError("OOM helper source changed after preparation")
    return record


def unlink_owned_gate(token: str) -> None:
    path = gate_path(token)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != STATE_OWNER_UID
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
    ):
        raise ValueError("untrusted OOM placement gate")
    path.unlink()


def write_state(record: dict[str, Any]) -> None:
    STATE_ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chown(STATE_ROOT, 0, 0)
    root_stat = STATE_ROOT.lstat()
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or STATE_ROOT.is_symlink()
        or root_stat.st_uid != STATE_OWNER_UID
        or root_stat.st_mode & 0o022
    ):
        raise ValueError("OOM helper state directory is writable by non-root")
    path = state_path(str(record["token"]))
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _unit_live(status: dict[str, str]) -> bool:
    return status.get("LoadState") not in (None, "not-found") and status.get("ActiveState") not in (
        None,
        "inactive",
        "failed",
    )


def _partial_identity(record: dict[str, Any], status: dict[str, str]) -> None:
    invocation = record.get("invocation_id")
    control_group = record.get("control_group")
    if not invocation or not control_group:
        raise ValueError("live partial preparation has no verified invocation identity")
    if (
        status.get("Id") != record.get("unit")
        or status.get("InvocationID") != invocation
        or status.get("ControlGroup") != control_group
    ):
        raise ValueError("refusing cleanup of a replaced partial preparation")


def _remove_recorded_leaf(record: dict[str, Any]) -> None:
    raw = record.get("leaf_path")
    if not raw:
        return
    leaf = CGROUP_ROOT / str(raw).lstrip("/")
    if not leaf.exists():
        return
    if not record.get("generation") or _generation(leaf) != record["generation"]:
        raise ValueError("refusing cleanup of an unverified partial workload generation")
    kill_file = leaf / "cgroup.kill"
    if kill_file.exists():
        kill_file.write_text("1")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            leaf.rmdir()
            return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError("partial workload cgroup did not become empty")


def _record_cleanup_failure(token: str, error: BaseException) -> None:
    record = trusted_state(token)
    if record is None:
        return
    record["cleanup_error"] = f"{type(error).__name__}: {error}"[:256]
    record["cleanup_failed_monotonic"] = time.monotonic()
    write_state(record)


def cleanup_partial_prepare(token: str, *, proof_fail: bool = False) -> None:
    """Clean only a missing unit or the exact recorded partial invocation."""
    deadline = time.monotonic() + 20
    while True:
        record = trusted_state(token)
        status = show(unit_name(token))
        if record is None:
            if _unit_live(status):
                if time.monotonic() < deadline:
                    time.sleep(0.05)
                    continue
                raise ValueError("unverifiable live unit remained after partial preparation")
            unlink_owned_gate(token)
            return
        if record.get("phase") not in ("starting", "prepared", "stopped"):
            raise ValueError("refusing partial cleanup of a running allocator")
        if _unit_live(status):
            try:
                _partial_identity(record, status)
            except ValueError:
                if not record.get("invocation_id") and time.monotonic() < deadline:
                    time.sleep(0.05)
                    continue
                raise
            if proof_fail:
                raise RuntimeError("injected bounded cleanup failure")
            result = command(["systemctl", "stop", str(record["unit"])], timeout=15)
            if result.returncode:
                raise RuntimeError("owned partial OOM unit did not stop")
            proof_fail = False
            continue
        _remove_recorded_leaf(record)
        control_group = record.get("control_group")
        if control_group and (CGROUP_ROOT / str(control_group).lstrip("/")).exists():
            if time.monotonic() < deadline:
                time.sleep(0.05)
                continue
            raise RuntimeError("owned partial OOM cgroup remained after unit stop")
        unlink_owned_gate(token)
        current = trusted_state(token)
        if current is not None:
            for key in ("token", "unit", "boot_id", "script_sha256", "invocation_id"):
                if current.get(key) != record.get(key):
                    raise ValueError("partial helper state was replaced during cleanup")
            state_path(token).unlink()
        return


def show(unit: str) -> dict[str, str]:
    result = command(
        [
            "systemctl",
            "show",
            unit,
            "--property=Id,LoadState,ActiveState,SubState,InvocationID,ControlGroup,Delegate,OOMPolicy,KillMode,RuntimeMaxUSec,MemoryMax,TasksMax",
        ]
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("systemctl status unavailable")
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def _generation(path: Path) -> dict[str, int]:
    stat = os.stat(path, follow_symlinks=False)
    return {"st_dev": stat.st_dev, "st_ino": stat.st_ino}


def _duration_seconds(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(us|ms|s|min)", value)
    if not match:
        raise ValueError("unrecognized systemd runtime")
    multiplier = {"us": 0.000001, "ms": 0.001, "s": 1.0, "min": 60.0}[match.group(2)]
    return float(match.group(1)) * multiplier


def verify_live(
    record: dict[str, Any], *, require_leaf: bool = True
) -> tuple[dict[str, str], Path]:
    if record.get("boot_id") != boot_identity() or record.get("script_sha256") != source_hash():
        raise ValueError("OOM helper boot or source identity changed")
    status = show(str(record["unit"]))
    if status.get("Id") != record["unit"]:
        raise ValueError("transient unit identity mismatch")
    if status.get("InvocationID") and status["InvocationID"] != record.get("invocation_id"):
        raise ValueError("transient unit was replaced")
    if status.get("ControlGroup") and status["ControlGroup"] != record.get("control_group"):
        raise ValueError("transient cgroup was replaced")
    for name, expected in (
        ("Delegate", "yes"),
        ("OOMPolicy", "continue"),
        ("KillMode", "control-group"),
    ):
        if status.get(name) != expected:
            raise ValueError(f"unsafe transient unit property {name}")
    if status.get("MemoryMax") != str(256 * 1024 * 1024) or status.get("TasksMax") != "16":
        raise ValueError("unsafe transient unit resource cap")
    runtime = _duration_seconds(status.get("RuntimeMaxUSec", ""))
    if runtime > MAX_LEASE_SECONDS or abs(runtime - float(record["lease_seconds"])) > 0.01:
        raise ValueError("unsafe transient unit runtime")
    parent = CGROUP_ROOT / str(record["control_group"]).lstrip("/")
    supervisor = CGROUP_ROOT / str(record["supervisor_group"]).lstrip("/")
    if (parent / "cgroup.procs").read_text().strip():
        raise ValueError("delegated parent cgroup contains tasks")
    if str(record.get("supervisor_pid")) not in (supervisor / "cgroup.procs").read_text().split():
        raise ValueError("supervisor is outside its separated subgroup")
    enabled = set((parent / "cgroup.subtree_control").read_text().split())
    if not {"memory", "pids"} <= {value.lstrip("+") for value in enabled}:
        raise ValueError("delegated memory and pids controllers are not enabled")
    leaf = CGROUP_ROOT / str(record["leaf_path"]).lstrip("/")
    if require_leaf:
        if not leaf.is_dir() or _generation(leaf) != record.get("generation"):
            raise ValueError("owned workload cgroup generation changed")
    return status, leaf


def _remaining(record: dict[str, Any]) -> float:
    return float(record["lease_seconds"]) - (
        time.monotonic() - float(record["lease_origin_monotonic"])
    )


def prepare(
    token: str,
    lease_seconds: int = MAX_LEASE_SECONDS,
    *,
    expiry_probe: bool = False,
    proof_fault: ProofFault | None = None,
) -> dict[str, Any]:
    valid_lease = 2 <= lease_seconds <= 15 if expiry_probe else 330 <= lease_seconds <= 360
    if not valid_lease:
        raise ValueError(
            "expiry probes require 2..15 seconds; scenario leases must reserve 330..360 seconds"
        )
    if available_memory() < MIN_AVAILABLE_BYTES:
        raise ValueError("host lacks the 512MiB available-memory safety reserve")
    if proof_fault is not None and (not expiry_probe or lease_seconds != 15):
        raise ValueError("bounded proof faults require a 15-second expiry-probe lease")
    unit = unit_name(token)
    if trusted_state(token) is not None or show(unit).get("LoadState") not in (None, "not-found"):
        raise ValueError("owned OOM resource already exists")
    script = Path(__file__).resolve()
    record: dict[str, Any] = {
        "token": token,
        "unit": unit,
        "lease_seconds": lease_seconds,
        "lease_origin_monotonic": time.monotonic(),
        "script_sha256": source_hash(),
        "boot_id": boot_identity(),
        "expiry_probe": expiry_probe,
        "available_memory_before": available_memory(),
        "phase": "starting",
    }
    cleanup_started = False

    def interrupt(signum: int, frame: object) -> None:
        if not cleanup_started:
            raise InterruptedError(f"prepare interrupted by {signal.Signals(signum).name}")

    previous_handlers: dict[signal.Signals, Any] = {}
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, interrupt)
    except BaseException:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        raise
    try:
        write_state(record)
        if proof_fault == "prelaunch_interrupt":
            raise KeyboardInterrupt("injected prelaunch interruption")
        if proof_fault == "prelaunch_signal_wait":
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                time.sleep(0.05)
            raise TimeoutError("prelaunch signal proof did not receive an interrupt")
        launch = [
            "systemd-run",
            "--unit=" + unit.removesuffix(".service"),
            "--collect",
            "--property=Delegate=yes",
            "--property=OOMPolicy=continue",
            "--property=KillMode=control-group",
            "--property=Restart=no",
            "--property=RuntimeMaxSec=" + str(lease_seconds),
            "--property=TimeoutStopSec=10s",
            "--property=MemoryMax=256M",
            "--property=TasksMax=16",
            "--property=CPUQuota=50%",
            sys.executable,
            str(script),
            "supervisor",
            "--token",
            token,
        ]
        if proof_fault is not None:
            launch.extend(["--proof-fault", proof_fault])
        result = command(launch)
        if result.returncode:
            raise RuntimeError("failed to create delegated transient OOM unit")
        deadline = time.monotonic() + (1.0 if proof_fault is not None else PREPARE_READY_SECONDS)
        while time.monotonic() < deadline:
            current = trusted_state(token)
            if current is not None and current.get("phase") == "prepared":
                verify_live(current)
                return current | {"status": show(unit)}
            current_status = show(unit)
            if current is None and not _unit_live(current_status):
                raise RuntimeError("delegated OOM supervisor exited before readiness")
            time.sleep(0.05)
        raise RuntimeError("delegated OOM resource did not become ready")
    except BaseException as primary:
        cleanup_started = True
        try:
            cleanup_partial_prepare(token, proof_fail=proof_fault == "cleanup_failure")
        except BaseException as cleanup:
            _record_cleanup_failure(token, cleanup)
            raise RuntimeError(
                f"prepare failed ({type(primary).__name__}: {primary}); "
                f"cleanup failed ({type(cleanup).__name__}: {cleanup})"
            ) from primary
        raise
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


def supervisor(token: str, proof_fault: ProofFault | None = None) -> None:
    record = trusted_state(token)
    if record is None or record.get("phase") != "starting":
        raise ValueError("missing prepared supervisor state")
    relative = unified_cgroup(Path("/proc/self/cgroup").read_text())
    parent = CGROUP_ROOT / relative.lstrip("/")
    supervisor_group = parent / "supervisor"
    leaf = parent / "workload"
    status = show(str(record["unit"]))
    if (
        status.get("Id") != record["unit"]
        or not status.get("InvocationID")
        or status.get("ControlGroup") != relative
    ):
        raise RuntimeError("transient unit identity unavailable")
    record.update(
        invocation_id=status["InvocationID"],
        control_group=status["ControlGroup"],
        supervisor_pid=os.getpid(),
    )
    write_state(record)
    stopped = False
    leaf_generation: dict[str, int] | None = None

    def stop(signum: int, frame: object) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    deadline = float(record["lease_origin_monotonic"]) + float(record["lease_seconds"])
    try:
        if proof_fault == "supervisor_early_exit":
            raise RuntimeError("injected supervisor early exit")
        if proof_fault in ("supervisor_not_ready", "cleanup_failure"):
            while not stopped and time.monotonic() < deadline:
                time.sleep(0.05)
            return
        supervisor_group.mkdir()
        (supervisor_group / "cgroup.procs").write_text(str(os.getpid()))
        (parent / "cgroup.subtree_control").write_text("+memory +pids")
        leaf.mkdir()
        leaf_generation = _generation(leaf)
        record.update(
            phase="prepared",
            leaf_path="/" + str(leaf.relative_to(CGROUP_ROOT)).replace(os.sep, "/"),
            supervisor_group="/"
            + str(supervisor_group.relative_to(CGROUP_ROOT)).replace(os.sep, "/"),
            generation=leaf_generation,
        )
        write_state(record)
        while not stopped and time.monotonic() < deadline:
            time.sleep(0.2)
    finally:
        current = trusted_state(token)
        if current is not None:
            if current.get("invocation_id") != record.get("invocation_id") or current.get(
                "control_group"
            ) != record.get("control_group"):
                raise RuntimeError("refusing cleanup of a replaced supervisor invocation")
            if leaf.exists():
                if leaf_generation is None or _generation(leaf) != leaf_generation:
                    raise RuntimeError("refusing cleanup of an unverified workload generation")
                kill_file = leaf / "cgroup.kill"
                if kill_file.exists():
                    kill_file.write_text("1")
                for _ in range(50):
                    try:
                        leaf.rmdir()
                        break
                    except OSError:
                        time.sleep(0.02)
                else:
                    raise RuntimeError("owned workload cgroup did not become empty at finalization")
            unlink_owned_gate(token)
            state_path(token).unlink()


def start(
    token: str,
    allocation_bytes: int,
    limit_bytes: int,
    seconds: int,
    worker_user: str = "fleetdoctor",
) -> dict[str, Any]:
    if not MIN_LIMIT <= limit_bytes <= MAX_LIMIT:
        raise ValueError("memory limit must be 32..64 MiB")
    if not limit_bytes < allocation_bytes <= 2 * MAX_LIMIT:
        raise ValueError("allocation must exceed the finite limit and remain <=128 MiB")
    if not 1 <= seconds <= MAX_CHILD_SECONDS:
        raise ValueError("allocation lifetime must be 1..180 seconds")
    if not USER.fullmatch(worker_user) or worker_user == "root":
        raise ValueError("worker user must be a bounded unprivileged account")
    record = trusted_state(token)
    if record is None or record.get("phase") not in ("prepared", "stopped"):
        raise ValueError("prepare an empty owned cgroup first")
    if record.get("expiry_probe"):
        raise ValueError("expiry-probe resources cannot run an allocator")
    status, leaf = verify_live(record)
    if status.get("ActiveState") != "active":
        raise ValueError("delegated OOM unit is not active")
    if _remaining(record) < seconds + 120:
        raise ValueError("insufficient lease reserve for injection, recovery, and release")
    if available_memory() < max(MIN_AVAILABLE_BYTES, 4 * limit_bytes):
        raise ValueError("host memory headroom is insufficient for bounded OOM injection")
    if (leaf / "cgroup.procs").read_text().strip():
        raise ValueError("workload cgroup must be empty before injection")
    caller_cgroup = current_cgroup()
    caller_unified = unified_cgroup(caller_cgroup)
    if caller_unified == record["leaf_path"] or caller_unified.startswith(
        str(record["leaf_path"]) + "/"
    ):
        raise ValueError("OOM helper controller is inside the injection cgroup")
    monitor_groups: dict[str, str | None] = {}
    for service in ("fleetdoctor-agent.service", "fleetdoctor-collector.service"):
        service_status = show(service)
        service_group = service_status.get("ControlGroup", "")
        if (
            service_status.get("LoadState") == "loaded"
            and service_status.get("ActiveState") == "active"
        ):
            if (
                not service_group
                or service_group == record["leaf_path"]
                or service_group.startswith(str(record["leaf_path"]) + "/")
            ):
                raise ValueError(service + " is not separated from the injection cgroup")
            monitor_groups[service] = service_group
        else:
            monitor_groups[service] = None
    (leaf / "memory.max").write_text(str(limit_bytes))
    (leaf / "memory.swap.max").write_text("0")
    (leaf / "pids.max").write_text("4")
    if (
        int((leaf / "memory.max").read_text()) != limit_bytes
        or (leaf / "memory.swap.max").read_text().strip() != "0"
    ):
        raise RuntimeError("kernel rejected bounded workload limits")
    import pwd

    account = pwd.getpwnam(worker_user)
    if account.pw_uid == 0:
        raise ValueError("worker account must resolve to a non-root UID")
    gate = gate_path(token)
    unlink_owned_gate(token)
    process = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "allocate",
            "--bytes",
            str(allocation_bytes),
            "--seconds",
            str(seconds),
            "--gate",
            str(gate),
        ],
        user=account.pw_uid,
        group=account.pw_gid,
        extra_groups=(),
        start_new_session=True,
    )
    try:
        (leaf / "cgroup.procs").write_text(str(process.pid))
        placed = process_cgroup(process.pid)
        if placed != record["leaf_path"]:
            raise RuntimeError("allocator was not placed in the exact owned workload cgroup")
        if process.poll() is not None:
            raise RuntimeError("blocked allocator exited before confinement verification")
        descriptor = os.open(
            gate,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        os.close(descriptor)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        unlink_owned_gate(token)
        raise
    record.update(
        phase="running",
        allocator_pid=process.pid,
        allocation_bytes=allocation_bytes,
        limit_bytes=limit_bytes,
        child_seconds=seconds,
        child_started_monotonic=time.monotonic(),
        available_memory_before_start=available_memory(),
        caller_cgroup=caller_cgroup.strip(),
        monitor_control_groups=monitor_groups,
    )
    write_state(record)
    return status_record(record)


def status_record(record: dict[str, Any]) -> dict[str, Any]:
    status, leaf = verify_live(record)
    events = {
        fields[0]: int(fields[1])
        for line in (leaf / "memory.events.local").read_text().splitlines()
        if len(fields := line.split()) == 2
    }
    processes = [int(value) for value in (leaf / "cgroup.procs").read_text().split()]
    return record | {
        "owned": True,
        "remaining_seconds": max(0, _remaining(record)),
        "status": status,
        "limits": {
            "memory.max": (leaf / "memory.max").read_text().strip(),
            "memory.swap.max": (leaf / "memory.swap.max").read_text().strip(),
            "pids.max": (leaf / "pids.max").read_text().strip(),
        },
        "memory_current": int((leaf / "memory.current").read_text()),
        "events": events,
        "processes": processes,
    }


def status(token: str) -> dict[str, Any]:
    record = trusted_state(token)
    if record is None:
        return {"token": token, "state": "absent", "owned": False}
    try:
        return status_record(record)
    except (FileNotFoundError, ValueError):
        current = show(str(record["unit"]))
        if current.get("LoadState") == "not-found" or current.get("ActiveState") in (
            "inactive",
            "failed",
        ):
            return record | {"owned": True, "state": "expired", "status": current}
        raise


def stop(token: str) -> dict[str, Any]:
    record = trusted_state(token)
    if record is None:
        return {"token": token, "state": "absent", "owned": False, "stopped": True}
    _, leaf = verify_live(record)
    if _remaining(record) < 90:
        raise ValueError("insufficient lease reserve for recovery and release")
    kill_file = leaf / "cgroup.kill"
    if kill_file.exists():
        kill_file.write_text("1")
    deadline = time.monotonic() + 10
    while (leaf / "cgroup.procs").read_text().strip() and time.monotonic() < deadline:
        time.sleep(0.05)
    if (leaf / "cgroup.procs").read_text().strip():
        raise RuntimeError("owned allocator did not stop")
    unlink_owned_gate(token)
    record["phase"] = "stopped"
    record["stopped_monotonic"] = time.monotonic()
    write_state(record)
    return status_record(record)


def release(token: str) -> dict[str, Any]:
    record = trusted_state(token)
    if record is None:
        return {"token": token, "state": "absent", "owned": False, "released": True}
    if record.get("phase") == "starting":
        cleanup_partial_prepare(token)
        if trusted_state(token) is not None or gate_path(token).exists():
            raise RuntimeError("partial preparation cleanup retained trusted helper files")
        return {"token": token, "unit": record["unit"], "owned": True, "released": True}
    current = show(str(record["unit"]))
    if current.get("LoadState") != "not-found":
        if current.get("InvocationID") and current["InvocationID"] != record.get("invocation_id"):
            raise ValueError("refusing to stop a replaced transient unit")
        if current.get("ActiveState") == "active":
            verify_live(record)
        result = command(["systemctl", "stop", str(record["unit"])], timeout=20)
        if result.returncode:
            raise RuntimeError("owned OOM unit did not stop")
    state_path(token).unlink(missing_ok=True)
    unlink_owned_gate(token)
    return {"token": token, "unit": record["unit"], "owned": True, "released": True}


def allocate(size: int, seconds: int, gate: Path) -> None:
    deadline = time.monotonic() + 10
    while not gate.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not gate.exists():
        raise TimeoutError("allocator placement gate was not opened")
    chunks: list[bytearray] = []
    allocation_deadline = time.monotonic() + seconds
    while sum(len(chunk) for chunk in chunks) < size and time.monotonic() < allocation_deadline:
        chunk = bytearray(min(1024 * 1024, size - sum(len(value) for value in chunks)))
        for index in range(0, len(chunk), 4096):
            chunk[index] = 1
        chunks.append(chunk)
    while time.monotonic() < allocation_deadline:
        time.sleep(0.1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--token", required=True)
    prepare_parser.add_argument("--lease-seconds", type=int, default=MAX_LEASE_SECONDS)
    prepare_parser.add_argument("--expiry-probe", action="store_true")
    prepare_parser.add_argument(
        "--proof-fault",
        choices=(
            "prelaunch_interrupt",
            "prelaunch_signal_wait",
            "supervisor_early_exit",
            "supervisor_not_ready",
            "cleanup_failure",
        ),
    )
    start_parser = sub.add_parser("start")
    start_parser.add_argument("--token", required=True)
    start_parser.add_argument("--allocation-bytes", type=int, default=96 * 1024 * 1024)
    start_parser.add_argument("--limit-bytes", type=int, default=48 * 1024 * 1024)
    start_parser.add_argument("--seconds", type=int, default=120)
    start_parser.add_argument("--worker-user", default="fleetdoctor")
    for action in ("status", "stop", "release"):
        item = sub.add_parser(action)
        item.add_argument("--token", required=True)
    supervisor_parser = sub.add_parser("supervisor")
    supervisor_parser.add_argument("--token", required=True)
    supervisor_parser.add_argument(
        "--proof-fault",
        choices=("supervisor_early_exit", "supervisor_not_ready", "cleanup_failure"),
    )
    allocate_parser = sub.add_parser("allocate")
    allocate_parser.add_argument("--bytes", type=int, required=True)
    allocate_parser.add_argument("--seconds", type=int, required=True)
    allocate_parser.add_argument("--gate", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "supervisor":
        supervisor(args.token, args.proof_fault)
        return
    if args.action == "allocate":
        allocate(args.bytes, args.seconds, args.gate)
        return
    if os.geteuid() != 0:
        raise PermissionError("OOM controller must run as root")
    if args.action == "prepare":
        result = prepare(
            args.token,
            args.lease_seconds,
            expiry_probe=args.expiry_probe,
            proof_fault=args.proof_fault,
        )
    elif args.action == "start":
        result = start(
            args.token, args.allocation_bytes, args.limit_bytes, args.seconds, args.worker_user
        )
    elif args.action == "status":
        result = status(args.token)
    elif args.action == "stop":
        result = stop(args.token)
    else:
        result = release(args.token)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
