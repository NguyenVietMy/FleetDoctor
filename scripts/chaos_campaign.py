#!/usr/bin/env python3
"""Freeze, execute and validate the fail-closed Ticket15 measurement campaign."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import statistics
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn, Protocol, cast
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
from uuid import UUID

from campaign_connection import (
    ConnectionPurpose,
    MonitorBackend,
    PersistentSshTransport,
    RelayHttpClient,
    validate_connection_receipt,
)
from chaos_harness import DiskHarness, InodeHarness, write_report
from chaos_oom import WorkloadNotObserved, add_recovery_sample, generation_key, workload
from dns_harness import DnsHarness
from fd_harness import FdHarness
from io_harness import IoHarness
from network_harness import NetworkHarness

BASELINE = "1b34a5d1abb364431c12860c1253e2f3b51af479"
PLAN_SHA256 = "ce914426774a3484bb76c290dcedcddb81d3a281da23fb67ada422930b59ffc0"
ORIGINAL_PLAN_SHA256 = "866081b38686ebe75ee8665d88a3e387125ed0c43a28a5586c7ccf23b4d6f44f"
SCENARIOS = (
    "disk",
    "inode",
    "fd",
    "oom",
    "cpu",
    "network",
    "dns",
    "io",
)
ASSIGNMENT = ("node-a", "node-b", "node-a", "node-b", "node-a")
RULES = {
    "disk": "disk_block_exhaustion",
    "inode": "inode_exhaustion",
    "fd": "fd_pressure",
    "oom": "workload_oom",
    "cpu": "cpu_saturation",
    "network": "network_path_degradation",
    "dns": "dns_resolution_failure",
    "io": "io_bottleneck",
}
MAX_PROTOCOL_BYTES = 64 * 1024
CAMPAIGN_LEASE_ROOT = (
    Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "FleetDoctor" / "campaign-leases"
    if os.name == "nt"
    else Path("/var/lock/fleetdoctor-campaigns")
)
CAMPAIGN_PHASES = 45
CAMPAIGN_DECLARED_SECONDS = CAMPAIGN_PHASES * 4 * 60
CAMPAIGN_TEARDOWN_RESERVE_SECONDS = 30 * 60
CONTROLLER_SESSION_SECONDS = 6 * 60 * 60
CONTROLLER_REQUEST_BUDGET = 4096
MONITOR_CONTROLLER_REQUEST_BUDGET = 200000
MONITOR_API_READ_BUDGET = 12 * CAMPAIGN_PHASES * 240 + 2000
FD_POST_RESTORE_DEADLINE_SECONDS = 60
FD_POST_RESTORE_MAX_POLLS = FD_POST_RESTORE_DEADLINE_SECONDS + 1
FD_POST_RESTORE_CALIBRATION_HANDOFFS = 2
FD_POST_RESTORE_MEASURED_HANDOFFS = 5
FD_POST_RESTORE_RESERVED_API_READS = (
    FD_POST_RESTORE_CALIBRATION_HANDOFFS + FD_POST_RESTORE_MEASURED_HANDOFFS
) * FD_POST_RESTORE_MAX_POLLS
if (
    FD_POST_RESTORE_CALIBRATION_HANDOFFS * FD_POST_RESTORE_DEADLINE_SECONDS > 120
    or FD_POST_RESTORE_MEASURED_HANDOFFS * FD_POST_RESTORE_DEADLINE_SECONDS > 300
    or FD_POST_RESTORE_RESERVED_API_READS > 2000
):
    raise RuntimeError("FD post-restore readiness exceeds the existing reserved campaign envelope")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def attempt_token(manifest: Mapping[str, Any], scenario: str, repetition: int, target: str) -> str:
    attempt_id = f"{scenario}-{repetition + 1}-{target}"
    return hashlib.sha256(f"{manifest['batch_id']}:{attempt_id}".encode()).hexdigest()[:32]


def oom_leaf_path(token: str) -> str:
    if re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise ValueError("invalid deterministic OOM token")
    return f"/system.slice/fleetdoctor-oom-{token}.service/workload"


def _http_url(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError(f"invalid {name}")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise ValueError(f"invalid {name}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=pairs,
        parse_constant=lambda item: (_ for _ in ()).throw(ValueError(f"non-finite {item}")),
    )
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def external_path(path: Path, checkout: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(checkout.resolve())
    except ValueError:
        return resolved
    raise ValueError("campaign artifacts and locks must remain outside the checkout")


def collect_source(checkout: Path) -> dict[str, Any]:
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=checkout,
        text=True,
    ).splitlines()
    hashes = {
        name: hashlib.sha256((checkout / name).read_bytes()).hexdigest()
        for name in names
        if (checkout / name).is_file()
    }
    return {
        "revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=checkout, text=True
        ).strip(),
        "dirty": bool(
            subprocess.check_output(["git", "status", "--porcelain"], cwd=checkout, text=True)
        ),
        "sha256": hashes,
        "aggregate_sha256": digest(hashes),
    }


def verify_source(checkout: Path, expected: dict[str, Any]) -> dict[str, Any]:
    actual = collect_source(checkout)
    if actual != expected:
        raise ValueError("actual checkout revision/dirty/full hashes differ from the frozen source")
    return actual


def validate_manifest(value: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "kind",
        "batch_id",
        "baseline",
        "plan_sha256",
        "original_plan_sha256",
        "ticket14_gate",
        "source",
        "installed",
        "configuration",
        "lab",
        "platform",
        "resources",
        "cadence_seconds",
        "deadlines",
        "assignments",
        "supersedes",
        "evidence_class",
        "runtime_receipt_sha256",
        "preparation_receipt_sha256",
        "connection_receipt_sha256",
    }
    if set(value) != required or value["schema_version"] != 2:
        raise ValueError("manifest fields/schema do not match Ticket15 v2")
    if value["kind"] not in {"calibration", "measured"}:
        raise ValueError("manifest kind must be calibration or measured")
    if value["evidence_class"] not in {"synthetic", "aws"}:
        raise ValueError("manifest evidence class must be synthetic or aws")
    if re.fullmatch(r"[0-9a-f]{64}", str(value["runtime_receipt_sha256"])) is None:
        raise ValueError("runtime receipt hash is invalid")
    if re.fullmatch(r"[0-9a-f]{64}", str(value["preparation_receipt_sha256"])) is None:
        raise ValueError("preparation receipt hash is invalid")
    if re.fullmatch(r"[0-9a-f]{64}", str(value["connection_receipt_sha256"])) is None:
        raise ValueError("connection receipt hash is invalid")
    batch_id = value["batch_id"]
    if (
        not isinstance(batch_id, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", batch_id) is None
    ):
        raise ValueError("invalid batch id")
    if (
        value["baseline"] != BASELINE
        or value["plan_sha256"] != PLAN_SHA256
        or value["original_plan_sha256"] != ORIGINAL_PLAN_SHA256
    ):
        raise ValueError("manifest baseline/plan binding mismatch")
    ticket14 = value["ticket14_gate"]
    if not isinstance(ticket14, dict) or ticket14.get("status") != "passed":
        raise ValueError("Ticket14 gate is missing or failed")
    if ticket14.get("revision") != BASELINE or not re.fullmatch(
        r"[0-9a-f]{64}", str(ticket14.get("coverage_receipt_sha256", ""))
    ):
        raise ValueError("Ticket14 gate binding is invalid")
    source = value["source"]
    if (
        not isinstance(source, dict)
        or re.fullmatch(r"[0-9a-f]{40}", str(source.get("revision", ""))) is None
        or not isinstance(source.get("dirty"), bool)
        or not isinstance(source.get("sha256"), dict)
        or not source["sha256"]
        or any(
            not isinstance(path, str) or re.fullmatch(r"[0-9a-f]{64}", str(file_hash)) is None
            for path, file_hash in source["sha256"].items()
        )
    ):
        raise ValueError("frozen full source manifest is invalid")
    if source.get("aggregate_sha256") != digest(source["sha256"]):
        raise ValueError("frozen source aggregate hash is invalid")
    for section in ("installed", "configuration", "platform", "resources"):
        if not isinstance(value[section], dict) or not value[section]:
            raise ValueError(f"manifest {section} must be a nonempty object")
    configuration = value["configuration"]
    if not isinstance(configuration.get("collector"), dict) or configuration.get(
        "sha256"
    ) != digest(configuration["collector"]):
        raise ValueError("effective collector configuration/hash binding is invalid")
    installed = value["installed"]
    if set(installed) != {"monitor", "node-a", "node-b"}:
        raise ValueError("installed hashes require monitor, node-a and node-b")
    installed_keys = {
        "monitor": {
            "source",
            "controller",
            "config_transaction",
            "protected_manifest",
            "controller_bundle",
        },
        "node-a": {
            "source",
            "controller",
            "config_transaction",
            "protected_manifest",
            "controller_bundle",
            "helpers",
        },
        "node-b": {
            "source",
            "controller",
            "config_transaction",
            "protected_manifest",
            "controller_bundle",
            "helpers",
        },
    }
    for role, facts in installed.items():
        if not isinstance(facts, dict) or set(facts) != installed_keys[role]:
            raise ValueError(f"installed facts missing for {role}")
        if any(re.fullmatch(r"[0-9a-f]{64}", str(item)) is None for item in facts.values()):
            raise ValueError(f"installed hash invalid for {role}")
    lab = value["lab"]
    if not isinstance(lab, dict) or set(lab) != {
        "account_id",
        "region",
        "availability_zone",
        "instances",
    }:
        raise ValueError("exact lab identity is incomplete")
    if (
        re.fullmatch(r"[0-9]{12}", str(lab["account_id"])) is None
        or lab["region"] != "us-east-1"
        or not isinstance(lab["availability_zone"], str)
    ):
        raise ValueError("lab region/AZ is invalid")
    instances = lab["instances"]
    if not isinstance(instances, dict) or set(instances) != {"monitor", "node-a", "node-b"}:
        raise ValueError("lab must contain exactly monitor/node-a/node-b")
    identifiers: set[str] = set()
    addresses: set[str] = set()
    for role, instance in instances.items():
        if not isinstance(instance, dict):
            raise ValueError(f"invalid instance facts for {role}")
        identifier = str(instance.get("id", ""))
        address = str(instance.get("private_ip", ""))
        if re.fullmatch(r"i-[0-9a-f]{8,17}", identifier) is None:
            raise ValueError(f"invalid instance id for {role}")
        ipaddress.ip_address(address)
        if not all(
            key in instance
            for key in ("type", "kernel", "cpu_credit_mode", "cpu_credit_balance", "state")
        ):
            raise ValueError(f"runtime instance facts missing for {role}")
        if (
            not isinstance(instance["type"], str)
            or not isinstance(instance["kernel"], str)
            or instance["cpu_credit_mode"] not in {"standard", "unlimited"}
            or not isinstance(instance["cpu_credit_balance"], (int, float))
            or isinstance(instance["cpu_credit_balance"], bool)
            or not math.isfinite(float(instance["cpu_credit_balance"]))
            or float(instance["cpu_credit_balance"]) < 0
            or instance["state"] != "running"
        ):
            raise ValueError(f"invalid runtime instance facts for {role}")
        identifiers.add(identifier)
        addresses.add(address)
    if len(identifiers) != 3 or len(addresses) != 3:
        raise ValueError("lab identities/addresses must be distinct")
    if value["cadence_seconds"] != 5:
        raise ValueError("campaign cadence must remain five seconds")
    deadlines = value["deadlines"]
    if deadlines != {
        "preparation_seconds": 60,
        "trigger_seconds": 60,
        "diagnosis_seconds": 60,
        "recovery_seconds": 60,
    }:
        raise ValueError("campaign deadlines differ from the frozen contract")
    assignments = value["assignments"]
    if not isinstance(assignments, dict) or set(assignments) != set(SCENARIOS):
        raise ValueError("all eight scenario assignments are required")
    if value["kind"] == "measured":
        if any(tuple(assignments[scenario]) != ASSIGNMENT for scenario in SCENARIOS):
            raise ValueError("measured assignment must be a,b,a,b,a for every scenario")
    elif any(tuple(assignments[scenario]) != ("node-a", "node-b") for scenario in SCENARIOS):
        raise ValueError("calibration requires one trial per scenario per node")
    if not isinstance(value["supersedes"], list):
        raise ValueError("supersedes must be an explicit list")
    platform = value["platform"]
    if set(platform) != {"node-a", "node-b"}:
        raise ValueError("platform facts require exactly both nodes")
    for node, facts in platform.items():
        if (
            not isinstance(facts, dict)
            or set(facts) != {"online_logical_cores"}
            or not isinstance(facts["online_logical_cores"], int)
            or isinstance(facts["online_logical_cores"], bool)
            or not 1 <= facts["online_logical_cores"] <= 64
        ):
            raise ValueError(f"invalid platform facts for {node}")
    resources = value["resources"]
    if set(resources) != {"api_url", "oom", "fd", "network"}:
        raise ValueError("resource manifest fields are incomplete or unknown")
    monitor_origin = f"http://{instances['monitor']['private_ip']}:8000"
    if resources["api_url"].rstrip("/") != monitor_origin:
        raise ValueError("API URL must be the verified monitor's fixed collector origin")
    oom = value["resources"].get("oom")
    if (
        not isinstance(oom, dict)
        or not isinstance(oom.get("leaf_paths"), list)
        or not isinstance(oom.get("existing_cgroups"), dict)
        or set(oom["existing_cgroups"]) != {"monitor", "node-a", "node-b"}
    ):
        raise ValueError("OOM predeclared leaf paths are required")
    oom_trials = len(assignments["oom"])
    if len(oom["leaf_paths"]) != oom_trials or len(set(oom["leaf_paths"])) != oom_trials:
        raise ValueError("OOM requires one unique predeclared leaf per assigned trial")
    expected_oom_paths = [
        oom_leaf_path(attempt_token(value, "oom", repetition, target))
        for repetition, target in enumerate(assignments["oom"])
    ]
    if oom["leaf_paths"] != expected_oom_paths:
        raise ValueError("OOM leaf paths do not match deterministic helper units")
    for node, existing in oom["existing_cgroups"].items():
        if (
            not isinstance(existing, list)
            or len(existing) != len(set(existing))
            or any(
                not isinstance(path, str)
                or len(path) > 256
                or re.fullmatch(r"/(?:[A-Za-z0-9_.:@-]+/)*[A-Za-z0-9_.:@-]+", path) is None
                for path in existing
            )
            or len(existing + oom["leaf_paths"]) > 8
        ):
            raise ValueError(f"invalid or excessive existing OOM scopes for {node}")
    fd = resources["fd"]
    if not isinstance(fd, dict) or set(fd) != {"node-a", "node-b"}:
        raise ValueError("FD resources require exactly both nodes")
    for node, facts in fd.items():
        pids = facts.get("existing_cpu_pids") if isinstance(facts, dict) else None
        if (
            not isinstance(pids, list)
            or len(pids) > 15
            or len(pids) != len(set(pids))
            or any(not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 for pid in pids)
        ):
            raise ValueError(f"invalid FD PID selectors for {node}")
    network = resources["network"]
    if not isinstance(network, dict) or set(network) != {"probe_target", "surrogate_url"}:
        raise ValueError("network resources are incomplete")
    ipaddress.ip_address(network["probe_target"])
    _http_url(network["surrogate_url"], "network surrogate URL")
    if network["surrogate_url"] != monitor_origin + "/health":
        raise ValueError("network surrogate must use the verified monitor relay")
    if CAMPAIGN_DECLARED_SECONDS + CAMPAIGN_TEARDOWN_RESERVE_SECONDS > CONTROLLER_SESSION_SECONDS:
        raise ValueError("declared campaign cannot fit the finite controller session")
    return value


def stable_lab_identity(lab: dict[str, Any]) -> dict[str, Any]:
    instances = lab.get("instances")
    if not isinstance(instances, dict):
        raise ValueError("lab instances are unavailable for exclusion")
    role_ids = {
        role: facts.get("id") if isinstance(facts, dict) else None
        for role, facts in sorted(instances.items())
    }
    if set(role_ids) != {"monitor", "node-a", "node-b"} or any(
        re.fullmatch(r"i-[0-9a-f]{8,17}", str(identifier)) is None
        for identifier in role_ids.values()
    ):
        raise ValueError("stable lab instance identity is incomplete")
    return {
        "account_id": lab.get("account_id"),
        "region": lab.get("region"),
        "availability_zone": lab.get("availability_zone"),
        "instances": role_ids,
    }


def lab_lease_path(lab: dict[str, Any], root: Path = CAMPAIGN_LEASE_ROOT) -> Path:
    return root / ("lab-" + digest(stable_lab_identity(lab)) + ".lock")


def _windows_process_state(pid: int) -> tuple[bool, str | None]:
    import ctypes
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    error_access_denied = 5
    error_invalid_parameter = 87
    error_not_found = 1168
    windll = cast(Any, getattr(ctypes, "WinDLL"))  # noqa: B009 - Windows-only API
    get_last_error = cast(Any, getattr(ctypes, "get_last_error"))  # noqa: B009
    kernel32 = windll("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        error = int(get_last_error())
        if error == error_access_denied:
            return True, None
        if error in {error_invalid_parameter, error_not_found}:
            return False, None
        raise OSError(error, "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed")
    try:
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise OSError(int(get_last_error()), "GetProcessTimes failed")
        identity = f"{creation.dwHighDateTime:08x}{creation.dwLowDateTime:08x}"
        return True, identity
    finally:
        kernel32.CloseHandle(handle)


def _process_identity(pid: int) -> str:
    if os.name == "nt":
        live, identity = _windows_process_state(pid)
        if not live or identity is None:
            raise RuntimeError("current Windows controller process identity is unavailable")
        return identity
    stat_fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    return stat_fields[21]


def _pid_is_live(pid: int, expected_identity: str | None = None) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        live, identity = _windows_process_state(pid)
        return bool(
            live
            and (identity is None or expected_identity is None or identity == expected_identity)
        )
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    if expected_identity is not None:
        try:
            return _process_identity(pid) == expected_identity
        except (FileNotFoundError, ProcessLookupError):
            return False
    return True


@contextmanager
def campaign_lock(path: Path, batch_id: str, lease_identity_sha256: str) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    owner = {
        "schema_version": 1,
        "batch_id": batch_id,
        "lease_identity_sha256": lease_identity_sha256,
        "pid": os.getpid(),
        "process_identity": _process_identity(os.getpid()),
        "created_at": datetime.now(UTC).isoformat(),
    }
    encoded = canonical(owner) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("short campaign lease write")
            offset += written
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        try:
            if load_json(path) == owner:
                path.unlink()
        except FileNotFoundError:
            pass


def recover_campaign_lock(path: Path, lease_identity_sha256: str) -> dict[str, Any]:
    if not path.exists():
        return {"status": "absent", "lease_identity_sha256": lease_identity_sha256}
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or (os.name == "posix" and info.st_mode & 0o022):
        raise ValueError("foreign or unprotected campaign lease")
    owner = load_json(path)
    if (
        set(owner)
        != {
            "schema_version",
            "batch_id",
            "lease_identity_sha256",
            "pid",
            "process_identity",
            "created_at",
        }
        or owner.get("schema_version") != 1
        or owner.get("lease_identity_sha256") != lease_identity_sha256
        or not isinstance(owner.get("pid"), int)
        or not isinstance(owner.get("process_identity"), str)
        or not isinstance(owner.get("batch_id"), str)
        or not isinstance(owner.get("created_at"), str)
    ):
        raise ValueError("campaign lease identity is foreign or malformed")
    if _pid_is_live(owner["pid"], owner["process_identity"]):
        raise RuntimeError("campaign lease is still owned by a live controller")
    path.unlink()
    return {
        "status": "recovered",
        "owner": owner,
        "lease_identity_sha256": lease_identity_sha256,
    }


class Backend(Protocol):
    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]: ...


class ControllerTransport(Protocol):
    def call(
        self, scenario: str, action: str, token: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]: ...


class Clock(Protocol):
    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...

    def utcnow(self) -> datetime: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def utcnow(self) -> datetime:
        return datetime.now(UTC)


class HttpBackend:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        suffix = "?" + urlencode(params) if params else ""
        request = Request(
            self.base_url + path + suffix,
            headers={"Authorization": "Bearer " + self.token},
        )
        with urlopen(request, timeout=3) as response:
            return cast(dict[str, Any], json.load(response))


class LegacyPersistentSshTransport:
    def __init__(
        self,
        host: str,
        key: Path,
        known_hosts: Path,
        *,
        user: str = "ec2-user",
        controller: str = "/usr/local/sbin/fleetdoctor-chaos-controller",
        call_timeout_seconds: float = 180,
    ) -> None:
        ipaddress.ip_address(host)
        if user != "ec2-user" or not controller.startswith("/usr/local/sbin/"):
            raise ValueError("SSH transport identity/controller is not allowlisted")
        if not 1 <= call_timeout_seconds <= 300:
            raise ValueError("SSH call timeout must be in 1..300 seconds")
        self.call_timeout_seconds = call_timeout_seconds
        self.process = subprocess.Popen(
            [
                "ssh",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ConnectionAttempts=1",
                "-o",
                "ServerAliveInterval=5",
                "-o",
                "ServerAliveCountMax=3",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UserKnownHostsFile=" + os.fspath(known_hosts),
                "-i",
                os.fspath(key),
                f"{user}@{host}",
                "sudo",
                "--",
                controller,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.sequence = 0
        self.broken = False
        self.closed = False
        self._lock = threading.Lock()

    def _abort(self) -> None:
        self.broken = True
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    pass

    def _exchange(self, encoded: bytes) -> bytes:
        result: list[bytes] = []
        failure: list[BaseException] = []

        def worker() -> None:
            try:
                assert self.process.stdin is not None and self.process.stdout is not None
                self.process.stdin.write(encoded)
                self.process.stdin.flush()
                result.append(self.process.stdout.readline(MAX_PROTOCOL_BYTES + 1))
            except BaseException as exc:
                failure.append(exc)

        thread = threading.Thread(target=worker, name="fleetdoctor-ssh-exchange", daemon=True)
        thread.start()
        thread.join(self.call_timeout_seconds)
        if thread.is_alive():
            self._abort()
            thread.join(5)
            raise TimeoutError("persistent SSH controller call exceeded its finite deadline")
        if failure:
            self._abort()
            raise RuntimeError("persistent SSH controller I/O failed") from failure[0]
        if not result:
            self._abort()
            raise RuntimeError("persistent SSH controller produced no response")
        return result[0]

    def call(
        self, scenario: str, action: str, token: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        with self._lock:
            if self.closed or self.broken or self.process.poll() is not None:
                raise RuntimeError("persistent SSH controller is not live")
            self.sequence += 1
            request_id = f"request-{self.sequence}"
            encoded = (
                canonical(
                    {
                        "id": request_id,
                        "scenario": scenario,
                        "action": action,
                        "token": token,
                        "arguments": arguments or {},
                    }
                )
                + b"\n"
            )
            if len(encoded) > MAX_PROTOCOL_BYTES:
                raise ValueError("controller request exceeds bound")
            line = self._exchange(encoded)
            if not line or len(line) > MAX_PROTOCOL_BYTES or not line.endswith(b"\n"):
                self._abort()
                raise RuntimeError("controller response is missing, truncated or oversized")
            try:
                response = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._abort()
                raise RuntimeError("controller response is malformed") from exc
            if not isinstance(response, dict) or response.get("id") != request_id:
                self._abort()
                raise RuntimeError("controller response identity mismatch")
            if response.get("ok") is not True or not isinstance(response.get("result"), dict):
                raise RuntimeError(str(response.get("error", "controller request failed")))
            return cast(dict[str, Any], response["result"])

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.broken:
            return
        if self.process.stdin is not None:
            closer = threading.Thread(target=self.process.stdin.close, daemon=True)
            closer.start()
            closer.join(5)
            if closer.is_alive():
                self._abort()
                raise TimeoutError("persistent SSH stdin close exceeded its finite deadline")
        try:
            code = self.process.wait(timeout=CAMPAIGN_TEARDOWN_RESERVE_SECONDS)
        except subprocess.TimeoutExpired as exc:
            self._abort()
            raise TimeoutError(
                "persistent SSH controller cleanup exceeded its finite deadline"
            ) from exc
        if code:
            stderr = self.process.stderr.read()[-2000:] if self.process.stderr else b""
            raise RuntimeError(
                "persistent SSH controller failed: " + stderr.decode(errors="replace")
            )

    def __enter__(self) -> LegacyPersistentSshTransport:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class TransportInjector:
    def __init__(self, transport: ControllerTransport, scenario: str) -> None:
        self.transport, self.scenario = transport, scenario

    def probe(self) -> dict[str, Any]:
        return self.transport.call(self.scenario, "probe", "0" * 32)

    def start(self, token: str, duration: int, **arguments: Any) -> dict[str, Any]:
        return self.transport.call(
            self.scenario, "start", token, {"duration": duration, **arguments}
        )

    def status(self, token: str) -> dict[str, Any]:
        return self.transport.call(self.scenario, "status", token)

    def cleanup(self, token: str) -> dict[str, Any]:
        return self.transport.call(self.scenario, "cleanup", token)


@dataclass
class AdapterContext:
    api: Backend
    transport: ControllerTransport
    manifest: dict[str, Any]
    target: str
    reference: str
    repetition: int
    output: Path
    token: str
    clock: Clock = dataclass_field(default_factory=SystemClock)
    runtime_receipt_sha256: str | None = None
    transports: Mapping[str, ControllerTransport] | None = None


def _event(report: Mapping[str, Any], name: str, field: str = "monotonic_seconds") -> float:
    events = report.get("events")
    if not isinstance(events, dict) or not isinstance(events.get(name), dict):
        raise ValueError(f"missing event {name}")
    value = events[name].get(field)
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"invalid event {name}")
    return float(value)


def _event_utc(report: Mapping[str, Any], name: str) -> str:
    events = report.get("events")
    value = events.get(name, {}).get("utc") if isinstance(events, dict) else None
    if not isinstance(value, str):
        raise ValueError(f"missing UTC correlation for {name}")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"UTC correlation lacks timezone for {name}")
    return value


def normalized_attempt(
    context: AdapterContext,
    scenario: str,
    phases: list[dict[str, Any]],
    *,
    incident_ids: list[str],
    raw_report: dict[str, Any],
) -> dict[str, Any]:
    for phase in phases:
        for event_field in (
            "injection_started_monotonic",
            "trigger_monotonic",
            "diagnosis_monotonic",
            "cleanup_monotonic",
            "resolution_monotonic",
        ):
            value = phase.get(event_field)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
            ):
                raise ValueError(f"{scenario} phase has invalid {event_field}")
        if not (
            phase["injection_started_monotonic"]
            <= phase["trigger_monotonic"]
            <= phase["diagnosis_monotonic"]
            and phase["cleanup_monotonic"] <= phase["resolution_monotonic"]
        ):
            raise ValueError(f"{scenario} phase event order is invalid")
        injection_utc = phase.get("injection_started_utc")
        if (
            not isinstance(injection_utc, str)
            or datetime.fromisoformat(injection_utc).tzinfo is None
        ):
            raise ValueError(f"{scenario} phase lacks a timezone-aware UTC correlation")
        phase["injection_to_diagnosis_seconds"] = (
            phase["diagnosis_monotonic"] - phase["injection_started_monotonic"]
        )
        phase["trigger_to_diagnosis_seconds"] = (
            phase["diagnosis_monotonic"] - phase["trigger_monotonic"]
        )
        phase["cleanup_to_resolution_seconds"] = (
            phase["resolution_monotonic"] - phase["cleanup_monotonic"]
        )
        if (
            phase["trigger_to_diagnosis_seconds"] > 60
            or phase["cleanup_to_resolution_seconds"] > 60
            or phase["injection_to_diagnosis_seconds"] > 120
        ):
            raise ValueError(f"{scenario} phase exceeded a hard deadline")
    raw_report["campaign_linkage"] = {
        "incident_ids": list(incident_ids),
        "phases": json.loads(canonical(phases)),
    }
    write_report(context.output, raw_report)
    return {
        "schema_version": 1,
        "batch_id": context.manifest["batch_id"],
        "kind": context.manifest["kind"],
        "scenario": scenario,
        "repetition": context.repetition,
        "target": context.target,
        "reference": context.reference,
        "token": context.token,
        "status": "passed",
        "source_sha256": digest(context.manifest["source"]),
        "configuration_sha256": digest(context.manifest["configuration"]),
        "lab_sha256": digest(context.manifest["lab"]),
        "incident_ids": incident_ids,
        "phases": phases,
        "cleanup_complete": True,
        "automatic_resolution": True,
        "evidence_validated": True,
        "unexpected_incidents": False,
        "evidence_class": context.manifest["evidence_class"],
        "raw_report_sha256": digest(raw_report),
        "raw_report": raw_report,
        "runtime_receipt_sha256": context.runtime_receipt_sha256,
    }


class ScenarioAdapter(ABC):
    name: str

    @abstractmethod
    def execute(self, context: AdapterContext) -> dict[str, Any]: ...


class DiskAdapter(ScenarioAdapter):
    name = "disk"

    def execute(self, context: AdapterContext) -> dict[str, Any]:
        harness = DiskHarness(
            context.api,
            TransportInjector(context.transport, "disk"),
            context.target,
            context.reference,
            context.output,
            context.manifest["platform"],
            lease_directory=context.output.parent / ".leases",
        )
        report = harness.run()
        phases = [
            {
                "name": "disk",
                "injection_started_monotonic": _event(report, "injection_start"),
                "injection_started_utc": _event_utc(report, "injection_start"),
                "trigger_monotonic": _event(report, "threshold_observed"),
                "diagnosis_monotonic": _event(report, "api_diagnosis"),
                "cleanup_monotonic": _event(report, "cleanup_complete"),
                "resolution_monotonic": _event(report, "api_resolution"),
            }
        ]
        return normalized_attempt(
            context, self.name, phases, incident_ids=[str(report["incident_id"])], raw_report=report
        )


class InodeAdapter(DiskAdapter):
    name = "inode"

    def execute(self, context: AdapterContext) -> dict[str, Any]:
        harness = InodeHarness(
            context.api,
            TransportInjector(context.transport, "inode"),
            context.target,
            context.reference,
            context.output,
            context.manifest["platform"],
            lease_directory=context.output.parent / ".leases",
        )
        report = harness.run()
        phases = [
            {
                "name": "inode",
                "injection_started_monotonic": _event(report, "injection_start"),
                "injection_started_utc": _event_utc(report, "injection_start"),
                "trigger_monotonic": _event(report, "threshold_observed"),
                "diagnosis_monotonic": _event(report, "api_diagnosis"),
                "cleanup_monotonic": _event(report, "cleanup_complete"),
                "resolution_monotonic": _event(report, "api_resolution"),
            }
        ]
        return normalized_attempt(
            context, self.name, phases, incident_ids=[str(report["incident_id"])], raw_report=report
        )


class FdInjector:
    def __init__(self, transport: ControllerTransport) -> None:
        self.transport = transport

    def start(self, token: str, limit: int, seconds: int) -> dict[str, Any]:
        return self.transport.call("fd", "start", token, {"limit": limit, "seconds": seconds})

    def pressure(self, token: str) -> dict[str, Any]:
        return self.transport.call("fd", "pressure", token)

    def release(self, token: str) -> dict[str, Any]:
        return self.transport.call("fd", "release", token)

    def status(self, token: str) -> dict[str, Any]:
        return self.transport.call("fd", "status", token)

    def cleanup(self, token: str) -> dict[str, Any]:
        return self.transport.call("fd", "cleanup", token)


FD_READINESS_MEMORY_ERRORS = frozenset(
    {
        "collection_supervisor_starting",
        "collection_supervisor_stuck",
        "collection_supervisor_timeout",
        "memory_collection_timeout",
        "memory_collection_worker_starting",
        "memory_collection_worker_stuck",
        "memory_counter_reset",
        "memory_rate_baseline_unavailable",
    }
)
FD_READINESS_HEALTHY_MEMORY_ERRORS = frozenset(
    {"memory_counter_reset", "memory_rate_baseline_unavailable"}
)


def _bounded_memory_errors(view: Mapping[str, Any]) -> tuple[list[str], bool]:
    memory = view.get("memory")
    if not isinstance(memory, dict):
        return [], True
    host = memory.get("host")
    if not isinstance(host, dict):
        return [], True
    errors = host.get("errors")
    if not isinstance(errors, list) or any(not isinstance(item, str) for item in errors):
        return [], True
    if len(errors) > 16 or any(item not in FD_READINESS_MEMORY_ERRORS for item in errors):
        return [], True
    return list(errors), False


def _bounded_sample_identity(view: Mapping[str, Any]) -> tuple[dict[str, Any], datetime] | None:
    sample = view.get("sample")
    if not isinstance(sample, dict):
        return None
    boot = sample.get("boot_id")
    session = sample.get("agent_session_id")
    sequence = sample.get("sequence")
    observed = sample.get("observed_at")
    if (
        not isinstance(boot, str)
        or not isinstance(session, str)
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 0
        or not isinstance(observed, str)
    ):
        return None
    try:
        UUID(boot)
        UUID(session)
        parsed = datetime.fromisoformat(observed)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    parsed = parsed.astimezone(UTC)
    return (
        {
            "boot_id": boot,
            "agent_session_id": session,
            "sequence": sequence,
            "observed_at": parsed.isoformat(),
        },
        parsed,
    )


def _fd_post_restore_readiness(
    context: AdapterContext,
    report: dict[str, Any],
    *,
    pre_restore_view: Mapping[str, Any],
    restored_inventory: Mapping[str, Any],
    restore_completed_at: datetime,
    expected_role_receipt_sha256: str,
) -> None:
    readiness: dict[str, Any] = {
        "stage": "post_selector_restore",
        "status": "pending",
        "deadline_outcome": "pending",
        "restore_completed_at": restore_completed_at.astimezone(UTC).isoformat(),
        "checks": [],
    }
    report["post_restore_readiness"] = readiness

    def initial_fail(category: str, message: str) -> NoReturn:
        readiness.update(status="failed", deadline_outcome="rejected", failure_category=category)
        write_report(context.output, report)
        raise ValueError(message)

    role_receipt = getattr(context.transport, "role_receipt", None)
    if not isinstance(role_receipt, dict) or digest(role_receipt) != expected_role_receipt_sha256:
        initial_fail("role_identity", "FD authenticated role receipt changed before readiness")
    expected_boot = role_receipt.get("boot_id")
    if not isinstance(expected_boot, str):
        initial_fail("role_identity", "FD authenticated role receipt lacks boot identity")
    try:
        UUID(expected_boot)
    except ValueError as exc:
        try:
            initial_fail("role_identity", "FD authenticated role receipt has invalid boot identity")
        except ValueError as failure:
            raise failure from exc

    pre = _bounded_sample_identity(pre_restore_view)
    if (
        pre is None
        or pre[0]["boot_id"] != expected_boot
        or pre_restore_view.get("fresh") is not True
    ):
        initial_fail("pre_restore_identity", "FD pre-restoration sample identity is invalid")
    pre_identity, pre_observed = pre
    write_report(context.output, report)
    deadline = context.clock.monotonic() + FD_POST_RESTORE_DEADLINE_SECONDS
    bound_session: str | None = None
    previous_new_identity: tuple[int, datetime] | None = None

    def fail(category: str, message: str, *, timeout: bool = False) -> NoReturn:
        readiness.update(
            status="failed",
            deadline_outcome="timeout" if timeout else "rejected",
            failure_category=category,
        )
        write_report(context.output, report)
        if timeout:
            raise TimeoutError(message) from None
        raise ValueError(message) from None

    for _ in range(FD_POST_RESTORE_MAX_POLLS):
        if context.clock.monotonic() >= deadline:
            fail("deadline", "FD post-restore readiness missed its deadline", timeout=True)
        if digest(getattr(context.transport, "role_receipt", None)) != expected_role_receipt_sha256:
            fail("role_identity", "FD authenticated role receipt changed during readiness")
        try:
            current_inventory = _bounded_inventory(
                context.transport.call("config", "inventory", "0" * 32, {"scope": "agent"})
            )
        except BaseException:
            readiness["checks"].append({"status": "failed", "category": "config_inventory"})
            fail("config_inventory", "FD collector configuration could not be verified")
        if current_inventory != restored_inventory:
            fail("config_changed", "FD collector configuration changed during readiness")
        try:
            view = context.api.get(f"/nodes/{context.target}/metrics")
        except BaseException:
            readiness["checks"].append({"status": "failed", "category": "metrics_read"})
            fail("metrics_read", "FD post-restore metrics read failed")
        if context.clock.monotonic() >= deadline:
            fail("deadline", "FD post-restore readiness read crossed its deadline", timeout=True)

        identity = _bounded_sample_identity(view)
        errors, malformed_errors = _bounded_memory_errors(view)
        coverage = view.get("memory_coverage")
        memory_host = coverage.get("host") if isinstance(coverage, dict) else None
        observation: dict[str, Any] = {
            "status": "pending",
            "category": "unclassified",
            "fresh": view.get("fresh") if isinstance(view.get("fresh"), bool) else None,
            "memory_host": memory_host
            if memory_host in {"available", "unavailable"}
            else "unknown",
            "memory_errors": errors if not malformed_errors else ["unknown"],
            "sample": identity[0] if identity is not None else None,
        }
        readiness["checks"].append(observation)
        if identity is None:
            fail("sample_identity", "FD post-restore sample identity is invalid")
        sample, observed = identity
        if sample["boot_id"] != expected_boot:
            fail("boot_changed", "FD post-restore sample boot changed")
        now = context.clock.utcnow().astimezone(UTC)
        if (
            observed > now.replace(microsecond=now.microsecond)
            and (observed - now).total_seconds() > 2
        ):
            fail("future_sample", "FD post-restore sample is future-dated")
        if view.get("fresh") is not True or view.get("stale") is True:
            fail("stale", "FD post-restore sample is stale")
        if view.get("active_incident_count") != 0:
            fail("incident", "FD post-restore sample has an active incident")
        if malformed_errors:
            fail("memory_errors", "FD post-restore memory errors are malformed or unknown")

        session = cast(str, sample["agent_session_id"])
        sequence = cast(int, sample["sequence"])
        if session == pre_identity["agent_session_id"]:
            if sequence < cast(int, pre_identity["sequence"]) or observed < pre_observed:
                fail("older_sample", "FD post-restore sample moved backwards")
            if memory_host != "available" or errors:
                fail("old_generation_unhealthy", "FD old collector generation became unhealthy")
            observation.update(category="pre_restore_generation")
            context.clock.sleep(1)
            continue
        if observed <= restore_completed_at or observed <= pre_observed:
            fail("older_sample", "FD new collector generation predates selector restoration")
        if bound_session is None:
            bound_session = session
        elif session != bound_session:
            fail("session_changed", "FD collector generation changed twice during readiness")
        if previous_new_identity is not None and (
            sequence <= previous_new_identity[0] or observed <= previous_new_identity[1]
        ):
            fail("non_monotonic", "FD new collector generation did not advance monotonically")
        previous_new_identity = (sequence, observed)

        if errors == ["collection_supervisor_starting"]:
            if memory_host != "unavailable":
                fail("startup_shape", "FD supervisor startup sample has invalid memory coverage")
            observation.update(category="collection_supervisor_starting")
            context.clock.sleep(1)
            continue
        if any(error not in FD_READINESS_HEALTHY_MEMORY_ERRORS for error in errors):
            fail("memory_errors", "FD post-restore memory collection failed")
        if memory_host != "available":
            fail("memory_unavailable", "FD post-restore host memory is unavailable")
        observation.update(status="passed", category="ready")
        readiness.update(status="passed", deadline_outcome="ready")
        write_report(context.output, report)
        return
    fail("deadline", "FD post-restore readiness missed its deadline", timeout=True)


class FdAdapter(ScenarioAdapter):
    name = "fd"

    def execute(self, context: AdapterContext) -> dict[str, Any]:
        role_receipt = getattr(context.transport, "role_receipt", None)
        if not isinstance(role_receipt, dict) or not isinstance(role_receipt.get("boot_id"), str):
            raise ValueError("FD requires an authenticated role boot receipt")
        try:
            UUID(role_receipt["boot_id"])
        except ValueError as exc:
            raise ValueError("FD authenticated role boot receipt is invalid") from exc
        role_receipt_sha256 = digest(role_receipt)
        injector = FdInjector(context.transport)
        harness = FdHarness(
            context.api,
            injector,
            context.target,
            context.reference,
            context.output,
            environment=context.manifest["platform"],
            token=context.token,
        )
        transaction = hashlib.sha256((context.token + "fd-selector").encode()).hexdigest()[:32]
        transaction_started = False
        existing = context.manifest["resources"]["fd"][context.target]["existing_cpu_pids"]
        expected_cgroups = [
            *context.manifest["resources"]["oom"]["existing_cgroups"][context.target],
            *context.manifest["resources"]["oom"]["leaf_paths"],
        ]
        parent = context.transport.call(
            "config",
            "status",
            preparation_token(context.manifest, context.target),
            {"scope": "agent"},
        )
        before_worker = _bounded_inventory(
            context.transport.call("config", "inventory", "0" * 32, {"scope": "agent"})
        )
        if (
            before_worker["selectors"]["FLEETDOCTOR_CGROUPS"] != expected_cgroups
            or before_worker["selectors"]["FLEETDOCTOR_CPU_PIDS"] != existing
            or parent.get("current_sha256") != before_worker["env_sha256"]
            or parent.get("changes") != {"FLEETDOCTOR_CGROUPS": ",".join(expected_cgroups)}
        ):
            raise ValueError("FD parent selector state differs before worker creation")

        def configure(identity: dict[str, Any]) -> dict[str, Any]:
            nonlocal transaction_started
            current = _bounded_inventory(
                context.transport.call("config", "inventory", "0" * 32, {"scope": "agent"})
            )
            if current != before_worker:
                raise ValueError("FD selector state raced after worker creation")
            pids = [int(value) for value in existing]
            pids.append(int(identity["pid"]))
            if len(pids) > 16:
                raise ValueError("FD selector would exceed sixteen PIDs")
            result = context.transport.call(
                "config",
                "begin",
                transaction,
                {
                    "changes": {"FLEETDOCTOR_CPU_PIDS": ",".join(str(item) for item in pids)},
                    "parent_token": preparation_token(context.manifest, context.target),
                    "expected_before": _expected_before(current),
                },
            )
            transaction_started = True
            return result

        harness.after_prepare = configure
        failure: BaseException | None = None
        pre_restore_view: dict[str, Any] | None = None
        pre_restore_capture_failure: BaseException | None = None
        try:
            report = harness.run("release", limit=128)
            try:
                pre_restore_view = context.api.get(f"/nodes/{context.target}/metrics")
            except BaseException as exc:
                pre_restore_capture_failure = exc
        except BaseException as exc:
            failure = exc
            raise
        finally:
            if transaction_started:
                try:
                    restored = context.transport.call("config", "restore", transaction)
                    if "report" in locals():
                        report["selector_restore"] = restored
                        write_report(context.output, report)
                except BaseException:
                    if failure is None:
                        raise
        restore_completed_at = context.clock.utcnow()
        if pre_restore_capture_failure is not None:
            report["post_restore_readiness"] = {
                "stage": "post_selector_restore",
                "status": "failed",
                "deadline_outcome": "rejected",
                "failure_category": "pre_restore_capture",
                "restore_completed_at": restore_completed_at.astimezone(UTC).isoformat(),
                "checks": [],
            }
            write_report(context.output, report)
            raise ValueError(
                "FD pre-restoration sample capture failed"
            ) from pre_restore_capture_failure
        if pre_restore_view is None:
            raise RuntimeError("FD pre-restoration sample capture was not retained")
        _fd_post_restore_readiness(
            context,
            report,
            pre_restore_view=pre_restore_view,
            restored_inventory=before_worker,
            restore_completed_at=restore_completed_at,
            expected_role_receipt_sha256=role_receipt_sha256,
        )
        phases = [
            {
                "name": "fd",
                "injection_started_monotonic": _event(report, "pressure_requested"),
                "injection_started_utc": _event_utc(report, "pressure_requested"),
                "trigger_monotonic": _event(report, "actual_resource_trigger_observed"),
                "diagnosis_monotonic": _event(report, "matching_incident_observed"),
                "cleanup_monotonic": _event(report, "actual_recovery_trigger_observed"),
                "resolution_monotonic": _event(report, "matching_recovery_observed"),
            }
        ]
        return normalized_attempt(
            context,
            self.name,
            phases,
            incident_ids=[str(report["incident"]["id"])],
            raw_report=report,
        )


class NetworkAdapter(ScenarioAdapter):
    name = "network"

    def execute(self, context: AdapterContext) -> dict[str, Any]:
        target = context.manifest["resources"]["network"]["probe_target"]

        def helper(action: str, token: str, profile: str, duration: int) -> dict[str, Any]:
            arguments = {"target": target, "profile": profile, "duration": duration}
            return context.transport.call(
                "network", action, token, arguments if action == "start" else {}
            )

        result = NetworkHarness(
            context.manifest["resources"]["api_url"],
            context.target,
            context.reference,
            target,
            context.manifest["resources"]["network"]["surrogate_url"],
            client=cast(
                Any,
                RelayHttpClient(context.api) if isinstance(context.api, MonitorBackend) else None,
            ),
            helper=helper,
        ).run()
        phases = []
        incident_ids = []
        for name in ("latency", "loss"):
            phase = result[name]
            phases.append(
                {
                    "name": name,
                    "injection_started_monotonic": phase["injection_started_monotonic"],
                    "injection_started_utc": phase["injection_started_utc"],
                    "trigger_monotonic": phase["trigger_observation"][
                        "response_completed_monotonic"
                    ],
                    "diagnosis_monotonic": phase["diagnosis_detail_response_completed_monotonic"],
                    "cleanup_monotonic": phase["recovery_started_monotonic"],
                    "resolution_monotonic": phase["recovery_response_completed_monotonic"],
                }
            )
            incident_ids.append(str(phase["incident_id"]))
        write_report(context.output, result)
        return normalized_attempt(
            context, self.name, phases, incident_ids=incident_ids, raw_report=result
        )


class DnsAdapter(ScenarioAdapter):
    name = "dns"

    def execute(self, context: AdapterContext) -> dict[str, Any]:
        def helper(action: str, token: str, invalid: str, duration: int) -> dict[str, Any]:
            arguments = {"invalid_resolver": invalid, "duration": duration}
            return context.transport.call(
                "dns", action, token, arguments if action == "start" else {}
            )

        result = DnsHarness(
            context.manifest["resources"]["api_url"],
            context.target,
            context.reference,
            client=cast(
                Any,
                RelayHttpClient(context.api) if isinstance(context.api, MonitorBackend) else None,
            ),
            helper=helper,
        ).run()
        phase = {
            "name": "dns",
            "injection_started_monotonic": result["injection_started_monotonic"],
            "injection_started_utc": result["injection_started_utc"],
            "trigger_monotonic": result["trigger"]["response_completed_monotonic"],
            "diagnosis_monotonic": result["incident"]["response_completed_monotonic"],
            "cleanup_monotonic": result["cleanup_response_completed_monotonic"],
            "resolution_monotonic": result["resolution"]["response_completed_monotonic"],
        }
        write_report(context.output, result)
        incident_id = str(result["incident"]["detail"]["id"])
        return normalized_attempt(
            context, self.name, [phase], incident_ids=[incident_id], raw_report=result
        )


class IoInjector:
    def __init__(self, transport: ControllerTransport) -> None:
        self.transport = transport

    def start(self, token: str, duration: int) -> dict[str, Any]:
        return self.transport.call("io", "start", token, {"duration": duration})

    def status(self, token: str) -> dict[str, Any]:
        return self.transport.call("io", "status", token)

    def cleanup(self, token: str) -> dict[str, Any]:
        return self.transport.call("io", "cleanup", token)


class IoAdapter(ScenarioAdapter):
    name = "io"

    def execute(self, context: AdapterContext) -> dict[str, Any]:
        if context.transports is None or context.reference not in context.transports:
            raise ValueError("I/O adapter requires the exact reference-node controller")
        reference_transport = context.transports[context.reference]
        reference_token = hashlib.sha256((context.token + ":reference").encode()).hexdigest()[:32]
        target_prepared = context.transport.call("io", "prepare", context.token)
        reference_prepared: dict[str, Any] | None = None
        failure: BaseException | None = None
        try:
            reference_prepared = reference_transport.call("io", "prepare", reference_token)
            report = IoHarness(
                context.api,
                IoInjector(context.transport),
                context.token,
                context.output,
                target=context.target,
                reference=context.reference,
                frozen_source=context.manifest["source"],
            ).run()
            report["resource_preparation"] = {
                "target": target_prepared,
                "reference": reference_prepared,
                "target_token": context.token,
                "reference_token": reference_token,
            }
            write_report(context.output, report)
        except BaseException as exc:
            failure = exc
            raise
        finally:
            cleanup_failures: list[BaseException] = []
            try:
                context.transport.call("io", "destroy", context.token)
            except BaseException as exc:
                cleanup_failures.append(exc)
            if reference_prepared is not None:
                try:
                    reference_transport.call("io", "destroy", reference_token)
                except BaseException as exc:
                    cleanup_failures.append(exc)
            if cleanup_failures and failure is None:
                raise RuntimeError(
                    "I/O mapping destruction failed: "
                    + "; ".join(f"{type(exc).__name__}: {exc}" for exc in cleanup_failures)
                )
        phase = {
            "name": "io",
            "injection_started_monotonic": _event(report, "injection_started", "monotonic"),
            "injection_started_utc": _event_utc(report, "injection_started"),
            "trigger_monotonic": _event(report, "first_trigger_response_complete", "monotonic"),
            "diagnosis_monotonic": _event(report, "diagnosis_detail_complete", "monotonic"),
            "cleanup_monotonic": _event(report, "cleanup_complete", "monotonic"),
            "resolution_monotonic": _event(report, "resolved_detail_complete", "monotonic"),
        }
        return normalized_attempt(
            context,
            self.name,
            [phase],
            incident_ids=[str(report["diagnosis"]["id"])],
            raw_report=report,
        )


def _identity(view: dict[str, Any]) -> tuple[str, str, int, str]:
    sample = view.get("sample") or {}
    return (
        str(sample.get("boot_id")),
        str(sample.get("agent_session_id")),
        int(sample.get("sequence", -1)),
        str(sample.get("observed_at")),
    )


class CpuAdapter(ScenarioAdapter):
    name = "cpu"

    def execute(self, context: AdapterContext) -> dict[str, Any]:
        clock = context.clock
        config = context.api.get("/configuration")["cpu_rule"]
        required = {"host_rates", "runnable", "logical_cores"}
        prior_ids = {
            str(item["id"])
            for item in context.api.get(
                "/diagnoses", {"node": context.target, "status": "active", "limit": 100}
            )["diagnoses"]
        }
        reference_prior = {
            str(item["id"])
            for item in context.api.get(
                "/diagnoses",
                {"node": context.reference, "status": "active", "limit": 100},
            )["diagnoses"]
        }

        def follows(
            identity: tuple[str, str, int, str], previous: tuple[str, str, int, str]
        ) -> bool:
            return bool(
                identity[:2] == previous[:2]
                and identity[2] > previous[2]
                and 0
                < (
                    datetime.fromisoformat(identity[3]) - datetime.fromisoformat(previous[3])
                ).total_seconds()
                <= float(config["max_gap_seconds"])
            )

        def reference() -> dict[str, Any]:
            view = context.api.get(f"/nodes/{context.reference}/metrics")
            current = context.api.get(
                "/diagnoses",
                {"node": context.reference, "status": "active", "limit": 100},
            )["diagnoses"]
            if (
                not view.get("fresh")
                or view.get("active_incident_count") != 0
                or any(str(item["id"]) not in reference_prior for item in current)
            ):
                raise ValueError("CPU reference freshness/incident continuity failed")
            return view

        baseline_identities: list[tuple[str, str, int, str]] = []
        reference_identities: list[tuple[str, str, int, str]] = []
        baseline_deadline = clock.monotonic() + 60
        while clock.monotonic() < baseline_deadline and len(baseline_identities) < 3:
            baseline = context.api.get(f"/nodes/{context.target}/metrics")
            baseline_reference = reference()
            identity = _identity(baseline)
            reference_identity = _identity(baseline_reference)
            cpu = baseline.get("cpu") or {}
            if (
                baseline.get("fresh")
                and baseline.get("active_incident_count") == 0
                and any(
                    baseline.get("cpu_coverage", {}).get(name) != "available" for name in required
                )
                is False
                and cpu.get("busy_percent") is not None
                and cpu["busy_percent"] < config["recovery_busy_percent"]
                and (not baseline_identities or follows(identity, baseline_identities[-1]))
                and (
                    not reference_identities
                    or follows(reference_identity, reference_identities[-1])
                )
            ):
                baseline_identities.append(identity)
                reference_identities.append(reference_identity)
            else:
                baseline_identities.clear()
                reference_identities.clear()
            clock.sleep(1)
        if len(baseline_identities) < 3:
            raise ValueError("CPU requires three fresh distinct low target/reference baselines")

        cores = int(context.manifest["platform"][context.target]["online_logical_cores"])
        workers = min(64, 2 * cores)
        injection_started = clock.monotonic()
        injection_started_utc = datetime.now(UTC).isoformat()
        context.transport.call("cpu", "start", context.token, {"workers": workers, "seconds": 180})
        trigger: float | None = None
        incident: dict[str, Any] | None = None
        cleanup = 0.0
        resolution = 0.0
        trigger_identity: tuple[str, str, int, str] | None = None
        opening_evidence_bytes: bytes | None = None
        try:
            trigger_deadline = injection_started + 60
            while clock.monotonic() < trigger_deadline:
                target = context.api.get(f"/nodes/{context.target}/metrics")
                reference()
                cpu = target.get("cpu") or {}
                identity = _identity(target)
                if (
                    target.get("fresh")
                    and follows(identity, baseline_identities[-1])
                    and cpu.get("busy_percent") is not None
                    and cpu["busy_percent"] >= config["trigger_busy_percent"]
                    and cpu.get("runnable_processes", 0) > cpu.get("logical_cores", 0)
                ):
                    trigger = clock.monotonic()
                    trigger_identity = identity
                    break
                clock.sleep(1)
            if trigger is None:
                raise TimeoutError("CPU ordinary trigger missed its preparation bound")
            deadline = trigger + 60
            while clock.monotonic() < deadline:
                reference()
                rows = context.api.get(
                    "/diagnoses",
                    {"node": context.target, "status": "active", "limit": 100},
                )["diagnoses"]
                new_rows = [item for item in rows if str(item["id"]) not in prior_ids]
                unexpected = [
                    item
                    for item in new_rows
                    if item.get("rule") not in {None, RULES[self.name]}
                    or item.get("resource") not in {None, "cpu"}
                ]
                if unexpected or len(new_rows) > 1:
                    raise ValueError("unexpected target incident opened during CPU detection")
                match = new_rows[0] if new_rows else None
                if match is not None:
                    detail = context.api.get("/diagnoses/" + str(match["id"]))
                    completed = clock.monotonic()
                    evidence = detail.get("opening_evidence", {}).get("cpu", {})
                    opening = detail.get("opening_evidence", {})
                    assert trigger_identity is not None
                    opening_identity = (
                        str(opening.get("boot_id")),
                        str(opening.get("agent_session_id")),
                        int(opening.get("sequence", -1)),
                        str(opening.get("observed_at")),
                    )
                    if (
                        completed > deadline
                        or detail.get("node_id") != context.target
                        or detail.get("rule") != RULES[self.name]
                        or detail.get("resource") != "cpu"
                        or detail.get("configuration") != config
                        or detail.get("severity") != config["severity"]
                        or opening.get("node_id") != context.target
                        or opening_identity[:2] != trigger_identity[:2]
                        or opening_identity[2] < trigger_identity[2]
                        or opening.get("cpu_available") is not True
                        or evidence.get("busy_percent", 0) < config["trigger_busy_percent"]
                        or evidence.get("runnable_processes", 0) <= evidence.get("logical_cores", 0)
                        or not isinstance(detail.get("latest_evidence"), dict)
                        or not detail.get("latest_evidence")
                        or not isinstance(detail.get("investigation_steps"), list)
                        or not detail.get("investigation_steps")
                    ):
                        raise ValueError("CPU incident evidence does not match the trigger")
                    opening_evidence_bytes = canonical(opening)
                    incident = detail | {"observed_monotonic": completed}
                    break
                clock.sleep(1)
            if incident is None:
                raise TimeoutError("CPU diagnosis missed 60 seconds after trigger")
        finally:
            result = context.transport.call("cpu", "cleanup", context.token)
            if result.get("cleaned") is not True:
                raise RuntimeError("CPU cleanup was not confirmed")
            cleanup = clock.monotonic()
        accepted: set[tuple[str, str, int, str]] = set()
        previous = trigger_identity
        deadline = cleanup + 60
        while clock.monotonic() < deadline:
            target = context.api.get(f"/nodes/{context.target}/metrics")
            reference()
            cpu = target.get("cpu") or {}
            identity = _identity(target)
            assert previous is not None
            continuous = follows(identity, previous)
            active_rows = context.api.get(
                "/diagnoses", {"node": context.target, "status": "active", "limit": 100}
            )["diagnoses"]
            if any(
                str(item["id"]) not in prior_ids | {str(incident["id"])} for item in active_rows
            ):
                raise ValueError("unexpected target incident remained during CPU recovery")
            if (
                target.get("fresh")
                and target.get("active_incident_count") in {0, 1}
                and cpu.get("busy_percent") is not None
                and cpu["busy_percent"] < config["recovery_busy_percent"]
                and continuous
            ):
                accepted.add(identity)
                previous = identity
            elif previous is not None and identity != previous:
                accepted.clear()
                previous = None
            detail = context.api.get("/diagnoses/" + str(incident["id"]))
            completed = clock.monotonic()
            if (
                detail.get("status") == "resolved"
                and len(accepted) >= int(config["consecutive_samples"])
                and completed <= deadline
                and opening_evidence_bytes is not None
                and canonical(detail.get("opening_evidence")) == opening_evidence_bytes
                and not active_rows
                and isinstance(detail.get("latest_evidence"), dict)
                and detail.get("latest_evidence")
                and isinstance(detail.get("investigation_steps"), list)
                and detail.get("investigation_steps")
            ):
                resolution = completed
                break
            clock.sleep(1)
        else:
            raise TimeoutError("CPU fresh recovery missed 60 seconds after cleanup")
        raw = {
            "status": "passed",
            "configuration": config,
            "injection_started_monotonic": injection_started,
            "injection_started_utc": injection_started_utc,
            "trigger_monotonic": trigger,
            "incident": incident,
            "cleanup_monotonic": cleanup,
            "resolution_monotonic": resolution,
            "recovery_identities": sorted(accepted),
        }
        write_report(context.output, raw)
        phase = {
            "name": "cpu",
            "injection_started_monotonic": injection_started,
            "injection_started_utc": injection_started_utc,
            "trigger_monotonic": trigger,
            "diagnosis_monotonic": incident["observed_monotonic"],
            "cleanup_monotonic": cleanup,
            "resolution_monotonic": resolution,
        }
        return normalized_attempt(
            context, self.name, [phase], incident_ids=[str(incident["id"])], raw_report=raw
        )


class OomAdapter(ScenarioAdapter):
    name = "oom"

    def execute(self, context: AdapterContext) -> dict[str, Any]:
        clock = context.clock
        cgroup = context.manifest["resources"]["oom"]["leaf_paths"][context.repetition]
        prepared: dict[str, Any] | None = None
        incident: dict[str, Any] | None = None
        trigger: float | None = None
        trigger_counters: tuple[int, int] | None = None
        cleanup = 0.0
        resolution = 0.0
        exact_resource = ""
        released: dict[str, Any] | None = None
        failure: BaseException | None = None
        report: dict[str, Any] = {
            "status": "running",
            "cgroup": cgroup,
            "baseline_samples": [],
            "trigger_samples": [],
            "recovery_samples": [],
            "reference_samples": [],
            "reference_checks": [],
        }

        def active(node: str) -> list[dict[str, Any]]:
            return list(
                context.api.get(
                    "/diagnoses",
                    {"node": node, "status": "active", "limit": 100},
                )["diagnoses"]
            )

        def rejected_reference_check(category: str) -> dict[str, Any]:
            check = {
                "status": "rejected",
                "rejection_category": category,
                "fresh": None,
                "sample": None,
                "memory_host": "unknown",
                "memory_errors": ["unknown"],
            }
            report["reference_checks"].append(check)
            return check

        def reference_incident_ids(check: dict[str, Any] | None = None) -> set[str]:
            try:
                return {str(item["id"]) for item in active(context.reference)}
            except BaseException:
                if check is None:
                    rejected_reference_check("incident_read")
                else:
                    check.update(status="rejected", rejection_category="incident_read")
                raise ValueError("OOM reference incident observation failed") from None

        def reference(original_ids: set[str]) -> None:
            try:
                view = context.api.get(f"/nodes/{context.reference}/metrics")
            except BaseException:
                rejected_reference_check("metrics_read")
                raise ValueError("OOM reference metrics observation failed") from None
            identity = _bounded_sample_identity(view)
            memory_errors, malformed_errors = _bounded_memory_errors(view)
            coverage = view.get("memory_coverage")
            memory_host = coverage.get("host") if isinstance(coverage, dict) else None
            check: dict[str, Any] = {
                "status": "pending",
                "rejection_category": None,
                "fresh": view.get("fresh") if isinstance(view.get("fresh"), bool) else None,
                "sample": identity[0] if identity is not None else None,
                "memory_host": memory_host
                if memory_host in {"available", "unavailable"}
                else "unknown",
                "memory_errors": memory_errors if not malformed_errors else ["unknown"],
            }
            report["reference_checks"].append(check)
            if (
                not view.get("fresh")
                or (view.get("memory_coverage") or {}).get("host") != "available"
            ):
                check.update(
                    status="rejected",
                    rejection_category="freshness" if not view.get("fresh") else "host_memory",
                )
                raise ValueError("OOM reference telemetry became stale")
            current_ids = reference_incident_ids(check)
            if not current_ids.issubset(original_ids):
                check.update(status="rejected", rejection_category="incident")
                raise ValueError("OOM reference opened an unexpected incident")
            check["status"] = "accepted"
            report["reference_samples"].append(
                {"identity": _identity(view), "active_incident_ids": sorted(current_ids)}
            )

        try:
            prepared = context.transport.call(
                "oom", "prepare", context.token, {"lease_seconds": 360}
            )
            report["prepared"] = prepared
            if prepared.get("leaf_path") != cgroup or prepared.get("phase") != "prepared":
                raise ValueError("prepared OOM leaf differs from its frozen manifest path")
            if prepared.get("processes"):
                raise ValueError("prepared OOM leaf is not empty")
            configuration = context.api.get("/configuration")
            if cgroup not in configuration["cgroups"]:
                raise ValueError("prepared OOM leaf is outside the frozen collector scope")
            config = configuration["oom_rule"]
            target_prior = {str(item["id"]) for item in active(context.target)}
            reference_prior = reference_incident_ids()
            baseline_identities: set[tuple[str, str, int, str]] = set()
            baseline_deadline = clock.monotonic() + 60
            baseline_item: dict[str, Any] | None = None
            baseline_events: tuple[int, int] | None = None
            previous_identity: tuple[str, str, int, str] | None = None
            exact_workload_observed = False
            while clock.monotonic() < baseline_deadline and len(baseline_identities) < 3:
                view = context.api.get(f"/nodes/{context.target}/metrics")
                if clock.monotonic() >= baseline_deadline:
                    raise TimeoutError(
                        "three fresh empty exact-generation OOM baselines are required"
                    )
                if (
                    not view.get("fresh")
                    or (view.get("memory_coverage") or {}).get("host") != "available"
                ):
                    raise ValueError("OOM target telemetry is stale during baseline")
                try:
                    candidate = workload(view, cgroup)
                except WorkloadNotObserved:
                    if exact_workload_observed:
                        raise RuntimeError(
                            "exact workload ordinary telemetry is unavailable after observation"
                        ) from None
                    current_target = active(context.target)
                    if clock.monotonic() >= baseline_deadline:
                        raise TimeoutError(
                            "three fresh empty exact-generation OOM baselines are required"
                        ) from None
                    if any(str(item["id"]) not in target_prior for item in current_target):
                        raise ValueError(
                            "unexpected target OOM incident opened during readiness"
                        ) from None
                    reference(reference_prior)
                    if clock.monotonic() >= baseline_deadline:
                        raise TimeoutError(
                            "three fresh empty exact-generation OOM baselines are required"
                        ) from None
                    clock.sleep(1)
                    continue
                exact_workload_observed = True
                identity = _identity(view)
                events = candidate["events"]
                counters = (int(events["oom"]), int(events["oom_kill"]))
                continuous = bool(
                    previous_identity is None
                    or (
                        identity[:2] == previous_identity[:2]
                        and identity[2] > previous_identity[2]
                        and 0
                        < (
                            datetime.fromisoformat(identity[3])
                            - datetime.fromisoformat(previous_identity[3])
                        ).total_seconds()
                        <= float(config["max_gap_seconds"])
                    )
                )
                current_target = active(context.target)
                if clock.monotonic() >= baseline_deadline:
                    raise TimeoutError(
                        "three fresh empty exact-generation OOM baselines are required"
                    )
                if (
                    candidate.get("generation_stable") is True
                    and candidate.get("events_stable") is True
                    and candidate.get("processes") == []
                    and float(candidate.get("usage_ratio", 1))
                    < float(config["recovery_percent"]) / 100
                    and (baseline_events is None or counters == baseline_events)
                    and continuous
                    and not any(
                        item.get("resource") == generation_key(cgroup, candidate)
                        for item in current_target
                    )
                ):
                    reference(reference_prior)
                    baseline_identities.add(identity)
                    baseline_item = candidate
                    baseline_events = counters
                    previous_identity = identity
                    report["baseline_samples"].append({"identity": identity, "workload": candidate})
                else:
                    baseline_identities.clear()
                    report["baseline_samples"].clear()
                    baseline_events = None
                    previous_identity = None
                    reference(reference_prior)
                if clock.monotonic() >= baseline_deadline:
                    raise TimeoutError(
                        "three fresh empty exact-generation OOM baselines are required"
                    )
                clock.sleep(1)
            if (
                clock.monotonic() >= baseline_deadline
                or baseline_item is None
                or len(baseline_identities) < 3
            ):
                raise TimeoutError("three fresh empty exact-generation OOM baselines are required")
            exact_resource = generation_key(cgroup, baseline_item)
            exact_generation = {
                "boot_id": str(baseline_item["boot_id"]),
                "st_dev": baseline_item["st_dev"],
                "st_ino": baseline_item["st_ino"],
            }
            assert baseline_events is not None
            helper_generation = prepared.get("generation")
            if not isinstance(helper_generation, dict) or any(
                helper_generation.get(field) != baseline_item.get(field)
                for field in ("st_dev", "st_ino")
            ):
                raise ValueError("helper and collector OOM generations disagree")
            report["exact_resource"] = exact_resource
            report["exact_generation"] = exact_generation
            report["configuration"] = config
            if clock.monotonic() >= baseline_deadline:
                raise TimeoutError("three fresh empty exact-generation OOM baselines are required")
            started = clock.monotonic()
            started_utc = datetime.now(UTC).isoformat()
            report["injection_started_monotonic"] = started
            report["injection_started_utc"] = started_utc
            injection = context.transport.call(
                "oom",
                "start",
                context.token,
                {
                    "allocation_bytes": 96 * 1024 * 1024,
                    "limit_bytes": 48 * 1024 * 1024,
                    "seconds": 180,
                },
            )
            limits = injection.get("limits") or {}
            monitor_groups = injection.get("monitor_control_groups") or {}
            if (
                limits.get("memory.max") != str(48 * 1024 * 1024)
                or limits.get("memory.swap.max") != "0"
                or limits.get("pids.max") != "4"
                or cgroup in str(injection.get("caller_cgroup", ""))
                or any(
                    group == cgroup or str(group).startswith(cgroup + "/")
                    for group in monitor_groups.values()
                    if group is not None
                )
            ):
                raise ValueError("OOM finite limits or monitoring separation changed")
            report["injection"] = injection
            deadline = started + 60
            while clock.monotonic() < deadline:
                view = context.api.get(f"/nodes/{context.target}/metrics")
                if (
                    not view.get("fresh")
                    or (view.get("memory_coverage") or {}).get("host") != "available"
                ):
                    raise ValueError("OOM target telemetry became stale during detection")
                current = workload(view, cgroup)
                if generation_key(cgroup, current) != exact_resource:
                    raise ValueError("OOM cgroup generation changed during detection")
                events = (int(current["events"]["oom"]), int(current["events"]["oom_kill"]))
                if events[1] > baseline_events[1] and trigger is None:
                    trigger = clock.monotonic()
                    trigger_counters = events
                    deadline = trigger + 60
                    report["trigger_samples"].append(
                        {"identity": _identity(view), "workload": current}
                    )
                reference(reference_prior)
                rows = active(context.target)
                unexpected = [
                    item
                    for item in rows
                    if str(item["id"]) not in target_prior
                    and item.get("resource") != exact_resource
                ]
                if unexpected:
                    raise ValueError("unexpected target OOM incident opened")
                match = next(
                    (
                        item
                        for item in rows
                        if str(item["id"]) not in target_prior
                        and item.get("resource") == exact_resource
                    ),
                    None,
                )
                if match is not None and trigger is not None:
                    detail = context.api.get("/diagnoses/" + str(match["id"]))
                    completed = clock.monotonic()
                    evidence = detail.get("opening_evidence", {})
                    if (
                        completed > deadline
                        or detail.get("node_id") != context.target
                        or detail.get("rule") != RULES[self.name]
                        or detail.get("resource") != exact_resource
                        or detail.get("configuration") != config
                        or detail.get("severity") != config["severity"]
                        or evidence.get("cgroup_path") != cgroup
                        or evidence.get("generation") != exact_generation
                        or evidence.get("event_delta", {}).get("oom_kill", 0) <= 0
                        or not isinstance(detail.get("latest_evidence"), dict)
                        or not detail.get("latest_evidence")
                        or not isinstance(detail.get("investigation_steps"), list)
                        or not detail.get("investigation_steps")
                    ):
                        raise ValueError("OOM incident evidence does not match the exact leaf")
                    incident = detail | {"observed_monotonic": completed}
                    break
                clock.sleep(1)
            if incident is None or trigger is None:
                raise TimeoutError("OOM trigger/diagnosis missed its deadline")
            ground = context.transport.call("oom", "status", context.token)
            report["real_kill_status"] = ground
            if (
                prepared is None
                or int(ground["events"]["oom_kill"]) <= int(prepared["events"]["oom_kill"])
                or ground.get("processes")
            ):
                raise ValueError("OOM helper did not prove kernel kill and allocator death")
            pre_stop_identity = report["trigger_samples"][-1]["identity"]
            context.transport.call("oom", "stop", context.token)
            cleanup = clock.monotonic()
            accepted: set[tuple[str, str, int, str]] = set()
            recovery_counters = cast(tuple[int, int], trigger_counters)
            previous_recovery_identity = cast(tuple[str, str, int, str], tuple(pre_stop_identity))
            opening_evidence_bytes = canonical(incident["opening_evidence"])
            deadline = cleanup + 60
            while clock.monotonic() < deadline:
                view = context.api.get(f"/nodes/{context.target}/metrics")
                if (
                    not view.get("fresh")
                    or (view.get("memory_coverage") or {}).get("host") != "available"
                ):
                    raise ValueError("OOM target telemetry became stale during recovery")
                current = workload(view, cgroup)
                if generation_key(cgroup, current) != exact_resource:
                    raise ValueError("OOM cgroup generation changed during recovery")
                counters = (
                    int(current["events"]["oom"]),
                    int(current["events"]["oom_kill"]),
                )
                identity = _identity(view)
                continuous = bool(
                    identity[:2] == previous_recovery_identity[:2]
                    and identity[2] > previous_recovery_identity[2]
                    and 0
                    < (
                        datetime.fromisoformat(identity[3])
                        - datetime.fromisoformat(previous_recovery_identity[3])
                    ).total_seconds()
                    <= float(config["max_gap_seconds"])
                )
                if counters != recovery_counters:
                    recovery_counters = counters
                    accepted.clear()
                    report["recovery_samples"].clear()
                    previous_recovery_identity = identity
                elif continuous and add_recovery_sample(
                    accepted,
                    identity,
                    cast(tuple[str, str, int, str], tuple(pre_stop_identity)),
                    current,
                    counters,
                    recovery_counters,
                    float(config["recovery_percent"]),
                ):
                    previous_recovery_identity = identity
                    report["recovery_samples"].append({"identity": identity, "workload": current})
                reference(reference_prior)
                detail = context.api.get("/diagnoses/" + str(incident["id"]))
                current_active = active(context.target)
                if any(
                    str(item["id"]) not in target_prior | {str(incident["id"])}
                    for item in current_active
                ):
                    raise ValueError("unexpected target incident remained during OOM recovery")
                if (
                    detail.get("status") == "resolved"
                    and canonical(detail.get("opening_evidence")) == opening_evidence_bytes
                    and len(accepted) >= int(config["consecutive_samples"])
                    and not current_active
                    and isinstance(detail.get("latest_evidence"), dict)
                    and detail.get("latest_evidence")
                    and isinstance(detail.get("investigation_steps"), list)
                    and detail.get("investigation_steps")
                ):
                    resolution = clock.monotonic()
                    break
                clock.sleep(1)
            if not resolution:
                raise TimeoutError("OOM recovery missed its deadline")
            report.update(
                status="passed",
                trigger_monotonic=trigger,
                incident=incident,
                cleanup_monotonic=cleanup,
                resolution_monotonic=resolution,
            )
        except BaseException as exc:
            report.update(status="failed", failure=f"{type(exc).__name__}: {exc}")
            failure = exc
        finally:
            try:
                released = context.transport.call("oom", "release", context.token)
                report["release"] = released
                if released.get("released") is not True and released.get("owned") is not False:
                    raise RuntimeError("OOM release was not confirmed")
            except BaseException as exc:
                report["release_failure"] = f"{type(exc).__name__}: {exc}"
                if failure is None:
                    raise
            finally:
                write_report(context.output, report)
        if failure is not None:
            raise failure
        assert incident is not None and trigger is not None
        phase = {
            "name": "oom",
            "injection_started_monotonic": started,
            "injection_started_utc": started_utc,
            "trigger_monotonic": trigger,
            "diagnosis_monotonic": incident["observed_monotonic"],
            "cleanup_monotonic": cleanup,
            "resolution_monotonic": resolution,
        }
        return normalized_attempt(
            context, self.name, [phase], incident_ids=[str(incident["id"])], raw_report=report
        )


ADAPTERS: dict[str, ScenarioAdapter] = {
    adapter.name: adapter
    for adapter in (
        DiskAdapter(),
        InodeAdapter(),
        FdAdapter(),
        OomAdapter(),
        CpuAdapter(),
        NetworkAdapter(),
        DnsAdapter(),
        IoAdapter(),
    )
}


def raw_evidence_matches(item: dict[str, Any]) -> bool:
    raw = item.get("raw_report")
    try:
        raw_digest = digest(raw)
    except (TypeError, ValueError):
        return False
    if not isinstance(raw, dict) or item.get("raw_report_sha256") != raw_digest:
        return False
    declared = {
        "incident_ids": item.get("incident_ids"),
        "phases": item.get("phases"),
    }
    if raw.get("campaign_linkage") != declared:
        return False
    scenario = item.get("scenario")
    try:
        if scenario in {"disk", "inode"}:
            observed_ids = [str(raw["incident_id"])]
            event_names = (
                "injection_start",
                "threshold_observed",
                "api_diagnosis",
                "cleanup_complete",
                "api_resolution",
            )
            observed_phases = [
                {
                    "name": scenario,
                    "injection_started_monotonic": _event(raw, event_names[0]),
                    "injection_started_utc": _event_utc(raw, event_names[0]),
                    "trigger_monotonic": _event(raw, event_names[1]),
                    "diagnosis_monotonic": _event(raw, event_names[2]),
                    "cleanup_monotonic": _event(raw, event_names[3]),
                    "resolution_monotonic": _event(raw, event_names[4]),
                }
            ]
        elif scenario == "fd":
            observed_ids = [str(raw["incident"]["id"])]
            observed_phases = [
                {
                    "name": "fd",
                    "injection_started_monotonic": _event(raw, "pressure_requested"),
                    "injection_started_utc": _event_utc(raw, "pressure_requested"),
                    "trigger_monotonic": _event(raw, "actual_resource_trigger_observed"),
                    "diagnosis_monotonic": _event(raw, "matching_incident_observed"),
                    "cleanup_monotonic": _event(raw, "actual_recovery_trigger_observed"),
                    "resolution_monotonic": _event(raw, "matching_recovery_observed"),
                }
            ]
        elif scenario in {"cpu", "oom"}:
            observed_ids = [str(raw["incident"]["id"])]
            observed_phases = [
                {
                    "name": scenario,
                    "injection_started_monotonic": float(raw["injection_started_monotonic"]),
                    "injection_started_utc": str(raw["injection_started_utc"]),
                    "trigger_monotonic": float(raw["trigger_monotonic"]),
                    "diagnosis_monotonic": float(raw["incident"]["observed_monotonic"]),
                    "cleanup_monotonic": float(raw["cleanup_monotonic"]),
                    "resolution_monotonic": float(raw["resolution_monotonic"]),
                }
            ]
        elif scenario == "network":
            observed_ids = [str(raw[name]["incident_id"]) for name in ("latency", "loss")]
            observed_phases = [
                {
                    "name": name,
                    "injection_started_monotonic": float(raw[name]["injection_started_monotonic"]),
                    "injection_started_utc": str(raw[name]["injection_started_utc"]),
                    "trigger_monotonic": float(
                        raw[name]["trigger_observation"]["response_completed_monotonic"]
                    ),
                    "diagnosis_monotonic": float(
                        raw[name]["diagnosis_detail_response_completed_monotonic"]
                    ),
                    "cleanup_monotonic": float(raw[name]["recovery_started_monotonic"]),
                    "resolution_monotonic": float(
                        raw[name]["recovery_response_completed_monotonic"]
                    ),
                }
                for name in ("latency", "loss")
            ]
        elif scenario == "dns":
            observed_ids = [str(raw["incident"]["detail"]["id"])]
            observed_phases = [
                {
                    "name": "dns",
                    "injection_started_monotonic": float(raw["injection_started_monotonic"]),
                    "injection_started_utc": str(raw["injection_started_utc"]),
                    "trigger_monotonic": float(raw["trigger"]["response_completed_monotonic"]),
                    "diagnosis_monotonic": float(raw["incident"]["response_completed_monotonic"]),
                    "cleanup_monotonic": float(raw["cleanup_response_completed_monotonic"]),
                    "resolution_monotonic": float(
                        raw["resolution"]["response_completed_monotonic"]
                    ),
                }
            ]
        elif scenario == "io":
            observed_ids = [str(raw["diagnosis"]["id"])]
            observed_phases = [
                {
                    "name": "io",
                    "injection_started_monotonic": _event(raw, "injection_started", "monotonic"),
                    "injection_started_utc": _event_utc(raw, "injection_started"),
                    "trigger_monotonic": _event(
                        raw, "first_trigger_response_complete", "monotonic"
                    ),
                    "diagnosis_monotonic": _event(raw, "diagnosis_detail_complete", "monotonic"),
                    "cleanup_monotonic": _event(raw, "cleanup_complete", "monotonic"),
                    "resolution_monotonic": _event(raw, "resolved_detail_complete", "monotonic"),
                }
            ]
        else:
            return False
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    actual_phases = item.get("phases")
    if not isinstance(actual_phases, list) or observed_ids != item.get("incident_ids"):
        return False
    fields = tuple(observed_phases[0]) if observed_phases else ()
    return len(actual_phases) == len(observed_phases) and all(
        all(phase.get(field) == observed.get(field) for field in fields)
        for phase, observed in zip(actual_phases, observed_phases, strict=True)
    )


def _bounded_inventory(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "env_sha256",
        "selectors",
        "missing_keys",
        "mode",
        "uid",
        "gid",
        "service_state",
    }:
        raise ValueError("selector inventory is malformed")
    if re.fullmatch(r"[0-9a-f]{64}", str(value["env_sha256"])) is None:
        raise ValueError("selector inventory environment hash is invalid")
    selectors = value["selectors"]
    if not isinstance(selectors, dict) or set(selectors) != {
        "FLEETDOCTOR_CGROUPS",
        "FLEETDOCTOR_CPU_PIDS",
    }:
        raise ValueError("selector inventory keys are invalid")
    if (
        not isinstance(selectors["FLEETDOCTOR_CGROUPS"], list)
        or not isinstance(selectors["FLEETDOCTOR_CPU_PIDS"], list)
        or len(selectors["FLEETDOCTOR_CGROUPS"]) > 8
        or len(selectors["FLEETDOCTOR_CPU_PIDS"]) > 16
        or len(set(selectors["FLEETDOCTOR_CGROUPS"])) != len(selectors["FLEETDOCTOR_CGROUPS"])
        or len(set(selectors["FLEETDOCTOR_CPU_PIDS"])) != len(selectors["FLEETDOCTOR_CPU_PIDS"])
    ):
        raise ValueError("selector inventory exceeds bounds or contains duplicates")
    return value


def _expected_before(inventory: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "env_sha256": inventory["env_sha256"],
        "selectors": inventory["selectors"],
        "missing_keys": inventory["missing_keys"],
    }


def declared_preparation_changes(manifest: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    oom = manifest["resources"]["oom"]
    node_changes = {
        node: {
            "FLEETDOCTOR_CGROUPS": ",".join([*oom["existing_cgroups"][node], *oom["leaf_paths"]])
        }
        for node in ("node-a", "node-b")
    }
    monitor_paths = list(dict.fromkeys([*oom["existing_cgroups"]["monitor"], *oom["leaf_paths"]]))
    if len(monitor_paths) > 8:
        raise ValueError("monitor OOM scope exceeds eight unique cgroups")
    return {
        "monitor": {"FLEETDOCTOR_CGROUPS": ",".join(monitor_paths)},
        **node_changes,
    }


def preparation_changes(
    manifest: Mapping[str, Any], inventories: Mapping[str, dict[str, Any]]
) -> dict[str, dict[str, str]]:
    oom = manifest["resources"]["oom"]
    if set(inventories) != {"monitor", "node-a", "node-b"}:
        raise ValueError("selector inventories require monitor and both nodes")
    for role in ("monitor", "node-a", "node-b"):
        inventory = _bounded_inventory(inventories[role])
        actual_cgroups = inventory["selectors"]["FLEETDOCTOR_CGROUPS"]
        if actual_cgroups != oom["existing_cgroups"][role]:
            raise ValueError(f"{role} current cgroups differ from the frozen declaration")
        if role != "monitor" and (
            inventory["selectors"]["FLEETDOCTOR_CPU_PIDS"]
            != manifest["resources"]["fd"][role]["existing_cpu_pids"]
        ):
            raise ValueError(f"{role} current CPU PIDs differ from the frozen declaration")
    return declared_preparation_changes(manifest)


def preparation_token(manifest: Mapping[str, Any], role: str) -> str:
    return hashlib.sha256(
        f"{manifest['batch_id']}:runtime-preparation:{role}".encode()
    ).hexdigest()[:32]


def prepare_runtime(
    manifest: dict[str, Any], transports: Mapping[str, ControllerTransport]
) -> dict[str, Any]:
    if set(transports) != {"monitor", "node-a", "node-b"}:
        raise ValueError("runtime preparation requires monitor and both node controllers")
    inventories = {
        role: _bounded_inventory(
            transports[role].call(
                "config",
                "inventory",
                "0" * 32,
                {"scope": "monitor" if role == "monitor" else "agent"},
            )
        )
        for role in ("monitor", "node-a", "node-b")
    }
    changes = preparation_changes(manifest, inventories)
    transactions: dict[str, Any] = {}
    started: list[tuple[str, str, str, bool]] = []
    try:
        for role in ("monitor", "node-a", "node-b"):
            scope = "monitor" if role == "monitor" else "agent"
            token = preparation_token(manifest, role)
            began = transports[role].call(
                "config",
                "begin",
                token,
                {
                    "scope": scope,
                    "changes": changes[role],
                    "expected_before": _expected_before(inventories[role]),
                },
            )
            started.append((role, token, scope, False))
            active = transports[role].call("config", "handoff", token, {"scope": scope})
            started[-1] = (role, token, scope, True)
            transactions[role] = {
                "token": token,
                "scope": scope,
                "changes": changes[role],
                "inventory": inventories[role],
                "begin": began,
                "active": active,
            }
    except BaseException as primary:
        failures: list[str] = []
        for role, token, scope, handed_off in reversed(started):
            try:
                if handed_off:
                    transports[role].call("config", "adopt", token, {"scope": scope})
                transports[role].call("config", "restore", token, {"scope": scope})
            except BaseException as exc:
                failures.append(f"{role}: {type(exc).__name__}: {exc}")
        if failures:
            raise RuntimeError(
                f"runtime preparation failed ({type(primary).__name__}: {primary}); "
                "rollback failed: " + "; ".join(failures)
            ) from primary
        raise
    return {
        "schema_version": 2,
        "status": "prepared",
        "evidence_class": manifest["evidence_class"],
        "batch_id": manifest["batch_id"],
        "lab_sha256": digest(manifest["lab"]),
        "configuration_sha256": digest(manifest["configuration"]),
        "connection_receipt_sha256": manifest["connection_receipt_sha256"],
        "handshakes": {
            role: getattr(transports[role], "hello_receipt", None)
            for role in ("monitor", "node-a", "node-b")
        },
        "transactions": transactions,
        "prepared_at": datetime.now(UTC).isoformat(),
    }


def preparation_receipt_binds(manifest: Mapping[str, Any], receipt: Mapping[str, Any]) -> bool:
    try:
        transactions = receipt.get("transactions")
        if not isinstance(transactions, dict):
            return False
        inventories = {
            role: transactions.get(role, {}).get("inventory")
            for role in ("monitor", "node-a", "node-b")
        }
        expected_changes = preparation_changes(manifest, inventories)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    return bool(
        set(receipt)
        == {
            "schema_version",
            "status",
            "evidence_class",
            "batch_id",
            "lab_sha256",
            "configuration_sha256",
            "connection_receipt_sha256",
            "handshakes",
            "transactions",
            "prepared_at",
        }
        and receipt.get("schema_version") == 2
        and receipt.get("status") == "prepared"
        and receipt.get("evidence_class") == manifest["evidence_class"]
        and receipt.get("batch_id") == manifest["batch_id"]
        and receipt.get("lab_sha256") == digest(manifest["lab"])
        and receipt.get("configuration_sha256") == digest(manifest["configuration"])
        and receipt.get("connection_receipt_sha256") == manifest["connection_receipt_sha256"]
        and isinstance(receipt.get("handshakes"), dict)
        and set(receipt["handshakes"]) == {"monitor", "node-a", "node-b"}
        and all(isinstance(value, dict) for value in receipt["handshakes"].values())
        and digest(receipt) == manifest["preparation_receipt_sha256"]
        and isinstance(receipt.get("prepared_at"), str)
        and isinstance(receipt.get("transactions"), dict)
        and set(receipt["transactions"]) == {"monitor", "node-a", "node-b"}
        and all(
            isinstance(receipt["transactions"][role], dict)
            and receipt["transactions"][role].get("token") == preparation_token(manifest, role)
            and receipt["transactions"][role].get("scope")
            == ("monitor" if role == "monitor" else "agent")
            and receipt["transactions"][role].get("changes") == expected_changes[role]
            and receipt["transactions"][role].get("begin", {}).get("original_selectors")
            == _expected_before(receipt["transactions"][role]["inventory"])
            and receipt["transactions"][role].get("active", {}).get("phase") == "active"
            for role in ("monitor", "node-a", "node-b")
        )
    )


def restore_prepared_runtime(
    manifest: dict[str, Any],
    receipt: dict[str, Any],
    transports: Mapping[str, ControllerTransport],
) -> dict[str, Any]:
    if not preparation_receipt_binds(manifest, receipt):
        raise ValueError("preparation receipt does not bind the frozen manifest")
    restored: dict[str, Any] = {}
    failures: list[str] = []
    for role in ("node-b", "node-a", "monitor"):
        transaction = receipt["transactions"][role]
        try:
            observed = transports[role].call(
                "config", "lookup", transaction["token"], {"scope": transaction["scope"]}
            )
            state = _validate_cleanup_lookup(manifest, role, observed, transaction=transaction)
            if state == "absent":
                restored[role] = observed
                continue
            transports[role].call(
                "config", "adopt", transaction["token"], {"scope": transaction["scope"]}
            )
            restored[role] = transports[role].call(
                "config", "restore", transaction["token"], {"scope": transaction["scope"]}
            )
        except BaseException as exc:
            failures.append(f"{role}: {type(exc).__name__}: {exc}")
    return {
        "status": "passed" if not failures else "failed",
        "batch_id": manifest["batch_id"],
        "preparation_receipt_sha256": digest(receipt),
        "restored": restored,
        "failures": failures,
        "finished_at": datetime.now(UTC).isoformat(),
    }


def _selector_state(value: object, name: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"env_sha256", "selectors", "missing_keys"}
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("env_sha256", ""))) is None
        or not isinstance(value.get("selectors"), dict)
        or set(value["selectors"]) != {"FLEETDOCTOR_CGROUPS", "FLEETDOCTOR_CPU_PIDS"}
        or not all(isinstance(item, list) for item in value["selectors"].values())
        or not isinstance(value.get("missing_keys"), list)
    ):
        raise ValueError(f"cleanup {name} selector state is malformed")
    return cast(dict[str, Any], value)


def _validate_cleanup_lookup(
    manifest: Mapping[str, Any],
    role: str,
    observed: object,
    *,
    transaction: Mapping[str, Any] | None = None,
) -> str:
    token = preparation_token(manifest, role)
    if observed == {"token": token, "state": "absent"}:
        return "absent"
    required = {
        "token",
        "state",
        "phase",
        "original_sha256",
        "updated_sha256",
        "current_sha256",
        "changes",
        "original_selectors",
        "prepared_selectors",
        "service_state",
    }
    if (
        not isinstance(observed, dict)
        or set(observed) != required
        or observed.get("token") != token
        or observed.get("state") != "active"
        or observed.get("phase") != "active"
        or observed.get("changes") != declared_preparation_changes(manifest)[role]
        or observed.get("current_sha256") != observed.get("updated_sha256")
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(observed.get(field, ""))) is None
            for field in ("original_sha256", "updated_sha256", "current_sha256")
        )
    ):
        raise ValueError(f"{role} cleanup lookup does not prove the exact active owner")
    original = _selector_state(observed["original_selectors"], "original")
    prepared = _selector_state(observed["prepared_selectors"], "prepared")
    expected_original_cgroups = manifest["resources"]["oom"]["existing_cgroups"][role]
    if original["selectors"]["FLEETDOCTOR_CGROUPS"] != expected_original_cgroups:
        raise ValueError(f"{role} cleanup original cgroups differ from the frozen declaration")
    if role != "monitor" and (
        original["selectors"]["FLEETDOCTOR_CPU_PIDS"]
        != manifest["resources"]["fd"][role]["existing_cpu_pids"]
    ):
        raise ValueError(f"{role} cleanup original PIDs differ from the frozen declaration")
    expected_prepared = {key: list(items) for key, items in original["selectors"].items()}
    for key, value in cast(dict[str, str], observed["changes"]).items():
        expected_prepared[key] = (
            []
            if value == ""
            else (
                [int(item) for item in value.split(",")]
                if key.endswith("PIDS")
                else value.split(",")
            )
        )
    if prepared["selectors"] != expected_prepared:
        raise ValueError(f"{role} cleanup prepared selectors differ from the exact owner")
    if transaction is not None and (
        transaction.get("token") != token
        or transaction.get("scope") != ("monitor" if role == "monitor" else "agent")
        or transaction.get("changes") != observed["changes"]
        or transaction.get("begin", {}).get("original_selectors") != original
        or transaction.get("begin", {}).get("prepared_selectors") != prepared
    ):
        raise ValueError(f"{role} cleanup lookup differs from the preparation receipt")
    return "active"


def recover_owned_runtime(
    manifest: dict[str, Any], transports: Mapping[str, ControllerTransport]
) -> dict[str, Any]:
    recovered: dict[str, Any] = {}
    failures: list[str] = []
    for role in ("node-b", "node-a", "monitor"):
        token = preparation_token(manifest, role)
        scope = "monitor" if role == "monitor" else "agent"
        try:
            observed = transports[role].call("config", "lookup", token, {"scope": scope})
            state = _validate_cleanup_lookup(manifest, role, observed)
            if state == "absent":
                recovered[role] = observed
                continue
            transports[role].call("config", "adopt", token, {"scope": scope})
            recovered[role] = transports[role].call("config", "restore", token, {"scope": scope})
        except BaseException as exc:
            failures.append(f"{role}: {type(exc).__name__}: {exc}")
    return {
        "status": "passed" if not failures else "failed",
        "batch_id": manifest["batch_id"],
        "recovered": recovered,
        "failures": failures,
        "finished_at": datetime.now(UTC).isoformat(),
    }


def runtime_receipt_binds(
    manifest: dict[str, Any],
    runtime_receipt: dict[str, Any],
    transports: Mapping[str, Any] | None = None,
) -> bool:
    def stable_hello(value: object) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        required = {
            "type",
            "ok",
            "batch_id",
            "nonce",
            "session_id",
            "protected_manifest_sha256",
            "controller_bundle_sha256",
            "identity",
        }
        if (
            set(value) != required
            or value.get("type") != "hello"
            or value.get("ok") is not True
            or re.fullmatch(r"[0-9a-f]{64}", str(value.get("nonce", ""))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(value.get("session_id", ""))) is None
            or not isinstance(value.get("identity"), dict)
        ):
            return None
        return {
            "batch_id": value["batch_id"],
            "protected_manifest_sha256": value["protected_manifest_sha256"],
            "controller_bundle_sha256": value["controller_bundle_sha256"],
            "identity": value["identity"],
        }

    required = {
        "schema_version",
        "evidence_class",
        "checked_at",
        "source",
        "installed",
        "configuration",
        "lab",
        "raw_receipts",
        "preparation_receipt_sha256",
        "connection_receipt_sha256",
        "handshakes",
    }
    return bool(
        set(runtime_receipt) == required
        and runtime_receipt.get("schema_version") == 2
        and runtime_receipt.get("evidence_class") == "aws"
        and digest(runtime_receipt) == manifest["runtime_receipt_sha256"]
        and runtime_receipt.get("source") == manifest["source"]
        and runtime_receipt.get("installed") == manifest["installed"]
        and runtime_receipt.get("configuration") == manifest["configuration"]["collector"]
        and runtime_receipt.get("lab") == manifest["lab"]
        and runtime_receipt.get("preparation_receipt_sha256")
        == manifest["preparation_receipt_sha256"]
        and runtime_receipt.get("connection_receipt_sha256")
        == manifest["connection_receipt_sha256"]
        and isinstance(runtime_receipt.get("handshakes"), dict)
        and set(runtime_receipt["handshakes"]) == {"monitor", "node-a", "node-b"}
        and all(
            stable_hello(runtime_receipt["handshakes"][role]) is not None
            for role in ("monitor", "node-a", "node-b")
        )
        and (
            transports is None
            or all(
                stable_hello(runtime_receipt["handshakes"][role])
                == stable_hello(getattr(transports[role], "hello_receipt", None))
                for role in ("monitor", "node-a", "node-b")
            )
        )
        and isinstance(runtime_receipt.get("raw_receipts"), dict)
        and runtime_receipt["raw_receipts"]
        and all(
            re.fullmatch(r"[0-9a-f]{64}", str(value)) is not None
            for value in runtime_receipt["raw_receipts"].values()
        )
    )


def validate_attempts(
    manifest: dict[str, Any],
    attempts: list[dict[str, Any]],
    runtime_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expected_count = 40 if manifest["kind"] == "measured" else 16
    result: dict[str, Any] = {
        "status": "failed",
        "kind": manifest["kind"],
        "batch_id": manifest["batch_id"],
        "required_attempts": expected_count,
        "attempt_count": len(attempts),
        "scenarios": {},
        "failures": [],
    }
    expected = {
        (scenario, repetition, target)
        for scenario in SCENARIOS
        for repetition, target in enumerate(manifest["assignments"][scenario])
    }
    actual = {
        (item.get("scenario"), item.get("repetition"), item.get("target")) for item in attempts
    }
    if len(attempts) != expected_count or actual != expected or len(actual) != len(attempts):
        result["failures"].append("missing, duplicate or wrongly assigned attempts")
    common = {
        (
            item.get("batch_id"),
            item.get("source_sha256"),
            item.get("configuration_sha256"),
            item.get("lab_sha256"),
        )
        for item in attempts
    }
    if len(common) != 1 or common != {
        (
            manifest["batch_id"],
            digest(manifest["source"]),
            digest(manifest["configuration"]),
            digest(manifest["lab"]),
        )
    }:
        result["failures"].append("attempts mix batch/source/configuration/lab identities")
    for item in attempts:
        scenario = item.get("scenario")
        repetition = item.get("repetition")
        target = item.get("target")
        expected_reference = "node-b" if target == "node-a" else "node-a"
        expected_token = (
            attempt_token(manifest, str(scenario), int(repetition), str(target))
            if scenario in SCENARIOS
            and isinstance(repetition, int)
            and not isinstance(repetition, bool)
            and target in {"node-a", "node-b"}
            else None
        )
        if (
            item.get("schema_version") != 1
            or item.get("kind") != manifest["kind"]
            or item.get("reference") != expected_reference
            or item.get("token") != expected_token
            or item.get("evidence_class") != manifest["evidence_class"]
            or item.get("status") != "passed"
            or item.get("cleanup_complete") is not True
            or item.get("automatic_resolution") is not True
            or item.get("evidence_validated") is not True
            or item.get("unexpected_incidents") is not False
            or not item.get("incident_ids")
        ):
            result["failures"].append(
                f"{item.get('scenario')} repetition {item.get('repetition')} is incomplete/failed"
            )
        incident_ids = item.get("incident_ids")
        expected_phases = ["latency", "loss"] if scenario == "network" else [scenario]
        if (
            not isinstance(incident_ids, list)
            or len(incident_ids) != len(expected_phases)
            or len(incident_ids) != len(set(incident_ids))
            or any(not isinstance(identifier, str) or not identifier for identifier in incident_ids)
            or [phase.get("name") for phase in item.get("phases", []) if isinstance(phase, dict)]
            != expected_phases
        ):
            result["failures"].append(
                f"{scenario} repetition {repetition} has invalid phase/incident linkage"
            )
        if not raw_evidence_matches(item):
            result["failures"].append(
                f"{item.get('scenario')} repetition {item.get('repetition')} lacks linked raw evidence"
            )
    if len({incident for item in attempts for incident in item.get("incident_ids", [])}) != sum(
        len(item.get("incident_ids", [])) for item in attempts
    ):
        result["failures"].append("incident IDs are reused across attempts/phases")
    for scenario in SCENARIOS:
        rows = sorted(
            (item for item in attempts if item.get("scenario") == scenario),
            key=lambda item: int(item["repetition"]),
        )
        values: list[float] = []
        phase_values: dict[str, list[float]] = {}
        for row in rows:
            computed = []
            for phase in row.get("phases", []):
                if set(phase) != {
                    "name",
                    "injection_started_monotonic",
                    "injection_started_utc",
                    "trigger_monotonic",
                    "diagnosis_monotonic",
                    "cleanup_monotonic",
                    "resolution_monotonic",
                    "injection_to_diagnosis_seconds",
                    "trigger_to_diagnosis_seconds",
                    "cleanup_to_resolution_seconds",
                }:
                    result["failures"].append(
                        f"{scenario} repetition {row.get('repetition')} phase schema is invalid"
                    )
                    continue
                event_values = [
                    phase[field]
                    for field in (
                        "injection_started_monotonic",
                        "trigger_monotonic",
                        "diagnosis_monotonic",
                        "cleanup_monotonic",
                        "resolution_monotonic",
                    )
                ]
                if any(
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(float(value))
                    for value in event_values
                ):
                    result["failures"].append(
                        f"{scenario} repetition {row.get('repetition')} has nonfinite events"
                    )
                    continue
                injection, trigger, diagnosis, cleanup, resolution = map(float, event_values)
                timing = diagnosis - trigger
                recovery = resolution - cleanup
                injection_timing = diagnosis - injection
                try:
                    utc = datetime.fromisoformat(str(phase["injection_started_utc"]))
                except ValueError:
                    utc = None
                if (
                    not injection <= trigger <= diagnosis
                    or not cleanup <= resolution
                    or timing > 60
                    or recovery > 60
                    or injection_timing > 120
                    or utc is None
                    or utc.tzinfo is None
                ):
                    result["failures"].append(
                        f"{scenario} repetition {row.get('repetition')} has invalid timing"
                    )
                if (
                    not math.isclose(
                        timing,
                        float(phase.get("trigger_to_diagnosis_seconds", math.nan)),
                        abs_tol=1e-9,
                    )
                    or not math.isclose(
                        recovery,
                        float(phase.get("cleanup_to_resolution_seconds", math.nan)),
                        abs_tol=1e-9,
                    )
                    or not math.isclose(
                        injection_timing,
                        float(phase.get("injection_to_diagnosis_seconds", math.nan)),
                        abs_tol=1e-9,
                    )
                ):
                    result["failures"].append(
                        f"{scenario} repetition {row.get('repetition')} declares forged timing"
                    )
                computed.append(timing)
                phase_values.setdefault(str(phase["name"]), []).append(timing)
            if not computed:
                result["failures"].append(
                    f"{scenario} repetition {row.get('repetition')} has no phases"
                )
            else:
                values.append(max(computed))
        scenario_result: dict[str, Any] = {
            "all_values_seconds": values,
            "phase_values_seconds": phase_values,
        }
        if len(values) == len(manifest["assignments"][scenario]):
            scenario_result["median_seconds"] = statistics.median(values)
            scenario_result["median_strictly_under_30"] = scenario_result["median_seconds"] < 30
            if manifest["kind"] == "measured" and not scenario_result["median_strictly_under_30"]:
                result["failures"].append(f"{scenario} scenario median is not strictly below 30")
        if scenario == "network" and manifest["kind"] == "measured":
            for phase in ("latency", "loss"):
                readings = phase_values.get(phase, [])
                if len(readings) != 5 or statistics.median(readings) >= 30:
                    result["failures"].append(
                        f"network {phase} median is missing or not strictly below 30"
                    )
        result["scenarios"][scenario] = scenario_result
    result["failures"] = list(dict.fromkeys(result["failures"]))
    result["status"] = "passed" if not result["failures"] else "failed"
    result["measured_criteria_consistent"] = result["status"] == "passed"
    result["aws_acceptance"] = bool(
        result["status"] == "passed"
        and manifest["kind"] == "measured"
        and manifest["evidence_class"] == "aws"
        and attempts
        and all(item.get("evidence_class") == "aws" for item in attempts)
        and all(
            item.get("runtime_receipt_sha256") == manifest["runtime_receipt_sha256"]
            for item in attempts
        )
        and runtime_receipt is not None
        and runtime_receipt_binds(manifest, runtime_receipt)
    )
    return result


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Ticket15 chaos campaign report",
        "",
        f"Status: **{report['status']}**",
        f"Batch: `{report['batch_id']}` ({report['kind']})",
        "",
        "| Scenario | Five values (seconds) | Median | Result |",
        "| --- | --- | --- | --- |",
    ]
    for scenario in SCENARIOS:
        item = report["scenarios"].get(scenario, {})
        values = ", ".join(f"{value:.3f}" for value in item.get("all_values_seconds", []))
        median = item.get("median_seconds")
        passed = item.get("median_strictly_under_30")
        lines.append(
            f"| {scenario} | {values or 'unavailable'} | {median:.3f}"
            if isinstance(median, (int, float))
            else f"| {scenario} | {values or 'unavailable'} | unavailable"
        )
        lines[-1] += f" | {'PASS' if passed else 'FAIL/HOLD'} |"
    if report["failures"]:
        lines += ["", "## Failures", ""] + [f"- {item}" for item in report["failures"]]
    lines += [
        "",
        "Synthetic/local receipts never establish AWS acceptance; the manifest environment controls that claim.",
    ]
    return "\n".join(lines) + "\n"


def run_campaign(
    manifest: dict[str, Any],
    output_dir: Path,
    api: Backend,
    transports: Mapping[str, ControllerTransport],
    *,
    lease_root: Path = CAMPAIGN_LEASE_ROOT,
    runtime_receipt_sha256: str | None = None,
    clock_factory: Callable[[], Clock] = SystemClock,
) -> list[dict[str, Any]]:
    if set(transports) != {"monitor", "node-a", "node-b"}:
        raise ValueError("campaign requires monitor and both node controllers")
    if manifest["evidence_class"] == "aws" and (
        runtime_receipt_sha256 != manifest["runtime_receipt_sha256"]
    ):
        raise ValueError("AWS campaign lacks its verified live runtime receipt")
    expected_changes = declared_preparation_changes(manifest)
    for role in ("monitor", "node-a", "node-b"):
        scope = "monitor" if role == "monitor" else "agent"
        status = transports[role].call(
            "config", "status", preparation_token(manifest, role), {"scope": scope}
        )
        if status.get("phase") != "active" or status.get("changes") != expected_changes[role]:
            raise ValueError(f"{role} preprepared configuration is not exact and active")

    def clean_boundary() -> None:
        if api.get("/configuration") != manifest["configuration"]["collector"]:
            raise ValueError("collector configuration changed across campaign attempts")
        for node in ("node-a", "node-b"):
            view = api.get(f"/nodes/{node}/metrics")
            if not view.get("fresh") or view.get("active_incident_count") != 0:
                raise ValueError(f"{node} is not clean at an attempt boundary")
            role_receipt = getattr(transports[node], "role_receipt", None)
            expected_boot = role_receipt.get("boot_id") if isinstance(role_receipt, dict) else None
            raw_sample = view.get("sample")
            sample: dict[str, Any] = raw_sample if isinstance(raw_sample, dict) else {}
            if not expected_boot or sample.get("boot_id") != expected_boot:
                raise ValueError(f"{node} boot identity changed at an attempt boundary")

    phase_count = sum(
        2 if scenario == "network" else 1
        for scenario in SCENARIOS
        for _target in manifest["assignments"][scenario]
    )
    declared_seconds = phase_count * sum(manifest["deadlines"].values())
    if (
        phase_count != (45 if manifest["kind"] == "measured" else 18)
        or declared_seconds + CAMPAIGN_TEARDOWN_RESERVE_SECONDS > CONTROLLER_SESSION_SECONDS
        or phase_count * 32 + 64 > CONTROLLER_REQUEST_BUDGET
        or MONITOR_API_READ_BUDGET > MONITOR_CONTROLLER_REQUEST_BUDGET
    ):
        raise ValueError("declared campaign cannot fit the finite controller budget")
    output_dir.mkdir(parents=True, exist_ok=False)
    journal = output_dir / "journal.json"
    attempts: list[dict[str, Any]] = []
    state: dict[str, Any] = {
        "schema_version": 1,
        "batch_id": manifest["batch_id"],
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "attempts": [],
    }
    write_report(journal, state)
    lease_identity_sha256 = digest(stable_lab_identity(manifest["lab"]))
    lock = lab_lease_path(manifest["lab"], lease_root)
    with campaign_lock(lock, manifest["batch_id"], lease_identity_sha256):
        try:
            for scenario in SCENARIOS:
                for repetition, target in enumerate(manifest["assignments"][scenario]):
                    clean_boundary()
                    reference = "node-b" if target == "node-a" else "node-a"
                    attempt_id = f"{scenario}-{repetition + 1}-{target}"
                    token = attempt_token(manifest, scenario, repetition, target)
                    raw_path = output_dir / (attempt_id + "-raw.json")
                    state["attempts"].append(
                        {
                            "id": attempt_id,
                            "status": "running",
                            "started_at": datetime.now(UTC).isoformat(),
                        }
                    )
                    write_report(journal, state)
                    context = AdapterContext(
                        api,
                        transports[target],
                        manifest,
                        target,
                        reference,
                        repetition,
                        raw_path,
                        token,
                        clock=clock_factory(),
                        runtime_receipt_sha256=runtime_receipt_sha256,
                        transports=transports,
                    )
                    attempt = ADAPTERS[scenario].execute(context)
                    attempt_path = output_dir / (attempt_id + ".json")
                    write_report(attempt_path, attempt)
                    attempts.append(attempt)
                    clean_boundary()
                    state["attempts"][-1].update(
                        status="passed",
                        finished_at=datetime.now(UTC).isoformat(),
                        receipt=str(attempt_path),
                    )
                    write_report(journal, state)
        except BaseException as exc:
            state["status"] = "failed"
            state["failure"] = f"{type(exc).__name__}: {exc}"
            state["finished_at"] = datetime.now(UTC).isoformat()
            write_report(journal, state)
            raise
        state["status"] = "complete"
        state["finished_at"] = datetime.now(UTC).isoformat()
        write_report(journal, state)
    return attempts


def live_preflight(
    manifest: dict[str, Any],
    checkout: Path,
    api: Backend,
    runtime_receipt: dict[str, Any],
    transports: Mapping[str, ControllerTransport],
) -> dict[str, Any]:
    if set(transports) != {"monitor", "node-a", "node-b"} or not runtime_receipt_binds(
        manifest, runtime_receipt, transports
    ):
        raise ValueError("live runtime receipt does not bind the exact source/configuration/lab")
    checked_at = datetime.fromisoformat(str(runtime_receipt["checked_at"]))
    if checked_at.tzinfo is None:
        raise ValueError("live runtime receipt timestamp lacks a timezone")
    age = datetime.now(UTC) - checked_at
    if age.total_seconds() < -60 or age.total_seconds() > 600:
        raise ValueError("live runtime receipt is stale or future-dated")
    source = verify_source(checkout, manifest["source"])
    configuration = api.get("/configuration")
    if configuration != manifest["configuration"]["collector"]:
        raise ValueError("live collector configuration differs from the frozen manifest")
    health = api.get("/health")
    if health.get("status") != "ok":
        raise ValueError("collector health is unavailable")
    nodes: dict[str, Any] = {}
    for node in ("node-a", "node-b"):
        view = api.get(f"/nodes/{node}/metrics")
        if not view.get("fresh") or view.get("active_incident_count") != 0:
            raise ValueError(f"{node} is stale or has an unexpected active incident")
        role_receipt = getattr(transports[node], "role_receipt", None)
        expected_boot = role_receipt.get("boot_id") if isinstance(role_receipt, dict) else None
        raw_sample = view.get("sample")
        sample = raw_sample if isinstance(raw_sample, dict) else {}
        if sample.get("boot_id") != expected_boot:
            raise ValueError(f"{node} metric boot identity differs from its verified session")
        nodes[node] = {
            "identity": _identity(view),
            "active_incident_count": view.get("active_incident_count"),
        }
    return {
        "status": "passed",
        "batch_id": manifest["batch_id"],
        "source": source,
        "configuration_sha256": digest(configuration),
        "health": health,
        "nodes": nodes,
        "checked_at": datetime.now(UTC).isoformat(),
        "runtime_receipt_sha256": digest(runtime_receipt),
    }


@contextmanager
def verified_transports(
    manifest: dict[str, Any],
    connection: dict[str, Any],
    key: Path,
    *,
    purpose: ConnectionPurpose = "new-work",
) -> Iterator[dict[str, PersistentSshTransport]]:
    validate_connection_receipt(manifest, connection, purpose=purpose)
    with ExitStack() as stack:
        transports = {
            role: stack.enter_context(
                PersistentSshTransport(
                    role,
                    connection["roles"][role],
                    key,
                    manifest["batch_id"],
                    purpose=purpose,
                    cleanup_token=(
                        preparation_token(manifest, role) if purpose == "cleanup" else None
                    ),
                )
            )
            for role in ("monitor", "node-a", "node-b")
        }
        yield transports


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--manifest", type=Path, required=True)
    validate_parser.add_argument("--connection-receipt", type=Path, required=True)
    freeze_parser = subparsers.add_parser("freeze-source")
    freeze_parser.add_argument("--checkout", type=Path, required=True)
    freeze_parser.add_argument("--output", type=Path, required=True)
    dry_parser = subparsers.add_parser("dry")
    dry_parser.add_argument("--manifest", type=Path, required=True)
    dry_parser.add_argument("--connection-receipt", type=Path, required=True)
    dry_parser.add_argument("--checkout", type=Path, required=True)
    dry_parser.add_argument("--output", type=Path, required=True)
    preflight_parser = subparsers.add_parser("preflight")
    preflight_parser.add_argument("--manifest", type=Path, required=True)
    preflight_parser.add_argument("--checkout", type=Path, required=True)
    preflight_parser.add_argument("--connection-receipt", type=Path, required=True)
    preflight_parser.add_argument("--key", type=Path, required=True)
    preflight_parser.add_argument("--runtime-receipt", type=Path, required=True)
    preflight_parser.add_argument("--output", type=Path, required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--manifest", type=Path, required=True)
    run_parser.add_argument("--checkout", type=Path, required=True)
    run_parser.add_argument("--connection-receipt", type=Path, required=True)
    run_parser.add_argument("--runtime-receipt", type=Path, required=True)
    run_parser.add_argument("--key", type=Path, required=True)
    run_parser.add_argument("--output-dir", type=Path, required=True)
    prepare_parser = subparsers.add_parser("prepare-runtime")
    prepare_parser.add_argument("--manifest", type=Path, required=True)
    prepare_parser.add_argument("--connection-receipt", type=Path, required=True)
    prepare_parser.add_argument("--key", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    restore_parser = subparsers.add_parser("restore-runtime")
    restore_parser.add_argument("--manifest", type=Path, required=True)
    restore_parser.add_argument("--preparation-receipt", type=Path, required=True)
    restore_parser.add_argument("--connection-receipt", type=Path, required=True)
    restore_parser.add_argument("--key", type=Path, required=True)
    restore_parser.add_argument("--output", type=Path, required=True)
    recover_parser = subparsers.add_parser("recover")
    recover_parser.add_argument("--manifest", type=Path, required=True)
    recover_parser.add_argument("--connection-receipt", type=Path, required=True)
    recover_parser.add_argument("--key", type=Path, required=True)
    recover_parser.add_argument("--output", type=Path, required=True)
    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--manifest", type=Path, required=True)
    report_parser.add_argument("--attempt", type=Path, action="append", default=[])
    report_parser.add_argument("--runtime-receipt", type=Path)
    report_parser.add_argument("--output-json", type=Path, required=True)
    report_parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "freeze-source":
        output = external_path(args.output, args.checkout)
        if output.exists():
            raise FileExistsError("refusing to overwrite frozen source manifest")
        write_report(output, collect_source(args.checkout))
        return
    if args.action == "recover":
        if args.output.exists():
            raise FileExistsError("refusing to overwrite recovery receipt")
        manifest = validate_manifest(load_json(args.manifest))
        connection = validate_connection_receipt(
            manifest, load_json(args.connection_receipt), purpose="cleanup"
        )
        lab_sha256 = digest(manifest["lab"])
        lease_identity_sha256 = digest(stable_lab_identity(manifest["lab"]))
        receipt: dict[str, Any] = {
            "status": "running",
            "batch_id": manifest["batch_id"],
            "lab_sha256": lab_sha256,
            "nodes": {},
        }
        try:
            with verified_transports(
                manifest, connection, args.key, purpose="cleanup"
            ) as transports:
                receipt["handshakes"] = {
                    role: transport.hello_receipt for role, transport in transports.items()
                }
                receipt["local_campaign_lease"] = recover_campaign_lock(
                    lab_lease_path(manifest["lab"]), lease_identity_sha256
                )
                recovery = recover_owned_runtime(manifest, transports)
                receipt["nodes"] = recovery["recovered"]
                receipt["failures"] = recovery["failures"]
            receipt["status"] = recovery["status"]
        except BaseException as exc:
            receipt.update(status="failed", failure=f"{type(exc).__name__}: {exc}")
            raise
        finally:
            receipt["finished_at"] = datetime.now(UTC).isoformat()
            write_report(args.output, receipt)
        if receipt["status"] == "failed":
            raise SystemExit(1)
        return
    manifest = validate_manifest(load_json(args.manifest))
    if args.action in {"validate", "dry"}:
        validate_connection_receipt(manifest, load_json(args.connection_receipt))
    if args.action in {"prepare-runtime", "restore-runtime"}:
        if args.output.exists():
            raise FileExistsError("refusing to overwrite runtime transaction receipt")
        purpose: ConnectionPurpose = "cleanup" if args.action == "restore-runtime" else "new-work"
        connection = validate_connection_receipt(
            manifest, load_json(args.connection_receipt), purpose=purpose
        )
        with verified_transports(manifest, connection, args.key, purpose=purpose) as transports:
            if args.action == "prepare-runtime":
                receipt = prepare_runtime(manifest, transports)
            else:
                receipt = restore_prepared_runtime(
                    manifest, load_json(args.preparation_receipt), transports
                )
        write_report(args.output, receipt)
        if receipt.get("status") == "failed":
            raise SystemExit(1)
        return
    if args.action == "validate":
        print(json.dumps({"status": "valid", "batch_id": manifest["batch_id"]}, sort_keys=True))
        return
    if args.action == "dry":
        output = external_path(args.output, args.checkout)
        if output.exists():
            raise FileExistsError("refusing to overwrite dry receipt")
        source = verify_source(args.checkout, manifest["source"])
        write_report(
            output,
            {
                "status": "passed",
                "mode": "dry",
                "batch_id": manifest["batch_id"],
                "source": source,
                "ordered_attempts": [
                    {"scenario": scenario, "repetition": index, "target": target}
                    for scenario in SCENARIOS
                    for index, target in enumerate(manifest["assignments"][scenario])
                ],
                "aws_or_ssh_execution": False,
            },
        )
        return
    if args.action == "preflight":
        output = external_path(args.output, args.checkout)
        if output.exists():
            raise FileExistsError("refusing to overwrite preflight receipt")
        connection = validate_connection_receipt(manifest, load_json(args.connection_receipt))
        runtime_receipt = load_json(args.runtime_receipt)
        with verified_transports(manifest, connection, args.key) as transports:
            receipt = live_preflight(
                manifest,
                args.checkout,
                MonitorBackend(transports["monitor"]),
                runtime_receipt,
                transports,
            )
        write_report(output, receipt)
        return
    if args.action == "run":
        output_dir = external_path(args.output_dir, args.checkout)
        connection = validate_connection_receipt(manifest, load_json(args.connection_receipt))
        runtime_receipt = load_json(args.runtime_receipt)
        with verified_transports(manifest, connection, args.key) as transports:
            api = MonitorBackend(transports["monitor"])
            preflight = live_preflight(manifest, args.checkout, api, runtime_receipt, transports)
            completed = run_campaign(
                manifest,
                output_dir,
                api,
                transports,
                runtime_receipt_sha256=digest(runtime_receipt),
            )
        verify_source(args.checkout, manifest["source"])
        report = validate_attempts(manifest, completed, runtime_receipt)
        write_report(output_dir / "preflight.json", preflight)
        write_report(output_dir / "report.json", report)
        (output_dir / "report.md").write_text(markdown_report(report), encoding="utf-8")
        if report["status"] != "passed":
            raise SystemExit(1)
        return
    if args.output_json.exists() or args.output_md.exists():
        raise FileExistsError("refusing to overwrite campaign report")
    attempts = [load_json(path) for path in args.attempt]
    report_runtime_receipt = load_json(args.runtime_receipt) if args.runtime_receipt else None
    report = validate_attempts(manifest, attempts, report_runtime_receipt)
    write_report(args.output_json, report)
    args.output_md.write_text(markdown_report(report), encoding="utf-8")
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
