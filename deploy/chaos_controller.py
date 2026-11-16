#!/usr/bin/env python3
"""Persistent root controller for an allowlisted FleetDoctor chaos campaign."""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import ipaddress
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, cast
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_API_RESPONSE_BYTES = 512 * 1024
MAX_REQUESTS = 4096
MAX_MONITOR_REQUESTS = 200000
MAX_SESSION_SECONDS = 6 * 60 * 60
MAX_CONFIG_TRANSACTIONS = 8
MAX_JOURNAL_FILES = 128
MAX_JOURNAL_BYTES = 16 * 1024 * 1024
TERMINAL_CLEANUP_RESERVE_SECONDS = (MAX_CONFIG_TRANSACTIONS + 2) * 150
PROTECTED_SOURCE = Path("/opt/fleetdoctor/current")
PROTECTED_MANIFEST = Path("/etc/fleetdoctor/chaos-controller.json")
RECEIPT_DIRECTORY = Path("/var/lib/fleetdoctor/chaos-controller")
TOKEN = re.compile(r"^[0-9a-f]{32}$")
REQUEST_FIELDS = {"id", "scenario", "action", "token", "arguments"}
AUTHENTICATED_REQUEST_FIELDS = REQUEST_FIELDS | {"batch_id", "session_id"}
HELLO_FIELDS = {"type", "batch_id", "nonce"}
HELPERS = {
    "disk": "deploy/disk_resource.py",
    "inode": "deploy/inode_resource.py",
    "fd": "deploy/fd_resource.py",
    "oom": "deploy/memory_resource.py",
    "cpu": "deploy/cpu_resource.py",
    "network": "deploy/network_resource.py",
    "dns": "deploy/dns_resource.py",
    "io": "deploy/io_resource.py",
    "config": "deploy/config_transaction.py",
}
ACTIONS = {
    "disk": {"probe", "start", "status", "cleanup"},
    "inode": {"probe", "start", "status", "cleanup"},
    "fd": {"start", "status", "pressure", "release", "cleanup"},
    "oom": {"prepare", "start", "status", "stop", "release"},
    "cpu": {"start", "status", "cleanup"},
    "network": {"start", "status", "cleanup"},
    "dns": {"start", "status", "cleanup"},
    "io": {"prepare", "start", "status", "cleanup", "destroy"},
    "config": {
        "inventory",
        "begin",
        "lookup",
        "status",
        "adopt",
        "handoff",
        "restore",
        "recover",
    },
}
CLEANUP = {
    "disk": ("cleanup",),
    "inode": ("cleanup",),
    "fd": ("cleanup",),
    "oom": ("stop", "release"),
    "cpu": ("cleanup",),
    "network": ("cleanup",),
    "dns": ("cleanup",),
    "io": ("cleanup", "destroy"),
}
TERMINAL_ACTION = {
    "disk": "cleanup",
    "inode": "cleanup",
    "fd": "cleanup",
    "oom": "release",
    "cpu": "cleanup",
    "network": "cleanup",
    "dns": "cleanup",
    "io": "destroy",
}


def _integer(value: object, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def _string(value: object, name: str, *, pattern: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or len(value) > maximum or re.fullmatch(pattern, value) is None:
        raise ValueError(f"invalid {name}")
    return value


def request_argv(source_root: Path, request: dict[str, Any]) -> tuple[list[str], bool]:
    if set(request) != REQUEST_FIELDS:
        raise ValueError("request fields do not match the controller protocol")
    _string(request["id"], "request id", pattern=r"[A-Za-z0-9_.:-]{1,64}")
    scenario = _string(request["scenario"], "scenario", pattern=r"[a-z]+", maximum=16)
    action = _string(request["action"], "action", pattern=r"[a-z]+", maximum=16)
    token = _string(request["token"], "token", pattern=TOKEN.pattern, maximum=32)
    arguments = request["arguments"]
    if scenario not in HELPERS or action not in ACTIONS[scenario]:
        raise ValueError("scenario/action is not allowlisted")
    if not isinstance(arguments, dict) or any(not isinstance(key, str) for key in arguments):
        raise ValueError("arguments must be an object")
    helper = source_root / HELPERS[scenario]
    helper_action = "status" if scenario == "config" and action in {"adopt", "handoff"} else action
    argv = [sys.executable, os.fspath(helper), helper_action]
    if scenario == "io":
        argv.append(token)
    elif scenario == "config":
        if action not in {"recover", "inventory"}:
            argv += ["--token", token]
    else:
        argv += ["--token", token]
    allowed: set[str] = set()
    if scenario in {"disk", "inode"}:
        allowed = {"duration"} if action == "start" else set()
        if "duration" in arguments:
            argv += ["--duration", str(_integer(arguments["duration"], "duration", 2, 240))]
    elif scenario == "fd":
        allowed = (
            {"limit", "seconds", "worker_user", "watchdog_seconds"} if action == "start" else set()
        )
        if action == "start":
            argv += ["--limit", str(_integer(arguments.get("limit", 128), "limit", 32, 4096))]
            argv += ["--seconds", str(_integer(arguments.get("seconds", 180), "seconds", 15, 180))]
            user = _string(
                arguments.get("worker_user", "fleetdoctor"),
                "worker user",
                pattern=r"[a-z_][a-z0-9_-]{0,31}",
                maximum=32,
            )
            argv += ["--worker-user", user]
            if "watchdog_seconds" in arguments:
                argv += [
                    "--watchdog-seconds",
                    str(_integer(arguments["watchdog_seconds"], "watchdog seconds", 15, 240)),
                ]
    elif scenario == "oom":
        if action == "prepare":
            allowed = {"lease_seconds"}
            argv += [
                "--lease-seconds",
                str(_integer(arguments.get("lease_seconds", 360), "lease seconds", 120, 360)),
            ]
        elif action == "start":
            allowed = {"allocation_bytes", "limit_bytes", "seconds", "worker_user"}
            allocation = _integer(
                arguments.get("allocation_bytes", 96 * 1024 * 1024),
                "allocation bytes",
                32 * 1024 * 1024,
                512 * 1024 * 1024,
            )
            limit = _integer(
                arguments.get("limit_bytes", 48 * 1024 * 1024),
                "limit bytes",
                32 * 1024 * 1024,
                64 * 1024 * 1024,
            )
            if allocation <= limit:
                raise ValueError("OOM allocation must exceed its finite limit")
            seconds = _integer(arguments.get("seconds", 180), "seconds", 15, 180)
            user = _string(
                arguments.get("worker_user", "fleetdoctor"),
                "worker user",
                pattern=r"[a-z_][a-z0-9_-]{0,31}",
                maximum=32,
            )
            argv += [
                "--allocation-bytes",
                str(allocation),
                "--limit-bytes",
                str(limit),
                "--seconds",
                str(seconds),
                "--worker-user",
                user,
            ]
    elif scenario == "cpu":
        allowed = {"workers", "seconds", "worker_user"} if action == "start" else set()
        if action == "start":
            argv += [
                "--workers",
                str(_integer(arguments["workers"], "workers", 1, 64)),
                "--seconds",
                str(_integer(arguments.get("seconds", 180), "seconds", 15, 180)),
                "--worker-user",
                _string(
                    arguments.get("worker_user", "fleetdoctor"),
                    "worker user",
                    pattern=r"[a-z_][a-z0-9_-]{0,31}",
                    maximum=32,
                ),
            ]
    elif scenario == "network":
        allowed = {"target", "profile", "duration"} if action == "start" else set()
        if action == "start":
            target = _string(arguments["target"], "network target", pattern=r"[0-9A-Fa-f:.]{2,64}")
            profile = arguments.get("profile", "latency")
            if profile not in {"latency", "loss"}:
                raise ValueError("network profile must be latency or loss")
            argv += [
                "--target",
                target,
                "--profile",
                profile,
                "--duration",
                str(_integer(arguments.get("duration", 180), "duration", 15, 180)),
            ]
    elif scenario == "dns":
        allowed = {"invalid_resolver", "duration"} if action == "start" else set()
        if action == "start":
            argv += [
                "--invalid-resolver",
                _string(
                    arguments.get("invalid_resolver", "203.0.113.254"),
                    "invalid resolver",
                    pattern=r"[0-9A-Fa-f:.]{2,64}",
                ),
                "--duration",
                str(_integer(arguments.get("duration", 180), "duration", 15, 180)),
            ]
    elif scenario == "io":
        allowed = {"duration"} if action == "start" else set()
        if action == "start":
            argv += [
                "--duration",
                str(_integer(arguments.get("duration", 120), "duration", 1, 120)),
            ]
    else:
        allowed = (
            {"changes", "scope", "parent_token", "expected_before"}
            if action == "begin"
            else {"scope"}
        )
        scope = arguments.get("scope", "agent")
        if scope not in {"agent", "monitor"}:
            raise ValueError("configuration scope must be agent or monitor")
        argv += ["--scope", scope]
        if action == "begin":
            changes = arguments.get("changes")
            if not isinstance(changes, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in changes.items()
            ):
                raise ValueError("configuration changes must be a string map")
            argv += [
                "--changes-json",
                json.dumps(changes, sort_keys=True, separators=(",", ":")),
                "--expected-before-json",
                json.dumps(arguments.get("expected_before"), sort_keys=True, separators=(",", ":")),
            ]
            expected_before = arguments.get("expected_before")
            if not isinstance(expected_before, dict) or set(expected_before) != {
                "env_sha256",
                "selectors",
                "missing_keys",
            }:
                raise ValueError("configuration expected-before snapshot is required")
            if "parent_token" in arguments:
                parent = _string(
                    arguments["parent_token"],
                    "parent configuration token",
                    pattern=TOKEN.pattern,
                    maximum=32,
                )
                argv += ["--parent-token", parent]
    unknown = set(arguments) - allowed
    if unknown:
        raise ValueError("non-allowlisted arguments: " + ",".join(sorted(unknown)))
    activates = action in {"start", "prepare", "begin", "adopt"}
    return argv, activates


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def validate_protected_path(path: Path, *, directory: bool, uid: int = 0) -> None:
    current = path
    chain = [current]
    while current != current.parent and current not in {
        Path("/"),
        Path("/opt"),
        Path("/etc"),
        Path("/var"),
    }:
        current = current.parent
        chain.append(current)
    for item in reversed(chain):
        info = item.lstat()
        expected = (
            stat.S_ISDIR(info.st_mode) if item != path or directory else stat.S_ISREG(info.st_mode)
        )
        if not expected or stat.S_ISLNK(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            raise ValueError(f"unprotected root runtime path: {item}")


def validate_source(source_root: Path, manifest_path: Path) -> dict[str, Any]:
    validate_protected_path(source_root, directory=True)
    validate_protected_path(manifest_path, directory=False)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if set(manifest) != {
        "schema_version",
        "batch_id",
        "role",
        "plan_sha256",
        "original_plan_sha256",
        "account_id",
        "region",
        "availability_zone",
        "instance_id",
        "private_ip",
        "source_root",
        "controller_sha256",
        "wrapper_sha256",
        "controller_bundle_sha256",
        "helpers",
    }:
        raise ValueError("controller manifest fields are invalid")
    if (
        manifest["schema_version"] != 2
        or Path(manifest["source_root"]) != source_root
        or manifest["role"] not in {"monitor", "node-a", "node-b"}
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", str(manifest["batch_id"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(manifest["plan_sha256"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(manifest["original_plan_sha256"])) is None
        or re.fullmatch(r"[0-9]{12}", str(manifest["account_id"])) is None
        or manifest["region"] != "us-east-1"
        or not isinstance(manifest["availability_zone"], str)
        or re.fullmatch(r"i-[0-9a-f]{8,17}", str(manifest["instance_id"])) is None
        or re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", str(manifest["private_ip"])) is None
    ):
        raise ValueError("controller manifest source root mismatch")
    controller = source_root / "deploy/chaos_controller.py"
    wrapper = source_root / "deploy/fleetdoctor-chaos-controller.sh"
    validate_protected_path(source_root / "deploy", directory=True)
    validate_protected_path(controller, directory=False)
    validate_protected_path(wrapper, directory=False)
    if (
        not controller.is_file()
        or _sha256(controller) != manifest["controller_sha256"]
        or _sha256(Path(__file__)) != manifest["controller_sha256"]
    ):
        raise ValueError("running controller differs from the frozen protected controller")
    if not wrapper.is_file() or _sha256(wrapper) != manifest["wrapper_sha256"]:
        raise ValueError("protected controller wrapper differs from the frozen manifest")
    helpers = manifest["helpers"]
    if not isinstance(helpers, dict) or set(helpers) != set(HELPERS):
        raise ValueError("controller manifest helper set mismatch")
    for scenario, relative in HELPERS.items():
        path = source_root / relative
        validate_protected_path(path.parent, directory=True)
        validate_protected_path(path, directory=False)
        if not path.is_file() or _sha256(path) != helpers[scenario]:
            raise ValueError(f"frozen helper mismatch: {scenario}")
    bundle = {
        "controller": manifest["controller_sha256"],
        "wrapper": manifest["wrapper_sha256"],
        "helpers": {key: helpers[key] for key in sorted(helpers)},
    }
    if manifest["controller_bundle_sha256"] != _digest(bundle):
        raise ValueError("protected controller bundle digest is invalid")
    return cast(dict[str, Any], manifest)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _bounded_http_read(
    opener: Any,
    request: Request,
    *,
    socket_timeout: float,
    operation_timeout: float,
    limit: int,
) -> tuple[int, str, bytes]:
    """Bound connect, headers, and a drip-fed body by one controller-clock deadline."""
    if not hasattr(signal, "SIGALRM") or not hasattr(signal, "setitimer"):
        raise RuntimeError("bounded controller HTTP requires POSIX interval timers")

    def expired(signum: int, frame: object) -> None:
        raise TimeoutError("HTTP operation exceeded its total wall-clock deadline")

    previous_handler = signal.getsignal(signal.SIGALRM)
    response: Any | None = None
    signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, operation_timeout)
    try:
        try:
            response = opener.open(request, timeout=socket_timeout)
        except HTTPError as exc:
            response = exc
        return (
            int(cast(Any, response).status),
            response.headers.get_content_type(),
            response.read(limit + 1),
        )
    finally:
        if response is not None:
            try:
                response.close()
            except OSError:
                pass
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


def _metadata_identity() -> dict[str, Any]:
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    token_request = Request(
        "http://169.254.169.254/latest/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
    )
    status, _content_type, token = _bounded_http_read(
        opener, token_request, socket_timeout=2, operation_timeout=3, limit=4096
    )
    if status != 200:
        raise RuntimeError("IMDSv2 token request failed")
    if not token or len(token) > 4096:
        raise ValueError("IMDSv2 token response is invalid")
    document_request = Request(
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        headers={"X-aws-ec2-metadata-token": token.decode("ascii")},
    )
    status, _content_type, raw = _bounded_http_read(
        opener, document_request, socket_timeout=2, operation_timeout=3, limit=16384
    )
    if status != 200:
        raise RuntimeError("instance identity document request failed")
    if len(raw) > 16384:
        raise ValueError("instance identity document exceeds bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("instance identity document is invalid")
    return cast(dict[str, Any], value)


def _host_key_identity(path: Path = Path("/etc/ssh/ssh_host_ed25519_key.pub")) -> dict[str, str]:
    validate_protected_path(path, directory=False)
    pieces = path.read_text(encoding="ascii").strip().split()
    if len(pieces) < 2 or pieces[0] != "ssh-ed25519":
        raise ValueError("host key must be a plain ED25519 public key")
    decoded = base64.b64decode(pieces[1], validate=True)
    fingerprint = base64.b64encode(hashlib.sha256(decoded).digest()).decode().rstrip("=")
    return {
        "host_public_key": f"ssh-ed25519 {pieces[1]}",
        "host_key_fingerprint": "SHA256:" + fingerprint,
    }


def attest_runtime_identity(
    manifest: Mapping[str, Any],
    *,
    metadata_provider: Callable[[], dict[str, Any]] = _metadata_identity,
    boot_path: Path = Path("/proc/sys/kernel/random/boot_id"),
    host_key_provider: Callable[[], dict[str, str]] = _host_key_identity,
) -> dict[str, Any]:
    document = metadata_provider()
    expected = {
        "accountId": manifest["account_id"],
        "region": manifest["region"],
        "availabilityZone": manifest["availability_zone"],
        "instanceId": manifest["instance_id"],
        "privateIp": manifest["private_ip"],
    }
    if any(document.get(key) != value for key, value in expected.items()):
        raise ValueError("actual instance identity differs from the protected manifest")
    boot_id = boot_path.read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-fA-F-]{36}", boot_id) is None:
        raise ValueError("kernel boot identity is invalid")
    key = host_key_provider()
    return {
        "role": manifest["role"],
        "account_id": manifest["account_id"],
        "region": manifest["region"],
        "availability_zone": manifest["availability_zone"],
        "instance_id": manifest["instance_id"],
        "private_ip": manifest["private_ip"],
        "boot_id": boot_id,
        **key,
    }


def _validate_api_request(path: object, params: object) -> tuple[str, dict[str, str]]:
    if not isinstance(path, str) or len(path) > 256 or "?" in path or "#" in path:
        raise ValueError("API relay path is invalid")
    allowed = (
        path in {"/health", "/configuration", "/nodes", "/diagnoses"}
        or re.fullmatch(r"/nodes/(?:node-a|node-b)/metrics", path) is not None
        or re.fullmatch(r"/diagnoses/[A-Za-z0-9_.:-]{1,128}", path) is not None
    )
    if not allowed:
        raise ValueError("API relay path is not allowlisted")
    if not isinstance(params, dict) or any(
        not isinstance(key, str) or not isinstance(value, (str, int)) or isinstance(value, bool)
        for key, value in params.items()
    ):
        raise ValueError("API relay query is invalid")
    if set(params) - {"node", "rule", "status", "limit"}:
        raise ValueError("API relay query key is not allowlisted")
    normalized = {key: str(value) for key, value in params.items()}
    if any(len(key) > 32 or len(value) > 128 for key, value in normalized.items()):
        raise ValueError("API relay query exceeds bound")
    if "limit" in normalized and (
        not normalized["limit"].isdigit() or not 1 <= int(normalized["limit"]) <= 100
    ):
        raise ValueError("API relay limit is invalid")
    return path, normalized


def api_get(
    manifest: Mapping[str, Any],
    path: object,
    params: object,
    *,
    opener: Any | None = None,
) -> dict[str, Any]:
    if manifest["role"] != "monitor":
        raise PermissionError("only the verified monitor may relay collector observations")
    path, query = _validate_api_request(path, params)
    address = str(ipaddress.ip_address(str(manifest["private_ip"])))
    url = f"http://{address}:8000{path}" + ("?" + urlencode(query) if query else "")
    client = opener or build_opener(ProxyHandler({}), _NoRedirect())
    request = Request(url, method="GET", headers={"Accept": "application/json"})
    status, content_type, raw = _bounded_http_read(
        client,
        request,
        socket_timeout=3,
        operation_timeout=4,
        limit=MAX_API_RESPONSE_BYTES,
    )
    if len(raw) > MAX_API_RESPONSE_BYTES:
        raise ValueError("API relay response exceeds bound")
    if content_type != "application/json":
        raise ValueError("API relay response is not JSON")
    body = json.loads(raw)
    if not isinstance(body, dict):
        raise ValueError("API relay response body must be an object")
    return {"status_code": status, "body": body}


def _atomic_receipt(path: Path, value: dict[str, Any]) -> None:
    encoded = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    temporary = path.with_name(path.name + ".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("short controller receipt write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class NodeLease:
    """Kernel-released node-wide exclusion for every persistent campaign controller."""

    def __init__(self, directory: Path = RECEIPT_DIRECTORY, *, uid: int = 0) -> None:
        if sys.platform != "linux":
            raise RuntimeError("node controller lease requires Linux")
        import fcntl

        validate_protected_path(directory, directory=True, uid=uid)
        self.path = directory / "node-controller.lock"
        self.descriptor = os.open(
            self.path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            info = os.fstat(self.descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
                raise ValueError("unprotected node controller lease")
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owner = (
                json.dumps(
                    {
                        "schema_version": 1,
                        "pid": os.getpid(),
                        "started_at": datetime.now(UTC).isoformat(),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
            os.ftruncate(self.descriptor, 0)
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            offset = 0
            while offset < len(owner):
                written = os.write(self.descriptor, owner[offset:])
                if written <= 0:
                    raise OSError("short node lease write")
                offset += written
            os.fsync(self.descriptor)
        except BaseException:
            os.close(self.descriptor)
            raise

    def close(self) -> None:
        if self.descriptor < 0:
            return
        import fcntl

        fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        os.close(self.descriptor)
        self.descriptor = -1


class ControllerJournal:
    def __init__(
        self,
        directory: Path = RECEIPT_DIRECTORY,
        *,
        batch_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        validate_protected_path(directory, directory=True)
        self.lease = NodeLease(directory)
        try:
            previous = list(directory.glob("session-*.json"))
            if len(previous) >= MAX_JOURNAL_FILES:
                raise RuntimeError("controller journal limit requires verified evidence archival")
            required = {"schema_version", "pid", "started_at", "active", "events", "status"}
            for path in previous:
                validate_protected_path(path, directory=False)
                if path.stat().st_size > MAX_JOURNAL_BYTES:
                    raise ValueError("controller journal exceeds its retained size bound")
                prior = json.loads(path.read_text(encoding="utf-8"))
                if (
                    not isinstance(prior, dict)
                    or not required.issubset(prior)
                    or set(prior) - required - {"finished_at", "batch_id", "session_id"}
                    or prior["schema_version"] not in {1, 2}
                    or not isinstance(prior["pid"], int)
                    or isinstance(prior["pid"], bool)
                    or prior["pid"] <= 0
                    or not isinstance(prior["started_at"], str)
                    or not isinstance(prior["events"], list)
                    or not isinstance(prior["status"], str)
                    or prior["status"] not in {"running", "completed", "failed", "cleanup_failed"}
                ):
                    raise ValueError("prior controller journal is malformed")
                if prior["schema_version"] == 2 and (
                    not isinstance(prior.get("batch_id"), str)
                    or not isinstance(prior.get("session_id"), str)
                ):
                    raise ValueError("prior authenticated controller journal is malformed")
                if prior["active"] is not None:
                    raise RuntimeError(
                        "unresolved controller ownership requires exact cleanup proof "
                        "and verified journal archival before another session"
                    )
            self.path = directory / f"session-{os.getpid()}.json"
            if self.path.exists():
                raise FileExistsError("controller session receipt already exists")
            self.value: dict[str, Any] = {
                "schema_version": 2 if batch_id is not None and session_id is not None else 1,
                "pid": os.getpid(),
                "started_at": datetime.now(UTC).isoformat(),
                "active": None,
                "events": [],
                "status": "running",
            }
            if batch_id is not None and session_id is not None:
                self.value.update(batch_id=batch_id, session_id=session_id)
            _atomic_receipt(self.path, self.value)
        except BaseException:
            self.lease.close()
            raise

    def record(self, event: str, **facts: Any) -> None:
        self.value["events"].append({"event": event, "at": datetime.now(UTC).isoformat(), **facts})
        if "active" in facts:
            self.value["active"] = facts["active"]
        _atomic_receipt(self.path, self.value)

    def finish(self, status: str) -> None:
        self.value.update(status=status, finished_at=datetime.now(UTC).isoformat())
        try:
            _atomic_receipt(self.path, self.value)
        finally:
            self.lease.close()


def _set_parent_death_signal() -> None:
    if sys.platform != "linux":
        raise RuntimeError("persistent controller requires Linux")
    parent = os.getppid()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG) failed")
    if os.getppid() != parent:
        raise RuntimeError("controller parent changed while arming parent-death cleanup")


def _run(argv: list[str], *, timeout_seconds: float = 150) -> dict[str, Any]:
    if not 0 < timeout_seconds <= 150:
        raise ValueError("helper timeout must be in 0..150 seconds")
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("helper pipes are unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": MAX_RESPONSE_BYTES, "stderr": 16 * 1024}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("allowlisted helper exceeded its controller deadline")
            events = selector.select(min(1.0, remaining))
            if not events and process.poll() is not None:
                events = selector.select(0)
            for key, _ in events:
                chunk = os.read(key.fd, 4096)
                name = cast(str, key.data)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[name].extend(chunk)
                if len(buffers[name]) > limits[name]:
                    raise ValueError(f"helper {name} exceeds controller bound")
        code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except BaseException:
        process.kill()
        process.wait(timeout=10)
        raise
    finally:
        selector.close()
    if code:
        stderr = bytes(buffers["stderr"][-2000:]).decode("utf-8", "replace")
        raise RuntimeError(f"allowlisted helper failed ({code}): {stderr}")
    value = json.loads(bytes(buffers["stdout"]))
    if not isinstance(value, dict):
        raise ValueError("helper response must be an object")
    return cast(dict[str, Any], value)


def _requests(stream: BinaryIO) -> Iterator[dict[str, Any]]:
    while True:
        line = stream.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return
        if len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
            raise ValueError("controller request exceeds bound or lacks newline")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("controller request must be an object")
        yield value


def _requests_fd(stream: BinaryIO, deadline: float) -> Iterator[dict[str, Any]]:
    descriptor = stream.fileno()
    os.set_blocking(descriptor, False)
    selector = selectors.DefaultSelector()
    selector.register(descriptor, selectors.EVENT_READ)
    pending = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("controller session expired")
            if not selector.select(min(1.0, remaining)):
                continue
            chunk = os.read(descriptor, 4096)
            if not chunk:
                if pending:
                    raise ValueError("controller closed with a partial request")
                return
            pending.extend(chunk)
            if len(pending) > MAX_REQUEST_BYTES:
                raise ValueError("controller request exceeds bound")
            while b"\n" in pending:
                line, _, rest = pending.partition(b"\n")
                pending = bytearray(rest)
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("controller request must be an object")
                yield value
    finally:
        selector.close()


def _cleanup_confirmed(scenario: str, result: dict[str, Any]) -> bool:
    if scenario in {"disk", "inode", "network", "dns"}:
        return result.get("cleanup_complete") is True
    if scenario == "io":
        return result.get("cleanup_complete") is True and result.get("phase") == "destroyed"
    if scenario in {"fd", "cpu"}:
        return result.get("cleaned") is True or result.get("owned") is False
    if scenario == "oom":
        return result.get("released") is True or result.get("owned") is False
    if scenario == "config":
        return result.get("phase") == "restored"
    return False


def serve(
    source_root: Path,
    reader: BinaryIO,
    writer: BinaryIO,
    *,
    runner: Callable[[list[str]], dict[str, Any]] = _run,
    journal: ControllerJournal | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    session: Mapping[str, Any] | None = None,
    api_reader: Callable[[object, object], dict[str, Any]] | None = None,
) -> None:
    fault_active: tuple[str, str] | None = None
    configurations: list[tuple[str, str, str]] = []
    stopping = False
    deadline = monotonic() + MAX_SESSION_SECONDS - TERMINAL_CLEANUP_RESERVE_SECONDS
    request_count = 0

    def ownership() -> dict[str, Any] | None:
        if fault_active is None and not configurations:
            return None
        return {
            "fault": (
                {"scenario": fault_active[0], "token": fault_active[1]}
                if fault_active is not None
                else None
            ),
            "configurations": [
                {"scenario": scenario, "token": token, "scope": scope}
                for scenario, token, scope in configurations
            ],
        }

    def cleanup_active() -> None:
        nonlocal fault_active, stopping
        if stopping:
            return
        stopping = True
        if fault_active is not None:
            scenario, token = fault_active
            try:
                for action in CLEANUP[scenario]:
                    request = {
                        "id": "terminal-cleanup",
                        "scenario": scenario,
                        "action": action,
                        "token": token,
                        "arguments": {},
                    }
                    argv, _ = request_argv(source_root, request)
                    result = runner(argv)
                    if action == TERMINAL_ACTION[scenario] and not _cleanup_confirmed(
                        scenario, result
                    ):
                        raise RuntimeError("terminal cleanup response is not conclusive")
                fault_active = None
                if journal:
                    journal.record(
                        "terminal_fault_cleanup_complete", active=ownership(), scenario=scenario
                    )
            except BaseException as exc:
                if journal:
                    journal.record(
                        "terminal_fault_cleanup_failed",
                        active=ownership(),
                        error=f"{type(exc).__name__}: {exc}",
                    )
                return
        while configurations:
            scenario, token, scope = configurations[-1]
            request = {
                "id": "terminal-config-restore",
                "scenario": scenario,
                "action": "restore",
                "token": token,
                "arguments": {"scope": scope},
            }
            try:
                argv, _ = request_argv(source_root, request)
                result = runner(argv)
                if not _cleanup_confirmed(scenario, result):
                    raise RuntimeError("terminal configuration restore is not conclusive")
                configurations.pop()
                if journal:
                    journal.record("terminal_config_restore_complete", active=ownership())
            except BaseException as exc:
                if journal:
                    journal.record(
                        "terminal_config_restore_failed",
                        active=ownership(),
                        error=f"{type(exc).__name__}: {exc}",
                    )
                return

    def interrupted(signum: int, frame: object) -> None:
        cleanup_active()
        raise SystemExit(128 + signum)

    previous_term = signal.signal(signal.SIGTERM, interrupted)
    previous_int = signal.signal(signal.SIGINT, interrupted)
    try:
        try:
            source = _requests_fd(reader, deadline)
            reader.fileno()
        except (AttributeError, OSError):
            source = _requests(reader)
        if session is not None:
            try:
                hello = next(source)
            except StopIteration as exc:
                raise ValueError("authenticated controller requires hello") from exc
            if (
                set(hello) != HELLO_FIELDS
                or hello.get("type") != "hello"
                or hello.get("batch_id") != session.get("batch_id")
                or re.fullmatch(r"[0-9a-f]{64}", str(hello.get("nonce", ""))) is None
            ):
                raise ValueError("controller hello identity is invalid")
            hello_response = {
                "type": "hello",
                "ok": True,
                "batch_id": session["batch_id"],
                "nonce": hello["nonce"],
                "session_id": session["session_id"],
                "protected_manifest_sha256": session["protected_manifest_sha256"],
                "controller_bundle_sha256": session["controller_bundle_sha256"],
                "identity": session["identity"],
            }
            writer.write(
                json.dumps(hello_response, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            )
            writer.flush()
        for request in source:
            request_count += 1
            request_limit = (
                MAX_MONITOR_REQUESTS
                if session is not None and session.get("identity", {}).get("role") == "monitor"
                else MAX_REQUESTS
            )
            if request_count > request_limit or monotonic() > deadline:
                raise TimeoutError("controller request/session bound exceeded")
            response: dict[str, Any] = {"id": request.get("id"), "ok": False}
            try:
                helper_request = request
                if session is not None:
                    if (
                        set(request) != AUTHENTICATED_REQUEST_FIELDS
                        or request.get("batch_id") != session.get("batch_id")
                        or request.get("session_id") != session.get("session_id")
                    ):
                        raise ValueError("authenticated request batch/session mismatch")
                    helper_request = {key: request[key] for key in REQUEST_FIELDS}
                    role = session["identity"]["role"]
                    scenario = helper_request["scenario"]
                    scope = helper_request["arguments"].get("scope", "agent")
                    if role == "monitor" and (
                        scenario not in {"config", "api"}
                        or (scenario == "config" and scope != "monitor")
                    ):
                        raise PermissionError("monitor session request is outside its role")
                    if role != "monitor" and (
                        scenario == "api" or (scenario == "config" and scope != "agent")
                    ):
                        raise PermissionError("node session request is outside its role")
                if helper_request.get("scenario") == "api":
                    if (
                        helper_request.get("action") != "get"
                        or helper_request.get("token") != "0" * 32
                        or not isinstance(helper_request.get("arguments"), dict)
                        or set(helper_request["arguments"]) != {"path", "params"}
                        or api_reader is None
                    ):
                        raise ValueError("API relay request is invalid")
                    result = api_reader(
                        helper_request["arguments"]["path"],
                        helper_request["arguments"]["params"],
                    )
                    response.update(ok=True, result=result)
                    if session is not None:
                        response.update(
                            batch_id=session["batch_id"], session_id=session["session_id"]
                        )
                    encoded = (
                        json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n"
                    ).encode()
                    if len(encoded) > MAX_API_RESPONSE_BYTES:
                        raise ValueError("API relay envelope exceeds bound")
                    writer.write(encoded)
                    writer.flush()
                    continue
                argv, activates = request_argv(source_root, helper_request)
                key = (str(helper_request["scenario"]), str(helper_request["token"]))
                scope = str(helper_request["arguments"].get("scope", "agent"))
                config_key = (key[0], key[1], scope)
                if activates:
                    if key[0] == "config":
                        if config_key in configurations:
                            raise RuntimeError("configuration transaction is already owned")
                        if len(configurations) >= MAX_CONFIG_TRANSACTIONS:
                            raise RuntimeError("configuration transaction bound exceeded")
                        configurations.append(config_key)
                    else:
                        if fault_active is not None and fault_active != key:
                            raise RuntimeError("one physical fault/resource is already active")
                        if fault_active is None:
                            fault_active = key
                    if journal:
                        journal.record(
                            "mutation_intent",
                            active=ownership(),
                            request_id=helper_request["id"],
                        )
                if helper_request["scenario"] == "config" and helper_request["action"] in {
                    "restore",
                    "handoff",
                }:
                    if not configurations or configurations[-1] != config_key:
                        raise RuntimeError(
                            "configuration restores must follow reverse ownership order"
                        )
                if (
                    key[0] != "config"
                    and helper_request["action"]
                    in {"pressure", "release", "stop", "cleanup", "destroy"}
                    and fault_active != key
                ):
                    raise RuntimeError("mutating action does not match the owned physical resource")
                result = runner(argv)
                if key[0] == "config" and helper_request["action"] == "handoff":
                    if result.get("phase") != "active":
                        raise RuntimeError("configuration handoff response is not conclusive")
                    configurations.pop()
                    if journal:
                        journal.record("explicit_config_handoff_complete", active=ownership())
                elif key[0] == "config" and helper_request["action"] == "restore":
                    if _cleanup_confirmed("config", result):
                        configurations.pop()
                        if journal:
                            journal.record("explicit_config_restore_complete", active=ownership())
                    else:
                        raise RuntimeError("explicit configuration restore is not conclusive")
                elif helper_request["action"] == TERMINAL_ACTION.get(key[0]):
                    if fault_active == key and _cleanup_confirmed(key[0], result):
                        fault_active = None
                        if journal:
                            journal.record("explicit_fault_cleanup_complete", active=ownership())
                    elif fault_active == key:
                        raise RuntimeError("explicit fault cleanup response is not conclusive")
                response.update(ok=True, result=result)
                if session is not None:
                    response.update(batch_id=session["batch_id"], session_id=session["session_id"])
            except Exception as exc:
                if journal:
                    journal.record(
                        "request_failed",
                        active=ownership(),
                        request_id=request.get("id"),
                        error=f"{type(exc).__name__}: {exc}",
                    )
                response["error"] = f"{type(exc).__name__}: {exc}"
            if session is not None:
                response.update(batch_id=session["batch_id"], session_id=session["session_id"])
            encoded = (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode()
            if len(encoded) > MAX_RESPONSE_BYTES:
                encoded = (
                    json.dumps(
                        {
                            "id": request.get("id"),
                            "ok": False,
                            "error": "response exceeds bound",
                            **(
                                {
                                    "batch_id": session["batch_id"],
                                    "session_id": session["session_id"],
                                }
                                if session is not None
                                else {}
                            ),
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode()
            writer.write(encoded)
            writer.flush()
    finally:
        cleanup_active()
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=PROTECTED_SOURCE)
    parser.add_argument(
        "--manifest", type=Path, default=Path("/etc/fleetdoctor/chaos-controller.json")
    )
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("persistent chaos controller requires root Linux")
    if args.source_root != PROTECTED_SOURCE or args.manifest != PROTECTED_MANIFEST:
        raise ValueError("controller runtime paths are fixed to the protected installation")
    manifest = validate_source(args.source_root, args.manifest)
    identity = attest_runtime_identity(manifest)
    session_id = secrets.token_hex(32)
    session = {
        "batch_id": manifest["batch_id"],
        "session_id": session_id,
        "protected_manifest_sha256": _sha256(args.manifest),
        "controller_bundle_sha256": manifest["controller_bundle_sha256"],
        "identity": identity,
    }
    _set_parent_death_signal()
    journal = ControllerJournal(batch_id=manifest["batch_id"], session_id=session_id)
    try:
        serve(
            args.source_root,
            sys.stdin.buffer,
            sys.stdout.buffer,
            journal=journal,
            session=session,
            api_reader=lambda path, params: api_get(manifest, path, params),
        )
    except BaseException:
        journal.finish("failed")
        raise
    status = "completed" if journal.value.get("active") is None else "cleanup_failed"
    journal.finish(status)
    if status == "cleanup_failed":
        raise RuntimeError(
            "controller cleanup is unconfirmed; retained journal blocks new sessions"
        )


if __name__ == "__main__":
    main()
