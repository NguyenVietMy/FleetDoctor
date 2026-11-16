#!/usr/bin/env python3
"""Crash-safe exact-byte FleetDoctor agent selector transactions."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ENV = Path("/etc/fleetdoctor/agent.env")
MONITOR_ENV = Path("/opt/fleetdoctor/current/.env")
STATE = Path("/var/lib/fleetdoctor/config-transactions")
SERVICE = "fleetdoctor-agent.service"
MONITOR_SERVICE = "fleetdoctor-compose-collector"
COMPOSE = Path("/opt/fleetdoctor/current/compose.yaml")
TOKEN = re.compile(r"^[0-9a-f]{32}$")
KEY_LINE = re.compile(
    rb"^(?P<prefix>[ \t]*)(?P<key>FLEETDOCTOR_CPU_PIDS|FLEETDOCTOR_CGROUPS)"
    rb"[ \t]*=[ \t]*(?P<value>.*?)[ \t]*$"
)
KEY_PREFIX = re.compile(rb"^[ \t]*(?:export[ \t]+)?(?:FLEETDOCTOR_CPU_PIDS|FLEETDOCTOR_CGROUPS)\b")
ALLOWED_KEYS = {"FLEETDOCTOR_CPU_PIDS", "FLEETDOCTOR_CGROUPS"}
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
BINARY = getattr(os, "O_BINARY", 0)


def _euid(path: Path) -> int:
    if hasattr(os, "geteuid"):
        return os.geteuid()
    probe = path if path.exists() else path.parent
    return probe.stat().st_uid


def _validate_fixed_root_path(path: Path, *, directory: bool) -> None:
    """Validate every component of a production root-owned path without following links."""
    if os.name != "posix":
        return
    current = path
    chain = [current]
    while current != current.parent:
        current = current.parent
        chain.append(current)
    for item in reversed(chain):
        info = item.lstat()
        expected_type = (
            stat.S_ISDIR(info.st_mode) if item != path or directory else stat.S_ISREG(info.st_mode)
        )
        if (
            not expected_type
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            raise ValueError(f"untrusted configuration transaction path: {item}")


def _validate_runtime_paths(env_path: Path, state_dir: Path) -> None:
    if env_path in {ENV, MONITOR_ENV}:
        _validate_fixed_root_path(env_path, directory=False)
    if state_dir == STATE:
        _validate_fixed_root_path(state_dir, directory=True)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _newline(raw: bytes) -> bytes:
    if b"\r\n" in raw:
        return b"\r\n"
    return b"\n"


def _decode_selector(raw: bytes, key: str) -> str:
    if len(raw) >= 2 and raw[:1] == raw[-1:] and raw[:1] in {b"'", b'"'}:
        quote = raw[:1]
        raw = raw[1:-1]
        if quote in raw or b"\\" in raw:
            raise ValueError(f"unsupported quoted selector syntax for {key}")
    elif raw[:1] in {b"'", b'"'} or raw[-1:] in {b"'", b'"'}:
        raise ValueError(f"unterminated selector quote for {key}")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"selector value for {key} must be ASCII") from exc


def parse_selectors(raw: bytes) -> tuple[dict[str, tuple[Any, ...]], tuple[str, ...]]:
    """Parse exactly the selector syntax that ``update_env_bytes`` can replace."""
    if b"\x00" in raw:
        raise ValueError("agent environment contains NUL")
    found: dict[str, tuple[Any, ...]] = {}
    for line in raw.splitlines(keepends=True):
        content = line.rstrip(b"\r\n")
        if content.count(b"'") % 2 or len(re.findall(rb'(?<!\\)"', content)) % 2:
            raise ValueError("multiline or ambiguous quoted environment value is unsupported")
        match = KEY_LINE.fullmatch(content)
        if match is None:
            if KEY_PREFIX.match(content):
                raise ValueError("unsupported selector assignment syntax")
            continue
        key = match.group("key").decode("ascii")
        if key in found:
            raise ValueError(f"duplicate selector key: {key}")
        value = _decode_selector(match.group("value"), key)
        found[key] = (
            validate_cpu_pids(value) if key == "FLEETDOCTOR_CPU_PIDS" else validate_cgroups(value)
        )
    missing = tuple(sorted(ALLOWED_KEYS - set(found)))
    return found, missing


def _selector_snapshot(raw: bytes) -> dict[str, Any]:
    selectors, missing = parse_selectors(raw)
    return {
        "env_sha256": sha256(raw),
        "selectors": {key: list(selectors.get(key, ())) for key in sorted(ALLOWED_KEYS)},
        "missing_keys": list(missing),
    }


def update_env_bytes(raw: bytes, changes: dict[str, str]) -> bytes:
    if not changes or set(changes) - ALLOWED_KEYS:
        raise ValueError("only the two selector keys may be changed")
    if b"\x00" in raw:
        raise ValueError("agent environment contains NUL")
    for key, value in changes.items():
        if not value.isascii() or any(character in value for character in "\r\n\x00"):
            raise ValueError(f"invalid selector value for {key}")
    endings = raw.splitlines(keepends=True)
    parse_selectors(raw)
    found: dict[str, int] = {}
    output: list[bytes] = []
    for line in endings:
        content = line.rstrip(b"\r\n")
        match = KEY_LINE.fullmatch(content)
        if match is None:
            output.append(line)
            continue
        key = match.group("key").decode("ascii")
        if key in found:
            raise ValueError(f"duplicate selector key: {key}")
        found[key] = len(output)
        if key in changes:
            ending = line[len(content) :]
            output.append(
                match.group("prefix") + key.encode() + b"=" + changes[key].encode("ascii") + ending
            )
        else:
            output.append(line)
    missing = [key for key in changes if key not in found]
    if missing:
        newline = _newline(raw)
        if raw and not raw.endswith((b"\n", b"\r")):
            output.append(newline)
        output.extend(
            key.encode() + b"=" + changes[key].encode("ascii") + newline for key in missing
        )
    return b"".join(output)


def validate_cpu_pids(value: str) -> tuple[int, ...]:
    if not value:
        return ()
    pieces = value.split(",")
    if len(pieces) > 16 or any(not item.isdigit() for item in pieces):
        raise ValueError("CPU PID selector must contain at most 16 numeric PIDs")
    result = tuple(int(item) for item in pieces)
    if len(set(result)) != len(result) or any(item <= 0 for item in result):
        raise ValueError("CPU PID selector requires unique positive PIDs")
    return result


def validate_cgroups(value: str) -> tuple[str, ...]:
    if not value:
        return ()
    pieces = value.split(",")
    if len(pieces) > 8 or len(set(pieces)) != len(pieces):
        raise ValueError("cgroup selector must contain at most eight unique paths")
    if any(re.fullmatch(r"/[A-Za-z0-9_.@/-]+", item) is None for item in pieces):
        raise ValueError("cgroup selector contains an invalid path")
    return tuple(pieces)


def validate_changes(changes: dict[str, str]) -> None:
    if "FLEETDOCTOR_CPU_PIDS" in changes:
        validate_cpu_pids(changes["FLEETDOCTOR_CPU_PIDS"])
    if "FLEETDOCTOR_CGROUPS" in changes:
        validate_cgroups(changes["FLEETDOCTOR_CGROUPS"])


def inventory(
    *,
    env_path: Path = ENV,
    state_dir: Path = STATE,
    service: str = SERVICE,
    service_state: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return bounded selector facts without exposing any other environment value."""
    _validate_runtime_paths(env_path, state_dir)
    info = env_path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("agent environment must be a regular non-symlink file")
    raw = env_path.read_bytes()
    result = _selector_snapshot(raw)
    result.update(
        {
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "service_state": service_state or _service_state(service),
        }
    )
    return result


def _atomic(path: Path, raw: bytes, mode: int, uid: int, gid: int) -> None:
    temporary = path.with_name(path.name + ".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | BINARY, mode)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short agent environment write")
            offset += written
        os.fsync(descriptor)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        if hasattr(os, "fchown"):
            os.fchown(descriptor, uid, gid)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    if os.name == "posix":
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _state_path(token: str, state_dir: Path) -> Path:
    if TOKEN.fullmatch(token) is None:
        raise ValueError("transaction token must be 32 lowercase hexadecimal characters")
    return state_dir / f"agent-env-{token}.json"


def _write_record(path: Path, record: dict[str, Any]) -> None:
    temporary = path.with_name(path.name + ".new")
    encoded = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
    if temporary.exists() or temporary.is_symlink():
        info = temporary.lstat()
        if temporary.is_symlink() or not temporary.is_file() or info.st_uid != _euid(temporary):
            raise ValueError("foreign transaction staging file")
        temporary.unlink()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | BINARY, 0o600)
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("short transaction journal write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    if os.name == "posix":
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _service_state(service: str) -> dict[str, str]:
    if service == MONITOR_SERVICE:
        container = subprocess.run(
            ["docker", "compose", "-f", os.fspath(COMPOSE), "ps", "-q", "collector"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if container.returncode:
            raise RuntimeError("failed to identify the collector container")
        identifier = container.stdout.strip()
        if not identifier:
            return {"ActiveState": "inactive", "UnitFileState": "unless-stopped"}
        inspected = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Status}} {{.HostConfig.RestartPolicy.Name}}",
                identifier,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if inspected.returncode:
            raise RuntimeError("failed to inspect the collector container")
        status, policy = inspected.stdout.strip().split(maxsplit=1)
        return {
            "ActiveState": "active" if status == "running" else "inactive",
            "UnitFileState": policy,
        }
    result: dict[str, str] = {}
    for property_name in ("ActiveState", "UnitFileState"):
        value = subprocess.run(
            ["systemctl", "show", service, "--property", property_name, "--value"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if value.returncode:
            raise RuntimeError(f"failed to read {service} {property_name}")
        result[property_name] = value.stdout.strip()
    return result


def _restart(service: str) -> None:
    argv = (
        [
            "docker",
            "compose",
            "-f",
            os.fspath(COMPOSE),
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "--wait",
            "--wait-timeout",
            "90",
            "collector",
        ]
        if service == MONITOR_SERVICE
        else ["systemctl", "restart", service]
    )
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise RuntimeError(f"failed to restart {service}: {result.stderr[-1000:]}")


def _stop(service: str) -> None:
    argv = (
        ["docker", "compose", "-f", os.fspath(COMPOSE), "stop", "collector"]
        if service == MONITOR_SERVICE
        else ["systemctl", "stop", service]
    )
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
    if result.returncode:
        raise RuntimeError(f"failed to restore inactive {service}: {result.stderr[-1000:]}")


def begin(
    token: str,
    changes: dict[str, str],
    *,
    parent_token: str | None = None,
    env_path: Path = ENV,
    state_dir: Path = STATE,
    service: str = SERVICE,
    service_state: dict[str, str] | None = None,
    restart: bool = True,
    expected_before: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate_changes(changes)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_runtime_paths(env_path, state_dir)
    state_path = _state_path(token, state_dir)
    if state_path.exists():
        raise FileExistsError("configuration transaction already exists")
    if parent_token is not None and TOKEN.fullmatch(parent_token) is None:
        raise ValueError("invalid parent configuration token")
    active_records: list[dict[str, Any]] = []
    if state_dir.exists():
        for candidate in state_dir.glob("agent-env-*.json"):
            existing_record = json.loads(candidate.read_text(encoding="utf-8"))
            if (
                isinstance(existing_record, dict)
                and existing_record.get("phase") in {"intent", "applied", "restore_intent"}
                and Path(str(existing_record.get("env_path", ""))) == env_path
            ):
                active_records.append(existing_record)
    if parent_token is None:
        if active_records:
            raise RuntimeError("an exclusive outer configuration transaction is already active")
    else:
        parents = [record for record in active_records if record.get("token") == parent_token]
        children = [record for record in active_records if record.get("parent_token") is not None]
        if (
            len(parents) != 1
            or parents[0].get("phase") != "applied"
            or parents[0].get("parent_token") is not None
            or set(parents[0].get("changes", {})) != {"FLEETDOCTOR_CGROUPS"}
            or set(changes) != {"FLEETDOCTOR_CPU_PIDS"}
            or env_path != ENV
            or children
        ):
            raise RuntimeError("only one exact FD selector child may nest under the outer scope")
    info = env_path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("agent environment must be a regular non-symlink file")
    original = env_path.read_bytes()
    observed_before = _selector_snapshot(original)
    if expected_before is not None:
        if set(expected_before) != {"env_sha256", "selectors", "missing_keys"}:
            raise ValueError("expected-before selector snapshot is malformed")
        if expected_before != observed_before:
            raise ValueError("selector environment changed since inventory")
    for key, value in changes.items():
        current = set(observed_before["selectors"][key])
        proposed = set(
            validate_cpu_pids(value) if key == "FLEETDOCTOR_CPU_PIDS" else validate_cgroups(value)
        )
        if not current.issubset(proposed):
            raise ValueError(f"selector update would drop existing {key} members")
    updated = update_env_bytes(original, changes)
    prepared_selectors = _selector_snapshot(updated)
    snapshot = service_state or _service_state(service)
    record: dict[str, Any] = {
        "schema_version": 1,
        "token": token,
        "created_at": datetime.now(UTC).isoformat(),
        "phase": "intent",
        "env_path": str(env_path),
        "service": service,
        "original_b64": base64.b64encode(original).decode("ascii"),
        "original_sha256": sha256(original),
        "updated_sha256": sha256(updated),
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "service_state": snapshot,
        "changes": changes,
        "parent_token": parent_token,
        "original_selectors": observed_before,
        "prepared_selectors": prepared_selectors,
    }
    _write_record(state_path, record)
    _atomic(env_path, updated, record["mode"], record["uid"], record["gid"])
    if env_path.read_bytes() != updated:
        raise RuntimeError("selector transaction readback mismatch")
    record["phase"] = "applied"
    _write_record(state_path, record)
    if restart and original != updated and snapshot.get("ActiveState") == "active":
        _restart(service)
        record["restarted"] = True
        _write_record(state_path, record)
    return {key: value for key, value in record.items() if key != "original_b64"}


def restore(
    token: str,
    *,
    state_dir: Path = STATE,
    restart: bool = True,
    expected_env_path: Path = ENV,
    expected_service: str = SERVICE,
) -> dict[str, Any]:
    _validate_runtime_paths(expected_env_path, state_dir)
    state_path = _state_path(token, state_dir)
    info = state_path.lstat()
    if state_path.is_symlink() or not state_path.is_file() or info.st_uid != _euid(state_path):
        raise ValueError("untrusted configuration transaction receipt")
    record = json.loads(state_path.read_text(encoding="utf-8"))
    allowed = {
        "schema_version",
        "token",
        "created_at",
        "phase",
        "env_path",
        "service",
        "original_b64",
        "original_sha256",
        "updated_sha256",
        "mode",
        "uid",
        "gid",
        "service_state",
        "changes",
        "restarted",
        "restored_sha256",
        "parent_token",
        "original_selectors",
        "prepared_selectors",
    }
    required = allowed - {"restarted", "restored_sha256"}
    if (
        not isinstance(record, dict)
        or set(record) - allowed
        or not required.issubset(record)
        or record.get("schema_version") != 1
        or record.get("token") != token
        or not isinstance(record.get("created_at"), str)
        or record.get("phase") not in {"intent", "applied", "restore_intent", "restored"}
        or Path(record.get("env_path", "")) != expected_env_path
        or record.get("service") != expected_service
        or not isinstance(record.get("mode"), int)
        or not isinstance(record.get("uid"), int)
        or not isinstance(record.get("gid"), int)
        or not isinstance(record.get("service_state"), dict)
        or set(record["service_state"]) != {"ActiveState", "UnitFileState"}
        or record["service_state"].get("ActiveState") not in {"active", "inactive"}
        or not isinstance(record["service_state"].get("UnitFileState"), str)
        or not isinstance(record.get("changes"), dict)
        or (
            record.get("parent_token") is not None
            and TOKEN.fullmatch(str(record.get("parent_token"))) is None
        )
    ):
        raise ValueError("configuration transaction receipt is malformed or out of scope")
    validate_changes(record["changes"])
    for candidate in state_dir.glob("agent-env-*.json"):
        if candidate == state_path:
            continue
        child = json.loads(candidate.read_text(encoding="utf-8"))
        if (
            isinstance(child, dict)
            and child.get("parent_token") == token
            and child.get("phase") != "restored"
        ):
            raise RuntimeError("nested configuration must be restored before its parent")
    env_path = Path(record["env_path"])
    original = base64.b64decode(record["original_b64"], validate=True)
    if sha256(original) != record["original_sha256"]:
        raise ValueError("configuration rollback bytes fail their retained hash")
    if record["phase"] == "restored":
        info = env_path.stat(follow_symlinks=False)
        observed_service = _service_state(record["service"]) if restart else record["service_state"]
        if (
            record.get("restored_sha256") != record["original_sha256"]
            or sha256(env_path.read_bytes()) != record["original_sha256"]
            or stat.S_IMODE(info.st_mode) != record["mode"]
            or info.st_uid != record["uid"]
            or info.st_gid != record["gid"]
            or observed_service != record["service_state"]
        ):
            raise ValueError("completed restoration receipt does not match exact runtime state")
        state_path.unlink()
        if os.name == "posix":
            directory = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return {
            "token": token,
            "phase": "restored",
            "original_sha256": record["original_sha256"],
            "restored_sha256": record["restored_sha256"],
            "service_state": record["service_state"],
            "observed_service_state": observed_service,
            "completed_before_recovery": True,
        }
    current = env_path.read_bytes()
    if sha256(current) not in {record["original_sha256"], record["updated_sha256"]}:
        raise ValueError("agent environment changed outside the owned transaction")
    staging = env_path.with_name(env_path.name + ".new")
    if staging.exists() or staging.is_symlink():
        staging_info = staging.lstat()
        if staging.is_symlink() or not staging.is_file() or staging_info.st_uid != record["uid"]:
            raise ValueError("foreign environment staging file blocks rollback")
        staging.unlink()
    record["phase"] = "restore_intent"
    _write_record(state_path, record)
    _atomic(env_path, original, record["mode"], record["uid"], record["gid"])
    if env_path.read_bytes() != original:
        raise RuntimeError("original agent environment was not restored exactly")
    if restart and record["original_sha256"] != record["updated_sha256"]:
        if record["service_state"].get("ActiveState") == "active":
            _restart(record["service"])
        else:
            _stop(record["service"])
    observed_service = _service_state(record["service"]) if restart else record["service_state"]
    if restart and observed_service != record["service_state"]:
        raise RuntimeError("agent service state was not restored")
    record["phase"] = "restored"
    record["restored_sha256"] = sha256(env_path.read_bytes())
    _write_record(state_path, record)
    state_path.unlink()
    if os.name == "posix":
        directory = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return {
        "token": token,
        "phase": "restored",
        "original_sha256": record["original_sha256"],
        "restored_sha256": record["restored_sha256"],
        "service_state": record["service_state"],
        "observed_service_state": observed_service,
    }


def status(
    token: str,
    *,
    state_dir: Path = STATE,
    expected_env_path: Path = ENV,
    expected_service: str = SERVICE,
) -> dict[str, Any]:
    """Prove that a handed-off transaction is still applied without changing it."""
    _validate_runtime_paths(expected_env_path, state_dir)
    state_path = _state_path(token, state_dir)
    info = state_path.lstat()
    if state_path.is_symlink() or not state_path.is_file() or info.st_uid != _euid(state_path):
        raise ValueError("untrusted configuration transaction receipt")
    record = json.loads(state_path.read_text(encoding="utf-8"))
    if (
        not isinstance(record, dict)
        or record.get("schema_version") != 1
        or record.get("token") != token
        or record.get("phase") != "applied"
        or Path(str(record.get("env_path", ""))) != expected_env_path
        or record.get("service") != expected_service
        or not isinstance(record.get("changes"), dict)
        or re.fullmatch(r"[0-9a-f]{64}", str(record.get("original_sha256", ""))) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(record.get("updated_sha256", ""))) is None
    ):
        raise ValueError("configuration transaction receipt is malformed or inactive")
    validate_changes(record["changes"])
    env_info = expected_env_path.stat(follow_symlinks=False)
    if (
        stat.S_IMODE(env_info.st_mode) != record.get("mode")
        or env_info.st_uid != record.get("uid")
        or env_info.st_gid != record.get("gid")
    ):
        raise ValueError("handed-off configuration metadata no longer matches its owner")
    current_sha256 = sha256(expected_env_path.read_bytes())
    if current_sha256 != record["updated_sha256"]:
        raise ValueError("handed-off configuration bytes no longer match the owned update")
    observed_service = _service_state(expected_service)
    if observed_service.get("ActiveState") != "active":
        raise RuntimeError("handed-off configuration service is not active")
    return {
        "token": token,
        "phase": "active",
        "original_sha256": record["original_sha256"],
        "updated_sha256": record["updated_sha256"],
        "current_sha256": current_sha256,
        "changes": record["changes"],
        "original_selectors": record.get("original_selectors"),
        "prepared_selectors": record.get("prepared_selectors"),
        "service_state": observed_service,
    }


def lookup(
    token: str,
    *,
    state_dir: Path = STATE,
    expected_env_path: Path = ENV,
    expected_service: str = SERVICE,
) -> dict[str, Any]:
    """Report only one exact transaction as active or absent without changing it."""
    _validate_runtime_paths(expected_env_path, state_dir)
    state_path = _state_path(token, state_dir)
    staging = state_path.with_name(state_path.name + ".new")
    if staging.exists() or staging.is_symlink():
        raise RuntimeError("exact configuration transaction has unresolved journal staging")
    if not state_path.exists() and not state_path.is_symlink():
        return {"token": token, "state": "absent"}
    active = status(
        token,
        state_dir=state_dir,
        expected_env_path=expected_env_path,
        expected_service=expected_service,
    )
    return {**active, "state": "active"}


def recover(
    *,
    state_dir: Path = STATE,
    restart: bool = True,
    expected_env_path: Path = ENV,
    expected_service: str = SERVICE,
) -> list[dict[str, Any]]:
    if not state_dir.exists():
        return []
    _validate_runtime_paths(expected_env_path, state_dir)
    results = []
    for staging in sorted(state_dir.glob("agent-env-*.json.new")):
        info = staging.lstat()
        if staging.is_symlink() or not staging.is_file() or info.st_uid != _euid(staging):
            raise ValueError("foreign transaction staging file blocks recovery")
        final = staging.with_suffix("")
        if final.exists():
            final_info = final.lstat()
            if final.is_symlink() or not final.is_file() or final_info.st_uid != _euid(final):
                raise ValueError("foreign transaction journal blocks recovery")
            json.loads(final.read_text(encoding="utf-8"))
            staging.unlink()
        else:
            json.loads(staging.read_text(encoding="utf-8"))
            os.replace(staging, final)
    receipts = sorted(
        state_dir.glob("agent-env-*.json"),
        key=lambda path: str(json.loads(path.read_text(encoding="utf-8")).get("created_at", "")),
        reverse=True,
    )
    for path in receipts:
        token = path.stem.removeprefix("agent-env-")
        results.append(
            restore(
                token,
                state_dir=state_dir,
                restart=restart,
                expected_env_path=expected_env_path,
                expected_service=expected_service,
            )
        )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    begin_parser = subparsers.add_parser("begin")
    begin_parser.add_argument("--token", required=True)
    begin_parser.add_argument("--changes-json", required=True)
    begin_parser.add_argument("--parent-token")
    begin_parser.add_argument("--scope", choices=("agent", "monitor"), default="agent")
    begin_parser.add_argument("--expected-before-json", required=True)
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("--token", required=True)
    restore_parser.add_argument("--scope", choices=("agent", "monitor"), default="agent")
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--token", required=True)
    status_parser.add_argument("--scope", choices=("agent", "monitor"), default="agent")
    lookup_parser = subparsers.add_parser("lookup")
    lookup_parser.add_argument("--token", required=True)
    lookup_parser.add_argument("--scope", choices=("agent", "monitor"), default="agent")
    recover_parser = subparsers.add_parser("recover")
    recover_parser.add_argument("--scope", choices=("agent", "monitor"), default="agent")
    inventory_parser = subparsers.add_parser("inventory")
    inventory_parser.add_argument("--scope", choices=("agent", "monitor"), default="agent")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("configuration transaction requires root Linux")
    env_path = MONITOR_ENV if args.scope == "monitor" else ENV
    service = MONITOR_SERVICE if args.scope == "monitor" else SERVICE
    if args.action == "begin":
        changes = json.loads(args.changes_json)
        expected_before = json.loads(args.expected_before_json)
        if not isinstance(changes, dict) or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in changes.items()
        ):
            raise ValueError("changes-json must be a string map")
        result: Any = begin(
            args.token,
            changes,
            parent_token=args.parent_token,
            env_path=env_path,
            service=service,
            expected_before=expected_before,
        )
    elif args.action == "inventory":
        result = inventory(env_path=env_path, service=service)
    elif args.action == "restore":
        result = restore(args.token, expected_env_path=env_path, expected_service=service)
    elif args.action == "status":
        result = status(args.token, expected_env_path=env_path, expected_service=service)
    elif args.action == "lookup":
        result = lookup(args.token, expected_env_path=env_path, expected_service=service)
    else:
        result = recover(expected_env_path=env_path, expected_service=service)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
