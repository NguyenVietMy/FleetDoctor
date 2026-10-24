#!/usr/bin/env python3
"""Root-only, lease-bound tc/netem helper for one exact ICMP echo-request path."""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import re
import select
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

BASE = Path("/run/fleetdoctor/network")
LEASE = BASE / "lease.json"
LOCK = BASE / "control.lock"
RUNS = BASE / "runs"
OWNED_ROOT_HANDLE = "1:"
OWNED_NETEM_HANDLE = "30:"
OWNED_FILTER_PREF = "49152"
OWNED_FILTER_HANDLE = "0xfd09"


def _tool(name: str) -> str:
    for candidate in (f"/usr/sbin/{name}", f"/sbin/{name}", f"/usr/bin/{name}", f"/bin/{name}"):
        path = Path(candidate)
        if path.is_file():
            value = path.stat()
            if value.st_uid != 0 or value.st_mode & 0o022 or not value.st_mode & stat.S_IXUSR:
                raise ValueError(f"untrusted {name} executable")
            return candidate
    raise FileNotFoundError(name)


def canonical_target(value: str) -> str:
    address = ipaddress.ip_address(value)
    if (
        address.version != 4
        or str(address) != value
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
        or value == "255.255.255.255"
    ):
        raise ValueError("target must be usable canonical IPv4")
    return value


def safe_base() -> None:
    if os.geteuid() != 0:
        raise PermissionError("network helper requires root")
    for ancestor in (Path("/run"), BASE.parent):
        if ancestor.is_symlink():
            raise ValueError("network helper ancestor symlink refused")
        if ancestor.exists():
            value = ancestor.stat(follow_symlinks=False)
            if value.st_uid != 0 or not stat.S_ISDIR(value.st_mode) or value.st_mode & 0o022:
                raise ValueError("network helper ancestor is not trusted")
    BASE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    parent_value = BASE.parent.stat(follow_symlinks=False)
    if (
        BASE.parent.is_symlink()
        or parent_value.st_uid != 0
        or not stat.S_ISDIR(parent_value.st_mode)
        or parent_value.st_mode & 0o022
    ):
        raise ValueError("network helper parent is not trusted")
    for path in (BASE, RUNS):
        if path.is_symlink():
            raise ValueError("network helper directory symlink refused")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        value = path.stat(follow_symlinks=False)
        if value.st_uid != 0 or not stat.S_ISDIR(value.st_mode) or value.st_mode & 0o077:
            raise ValueError("network helper directory must be root-only")
    for path in (LOCK,):
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        value = path.stat(follow_symlinks=False)
        if value.st_uid != 0 or not stat.S_ISREG(value.st_mode) or value.st_mode & 0o077:
            raise ValueError("network helper lock must be root-only")


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
                    raise TimeoutError("network helper lock deadline exceeded") from exc
                time.sleep(0.02)
        yield
    finally:
        os.close(fd)


def run_path(token: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}", token):
        raise ValueError("token must contain exactly 32 lowercase hexadecimal characters")
    return RUNS / f"{token}.json"


def save(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        if os.write(fd, data) != len(data):
            raise OSError("short network helper metadata write")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)


def command(argv: list[str], *, timeout: float = 2) -> dict[str, Any]:
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    stdout, stderr = result.stdout[:65536], result.stderr[:65536]
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise ValueError("helper command output exceeds 64KiB")
    return {
        "argv": argv,
        "returncode": result.returncode,
        "stdout": stdout.decode("utf-8", "replace"),
        "stderr": stderr.decode("utf-8", "replace"),
    }


def checked(argv: list[str]) -> dict[str, Any]:
    result = command(argv)
    if result["returncode"]:
        raise RuntimeError(f"{Path(argv[0]).name} command failed with exit {result['returncode']}")
    return result


def namespace_identity() -> dict[str, int]:
    value = os.stat("/proc/self/ns/net")
    return {"device": value.st_dev, "inode": value.st_ino}


def route_identity(target: str, ip: str) -> dict[str, Any]:
    result = checked([ip, "-j", "-4", "route", "get", target])
    rows = json.loads(result["stdout"])
    if not isinstance(rows, list) or len(rows) != 1 or rows[0].get("dst") != target:
        raise ValueError("exact target route unavailable")
    interface = rows[0].get("dev")
    if not isinstance(interface, str) or not re.fullmatch(r"[a-zA-Z0-9_.:@-]{1,64}", interface):
        raise ValueError("route interface unavailable")
    return {
        "target": target,
        "interface": interface,
        "ifindex": __import__("socket").if_nametoindex(interface),
        "source": rows[0].get("prefsrc"),
        "namespace": namespace_identity(),
    }


def tc_state(interface: str, tc: str) -> dict[str, Any]:
    state: dict[str, Any] = {}

    def inspect(kind: str, argv: list[str]) -> None:
        result = command(argv)
        if result["returncode"] != 0:
            raise RuntimeError(f"tc {kind} inspection failed")
        try:
            state[kind] = json.loads(result["stdout"] or "[]")
        except json.JSONDecodeError as exc:
            raise ValueError(f"tc {kind} output malformed") from exc

    inspect("qdisc", [tc, "-j", "qdisc", "show", "dev", interface])
    root_handles = [
        str(item.get("handle"))
        for item in state["qdisc"]
        if isinstance(item, dict)
        and item.get("root") is True
        and re.fullmatch(r"[0-9a-fA-F]+:", str(item.get("handle", "")))
    ]
    root_selector = ["parent", root_handles[0]] if len(root_handles) == 1 else ["root"]
    inspect("class", [tc, "-j", "class", "show", "dev", interface])
    inspect("filter_root", [tc, "-j", "filter", "show", "dev", interface, *root_selector])
    inspect("filter_ingress", [tc, "-j", "filter", "show", "dev", interface, "ingress"])
    return state


VOLATILE_TC_FIELDS = {
    "bytes",
    "packets",
    "drops",
    "overlimits",
    "requeues",
    "backlog",
    "qlen",
    "lastuse",
    "used",
    "installed",
    "in_hw",
    "not_in_hw",
    "in_hw_count",
}


def normalized_state(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalized_state(item)
            for key, item in sorted(value.items())
            if key not in VOLATILE_TC_FIELDS
        }
    if isinstance(value, list):
        normalized = [normalized_state(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def supported_baseline(state: dict[str, Any]) -> bool:
    qdiscs = state.get("qdisc")
    return bool(
        isinstance(qdiscs, list)
        and len(qdiscs) == 1
        and qdiscs[0].get("kind") == "noqueue"
        and qdiscs[0].get("root") is True
        and not state.get("class")
        and not state.get("filter_root")
        and not state.get("filter_ingress")
    )


def _handle(item: dict[str, Any]) -> str:
    return str(item.get("handle", "")).lower()


def _parent(item: dict[str, Any]) -> str:
    return str(item.get("parent", "")).lower()


def _class_kind(item: dict[str, Any]) -> str:
    kind, class_name = item.get("kind"), item.get("class")
    if kind is not None and class_name is not None and kind != class_name:
        return ""
    return str(kind if kind is not None else class_name or "")


def _find_values(value: Any, key: str) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for current, item in value.items():
            if current == key:
                found.append(item)
            found.extend(_find_values(item, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(_find_values(item, key))
    return found


def _only_fields(value: dict[str, Any], allowed: set[str]) -> bool:
    """Reject semantic additions while tolerating the bounded tc runtime counters."""
    return not (set(value) - allowed - VOLATILE_TC_FIELDS)


def owned_prefix(state: dict[str, Any], steps: int, target: str, profile: str) -> bool:
    """Match the exact object set for a fixed setup prefix; kernel metadata may vary."""
    if steps not in (1, 2, 3) or state.get("filter_ingress"):
        return False
    qdiscs = state.get("qdisc")
    classes = state.get("class")
    filters = state.get("filter_root")
    if (
        not isinstance(qdiscs, list)
        or not isinstance(classes, list)
        or not isinstance(filters, list)
    ):
        return False
    expected_qdisc_count = 2 if steps == 3 else 1
    if len(qdiscs) != expected_qdisc_count:
        return False
    prios = [item for item in qdiscs if item.get("kind") == "prio"]
    netems = [item for item in qdiscs if item.get("kind") == "netem"]
    if (
        len(prios) != 1
        or _handle(prios[0]) != "1:"
        or prios[0].get("root") is not True
        or not _only_fields(prios[0], {"kind", "handle", "root", "refcnt", "options"})
    ):
        return False
    prio_options = prios[0].get("options")
    if (
        not isinstance(prio_options, dict)
        or not _only_fields(prio_options, {"bands", "priomap", "multiqueue"})
        or prio_options.get("bands") != 3
        or prio_options.get("priomap") != [1] * 16
        or prio_options.get("multiqueue", False) is not False
    ):
        return False
    if (
        len(classes) != 3
        or any(
            not isinstance(item, dict)
            or not _only_fields(item, {"kind", "class", "handle", "parent", "leaf"})
            for item in classes
        )
        or {(_handle(item), _parent(item), _class_kind(item)) for item in classes}
        != {("1:1", "1:", "prio"), ("1:2", "1:", "prio"), ("1:3", "1:", "prio")}
        or any(
            item.get("leaf") not in (None, "0x30")
            or (item.get("leaf") == "0x30" and _handle(item) != "1:3")
            for item in classes
        )
    ):
        return False
    if steps == 1:
        return not filters and not netems
    if not 1 <= len(filters) <= 2 or any(
        not isinstance(item, dict) or item.get("kind") != "flower" for item in filters
    ):
        return False
    detailed = [item for item in filters if isinstance(item.get("options"), dict)]
    summaries = [item for item in filters if not isinstance(item.get("options"), dict)]
    if (
        len(detailed) != 1
        or len(summaries) > 1
        or any(not _only_fields(item, {"protocol", "pref", "kind", "chain"}) for item in summaries)
    ):
        return False
    flower = detailed[0]
    if not _only_fields(flower, {"protocol", "pref", "kind", "chain", "handle", "options"}):
        return False
    for item in filters:
        if (
            item.get("protocol") not in {"ip", "0x0800", 2048}
            or item.get("pref") not in {49152, "49152"}
            or item.get("chain", 0) not in {0, "0"}
        ):
            return False
    options = flower["options"]
    if not _only_fields(options, {"handle", "classid", "keys"}):
        return False
    keys = options.get("keys")
    if (
        not isinstance(keys, dict)
        or not _only_fields(keys, {"eth_type", "dst_ip", "ip_proto", "icmp_type", "icmp_code"})
        or keys.get("eth_type", "ipv4") != "ipv4"
        or keys.get("dst_ip") != target
        or keys.get("ip_proto") != "icmp"
        or keys.get("icmp_type") not in {8, "8"}
        or keys.get("icmp_code") not in {0, "0"}
        or options.get("classid") != "1:3"
    ):
        return False
    accepted_handles = {OWNED_FILTER_HANDLE, OWNED_FILTER_HANDLE.upper(), 0xFD09, "fd09::1"}
    handles = [
        value for value in (flower.get("handle"), options.get("handle")) if value is not None
    ]
    if len(handles) != 1 or handles[0] not in accepted_handles:
        return False
    if steps == 2:
        return not netems
    if len(netems) != 1 or _handle(netems[0]) != OWNED_NETEM_HANDLE or _parent(netems[0]) != "1:3":
        return False
    if not _only_fields(netems[0], {"kind", "handle", "parent", "options"}):
        return False
    options = netems[0].get("options", {})
    if not isinstance(options, dict) or not _only_fields(
        options, {"limit", "delay", "loss-random", "seed", "ecn", "gap"}
    ):
        return False
    delay = options.get("delay")
    loss_keys = [key for key in ("loss-random",) if key in options]
    if profile == "latency":
        if isinstance(delay, dict):
            delay_matches = delay == {"correlation": 0, "delay": 0.25, "jitter": 0}
        else:
            delay_matches = delay == 250000
        return (
            delay_matches
            and not loss_keys
            and options.get("limit") in (None, 1000)
            and options.get("ecn", False) is False
            and options.get("gap", 0) == 0
        )
    if len(loss_keys) != 1:
        return False
    loss = options[loss_keys[0]]
    if not isinstance(loss, dict) or not _only_fields(loss, {"loss", "probability", "correlation"}):
        return False
    modern = set(loss) == {"loss", "correlation"} and loss["loss"] == 1
    legacy = set(loss) == {"probability", "correlation"} and loss["probability"] == 4294967295
    return (
        delay is None
        and (modern or legacy)
        and loss["correlation"] == 0
        and options.get("limit") in (None, 1000)
        and options.get("ecn", False) is False
        and options.get("gap", 0) == 0
    )


def load_record(token: str) -> dict[str, Any]:
    path = run_path(token)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        value = os.fstat(fd)
        if value.st_uid != 0 or not stat.S_ISREG(value.st_mode) or value.st_mode & 0o077:
            raise ValueError("untrusted network run record")
        with os.fdopen(fd, encoding="utf-8") as stream:
            record: dict[str, Any] = json.load(stream)
            fd = -1
    finally:
        if fd >= 0:
            os.close(fd)
    if record.get("token") != token:
        raise ValueError("network run token changed")
    return record


def validate_lease(token: str, *, allow_absent_after_restore: bool = False) -> bool:
    if LEASE.is_symlink():
        raise ValueError("network lease symlink refused")
    if not LEASE.exists():
        if allow_absent_after_restore:
            return False
        raise ValueError("network lease is missing")
    fd = os.open(LEASE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        value = os.fstat(fd)
        if (
            value.st_uid != 0
            or not stat.S_ISREG(value.st_mode)
            or value.st_nlink != 1
            or value.st_mode & 0o077
        ):
            raise ValueError("network lease is not trusted")
        with os.fdopen(fd, encoding="utf-8") as stream:
            lease = json.load(stream)
            fd = -1
    finally:
        if fd >= 0:
            os.close(fd)
    if lease != {"token": token}:
        raise ValueError("network lease token does not authorize this run")
    return True


def process_start(pid: int) -> str:
    return Path(f"/proc/{pid}/stat").read_text().split()[21]


def owned_watchdog(record: dict[str, Any]) -> bool:
    try:
        pid = record["watchdog_pid"]
        cmdline = [part for part in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if part]
        return (
            process_start(pid) == record["watchdog_start"]
            and str(Path(__file__).resolve()).encode() in cmdline
            and b"watchdog" in cmdline
            and record["token"].encode() in cmdline
        )
    except (KeyError, OSError, TypeError, ValueError):
        return False


def launch_watchdog(token: str, duration: int) -> subprocess.Popen[bytes]:
    read_fd, write_fd = os.pipe()
    log = (RUNS / f"{token}.log").open("ab")
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "watchdog",
                "--token",
                token,
                "--duration",
                str(duration),
                "--ready-fd",
                str(write_fd),
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
            close_fds=True,
            pass_fds=(write_fd,),
        )
    finally:
        log.close()
        os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], 2)
        if not ready or os.read(read_fd, 5) != b"ready":
            process.kill()
            process.wait(timeout=2)
            raise TimeoutError("network watchdog readiness deadline exceeded")
    finally:
        os.close(read_fd)
    return process


def cleanup_locked(token: str, *, reason: str) -> dict[str, Any]:
    record = load_record(token)
    if record.get("cleanup_complete") is True:
        return record
    resuming_after_lease_unlink = record.get("cleanup_phase") == "lease_removal_pending"
    lease_present = validate_lease(token, allow_absent_after_restore=resuming_after_lease_unlink)
    tc, ip = record["tools"]["tc"], record["tools"]["ip"]
    try:
        route = route_identity(record["target"], ip)
        namespace = namespace_identity()
    except BaseException as exc:
        record.update(
            cleanup_attempt_utc=datetime.now(UTC).isoformat(),
            cleanup_failed="route_or_namespace_identity_unavailable",
            cleanup_failure=f"{type(exc).__name__}: {exc}",
        )
        save(run_path(token), record)
        raise
    if route != record["route_before"] or namespace != record["namespace"]:
        record.update(
            cleanup_attempt_utc=datetime.now(UTC).isoformat(),
            cleanup_failed="route_or_namespace_identity_changed",
            cleanup_failure="trusted cleanup authority no longer matches its recorded identity",
        )
        save(run_path(token), record)
        raise ValueError("network route or namespace identity changed; cleanup refused")
    live = tc_state(record["interface"], tc)
    record["cleanup_attempt_utc"] = datetime.now(UTC).isoformat()
    record["cleanup_prestate"] = live
    save(run_path(token), record)
    original = normalized_state(record["prestate"])
    if normalized_state(live) == original:
        restored = live
    else:
        completed = int(record.get("completed_steps", 0))
        pending = record.get("pending_step")
        candidates = {completed}
        if type(pending) is int and 0 <= pending <= 2:
            candidates.add(pending + 1)
        exact_active = record.get("active_state")
        matches_active = exact_active is not None and normalized_state(live) == normalized_state(
            exact_active
        )
        matches_prefix = exact_active is None and any(
            owned_prefix(live, steps, record["target"], record["profile"])
            for steps in candidates
            if steps in (1, 2, 3)
        )
        if not (matches_active or matches_prefix):
            record["cleanup_failed"] = "foreign_or_changed_tc_hierarchy"
            save(run_path(token), record)
            raise ValueError("live tc hierarchy is not the owned tree; cleanup refused")
        result = command(
            [tc, "qdisc", "del", "dev", record["interface"], "root", "handle", OWNED_ROOT_HANDLE]
        )
        record.setdefault("commands", []).append(result)
        save(run_path(token), record)
        if result["returncode"]:
            record["cleanup_failed"] = "owned_root_delete_failed"
            save(run_path(token), record)
            raise RuntimeError("owned tc cleanup failed")
        restored = tc_state(record["interface"], tc)
    if normalized_state(restored) != original:
        record["cleanup_failed"] = "baseline_not_restored"
        save(run_path(token), record)
        raise RuntimeError("captured tc baseline was not restored")
    record.update(
        restored_state=restored,
        route_after=route,
        cleanup_phase="lease_removal_pending" if resuming_after_lease_unlink else "restored",
    )
    record.pop("cleanup_failed", None)
    save(run_path(token), record)
    if lease_present:
        validate_lease(token)
        record["cleanup_phase"] = "lease_removal_pending"
        save(run_path(token), record)
        LEASE.unlink()
    elif not resuming_after_lease_unlink:
        raise ValueError("network lease disappeared before authorized removal")
    record.update(
        cleanup_complete=True,
        cleanup_reason=reason,
        cleanup_utc=datetime.now(UTC).isoformat(),
        cleanup_phase="complete",
    )
    save(run_path(token), record)
    return record


def cleanup(token: str, *, reason: str = "requested") -> dict[str, Any]:
    with locked():
        return cleanup_locked(token, reason=reason)


def setup_commands(tc: str, interface: str, target: str, profile: str) -> list[list[str]]:
    """Return the fixed owned hierarchy for one exact ICMP echo-request destination."""
    return [
        [
            tc,
            "qdisc",
            "add",
            "dev",
            interface,
            "root",
            "handle",
            OWNED_ROOT_HANDLE,
            "prio",
            "bands",
            "3",
            "priomap",
            *("1" for _ in range(16)),
        ],
        [
            tc,
            "filter",
            "add",
            "dev",
            interface,
            "protocol",
            "ip",
            "parent",
            OWNED_ROOT_HANDLE,
            "pref",
            OWNED_FILTER_PREF,
            "handle",
            OWNED_FILTER_HANDLE,
            "flower",
            "ip_proto",
            "icmp",
            "dst_ip",
            target,
            "type",
            "8",
            "code",
            "0",
            "flowid",
            "1:3",
        ],
        [
            tc,
            "qdisc",
            "add",
            "dev",
            interface,
            "parent",
            "1:3",
            "handle",
            OWNED_NETEM_HANDLE,
            "netem",
            *(["delay", "250ms"] if profile == "latency" else ["loss", "100%"]),
        ],
    ]


def start(token: str, target: str, profile: str, duration: int) -> dict[str, Any]:
    if profile not in ("latency", "loss") or not 2 <= duration <= 180:
        raise ValueError("profile or duration outside bounds")
    target = canonical_target(target)
    path = run_path(token)
    with locked():
        if LEASE.is_symlink() or LEASE.exists():
            raise ValueError("unresolved network helper lease exists")
        if path.exists() or path.is_symlink():
            raise ValueError("network run token already exists")
        tc, ip = _tool("tc"), _tool("ip")
        route = route_identity(target, ip)
        prestate = tc_state(route["interface"], tc)
        if not supported_baseline(prestate):
            raise ValueError("foreign tc state refused; prepare a dedicated noqueue lab interface")
        lease_fd = os.open(LEASE, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.write(lease_fd, json.dumps({"token": token}).encode())
            os.fsync(lease_fd)
        finally:
            os.close(lease_fd)
        record: dict[str, Any] = {
            "token": token,
            "target": target,
            "profile": profile,
            "duration_seconds": duration,
            "interface": route["interface"],
            "ifindex": route["ifindex"],
            "namespace": namespace_identity(),
            "route_before": route,
            "prestate": prestate,
            "tools": {"tc": tc, "ip": ip},
            "commands": [],
            "cleanup_complete": False,
            "started_utc": datetime.now(UTC).isoformat(),
            "deadline_monotonic": time.monotonic() + duration,
            "parent_pid": os.getpid(),
            "parent_start": process_start(os.getpid()),
            "setup_state": "starting",
            "completed_steps": 0,
        }
        save(path, record)
        watchdog = launch_watchdog(token, duration)
        record.update(watchdog_pid=watchdog.pid, watchdog_start=process_start(watchdog.pid))
        save(path, record)
        if not owned_watchdog(record):
            raise RuntimeError("independent network watchdog did not establish authority")
        commands = setup_commands(tc, route["interface"], target, profile)
        try:
            for index, argv in enumerate(commands):
                record["pending_step"] = index
                save(path, record)
                result = command(argv)
                record["commands"].append(result)
                save(path, record)
                if result["returncode"]:
                    raise RuntimeError(
                        f"{Path(argv[0]).name} command failed with exit {result['returncode']}"
                    )
                record["completed_steps"] = index + 1
                save(path, record)
            live = tc_state(route["interface"], tc)
            if not owned_prefix(live, 3, target, profile):
                raise RuntimeError("installed tc hierarchy does not match owned intent")
            record["active_state"] = live
            record["route_active"] = route_identity(target, ip)
            if record["route_active"] != route:
                raise RuntimeError("route changed during network setup")
            record["pending_step"] = None
            record["setup_state"] = "active"
            save(path, record)
            return record
        except BaseException as exc:
            record["setup_failure"] = f"{type(exc).__name__}: {exc}"
            save(path, record)
            try:
                cleanup_locked(token, reason="partial_setup_rollback")
            except BaseException as cleanup_error:
                exc.add_note(f"retained cleanup failure: {type(cleanup_error).__name__}")
            raise


def status(token: str) -> dict[str, Any]:
    with locked():
        record = load_record(token)
        if record.get("cleanup_complete"):
            return record
        if not owned_watchdog(record):
            raise ValueError("network watchdog identity is not live")
        route = route_identity(record["target"], record["tools"]["ip"])
        state = tc_state(record["interface"], record["tools"]["tc"])
        if route != record["route_before"] or normalized_state(state) != normalized_state(
            record["active_state"]
        ):
            raise ValueError("active network resource identity changed")
        return {**record, "observed_state": state, "route_status": route}


def watchdog(token: str, duration: int, ready_fd: int) -> None:
    record = load_record(token)
    validate_lease(token)
    raw_deadline = record.get("deadline_monotonic")
    if not isinstance(raw_deadline, (int, float)) or isinstance(raw_deadline, bool):
        raise ValueError("network watchdog deadline is invalid")
    deadline = float(raw_deadline)
    if deadline <= time.monotonic() or deadline > time.monotonic() + 180:
        raise ValueError("network watchdog deadline is invalid")
    os.write(ready_fd, b"ready")
    os.close(ready_fd)
    while time.monotonic() < deadline:
        latest = load_record(token)
        if latest.get("cleanup_complete"):
            return
        if latest.get("setup_state") == "starting":
            try:
                parent_alive = process_start(latest["parent_pid"]) == latest["parent_start"]
            except (KeyError, OSError, TypeError, ValueError):
                parent_alive = False
            if not parent_alive:
                cleanup(token, reason="setup_parent_lost")
                return
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    cleanup(token, reason="watchdog_deadline")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "status", "cleanup", "watchdog"))
    parser.add_argument("--token", required=True)
    parser.add_argument("--target", default="")
    parser.add_argument("--profile", choices=("latency", "loss"), default="latency")
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--ready-fd", type=int, default=-1)
    args = parser.parse_args()
    safe_base()

    def interrupted(signum: int, frame: object) -> None:
        raise InterruptedError(f"network helper interrupted by signal {signum}")

    if args.action != "watchdog":
        signal.signal(signal.SIGINT, interrupted)
        signal.signal(signal.SIGTERM, interrupted)
    if args.action == "watchdog":
        if args.ready_fd < 0:
            parser.error("watchdog requires readiness descriptor")
        watchdog(args.token, args.duration, args.ready_fd)
    elif args.action == "start":
        print(json.dumps(start(args.token, args.target, args.profile, args.duration)))
    elif args.action == "status":
        print(json.dumps(status(args.token)))
    else:
        print(json.dumps(cleanup(args.token)))


if __name__ == "__main__":
    main()
