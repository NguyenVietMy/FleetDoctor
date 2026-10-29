"""Bounded Linux network-path collection with an isolated owned worker group."""

from __future__ import annotations

import ipaddress
import math
import multiprocessing as mp
import os
import pickle
import re
import selectors
import signal
import struct
import subprocess
import time
from collections.abc import Callable
from multiprocessing.connection import Connection
from multiprocessing.reduction import ForkingPickler
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import ValidationError

from fleetdoctor.schema import (
    InterfaceNetworkObservation,
    NetworkObservation,
    NetworkProbeObservation,
    TcpNetworkObservation,
)

MAX_READ = 64 * 1024
MAX_PING_OUTPUT = 8 * 1024
MAX_INTERFACES = 16
MAX_SOCKET_LINES = 4096
MAX_PROC_SCAN = 32768
PROC_SCAN_BUDGET_SECONDS = 0.05
PING_ARGV = ("ping", "-n", "-4", "-c", "3", "-i", "0.2", "-W", "1")
TCP_STATES = {
    "01": "established",
    "02": "syn_sent",
    "03": "syn_recv",
    "04": "fin_wait1",
    "05": "fin_wait2",
    "06": "time_wait",
    "07": "close",
    "08": "close_wait",
    "09": "last_ack",
    "0A": "listen",
    "0B": "closing",
}


class _FrameTimeout(TimeoutError):
    """A wire-frame deadline expired, possibly after consuming frame bytes."""

    def __init__(self, *, partial: bool) -> None:
        super().__init__("multiprocessing frame deadline expired")
        self.partial = partial


def _receive_bytes_deadline(conn: Connection, maxlength: int, deadline: float) -> bytes:
    """Receive one multiprocessing frame without exceeding an absolute deadline.

    POSIX ``Connection.poll`` only promises that some bytes are readable. Reading
    the framing bytes directly prevents ``recv_bytes`` from blocking forever on
    an incomplete header or body. Windows and test doubles retain the public
    Connection API because their handles do not have POSIX fd semantics.
    """
    remaining = max(0.0, deadline - time.monotonic())
    if os.name != "posix":
        if not conn.poll(remaining):
            raise _FrameTimeout(partial=False)
        return conn.recv_bytes(maxlength)

    try:
        fd = conn.fileno()
    except (AttributeError, OSError, TypeError):
        if not conn.poll(remaining):
            raise _FrameTimeout(partial=False) from None
        return conn.recv_bytes(maxlength)

    selector = selectors.DefaultSelector()
    consumed = False

    def read_exact(length: int) -> bytes:
        nonlocal consumed
        chunks = bytearray()
        while len(chunks) < length:
            remaining = max(0.0, deadline - time.monotonic())
            if not selector.select(remaining):
                raise _FrameTimeout(partial=consumed or bool(chunks))
            chunk = os.read(fd, length - len(chunks))
            if not chunk:
                raise EOFError
            chunks.extend(chunk)
            consumed = True
        return bytes(chunks)

    try:
        selector.register(fd, selectors.EVENT_READ)
        size = struct.unpack("!i", read_exact(4))[0]
        if size == -1:
            size = struct.unpack("!Q", read_exact(8))[0]
        elif size < 0:
            raise OSError("invalid multiprocessing frame length")
        if size > maxlength:
            raise OSError("multiprocessing frame exceeds maximum length")
        return read_exact(size)
    finally:
        selector.close()


def _receive_pickled_deadline(conn: Connection, maxlength: int, deadline: float) -> Any:
    return ForkingPickler.loads(_receive_bytes_deadline(conn, maxlength, deadline))


def canonical_ipv4(value: str, *, allow_loopback: bool = False) -> str:
    """Return one canonical unicast IPv4 address, rejecting ambiguous spellings."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("network target must be canonical numeric IPv4") from exc
    if address.version != 4 or str(address) != value:
        raise ValueError("network target must be canonical numeric IPv4")
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_reserved
        or address == ipaddress.ip_address("255.255.255.255")
        or (address.is_loopback and not allow_loopback)
    ):
        raise ValueError("network target must be usable unicast IPv4")
    return value


def configured_target(
    explicit: str, collector_url: str, *, allow_loopback: bool = False
) -> str | None:
    if explicit:
        return canonical_ipv4(explicit, allow_loopback=allow_loopback)
    host = urlsplit(collector_url).hostname
    if host is None:
        return None
    try:
        return canonical_ipv4(host, allow_loopback=allow_loopback)
    except ValueError:
        return None


def _bounded_read(path: str, limit: int = MAX_READ) -> tuple[str | None, str | None]:
    try:
        with open(path, "rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            return data[:limit].decode("ascii", "replace"), "truncated"
        return data.decode("ascii"), None
    except (OSError, UnicodeError) as exc:
        return None, f"{Path(path).name}_{type(exc).__name__}"


def parse_ping(stdout: str, stderr: str, returncode: int, target: str) -> NetworkProbeObservation:
    """Parse per-reply RTTs; iputils' summary average is deliberately ignored."""
    combined = (stdout + "\n" + stderr).encode("utf-8", "replace")
    if len(combined) > MAX_PING_OUTPUT:
        return NetworkProbeObservation.unavailable(target, "ping_output_truncated")
    lowered = stderr.lower()
    if returncode == 2 and ("operation not permitted" in lowered or "permission denied" in lowered):
        return NetworkProbeObservation.unavailable(target, "ping_permission_denied")
    summary = re.findall(r"(\d+) packets transmitted, (\d+) (?:packets )?received", stdout)
    if len(summary) != 1:
        return NetworkProbeObservation.unavailable(target, "ping_summary_missing")
    sent, received = (int(value) for value in summary[0])
    replies: list[tuple[int, float]] = []
    for match in re.finditer(
        rf"bytes from {re.escape(target)}(?:\s*\([^)]*\))?:.*?icmp_seq[= ](\d+).*?time[= ]([0-9]+(?:\.[0-9]+)?)\s*ms",
        stdout,
    ):
        sequence, rtt = int(match.group(1)), float(match.group(2))
        if not math.isfinite(rtt) or rtt < 0:
            return NetworkProbeObservation.unavailable(target, "ping_invalid_rtt")
        replies.append((sequence, rtt))
    unique = {sequence for sequence, _ in replies}
    if sent != 3 or not 0 <= received <= 3 or len(unique) != len(replies):
        return NetworkProbeObservation.unavailable(target, "ping_inconsistent_summary")
    if len(replies) != received or any(sequence < 1 or sequence > 3 for sequence in unique):
        return NetworkProbeObservation.unavailable(target, "ping_reply_mismatch")
    if returncode not in (0, 1) or (returncode == 0 and received == 0):
        return NetworkProbeObservation.unavailable(target, "ping_returncode_mismatch")
    rtts = sorted(rtt for _, rtt in replies)
    median = rtts[len(rtts) // 2] if len(rtts) % 2 else sum(rtts[0:2]) / 2
    return NetworkProbeObservation(
        status="available",
        target=target,
        sent=sent,
        received=received,
        lost=sent - received,
        loss_ratio=(sent - received) / sent,
        successful_sequences=sorted(unique),
        successful_rtts_ms=rtts,
        median_rtt_ms=median if rtts else None,
        route_error="route_pending",
        errors=[],
    )


def parse_route(output: str, target: str) -> tuple[str | None, int | None, str | None]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines or not lines[0].startswith(target + " "):
        return None, None, "route_malformed"
    match = re.search(r"(?:^|\s)dev\s+([a-zA-Z0-9_.:@-]{1,64})(?:\s|$)", lines[0])
    if match is None:
        return None, None, "route_interface_missing"
    name = match.group(1)
    try:
        return name, socket_ifindex(name), None
    except OSError:
        return None, None, "route_ifindex_unavailable"


def socket_ifindex(name: str) -> int:
    import socket

    return socket.if_nametoindex(name)


def _run_bounded(
    argv: list[str], timeout: float, output_limit: int
) -> tuple[int | None, str, str, str | None]:
    """Run in the worker's process group with a hard time and memory bound."""
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C"},
        )
    except FileNotFoundError:
        return None, "", "", "tool_missing"
    except PermissionError:
        return None, "", "", "spawn_permission_denied"
    assert process.stdout is not None and process.stderr is not None
    stdout_fd, stderr_fd = process.stdout.fileno(), process.stderr.fileno()
    selector = selectors.DefaultSelector()
    buffers = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    error = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error = "timeout"
                break
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, min(4096, output_limit + 1))
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                buffers[key.fd].extend(chunk)
                if sum(len(value) for value in buffers.values()) > output_limit:
                    error = "output_truncated"
                    break
            if error:
                break
        if error:
            process.kill()
        remaining = max(0.01, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=0.2)
            error = error or "timeout"
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=0.1)
        selector.close()
        process.stdout.close()
        process.stderr.close()
    stdout = bytes(buffers[stdout_fd][:output_limit]).decode("utf-8", "replace")
    stderr = bytes(buffers[stderr_fd][:output_limit]).decode("utf-8", "replace")
    return process.returncode, stdout, stderr, error


def _route(target: str, timeout: float) -> tuple[str | None, int | None, str | None]:
    returncode, stdout, stderr, error = _run_bounded(
        ["ip", "-4", "route", "get", target], timeout, 4096
    )
    if error:
        return None, None, "route_" + error
    if returncode:
        lowered = stderr.lower()
        denied = "permission" in lowered or (
            "cannot open netlink socket" in lowered
            and "address family not supported by protocol" in lowered
        )
        reason = "route_netlink_denied" if denied else "route_failed"
        return None, None, reason
    return parse_route(stdout, target)


def _ping(target: str, timeout: float) -> NetworkProbeObservation:
    returncode, stdout, stderr, error = _run_bounded([*PING_ARGV, target], timeout, MAX_PING_OUTPUT)
    if error:
        return NetworkProbeObservation.unavailable(target, "ping_" + error)
    if returncode is None:
        return NetworkProbeObservation.unavailable(target, "ping_spawn_failed")
    return parse_ping(stdout, stderr, returncode, target)


def _tcp_snapshot() -> tuple[
    dict[str, int] | None,
    dict[str, int],
    Literal["complete", "partial", "unavailable"],
    list[str],
]:
    errors: list[str] = []
    text, issue = _bounded_read("/proc/net/snmp")
    counters: dict[str, int] | None = None
    if issue:
        errors.append("tcp_snmp_" + issue)
    elif text is not None:
        rows = [line.split() for line in text.splitlines() if line.startswith("Tcp:")]
        if len(rows) >= 2 and len(rows[-2]) == len(rows[-1]):
            try:
                values = dict(
                    zip(rows[-2][1:], (int(value) for value in rows[-1][1:]), strict=True)
                )
                counters = {
                    "retrans_segs": values["RetransSegs"],
                    "curr_estab": values["CurrEstab"],
                }
            except (KeyError, ValueError):
                errors.append("tcp_snmp_malformed")
        else:
            errors.append("tcp_snmp_malformed")
    states = {name: 0 for name in TCP_STATES.values()}
    inventory_partial = False
    readable_inventories = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        body, read_issue = _bounded_read(path)
        if body is None:
            inventory_partial = True
            errors.append("tcp_inventory_" + (read_issue or "unavailable"))
            continue
        readable_inventories += 1
        lines = body.splitlines()[1:]
        if len(lines) > MAX_SOCKET_LINES or read_issue == "truncated":
            lines = lines[:MAX_SOCKET_LINES]
            inventory_partial = True
            errors.append("tcp_inventory_truncated")
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or fields[3] not in TCP_STATES:
                inventory_partial = True
                errors.append("tcp_inventory_malformed")
                continue
            states[TCP_STATES[fields[3]]] += 1
    coverage: Literal["complete", "partial", "unavailable"] = (
        "unavailable"
        if readable_inventories == 0
        else "partial"
        if inventory_partial or readable_inventories < 2
        else "complete"
    )
    return (
        counters,
        states if readable_inventories else {},
        coverage,
        list(dict.fromkeys(errors))[:8],
    )


def _interface_snapshot() -> tuple[
    dict[str, dict[str, int]], Literal["complete", "partial", "unavailable"], list[str]
]:
    text, issue = _bounded_read("/proc/net/dev")
    if text is None:
        return {}, "unavailable", ["interface_" + (issue or "unavailable")]
    result: dict[str, dict[str, int]] = {}
    errors: list[str] = []
    coverage: Literal["complete", "partial", "unavailable"] = "partial" if issue else "complete"
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        name = name.strip()
        fields = raw.split()
        if not re.fullmatch(r"[a-zA-Z0-9_.:@-]{1,64}", name) or len(fields) < 16:
            coverage = "partial"
            errors.append("interface_malformed")
            continue
        try:
            result[name] = {
                "rx_errors": int(fields[2]),
                "rx_dropped": int(fields[3]),
                "tx_errors": int(fields[10]),
                "tx_dropped": int(fields[11]),
            }
        except ValueError:
            coverage = "partial"
            errors.append("interface_malformed")
    if len(result) > MAX_INTERFACES:
        result = dict(sorted(result.items())[:MAX_INTERFACES])
        coverage = "partial"
        errors.append("interface_limit")
    return result, coverage, list(dict.fromkeys(errors))[:8]


def _bounded_network_observation(
    *,
    probe: NetworkProbeObservation,
    tcp: TcpNetworkObservation,
    interfaces: list[InterfaceNetworkObservation],
    interface_coverage: Literal["complete", "partial", "unavailable"],
    elapsed_seconds: float,
    errors: list[str],
) -> NetworkObservation:
    """Trim optional context until the mandatory probe fits the 8 KiB wire contract."""
    retained = list(interfaces)
    trimmed = False
    bounded_errors = list(dict.fromkeys(errors))[:8]
    current_tcp = tcp
    while True:
        try:
            return NetworkObservation(
                probe=probe,
                tcp=current_tcp,
                interfaces=retained,
                interface_coverage=("partial" if trimmed else interface_coverage),
                elapsed_seconds=elapsed_seconds,
                context_trimmed=trimmed,
                errors=bounded_errors,
            )
        except ValidationError as exc:
            if "network observation exceeds 8KiB" not in str(exc):
                raise
            trimmed = True
            if "network_context_trimmed" not in bounded_errors:
                bounded_errors = [*bounded_errors, "network_context_trimmed"][:8]
            if retained:
                retained.pop()
                continue
            if current_tcp.state_counts:
                current_tcp = current_tcp.model_copy(
                    update={
                        "state_counts": {},
                        "state_inventory": "partial",
                        "errors": [*current_tcp.errors, "network_context_trimmed"][:8],
                    }
                )
                continue
            current_tcp = TcpNetworkObservation(errors=["network_context_trimmed"])


class NetworkCollector:
    def __init__(self) -> None:
        self.previous_tcp: tuple[str, float, int] | None = None
        self.previous_interfaces: dict[tuple[str, int], tuple[str, float, dict[str, int]]] = {}

    def collect(self, target: str | None) -> NetworkObservation:
        started = time.monotonic()
        route_before: tuple[str | None, int | None, str | None]
        route_after: tuple[str | None, int | None, str | None]
        if target is None:
            probe = NetworkProbeObservation(
                status="unconfigured",
                route_error="target_unconfigured",
                errors=["target_unconfigured"],
            )
            target_key = "unconfigured"
            route_before = route_after = (None, None, "target_unconfigured")
        else:
            target_key = target
            deadline = started + 2.7
            route_before = _route(target, min(0.25, max(0.01, deadline - time.monotonic())))
            probe = _ping(target, min(2.1, max(0.01, deadline - time.monotonic())))
            route_after = _route(target, min(0.25, max(0.01, deadline - time.monotonic())))
        if route_before[:2] == route_after[:2] and route_before[0] is not None:
            probe = probe.model_copy(
                update={
                    "interface": route_before[0],
                    "interface_ifindex": route_before[1],
                    "route_status": "available",
                    "route_error": None,
                }
            )
        else:
            error = route_before[2] or route_after[2] or "route_changed"
            probe = probe.model_copy(update={"route_status": "unavailable", "route_error": error})
        counters, states, inventory, tcp_errors = _tcp_snapshot()
        now = time.monotonic()
        retrans = counters["retrans_segs"] if counters else None
        curr_estab = counters["curr_estab"] if counters else None
        tcp_interval = tcp_rate = None
        tcp_rate_status: Literal[
            "available",
            "baseline",
            "baseline_expired",
            "counter_reset",
            "identity_changed",
            "nonpositive_interval",
            "unavailable",
        ] = "baseline"
        if retrans is None:
            tcp_rate_status = "unavailable"
        elif self.previous_tcp is not None:
            old_target, old_at, old_value = self.previous_tcp
            interval = now - old_at
            if old_target != target_key:
                tcp_rate_status = "identity_changed"
            elif interval <= 0:
                tcp_rate_status = "nonpositive_interval"
            elif interval > 10:
                tcp_rate_status = "baseline_expired"
            elif retrans < old_value:
                tcp_rate_status = "counter_reset"
            else:
                tcp_interval, tcp_rate = interval, (retrans - old_value) / interval
                tcp_rate_status = "available"
        if retrans is not None:
            self.previous_tcp = (target_key, now, retrans)
        else:
            self.previous_tcp = None
        tcp = TcpNetworkObservation(
            retrans_segs=retrans,
            retrans_per_second=tcp_rate,
            rate_interval_seconds=tcp_interval,
            rate_status=tcp_rate_status,
            curr_estab=curr_estab,
            state_counts=states,
            state_inventory=inventory,
            errors=tcp_errors,
        )
        interface_values, interface_coverage, interface_errors = _interface_snapshot()
        interfaces: list[InterfaceNetworkObservation] = []
        for name, values in sorted(interface_values.items()):
            try:
                ifindex = socket_ifindex(name)
            except OSError:
                interface_coverage = "partial"
                interface_errors.append("interface_ifindex_unavailable")
                continue
            identity = name, ifindex
            old = self.previous_interfaces.get(identity)
            rates: dict[str, float | None] = {key + "_per_second": None for key in values}
            iface_interval: float | None = None
            statuses: dict[
                str,
                Literal[
                    "available",
                    "baseline",
                    "baseline_expired",
                    "counter_reset",
                    "identity_changed",
                    "nonpositive_interval",
                ],
            ] = {key: "baseline" for key in values}
            if old is not None:
                old_target, old_at, old_values = old
                iface_interval = now - old_at
                if old_target != target_key:
                    statuses = {key: "identity_changed" for key in values}
                    iface_interval = None
                elif iface_interval <= 0:
                    statuses = {key: "nonpositive_interval" for key in values}
                    iface_interval = None
                elif iface_interval > 10:
                    statuses = {key: "baseline_expired" for key in values}
                    iface_interval = None
                else:
                    rates = {
                        key + "_per_second": (
                            (value - old_values[key]) / iface_interval
                            if value >= old_values[key]
                            else None
                        )
                        for key, value in values.items()
                    }
                    statuses = {
                        key: "available" if value >= old_values[key] else "counter_reset"
                        for key, value in values.items()
                    }
                    if not any(value is not None for value in rates.values()):
                        iface_interval = None
            interfaces.append(
                InterfaceNetworkObservation(
                    name=name,
                    ifindex=ifindex,
                    rx_errors=values["rx_errors"],
                    rx_dropped=values["rx_dropped"],
                    tx_errors=values["tx_errors"],
                    tx_dropped=values["tx_dropped"],
                    rx_errors_per_second=rates["rx_errors_per_second"],
                    rx_dropped_per_second=rates["rx_dropped_per_second"],
                    tx_errors_per_second=rates["tx_errors_per_second"],
                    tx_dropped_per_second=rates["tx_dropped_per_second"],
                    rate_interval_seconds=iface_interval,
                    rate_status=statuses,
                )
            )
            self.previous_interfaces[identity] = (target_key, now, values)
        live_identities = {(item.name, item.ifindex) for item in interfaces}
        self.previous_interfaces = {
            key: value for key, value in self.previous_interfaces.items() if key in live_identities
        }
        if interface_coverage == "unavailable":
            self.previous_interfaces.clear()
        return _bounded_network_observation(
            probe=probe,
            tcp=tcp,
            interfaces=interfaces,
            interface_coverage=interface_coverage,
            elapsed_seconds=time.monotonic() - started,
            errors=interface_errors,
        )


def _proc_identity(pid: int) -> tuple[int, int, int] | None:
    """Return (process-group, session, starttime) from Linux procfs."""
    if os.name != "posix" or not Path("/proc").is_dir():
        return None
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        tail = value[value.rfind(")") + 2 :].split()
        return int(tail[2]), int(tail[3]), int(tail[19])
    except (OSError, ValueError, IndexError):
        return None


def _group_members(
    pgid: int,
    *,
    budget: float = PROC_SCAN_BUDGET_SECONDS,
    max_entries: int = MAX_PROC_SCAN,
) -> dict[int, int] | None:
    """List identities in the worker's owned Linux session, or None if unverifiable."""
    proc = Path("/proc")
    if os.name != "posix" or not proc.is_dir():
        return None
    members: dict[int, int] = {}
    deadline = time.monotonic() + budget
    scanned = 0
    try:
        with os.scandir(proc) as entries:
            for entry in entries:
                scanned += 1
                if scanned > max_entries or time.monotonic() > deadline:
                    return None
                if not entry.name.isdecimal():
                    continue
                pid = int(entry.name)
                identity = _proc_identity(pid)
                if identity is not None and identity[0] == pgid and identity[1] == pgid:
                    members[pid] = identity[2]
    except OSError:
        return None
    return members


def _stop_worker(_signum: int, _frame: object) -> None:
    raise SystemExit


def _worker(conn: Connection) -> None:
    try:
        os.setsid()
        signal.signal(signal.SIGTERM, _stop_worker)
        identity = _proc_identity(os.getpid())
        conn.send(
            {
                "ready": True,
                "pid": os.getpid(),
                "pgid": os.getpgrp(),
                "starttime": identity[2] if identity is not None else None,
            }
        )
        collector = NetworkCollector()
        while True:
            target = conn.recv()
            conn.send(collector.collect(target).model_dump())
    except (EOFError, BrokenPipeError):
        pass
    finally:
        conn.close()


class NetworkCollectionWorker:
    """A spawned process whose verified process group also contains ping."""

    def __init__(self, target: Callable[[Connection], None] = _worker) -> None:
        self.process: Any = None
        self.conn: Connection | None = None
        self.ready = False
        self.target = target
        self.pgid: int | None = None
        self.starttime: int | None = None
        self.stuck = False

    def start(self) -> None:
        if self.process is not None or self.stuck:
            return
        ctx = mp.get_context("spawn")
        self.conn, child = ctx.Pipe()
        self.process = ctx.Process(target=self.target, args=(child,), daemon=True)
        self.process.start()
        pid = self.process.pid
        identity = _proc_identity(pid) if os.name == "posix" and pid is not None else None
        self.starttime = identity[2] if identity is not None else None
        child.close()

    def wait_ready(self, timeout: float = 0) -> bool:
        self.start()
        if not self.ready and self.conn is not None:
            deadline = time.monotonic() + max(0.0, timeout)
            try:
                response = _receive_pickled_deadline(self.conn, MAX_READ, deadline)
                pid = self.process.pid if self.process is not None else None
                identity = _proc_identity(pid) if pid is not None else None
                self.ready = bool(
                    response.get("ready")
                    and response.get("pid") == pid == response.get("pgid")
                    and identity is not None
                    and identity == (pid, pid, response.get("starttime"))
                )
                self.pgid = pid if self.ready else None
                self.starttime = identity[2] if self.ready and identity is not None else None
                if not self.ready:
                    self.close()
            except _FrameTimeout as exc:
                if exc.partial:
                    self.close()
            except (AttributeError, OSError, EOFError, pickle.UnpicklingError, ValueError):
                self.close()
        return self.ready

    def close(self) -> None:
        was_ready = self.ready
        self.ready = False
        process = self.process
        if process is not None:
            pid = process.pid
            if os.name == "posix" and not was_ready:
                identity = _proc_identity(pid)
                if self.starttime is None or identity is None or identity[2] != self.starttime:
                    if process.is_alive():
                        self.stuck = True
                else:
                    process.terminate()
                    process.join(timeout=0.25)
                    if process.is_alive() and _proc_identity(pid) == identity:
                        process.kill()
                        process.join(timeout=0.25)
                    if process.is_alive():
                        self.stuck = True
                if not self.stuck and not process.is_alive():
                    process.close()
                    self.process = None
                if self.conn is not None:
                    self.conn.close()
                    self.conn = None
                self.pgid = None
                self.starttime = None
                return
            owned_group: dict[int, int] | None = None
            identity = _proc_identity(pid) if os.name == "posix" else None
            group_authorized = bool(
                self.pgid == pid
                and self.starttime is not None
                and identity == (pid, pid, self.starttime)
            )
            if group_authorized:
                owned_group = _group_members(pid)
                if owned_group is None or owned_group.get(pid) != self.starttime:
                    group_authorized = False
                    self.stuck = True
            if os.name == "posix" and group_authorized:
                try:
                    os.killpg(pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
            else:
                if process.is_alive() and os.name != "posix":
                    process.terminate()
                elif process.is_alive():
                    self.stuck = True
            process.join(timeout=0.25)
            survivors = _group_members(pid) if group_authorized else {}
            if survivors is None:
                self.stuck = True
            elif owned_group is not None and any(
                owned_group.get(member_pid) != starttime
                for member_pid, starttime in survivors.items()
            ):
                self.stuck = True
            elif survivors:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                limit = time.monotonic() + 0.25
                while time.monotonic() < limit:
                    survivors = _group_members(pid)
                    if survivors == {}:
                        break
                    if survivors is None or any(
                        owned_group is None or owned_group.get(member_pid) != starttime
                        for member_pid, starttime in survivors.items()
                    ):
                        self.stuck = True
                        break
                    time.sleep(0.01)
            if process.is_alive() and not self.stuck:
                if os.name != "posix":
                    process.kill()
                elif group_authorized:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.join(timeout=0.25)
            remaining = _group_members(pid) if group_authorized else {}
            if process.is_alive() or remaining not in ({}, None):
                self.stuck = True
            if remaining is None and group_authorized:
                self.stuck = True
            if self.stuck:
                self.process = process
            else:
                process.close()
                self.process = None
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        self.pgid = None
        self.starttime = None

    def collect(self, target: str | None, budget: float = 2.8) -> NetworkObservation:
        if os.name != "posix":
            return NetworkObservation.unavailable(target, "platform_unsupported")
        if self.stuck:
            return NetworkObservation.unavailable(target, "network_worker_stuck")
        if not self.wait_ready():
            return NetworkObservation.unavailable(target, "network_worker_starting")
        try:
            if self.conn is None:
                raise TimeoutError
            deadline = time.monotonic() + max(0.0, budget)
            self.conn.send(target)
            response = _receive_pickled_deadline(self.conn, MAX_READ, deadline)
            return NetworkObservation.model_validate(response)
        except (
            TimeoutError,
            OSError,
            EOFError,
            pickle.UnpicklingError,
            ValueError,
            ValidationError,
        ):
            self.close()
            return NetworkObservation.unavailable(target, "network_collection_timeout")
