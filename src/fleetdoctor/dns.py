"""Bounded uncached DNS collection and parent-owned baseline retention."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

import dns.exception
import dns.message
import dns.rcode
import dns.resolver
from pydantic import ValidationError

from fleetdoctor.network import _run_bounded
from fleetdoctor.schema import (
    DnsBaselineObservation,
    DnsObservation,
    DnsQueryObservation,
    NetworkProbeObservation,
    ResolverSnapshot,
)

RESOLV_CONF = Path("/etc/resolv.conf")
MAX_RESOLV_CONF = 32 * 1024
MAX_RESOLVED_OUTPUT = 16 * 1024
QUERY_LIFETIME = 1.2
MAX_BASELINES = 721
MAX_BASELINE_BYTES = 3072
MAX_HISTORY_BYTES = MAX_BASELINES * MAX_BASELINE_BYTES
MAX_BASELINE_AGE_SECONDS = 3600.0
SYSTEMD_STUBS = {"127.0.0.53", "127.0.0.54"}


def canonical_hostname(value: str) -> str:
    """Return a canonical absolute ASCII hostname without invoking DNS."""
    if not value or value != value.strip() or not value.endswith(".") or value != value.lower():
        raise ValueError("DNS hostname must be lowercase absolute ASCII with a trailing dot")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("DNS hostname must be ASCII") from exc
    labels = value[:-1].split(".")
    if len(labels) < 2 or any(
        not label
        or len(label.encode("ascii")) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise ValueError("DNS hostname must contain valid labels and at least two labels")
    if len(encoded) > 254 or sum(len(label.encode("ascii")) + 1 for label in labels) + 1 > 255:
        raise ValueError("DNS hostname exceeds the wire limit")
    return value


def configured_hostname(raw: str) -> str | None:
    return canonical_hostname(raw) if raw else None


def require_private_numeric_ingest(url: str, *, allow_loopback: bool = False) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.hostname is None:
        raise ValueError("DNS monitoring requires a plain HTTP numeric private-IP collector URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("DNS monitoring requires numeric collector addressing") from exc
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_reserved
        or (address.is_loopback and not allow_loopback)
        or (not address.is_private and not (allow_loopback and address.is_loopback))
    ):
        raise ValueError("DNS monitoring requires private numeric collector addressing")


@dataclass(frozen=True)
class _ResolverRead:
    snapshot: ResolverSnapshot
    identity: tuple[Any, ...]
    content: bytes


def _read_resolver(path: Path = RESOLV_CONF) -> _ResolverRead:
    try:
        before = path.lstat()
        if before.st_nlink != 1:
            raise ValueError("resolver_entry_hardlinked")
        entry_type: Literal["regular", "symlink"] = "symlink" if path.is_symlink() else "regular"
        if entry_type == "regular" and not path.is_file():
            raise ValueError("resolver_entry_unsupported")
        link_target = os.readlink(path) if entry_type == "symlink" else None
        with path.open("rb") as handle:
            content = handle.read(MAX_RESOLV_CONF + 1)
        if len(content) > MAX_RESOLV_CONF:
            raise ValueError("resolver_file_truncated")
        after = path.lstat()
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            entry_type,
            link_target,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            entry_type,
            link_target,
        ):
            raise ValueError("resolver_changed_during_read")
        text = content.decode("ascii")
        nameservers: list[str] = []
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if parts[0] != "nameserver":
                continue
            if len(parts) != 2:
                raise ValueError("resolver_nameserver_malformed")
            address = ipaddress.ip_address(parts[1])
            value = str(address)
            if value not in nameservers:
                nameservers.append(value)
            if len(nameservers) > 3:
                raise ValueError("resolver_nameserver_limit")
        if not nameservers:
            raise ValueError("resolver_nameserver_missing")
        fingerprint = hashlib.sha256(
            json.dumps(identity, separators=(",", ":"), default=str).encode() + b"\0" + content
        ).hexdigest()
        return _ResolverRead(
            ResolverSnapshot(
                status="available",
                nameservers=nameservers,
                fingerprint=fingerprint,
                entry_type=entry_type,
                link_target=link_target,
                known_systemd_stub=set(nameservers).issubset(SYSTEMD_STUBS),
            ),
            identity,
            content,
        )
    except (OSError, UnicodeError, ValueError, ValidationError) as exc:
        error = (
            str(exc)
            if isinstance(exc, ValueError) and str(exc).startswith("resolver_")
            else type(exc).__name__
        )
        raise ValueError(error[:128]) from exc


def _same_resolver(first: _ResolverRead, path: Path = RESOLV_CONF) -> bool:
    try:
        second = _read_resolver(path)
    except ValueError:
        return False
    return first.identity == second.identity and first.content == second.content


def _resolved_query(hostname: str) -> DnsQueryObservation:
    argv = [
        "resolvectl",
        "--cache=no",
        "--synthesize=no",
        "--zone=no",
        "--protocol=dns",
        "--type=A",
        "--legend=no",
        "query",
        hostname,
    ]
    help_code, help_out, help_err, help_problem = _run_bounded(
        ["resolvectl", "--help"], 0.4, MAX_RESOLVED_OUTPUT
    )
    help_text = help_out + help_err
    if help_problem == "tool_missing":
        return DnsQueryObservation(
            status="unavailable", hostname=hostname, error="resolvectl_missing", adapter="none"
        )
    required_flags = ("--cache", "--synthesize", "--protocol", "--type")
    if (
        help_code != 0
        or help_problem is not None
        or any(flag not in help_text for flag in required_flags)
    ):
        return DnsQueryObservation(
            status="unavailable",
            hostname=hostname,
            error="resolvectl_capability_unavailable",
            adapter="none",
        )
    started = time.monotonic()
    returncode, stdout, stderr, problem = _run_bounded(argv, QUERY_LIFETIME, MAX_RESOLVED_OUTPUT)
    elapsed = min(3.0, time.monotonic() - started)
    if problem == "output_truncated":
        return DnsQueryObservation(
            status="unavailable",
            hostname=hostname,
            error="resolvectl_output_truncated",
            adapter="none",
        )
    if problem == "timeout":
        return DnsQueryObservation(
            status="failure",
            hostname=hostname,
            duration_seconds=elapsed,
            error="query_timeout",
            adapter="systemd-resolved",
        )
    if problem is not None or returncode is None:
        return DnsQueryObservation(
            status="unavailable", hostname=hostname, error="resolvectl_spawn_failed", adapter="none"
        )
    combined = stdout + "\n" + stderr
    lowered = combined.lower()
    if any(
        token in lowered for token in ("unknown option", "unrecognized option", "access denied")
    ):
        return DnsQueryObservation(
            status="unavailable",
            hostname=hostname,
            error="resolvectl_unsupported_or_denied",
            adapter="none",
        )
    answers: list[str] = []
    aliases: dict[str, str] = {}
    records: list[tuple[str, str, str]] = []
    for raw_line in stdout.splitlines():
        match = re.fullmatch(r"\s*(\S+)\s+IN\s+(A|CNAME)\s+(\S+)\s*", raw_line)
        if match is None:
            if raw_line.strip():
                return DnsQueryObservation(
                    status="unavailable",
                    hostname=hostname,
                    error="resolvectl_output_unparseable",
                    adapter="none",
                )
            continue
        owner, record_type, value = match.groups()
        try:
            owner = canonical_hostname(owner if owner.endswith(".") else owner + ".")
            if record_type == "CNAME":
                aliases[owner] = canonical_hostname(value if value.endswith(".") else value + ".")
            else:
                address = ipaddress.ip_address(value)
                if address.version != 4 or str(address) != value:
                    raise ValueError
                records.append((owner, record_type, value))
        except ValueError:
            return DnsQueryObservation(
                status="unavailable",
                hostname=hostname,
                error="resolvectl_output_unparseable",
                adapter="none",
            )
    terminal = hostname
    seen: set[str] = set()
    while terminal in aliases and terminal not in seen and len(seen) <= 8:
        seen.add(terminal)
        terminal = aliases[terminal]
    for owner, _, value in records:
        if owner == terminal and value not in answers:
            answers.append(value)
        if len(answers) == 8:
            break
    if returncode == 0 and answers:
        return DnsQueryObservation(
            status="success",
            hostname=hostname,
            answers=answers,
            duration_seconds=elapsed,
            adapter="systemd-resolved",
        )
    if returncode == 0:
        return DnsQueryObservation(
            status="failure",
            hostname=hostname,
            duration_seconds=elapsed,
            error="no_a_answer",
            adapter="systemd-resolved",
        )
    measured_errors = ("nxdomain", "servfail", "refused", "no appropriate resource record")
    if any(token in lowered for token in measured_errors):
        return DnsQueryObservation(
            status="failure",
            hostname=hostname,
            duration_seconds=elapsed,
            error="resolver_response_error",
            adapter="systemd-resolved",
        )
    return DnsQueryObservation(
        status="unavailable",
        hostname=hostname,
        error="resolvectl_service_or_invocation_failed",
        adapter="none",
    )


def _read_proc_network(path: Path, limit: int) -> str | None:
    try:
        with path.open("rb") as handle:
            value = handle.read(limit + 1)
        if len(value) > limit:
            return None
        return value.decode("ascii")
    except (OSError, UnicodeError):
        return None


def _proc_local_addresses() -> set[str] | None:
    fib = _read_proc_network(Path("/proc/net/fib_trie"), 512 * 1024)
    inet6 = _read_proc_network(Path("/proc/net/if_inet6"), 64 * 1024)
    if fib is None or inet6 is None:
        return None
    addresses: set[str] = set()
    candidate: str | None = None
    for line in fib.splitlines():
        match = re.fullmatch(r"\s*[|+]--\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
        if match is not None:
            candidate = match.group(1)
        elif candidate is not None and re.fullmatch(r"\s*/\d+ host LOCAL", line):
            try:
                addresses.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                return None
            candidate = None
    try:
        for line in inet6.splitlines():
            parts = line.split()
            if len(parts) != 6 or len(parts[0]) != 32:
                return None
            addresses.add(str(ipaddress.IPv6Address(int(parts[0], 16))))
    except ValueError:
        return None
    return addresses


def _local_addresses() -> set[str] | None:
    proc = _proc_local_addresses()
    if proc is not None:
        return proc
    code, stdout, _, problem = _run_bounded(["ip", "-j", "address", "show"], 0.4, 32 * 1024)
    if code != 0 or problem is not None:
        return None
    try:
        rows = json.loads(stdout)
        return {
            str(ipaddress.ip_address(item["local"]))
            for row in rows
            for item in row.get("addr_info", [])
            if item.get("family") in ("inet", "inet6") and isinstance(item.get("local"), str)
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _measured_no_nameservers(exc: dns.resolver.NoNameservers) -> str | None:
    errors = getattr(exc, "kwargs", {}).get("errors")
    if not isinstance(errors, list) or not errors:
        return None
    rcodes: set[dns.rcode.Rcode] = set()
    for item in errors:
        if not isinstance(item, tuple) or len(item) != 5:
            return None
        problem, response = item[3], item[4]
        if not isinstance(problem, str) or not isinstance(response, dns.message.QueryMessage):
            return None
        rcode = response.rcode()
        if rcode not in (dns.rcode.SERVFAIL, dns.rcode.REFUSED):
            return None
        if problem != dns.rcode.to_text(rcode):
            return None
        rcodes.add(rcode)
    return "_".join(sorted(dns.rcode.to_text(code).lower() for code in rcodes))


def _direct_query(hostname: str, nameservers: list[str]) -> DnsQueryObservation:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = nameservers
    resolver.search = []
    resolver.timeout = QUERY_LIFETIME / max(1, len(nameservers))
    resolver.lifetime = QUERY_LIFETIME
    resolver.cache = None
    started = time.monotonic()
    try:
        answer = resolver.resolve(hostname, "A", search=False, lifetime=QUERY_LIFETIME)
        elapsed = min(3.0, time.monotonic() - started)
        values = sorted({str(item.address) for item in answer})[:8]
        if not values:
            raise dns.resolver.NoAnswer
        selected = str(answer.nameserver) if answer.nameserver is not None else None
        return DnsQueryObservation(
            status="success",
            hostname=hostname,
            answers=values,
            duration_seconds=elapsed,
            selected_server=selected,
            adapter="dnspython",
        )
    except dns.exception.Timeout:
        return DnsQueryObservation(
            status="failure",
            hostname=hostname,
            duration_seconds=min(3.0, time.monotonic() - started),
            error="query_timeout",
            adapter="dnspython",
        )
    except dns.resolver.NoNameservers as exc:
        response_error = _measured_no_nameservers(exc)
        if response_error is None:
            return DnsQueryObservation(
                status="unavailable",
                hostname=hostname,
                error="resolver_operation_unavailable",
                adapter="none",
            )
        return DnsQueryObservation(
            status="failure",
            hostname=hostname,
            duration_seconds=min(3.0, time.monotonic() - started),
            error=response_error,
            adapter="dnspython",
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
        return DnsQueryObservation(
            status="failure",
            hostname=hostname,
            duration_seconds=min(3.0, time.monotonic() - started),
            error=type(exc).__name__.lower()[:128],
            adapter="dnspython",
        )
    except (OSError, ValueError, dns.exception.DNSException) as exc:
        return DnsQueryObservation(
            status="unavailable", hostname=hostname, error=type(exc).__name__, adapter="none"
        )


class DnsCollector:
    def __init__(self, resolv_conf: Path = RESOLV_CONF) -> None:
        self.resolv_conf = resolv_conf

    def collect(self, hostname: str | None, direct_ip_target: str | None) -> DnsObservation:
        started = time.monotonic()
        if hostname is None:
            return DnsObservation.unavailable(None, None, "dns_unconfigured")
        try:
            canonical_hostname(hostname)
            if direct_ip_target is None:
                raise ValueError("direct_ip_target_missing")
            first = _read_resolver(self.resolv_conf)
        except (ValueError, ValidationError) as exc:
            return DnsObservation.unavailable(hostname, direct_ip_target, str(exc)[:128])
        query = (
            _resolved_query(hostname)
            if first.snapshot.known_systemd_stub
            else DnsQueryObservation(
                status="unavailable",
                hostname=hostname,
                error="unknown_node_local_caching_stub",
                adapter="none",
            )
            if any(ipaddress.ip_address(value).is_loopback for value in first.snapshot.nameservers)
            or (local := _local_addresses()) is None
            or any(value in local for value in first.snapshot.nameservers)
            else _direct_query(hostname, first.snapshot.nameservers)
        )
        if not _same_resolver(first, self.resolv_conf):
            return DnsObservation.unavailable(
                hostname, direct_ip_target, "resolver_changed_during_query"
            )
        return DnsObservation(
            hostname=hostname,
            direct_ip_target=direct_ip_target,
            resolver=first.snapshot,
            query=query,
            retention_coverage="complete",
            elapsed_seconds=min(3.0, time.monotonic() - started),
        )


@dataclass(frozen=True)
class _StoredBaseline:
    encoded: bytes
    captured_monotonic: float
    observed_at: datetime
    sequence: int
    median_rtt_ms: float


class DnsBaselineHistory:
    """Bounded parent-process history; only one selected candidate crosses the wire."""

    def __init__(self) -> None:
        self._scope: tuple[str, UUID, UUID, str, str] | None = None
        self._items: dict[tuple[str, str, int], _StoredBaseline] = {}
        self._serialized_bytes = 0
        self.coverage_complete = True

    @property
    def count(self) -> int:
        return len(self._items)

    @property
    def serialized_bytes(self) -> int:
        return self._serialized_bytes

    def _clear(self) -> None:
        self._items.clear()
        self._serialized_bytes = 0

    def attach(
        self,
        observation: DnsObservation,
        *,
        node_id: str,
        boot_id: UUID,
        agent_session_id: UUID,
        sequence: int,
        observed_at: datetime,
        direct_ip_probe: NetworkProbeObservation,
        monotonic_now: float | None = None,
    ) -> DnsObservation:
        now_mono = time.monotonic() if monotonic_now is None else monotonic_now
        if observation.hostname is None or observation.direct_ip_target is None:
            self._scope = None
            self._clear()
            self.coverage_complete = True
            return observation
        scope = (
            node_id,
            boot_id,
            agent_session_id,
            observation.hostname,
            observation.direct_ip_target,
        )
        if self._scope != scope:
            self._scope = scope
            self._clear()
            self.coverage_complete = True
        retained: dict[tuple[str, str, int], _StoredBaseline] = {}
        for key, item in self._items.items():
            wire_age = (observed_at - item.observed_at).total_seconds()
            if (
                0 <= wire_age <= MAX_BASELINE_AGE_SECONDS
                and 0 <= now_mono - item.captured_monotonic <= MAX_BASELINE_AGE_SECONDS
            ):
                retained[key] = item
        self._items = retained
        self._serialized_bytes = sum(len(item.encoded) for item in retained.values())
        candidate_error = None
        if (
            observation.query.status == "success"
            and observation.resolver.status == "available"
            and direct_ip_probe.status == "available"
            and direct_ip_probe.target == observation.direct_ip_target
            and direct_ip_probe.sent == 3
            and direct_ip_probe.received == 3
            and direct_ip_probe.lost == 0
            and direct_ip_probe.median_rtt_ms is not None
        ):
            try:
                assert observation.resolver.fingerprint is not None
                candidate = DnsBaselineObservation(
                    node_id=node_id,
                    boot_id=boot_id,
                    agent_session_id=agent_session_id,
                    sequence=sequence,
                    observed_at=observed_at,
                    hostname=observation.hostname,
                    direct_ip_target=observation.direct_ip_target,
                    query=observation.query,
                    direct_ip_probe=direct_ip_probe,
                    resolver_fingerprint=observation.resolver.fingerprint,
                    resolver_nameservers=observation.resolver.nameservers,
                )
                encoded = candidate.model_dump_json().encode("utf-8")
                if len(encoded) > MAX_BASELINE_BYTES:
                    raise ValueError("baseline_candidate_oversize")
                key = (str(boot_id), str(agent_session_id), sequence)
                if key not in self._items:
                    self._items[key] = _StoredBaseline(
                        encoded,
                        now_mono,
                        observed_at,
                        sequence,
                        direct_ip_probe.median_rtt_ms,
                    )
                    self._serialized_bytes += len(encoded)
                    while len(self._items) > MAX_BASELINES:
                        oldest = min(self._items, key=lambda item: self._items[item].sequence)
                        self._serialized_bytes -= len(self._items.pop(oldest).encoded)
                        self.coverage_complete = False
            except (AssertionError, ValueError, ValidationError) as exc:
                candidate_error = str(exc)[:128] or type(exc).__name__
        selected = min(
            self._items.values(),
            key=lambda item: (item.median_rtt_ms, -item.sequence),
            default=None,
        )
        baseline = (
            DnsBaselineObservation.model_validate_json(selected.encoded)
            if selected is not None
            else None
        )
        if self.serialized_bytes > MAX_HISTORY_BYTES:
            raise RuntimeError("DNS baseline history exceeded its serialized byte bound")
        update = observation.model_dump(mode="python")
        update.update(
            baseline=baseline,
            retention_coverage="complete" if self.coverage_complete else "incomplete",
            candidate_error=candidate_error,
        )
        try:
            return DnsObservation.model_validate(update)
        except ValidationError as exc:
            if "DNS observation exceeds 8KiB" not in str(exc):
                raise
            resolver = observation.resolver.model_dump(mode="python")
            resolver["errors"] = ["payload_budget"]
            update.update(
                resolver=resolver,
                context_trimmed=True,
                candidate_error=candidate_error or "optional_context_compacted",
            )
            return DnsObservation.model_validate(update)
