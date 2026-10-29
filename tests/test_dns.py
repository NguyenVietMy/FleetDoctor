import ipaddress
import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast
from uuid import UUID

import dns.exception
import dns.message
import dns.rcode
import dns.resolver
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

import fleetdoctor.dns as dns_module
import fleetdoctor.network as network_module
from fleetdoctor.agent import make_sample
from fleetdoctor.collector import create_app
from fleetdoctor.delivery import DeliveryQueue
from fleetdoctor.dns import (
    MAX_BASELINES,
    MAX_HISTORY_BYTES,
    DnsBaselineHistory,
    DnsCollector,
    canonical_hostname,
    require_private_numeric_ingest,
)
from fleetdoctor.incidents import DnsConfig, Incident
from fleetdoctor.rules import DnsEvaluator, _valid_dns_baseline
from fleetdoctor.schema import (
    CpuObservation,
    DnsBaselineObservation,
    DnsObservation,
    DnsQueryObservation,
    FdObservation,
    Filesystem,
    HostMemoryObservation,
    MemoryObservation,
    NetworkObservation,
    NetworkProbeObservation,
    ResolverSnapshot,
    Sample,
    TcpNetworkObservation,
)
from fleetdoctor.store import FixtureStore

BOOT = UUID("11111111-1111-1111-1111-111111111111")
SESSION = UUID("22222222-2222-2222-2222-222222222222")
TARGET = "192.0.2.10"
HOSTNAME = "baseline.fleetdoctor.test."
NOW = datetime(2026, 10, 24, 16, 0, tzinfo=UTC)


def probe(rtt: float = 20.0, *, lost: int = 0, target: str = TARGET) -> NetworkProbeObservation:
    received = 3 - lost
    rtts = [rtt] * received
    return NetworkProbeObservation(
        status="available",
        target=target,
        sent=3,
        received=received,
        lost=lost,
        loss_ratio=lost / 3,
        successful_sequences=list(range(1, received + 1)),
        successful_rtts_ms=rtts,
        median_rtt_ms=rtt if rtts else None,
        route_error="fixture_unknown_route",
    )


def network(value: NetworkProbeObservation | None = None) -> NetworkObservation:
    return NetworkObservation(
        probe=value or probe(),
        tcp=TcpNetworkObservation(errors=["fixture"]),
        interface_coverage="unavailable",
        errors=["fixture"],
    )


def resolver() -> ResolverSnapshot:
    return ResolverSnapshot(
        status="available",
        nameservers=["192.0.2.53"],
        fingerprint="a" * 64,
        entry_type="regular",
    )


def raw_dns(
    status: Literal["success", "failure", "unavailable"],
    *,
    hostname: str = HOSTNAME,
    error: str | None = None,
) -> DnsObservation:
    query = (
        DnsQueryObservation(
            status="success",
            hostname=hostname,
            answers=["192.0.2.80"],
            duration_seconds=0.01,
            selected_server="192.0.2.53",
            adapter="dnspython",
        )
        if status == "success"
        else DnsQueryObservation(
            status=status,
            hostname=hostname,
            duration_seconds=0.02 if status == "failure" else None,
            error=error or "servfail",
            adapter="dnspython" if status == "failure" else "none",
        )
    )
    return DnsObservation(
        hostname=hostname,
        direct_ip_target=TARGET,
        resolver=resolver(),
        query=query,
        retention_coverage="complete",
    )


def sample(
    sequence: int,
    status: Literal["success", "failure", "unavailable"],
    *,
    observed: datetime | None = None,
    rtt: float = 20.0,
    lost: int = 0,
    hostname: str = HOSTNAME,
    baseline: DnsBaselineObservation | None = None,
) -> Any:
    current_probe = probe(rtt, lost=lost)
    dns = raw_dns(status, hostname=hostname).model_copy(update={"baseline": baseline})
    return make_sample(
        "node-a",
        BOOT,
        SESSION,
        sequence,
        [Filesystem(mountpoint="/", errors=["fixture"])],
        observed or NOW + timedelta(seconds=sequence * 5),
        cpu=CpuObservation(errors=["fixture"]),
        memory=MemoryObservation(host=HostMemoryObservation(errors=["fixture"])),
        fd=FdObservation(errors=["fixture"]),
        network=network(current_probe),
        dns=dns,
    )


def baseline_for(
    hostname: str = HOSTNAME, *, sequence: int = 0, rtt: float = 20.0
) -> DnsBaselineObservation:
    return DnsBaselineObservation(
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=sequence,
        observed_at=NOW + timedelta(seconds=sequence * 5),
        hostname=hostname,
        direct_ip_target=TARGET,
        query=raw_dns("success", hostname=hostname).query,
        direct_ip_probe=probe(rtt),
        resolver_fingerprint="a" * 64,
        resolver_nameservers=["192.0.2.53"],
    )


@pytest.mark.parametrize(
    "value",
    ["Example.COM.", "single.", "missing-dot.example", "-bad.example.", "bad..example."],
)
def test_hostname_is_canonical_at_configuration_and_wire_boundaries(value: str) -> None:
    with pytest.raises(ValueError):
        canonical_hostname(value)
    with pytest.raises(ValidationError):
        DnsQueryObservation(status="failure", hostname=value, duration_seconds=0.1, error="x")


def test_private_numeric_ingestion_rejects_names_public_unspecified_and_implicit_loopback() -> None:
    for url in ("http://collector:8000/ingest", "http://8.8.8.8/ingest", "http://0.0.0.0"):
        with pytest.raises(ValueError):
            require_private_numeric_ingest(url)
    require_private_numeric_ingest("http://10.0.0.2:8000/ingest")
    require_private_numeric_ingest("http://127.0.0.1:8000/ingest", allow_loopback=True)


def test_resolved_parser_accepts_exact_a_owner_and_rejects_diagnostic_ipv4(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = iter(
        [
            (0, "--cache --synthesize --protocol --type", "", None),
            (0, "baseline.fleetdoctor.test IN A 10.77.0.9\n", "", None),
        ]
    )
    monkeypatch.setattr(dns_module, "_run_bounded", lambda *args, **kwargs: next(responses))
    good = dns_module._resolved_query(HOSTNAME)
    assert good.status == "success" and good.answers == ["10.77.0.9"]

    responses = iter(
        [
            (0, "--cache --synthesize --protocol --type", "", None),
            (1, "", "resolve call failed via 10.77.0.9: Network is down", None),
        ]
    )
    monkeypatch.setattr(dns_module, "_run_bounded", lambda *args, **kwargs: next(responses))
    unavailable = dns_module._resolved_query(HOSTNAME)
    assert unavailable.status == "unavailable" and unavailable.answers == []


def test_resolved_overflow_and_stall_are_bounded_and_reaped(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("real child pipe behavior requires Linux")
    flood = tmp_path / "flood.py"
    flood.write_text("import os\nwhile True: os.write(1, b'x'*4096)\n", encoding="utf-8")
    started = time.monotonic()
    _, _, _, error = network_module._run_bounded([sys.executable, str(flood)], 1, 4096)
    assert error == "output_truncated" and time.monotonic() - started < 2
    stall = tmp_path / "stall.py"
    stall.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    started = time.monotonic()
    _, _, _, error = network_module._run_bounded([sys.executable, str(stall)], 0.2, 4096)
    assert error == "timeout" and time.monotonic() - started < 1


def test_unknown_local_stub_is_unavailable_not_directly_queried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "resolv.conf"
    path.write_text("nameserver 127.0.0.11\n", encoding="ascii")
    monkeypatch.setattr(dns_module, "_local_addresses", lambda: {"127.0.0.11"})
    monkeypatch.setattr(
        dns_module,
        "_direct_query",
        lambda *_: pytest.fail("unknown local cache must not use the direct adapter"),
    )
    value = DnsCollector(path).collect(HOSTNAME, TARGET)
    assert value.query.status == "unavailable"
    assert value.query.error == "unknown_node_local_caching_stub"


def test_nonloopback_local_stub_and_unknown_inventory_are_never_directly_queried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "resolv.conf"
    path.write_text("nameserver 10.77.0.2\n", encoding="ascii")
    monkeypatch.setattr(
        dns_module,
        "_direct_query",
        lambda *_: pytest.fail("unproved nonlocal resolver must not use direct adapter"),
    )
    monkeypatch.setattr(dns_module, "_local_addresses", lambda: {"127.0.0.1", "10.77.0.2"})
    local = DnsCollector(path).collect(HOSTNAME, TARGET)
    assert local.query.status == "unavailable"
    assert local.query.error == "unknown_node_local_caching_stub"

    monkeypatch.setattr(dns_module, "_local_addresses", lambda: None)
    unknown = DnsCollector(path).collect(HOSTNAME, TARGET)
    assert unknown.query.status == "unavailable"
    assert unknown.query.error == "unknown_node_local_caching_stub"


def test_proc_local_address_inventory_does_not_require_netlink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fib = """Main:
  +-- 0.0.0.0/0 2 0 2
     +-- 10.77.0.0/24 2 0 2
        |-- 10.77.0.2
           /32 host LOCAL
"""
    inet6 = "00000000000000000000000000000001 01 80 10 80 lo\n"
    monkeypatch.setattr(
        dns_module,
        "_read_proc_network",
        lambda path, _limit: inet6 if path.name == "if_inet6" else fib,
    )
    assert dns_module._proc_local_addresses() == {"10.77.0.2", "::1"}


def no_nameservers(
    error: BaseException | str, rcode: dns.rcode.Rcode | None = None
) -> dns.resolver.NoNameservers:
    request = dns.message.make_query(HOSTNAME, "A")
    response = dns.message.make_response(request) if rcode is not None else None
    if rcode is not None:
        assert response is not None
        response.set_rcode(rcode)
    return dns.resolver.NoNameservers(  # type: ignore[no-untyped-call]
        request=request,
        errors=[("192.0.2.53", False, 53, error, response)],
    )


@pytest.mark.parametrize(
    "problem,rcode,status,error",
    [
        (PermissionError(13, "denied"), None, "unavailable", "resolver_operation_unavailable"),
        (
            dns.exception.FormError(),  # type: ignore[no-untyped-call]
            None,
            "unavailable",
            "resolver_operation_unavailable",
        ),
        ("SERVFAIL", dns.rcode.SERVFAIL, "failure", "servfail"),
        ("REFUSED", dns.rcode.REFUSED, "failure", "refused"),
    ],
)
def test_direct_adapter_classifies_no_nameservers_provenance(
    monkeypatch: pytest.MonkeyPatch,
    problem: BaseException | str,
    rcode: dns.rcode.Rcode | None,
    status: str,
    error: str,
) -> None:
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        lambda *args, **kwargs: (_ for _ in ()).throw(no_nameservers(problem, rcode)),
    )
    result = dns_module._direct_query(HOSTNAME, ["192.0.2.53"])
    assert result.status == status and result.error == error
    assert result.adapter == ("dnspython" if status == "failure" else "none")


def test_direct_adapter_timeout_remains_measured_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            dns.exception.Timeout()  # type: ignore[no-untyped-call]
        ),
    )
    result = dns_module._direct_query(HOSTNAME, ["192.0.2.53"])
    assert result.status == "failure"
    assert result.error == "query_timeout"
    assert result.adapter == "dnspython"


@pytest.mark.parametrize(
    "case,opens",
    [
        ("permission", False),
        ("parse", False),
        ("servfail", True),
        ("refused", True),
        ("timeout", True),
    ],
)
def test_direct_adapter_provenance_controls_actual_ingest_rule(
    monkeypatch: pytest.MonkeyPatch, case: str, opens: bool
) -> None:
    def resolve(*args: Any, **kwargs: Any) -> Any:
        if case == "permission":
            raise no_nameservers(PermissionError(13, "denied"))
        if case == "parse":
            raise no_nameservers(
                dns.exception.FormError()  # type: ignore[no-untyped-call]
            )
        if case == "timeout":
            raise dns.exception.Timeout
        rcode = dns.rcode.SERVFAIL if case == "servfail" else dns.rcode.REFUSED
        raise no_nameservers(dns.rcode.to_text(rcode), rcode)

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    query = dns_module._direct_query(HOSTNAME, ["192.0.2.53"])
    clock = [NOW + timedelta(seconds=5)]
    client = TestClient(
        create_app(
            {"node-a": SecretStr("a" * 32)},
            store=FixtureStore(),
            clock=lambda: clock[0],
            dns_config=DnsConfig(consecutive_samples=3),
        )
    )
    headers = {"Authorization": "Bearer " + "a" * 32}
    baseline = baseline_for()
    for sequence in range(1, 4):
        base = sample(sequence, "failure", baseline=baseline)
        dns_value = DnsObservation.model_validate(
            base.dns.model_dump(mode="python") | {"query": query}
        )
        current = Sample.model_validate(base.model_dump(mode="python") | {"dns": dns_value})
        clock[0] = current.observed_at
        client.post(
            "/ingest", content=current.model_dump_json(), headers=headers
        ).raise_for_status()
    assert (client.get("/diagnoses", params={"status": "active"}).json()["total"] == 1) is opens


def test_history_keeps_minimum_rtt_and_selects_newest_equal_tie() -> None:
    history = DnsBaselineHistory()
    first = history.attach(
        raw_dns("success"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=0,
        observed_at=NOW,
        direct_ip_probe=probe(20),
        monotonic_now=100,
    )
    assert first.baseline is not None and first.baseline.direct_ip_probe.median_rtt_ms == 20
    second = history.attach(
        raw_dns("success"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=1,
        observed_at=NOW + timedelta(seconds=5),
        direct_ip_probe=probe(200),
        monotonic_now=105,
    )
    assert second.baseline is not None and second.baseline.sequence == 0
    tied = history.attach(
        raw_dns("success"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=2,
        observed_at=NOW + timedelta(seconds=10),
        direct_ip_probe=probe(20),
        monotonic_now=110,
    )
    assert tied.baseline is not None and tied.baseline.sequence == 2


@pytest.mark.parametrize("limit,opens", [(10.0, False), (150.0, True), (250.0, True)])
def test_minimum_rtt_history_drives_actual_opening_threshold(limit: float, opens: bool) -> None:
    history = DnsBaselineHistory()
    for sequence, rtt in ((0, 20.0), (1, 200.0)):
        attached = history.attach(
            raw_dns("success"),
            node_id="node-a",
            boot_id=BOOT,
            agent_session_id=SESSION,
            sequence=sequence,
            observed_at=NOW + timedelta(seconds=sequence * 5),
            direct_ip_probe=probe(rtt),
            monotonic_now=float(sequence * 5),
        )
    assert attached.baseline is not None
    assert attached.baseline.sequence == 0
    assert attached.baseline.direct_ip_probe.median_rtt_ms == 20.0
    evaluator = DnsEvaluator([])
    previous = sample(1, "success", baseline=attached.baseline)
    changes: list[Incident] = []
    for sequence in range(2, 5):
        current = sample(sequence, "failure", baseline=attached.baseline)
        changes = evaluator.evaluate(
            current,
            previous,
            current.observed_at,
            DnsConfig(direct_ip_rtt_max_ms=limit),
        )
        previous = current
    assert bool(changes) is opens


def test_local_baseline_survives_delivery_retry_compaction_and_lost_ack() -> None:
    history = DnsBaselineHistory()
    healthy_dns = history.attach(
        raw_dns("success"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=0,
        observed_at=NOW,
        direct_ip_probe=probe(20),
        monotonic_now=0,
    )
    healthy = sample(0, "success", baseline=healthy_dns.baseline)
    queue = DeliveryQueue(max_count=1)
    entry = queue.enqueue(healthy, NOW)
    assert entry is not None and queue.select(NOW) is entry
    original = entry.body
    queue.complete(entry, "retry", NOW)  # transport failure: collector never saw it
    assert queue.select(NOW) is entry and entry.body is original
    queue.complete(entry, "retry", NOW)  # acknowledgement may have been lost
    replacement = queue.enqueue(sample(1, "failure"), NOW + timedelta(seconds=5))
    assert replacement is not None and queue.reasons == {"capacity": 1}
    later = history.attach(
        raw_dns("failure"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=2,
        observed_at=NOW + timedelta(seconds=10),
        direct_ip_probe=probe(20),
        monotonic_now=10,
    )
    assert later.baseline is not None and later.baseline.sequence == 0


def test_history_scope_restart_and_invalid_new_candidate_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    history = DnsBaselineHistory()
    first = history.attach(
        raw_dns("success"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=0,
        observed_at=NOW,
        direct_ip_probe=probe(20),
        monotonic_now=0,
    )
    assert first.baseline is not None and history.count == 1

    original_dump = DnsBaselineObservation.model_dump_json
    monkeypatch.setattr(
        DnsBaselineObservation,
        "model_dump_json",
        lambda self, *args, **kwargs: (
            "x" * 3073 if self.sequence == 1 else original_dump(self, *args, **kwargs)
        ),
    )
    invalid = history.attach(
        raw_dns("success"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=1,
        observed_at=NOW + timedelta(seconds=5),
        direct_ip_probe=probe(10),
        monotonic_now=5,
    )
    assert invalid.baseline is not None and invalid.baseline.sequence == 0
    assert invalid.candidate_error is not None
    assert "DNS baseline exceeds 3072 bytes" in invalid.candidate_error
    assert history.count == 1
    monkeypatch.setattr(DnsBaselineObservation, "model_dump_json", original_dump)

    changed_session = history.attach(
        raw_dns("failure"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=UUID("33333333-3333-3333-3333-333333333333"),
        sequence=2,
        observed_at=NOW + timedelta(seconds=10),
        direct_ip_probe=probe(),
        monotonic_now=10,
    )
    assert changed_session.baseline is None and history.count == 0
    restarted_agent = DnsBaselineHistory()
    assert restarted_agent.count == 0


def test_backward_clock_clears_future_history_candidate() -> None:
    history = DnsBaselineHistory()
    history.attach(
        raw_dns("success"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=0,
        observed_at=NOW,
        direct_ip_probe=probe(),
        monotonic_now=100,
    )
    result = history.attach(
        raw_dns("failure"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=1,
        observed_at=NOW - timedelta(seconds=1),
        direct_ip_probe=probe(),
        monotonic_now=99,
    )
    assert result.baseline is None and history.count == 0


def test_history_cap_duplicate_and_serialized_bounds() -> None:
    history = DnsBaselineHistory()
    for sequence in range(MAX_BASELINES + 1):
        history.attach(
            raw_dns("success"),
            node_id="node-a",
            boot_id=BOOT,
            agent_session_id=SESSION,
            sequence=sequence,
            observed_at=NOW + timedelta(seconds=sequence),
            direct_ip_probe=probe(float(20 + sequence % 2)),
            monotonic_now=100 + sequence,
        )
    assert history.count == MAX_BASELINES
    assert history.serialized_bytes <= MAX_HISTORY_BYTES
    assert history.coverage_complete is False
    before = history.count
    history.attach(
        raw_dns("success"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=MAX_BASELINES,
        observed_at=NOW + timedelta(seconds=MAX_BASELINES),
        direct_ip_probe=probe(21),
        monotonic_now=100 + MAX_BASELINES,
    )
    assert history.count == before


def test_history_prunes_expired_boundary_before_capacity_admission() -> None:
    history = DnsBaselineHistory()
    latest = raw_dns("success")
    for sequence in range(722):
        latest = history.attach(
            raw_dns("success"),
            node_id="node-a",
            boot_id=BOOT,
            agent_session_id=SESSION,
            sequence=sequence,
            observed_at=NOW + timedelta(seconds=sequence * 5),
            direct_ip_probe=probe(20),
            monotonic_now=float(sequence * 5),
        )
    assert history.count == MAX_BASELINES
    assert history.coverage_complete is True
    assert latest.retention_coverage == "complete"


def test_history_inclusive_hour_and_next_best_fallback() -> None:
    history = DnsBaselineHistory()
    for sequence, rtt in ((1, 10.0), (2, 20.0)):
        history.attach(
            raw_dns("success"),
            node_id="node-a",
            boot_id=BOOT,
            agent_session_id=SESSION,
            sequence=sequence,
            observed_at=NOW + timedelta(seconds=sequence),
            direct_ip_probe=probe(rtt),
            monotonic_now=float(sequence),
        )
    at_boundary = history.attach(
        raw_dns("failure"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=3,
        observed_at=NOW + timedelta(seconds=3601),
        direct_ip_probe=probe(),
        monotonic_now=3601.0,
    )
    assert at_boundary.baseline is not None and at_boundary.baseline.sequence == 1
    after_boundary = history.attach(
        raw_dns("failure"),
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=4,
        observed_at=NOW + timedelta(seconds=3602),
        direct_ip_probe=probe(),
        monotonic_now=3602.0,
    )
    assert after_boundary.baseline is not None and after_boundary.baseline.sequence == 2


def test_failing_query_requires_strictly_earlier_baseline_sequence_and_time() -> None:
    baseline = baseline_for(sequence=1).model_copy(
        update={"observed_at": NOW + timedelta(seconds=4)}
    )
    current = sample(1, "failure", observed=NOW + timedelta(seconds=5), baseline=baseline)
    assert _valid_dns_baseline(current, baseline, 150.0) == (
        False,
        "known_good_baseline_not_historical",
    )


def test_current_success_baseline_requires_matching_resolver_provenance() -> None:
    baseline = baseline_for(sequence=0).model_copy(update={"resolver_fingerprint": "b" * 64})
    current = sample(0, "success", observed=NOW, baseline=baseline)
    assert _valid_dns_baseline(current, baseline, 150.0) == (
        False,
        "known_good_baseline_current_fact_mismatch",
    )
    historical = sample(
        1,
        "failure",
        observed=NOW + timedelta(seconds=5),
        baseline=baseline.model_copy(update={"sequence": 0, "observed_at": NOW}),
    )
    assert _valid_dns_baseline(historical, historical.dns.baseline, 150.0) == (True, None)


def test_max_dns_context_attaches_baseline_with_explicit_validated_compaction() -> None:
    hostname = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 60)) + "."
    current = DnsObservation(
        hostname=hostname,
        direct_ip_target=TARGET,
        resolver=ResolverSnapshot(
            status="available",
            nameservers=["192.0.2.53", "2001:db8::53", "2001:db8::54"],
            fingerprint="f" * 64,
            entry_type="symlink",
            link_target="/" + "l" * 4095,
            errors=[str(index) + "e" * 127 for index in range(8)],
        ),
        query=DnsQueryObservation(
            status="success",
            hostname=hostname,
            answers=[f"198.51.100.{index}" for index in range(1, 9)],
            duration_seconds=1.2,
            selected_server="2001:db8::53",
            adapter="dnspython",
        ),
        retention_coverage="complete",
    )
    maximum_probe = probe(20).model_copy(update={"errors": ["p" * 128] * 8})
    attached = DnsBaselineHistory().attach(
        current,
        node_id="node-a",
        boot_id=BOOT,
        agent_session_id=SESSION,
        sequence=0,
        observed_at=NOW,
        direct_ip_probe=maximum_probe,
        monotonic_now=0,
    )
    assert attached.baseline is not None
    assert attached.context_trimmed is True
    assert attached.resolver.errors == ["payload_budget"]
    assert attached.query == current.query
    assert len(attached.model_dump_json().encode()) <= 8192
    assert DnsObservation.model_validate_json(attached.model_dump_json()) == attached


def test_maximum_history_uses_bounded_production_objects_and_index() -> None:
    history = DnsBaselineHistory()
    for sequence in range(MAX_BASELINES):
        history.attach(
            raw_dns("success"),
            node_id="node-a",
            boot_id=BOOT,
            agent_session_id=SESSION,
            sequence=sequence,
            observed_at=NOW + timedelta(seconds=sequence),
            direct_ip_probe=probe(20),
            monotonic_now=float(sequence),
        )
    assert history.count == MAX_BASELINES
    assert history.serialized_bytes <= MAX_HISTORY_BYTES
    index_bytes = sys.getsizeof(history._items) + sum(
        sys.getsizeof(key) + sys.getsizeof(value) for key, value in history._items.items()
    )
    assert index_bytes < 512 * 1024


def test_dns_rule_opens_after_three_failures_and_recovers_after_three_successes() -> None:
    config = DnsConfig()
    evaluator = DnsEvaluator([])
    base = baseline_for()
    previous = sample(0, "success", baseline=base)
    changes = []
    for sequence in range(1, 4):
        current = sample(sequence, "failure", baseline=base)
        changes = evaluator.evaluate(current, previous, current.observed_at, config)
        previous = current
    assert len(changes) == 1
    incident = changes[0]
    assert incident.rule == "dns_resolution_failure" and incident.status == "active"
    assert incident.opening_evidence["dns_conclusive"] is True
    for sequence in range(4, 7):
        current = sample(sequence, "success", baseline=base)
        changes = evaluator.evaluate(current, previous, current.observed_at, config)
        previous = current
    assert changes[0].id == incident.id and changes[0].status == "resolved"
    assert Incident.model_validate_json(changes[0].model_dump_json()) == changes[0]


def test_scope_change_preserves_frozen_opening_and_nested_current_dns_facts() -> None:
    evaluator = DnsEvaluator([])
    baseline = baseline_for()
    previous = sample(0, "success", baseline=baseline)
    incident: Incident | None = None
    for sequence in range(1, 4):
        current = sample(sequence, "failure", baseline=baseline)
        changes = evaluator.evaluate(current, previous, current.observed_at, DnsConfig())
        previous = current
        if changes:
            incident = changes[0]
    assert incident is not None and incident.status == "active"
    opening = incident.opening_evidence.copy()

    changed_hostname = "changed.fleetdoctor.test."
    changed = sample(4, "success", hostname=changed_hostname)
    changes = evaluator.evaluate(changed, previous, changed.observed_at, DnsConfig())
    retained = next(item for item in changes if item.id == incident.id)
    assert retained.status == "active"
    assert retained.opening_evidence == opening
    assert retained.latest_evidence["inconclusive_reason"] == "scope_changed"
    current_dns = cast(dict[str, Any], retained.latest_evidence["dns"])
    assert current_dns["hostname"] == changed_hostname
    assert current_dns["direct_ip_target"] == TARGET
    assert cast(dict[str, Any], current_dns["query"])["status"] == "success"
    assert cast(dict[str, Any], current_dns["resolver"])["status"] == "available"


@pytest.mark.parametrize("rtt,lost", [(150.0, 0), (20.0, 1)])
def test_dns_failure_is_inconclusive_when_direct_ip_is_not_exactly_healthy(
    rtt: float, lost: int
) -> None:
    evaluator = DnsEvaluator([])
    base = baseline_for()
    current = sample(1, "failure", baseline=base, rtt=rtt, lost=lost)
    assert (
        evaluator.evaluate(
            current, sample(0, "success", baseline=base), current.observed_at, DnsConfig()
        )
        == []
    )
    assert evaluator.windows[("node-a", f"dns:{HOSTNAME}|ipv4:{TARGET}")].opening == 0


def test_dns_failure_rejects_baseline_equal_to_frozen_rtt_limit() -> None:
    evaluator = DnsEvaluator([])
    current = sample(1, "failure", baseline=baseline_for(rtt=150.0))
    assert evaluator.evaluate(current, None, current.observed_at, DnsConfig()) == []
    facts = evaluator.windows[("node-a", f"dns:{HOSTNAME}|ipv4:{TARGET}")]
    assert facts.opening == 0


def test_dns_api_metrics_severity_and_durable_count_capacity() -> None:
    clock = [NOW + timedelta(seconds=100)]
    store = FixtureStore()
    app = create_app(
        {"node-a": SecretStr("a" * 32)},
        store=store,
        clock=lambda: clock[0],
        dns_config=DnsConfig(consecutive_samples=1, severity="critical"),
    )
    client = TestClient(app)
    for index in range(16):
        hostname = f"h{index}.fleetdoctor.test."
        current = sample(index + 1, "failure", hostname=hostname, baseline=baseline_for(hostname))
        clock[0] = current.observed_at
        response = client.post(
            "/ingest",
            content=current.model_dump_json(),
            headers={"Authorization": "Bearer " + "a" * 32},
        )
        assert response.status_code == 200
    view = client.get("/nodes/node-a/metrics").json()
    assert view["active_incident_counts"]["dns_resolution_failure"] == 16
    assert view["dns_coverage"]["admission_capacity"] == "unavailable"
    incidents = client.get(
        "/diagnoses", params={"rule": "dns_resolution_failure", "status": "active", "limit": 100}
    ).json()
    assert incidents["total"] == 16 and all(
        item["severity"] == "critical" for item in incidents["diagnoses"]
    )
    metrics = client.get("/metrics").text
    assert 'fleetdoctor_dns_admission_capacity_available{node="node-a"} 0.0' in metrics
    assert "fleetdoctor_dns_query_success" in metrics
    assert client.get("/diagnoses", params={"rule": "not-a-rule"}).status_code == 422

    overflow = sample(
        17,
        "failure",
        hostname="h16.fleetdoctor.test.",
        baseline=baseline_for("h16.fleetdoctor.test."),
    )
    clock[0] = overflow.observed_at
    assert (
        client.post(
            "/ingest",
            content=overflow.model_dump_json(),
            headers={"Authorization": "Bearer " + "a" * 32},
        ).status_code
        == 200
    )
    view = client.get("/nodes/node-a/metrics").json()
    assert view["active_incident_counts"]["dns_resolution_failure"] == 16
    assert view["dns_coverage"]["candidate_overflow"] is True

    ordinary = sample(18, "success", hostname="ordinary.fleetdoctor.test.")
    clock[0] = ordinary.observed_at
    client.post(
        "/ingest",
        content=ordinary.model_dump_json(),
        headers={"Authorization": "Bearer " + "a" * 32},
    ).raise_for_status()
    assert client.get("/nodes/node-a/metrics").json()["dns_coverage"]["candidate_overflow"] is False

    recovered = sample(19, "success", hostname="h0.fleetdoctor.test.")
    clock[0] = recovered.observed_at
    client.post(
        "/ingest",
        content=recovered.model_dump_json(),
        headers={"Authorization": "Bearer " + "a" * 32},
    ).raise_for_status()
    restarted = TestClient(
        create_app(
            {"node-a": SecretStr("a" * 32)},
            store=store,
            clock=lambda: clock[0],
            dns_config=DnsConfig(consecutive_samples=1, severity="info"),
        )
    )
    restarted_view = restarted.get("/nodes/node-a/metrics").json()
    assert restarted_view["active_incident_counts"]["dns_resolution_failure"] == 15
    assert restarted_view["dns_coverage"]["admission_capacity"] == "available"


def test_schema_rejects_noncanonical_baseline_nameserver_and_target() -> None:
    value = baseline_for().model_dump(mode="json")
    value["resolver_nameservers"] = ["192.0.2.053"]
    with pytest.raises(ValidationError):
        DnsBaselineObservation.model_validate(value)
    value = baseline_for().model_dump(mode="json")
    value["direct_ip_target"] = str(ipaddress.ip_address("0.0.0.0"))
    with pytest.raises(ValidationError):
        DnsBaselineObservation.model_validate(value)


def test_schema_rejects_measured_dns_without_adapter_or_available_resolver() -> None:
    query = raw_dns("failure").query.model_dump(mode="python")
    query["adapter"] = "none"
    with pytest.raises(ValidationError, match="supported adapter"):
        DnsQueryObservation.model_validate(query)

    for adapter in ("dnspython", "systemd-resolved"):
        valid = raw_dns("failure").model_dump(mode="python")
        valid["query"]["adapter"] = adapter
        assert DnsObservation.model_validate(valid).query.adapter == adapter

    invalid = raw_dns("failure").model_dump(mode="python")
    invalid["resolver"] = {
        "status": "unavailable",
        "nameservers": [],
        "errors": ["resolver_configuration_unavailable"],
    }
    with pytest.raises(ValidationError, match="available resolver configuration"):
        DnsObservation.model_validate(invalid)


def test_invalid_unavailable_dns_wire_facts_cannot_open_or_resolve_incident() -> None:
    clock = [NOW + timedelta(seconds=5)]
    app = create_app(
        {"node-a": SecretStr("a" * 32)},
        store=FixtureStore(),
        clock=lambda: clock[0],
        dns_config=DnsConfig(consecutive_samples=1),
    )
    client = TestClient(app)
    headers = {"Authorization": "Bearer " + "a" * 32}

    unsupported = sample(1, "failure", baseline=baseline_for()).model_dump(mode="json")
    unsupported["dns"]["query"]["adapter"] = "none"
    response = client.post("/ingest", json=unsupported, headers=headers)
    assert response.status_code == 422
    assert client.get("/diagnoses").json()["total"] == 0

    valid_failure = sample(1, "failure", baseline=baseline_for())
    client.post(
        "/ingest", content=valid_failure.model_dump_json(), headers=headers
    ).raise_for_status()
    assert client.get("/diagnoses", params={"status": "active"}).json()["total"] == 1

    invalid_recovery = sample(2, "success", baseline=baseline_for()).model_dump(mode="json")
    invalid_recovery["dns"]["resolver"] = {
        "status": "unavailable",
        "nameservers": [],
        "errors": ["resolver_configuration_unavailable"],
    }
    clock[0] = NOW + timedelta(seconds=10)
    response = client.post("/ingest", json=invalid_recovery, headers=headers)
    assert response.status_code == 422
    assert client.get("/diagnoses", params={"status": "active"}).json()["total"] == 1


def test_dns_inconclusive_metric_validates_present_baseline_and_unavailable_query() -> None:
    clock = [NOW + timedelta(seconds=5)]
    app = create_app(
        {"node-a": SecretStr("a" * 32)},
        store=FixtureStore(),
        clock=lambda: clock[0],
        dns_config=DnsConfig(consecutive_samples=1),
    )
    client = TestClient(app)
    headers = {"Authorization": "Bearer " + "a" * 32}
    nonhistorical = sample(1, "failure", baseline=baseline_for(sequence=1))
    client.post(
        "/ingest", content=nonhistorical.model_dump_json(), headers=headers
    ).raise_for_status()
    metrics = client.get("/metrics").text
    assert 'fleetdoctor_dns_inconclusive{node="node-a"} 1.0' in metrics
    assert client.get("/diagnoses").json()["total"] == 0

    clock[0] = NOW + timedelta(seconds=10)
    unavailable = sample(2, "unavailable")
    client.post(
        "/ingest", content=unavailable.model_dump_json(), headers=headers
    ).raise_for_status()
    metrics = client.get("/metrics").text
    assert 'fleetdoctor_dns_probe_coverage_ratio{node="node-a"} 0.0' in metrics
    assert 'fleetdoctor_dns_inconclusive{node="node-a"} 1.0' in metrics


def test_dns_inconclusive_metric_uses_active_incident_frozen_threshold_after_restart() -> None:
    store = FixtureStore()
    clock = [NOW + timedelta(seconds=5)]
    headers = {"Authorization": "Bearer " + "a" * 32}
    opening_app = create_app(
        {"node-a": SecretStr("a" * 32)},
        store=store,
        clock=lambda: clock[0],
        dns_config=DnsConfig(direct_ip_rtt_max_ms=250, consecutive_samples=1),
    )
    opening = sample(1, "failure", baseline=baseline_for(rtt=200))
    TestClient(opening_app).post(
        "/ingest", content=opening.model_dump_json(), headers=headers
    ).raise_for_status()

    clock[0] = NOW + timedelta(seconds=10)
    restarted = TestClient(
        create_app(
            {"node-a": SecretStr("a" * 32)},
            store=store,
            clock=lambda: clock[0],
            dns_config=DnsConfig(direct_ip_rtt_max_ms=50, consecutive_samples=1),
        )
    )
    latest = sample(2, "failure", baseline=baseline_for(rtt=200))
    restarted.post("/ingest", content=latest.model_dump_json(), headers=headers).raise_for_status()
    detail = restarted.get("/diagnoses", params={"status": "active"}).json()
    assert detail["total"] == 1
    assert detail["diagnoses"][0]["configuration"]["direct_ip_rtt_max_ms"] == 250
    incident = restarted.get("/diagnoses/" + detail["diagnoses"][0]["id"]).json()
    assert incident["latest_evidence"]["dns_conclusive"] is True
    assert 'fleetdoctor_dns_inconclusive{node="node-a"} 0.0' in restarted.get("/metrics").text
