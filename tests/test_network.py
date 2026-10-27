import asyncio
import json
import os
import signal
import struct
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

import fleetdoctor.collector as collector_module
import fleetdoctor.network as network_module
from fleetdoctor.agent import _drain_collection_tasks, collect_loop, make_sample
from fleetdoctor.collector import create_app
from fleetdoctor.incidents import NetworkConfig
from fleetdoctor.network import (
    NetworkCollectionWorker,
    NetworkCollector,
    canonical_ipv4,
    parse_ping,
    parse_route,
)
from fleetdoctor.rules import NetworkEvaluator
from fleetdoctor.schema import (
    CpuObservation,
    FdObservation,
    Filesystem,
    HostMemoryObservation,
    MemoryObservation,
    NetworkObservation,
    NetworkProbeObservation,
    Sample,
    TcpNetworkObservation,
)
from fleetdoctor.store import FixtureStore, PostgresStore

TARGET = "192.0.2.10"


def observation(
    *, lost: int = 0, rtts: list[float] | None = None, target: str = TARGET
) -> NetworkObservation:
    values = rtts if rtts is not None else ([] if lost == 3 else [20.0] * (3 - lost))
    probe = NetworkProbeObservation(
        status="available",
        target=target,
        sent=3,
        received=3 - lost,
        lost=lost,
        loss_ratio=lost / 3,
        successful_sequences=list(range(1, 4 - lost)),
        successful_rtts_ms=sorted(values),
        median_rtt_ms=(sorted(values)[len(values) // 2] if values else None),
        route_error="fixture_unknown_route",
    )
    return NetworkObservation(
        probe=probe,
        tcp=TcpNetworkObservation(
            retrans_segs=1,
            rate_status="baseline",
            curr_estab=2,
            state_counts={"established": 2},
            state_inventory="complete",
        ),
        interface_coverage="complete",
        elapsed_seconds=0.1,
    )


def sample(sequence: int, observed: datetime, value: NetworkObservation) -> Sample:
    return make_sample(
        "node-a",
        BOOT,
        SESSION,
        sequence,
        [Filesystem(mountpoint="/", errors=["fixture"])],
        observed,
        cpu=CpuObservation(errors=["fixture"]),
        memory=MemoryObservation(host=HostMemoryObservation(errors=["fixture"])),
        fd=FdObservation(errors=["fixture"]),
        network=value,
    )


BOOT, SESSION = uuid4(), uuid4()


def worker_exits_before_ready(conn: Any) -> None:
    conn.close()


def worker_never_ready(conn: Any) -> None:
    time.sleep(30)


def worker_with_stubborn_child(conn: Any) -> None:
    os.setsid()
    signal.signal(signal.SIGTERM, network_module._stop_worker)
    identity = network_module._proc_identity(os.getpid())
    assert identity is not None
    conn.send(
        {
            "ready": True,
            "pid": os.getpid(),
            "pgid": os.getpgrp(),
            "starttime": identity[2],
        }
    )
    conn.recv()
    network_module._run_bounded(["sleep", "30"], 30.0, 1024)


def worker_with_partial_result(conn: Any) -> None:
    os.setsid()
    signal.signal(signal.SIGTERM, network_module._stop_worker)
    identity = network_module._proc_identity(os.getpid())
    assert identity is not None
    conn.send(
        {
            "ready": True,
            "pid": os.getpid(),
            "pgid": os.getpgrp(),
            "starttime": identity[2],
        }
    )
    conn.recv()
    os.write(conn.fileno(), struct.pack("!i", 4096) + b"{")
    time.sleep(30)


def test_ping_partial_loss_uses_successful_reply_median_not_summary_average() -> None:
    output = """64 bytes from 192.0.2.10: icmp_seq=1 ttl=64 time=10.0 ms
64 bytes from 192.0.2.10: icmp_seq=3 ttl=64 time=250.0 ms
3 packets transmitted, 2 received, 33% packet loss, time 401ms
rtt min/avg/max/mdev = 10.000/999.000/250.000/1.000 ms
"""
    value = parse_ping(output, "", 1, TARGET)
    assert value.status == "available"
    assert value.lost == 1
    assert value.successful_sequences == [1, 3]
    assert value.median_rtt_ms == 130


def test_ping_no_reply_is_measured_loss_but_permission_is_unavailable() -> None:
    no_reply = parse_ping("3 packets transmitted, 0 received, 100% packet loss\n", "", 1, TARGET)
    assert (no_reply.status, no_reply.lost, no_reply.median_rtt_ms) == ("available", 3, None)
    denied = parse_ping("", "ping: socket: Operation not permitted", 2, TARGET)
    assert denied.status == "unavailable" and denied.errors == ["ping_permission_denied"]
    assert denied.loss_ratio is None


def test_ping_malformed_duplicate_and_wrong_count_are_unavailable() -> None:
    duplicate = """64 bytes from 192.0.2.10: icmp_seq=1 ttl=64 time=10 ms
64 bytes from 192.0.2.10: icmp_seq=1 ttl=64 time=20 ms
3 packets transmitted, 2 received, 33% packet loss
"""
    assert parse_ping(duplicate, "", 1, TARGET).status == "unavailable"
    assert parse_ping("2 packets transmitted, 0 received\n", "", 1, TARGET).status == "unavailable"


def test_ping_uses_external_hard_bound_without_an_iputils_deadline() -> None:
    assert network_module.PING_ARGV == (
        "ping",
        "-n",
        "-4",
        "-c",
        "3",
        "-i",
        "0.2",
        "-W",
        "1",
    )


def test_route_accepts_normal_cache_continuation() -> None:
    if os.name != "posix":
        pytest.skip("ifindex fixture requires Linux")
    name = "lo"
    parsed = parse_route(f"{TARGET} dev {name} src 192.0.2.2 uid 1000\n    cache\n", TARGET)
    assert parsed[0] == name and parsed[1] is not None and parsed[2] is None


@pytest.mark.parametrize(
    "value", ["999.1.1.1", "01.2.3.4", "0.0.0.0", "224.0.0.1", "255.255.255.255"]
)
def test_target_is_canonical_at_startup_and_wire_boundary(value: str) -> None:
    with pytest.raises(ValueError):
        canonical_ipv4(value)
    with pytest.raises(ValidationError):
        NetworkProbeObservation.unavailable(value, "fixture")


def test_owned_install_paths_install_and_verify_network_prerequisites() -> None:
    root = Path(__file__).resolve().parents[1]
    installer = (root / "deploy/install-agent.sh").read_text(encoding="utf-8")
    bootstrap = (root / "infra/aws/node-bootstrap.sh").read_text(encoding="utf-8")
    assert "dnf install -y iputils iproute procps-ng" in installer
    assert "apt-get install -y --no-install-recommends iputils-ping iproute2 procps" in installer
    assert installer.count("command -v ping") >= 2
    assert installer.count("command -v sysctl") >= 2
    assert "/usr/local/sbin/fleetdoctor-network-prepare fleetdoctor" in installer
    assert "dnf install -y python3.11 python3.11-pip chrony iputils iproute procps-ng" in bootstrap
    assert "read -r ping_min ping_max ping_extra" in bootstrap


def test_network_rule_boundaries_loss_recovery_and_target_change() -> None:
    config = NetworkConfig(consecutive_samples=3)
    evaluator = NetworkEvaluator([])
    now = datetime.now(UTC)
    previous = None
    changes = []
    for sequence, rtt in enumerate((199.9, 200.0, 200.0, 200.0)):
        current = sample(
            sequence, now + timedelta(seconds=sequence * 5), observation(rtts=[rtt] * 3)
        )
        changes = evaluator.evaluate(current, previous, current.observed_at, config)
        previous = current
    assert len(changes) == 1 and changes[0].status == "active"
    incident = changes[0]
    changed = sample(4, now + timedelta(seconds=20), observation(target="192.0.2.11"))
    updates = evaluator.evaluate(changed, previous, changed.observed_at, config)
    retained = next(item for item in updates if item.id == incident.id)
    assert retained.status == "active"
    coverage = cast(dict[str, Any], retained.latest_evidence["coverage"])
    assert coverage["limitation"] == "target_changed"
    previous = changed
    for sequence, rtt in enumerate((150.0, 149.9, 149.9), start=5):
        current = sample(
            sequence, now + timedelta(seconds=sequence * 5), observation(rtts=[rtt] * 3)
        )
        evaluator.evaluate(current, previous, current.observed_at, config)
        previous = current
    assert evaluator.active[("node-a", f"ipv4:{TARGET}")].status == "active"


@pytest.mark.parametrize(
    ("configured", "expected"),
    [({}, "warning"), ({"severity": "info"}, "info"), ({"severity": "critical"}, "critical")],
)
def test_network_environment_severity_opens_and_freezes_typed_incident(
    monkeypatch: pytest.MonkeyPatch,
    configured: dict[str, str],
    expected: Literal["info", "warning", "critical"],
) -> None:
    store = FixtureStore()
    rule = {"consecutive_samples": 1, **configured}
    monkeypatch.setenv("FLEETDOCTOR_NODE_TOKENS", json.dumps({"node-a": "a" * 32}))
    monkeypatch.setenv("FLEETDOCTOR_NETWORK_RULE", json.dumps(rule))
    monkeypatch.setattr(PostgresStore, "environment", staticmethod(lambda: store))
    app = collector_module.app_factory()
    client = TestClient(app)
    configured_rule = client.get("/configuration").json()["network_rule"]
    assert configured_rule["severity"] == expected

    now = datetime.now(UTC) - timedelta(seconds=1)
    response = client.post(
        "/ingest",
        content=sample(0, now, observation(lost=1)).model_dump_json(),
        headers={"Authorization": "Bearer " + "a" * 32},
    )
    assert response.status_code == 200 and response.json()["status"] == "accepted"
    incident = store.active()[0]
    assert incident.severity == expected
    assert isinstance(incident.configuration, NetworkConfig)
    assert incident.configuration.severity == expected
    assert incident.opening_evidence["network_available"] is True
    assert cast(dict[str, Any], incident.opening_evidence["probe"])["lost"] == 1
    opening_evidence = incident.opening_evidence
    opening_configuration = incident.configuration

    replacement: Literal["info", "critical"] = "critical" if expected != "critical" else "info"
    app.state.fleet.network_config = NetworkConfig(consecutive_samples=1, severity=replacement)
    update = client.post(
        "/ingest",
        content=sample(1, datetime.now(UTC), observation(lost=2)).model_dump_json(),
        headers={"Authorization": "Bearer " + "a" * 32},
    )
    assert update.status_code == 200 and update.json()["status"] == "accepted"
    updated = store.active()[0]
    assert updated.id == incident.id
    assert updated.severity == expected
    assert updated.configuration == opening_configuration
    assert updated.opening_evidence == opening_evidence
    assert updated.latest_evidence["sequence"] == 1
    assert cast(dict[str, Any], updated.latest_evidence["probe"])["lost"] == 2
    detail = client.get(f"/diagnoses/{incident.id}").json()
    assert detail["severity"] == expected
    assert detail["configuration"]["severity"] == expected
    assert detail["opening_evidence"] == opening_evidence
    assert detail["latest_evidence"]["sequence"] == 1


def test_network_environment_rejects_unknown_severity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLEETDOCTOR_NODE_TOKENS", json.dumps({"node-a": "a" * 32}))
    monkeypatch.setenv("FLEETDOCTOR_NETWORK_RULE", json.dumps({"severity": "fatal"}))
    with pytest.raises(ValidationError):
        collector_module.app_factory()


def test_frozen_gap_and_pending_target_windows_are_bounded() -> None:
    frozen = NetworkConfig(consecutive_samples=1, max_gap_seconds=5)
    evaluator = NetworkEvaluator([])
    now = datetime.now(UTC)
    first = sample(0, now, observation(lost=1))
    opened = evaluator.evaluate(first, None, now, frozen)[0]
    assert opened.configuration.max_gap_seconds == 5
    previous = first
    for index in range(1, 25):
        target = f"192.0.2.{20 + index}"
        current = sample(index, now + timedelta(seconds=index), observation(target=target))
        evaluator.evaluate(
            current, previous, current.observed_at, NetworkConfig(max_gap_seconds=10)
        )
        previous = current
    assert len(evaluator.windows) <= 1


def test_interface_counter_reset_is_per_field(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshots: Any = iter(
        [
            (
                {"eth0": {"rx_errors": 10, "rx_dropped": 10, "tx_errors": 10, "tx_dropped": 10}},
                "complete",
                [],
            ),
            (
                {"eth0": {"rx_errors": 9, "rx_dropped": 12, "tx_errors": 13, "tx_dropped": 14}},
                "complete",
                [],
            ),
        ]
    )
    monkeypatch.setattr(network_module, "_interface_snapshot", lambda: next(snapshots))
    monkeypatch.setattr(network_module, "socket_ifindex", lambda name: 2)
    monkeypatch.setattr(
        network_module,
        "_tcp_snapshot",
        lambda: ({"retrans_segs": 1, "curr_estab": 1}, {"established": 1}, "complete", []),
    )
    monkeypatch.setattr(network_module, "_route", lambda target, timeout: ("eth0", 2, None))
    monkeypatch.setattr(network_module, "_ping", lambda target, timeout: observation().probe)
    collector = NetworkCollector()
    collector.collect(TARGET)
    # Windows' monotonic clock can advance in roughly 15.6 ms ticks.
    time.sleep(0.03)
    second = collector.collect(TARGET).interfaces[0]
    assert second.rate_status["rx_errors"] == "counter_reset"
    assert second.rx_errors_per_second is None
    assert second.rate_status["rx_dropped"] == "available"
    assert second.rx_dropped_per_second is not None


def test_tcp_gauge_decrease_does_not_reset_cumulative_rate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshots: Any = iter(
        [
            ({"retrans_segs": 10, "curr_estab": 8}, {"established": 8}, "complete", []),
            ({"retrans_segs": 12, "curr_estab": 2}, {"established": 2}, "complete", []),
        ]
    )
    monkeypatch.setattr(network_module, "_tcp_snapshot", lambda: next(snapshots))
    monkeypatch.setattr(network_module, "_interface_snapshot", lambda: ({}, "unavailable", []))
    monkeypatch.setattr(network_module, "_route", lambda target, timeout: ("eth0", 2, None))
    monkeypatch.setattr(network_module, "_ping", lambda target, timeout: observation().probe)
    collector = NetworkCollector()
    collector.collect(TARGET)
    time.sleep(0.03)
    second = collector.collect(TARGET).tcp
    assert second.curr_estab == 2 and second.state_counts["established"] == 2
    assert second.rate_status == "available" and second.retrans_per_second is not None


@pytest.mark.skipif(os.name != "posix", reason="Linux process-group behavior")
def test_worker_startup_failure_and_hard_timeout_leave_no_owned_group() -> None:
    startup = NetworkCollectionWorker(target=worker_exits_before_ready)
    assert not startup.wait_ready(15)
    assert startup.process is None and not startup.stuck

    never_ready = NetworkCollectionWorker(target=worker_never_ready)
    never_ready.start()
    process = never_ready.process
    assert process is not None and process.is_alive()
    never_ready_pid = process.pid
    never_ready.close()
    assert never_ready.process is None and not never_ready.stuck
    assert network_module._proc_identity(never_ready_pid) is None

    worker = NetworkCollectionWorker(target=worker_with_stubborn_child)
    assert worker.wait_ready(15)
    pgid = worker.pgid
    assert pgid is not None
    result = worker.collect(TARGET, budget=0.05)
    assert result.probe.status == "unavailable"
    assert result.probe.errors == ["network_collection_timeout"]
    assert network_module._group_members(pgid) == {}
    assert worker.process is None and not worker.stuck


@pytest.mark.skipif(os.name != "posix", reason="real multiprocessing pipe fd semantics")
def test_worker_partial_result_frame_is_bounded_and_reaps_owned_group() -> None:
    worker = NetworkCollectionWorker(target=worker_with_partial_result)
    assert worker.wait_ready(2.0)
    pgid = worker.pgid
    assert pgid is not None
    started = time.monotonic()
    result = worker.collect(TARGET, budget=0.2)
    elapsed = time.monotonic() - started
    assert elapsed < 1.0
    assert result.probe.errors == ["network_collection_timeout"]
    assert worker.process is None and not worker.stuck
    assert network_module._group_members(pgid) == {}


def test_largest_interface_context_is_trimmed_without_losing_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        ("interface" + str(index).zfill(2) + "x" * 50): {
            "rx_errors": 2**63 + index,
            "rx_dropped": 2**63 + index,
            "tx_errors": 2**63 + index,
            "tx_dropped": 2**63 + index,
        }
        for index in range(16)
    }
    monkeypatch.setattr(network_module, "_interface_snapshot", lambda: (values, "complete", []))
    monkeypatch.setattr(network_module, "socket_ifindex", lambda name: list(values).index(name) + 1)
    monkeypatch.setattr(
        network_module,
        "_tcp_snapshot",
        lambda: (
            {"retrans_segs": 2**63, "curr_estab": 2**63},
            {name: 2**63 for name in network_module.TCP_STATES.values()},
            "complete",
            [],
        ),
    )
    monkeypatch.setattr(network_module, "_route", lambda target, timeout: ("eth0", 2, None))
    monkeypatch.setattr(network_module, "_ping", lambda target, timeout: observation().probe)
    value = NetworkCollector().collect(TARGET)
    assert value.probe.status == "available" and value.probe.target == TARGET
    assert value.context_trimmed and value.interface_coverage == "partial"
    assert "network_context_trimmed" in value.errors
    assert len(value.model_dump_json().encode("utf-8")) <= 8 * 1024


def test_tcp_inventory_recovers_to_partial_when_second_file_is_readable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads = iter(
        [
            ("Tcp: RetransSegs CurrEstab\nTcp: 1 2\n", None),
            (None, "PermissionError"),
            ("  sl  local_address rem_address st\n   0: 00000000 00000000 01\n", None),
        ]
    )
    monkeypatch.setattr(network_module, "_bounded_read", lambda path: next(reads))
    counters, states, coverage, errors = network_module._tcp_snapshot()
    assert counters == {"retrans_segs": 1, "curr_estab": 2}
    expected_states = {name: 0 for name in network_module.TCP_STATES.values()}
    expected_states["established"] = 1
    assert coverage == "partial" and states == expected_states
    assert errors == ["tcp_inventory_PermissionError"]


def test_drain_waits_for_every_concurrent_worker_call() -> None:
    completed: list[str] = []

    async def work(name: str, delay: float) -> None:
        await asyncio.sleep(delay)
        completed.append(name)

    async def prove() -> None:
        tasks = [asyncio.create_task(work("a", 0.01)), asyncio.create_task(work("b", 0.02))]
        await _drain_collection_tasks(tasks)

    asyncio.run(prove())
    assert completed == ["a", "b"]


def test_collect_loop_cancellation_waits_for_every_launched_collector() -> None:
    started = [threading.Event() for _ in range(4)]
    release = [threading.Event() for _ in range(4)]

    def blocking(index: int, value: Any) -> Any:
        started[index].set()
        assert release[index].wait(2)
        return value

    class Worker:
        def __init__(self, index: int, value: Any) -> None:
            self.index, self.value = index, value

        def collect(self, argument: Any) -> Any:
            return blocking(self.index, self.value)

    async def prove() -> None:
        task = asyncio.create_task(
            collect_loop(
                "node-a",
                BOOT,
                SESSION,
                cast(Any, Worker(0, [Filesystem(mountpoint="/", errors=["fixture"])])),
                "http://fixture",
                SecretStr("f" * 40),
                ("/",),
                True,
                asyncio.Event(),
                cpu_worker=cast(Any, Worker(1, CpuObservation(errors=["fixture"]))),
                memory_worker=cast(
                    Any,
                    Worker(2, MemoryObservation(host=HostMemoryObservation(errors=["fixture"]))),
                ),
                network_worker=cast(Any, Worker(3, observation())),
                network_target=TARGET,
            )
        )
        await asyncio.wait_for(
            asyncio.to_thread(lambda: all(event.wait(1) for event in started)), timeout=2
        )
        task.cancel()
        for event in release[:-1]:
            event.set()
            await asyncio.sleep(0.02)
            assert not task.done()
        release[-1].set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(prove())


def test_v5_api_rule_and_metrics_keep_no_reply_rtt_absent() -> None:
    now = datetime.now(UTC)
    store = FixtureStore()
    app = create_app(
        {"node-a": SecretStr("a" * 32)},
        clock=lambda: now,
        store=store,
        network_config=NetworkConfig(consecutive_samples=1),
    )
    client = TestClient(app)
    value = sample(0, now, observation(lost=3))
    response = client.post(
        "/ingest",
        content=value.model_dump_json(),
        headers={"Authorization": "Bearer " + "a" * 32},
    )
    assert response.status_code == 200 and response.json()["status"] == "accepted"
    detail = client.get("/nodes/node-a/metrics").json()
    assert detail["network"]["probe"]["lost"] == 3
    assert detail["network"]["probe"]["median_rtt_ms"] is None
    assert detail["active_incident_counts"]["network_path_degradation"] == 1
    metrics = client.get("/metrics").text
    assert 'fleetdoctor_network_probe_loss_packets{node="node-a"} 3.0' in metrics
    assert 'fleetdoctor_network_probe_loss_ratio{node="node-a"} 1.0' in metrics
    assert not any(
        line.startswith("fleetdoctor_network_probe_median_rtt_seconds{") and 'node="node-a"' in line
        for line in metrics.splitlines()
    )
    assert 'fleetdoctor_network_tcp_curr_estab{node="node-a"} 2.0' in metrics


def test_v4_remains_explicitly_accepted_without_network_fields() -> None:
    legacy = make_sample(
        "node-a",
        uuid4(),
        uuid4(),
        0,
        [Filesystem(mountpoint="/", errors=["fixture"])],
        cpu=CpuObservation(errors=["fixture"]),
        memory=MemoryObservation(host=HostMemoryObservation(errors=["fixture"])),
        fd=FdObservation(errors=["fixture"]),
    )
    assert legacy.schema_version == 4 and legacy.network is None


def test_network_v4_v5_order_atomicity_frozen_restart_and_recurrence() -> None:
    clock = [datetime(2026, 10, 21, 12, tzinfo=UTC)]
    boot, session = uuid4(), uuid4()
    store = FixtureStore()
    token = SecretStr("a" * 32)
    config = NetworkConfig(consecutive_samples=3)

    def app_client(rule: NetworkConfig) -> TestClient:
        return TestClient(
            create_app(
                {"node-a": token},
                clock=lambda: clock[0],
                store=store,
                network_config=rule,
            )
        )

    client = app_client(config)

    def wire(sequence: int, value: NetworkObservation | None) -> Sample:
        observed = datetime(2026, 10, 21, 12, tzinfo=UTC) + timedelta(seconds=sequence * 5)
        clock[0] = observed
        return make_sample(
            "node-a",
            boot,
            session,
            sequence,
            [Filesystem(mountpoint="/", errors=["fixture"])],
            observed,
            cpu=CpuObservation(errors=["fixture"]),
            memory=MemoryObservation(host=HostMemoryObservation(errors=["fixture"])),
            fd=FdObservation(errors=["fixture"]),
            network=value,
        )

    def post(value: Sample) -> Any:
        return client.post(
            "/ingest",
            content=value.model_dump_json(),
            headers={"Authorization": "Bearer " + token.get_secret_value()},
        )

    legacy = wire(0, None)
    assert legacy.schema_version == 4 and post(legacy).json()["status"] == "accepted"
    first = wire(1, observation(lost=1))
    assert first.schema_version == 5 and post(first).json()["status"] == "accepted"
    assert post(first).json()["status"] == "duplicate"
    conflict = first.model_copy(update={"network": observation(lost=2)})
    assert post(conflict).status_code == 409
    second = wire(2, observation(lost=1))
    store.fail = True
    assert post(second).status_code == 503
    store.fail = False
    assert not store.active()
    assert post(second).json()["status"] == "accepted"
    third = wire(3, observation(lost=1))
    assert post(third).json()["status"] == "accepted"
    active = store.active()[0]
    original_id = active.id
    assert active.configuration == config

    client = app_client(NetworkConfig(consecutive_samples=1, recovery_rtt_ms=100))
    for sequence in (4, 5):
        assert post(wire(sequence, observation())).json()["status"] == "accepted"
        assert store.active()[0].id == original_id
    assert post(wire(6, observation())).json()["status"] == "accepted"
    assert not store.active()
    resolved = client.get(f"/diagnoses/{original_id}").json()
    assert resolved["configuration"] == config.model_dump(mode="json")

    for sequence in (7, 8, 9):
        assert post(wire(sequence, observation(lost=1))).json()["status"] == "accepted"
    recurrence = store.active()[0]
    assert recurrence.id != original_id
    out_of_order = wire(10, observation(lost=1)).model_copy(
        update={"observed_at": clock[0] - timedelta(seconds=20)}
    )
    assert post(out_of_order).json()["status"] == "ineligible"


def test_network_admission_capacity_overflow_reload_and_recovery_are_truthful() -> None:
    now = [datetime(2026, 10, 24, 12, tzinfo=UTC)]
    store = FixtureStore()
    tokens = {"node-a": SecretStr("a" * 32), "node-b": SecretStr("b" * 32)}
    rule = NetworkConfig(consecutive_samples=1)

    def new_client() -> TestClient:
        return TestClient(
            create_app(tokens, store=store, clock=lambda: now[0], network_config=rule)
        )

    client = new_client()

    def post_network(sequence: int, target: str, *, lost: int) -> None:
        now[0] += timedelta(seconds=1)
        response = client.post(
            "/ingest",
            content=sample(
                sequence, now[0], observation(target=target, lost=lost)
            ).model_dump_json(),
            headers={"Authorization": "Bearer " + "a" * 32},
        )
        assert response.status_code == 200 and response.json()["status"] == "accepted"

    def post_targetless(sequence: int) -> None:
        now[0] += timedelta(seconds=1)
        value = make_sample(
            "node-a",
            BOOT,
            SESSION,
            sequence,
            [Filesystem(mountpoint="/", errors=["fixture"])],
            now[0],
            cpu=CpuObservation(errors=["fixture"]),
            memory=MemoryObservation(host=HostMemoryObservation(errors=["fixture"])),
            fd=FdObservation(errors=["fixture"]),
        )
        response = client.post(
            "/ingest",
            content=value.model_dump_json(),
            headers={"Authorization": "Bearer " + "a" * 32},
        )
        assert response.status_code == 200 and response.json()["status"] == "accepted"

    def assert_admission(capacity: str, overflow: bool) -> None:
        coverage = client.get("/nodes/node-a/metrics").json()["network_coverage"]
        assert coverage["admission_capacity"] == capacity
        assert coverage["candidate_overflow"] is overflow
        metrics = client.get("/metrics").text
        expected_capacity = 1.0 if capacity == "available" else 0.0
        assert (
            f'fleetdoctor_network_admission_capacity_available{{node="node-a"}} {expected_capacity}'
        ) in metrics
        assert (
            f'fleetdoctor_network_admission_candidate_overflow{{node="node-a"}} '
            f"{1.0 if overflow else 0.0}"
        ) in metrics
        node_b = client.get("/nodes/node-b/metrics").json()["network_coverage"]
        assert node_b["admission_capacity"] == "available"
        assert not node_b["candidate_overflow"]

    targets = [f"10.0.0.{index}" for index in range(1, 20)]
    for sequence, target in enumerate(targets[:15]):
        post_network(sequence, target, lost=1)
    assert len(store.active()) == 15
    assert_admission("available", False)

    post_network(15, targets[15], lost=1)
    assert len(store.active()) == 16
    assert_admission("unavailable", False)

    client = new_client()
    assert len(store.active()) == 16
    assert_admission("unavailable", False)

    post_network(16, targets[16], lost=1)
    assert len(store.active()) == 16
    assert_admission("unavailable", True)

    post_network(17, targets[16], lost=0)
    assert len(store.active()) == 16
    assert_admission("unavailable", False)

    post_network(18, targets[17], lost=1)
    assert_admission("unavailable", True)
    post_targetless(19)
    assert_admission("unavailable", False)

    post_network(20, targets[18], lost=1)
    assert_admission("unavailable", True)
    post_network(21, targets[0], lost=0)
    assert len(store.active()) == 15
    assert_admission("available", False)
