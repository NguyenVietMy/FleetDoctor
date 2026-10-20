from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from fleetdoctor.agent import make_sample
from fleetdoctor.checkpoint import canonical_sample_bytes, sample_fingerprint
from fleetdoctor.collector import create_app
from fleetdoctor.cpu import (
    CpuCollector,
    cpu_rates,
    parse_loadavg,
    parse_proc_stat,
    parse_process_stat,
)
from fleetdoctor.incidents import CpuConfig
from fleetdoctor.schema import CpuCounters, CpuObservation, Delivery, Filesystem, Sample
from fleetdoctor.store import FixtureStore

NOW = datetime(2026, 10, 14, 12, tzinfo=UTC)
BOOT = UUID("11111111-1111-4111-8111-111111111111")
SESSION = UUID("22222222-2222-4222-8222-222222222222")
TOKEN = "a" * 40


def filesystem(percent: float = 10) -> Filesystem:
    used = int(percent)
    available = 100 - used
    return Filesystem(
        mountpoint="/",
        total_bytes=100,
        free_bytes=available,
        available_bytes=available,
        used_bytes=used,
        block_usage_percent=percent,
        inodes_total=100,
        inodes_free=90,
        inode_usage_percent=10,
    )


def cpu(
    busy: float | None,
    *,
    runnable: int | None = 3,
    cores: int | None = 2,
    load: float = 0,
) -> CpuObservation:
    return CpuObservation(
        interval_seconds=5 if busy is not None else None,
        busy_percent=busy,
        iowait_percent=2 if busy is not None else None,
        steal_percent=1 if busy is not None else None,
        logical_cores=cores,
        online_cpu_ids=list(range(cores)) if cores is not None else [],
        runnable_processes=runnable,
        load_1m=load,
        load_5m=load,
        load_15m=load,
        ticks_per_second=100,
        counters=CpuCounters(
            user=10, nice=0, system=2, idle=2, iowait=1, irq=0, softirq=1, steal=1
        ),
        process_inventory="complete",
        scanned_processes=0,
        errors=[]
        if busy is not None and cores is not None and runnable is not None
        else ["source_unavailable"],
    )


def sample(
    sequence: int,
    busy: float | None,
    *,
    runnable: int | None = 3,
    cores: int | None = 2,
    load: float = 0,
    disk: float = 10,
) -> Sample:
    return make_sample(
        "node-a",
        BOOT,
        SESSION,
        sequence,
        [filesystem(disk)],
        NOW + timedelta(seconds=sequence),
        cpu=cpu(busy, runnable=runnable, cores=cores, load=load),
    )


def post(client: TestClient, value: Sample) -> object:
    response = client.post(
        "/ingest",
        content=value.model_dump_json(),
        headers={"Authorization": "Bearer " + TOKEN},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_proc_parsers_and_independent_cpu_fractions() -> None:
    old, cores, runnable = parse_proc_stat(
        "cpu 100 10 20 200 30 4 6 5 99 88\ncpu0 1\ncpu1 1\nprocs_running 3\n"
    )
    new, _, _ = parse_proc_stat(
        "cpu 140 20 40 230 40 9 11 10 999 888\ncpu0 1\ncpu1 1\nprocs_running 4\n"
    )
    busy, iowait, steal = cpu_rates(old, new)
    assert (cores, runnable) == ((0, 1), 3)
    assert busy == pytest.approx(80 / 125 * 100)
    assert iowait == pytest.approx(10 / 125 * 100)
    assert steal == pytest.approx(5 / 125 * 100)
    assert parse_loadavg("1.25 2.5 3.75 2/100 1") == (1.25, 2.5, 3.75)
    with pytest.raises(ValueError, match="reset"):
        cpu_rates(new, old)


def test_process_parser_handles_spaces_and_embedded_close_parenthesis() -> None:
    # state through rss: field 2 is deliberately awkward; numeric indices remain stable.
    rest = ["R"] + ["0"] * 21
    rest[11], rest[12], rest[19], rest[21] = "10", "4", "12345", "7"
    parsed = parse_process_stat("42 (worker ) odd name) " + " ".join(rest))
    assert (parsed.pid, parsed.comm, parsed.ticks, parsed.starttime, parsed.rss_pages) == (
        42,
        "worker ) odd name",
        14,
        12345,
        7,
    )


def process_line(pid: int, comm: str, ticks: int, start: int, rss: int = 7) -> str:
    rest = ["R"] + ["0"] * 21
    rest[11], rest[12], rest[19], rest[21] = str(ticks), "0", str(start), str(rss)
    return f"{pid} ({comm}) " + " ".join(rest)


def test_collector_rates_pid_reuse_hotplug_and_interval_reset(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "loadavg").write_text("1 2 3 1/10 1\n")
    (proc / "42").mkdir()
    clock = [0.0]
    collector = CpuCollector(proc, clock=lambda: clock[0], ticks_per_second=100, page_size=4096)

    def write(user: int, idle: int, cores: int, ticks: int, start: int = 100) -> None:
        cpu_lines = "\n".join(f"cpu{index} 1" for index in range(cores))
        (proc / "stat").write_text(f"cpu {user} 0 0 {idle} 0 0 0 0\n{cpu_lines}\nprocs_running 3\n")
        (proc / "42" / "stat").write_text(process_line(42, "odd ) worker", ticks, start))

    write(100, 100, 1, 100)
    first = collector.collect((42,))
    assert first.busy_percent is None and first.processes[0].cpu_percent is None
    clock[0] = 5
    write(200, 100, 1, 600)
    second = collector.collect((42,))
    assert second.busy_percent == 100 and second.processes[0].cpu_percent == 100
    clock[0] = 10
    write(300, 100, 1, 1600)
    third = collector.collect((42,))
    assert third.processes[0].cpu_percent == 200
    clock[0] = 15
    write(400, 100, 1, 1700, start=101)
    reused = collector.collect((42,))
    assert reused.processes[0].cpu_percent is None
    clock[0] = 20
    write(500, 100, 2, 1800, start=101)
    hotplug = collector.collect((42,))
    assert hotplug.busy_percent is None and "cpu_rate_baseline_unavailable" in hotplug.errors
    clock[0] = 31
    write(600, 100, 2, 1900, start=101)
    long_interval = collector.collect((42,))
    assert long_interval.busy_percent is None
    with pytest.raises(ValueError, match="at most 16"):
        collector.collect(tuple(range(1, 18)))


def test_v2_contract_is_strict_and_v1_shape_has_no_cpu_key() -> None:
    v1 = make_sample("node-a", BOOT, SESSION, 3, [Filesystem(mountpoint="/", errors=["x"])], NOW)
    assert "cpu" not in v1.model_dump(mode="json")
    assert "cpu" not in v1.model_dump_json()
    with pytest.raises(ValidationError):
        Sample.model_validate(v1.model_dump(mode="json") | {"schema_version": 2})
    v2 = sample(1, 95)
    assert v2.schema_version == 2 and v2.cpu is not None
    with pytest.raises(ValidationError):
        Sample.model_validate(v2.model_dump(mode="json") | {"units": {"cpu": "percent"}})


def test_historical_v1_bytes_and_fingerprint_are_literal_regressions() -> None:
    value = make_sample(
        "node-a",
        BOOT,
        SESSION,
        3,
        [Filesystem(mountpoint="/", errors=["baseline_unavailable"])],
        NOW,
    )
    expected_hex = (
        "7b226167656e745f73657373696f6e5f6964223a2232323232323232322d323232322d343232322d383232322d323232323232323232323232222c"
        "22626f6f745f6964223a2231313131313131312d313131312d343131312d383131312d313131313131313131313131222c2264656c697665727922"
        "3a6e756c6c2c2266696c6573797374656d73223a5b7b22617661696c61626c655f6279746573223a6e756c6c2c22626c6f636b5f75736167655f70"
        "657263656e74223a6e756c6c2c226572726f7273223a5b22626173656c696e655f756e617661696c61626c65225d2c22667265655f627974657322"
        "3a6e756c6c2c22696e6f64655f75736167655f70657263656e74223a6e756c6c2c22696e6f6465735f66726565223a6e756c6c2c22696e6f6465"
        "735f746f74616c223a6e756c6c2c226d6f756e74706f696e74223a222f222c22746f74616c5f6279746573223a6e756c6c2c22757365645f627974"
        "6573223a6e756c6c7d5d2c226e6f64655f6964223a226e6f64652d61222c226f627365727665645f6174223a22323032362d31302d31345431323a"
        "30303a30305a222c22736368656d615f76657273696f6e223a312c2273657175656e6365223a332c22756e697473223a7b22696e6f646573223a22"
        "636f756e74222c226f62736572766174696f6e5f74696d65223a22555443222c227370616365223a226279746573222c227573616765223a227065"
        "7263656e74227d7d"
    )
    assert canonical_sample_bytes(value).hex() == expected_hex
    assert (
        sample_fingerprint(value)
        == "5508f3fefebb57c014c117e3a120a4c9cf98c775373ef9b930e65d38a44e3f85"
    )
    assert value.model_dump_json() == (
        '{"schema_version":1,"node_id":"node-a","boot_id":"11111111-1111-4111-8111-111111111111",'
        '"agent_session_id":"22222222-2222-4222-8222-222222222222","sequence":3,'
        '"observed_at":"2026-10-14T12:00:00Z","units":{"space":"bytes","inodes":"count",'
        '"usage":"percent","observation_time":"UTC"},"filesystems":[{"mountpoint":"/",'
        '"total_bytes":null,"free_bytes":null,"available_bytes":null,"used_bytes":null,'
        '"block_usage_percent":null,"inodes_total":null,"inodes_free":null,'
        '"inode_usage_percent":null,"errors":["baseline_unavailable"]}],"delivery":null}'
    )
    delivered = value.model_copy(update={"delivery": Delivery(discard_total=7)})
    assert delivered.model_dump_json() == value.model_dump_json().replace(
        '"delivery":null', '"delivery":{"discard_total":7}'
    )
    assert (
        sample_fingerprint(delivered)
        == "7f9fa81c48fd7138c7992d82021be2407438209669751dab46734f3d72c2c612"
    )


def test_cpu_trigger_recovery_metrics_staleness_and_history_mapping() -> None:
    current = [NOW]
    store = FixtureStore()
    app = create_app({"node-a": SecretStr(TOKEN)}, store=store, clock=lambda: current[0])
    client = TestClient(app)
    for sequence in range(3):
        current[0] = NOW + timedelta(seconds=sequence)
        post(client, sample(sequence, 90))
    active = store.active()
    assert len(active) == 1 and active[0].rule == "cpu_saturation" and active[0].resource == "cpu"
    view = client.get("/nodes/node-a/metrics").json()
    assert view["active_incident_counts"] == {
        "disk_block_exhaustion": 0,
        "inode_exhaustion": 0,
        "cpu_saturation": 1,
        "workload_oom": 0,
        "fd_pressure": 0,
    }
    assert view["cpu"]["runnable_processes"] == 3
    metrics = client.get("/metrics").text
    assert 'fleetdoctor_cpu_busy_ratio{node="node-a"} 0.9' in metrics
    assert 'fleetdoctor_active_incidents{node="node-a",rule="cpu_saturation"} 1.0' in metrics
    opening = active[0].opening_evidence
    for sequence in range(3, 6):
        current[0] = NOW + timedelta(seconds=sequence)
        post(client, sample(sequence, 79, runnable=None))
    resolved = store.get(active[0].id)
    assert resolved is not None and resolved.status == "resolved"
    assert resolved.opening_evidence == opening
    current[0] += timedelta(seconds=11)
    stale = client.get("/nodes/node-a/metrics").json()
    assert stale["cpu"] is None and "cpu" not in stale["sample"]
    assert 'fleetdoctor_cpu_busy_ratio{node="node-a"}' not in client.get("/metrics").text


def test_load_or_incomplete_trigger_data_cannot_open_and_mixed_rules_coexist() -> None:
    current = [NOW]
    store = FixtureStore()
    client = TestClient(
        create_app({"node-a": SecretStr(TOKEN)}, store=store, clock=lambda: current[0])
    )
    for sequence in range(3):
        current[0] = NOW + timedelta(seconds=sequence)
        post(client, sample(sequence, 10, load=100))
    assert not store.active()
    for sequence in range(3, 6):
        current[0] = NOW + timedelta(seconds=sequence)
        post(client, sample(sequence, 95, runnable=2, disk=98))
    assert {record.rule for record in store.active()} == {"disk_block_exhaustion"}
    for sequence in range(6, 9):
        current[0] = NOW + timedelta(seconds=sequence)
        post(client, sample(sequence, 95, runnable=3, disk=98))
    assert {(record.rule, record.resource) for record in store.active()} == {
        ("disk_block_exhaustion", "/"),
        ("cpu_saturation", "cpu"),
    }


def test_cpu_commit_failure_rolls_back_checkpoint_and_rule_state() -> None:
    current = [NOW]
    store = FixtureStore()
    app = create_app({"node-a": SecretStr(TOKEN)}, store=store, clock=lambda: current[0])
    client = TestClient(app)
    for sequence in range(2):
        current[0] = NOW + timedelta(seconds=sequence)
        post(client, sample(sequence, 95))
    before = store.snapshot({"node-a"}).checkpoints["node-a"]
    store.fail_after_incidents = True
    current[0] += timedelta(seconds=1)
    response = client.post(
        "/ingest",
        content=sample(2, 95).model_dump_json(),
        headers={"Authorization": "Bearer " + TOKEN},
    )
    assert response.status_code == 503
    assert store.snapshot({"node-a"}).checkpoints["node-a"] == before
    assert not app.state.fleet.evaluator.active


def test_cpu_threshold_boundaries_and_missing_data_break_windows() -> None:
    current = [NOW]
    store = FixtureStore()
    client = TestClient(
        create_app({"node-a": SecretStr(TOKEN)}, store=store, clock=lambda: current[0])
    )
    values = [90, 90, None, 90, 90]
    for sequence, busy in enumerate(values):
        current[0] = NOW + timedelta(seconds=sequence)
        post(client, sample(sequence, busy))
    assert not store.active()
    current[0] = NOW + timedelta(seconds=5)
    post(client, sample(5, 90))
    incident = store.active()[0]
    for sequence in range(6, 9):
        current[0] = NOW + timedelta(seconds=sequence)
        post(client, sample(sequence, 80))
    assert store.get(incident.id).status == "active"  # type: ignore[union-attr]
    current[0] = NOW + timedelta(seconds=9)
    post(client, sample(9, None))
    for sequence in range(10, 13):
        current[0] = NOW + timedelta(seconds=sequence)
        post(client, sample(sequence, 79))
    assert store.get(incident.id).status == "resolved"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "value",
    [
        {"trigger_busy_percent": 0},
        {"trigger_busy_percent": 80, "recovery_busy_percent": 80},
        {"consecutive_samples": True},
        {"max_gap_seconds": 11},
        {"severity": "fatal"},
    ],
)
def test_invalid_cpu_configuration(value: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        CpuConfig.model_validate(value)
