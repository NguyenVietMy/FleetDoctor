import asyncio
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from fleetdoctor import delivery
from fleetdoctor.agent import (
    enqueue_bounded_sample,
    make_sample,
    payload_bounded_sample,
    refresh_fd_watch,
)
from fleetdoctor.collector import create_app
from fleetdoctor.cpu import parse_process_stat
from fleetdoctor.fd import (
    FdCollectionWorker,
    FdCollector,
    WatchIdentity,
    WatchResponse,
    parse_soft_limit,
)
from fleetdoctor.incidents import FdConfig, Incident
from fleetdoctor.schema import (
    UNITS_V5,
    CpuObservation,
    Delivery,
    FdObservation,
    FdProcessIdentity,
    FdProcessObservation,
    Filesystem,
    HostMemoryObservation,
    MemoryObservation,
    NetworkObservation,
    NetworkProbeObservation,
    ProcessIdentity,
    ProcessObservation,
    Sample,
    TcpNetworkObservation,
)
from fleetdoctor.store import FixtureStore

NOW = datetime(2026, 10, 19, 18, tzinfo=UTC)
BOOT = UUID("11111111-1111-4111-8111-111111111111")
NEW_BOOT = UUID("33333333-3333-4333-8333-333333333333")
SESSION = UUID("22222222-2222-4222-8222-222222222222")
NEW_SESSION = UUID("44444444-4444-4444-8444-444444444444")
TOKEN = "f" * 40


def filesystem() -> Filesystem:
    return Filesystem(
        mountpoint="/",
        total_bytes=100,
        free_bytes=90,
        available_bytes=90,
        used_bytes=10,
        block_usage_percent=10,
        inodes_total=100,
        inodes_free=90,
        inode_usage_percent=10,
    )


def process_line(pid: int, start: int, comm: str = "fd-worker", state: str = "R") -> str:
    rest = [state] + ["0"] * 21
    rest[11], rest[12], rest[19], rest[21] = "10", "0", str(start), "7"
    return f"{pid} ({comm}) " + " ".join(rest)


def make_proc_process(
    proc: Path,
    pid: int,
    start: int,
    *,
    count: int,
    limit: str = "8",
) -> Path:
    directory = proc / str(pid)
    (directory / "fd").mkdir(parents=True)
    (directory / "stat").write_text(process_line(pid, start))
    (directory / "limits").write_text(
        f"Max open files            {limit}                  {limit}                  files\n"
    )
    set_fd_count(directory, count)
    return directory


def set_fd_count(directory: Path, count: int) -> None:
    fd_dir = directory / "fd"
    for entry in fd_dir.iterdir():
        entry.unlink()
    for number in range(count):
        (fd_dir / str(number)).write_text("")


def identity(pid: int = 42, start: int = 100, boot: UUID = BOOT) -> FdProcessIdentity:
    return FdProcessIdentity(boot_id=boot, pid=pid, starttime_ticks=start)


def fd_sample(
    sequence: int,
    observation: FdProcessObservation,
    *,
    boot: UUID = BOOT,
    session: UUID = SESSION,
) -> Sample:
    return make_sample(
        "node-a",
        boot,
        session,
        sequence,
        [filesystem()],
        NOW + timedelta(seconds=sequence * 5),
        cpu=CpuObservation(
            logical_cores=1,
            online_cpu_ids=[0],
            runnable_processes=0,
            process_inventory="complete",
            errors=["cpu_rate_baseline_unavailable"],
        ),
        memory=MemoryObservation(
            host=HostMemoryObservation(errors=["memory_rate_baseline_unavailable"])
        ),
        fd=FdObservation(
            observations=[observation],
            watch_coverage="available",
            watch_revision=sequence,
        ),
    )


def fd_block_sample(
    sequence: int,
    observations: list[FdProcessObservation],
    observed_at: datetime,
) -> Sample:
    value = fd_sample(sequence, observations[0] if observations else present(16))
    return value.model_copy(
        update={
            "observed_at": observed_at,
            "fd": FdObservation(
                observations=observations,
                watch_coverage="available",
                watch_revision=sequence,
            ),
        }
    )


def present(
    count: int,
    *,
    configured: bool = False,
    watched: bool = False,
    limit: int = 128,
    item: FdProcessIdentity | None = None,
) -> FdProcessObservation:
    target = item or identity()
    return FdProcessObservation(
        identity=target,
        status="present",
        configured=configured,
        watched=watched,
        comm="fd-worker",
        descriptor_count=count,
        soft_limit=limit,
        pressure_ratio=count / limit,
        count_delta=5,
        growth_per_second=1,
        growth_interval_seconds=5,
    )


def post(client: TestClient, value: Sample) -> dict[str, Any]:
    response = client.post(
        "/ingest",
        headers={"Authorization": "Bearer " + TOKEN},
        content=value.model_dump_json(),
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


def test_limit_parser_and_fd_schema_reject_contradictions() -> None:
    assert parse_soft_limit(
        "Max open files            128                  128                  files\n"
    ) == (
        128,
        False,
    )
    assert parse_soft_limit(
        "Max open files            unlimited            unlimited            files\n"
    ) == (
        None,
        True,
    )
    for malformed in ("", "Max open files 0 0 files\n", "Max open files nope 5 files\n"):
        with pytest.raises(ValueError):
            parse_soft_limit(malformed)
    with pytest.raises(ValidationError, match="incorrect FD pressure"):
        FdProcessObservation(
            identity=identity(),
            status="present",
            descriptor_count=100,
            soft_limit=128,
            pressure_ratio=0.5,
        )
    with pytest.raises(ValidationError, match="only valid for a watched identity"):
        FdProcessObservation(identity=identity(), status="exited")
    with pytest.raises(ValidationError, match="must be present together"):
        FdProcessObservation(
            identity=identity(),
            status="present",
            descriptor_count=4,
            soft_limit=8,
            pressure_ratio=0.5,
            growth_per_second=1,
            growth_interval_seconds=5,
        )
    with pytest.raises(ValidationError, match="incorrect FD growth rate"):
        FdProcessObservation(
            identity=identity(),
            status="present",
            descriptor_count=4,
            soft_limit=8,
            pressure_ratio=0.5,
            count_delta=-2,
            growth_per_second=1,
            growth_interval_seconds=5,
        )


def test_configured_outside_top_selection_and_signed_real_collector_baseline(
    tmp_path: Path,
) -> None:
    proc = tmp_path / "proc"
    configured = make_proc_process(proc, 42, 100, count=2, limit="8")
    make_proc_process(proc, 99, 900, count=1, limit="16")
    now = [10.0]
    collector = FdCollector(proc, clock=lambda: now[0])
    cpu = CpuObservation(
        logical_cores=1,
        online_cpu_ids=[0],
        runnable_processes=0,
        processes=[
            ProcessObservation(
                identity=ProcessIdentity(pid=99, starttime_ticks=900),
                comm="top-only",
                cpu_percent=80,
                rss_bytes=4096,
            )
        ],
        process_inventory="complete",
        scanned_processes=1,
        errors=["cpu_rate_baseline_unavailable"],
    )

    def configured_observation() -> FdProcessObservation:
        block = collector.collect(BOOT, cpu, (42,), (), "available", 1, None)
        return next(item for item in block.observations if item.identity.pid == 42)

    first = configured_observation()
    assert first.configured is True and first.watched is False
    assert first.descriptor_count == 2 and first.soft_limit == 8
    assert first.pressure_ratio == 0.25
    assert first.cpu_percent is None and first.rss_bytes is None
    assert (first.count_delta, first.growth_per_second, first.growth_interval_seconds) == (
        None,
        None,
        None,
    )

    set_fd_count(configured, 5)
    now[0] += 5
    positive = configured_observation()
    assert (positive.count_delta, positive.growth_per_second, positive.growth_interval_seconds) == (
        3,
        0.6,
        5,
    )

    set_fd_count(configured, 1)
    now[0] += 5
    negative = configured_observation()
    assert (negative.count_delta, negative.growth_per_second, negative.growth_interval_seconds) == (
        -4,
        -0.8,
        5,
    )

    now[0] += 11
    gap = configured_observation()
    assert (gap.count_delta, gap.growth_per_second, gap.growth_interval_seconds) == (
        None,
        None,
        None,
    )

    set_fd_count(configured, 3)
    now[0] += 5
    after_gap = configured_observation()
    assert (after_gap.count_delta, after_gap.growth_per_second) == (2, 0.4)


def test_configured_collection_does_not_depend_on_cpu_inventory(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    make_proc_process(proc, 42, 100, count=4, limit="8")
    cpu = CpuObservation(
        logical_cores=1,
        online_cpu_ids=[0],
        runnable_processes=0,
        process_inventory="unavailable",
        errors=["process_inventory_unavailable"],
    )
    block = FdCollector(proc, clock=lambda: 1.0).collect(BOOT, cpu, (42,), (), "available", 1, None)
    assert len(block.observations) == 1
    observation = block.observations[0]
    assert observation.configured is True
    assert observation.descriptor_count == 4
    assert observation.soft_limit == 8
    assert observation.pressure_ratio == 0.5
    assert observation.cpu_percent is None and observation.rss_bytes is None


@pytest.mark.parametrize(
    ("limit_text", "expected_limit", "unlimited", "error"),
    [
        ("unlimited", None, True, None),
        ("0", None, False, "limit_ValueError"),
        ("missing", None, False, "limit_ValueError"),
    ],
)
def test_real_collector_limit_unavailable_zero_and_unlimited_semantics(
    tmp_path: Path,
    limit_text: str,
    expected_limit: int | None,
    unlimited: bool,
    error: str | None,
) -> None:
    proc = tmp_path / "proc"
    directory = make_proc_process(proc, 42, 100, count=4, limit="8")
    if limit_text == "missing":
        (directory / "limits").write_text("no open-file row\n")
    else:
        (directory / "limits").write_text(
            f"Max open files            {limit_text}                  {limit_text}                  files\n"
        )
    cpu = CpuObservation(
        logical_cores=1,
        online_cpu_ids=[0],
        runnable_processes=0,
        process_inventory="unavailable",
        errors=["process_inventory_unavailable"],
    )
    observation = (
        FdCollector(proc, clock=lambda: 1.0)
        .collect(BOOT, cpu, (42,), (), "available", 1, None)
        .observations[0]
    )
    assert observation.descriptor_count == 4
    assert observation.soft_limit == expected_limit
    assert observation.limit_unlimited is unlimited
    assert observation.pressure_ratio is None
    assert (error in observation.errors) if error else not observation.errors


def test_real_collector_count_error_resets_growth_baseline(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    directory = make_proc_process(proc, 42, 100, count=2, limit="8")
    now = [1.0]
    cpu = CpuObservation(
        logical_cores=1,
        online_cpu_ids=[0],
        runnable_processes=0,
        process_inventory="unavailable",
        errors=["process_inventory_unavailable"],
    )
    collector = FdCollector(proc, clock=lambda: now[0])
    collector.collect(BOOT, cpu, (42,), (), "available", 1, None)
    for entry in (directory / "fd").iterdir():
        entry.unlink()
    (directory / "fd").rmdir()
    now[0] += 5
    failed = collector.collect(BOOT, cpu, (42,), (), "available", 2, None).observations[0]
    assert failed.descriptor_count is None
    assert failed.count_delta is None and failed.growth_per_second is None
    assert failed.errors == ["count_FileNotFoundError"]

    set_fd_count(make_proc_process(proc, 42, 100, count=3, limit="8"), 3)
    now[0] += 5
    reset = collector.collect(BOOT, cpu, (42,), (), "available", 3, None).observations[0]
    assert reset.descriptor_count == 3
    assert reset.count_delta is None and reset.growth_per_second is None


def test_identity_recheck_race_discards_configured_measurement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = tmp_path / "proc"
    make_proc_process(proc, 42, 100, count=4, limit="8")
    collector = FdCollector(proc, clock=lambda: 1.0)
    calls = 0

    def changing(boot: UUID, pid: int) -> tuple[FdProcessIdentity, str, str]:
        nonlocal calls
        calls += 1
        start = 100 if calls < 3 else 101
        return identity(pid, start, boot), "fd-worker", "R"

    monkeypatch.setattr(collector, "_current_identity", changing)
    cpu = CpuObservation(
        logical_cores=1,
        online_cpu_ids=[0],
        runnable_processes=0,
        process_inventory="unavailable",
        errors=["process_inventory_unavailable"],
    )
    block = collector.collect(BOOT, cpu, (42,), (), "available", 1, None)
    assert block.observations == []


def test_selected_candidate_exit_race_is_omitted_not_worker_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cpu = CpuObservation(
        logical_cores=1,
        online_cpu_ids=[0],
        runnable_processes=0,
        processes=[
            ProcessObservation(
                identity=ProcessIdentity(pid=42, starttime_ticks=100),
                comm="gone",
                configured=True,
            )
        ],
        process_inventory="complete",
        scanned_processes=1,
        errors=["cpu_rate_baseline_unavailable"],
    )
    collector = FdCollector(Path("/does-not-matter"))

    def gone(*args: object) -> object:
        raise FileNotFoundError

    monkeypatch.setattr(collector, "_current_identity", gone)
    block = collector.collect(BOOT, cpu, (42,), (), "available", 0, None)
    assert block.observations == []


def test_watched_zombie_is_exact_terminated_identity_evidence(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    directory = proc / "42"
    directory.mkdir(parents=True)
    (directory / "stat").write_text(process_line(42, 100, state="Z"))
    watched = identity()
    block = FdCollector(proc).collect(
        BOOT,
        CpuObservation(
            logical_cores=1,
            online_cpu_ids=[0],
            runnable_processes=0,
            process_inventory="complete",
            errors=["cpu_rate_baseline_unavailable"],
        ),
        (),
        (
            WatchIdentity(
                boot_id=watched.boot_id,
                pid=watched.pid,
                starttime_ticks=watched.starttime_ticks,
                resource=watched.resource,
            ),
        ),
        "available",
        1,
        None,
    )
    assert len(block.observations) == 1
    assert block.observations[0].status == "exited"
    assert block.observations[0].errors == ["process_zombie_terminated"]


def test_maximum_generated_fd_block_is_compacted_before_validation(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    processes = []
    for pid in range(2000, 2036):
        directory = proc / str(pid)
        (directory / "fd").mkdir(parents=True)
        (directory / "stat").write_text(process_line(pid, pid, "x" * 128))
        (directory / "limits").write_text(
            "Max open files            128                  128                  files\n"
        )
        for number in range(4):
            (directory / "fd" / str(number)).write_text("")
        processes.append(
            ProcessObservation(
                identity=ProcessIdentity(pid=pid, starttime_ticks=pid),
                comm="x" * 128,
                cpu_percent=100,
                rss_bytes=1000,
            )
        )
    watches = []
    for pid in range(1000, 1032):
        directory = proc / str(pid)
        (directory / "fd").mkdir(parents=True)
        (directory / "stat").write_text(process_line(pid, pid, "w" * 128))
        (directory / "limits").write_text(
            "Max open files            128                  128                  files\n"
        )
        for number in range(4):
            (directory / "fd" / str(number)).write_text("")
        watched = identity(pid, pid)
        watches.append(
            WatchIdentity(
                boot_id=watched.boot_id,
                pid=watched.pid,
                starttime_ticks=watched.starttime_ticks,
                resource=watched.resource,
            )
        )
    cpu = CpuObservation(
        logical_cores=1,
        online_cpu_ids=[0],
        runnable_processes=0,
        processes=processes,
        process_inventory="complete",
        scanned_processes=36,
        errors=["cpu_rate_baseline_unavailable"],
    )
    collector = FdCollector(proc, clock=lambda: 1.0)
    block = collector.collect(BOOT, cpu, (), tuple(watches), "available", 7, None)
    assert len(block.model_dump_json().encode()) <= 24 * 1024
    assert {item.identity.resource for item in block.observations if item.watched} == {
        item.resource for item in watches
    }
    assert block.context_trimmed
    assert "payload_budget" in block.errors


def test_fd_collection_budget_cutoff_retains_watched_unknown_status() -> None:
    calls = 0

    def clock() -> float:
        nonlocal calls
        calls += 1
        return 0.0 if calls == 1 else 1.0

    watched = identity(77, 700)
    block = FdCollector(Path("/unread"), clock=clock).collect(
        BOOT,
        CpuObservation(
            logical_cores=1,
            online_cpu_ids=[0],
            runnable_processes=0,
            process_inventory="complete",
            errors=["cpu_rate_baseline_unavailable"],
        ),
        (),
        (
            WatchIdentity(
                boot_id=watched.boot_id,
                pid=watched.pid,
                starttime_ticks=watched.starttime_ticks,
                resource=watched.resource,
            ),
        ),
        "available",
        1,
        None,
    )
    assert len(block.observations) == 1
    assert block.observations[0].status == "unknown"
    assert block.observations[0].errors == ["collection_budget"]


def test_fd_worker_not_ready_retains_all_watch_identity_and_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = FdCollectionWorker()
    first = identity(42, 100)
    second = identity(77, 700)
    watches = tuple(
        WatchIdentity(
            boot_id=item.boot_id,
            pid=item.pid,
            starttime_ticks=item.starttime_ticks,
            resource=item.resource,
        )
        for item in (first, second)
    )
    cpu = CpuObservation(
        logical_cores=1,
        online_cpu_ids=[0],
        runnable_processes=0,
        process_inventory="complete",
        errors=["cpu_rate_baseline_unavailable"],
    )
    monkeypatch.setattr(worker, "wait_ready", lambda timeout=0: False)

    block = worker.collect(
        BOOT,
        cpu,
        (77,),
        watches,
        "degraded",
        19,
        "watch_TimeoutError",
    )

    assert block.watch_coverage == "degraded"
    assert block.watch_revision == 19
    assert block.configured_pids == 1
    assert block.errors == ["fd_collection_worker_starting", "watch_TimeoutError"]
    assert len(block.errors) <= 8 and all(len(error) <= 128 for error in block.errors)
    assert [item.identity for item in block.observations] == [first, second]
    assert all(item.status == "unknown" and item.watched for item in block.observations)
    assert [item.configured for item in block.observations] == [False, True]
    assert all(item.errors == ["fd_collection_worker_starting"] for item in block.observations)


@pytest.mark.skipif(os.name != "posix", reason="spawned Linux FD worker recovery")
def test_fd_worker_reaps_delayed_death_and_restarts_with_watches() -> None:
    class DelayedDeath:
        alive = True
        closed = False

        def is_alive(self) -> bool:
            return self.alive

        def close(self) -> None:
            self.closed = True

    retained = DelayedDeath()
    worker = FdCollectionWorker()
    worker.process = retained
    # A fixed PID can belong to an unrelated process on the host runner.
    # Configure and watch this test process so both refer to one known identity.
    process = parse_process_stat(Path("/proc/self/stat").read_text())
    watched = identity(process.pid, process.starttime)
    configured = (watched.pid,)
    watch = WatchIdentity(
        boot_id=watched.boot_id,
        pid=watched.pid,
        starttime_ticks=watched.starttime_ticks,
        resource=watched.resource,
    )
    cpu = CpuObservation(
        logical_cores=1,
        online_cpu_ids=[0],
        runnable_processes=0,
        process_inventory="complete",
        errors=["cpu_rate_baseline_unavailable"],
    )
    try:
        unavailable = worker.collect(BOOT, cpu, configured, (watch,), "available", 4, None)
        assert unavailable.watch_coverage == "degraded"
        assert unavailable.observations[0].status == "unknown"
        assert unavailable.observations[0].configured is True
        assert unavailable.observations[0].errors == ["fd_collection_worker_stuck"]

        retained.alive = False
        starting = worker.collect(BOOT, cpu, configured, (watch,), "available", 4, None)
        assert retained.closed
        assert len(starting.observations) == 1
        assert starting.observations[0].identity == watched
        assert starting.observations[0].watched is True
        assert starting.observations[0].configured is True
        assert starting.watch_revision == 4
        if starting.errors == ["fd_collection_worker_starting"]:
            assert starting.watch_coverage == "degraded"
            assert starting.observations[0].status == "unknown"
            assert worker.wait_ready(5)
            recovered = worker.collect(BOOT, cpu, configured, (watch,), "available", 4, None)
        else:
            recovered = starting
        assert "fd_collection_worker_stuck" not in recovered.errors
        assert "fd_collection_worker_starting" not in recovered.errors
        assert len(recovered.observations) == 1
        assert recovered.observations[0].identity == watched
        assert recovered.observations[0].watched is True
        assert recovered.observations[0].configured is True
        assert recovered.watch_revision == 4
    finally:
        worker.close()


def test_fd_open_watch_restart_lost_ack_exit_resolution_and_metrics() -> None:
    now = [NOW]
    store = FixtureStore()
    app = create_app({"node-a": SecretStr(TOKEN)}, store=store, clock=lambda: now[0])
    client = TestClient(app)
    for sequence, count in enumerate((116, 120, 124)):
        now[0] = NOW + timedelta(seconds=sequence * 5)
        post(client, fd_sample(sequence, present(count)))
    opened = store.active()[0]
    assert opened.rule == "fd_pressure" and opened.opening_evidence["suspected_leak"] is True
    restored = Incident.model_validate(opened.model_dump(mode="json"))
    assert isinstance(restored.configuration, FdConfig)
    unauthorized = client.get("/nodes/node-a/fd-watch")
    assert unauthorized.status_code == 403
    watch = client.get("/nodes/node-a/fd-watch", headers={"Authorization": "Bearer " + TOKEN})
    assert watch.status_code == 200
    assert watch.json()["complete"] is True
    assert watch.json()["watches"][0]["resource"] == opened.resource

    # Rebuild state from the same durable store, as after collector restart/lost acknowledgement.
    app = create_app({"node-a": SecretStr(TOKEN)}, store=store, clock=lambda: now[0])
    client = TestClient(app)
    for offset in range(3):
        sequence = 3 + offset
        now[0] = NOW + timedelta(seconds=sequence * 5)
        post(
            client,
            fd_sample(
                sequence,
                FdProcessObservation(identity=identity(), status="exited", watched=True),
                session=NEW_SESSION,
            ),
        )
    resolved = store.get(opened.id)
    assert resolved is not None and resolved.status == "resolved"
    assert resolved.resolution_reason == "confirmed_exit"
    assert resolved.opening_evidence == opened.opening_evidence
    metrics = client.get("/metrics").text
    assert 'fleetdoctor_active_incidents{node="node-a",rule="fd_pressure"} 0.0' in metrics
    assert "fleetdoctor_fd_coverage_ratio" in metrics


def test_release_strict_threshold_and_three_new_boot_confirmations() -> None:
    now = [NOW]
    store = FixtureStore()
    client = TestClient(create_app({"node-a": SecretStr(TOKEN)}, store=store, clock=lambda: now[0]))
    for sequence in range(3):
        now[0] = NOW + timedelta(seconds=sequence * 5)
        post(client, fd_sample(sequence, present(124)))
    first = store.active()[0]
    # Equality at 80% is not recovery.
    for sequence in range(3, 6):
        now[0] = NOW + timedelta(seconds=sequence * 5)
        post(client, fd_sample(sequence, present(80, watched=True, limit=100)))
    assert store.get(first.id).status == "active"  # type: ignore[union-attr]
    for sequence in range(6, 9):
        now[0] = NOW + timedelta(seconds=sequence * 5)
        post(client, fd_sample(sequence, present(16, watched=True)))
    assert store.get(first.id).resolution_reason == "descriptor_release"  # type: ignore[union-attr]

    second_identity = identity(43, 200)
    for sequence in range(9, 12):
        now[0] = NOW + timedelta(seconds=sequence * 5)
        post(client, fd_sample(sequence, present(124, item=second_identity)))
    second = store.active()[0]
    for sequence in range(12, 14):
        now[0] = NOW + timedelta(seconds=sequence * 5)
        post(
            client,
            fd_sample(
                sequence,
                FdProcessObservation(identity=second_identity, status="replaced", watched=True),
                boot=NEW_BOOT,
            ),
        )
    assert store.get(second.id).status == "active"  # type: ignore[union-attr]
    sequence = 14
    now[0] = NOW + timedelta(seconds=sequence * 5)
    post(
        client,
        fd_sample(
            sequence,
            FdProcessObservation(identity=second_identity, status="replaced", watched=True),
            boot=NEW_BOOT,
        ),
    )
    result = store.get(second.id)
    assert result is not None and result.resolution_reason == "boot_replaced"
    assert result.latest_evidence["prior_boot_id"] == str(BOOT)
    assert result.latest_evidence["current_boot_id"] == str(NEW_BOOT)


def combined_payload_sample(host_errors: list[str]) -> Sample:
    watched = [
        FdProcessObservation(
            identity=identity(100 + index, 1000 + index),
            status="unknown",
            watched=True,
            errors=["watch_unknown"],
        )
        for index in range(32)
    ]
    candidates = [
        FdProcessObservation(
            identity=identity(1000 + index, 2000 + index),
            status="present",
            comm="c" * 128,
            descriptor_count=16,
            soft_limit=128,
            pressure_ratio=0.125,
            cpu_percent=10,
            rss_bytes=4096,
        )
        for index in range(20)
    ]
    block = FdObservation(
        observations=[*watched, *candidates],
        watch_coverage="degraded",
        watch_revision=1,
        errors=["watch_timeout"],
    )
    cpu_processes = [
        ProcessObservation(
            identity=ProcessIdentity(pid=3000 + index, starttime_ticks=4000 + index),
            comm="p" * 128,
            cpu_percent=10,
            rss_bytes=4096,
        )
        for index in range(36)
    ]
    return make_sample(
        "node-a",
        BOOT,
        SESSION,
        0,
        [Filesystem(mountpoint=f"/f{index}", errors=["e" * 256] * 8) for index in range(8)],
        NOW,
        cpu=CpuObservation(
            logical_cores=1,
            online_cpu_ids=[0],
            runnable_processes=0,
            processes=cpu_processes,
            process_inventory="complete",
            scanned_processes=36,
            errors=["cpu_rate_baseline_unavailable"],
        ),
        memory=MemoryObservation(host=HostMemoryObservation(errors=host_errors)),
        fd=block,
    )


def test_combined_payload_fallback_preserves_watched_statuses() -> None:
    value = combined_payload_sample(["m" * 1200] * 16)
    assert len(value.model_dump_json().encode()) > 65_536
    bounded = payload_bounded_sample(value)
    enveloped = bounded.model_copy(update={"delivery": Delivery(discard_total=delivery.MAX_TOTAL)})
    assert len(enveloped.model_dump_json().encode()) <= delivery.MAX_BODY
    assert len(bounded.fd.observations) == 32  # type: ignore[union-attr]


def test_v5_payload_compaction_bounds_marker_and_round_trips_saturated_errors() -> None:
    base = combined_payload_sample(["m" * 1200] * 16)
    network = NetworkObservation(
        probe=NetworkProbeObservation(
            status="available",
            target="192.0.2.10",
            sent=3,
            received=3,
            lost=0,
            loss_ratio=0,
            successful_sequences=[1, 2, 3],
            successful_rtts_ms=[1.0, 2.0, 3.0],
            median_rtt_ms=2.0,
            route_error="fixture_unknown_route",
        ),
        tcp=TcpNetworkObservation(
            retrans_segs=1,
            rate_status="baseline",
            curr_estab=1,
            state_counts={"established": 1},
            state_inventory="complete",
        ),
        interface_coverage="complete",
        elapsed_seconds=0.1,
        errors=[f"network_error_{index}" for index in range(8)],
    )
    raw = base.model_dump(mode="json")
    raw.update(schema_version=5, units=UNITS_V5, network=network.model_dump(mode="json"))
    value = Sample.model_validate(raw)
    assert len(value.model_dump_json().encode()) > delivery.MAX_BODY

    bounded = payload_bounded_sample(value)
    assert bounded.network is not None
    assert bounded.network.context_trimmed
    assert bounded.network.errors[-1] == "payload_budget"
    assert len(bounded.network.errors) == 8
    assert bounded.network.probe == network.probe
    envelope = bounded.model_copy(update={"delivery": Delivery(discard_total=delivery.MAX_TOTAL)})
    body = envelope.model_dump_json().encode()
    assert len(body) <= delivery.MAX_BODY
    decoded = Sample.model_validate_json(body)
    assert decoded.network is not None
    assert decoded.network.probe == network.probe
    assert decoded.network.errors[-1] == "payload_budget"


def test_delivery_envelope_boundary_compacts_fd_context_before_queueing() -> None:
    target_size = 65_530
    host_errors = ["m" * 1200 for _ in range(16)]
    initial = combined_payload_sample(host_errors)
    to_remove = len(initial.model_dump_json().encode()) - target_size
    assert 0 <= to_remove <= sum(len(error) - 1 for error in host_errors)
    for index, error in enumerate(host_errors):
        removed = min(to_remove, len(error) - 1)
        host_errors[index] = error[:-removed] if removed else error
        to_remove -= removed
    assert to_remove == 0

    value = combined_payload_sample(host_errors)
    assert value.delivery is None
    assert len(value.model_dump_json().encode()) == target_size
    zero_envelope = value.model_copy(update={"delivery": Delivery(discard_total=0)})
    max_envelope = value.model_copy(update={"delivery": Delivery(discard_total=delivery.MAX_TOTAL)})
    assert len(zero_envelope.model_dump_json().encode()) > delivery.MAX_BODY
    assert len(max_envelope.model_dump_json().encode()) > len(
        zero_envelope.model_dump_json().encode()
    )

    bounded = payload_bounded_sample(value)
    assert bounded.fd is not None and bounded.fd.context_trimmed
    assert "payload_budget" in bounded.fd.errors
    required = {
        (item.identity.resource, item.status)
        for item in value.fd.observations  # type: ignore[union-attr]
        if item.watched
    }
    retained = {(item.identity.resource, item.status) for item in bounded.fd.observations}
    assert retained == required
    bounded_max = bounded.model_copy(
        update={"delivery": Delivery(discard_total=delivery.MAX_TOTAL)}
    )
    assert len(bounded_max.model_dump_json().encode()) <= delivery.MAX_BODY

    queue = delivery.DeliveryQueue()
    enqueue_bounded_sample(queue, value, NOW)
    assert queue.discard_total == 0 and queue.reasons == {}
    assert len(queue.entries) == 1 and len(queue.entries[0].body) <= delivery.MAX_BODY
    queued = Sample.model_validate_json(queue.entries[0].body)
    assert queued.fd is not None and queued.fd.context_trimmed
    assert {(item.identity.resource, item.status) for item in queued.fd.observations} == required

    saturated = delivery.DeliveryQueue()
    saturated.discard_total = delivery.MAX_TOTAL
    enqueue_bounded_sample(saturated, value, NOW)
    assert len(saturated.entries) == 1
    assert len(saturated.entries[0].body) <= delivery.MAX_BODY
    assert saturated.discard_total == delivery.MAX_TOTAL and saturated.reasons == {}


def test_max_delivery_reservation_warns_only_when_actual_enqueue_drops(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def v3_payload_of_size(target: int) -> Sample:
        def build(error: str) -> Sample:
            return make_sample(
                "node-a",
                BOOT,
                SESSION,
                0,
                [Filesystem(mountpoint="/", errors=["fixture"])],
                NOW,
                cpu=CpuObservation(errors=["fixture"]),
                memory=MemoryObservation(host=HostMemoryObservation(errors=[error])),
            )

        base = build("m")
        filler_length = target - len(base.model_dump_json().encode()) + 1
        assert filler_length > 0
        value = build("m" * filler_length)
        assert len(value.model_dump_json().encode()) == target
        return Sample.model_validate_json(value.model_dump_json())

    candidate = v3_payload_of_size(65_510)
    actual = candidate.model_copy(update={"delivery": Delivery(discard_total=0)})
    reserved = candidate.model_copy(update={"delivery": Delivery(discard_total=delivery.MAX_TOTAL)})
    assert len(actual.model_dump_json().encode()) <= delivery.MAX_BODY
    assert len(reserved.model_dump_json().encode()) > delivery.MAX_BODY

    queue = delivery.DeliveryQueue()
    with caplog.at_level(logging.WARNING, logger="fleetdoctor.agent"):
        enqueue_bounded_sample(queue, candidate, NOW)
    assert len(queue.entries) == 1 and queue.discard_total == 0
    assert not any("delivery dropped" in record.getMessage() for record in caplog.records)

    caplog.clear()
    unavoidable = v3_payload_of_size(delivery.MAX_BODY)
    with caplog.at_level(logging.WARNING, logger="fleetdoctor.agent"):
        enqueue_bounded_sample(queue, unavoidable, NOW)
    assert len(queue.entries) == 1
    assert queue.discard_total == 1 and queue.reasons == {"oversize": 1}
    assert any(
        record.getMessage().startswith("delivery dropped oversized sample:")
        for record in caplog.records
    )


def test_pending_identity_absence_resets_opening_and_churn_is_bounded() -> None:
    now = [NOW]
    store = FixtureStore()
    app = create_app({"node-a": SecretStr(TOKEN)}, store=store, clock=lambda: now[0])
    client = TestClient(app)
    for sequence in range(2):
        now[0] = NOW + timedelta(seconds=sequence)
        value = fd_sample(sequence, present(124)).model_copy(update={"observed_at": now[0]})
        post(client, value)
    now[0] += timedelta(seconds=1)
    absent = fd_sample(2, present(16)).model_copy(
        update={
            "observed_at": now[0],
            "fd": FdObservation(watch_coverage="available", watch_revision=2, observations=[]),
        }
    )
    post(client, absent)
    now[0] += timedelta(seconds=1)
    post(client, fd_sample(3, present(124)).model_copy(update={"observed_at": now[0]}))
    assert store.active() == []
    for sequence in (4, 5):
        now[0] += timedelta(seconds=1)
        post(client, fd_sample(sequence, present(124)).model_copy(update={"observed_at": now[0]}))
    assert len(store.active()) == 1

    # Resolved/new candidate churn cannot leave one window per historical PID.
    churn_store = FixtureStore()
    churn_app = create_app({"node-a": SecretStr(TOKEN)}, store=churn_store, clock=lambda: now[0])
    churn = TestClient(churn_app)
    for sequence in range(100):
        now[0] += timedelta(milliseconds=50)
        item = identity(1000 + sequence, 5000 + sequence)
        post(
            churn,
            fd_sample(sequence, present(124, item=item)).model_copy(update={"observed_at": now[0]}),
        )
        assert len(churn_app.state.fleet.evaluator.fd.windows) <= 1


def test_active_incident_uses_frozen_max_gap_in_both_directions() -> None:
    def run_case(open_gap: float, current_gap: float) -> str:
        now = [NOW]
        store = FixtureStore()
        client = TestClient(
            create_app(
                {"node-a": SecretStr(TOKEN)},
                store=store,
                clock=lambda: now[0],
                fd_config=FdConfig(max_gap_seconds=open_gap),
            )
        )
        for sequence, seconds in enumerate((0, 1, 2)):
            now[0] = NOW + timedelta(seconds=seconds)
            post(
                client,
                fd_sample(sequence, present(124)).model_copy(update={"observed_at": now[0]}),
            )
        opened = store.active()[0]
        assert opened.configuration.max_gap_seconds == open_gap
        client = TestClient(
            create_app(
                {"node-a": SecretStr(TOKEN)},
                store=store,
                clock=lambda: now[0],
                fd_config=FdConfig(max_gap_seconds=current_gap),
            )
        )
        for sequence, seconds in zip((3, 4, 5), (10, 18, 26), strict=True):
            now[0] = NOW + timedelta(seconds=seconds)
            post(
                client,
                fd_sample(sequence, present(16, watched=True)).model_copy(
                    update={"observed_at": now[0]}
                ),
            )
        result = store.get(opened.id)
        assert result is not None
        return result.status

    assert run_case(10, 5) == "resolved"
    assert run_case(5, 10) == "active"


def test_fd_admission_cap_never_evicts_active_and_configured_candidate_wins() -> None:
    now = [NOW]
    store = FixtureStore()
    app = create_app({"node-a": SecretStr(TOKEN)}, store=store, clock=lambda: now[0])
    client = TestClient(app)
    initial = [present(124, item=identity(100 + index, 1000 + index)) for index in range(32)]
    for sequence in range(3):
        now[0] += timedelta(seconds=1)
        post(client, fd_block_sample(sequence, initial, now[0]))
    original = {incident.resource for incident in store.active()}
    assert len(original) == 32
    for sequence in range(3, 6):
        now[0] += timedelta(seconds=1)
        post(
            client,
            fd_block_sample(
                sequence,
                [
                    present(
                        124,
                        watched=True,
                        item=identity(100 + index, 1000 + index),
                    )
                    for index in range(32)
                ],
                now[0],
            ),
        )
    saturated = client.get("/nodes/node-a/metrics").json()
    assert saturated["fd_coverage"]["admission_capacity"] == "unavailable"
    assert not saturated["fd_coverage"]["candidate_overflow"]
    assert (
        'fleetdoctor_fd_admission_capacity_available{node="node-a"} 0.0'
        in client.get("/metrics").text
    )

    extra = present(124, configured=True, item=identity(999, 9999))
    for sequence in range(6, 9):
        now[0] += timedelta(seconds=1)
        post(client, fd_block_sample(sequence, [extra], now[0]))
    assert {incident.resource for incident in store.active()} == original
    view = client.get("/nodes/node-a/metrics").json()
    assert view["fd_coverage"]["admission_capacity"] == "unavailable"
    assert view["fd_coverage"]["candidate_overflow"]
    assert (
        'fleetdoctor_fd_admission_candidate_overflow{node="node-a"} 1.0'
        in client.get("/metrics").text
    )

    recovering = [
        present(
            16 if index == 0 else 124,
            watched=True,
            item=identity(100 + index, 1000 + index),
        )
        for index in range(32)
    ]
    for sequence in range(9, 12):
        now[0] += timedelta(seconds=1)
        post(client, fd_block_sample(sequence, recovering, now[0]))
    assert len(store.active()) == 31
    recovered = client.get("/nodes/node-a/metrics").json()
    assert recovered["fd_coverage"]["admission_capacity"] == "available"
    assert not recovered["fd_coverage"]["candidate_overflow"]
    assert (
        'fleetdoctor_fd_admission_capacity_available{node="node-a"} 1.0'
        in client.get("/metrics").text
    )

    priority_store = FixtureStore()
    priority_app = create_app(
        {"node-a": SecretStr(TOKEN)}, store=priority_store, clock=lambda: now[0]
    )
    priority_client = TestClient(priority_app)
    retained = [present(124, item=identity(200 + index, 2000 + index)) for index in range(31)]
    for sequence in range(3):
        now[0] += timedelta(seconds=1)
        post(priority_client, fd_block_sample(sequence, retained, now[0]))
    configured = present(124, configured=True, item=identity(800, 8000))
    ordinary = present(124, item=identity(700, 7000))
    for sequence in range(3, 6):
        now[0] += timedelta(seconds=1)
        post(
            priority_client,
            fd_block_sample(sequence, [ordinary, configured], now[0]),
        )
    active = {incident.resource for incident in priority_store.active()}
    assert len(active) == 32
    assert configured.identity.resource in active
    assert ordinary.identity.resource not in active


def test_watch_fetch_has_overall_deadline_preserves_cache_and_valid_empty_clears() -> None:
    item = identity()
    cached = WatchResponse(
        node_id="node-a",
        revision=7,
        complete=True,
        watches=[
            WatchIdentity(
                boot_id=item.boot_id,
                pid=item.pid,
                starttime_ticks=item.starttime_ticks,
                resource=item.resource,
            )
        ],
    )

    class SlowStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            for chunk in (
                b'{"node_id":',
                b'"node-a",',
                b'"revision":8,"complete":true,"watches":[]}',
            ):
                await asyncio.sleep(0.6)
                yield chunk

    async def exercise() -> None:
        def slow(request: httpx.Request) -> httpx.Response:
            assert request.headers["authorization"] == "Bearer " + TOKEN
            return httpx.Response(200, stream=SlowStream())

        started = time.monotonic()
        async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as client:
            result, coverage, error = await refresh_fd_watch(
                client, "http://collector/ingest", "node-a", SecretStr(TOKEN), cached
            )
        assert time.monotonic() - started < 1.5
        assert result == cached and coverage == "degraded" and error == "watch_TimeoutError"

        body = json.dumps(
            {"node_id": "node-a", "revision": 8, "complete": True, "watches": []}
        ).encode()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body))
        ) as client:
            result, coverage, error = await refresh_fd_watch(
                client, "http://collector/ingest", "node-a", SecretStr(TOKEN), cached
            )
        assert result is not None and result.watches == [] and result.revision == 8
        assert coverage == "available" and error is None

    asyncio.run(exercise())
