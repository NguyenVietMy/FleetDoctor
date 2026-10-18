import json
import os
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from fleetdoctor.agent import make_sample
from fleetdoctor.checkpoint import Checkpoint
from fleetdoctor.collector import create_app
from fleetdoctor.incidents import CpuConfig, DiskConfig, Incident, OomConfig
from fleetdoctor.memory import (
    JournalCoverage,
    MemoryCollectionWorker,
    MemoryCollector,
    parse_limit,
    parse_meminfo,
    parse_memory_events,
    parse_vmstat,
    validate_cgroup_paths,
)
from fleetdoctor.schema import (
    CpuObservation,
    Filesystem,
    HostMemoryObservation,
    KernelOomLog,
    MemoryEvents,
    MemoryObservation,
    Sample,
    WorkloadMemoryObservation,
)
from fleetdoctor.store import FixtureStore, StoreError

NOW = datetime(2026, 10, 17, 21, tzinfo=UTC)
BOOT = UUID("11111111-1111-4111-8111-111111111111")
SESSION = UUID("22222222-2222-4222-8222-222222222222")
TOKEN = "a" * 32
CGROUP = "/fleetdoctor-oom-test/workload"
MISSING_CGROUP = "/fleetdoctor-oom-test/missing"


def filesystem(usage: int = 10) -> Filesystem:
    return Filesystem(
        mountpoint="/",
        total_bytes=100,
        free_bytes=100 - usage,
        available_bytes=100 - usage,
        used_bytes=usage,
        block_usage_percent=usage,
        inodes_total=100,
        inodes_free=90,
        inode_usage_percent=10,
    )


def workload(
    oom: int,
    kills: int,
    *,
    usage: int = 90,
    limit: int | None = 100,
    inode: int = 42,
    stable: bool = True,
) -> WorkloadMemoryObservation:
    events = MemoryEvents(oom=oom, oom_kill=kills)
    return WorkloadMemoryObservation(
        cgroup_path=CGROUP,
        boot_id=BOOT,
        st_dev=7,
        st_ino=inode,
        current_bytes=usage,
        max_bytes=limit,
        max_unlimited=limit is None,
        usage_ratio=usage / limit if limit else None,
        swap_current_bytes=0,
        swap_max_bytes=0,
        events_before=events if stable else MemoryEvents(oom=max(0, oom - 1), oom_kill=kills),
        events=events,
        events_stable=stable,
        process_inventory="complete",
        errors=[] if stable else ["unstable_snapshot"],
    )


def sample(
    sequence: int,
    item: WorkloadMemoryObservation,
    gap: int = 5,
    *,
    disk: int = 10,
    busy: float | None = None,
) -> Sample:
    cpu = (
        CpuObservation(
            interval_seconds=5,
            busy_percent=busy,
            iowait_percent=0,
            steal_percent=0,
            logical_cores=2,
            online_cpu_ids=[0, 1],
            runnable_processes=3,
            process_inventory="complete",
        )
        if busy is not None
        else CpuObservation(errors=["cpu_rate_baseline_unavailable"])
    )
    return make_sample(
        "node-a",
        BOOT,
        SESSION,
        sequence,
        [filesystem(disk)],
        NOW + timedelta(seconds=sequence * gap),
        cpu=cpu,
        memory=MemoryObservation(
            host=HostMemoryObservation(errors=["memory_rate_baseline_unavailable"]),
            workloads=[item],
            kernel_log_coverage="permission_denied",
        ),
    )


def post(client: TestClient, value: Sample) -> object:
    return client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {TOKEN}"},
        content=value.model_dump_json(),
    )


def test_memory_parsers_units_unlimited_and_path_validation() -> None:
    assert parse_meminfo(
        "MemTotal: 10 kB\nMemAvailable: 7 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
    ) == (10240, 7168, 0, 0)
    assert parse_vmstat("pgfault 9\npgmajfault 2\npswpin 3\npswpout 4\n").pswpout == 4
    assert parse_memory_events("low 0\nhigh 2\nmax 3\noom 4\noom_kill 5\n").oom_kill == 5
    assert parse_limit("max\n") == (None, True)
    assert parse_limit("0\n") == (0, False)
    assert validate_cgroup_paths(CGROUP) == (CGROUP,)
    for invalid in ("/", "relative", "/a/../b", "/a//b", ",/a", "/a,/a"):
        with pytest.raises(ValueError):
            validate_cgroup_paths(invalid)


def test_schema_v3_accepts_above_limit_and_rejects_inconsistent_ratio() -> None:
    item = workload(1, 1, usage=110, limit=100)
    assert item.usage_ratio == 1.1
    value = sample(0, item)
    assert value.schema_version == 3
    assert value.model_dump(mode="json")["memory"]["workloads"][0]["usage_ratio"] == 1.1
    with pytest.raises(ValidationError):
        WorkloadMemoryObservation(
            **(item.model_dump(exclude={"usage_ratio"}) | {"usage_ratio": 1.0})
        )
    with pytest.raises(ValidationError, match="events_stable"):
        WorkloadMemoryObservation(**(item.model_dump() | {"events_stable": False}))
    with pytest.raises(ValidationError, match="events_stable"):
        WorkloadMemoryObservation(
            **(
                item.model_dump()
                | {
                    "events_before": MemoryEvents(oom=0, oom_kill=0),
                    "events_stable": True,
                }
            )
        )
    other_boot = item.model_copy(update={"boot_id": UUID(int=99)})
    with pytest.raises(ValidationError, match="workload boot identity"):
        make_sample(
            "node-a",
            BOOT,
            SESSION,
            1,
            [filesystem()],
            NOW,
            cpu=CpuObservation(errors=["baseline"]),
            memory=MemoryObservation(
                host=HostMemoryObservation(errors=["baseline"]), workloads=[other_boot]
            ),
        )


def test_collector_reads_rates_generation_and_event_bracket(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    root = tmp_path / "cgroup"
    leaf = root / CGROUP.lstrip("/")
    leaf.mkdir(parents=True)
    proc.mkdir()
    (proc / "meminfo").write_text(
        "MemTotal: 100 kB\nMemAvailable: 80 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
    )
    (proc / "vmstat").write_text("pgfault 10\npgmajfault 1\npswpin 2\npswpout 3\n")
    for name, value in {
        "memory.current": "64",
        "memory.max": "32",
        "memory.swap.current": "0",
        "memory.swap.max": "max",
        "memory.events.local": "oom 0\noom_kill 0\n",
        "cgroup.procs": "",
    }.items():
        (leaf / name).write_text(value)
    times = iter((1.0, 6.0, 11.0, 16.0))
    collector = MemoryCollector(
        proc=proc,
        cgroup_root=root,
        clock=lambda: next(times),
        boot_id=BOOT,
        page_size=4096,
        journal=lambda cursor: ([], "cursor", "available"),
    )
    first = collector.collect((CGROUP,))
    assert first.kernel_log_coverage == "baseline"
    assert first.workloads[0].usage_ratio == 2
    (proc / "vmstat").write_text("pgfault 20\npgmajfault 6\npswpin 4\npswpout 8\n")
    second = collector.collect((CGROUP,))
    assert second.host.interval_seconds == 5
    assert second.host.pgfault_per_second == 2
    assert second.host.swap_out_bytes_per_second == 4096
    assert second.workloads[0].generation_key.endswith(
        f"|{leaf.stat().st_dev}|{leaf.stat().st_ino}"
    )
    (proc / "vmstat").write_text("pgfault 1\npgmajfault 1\npswpin 1\npswpout 1\n")
    reset = collector.collect((CGROUP,))
    assert reset.host.interval_seconds is None
    assert "memory_counter_reset" in reset.host.errors
    (proc / "42").mkdir()

    def write_process(starttime: int) -> None:
        fields = ["R"] + ["0"] * 21
        fields[19], fields[21] = str(starttime), "7"
        (proc / "42" / "stat").write_text("42 (worker) " + " ".join(fields))

    (leaf / "cgroup.procs").write_text("42\n")
    write_process(100)
    first_identity = collector.collect((CGROUP,)).workloads[0].processes[0].identity
    assert first_identity.starttime_ticks == 100
    write_process(101)
    # PID/start-time, rather than PID alone, is the reusable identity boundary.
    collector.clock = lambda: 21.0
    reused_identity = collector.collect((CGROUP,)).workloads[0].processes[0].identity
    assert reused_identity.pid == 42 and reused_identity.starttime_ticks == 101


def test_missing_cgroup_and_journal_rebaseline_and_exact_memcg_scope(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    root = tmp_path / "cgroup"
    proc.mkdir()
    root.mkdir()
    (proc / "meminfo").write_text(
        "MemTotal: 100 kB\nMemAvailable: 80 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
    )
    (proc / "vmstat").write_text("pgfault 10\npgmajfault 1\npswpin 2\npswpout 3\n")
    old: dict[str, object] = {
        "__CURSOR": "old",
        "__REALTIME_TIMESTAMP": "1",
        "MESSAGE": "oom-kill: oom_memcg=" + CGROUP,
    }
    exact: dict[str, object] = {
        "__CURSOR": "new",
        "__REALTIME_TIMESTAMP": "2",
        "MESSAGE": "oom-kill: oom_memcg=" + CGROUP + ",task_memcg=/elsewhere",
    }
    substring_only: dict[str, object] = {
        "__CURSOR": "substring",
        "__REALTIME_TIMESTAMP": "2",
        "MESSAGE": "unscoped text mentions " + CGROUP + " but has no explicit memcg field",
    }
    descendant: dict[str, object] = {
        "__CURSOR": "descendant",
        "__REALTIME_TIMESTAMP": "2",
        "MESSAGE": "oom-kill: oom_memcg=" + CGROUP + "/child",
    }
    responses: Iterator[tuple[list[dict[str, object]], str | None, JournalCoverage]] = iter(
        (
            ([], None, "permission_denied"),
            ([old], "old", "available"),
            ([substring_only, descendant, exact], "new", "available"),
        )
    )
    seen_cursors: list[str | None] = []

    def journal(
        cursor: str | None,
    ) -> tuple[list[dict[str, object]], str | None, JournalCoverage]:
        seen_cursors.append(cursor)
        return next(responses)

    collector = MemoryCollector(
        proc=proc,
        cgroup_root=root,
        clock=iter((1.0, 2.0, 3.0)).__next__,
        boot_id=BOOT,
        page_size=4096,
        journal=journal,
    )
    denied = collector.collect((CGROUP,))
    assert denied.kernel_log_coverage == "permission_denied"
    assert denied.workload_errors == {CGROUP: ["cgroup_missing"]}
    rebased = collector.collect((CGROUP,))
    assert rebased.kernel_log_coverage == "baseline" and not rebased.kernel_logs
    current = collector.collect((CGROUP,))
    assert seen_cursors == [None, None, "old"]
    assert [item.cursor for item in current.kernel_logs] == ["new"]
    assert current.kernel_logs[0].cgroup_path == CGROUP
    assert current.kernel_logs[0].boot_id == BOOT


def test_v3_ingest_requires_explicit_exact_configured_cgroup_coverage() -> None:
    client = TestClient(
        create_app({"node-a": SecretStr(TOKEN)}, store=FixtureStore(), cgroup_paths=(CGROUP,))
    )
    missing = sample(0, workload(0, 0))
    assert missing.memory is not None
    missing.memory = MemoryObservation(
        host=missing.memory.host,
        workload_errors={CGROUP: ["cgroup_missing"]},
        kernel_log_coverage="permission_denied",
    )
    assert post(client, missing).status_code == 200  # type: ignore[attr-defined]
    wrong = sample(1, workload(0, 0))
    assert wrong.memory is not None
    wrong.memory = wrong.memory.model_copy(
        update={"workload_errors": {"/unconfigured": ["cgroup_missing"]}}
    )
    assert post(client, wrong).status_code == 422  # type: ignore[attr-defined]


def test_journal_validates_boot_cursor_and_permission(monkeypatch: pytest.MonkeyPatch) -> None:
    collector = MemoryCollector(
        boot_id=BOOT, page_size=4096, journal=lambda cursor: ([], None, "available")
    )
    wrong_boot = json.dumps(
        {
            "__CURSOR": "cursor-1",
            "__REALTIME_TIMESTAMP": "1",
            "_BOOT_ID": str(UUID(int=99)),
            "MESSAGE": "oom-kill: oom_memcg=" + CGROUP,
        }
    ).encode()
    monkeypatch.setattr(collector, "_bounded_journal_command", lambda command: (wrong_boot, b"", 0))
    assert collector._journal(None)[2] == "cursor_lost"
    monkeypatch.setattr(
        collector,
        "_bounded_journal_command",
        lambda command: (b"", b"Not seeing messages due to insufficient permissions", 0),
    )
    assert collector._journal(None)[2] == "permission_denied"


def test_journal_exact_cap_overflow_and_fresh_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    collector = MemoryCollector(
        boot_id=BOOT, page_size=4096, journal=lambda cursor: ([], None, "available")
    )
    commands: list[list[str]] = []

    def body(count: int) -> bytes:
        return (
            "\n".join(
                json.dumps(
                    {
                        "__CURSOR": f"cursor-{index}",
                        "__REALTIME_TIMESTAMP": str(index + 1),
                        "_BOOT_ID": str(BOOT),
                        "MESSAGE": "ordinary kernel record",
                    }
                )
                for index in range(count)
            )
            + f"\n-- cursor: cursor-{count - 1}\n"
        ).encode()

    def exact(command: list[str]) -> tuple[bytes, bytes, int]:
        commands.append(command)
        return body(64), b"", 0

    monkeypatch.setattr(collector, "_bounded_journal_command", exact)
    records, cursor, coverage = collector._journal("before")
    assert len(records) == 64 and cursor == "cursor-63" and coverage == "available"
    assert "--lines=65" in commands[0]

    monkeypatch.setattr(collector, "_bounded_journal_command", lambda command: (body(65), b"", 0))
    assert collector._journal("cursor-63") == ([], "cursor-63", "cursor_lost")

    responses: Iterator[tuple[list[dict[str, object]], str | None, JournalCoverage]] = iter(
        (
            ([], "baseline", "available"),
            ([], "baseline", "cursor_lost"),
            ([], "fresh", "available"),
        )
    )
    collector.journal = lambda cursor: next(responses)
    assert collector._logs((CGROUP,))[1] == "baseline"
    assert collector._logs((CGROUP,))[1] == "cursor_lost"
    logs, baseline_coverage, errors = collector._logs((CGROUP,))
    assert not logs and baseline_coverage == "baseline" and not errors
    assert collector.journal_cursor == "fresh"


def test_unicode_kernel_logs_respect_encoded_message_and_total_budget() -> None:
    records: list[dict[str, object]] = [
        {
            "__CURSOR": f"unicode-{index}",
            "__REALTIME_TIMESTAMP": str(index + 1),
            "_BOOT_ID": str(BOOT),
            "MESSAGE": "oom-kill: oom_memcg=" + CGROUP + " " + "\N{SNOWMAN}" * 600,
        }
        for index in range(16)
    ]
    collector = MemoryCollector(
        boot_id=BOOT,
        page_size=4096,
        journal=lambda cursor: (records, "unicode-15", "available"),
    )
    collector.journal_initialized = True
    collector.journal_cursor = "before"
    logs, coverage, errors = collector._logs((CGROUP,))
    assert coverage == "available" and not errors and len(logs) == 16
    assert all(len(item.message.encode("utf-8")) <= 512 for item in logs)
    assert sum(len(item.message.encode("utf-8")) for item in logs) <= 8192
    assert all(item.cgroup_path == CGROUP for item in logs)
    MemoryObservation(
        host=HostMemoryObservation(errors=["baseline"]),
        kernel_logs=logs,
        kernel_log_coverage="available",
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX pipe selector proof")
def test_journal_subprocess_output_is_hard_bounded() -> None:
    collector = MemoryCollector(
        boot_id=BOOT, page_size=4096, journal=lambda cursor: ([], None, "available")
    )
    with pytest.raises(ValueError, match="bounded capture"):
        collector._bounded_journal_command(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 70000)"]
        )


def test_immediate_kill_update_recovery_recurrence_and_metrics() -> None:
    current = [NOW]
    store = FixtureStore()
    app = create_app(
        {"node-a": SecretStr(TOKEN)},
        store=store,
        clock=lambda: current[0],
        cgroup_paths=(CGROUP,),
    )
    client = TestClient(app)
    assert post(client, sample(0, workload(0, 0))).status_code == 200  # type: ignore[attr-defined]
    current[0] += timedelta(seconds=5)
    assert post(client, sample(1, workload(1, 1))).status_code == 200  # type: ignore[attr-defined]
    active = store.active()
    assert len(active) == 1 and active[0].rule == "workload_oom"
    assert active[0].opening_evidence["event_delta"] == {"oom": 1, "oom_kill": 1}
    assert active[0].resource.startswith(CGROUP + "|")
    filtered = client.get("/diagnoses", params={"rule": "workload_oom"}).json()
    assert filtered["total"] == 1 and filtered["diagnoses"][0]["rule"] == "workload_oom"
    for sequence in range(2, 5):
        current[0] += timedelta(seconds=5)
        assert post(client, sample(sequence, workload(1, 1, usage=79))).status_code == 200  # type: ignore[attr-defined]
    assert not store.active()
    resolved = next(iter(store.records.values()))
    assert resolved.status == "resolved"
    current[0] += timedelta(seconds=5)
    assert post(client, sample(5, workload(2, 2, usage=70))).status_code == 200  # type: ignore[attr-defined]
    assert len(store.active()) == 1 and store.active()[0].id != resolved.id
    metrics = client.get("/metrics").text
    assert 'fleetdoctor_active_incidents{node="node-a",rule="workload_oom"} 1.0' in metrics
    assert (
        f'fleetdoctor_workload_memory_oom_kill_total{{cgroup="{CGROUP}",node="node-a"}} 2.0'
        in metrics
    )


def test_every_configured_cgroup_has_binary_coverage_and_unavailable_data_is_absent() -> None:
    current = [NOW]
    client = TestClient(
        create_app(
            {"node-a": SecretStr(TOKEN)},
            store=FixtureStore(),
            clock=lambda: current[0],
            cgroup_paths=(CGROUP, MISSING_CGROUP),
        )
    )
    available = sample(0, workload(0, 0))
    assert available.memory is not None
    available.memory = available.memory.model_copy(
        update={"workload_errors": {MISSING_CGROUP: ["cgroup_permission_denied"]}}
    )
    assert post(client, available).status_code == 200  # type: ignore[attr-defined]
    view = client.get("/nodes/node-a/metrics").json()
    assert view["memory_coverage"]["workloads"] == {
        CGROUP: "available",
        MISSING_CGROUP: "unavailable",
    }
    metrics = client.get("/metrics").text
    assert f'fleetdoctor_memory_coverage_ratio{{node="node-a",scope="{CGROUP}"}} 1.0' in metrics
    assert (
        f'fleetdoctor_memory_coverage_ratio{{node="node-a",scope="{MISSING_CGROUP}"}} 0.0'
        in metrics
    )
    assert not any(
        f'cgroup="{MISSING_CGROUP}"' in line
        for line in metrics.splitlines()
        if not line.startswith("fleetdoctor_memory_coverage_ratio")
    )

    partial = WorkloadMemoryObservation(
        cgroup_path=CGROUP,
        boot_id=BOOT,
        st_dev=7,
        st_ino=42,
        errors=["cgroup_permission_denied"],
    )
    partial_sample = sample(1, workload(0, 0))
    assert partial_sample.memory is not None
    partial_sample.memory = partial_sample.memory.model_copy(
        update={
            "workloads": [partial],
            "workload_errors": {MISSING_CGROUP: ["cgroup_missing"]},
        }
    )
    current[0] = partial_sample.observed_at
    assert post(client, partial_sample).status_code == 200  # type: ignore[attr-defined]
    partial_metrics = client.get("/metrics").text
    for path in (CGROUP, MISSING_CGROUP):
        assert (
            f'fleetdoctor_memory_coverage_ratio{{node="node-a",scope="{path}"}} 0.0'
            in partial_metrics
        )
    assert f'fleetdoctor_workload_memory_current_bytes{{cgroup="{CGROUP}"' not in partial_metrics
    assert f'fleetdoctor_workload_memory_oom_total{{cgroup="{CGROUP}"' not in partial_metrics

    current[0] = partial_sample.observed_at + timedelta(seconds=11)
    stale_metrics = client.get("/metrics").text
    for path in (CGROUP, MISSING_CGROUP):
        assert (
            f'fleetdoctor_memory_coverage_ratio{{node="node-a",scope="{path}"}} 0.0'
            in stale_metrics
        )


def test_explicit_unstable_marker_keeps_counters_but_blocks_recovery_and_metrics() -> None:
    current = [NOW]
    store = FixtureStore()
    client = TestClient(
        create_app(
            {"node-a": SecretStr(TOKEN)},
            store=store,
            clock=lambda: current[0],
            cgroup_paths=(CGROUP,),
        )
    )

    def assert_unavailable() -> dict[str, object]:
        view: dict[str, object] = client.get("/nodes/node-a/metrics").json()
        assert view["memory_coverage"] == {
            "host": "unavailable",
            "kernel_logs": "permission_denied",
            "workloads": {CGROUP: "unavailable"},
        }
        metrics = client.get("/metrics").text
        assert f'fleetdoctor_memory_coverage_ratio{{node="node-a",scope="{CGROUP}"}} 0.0' in metrics
        assert not any(
            line.startswith("fleetdoctor_workload_") and f'cgroup="{CGROUP}"' in line
            for line in metrics.splitlines()
        )
        return view

    def marked(oom: int, kills: int, *, usage: int = 90) -> WorkloadMemoryObservation:
        return workload(oom, kills, usage=usage).model_copy(
            update={"errors": ["unstable_snapshot"]}
        )

    opening = marked(1, 1)
    assert opening.events_stable is True
    assert opening.snapshot_stable is False
    assert "snapshot_stable" not in opening.model_dump()

    assert post(client, sample(0, workload(0, 0))).status_code == 200  # type: ignore[attr-defined]
    current[0] += timedelta(seconds=5)
    assert post(client, sample(1, opening)).status_code == 200  # type: ignore[attr-defined]
    view = assert_unavailable()
    assert view["memory"]["workloads"][0]["events"]["oom_kill"] == 1  # type: ignore[index]
    assert len(store.active()) == 1
    assert store.active()[0].opening_evidence["event_delta"] == {"oom": 1, "oom_kill": 1}
    assert (
        store.active()[0].opening_evidence["coverage"]["snapshot"] == "unstable"  # type: ignore[index, call-overload]
    )

    for sequence in (2, 3, 4):
        current[0] += timedelta(seconds=5)
        assert post(client, sample(sequence, marked(1, 1, usage=79))).status_code == 200  # type: ignore[attr-defined]
        assert_unavailable()
        assert len(store.active()) == 1
        assert (
            store.active()[0].latest_evidence["coverage"]["snapshot"] == "unstable"  # type: ignore[index, call-overload]
        )

    # Two healthy samples begin recovery, but a marked sample resets the sequence.
    for sequence in (5, 6):
        current[0] += timedelta(seconds=5)
        assert post(client, sample(sequence, workload(1, 1, usage=79))).status_code == 200  # type: ignore[attr-defined]
        assert len(store.active()) == 1

    current[0] += timedelta(seconds=5)
    assert post(client, sample(7, marked(1, 1, usage=79))).status_code == 200  # type: ignore[attr-defined]
    assert_unavailable()
    assert len(store.active()) == 1

    for sequence in (8, 9):
        current[0] += timedelta(seconds=5)
        assert post(client, sample(sequence, workload(1, 1, usage=79))).status_code == 200  # type: ignore[attr-defined]
        assert len(store.active()) == 1

    stable_view = client.get("/nodes/node-a/metrics").json()
    assert stable_view["memory_coverage"]["workloads"] == {CGROUP: "available"}
    stable_metrics = client.get("/metrics").text
    assert (
        f'fleetdoctor_memory_coverage_ratio{{node="node-a",scope="{CGROUP}"}} 1.0' in stable_metrics
    )
    for metric in (
        "fleetdoctor_workload_memory_current_bytes",
        "fleetdoctor_workload_memory_max_bytes",
        "fleetdoctor_workload_memory_usage_ratio",
        "fleetdoctor_workload_swap_current_bytes",
        "fleetdoctor_workload_swap_max_bytes",
        "fleetdoctor_workload_memory_oom_total",
        "fleetdoctor_workload_memory_oom_kill_total",
    ):
        assert f'{metric}{{cgroup="{CGROUP}",node="node-a"}}' in stable_metrics
    current[0] += timedelta(seconds=5)
    assert post(client, sample(10, workload(1, 1, usage=79))).status_code == 200  # type: ignore[attr-defined]
    assert not store.active()


@pytest.mark.parametrize("break_kind", ["gap", "session", "boot", "counter_reset"])
def test_oom_continuity_breaks_cannot_infer_a_kill(break_kind: str) -> None:
    store = FixtureStore()
    current = [NOW]
    client = TestClient(
        create_app(
            {"node-a": SecretStr(TOKEN)},
            store=store,
            clock=lambda: current[0],
            cgroup_paths=(CGROUP,),
        )
    )
    baseline = sample(0, workload(5, 5))
    post(client, baseline)
    candidate = sample(1, workload(6, 6))
    if break_kind == "gap":
        candidate = candidate.model_copy(update={"observed_at": NOW + timedelta(seconds=11)})
    elif break_kind == "session":
        candidate = candidate.model_copy(update={"agent_session_id": UUID(int=88)})
    elif break_kind == "boot":
        other_boot = UUID(int=77)
        other_workload = candidate.memory.workloads[0].model_copy(update={"boot_id": other_boot})  # type: ignore[union-attr]
        candidate = candidate.model_copy(
            update={
                "boot_id": other_boot,
                "memory": candidate.memory.model_copy(update={"workloads": [other_workload]}),  # type: ignore[union-attr]
            }
        )
    else:
        candidate = sample(1, workload(4, 4))
    current[0] = candidate.observed_at
    post(client, candidate)
    assert not store.active()


def test_active_oom_restart_json_reload_and_threshold_require_three_new_samples() -> None:
    current = [NOW]
    store = FixtureStore()
    first = TestClient(
        create_app(
            {"node-a": SecretStr(TOKEN)},
            store=store,
            clock=lambda: current[0],
            cgroup_paths=(CGROUP,),
        )
    )
    post(first, sample(0, workload(0, 0)))
    current[0] += timedelta(seconds=5)
    post(first, sample(1, workload(1, 1)))
    opened = store.active()[0]
    store.records[opened.id] = Incident.model_validate_json(opened.model_dump_json())
    restarted = TestClient(
        create_app(
            {"node-a": SecretStr(TOKEN)},
            store=store,
            clock=lambda: current[0],
            cgroup_paths=(CGROUP,),
        )
    )
    assert restarted.get("/diagnoses/" + str(opened.id)).json()["evidence_stale"] is True
    current[0] += timedelta(seconds=5)
    post(restarted, sample(2, workload(1, 1, usage=80)))
    for sequence in (3, 4):
        current[0] += timedelta(seconds=5)
        post(restarted, sample(sequence, workload(1, 1, usage=79)))
    assert store.active()
    current[0] += timedelta(seconds=5)
    post(restarted, sample(5, workload(1, 1, usage=79)))
    assert not store.active()


def test_memory_worker_stuck_is_explicit_and_never_spawns_replacement() -> None:
    class Process:
        def is_alive(self) -> bool:
            return True

    worker = MemoryCollectionWorker()
    worker.process = Process()
    worker.conn = None
    result = worker.collect((CGROUP,))
    assert result.host.errors == ["memory_collection_worker_stuck"]
    assert result.workload_errors == {CGROUP: ["memory_collection_worker_stuck"]}


def test_baselines_resets_instability_missing_limits_and_generation_isolation() -> None:
    current = [NOW]
    store = FixtureStore()
    client = TestClient(
        create_app(
            {"node-a": SecretStr(TOKEN)},
            store=store,
            clock=lambda: current[0],
            cgroup_paths=(CGROUP,),
        )
    )
    post(client, sample(0, workload(9, 9)))
    current[0] += timedelta(seconds=5)
    post(client, sample(1, workload(10, 9)))  # oom without a kill cannot open
    assert not store.active()
    current[0] += timedelta(seconds=5)
    post(client, sample(2, workload(11, 10, stable=False)))  # racing event still opens
    assert len(store.active()) == 1
    for sequence, item in (
        (3, workload(11, 10, usage=1, limit=None)),
        (4, workload(11, 10, usage=1, stable=False)),
        (5, workload(11, 10, usage=1)),
        (6, workload(11, 10, usage=1)),
    ):
        current[0] += timedelta(seconds=5)
        post(client, sample(sequence, item))
    assert len(store.active()) == 1
    current[0] += timedelta(seconds=5)
    post(client, sample(7, workload(11, 10, usage=1)))
    assert not store.active()
    # A replacement generation baselines independently and does not consume old counters.
    current[0] += timedelta(seconds=5)
    post(client, sample(8, workload(50, 50, inode=99)))
    assert not store.active()
    current[0] += timedelta(seconds=5)
    post(client, sample(9, workload(51, 51, inode=99)))
    assert len(store.active()) == 1


def test_removed_generation_stays_active_and_replacement_opens_independently() -> None:
    current = [NOW]
    store = FixtureStore()
    client = TestClient(
        create_app(
            {"node-a": SecretStr(TOKEN)},
            store=store,
            clock=lambda: current[0],
            cgroup_paths=(CGROUP,),
        )
    )
    post(client, sample(0, workload(0, 0, inode=42)))
    current[0] += timedelta(seconds=5)
    post(client, sample(1, workload(1, 1, inode=42)))
    old = store.active()[0]
    # Replacement generation starts from its own high cumulative counters.
    current[0] += timedelta(seconds=5)
    post(client, sample(2, workload(20, 20, inode=99)))
    assert store.active() == [old]
    current[0] += timedelta(seconds=5)
    post(client, sample(3, workload(21, 21, inode=99)))
    active = store.active()
    assert len(active) == 2 and {item.resource for item in active} == {
        workload(0, 0, inode=42).generation_key,
        workload(0, 0, inode=99).generation_key,
    }
    assert next(item for item in active if item.id == old.id).latest_evidence == old.latest_evidence


class LostAcknowledgementStore(FixtureStore):
    lose_once = False

    def commit(self, changes: list[Incident], checkpoint: Checkpoint) -> None:
        super().commit(changes, checkpoint)
        if self.lose_once:
            self.lose_once = False
            raise StoreError("lost acknowledgement")


@pytest.mark.parametrize("lost_ack", [False, True])
def test_mixed_disk_cpu_oom_atomic_rollback_and_reconciliation(lost_ack: bool) -> None:
    current = [NOW]
    store: FixtureStore = LostAcknowledgementStore() if lost_ack else FixtureStore()
    client = TestClient(
        create_app(
            {"node-a": SecretStr(TOKEN)},
            store=store,
            clock=lambda: current[0],
            cgroup_paths=(CGROUP,),
        )
    )
    for sequence in range(2):
        response = post(
            client,
            sample(sequence, workload(0, 0), disk=98, busy=95),
        )
        assert response.status_code == 200  # type: ignore[attr-defined]
        current[0] += timedelta(seconds=5)
    final = sample(2, workload(1, 1), disk=98, busy=95)
    if lost_ack:
        assert isinstance(store, LostAcknowledgementStore)
        store.lose_once = True
        assert post(client, final).status_code == 503  # type: ignore[attr-defined]
        # The retry reconciles all three committed rows and checkpoint before reevaluation.
        assert post(client, final).json()["status"] == "duplicate"  # type: ignore[attr-defined]
    else:
        store.fail_after_incidents = True
        assert post(client, final).status_code == 503  # type: ignore[attr-defined]
        assert not store.active()
        store.fail_after_incidents = False
        assert post(client, final).json()["status"] == "accepted"  # type: ignore[attr-defined]
    assert {item.rule for item in store.active()} == {
        "disk_block_exhaustion",
        "cpu_saturation",
        "workload_oom",
    }


def test_worst_case_v3_sample_stays_inside_ingest_bound() -> None:
    from fleetdoctor.schema import MemoryObservation

    items = [workload(2**64 - 1, 2**64 - 1, inode=index + 1) for index in range(4)]
    for index, item in enumerate(items):
        item.cgroup_path = f"/fleetdoctor/workload-{index}"
    logs = [
        KernelOomLog(
            boot_id=BOOT,
            cursor=f"cursor-{index}",
            realtime_timestamp=NOW,
            message="x" * 500,
            cgroup_path=items[index % 4].cgroup_path,
        )
        for index in range(16)
    ]
    value = make_sample(
        "node-a",
        BOOT,
        SESSION,
        2**64 - 1,
        [filesystem()],
        NOW,
        cpu=CpuObservation(errors=["baseline"]),
        memory=MemoryObservation(
            host=HostMemoryObservation(errors=["baseline"]),
            workloads=items,
            kernel_logs=logs,
            kernel_log_coverage="available",
        ),
    )
    assert len(value.model_dump_json().encode()) < 65536


@pytest.mark.parametrize(
    ("rule", "configuration", "expected"),
    [
        ("disk_block_exhaustion", DiskConfig(), DiskConfig),
        ("cpu_saturation", CpuConfig(), CpuConfig),
        ("workload_oom", OomConfig(), OomConfig),
    ],
)
def test_persisted_incident_json_decodes_configuration_by_rule(
    rule: str,
    configuration: DiskConfig | CpuConfig | OomConfig,
    expected: type[DiskConfig] | type[CpuConfig] | type[OomConfig],
) -> None:
    resource = "/" if rule == "disk_block_exhaustion" else "cpu"
    availability = "block_available" if rule == "disk_block_exhaustion" else "cpu_available"
    if rule == "workload_oom":
        resource = CGROUP + "|" + str(BOOT) + "|1|2"
        availability = "memory_available"
    record = Incident(
        id=UUID("33333333-3333-4333-8333-333333333333"),
        node_id="node-a",
        resource=resource,
        rule=rule,  # type: ignore[arg-type]
        severity=configuration.severity,
        diagnosis="persisted fixture",
        configuration=configuration,
        opening_evidence={availability: True},
        latest_evidence={availability: True},
        opened_at=NOW,
        observed_at=NOW,
        evaluated_at=NOW,
        updated_at=NOW,
        investigation_steps=["fixture"],
    )
    reloaded = Incident.model_validate_json(record.model_dump_json())
    assert type(reloaded.configuration) is expected
