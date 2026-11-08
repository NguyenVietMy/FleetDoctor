from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from test_io import BOOT, SESSION, device

from fleetdoctor.agent import make_sample
from fleetdoctor.checkpoint import canonical_sample_bytes, sample_fingerprint
from fleetdoctor.collector import create_app
from fleetdoctor.incidents import DiskConfig, IoConfig
from fleetdoctor.rules import MAX_ACTIVE_IO_RESOURCES, IoEvaluator
from fleetdoctor.schema import (
    UNITS,
    UNITS_V2,
    UNITS_V3,
    UNITS_V4,
    UNITS_V5,
    UNITS_V6,
    CpuObservation,
    DnsObservation,
    FdObservation,
    Filesystem,
    HostMemoryObservation,
    IoDeviceObservation,
    IoObservation,
    MemoryObservation,
    NetworkObservation,
    Sample,
)
from fleetdoctor.store import FixtureStore

START = datetime(2026, 10, 29, 12, tzinfo=UTC)
TOKEN = "a" * 40


def binding(index: int) -> dict[str, Any]:
    return {
        "major_minor": f"253:{index}",
        "sysfs_path": f"/sys/devices/virtual/block/dm-{index}",
        "diskseq": str(1000 + index),
        "dm_uuid": f"fleetdoctor-ticket11-lifecycle-{index}",
        "filesystem_id": 10_000 + index,
    }


def fingerprint(value: dict[str, Any]) -> str:
    material = {
        key: value[key]
        for key in ("major_minor", "sysfs_path", "diskseq", "dm_uuid", "filesystem_id")
    }
    return (
        "io:"
        + hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:32]
    )


def remap(
    value: IoDeviceObservation, index: int, scopes: list[str] | None = None
) -> IoDeviceObservation:
    raw = value.model_dump(mode="python")
    raw.update(binding(index))
    raw["device_name"] = f"dm-{index}"
    raw["resource"] = fingerprint(raw)
    if scopes is not None:
        raw["scopes"] = sorted(scopes)
        raw["mount_ids"] = {scope: 100 + offset for offset, scope in enumerate(sorted(scopes))}
    return IoDeviceObservation.model_validate(raw)


def baseline(index: int, scopes: list[str] | None = None) -> IoDeviceObservation:
    value = remap(device(scopes=scopes or [f"/io-{index}"]), index, scopes)
    raw = value.model_dump(mode="python")
    raw.update(
        rate_status="baseline",
        counters_before=None,
        elapsed_seconds=None,
        completion_count=None,
        completion_latency_ms=None,
        average_outstanding=None,
        read_bytes_per_second=None,
        write_bytes_per_second=None,
        completions_per_second=None,
        confirmed_idle=False,
    )
    return IoDeviceObservation.model_validate(raw)


def interval(
    previous: IoDeviceObservation,
    *,
    latency: float | None,
    outstanding: float,
    idle: bool = False,
) -> IoDeviceObservation:
    assert previous.counters is not None
    before = previous.counters.model_copy(deep=True)
    after = before.model_copy(deep=True)
    if latency is not None:
        assert float(latency).is_integer()
        after.reads_completed += 1
        after.writes_completed += 1
        after.sectors_read += 2
        after.sectors_written += 2
        after.read_ms += int(latency)
        after.write_ms += int(latency)
        after.io_ms += 1
        after.weighted_io_ms += int(outstanding * 1000)
        completions = 2
        read_rate = write_rate = 1024.0
    else:
        completions = 0
        read_rate = write_rate = 0.0
        if not idle:
            # Zero completions alone is not confirmed idle when optional groups
            # are absent, even with zero latency and backlog.
            after.discards_completed = None
            after.discard_sectors = None
            after.discard_ms = None
            after.flushes_completed = None
            after.flush_ms = None
    raw = previous.model_dump(mode="python")
    raw.update(
        rate_status="available",
        counters_before=before,
        counters=after,
        elapsed_seconds=1.0,
        completion_count=completions,
        completion_latency_ms=latency,
        average_outstanding=outstanding,
        read_bytes_per_second=read_rate,
        write_bytes_per_second=write_rate,
        completions_per_second=float(completions),
        confirmed_idle=idle,
        errors=[],
    )
    return IoDeviceObservation.model_validate(raw)


def non_rate(previous: IoDeviceObservation, status: str) -> IoDeviceObservation:
    assert previous.counters is not None
    raw = previous.model_dump(mode="python")
    raw.update(
        rate_status=status,
        counters_before=None,
        elapsed_seconds=None,
        completion_count=None,
        completion_latency_ms=None,
        average_outstanding=None,
        read_bytes_per_second=None,
        write_bytes_per_second=None,
        completions_per_second=None,
        confirmed_idle=False,
        errors=[status],
    )
    return IoDeviceObservation.model_validate(raw)


def filesystem(usage: float = 10) -> Filesystem:
    total = 1_000_000
    used = int(total * usage / 100)
    return Filesystem(
        mountpoint="/",
        total_bytes=total,
        free_bytes=total - used,
        available_bytes=total - used,
        used_bytes=used,
        block_usage_percent=usage,
        inodes_total=1000,
        inodes_free=900,
        inode_usage_percent=10,
    )


def io_sample(
    sequence: int,
    values: list[IoDeviceObservation],
    *,
    observed: datetime,
    node: str = "node-a",
    boot: UUID = BOOT,
    session: UUID = SESSION,
    status: Literal["available", "partial", "unavailable", "disabled"] = "available",
    inventory_complete: bool = True,
    configured_scopes: list[str] | None = None,
    mapping_errors: dict[str, str] | None = None,
    disk_usage: float = 10,
) -> Sample:
    scopes = configured_scopes
    if scopes is None:
        scopes = sorted({scope for value in values for scope in value.scopes})
    observation = IoObservation(
        status=status,
        inventory_complete=inventory_complete,
        configured_scopes=scopes,
        devices=values,
        mapping_errors=mapping_errors or {},
    )
    return make_sample(
        node,
        boot,
        session,
        sequence,
        [filesystem(disk_usage)],
        observed,
        cpu=CpuObservation(errors=["fixture"]),
        memory=MemoryObservation(host=HostMemoryObservation(errors=["fixture"])),
        fd=FdObservation(errors=["fixture"]),
        network=NetworkObservation.unavailable(None, "fixture"),
        dns=DnsObservation.unavailable(None, None, "fixture"),
        io=observation,
    )


def evaluate(
    evaluator: IoEvaluator,
    current: Sample,
    previous: Sample | None,
    config: IoConfig,
) -> list[Any]:
    return evaluator.evaluate(current, previous, current.observed_at, config)


def test_scope_split_merge_missing_last_positive_and_replacement_semantics() -> None:
    config = IoConfig(consecutive_samples=1)
    evaluator = IoEvaluator([])
    first_device = baseline(7, ["/a", "/b"])
    first = io_sample(0, [first_device], observed=START)
    hot = interval(first_device, latency=20, outstanding=1)
    opening = io_sample(1, [hot], observed=START + timedelta(seconds=1))
    opened = evaluate(evaluator, opening, first, config)[0]
    opening_evidence = opened.opening_evidence

    split_x_raw = interval(hot, latency=20, outstanding=1).model_dump(mode="python")
    split_x_raw.update(scopes=["/a"], mount_ids={"/a": 20})
    split_x = IoDeviceObservation.model_validate(split_x_raw)
    split_y_base = baseline(8, ["/b"])
    split_baseline = io_sample(2, [split_x, split_y_base], observed=START + timedelta(seconds=2))
    changes = evaluate(evaluator, split_baseline, opening, config)
    changed_x = next(item for item in changes if item.id == opened.id)
    assert changed_x.opening_evidence == opening_evidence
    assert changed_x.latest_evidence["scopes"] == ["/a"]

    split_x2 = interval(split_x, latency=20, outstanding=1)
    split_y_hot = interval(split_y_base, latency=20, outstanding=1)
    split_open = io_sample(3, [split_x2, split_y_hot], observed=START + timedelta(seconds=3))
    changes = evaluate(evaluator, split_open, split_baseline, config)
    changed_x = next(item for item in changes if item.id == opened.id)
    opened_y = next(item for item in changes if item.resource == split_y_hot.resource)
    assert changed_x.id == opened.id and changed_x.opening_evidence == opening_evidence
    assert opened_y.id != opened.id and opened_y.status == "active"

    merge_x_raw = interval(split_x2, latency=20, outstanding=1).model_dump(mode="python")
    merge_x_raw.update(scopes=["/a", "/b"], mount_ids={"/a": 30, "/b": 31})
    merged_x = IoDeviceObservation.model_validate(merge_x_raw)
    inverse_merge = io_sample(4, [merged_x], observed=START + timedelta(seconds=4))
    changes = evaluate(evaluator, inverse_merge, split_open, config)
    retained_x = next(item for item in changes if item.id == opened.id)
    retired_y = next(item for item in changes if item.id == opened_y.id)
    assert retained_x.status == "active" and retained_x.opening_evidence == opening_evidence
    assert retired_y.status == "superseded" and retired_y.resolved_at is None
    assert ("node-a", merged_x.resource) in evaluator.active
    assert ("node-a", split_y_hot.resource) not in evaluator.active

    missing = io_sample(
        5,
        [],
        observed=START + timedelta(seconds=5),
        status="partial",
        inventory_complete=False,
        configured_scopes=["/a", "/b"],
        mapping_errors={"/a": "mapping_unavailable", "/b": "mapping_unavailable"},
    )
    missing_change = evaluate(evaluator, missing, inverse_merge, config)[0]
    assert missing_change.status == "active"
    assert missing_change.latest_evidence["io_available"] is False
    assert missing_change.latest_evidence["last_positive_scopes"] == ["/a", "/b"]

    replacement = baseline(9, ["/a", "/b"])
    replacement_sample = io_sample(6, [replacement], observed=START + timedelta(seconds=6))
    changes = evaluate(evaluator, replacement_sample, missing, config)
    retired = next(item for item in changes if item.id == opened.id)
    assert retired.status == "superseded" and retired.resolved_at is None
    assert retired.supersession_reason == "positive_resource_replacement"
    assert retired.replacement_resource_evidence == {
        "inventory_complete": True,
        "old_scopes": ["/a", "/b"],
        "replacements": [{"resource": replacement.resource, "scopes": ["/a", "/b"]}],
    }


def test_threshold_equality_strict_recovery_null_latency_and_frozen_configuration() -> None:
    opening_config = IoConfig(consecutive_samples=1, severity="warning")
    evaluator = IoEvaluator([])
    base = baseline(1)
    first = io_sample(0, [base], observed=START)
    equality = interval(base, latency=20, outstanding=1)
    second = io_sample(1, [equality], observed=START + timedelta(seconds=1))
    opened = evaluate(evaluator, second, first, opening_config)[0]
    assert opened.status == "active" and opened.configuration == opening_config

    recovery_equality = interval(equality, latency=10, outstanding=0.5)
    third = io_sample(2, [recovery_equality], observed=START + timedelta(seconds=2))
    still_active = evaluate(
        evaluator,
        third,
        second,
        IoConfig(consecutive_samples=1, recovery_latency_ms=19, recovery_outstanding=0.9),
    )[0]
    assert still_active.status == "active" and still_active.configuration == opening_config

    null_not_idle = interval(recovery_equality, latency=None, outstanding=0, idle=False)
    fourth = io_sample(3, [null_not_idle], observed=START + timedelta(seconds=3))
    still_active = evaluate(evaluator, fourth, third, opening_config)[0]
    assert still_active.status == "active"
    assert still_active.latest_evidence["coverage"]["confirmed_idle"] is False

    strict = interval(null_not_idle, latency=9, outstanding=0.4)
    fifth = io_sample(4, [strict], observed=START + timedelta(seconds=4))
    resolved = evaluate(evaluator, fifth, fourth, opening_config)[0]
    assert resolved.status == "resolved" and resolved.id == opened.id
    assert resolved.opening_evidence == opened.opening_evidence


def test_gap_and_unopened_config_change_reset_windows() -> None:
    first_config = IoConfig(consecutive_samples=2, max_gap_seconds=5, severity="warning")
    second_config = IoConfig(consecutive_samples=2, max_gap_seconds=5, severity="critical")
    evaluator = IoEvaluator([])
    base = baseline(2)
    first = io_sample(0, [base], observed=START)
    hot1 = interval(base, latency=20, outstanding=1)
    one = io_sample(1, [hot1], observed=START + timedelta(seconds=1))
    assert evaluate(evaluator, one, first, first_config) == []

    hot_after_gap = interval(hot1, latency=20, outstanding=1)
    gap = io_sample(2, [hot_after_gap], observed=START + timedelta(seconds=7))
    assert evaluate(evaluator, gap, one, first_config) == []
    assert evaluator.windows == {}

    hot2 = interval(hot_after_gap, latency=20, outstanding=1)
    two = io_sample(3, [hot2], observed=START + timedelta(seconds=8))
    assert evaluate(evaluator, two, gap, first_config) == []
    hot3 = interval(hot2, latency=20, outstanding=1)
    three = io_sample(4, [hot3], observed=START + timedelta(seconds=9))
    assert evaluate(evaluator, three, two, second_config) == []
    hot4 = interval(hot3, latency=20, outstanding=1)
    four = io_sample(5, [hot4], observed=START + timedelta(seconds=10))
    opened = evaluate(evaluator, four, three, second_config)[0]
    assert opened.configuration == second_config and opened.opened_at == four.observed_at


@pytest.mark.parametrize(
    "reset",
    ["boot", "session", "sequence", "counter", "baseline"],
)
def test_generation_counter_and_baseline_resets_cannot_open(reset: str) -> None:
    config = IoConfig(consecutive_samples=1)
    evaluator = IoEvaluator([])
    base = baseline(3)
    previous = io_sample(5, [base], observed=START)
    candidate = interval(base, latency=20, outstanding=1)
    boot, session, sequence = BOOT, SESSION, 6
    if reset == "boot":
        boot = uuid4()
    elif reset == "session":
        session = uuid4()
    elif reset == "sequence":
        sequence = 5
    elif reset == "counter":
        candidate = non_rate(candidate, "reset")
    elif reset == "baseline":
        candidate = non_rate(candidate, "baseline")
    current = io_sample(
        sequence,
        [candidate],
        observed=START + timedelta(seconds=1),
        boot=boot,
        session=session,
    )
    assert evaluate(evaluator, current, previous, config) == []
    assert evaluator.active == {} and evaluator.windows == {}


def test_nodes_devices_and_recurrence_are_isolated() -> None:
    config = IoConfig(consecutive_samples=1)
    evaluator = IoEvaluator([])
    bases = [baseline(10), baseline(11)]
    first = io_sample(0, bases, observed=START)
    hot = [interval(value, latency=20, outstanding=1) for value in bases]
    second = io_sample(1, hot, observed=START + timedelta(seconds=1))
    opened_a = evaluate(evaluator, second, first, config)
    assert len(opened_a) == 2

    node_b_base = baseline(12)
    node_b_first = io_sample(0, [node_b_base], observed=START, node="node-b")
    node_b_hot = interval(node_b_base, latency=20, outstanding=1)
    node_b_second = io_sample(1, [node_b_hot], observed=START + timedelta(seconds=1), node="node-b")
    opened_b = evaluate(evaluator, node_b_second, node_b_first, config)[0]
    assert len(evaluator.active) == 3

    recovery = interval(hot[0], latency=9, outstanding=0.4)
    recovery_sample = io_sample(2, [recovery], observed=START + timedelta(seconds=2))
    resolved = evaluate(evaluator, recovery_sample, second, config)[0]
    assert resolved.status == "resolved"
    assert ("node-a", hot[1].resource) in evaluator.active
    assert ("node-b", node_b_hot.resource) in evaluator.active
    assert evaluator.active[("node-b", node_b_hot.resource)].id == opened_b.id

    recurrence_device = interval(recovery, latency=20, outstanding=1)
    recurrence_sample = io_sample(3, [recurrence_device], observed=START + timedelta(seconds=3))
    recurrence = evaluate(evaluator, recurrence_sample, recovery_sample, config)[0]
    assert recurrence.status == "active" and recurrence.id != resolved.id


def test_schema_1_through_6_remain_fingerprint_compatible_without_io() -> None:
    base = io_sample(0, [baseline(20)], observed=START)
    units = {1: UNITS, 2: UNITS_V2, 3: UNITS_V3, 4: UNITS_V4, 5: UNITS_V5, 6: UNITS_V6}
    fields = {
        1: ("cpu", "memory", "fd", "network", "dns", "io"),
        2: ("memory", "fd", "network", "dns", "io"),
        3: ("fd", "network", "dns", "io"),
        4: ("network", "dns", "io"),
        5: ("dns", "io"),
        6: ("io",),
    }
    for version in range(1, 7):
        raw = base.model_dump(mode="json")
        raw["schema_version"] = version
        raw["units"] = units[version]
        for name in fields[version]:
            raw.pop(name, None)
        assert "io" not in raw
        independently_canonicalized = json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        parsed = Sample.model_validate(raw)
        assert parsed.schema_version == version and parsed.io is None
        legacy_payload = parsed.model_dump(mode="json")
        assert legacy_payload == raw
        assert b'"io"' not in independently_canonicalized
        assert canonical_sample_bytes(parsed) == independently_canonicalized
        assert sample_fingerprint(parsed) == hashlib.sha256(independently_canonicalized).hexdigest()


def test_pending_four_is_sorted_bounded_and_rotates_before_opening() -> None:
    config = IoConfig(consecutive_samples=3)
    evaluator = IoEvaluator([])
    first_bases = list(reversed([baseline(index) for index in range(90, 94)]))
    first = io_sample(0, first_bases, observed=START)
    first_hot = list(
        reversed([interval(value, latency=20, outstanding=1) for value in first_bases])
    )
    second = io_sample(1, first_hot, observed=START + timedelta(seconds=1))
    assert evaluate(evaluator, second, first, config) == []
    first_resources = sorted(value.resource for value in first_bases)
    assert list(evaluator.windows) == [("node-a", resource) for resource in first_resources]
    assert len(evaluator.windows) == 4

    rotated_bases = list(reversed([baseline(index) for index in range(94, 98)]))
    third = io_sample(2, rotated_bases, observed=START + timedelta(seconds=2))
    assert evaluate(evaluator, third, second, config) == []
    assert evaluator.windows == {}
    rotated_hot1 = list(
        reversed([interval(value, latency=20, outstanding=1) for value in rotated_bases])
    )
    fourth = io_sample(3, rotated_hot1, observed=START + timedelta(seconds=3))
    assert evaluate(evaluator, fourth, third, config) == []
    rotated_resources = sorted(value.resource for value in rotated_bases)
    assert list(evaluator.windows) == [("node-a", resource) for resource in rotated_resources]
    assert len(evaluator.windows) == 4

    rotated_hot2 = [interval(value, latency=20, outstanding=1) for value in rotated_hot1]
    fifth = io_sample(4, rotated_hot2, observed=START + timedelta(seconds=4))
    assert evaluate(evaluator, fifth, fourth, config) == []
    assert len(evaluator.windows) == 4
    rotated_hot3 = [interval(value, latency=20, outstanding=1) for value in rotated_hot2]
    sixth = io_sample(5, rotated_hot3, observed=START + timedelta(seconds=5))
    opened = evaluate(evaluator, sixth, fifth, config)
    assert {item.resource for item in opened} == set(rotated_resources)
    assert len(evaluator.active) == 4 and evaluator.windows == {}


def feed_group(
    evaluator: IoEvaluator,
    previous: Sample | None,
    *,
    start_index: int,
    sequence: int,
    observed: datetime,
    config: IoConfig,
) -> tuple[Sample, list[Any]]:
    bases = [baseline(index) for index in range(start_index, start_index + 4)]
    baseline_sample = io_sample(sequence, bases, observed=observed)
    evaluate(evaluator, baseline_sample, previous, config)
    hot = [interval(value, latency=20, outstanding=1) for value in bases]
    hot_sample = io_sample(sequence + 1, hot, observed=observed + timedelta(seconds=1))
    changes = evaluate(evaluator, hot_sample, baseline_sample, config)
    return hot_sample, changes


def post(client: TestClient, value: Sample) -> Any:
    return client.post(
        "/ingest",
        content=value.model_dump_json(),
        headers={"Authorization": "Bearer " + TOKEN},
    )


def test_cap16_pending4_sorted_overflow_reload_recovery_and_remap() -> None:
    config = IoConfig(consecutive_samples=1)
    evaluator = IoEvaluator([])
    previous: Sample | None = None
    sequence = 0
    for group in range(4):
        previous, changes = feed_group(
            evaluator,
            previous,
            start_index=30 + group * 4,
            sequence=sequence,
            observed=START + timedelta(seconds=sequence),
            config=config,
        )
        sequence += 2
        group_resources = {
            baseline(index).resource for index in range(30 + group * 4, 34 + group * 4)
        }
        assert {
            item.resource
            for item in changes
            if item.status == "active" and item.resource in group_resources
        } == group_resources
    assert len(evaluator.active) == MAX_ACTIVE_IO_RESOURCES

    previous, blocked = feed_group(
        evaluator,
        previous,
        start_index=50,
        sequence=sequence,
        observed=START + timedelta(seconds=sequence),
        config=config,
    )
    sequence += 2
    assert not [
        item for item in blocked if item.resource in {baseline(i).resource for i in range(50, 54)}
    ]
    assert len(evaluator.active) == 16
    assert evaluator.admission_overflow_nodes == {"node-a"}

    store = FixtureStore()
    store.records = {item.id: item.model_copy(deep=True) for item in evaluator.active.values()}
    now = [START + timedelta(seconds=100)]

    def new_client() -> TestClient:
        return TestClient(
            create_app(
                {"node-a": SecretStr(TOKEN), "node-b": SecretStr("b" * 40)},
                store=store,
                clock=lambda: now[0],
                io_config=config,
            )
        )

    client = new_client()
    view = client.get("/nodes/node-a/metrics").json()
    assert view["io_coverage"]["admission_capacity"] == "unavailable"
    assert view["io_coverage"]["candidate_overflow"] is False
    node_b = client.get("/nodes/node-b/metrics").json()["io_coverage"]
    assert node_b["collection"] == "unavailable"
    assert node_b["configured_scopes"] == node_b["available_scopes"] == 0
    assert node_b["observed"] == node_b["available"] == 0
    assert node_b["admission_capacity"] == "available"
    assert node_b["candidate_overflow"] is False

    bases = [baseline(index) for index in range(60, 64)]
    baseline_sample = io_sample(0, bases, observed=now[0])
    assert post(client, baseline_sample).json()["status"] == "accepted"
    now[0] += timedelta(seconds=1)
    hot = [interval(value, latency=20, outstanding=1) for value in bases]
    overflow_sample = io_sample(1, hot, observed=now[0])
    assert post(client, overflow_sample).json()["status"] == "accepted"
    view = client.get("/nodes/node-a/metrics").json()
    assert view["io_coverage"]["candidate_overflow"] is True
    assert len(store.active()) == 16

    client = new_client()
    assert client.get("/nodes/node-a/metrics").json()["io_coverage"]["candidate_overflow"] is False
    chosen = store.active()[0]
    positive = IoDeviceObservation.model_validate(chosen.opening_evidence["device"])
    now[0] += timedelta(seconds=1)
    first_recovery = interval(positive, latency=9, outstanding=0.4)
    first_recovery_sample = io_sample(2, [first_recovery], observed=now[0])
    assert post(client, first_recovery_sample).json()["status"] == "accepted"
    now[0] += timedelta(seconds=1)
    second_recovery = interval(first_recovery, latency=9, outstanding=0.4)
    second_recovery_sample = io_sample(3, [second_recovery], observed=now[0])
    assert post(client, second_recovery_sample).json()["status"] == "accepted"
    assert len(store.active()) == 15
    assert (
        client.get("/nodes/node-a/metrics").json()["io_coverage"]["admission_capacity"]
        == "available"
    )

    now[0] += timedelta(seconds=1)
    remap_base = baseline(70)
    remap_first = io_sample(4, [remap_base], observed=now[0])
    assert post(client, remap_first).json()["status"] == "accepted"
    now[0] += timedelta(seconds=1)
    remap_hot = interval(remap_base, latency=20, outstanding=1)
    remap_second = io_sample(5, [remap_hot], observed=now[0])
    assert post(client, remap_second).json()["status"] == "accepted"
    assert len(store.active()) == 16

    now[0] += timedelta(seconds=1)
    beyond_base = baseline(71)
    assert post(client, io_sample(6, [beyond_base], observed=now[0])).json()["status"] == "accepted"
    now[0] += timedelta(seconds=1)
    beyond_hot = interval(beyond_base, latency=20, outstanding=1)
    assert post(client, io_sample(7, [beyond_hot], observed=now[0])).json()["status"] == "accepted"
    final = client.get("/nodes/node-a/metrics").json()["io_coverage"]
    assert final["admission_capacity"] == "unavailable" and final["candidate_overflow"]

    current = next(
        item
        for item in store.active()
        if "/io-70" in cast(list[Any], item.opening_evidence["scopes"])
    )
    superseded_ids = []
    sequence = 8
    for generation in range(100, 117):
        assert len(store.active()) == MAX_ACTIVE_IO_RESOURCES
        old_id = current.id
        now[0] += timedelta(seconds=1)
        replacement_base = baseline(generation, ["/io-70"])
        response = post(client, io_sample(sequence, [replacement_base], observed=now[0]))
        assert response.json()["status"] == "accepted"
        sequence += 1
        terminal = store.get(old_id)
        assert terminal is not None and terminal.status == "superseded"
        assert terminal.resolved_at is None
        superseded_ids.append(old_id)
        assert len(store.active()) == MAX_ACTIVE_IO_RESOURCES - 1

        now[0] += timedelta(seconds=1)
        replacement_hot = interval(replacement_base, latency=20, outstanding=1)
        response = post(client, io_sample(sequence, [replacement_hot], observed=now[0]))
        assert response.json()["status"] == "accepted"
        sequence += 1
        current = next(item for item in store.active() if item.resource == replacement_hot.resource)
        assert len(store.active()) == MAX_ACTIVE_IO_RESOURCES
    superseded, total = store.query("node-a", "io_bottleneck", "superseded", None, None, 100, 0)
    assert total >= 17
    assert set(superseded_ids) <= {item.id for item in superseded}
    assert len(set(superseded_ids)) == 17
    assert not set(superseded_ids) & {item.id for item in store.active()}


@pytest.mark.parametrize("failure_boundary", ["fail_after_incidents", "fail_after_checkpoint"])
def test_mixed_io_and_legacy_atomic_commit_checkpoint_reload_and_ordering(
    failure_boundary: str,
) -> None:
    now = [START]
    store = FixtureStore()

    def new_client() -> TestClient:
        return TestClient(
            create_app(
                {"node-a": SecretStr(TOKEN)},
                store=store,
                clock=lambda: now[0],
                config=DiskConfig(consecutive_samples=1),
                io_config=IoConfig(consecutive_samples=1),
            )
        )

    client = new_client()
    base = baseline(80, ["/io"])
    baseline_sample = io_sample(0, [base], observed=now[0])
    assert post(client, baseline_sample).json()["status"] == "accepted"
    checkpoint_before = store.snapshot({"node-a"}).checkpoints["node-a"]

    now[0] += timedelta(seconds=1)
    hot = interval(base, latency=20, outstanding=1)
    trigger = io_sample(1, [hot], observed=now[0], disk_usage=98)
    setattr(store, failure_boundary, True)
    assert post(client, trigger).status_code == 503
    failed_snapshot = store.snapshot({"node-a"})
    assert failed_snapshot.active == []
    assert failed_snapshot.checkpoints["node-a"] == checkpoint_before
    assert cast(Any, client.app).state.fleet.latest["node-a"] == baseline_sample

    setattr(store, failure_boundary, False)
    accepted = post(client, trigger)
    assert accepted.status_code == 200 and accepted.json()["status"] == "accepted"
    active = store.active()
    assert {item.rule for item in active} == {"disk_block_exhaustion", "io_bottleneck"}
    assert len(active) == 2
    assert store.snapshot({"node-a"}).checkpoints["node-a"].revision == 2
    assert post(client, trigger).json()["status"] == "duplicate"
    listed = client.get("/diagnoses", params={"status": "active"}).json()
    assert listed["total"] == 2
    assert [item["id"] for item in listed["diagnoses"]] == [
        str(item.id)
        for item in sorted(active, key=lambda item: (item.opened_at, str(item.id)), reverse=True)
    ]

    client = new_client()
    for incident in active:
        detail = client.get(f"/diagnoses/{incident.id}").json()
        assert detail["evidence_stale"] and not detail["evidence_fresh"]
        assert incident.id in cast(Any, client.app).state.fleet.evaluator.reloaded
        assert detail["opening_evidence"] == incident.opening_evidence

    stale = trigger.model_copy(
        update={"sequence": 2, "observed_at": now[0] - timedelta(seconds=10, microseconds=1)}
    )
    assert post(client, stale).json()["status"] == "ineligible"
    replacement_session = uuid4()
    nonincreasing = trigger.model_copy(update={"agent_session_id": replacement_session})
    assert post(client, nonincreasing).json()["status"] == "superseded"
    now[0] += timedelta(seconds=1)
    newer = trigger.model_copy(
        update={
            "agent_session_id": replacement_session,
            "sequence": 0,
            "observed_at": now[0],
        }
    )
    assert post(client, newer).json()["status"] == "accepted"
    assert post(client, newer).json()["status"] == "duplicate"
    old_session = trigger.model_copy(
        update={"sequence": 2, "observed_at": now[0] + timedelta(microseconds=1)}
    )
    assert post(client, old_session).json()["status"] == "superseded"
    assert {item.id for item in store.active()} == {item.id for item in active}
