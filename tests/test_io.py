from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

import fleetdoctor.io as io_module
from fleetdoctor.agent import make_sample
from fleetdoctor.collector import create_app, io_scope_coverage
from fleetdoctor.incidents import IoConfig
from fleetdoctor.io import (
    IoCollector,
    _read_bounded,
    configured_io_mounts,
    configured_io_pids,
    parse_diskstats,
    parse_mountinfo,
    parse_pressure,
    parse_process_io,
)
from fleetdoctor.rules import IoEvaluator
from fleetdoctor.schema import (
    CpuObservation,
    DnsObservation,
    FdObservation,
    Filesystem,
    HostMemoryObservation,
    IoCounters,
    IoDeviceObservation,
    IoObservation,
    IoPressureObservation,
    IoProcessObservation,
    MemoryObservation,
    NetworkObservation,
)
from fleetdoctor.store import FixtureStore

BOOT = UUID("11111111-1111-4111-8111-111111111111")
SESSION = UUID("22222222-2222-4222-8222-222222222222")


class ShortReadFile:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = iter(chunks)

    def __enter__(self) -> ShortReadFile:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        chunk = next(self.chunks, b"")
        if len(chunk) > limit:
            raise AssertionError("bounded reader requested too few bytes")
        return chunk


def test_bounded_proc_reader_accumulates_short_reads_and_enforces_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = b"10 1 0:1 / /old rw - ext4 /dev/old rw\n"
    selected = b"11 1 253:7 / /io rw - ext4 /dev/dm-7 rw\n"
    monkeypatch.setattr(
        "builtins.open",
        lambda *_args, **_kwargs: ShortReadFile([prefix, selected, b""]),
    )
    records = parse_mountinfo(_read_bounded("/proc/self/mountinfo", 256))
    assert records[-1].mountpoint == "/io"
    monkeypatch.setattr("builtins.open", lambda *_args, **_kwargs: ShortReadFile([b"abc", b"def"]))
    with pytest.raises(ValueError, match="oversize"):
        _read_bounded("/proc/diskstats", 5)
    monkeypatch.setattr("builtins.open", lambda *_args, **_kwargs: ShortReadFile([b"\xff", b""]))
    with pytest.raises(UnicodeDecodeError):
        _read_bounded("/proc/pressure/io", 5)


def counters(
    *,
    reads: int = 10,
    read_sectors: int = 20,
    read_ms: int = 200,
    writes: int = 5,
    write_sectors: int = 10,
    write_ms: int = 100,
    inflight: int = 0,
    io_ms: int = 150,
    weighted: int = 200,
) -> IoCounters:
    return IoCounters(
        reads_completed=reads,
        sectors_read=read_sectors,
        read_ms=read_ms,
        writes_completed=writes,
        sectors_written=write_sectors,
        write_ms=write_ms,
        inflight=inflight,
        io_ms=io_ms,
        weighted_io_ms=weighted,
        discards_completed=0,
        discard_sectors=0,
        discard_ms=0,
        flushes_completed=0,
        flush_ms=0,
    )


def resource() -> str:
    material = {
        "major_minor": "253:7",
        "sysfs_path": "/sys/devices/virtual/block/dm-7",
        "diskseq": "41",
        "dm_uuid": "fleetdoctor-ticket11-test",
        "filesystem_id": 77,
    }
    return (
        "io:"
        + hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:32]
    )


def device(
    *,
    latency: float | None = 20,
    outstanding: float = 1,
    idle: bool = False,
    scopes: list[str] | None = None,
) -> IoDeviceObservation:
    scopes = scopes or ["/io"]
    before = counters()
    if idle:
        after = before.model_copy(deep=True)
        completion_count = 0
        latency = None
        outstanding = 0
        read_bps = write_bps = completions = 0
    else:
        after = counters(
            reads=20,
            read_sectors=40,
            read_ms=300,
            writes=10,
            write_sectors=20,
            write_ms=200,
            io_ms=250,
            weighted=1200,
        )
        completion_count = 15
        latency = 200 / 15
        outstanding = 1
        read_bps = 20 * 512
        write_bps = 10 * 512
        completions = 15
    return IoDeviceObservation(
        resource=resource(),
        status="available",
        rate_status="available",
        major_minor="253:7",
        device_name="dm-7",
        sysfs_path="/sys/devices/virtual/block/dm-7",
        diskseq="41",
        dm_uuid="fleetdoctor-ticket11-test",
        filesystem_id=77,
        scopes=scopes,
        mount_ids={scope: index + 10 for index, scope in enumerate(scopes)},
        mount_namespace="mnt:[123]",
        counters=after,
        counters_before=before,
        elapsed_seconds=1,
        completion_count=completion_count,
        completion_latency_ms=latency,
        average_outstanding=outstanding,
        read_bytes_per_second=read_bps,
        write_bytes_per_second=write_bps,
        completions_per_second=completions,
        confirmed_idle=idle,
    )


def chained(previous: IoDeviceObservation, *, idle: bool) -> IoDeviceObservation:
    assert previous.counters is not None
    before = previous.counters.model_copy(deep=True)
    after = before.model_copy(deep=True)
    if idle:
        completion_count = 0
        latency = None
        outstanding = read_bps = write_bps = completions = 0
    else:
        after.reads_completed += 10
        after.sectors_read += 20
        after.read_ms += 100
        after.writes_completed += 5
        after.sectors_written += 10
        after.write_ms += 100
        after.io_ms += 100
        after.weighted_io_ms += 1000
        completion_count = 15
        latency = 200 / 15
        outstanding = 1
        read_bps = 20 * 512
        write_bps = 10 * 512
        completions = 15
    payload = previous.model_dump()
    payload.update(
        rate_status="available",
        counters_before=before.model_dump(),
        counters=after.model_dump(),
        elapsed_seconds=1,
        completion_count=completion_count,
        completion_latency_ms=latency,
        average_outstanding=outstanding,
        read_bytes_per_second=read_bps,
        write_bytes_per_second=write_bps,
        completions_per_second=completions,
        confirmed_idle=idle,
        errors=[],
    )
    return IoDeviceObservation.model_validate(payload)


def sample(sequence: int, value: IoDeviceObservation, observed: datetime):  # type: ignore[no-untyped-def]
    io = IoObservation(
        status="available",
        inventory_complete=True,
        configured_scopes=value.scopes,
        devices=[value],
    )
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
        network=NetworkObservation.unavailable(None, "fixture"),
        dns=DnsObservation.unavailable(None, None, "fixture"),
        io=io,
    )


def test_configuration_bounds() -> None:
    assert configured_io_mounts("/a,/b") == ("/a", "/b")
    assert configured_io_mounts("/b,/a") == ("/a", "/b")
    assert configured_io_pids("1,2") == (1, 2)
    for raw in ("relative", "/a,/a", ",/a", "/a/../b"):
        with pytest.raises(ValueError):
            configured_io_mounts(raw)
    with pytest.raises(ValueError):
        configured_io_pids("1,1")


def test_reversed_mount_order_is_normalized_and_deduplicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mountinfo = "10 1 253:7 / /a rw - ext4 /dev/dm-7 rw\n11 1 253:7 / /b rw - ext4 /dev/dm-7 rw"
    diskstats = "253 7 dm-7 10 0 20 200 5 0 10 100 0 150 200 0 0 0 0 0 0"
    pressure = "some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0"

    def bounded(path: str | object, _limit: int = io_module.MAX_READ) -> str:
        value = str(path).replace("\\", "/")
        if value.endswith("/self/mountinfo"):
            return mountinfo
        if value.endswith("/diskstats"):
            return diskstats
        if value.endswith("/pressure/io"):
            return pressure
        raise AssertionError(value)

    monkeypatch.setattr(io_module, "_read_bounded", bounded)
    monkeypatch.setattr(os, "readlink", lambda _path: "mnt:[123]")
    collector = IoCollector(monotonic=lambda: 1.0)
    identity = (
        "253:7",
        "/sys/devices/virtual/block/dm-7",
        "41",
        "fleetdoctor-ticket11-test",
        77,
    )
    monkeypatch.setattr(collector, "_stable_mapping", lambda _record, _path: identity)
    monkeypatch.setattr(collector, "_slaves", lambda _path: set())
    observation = collector.collect(("/b", "/a"))
    assert observation.status == "available" and observation.inventory_complete
    assert observation.configured_scopes == ["/a", "/b"]
    assert len(observation.devices) == 1
    assert observation.devices[0].scopes == ["/a", "/b"]
    assert observation.devices[0].mount_ids == {"/a": 10, "/b": 11}


def test_diskstats_formats_and_malformed_tails() -> None:
    legacy = "253 7 dm-7 1 0 2 3 4 0 5 6 0 7 8"
    discard = legacy + " 9 0 10 11"
    flush = discard + " 12 13"
    assert parse_diskstats(legacy)["253:7"][1].discards_completed is None
    assert parse_diskstats(discard)["253:7"][1].discards_completed == 9
    assert parse_diskstats(flush + " 99 100")["253:7"][1].flush_ms == 13
    for malformed in (legacy + " 9", discard + " 12", legacy.replace(" 8", " x", 1)):
        with pytest.raises(ValueError):
            parse_diskstats(malformed)
    with pytest.raises(ValueError):
        parse_diskstats(legacy + "\n" + legacy)


def test_mount_pressure_and_process_parsers_reject_ambiguity() -> None:
    record = parse_mountinfo("10 1 253:7 / /io rw - ext4 /dev/dm-7 rw")[0]
    assert (record.mount_id, record.major_minor, record.mountpoint) == (10, "253:7", "/io")
    pressure = "some avg10=1.00 avg60=2.00 avg300=3.00 total=4\nfull avg10=0.10 avg60=0.20 avg300=0.30 total=5"
    assert parse_pressure(pressure, "host").some == {
        "avg10": 1.0,
        "avg60": 2.0,
        "avg300": 3.0,
        "total": 4,
    }
    with pytest.raises(ValueError):
        parse_pressure(pressure + "\nsome avg10=1 avg60=2 avg300=3 total=4", "host")
    parsed = parse_process_io(
        "rchar: 10\nwchar: 11\nread_bytes: 12\nwrite_bytes: 13\ncancelled_write_bytes: 14"
    )
    assert parsed["cancelled_write_bytes"] == 14
    assert parsed["wchar"] == 11 and parsed["write_bytes"] == 13
    with pytest.raises(ValueError, match="negative"):
        parse_process_io(
            "rchar: 10\nwchar: 11\nread_bytes: 12\nwrite_bytes: 13\ncancelled_write_bytes: -1"
        )
    assert (
        parse_process_io(
            f"rchar: 0\nwchar: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: {2**64 - 1}"
        )["cancelled_write_bytes"]
        == 2**64 - 1
    )
    process = IoProcessObservation(
        pid=7,
        starttime=8,
        status="available",
        rate_status="baseline",
        physical_read_bytes=0,
        physical_write_bytes=3,
        logical_read_characters=9,
        logical_write_characters=10,
        cancelled_write_bytes=5,
        net_write_balance_bytes=-2,
    )
    assert process.cancelled_write_bytes == 5
    assert process.net_write_balance_bytes == -2
    with pytest.raises(ValidationError, match="net write balance"):
        process.model_copy(update={"net_write_balance_bytes": 3}).model_validate(
            process.model_copy(update={"net_write_balance_bytes": 3}).model_dump()
        )


def test_pressure_schema_bounds_raw_values_without_runtime_overflow() -> None:
    boundary = {
        "avg10": 0,
        "avg60": 50.5,
        "avg300": 100,
        "total": 2**64 - 1,
    }
    value = IoPressureObservation(scope="host", status="available", some=boundary, full=boundary)
    assert value.some is not None and value.some["total"] == 2**64 - 1

    invalid_values = (
        {**boundary, "total": 2**1024},
        {**boundary, "total": 2**64},
        {**boundary, "total": -1},
        {**boundary, "total": True},
        {**boundary, "avg10": True},
        {**boundary, "avg10": float("inf")},
        {**boundary, "avg10": float("nan")},
        {**boundary, "avg10": -0.1},
        {**boundary, "avg10": 100.1},
    )
    for invalid in invalid_values:
        with pytest.raises(ValidationError):
            IoPressureObservation(scope="host", status="available", some=invalid, full=boundary)


def test_pressure_scope_is_host_or_canonical_registered_cgroup_label() -> None:
    row = {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0, "total": 0}
    assert (
        IoPressureObservation(
            scope="/system.slice/fleetdoctor@node.service",
            status="available",
            some=row,
            full=row,
        ).scope
        == "/system.slice/fleetdoctor@node.service"
    )
    for invalid_scope in ("HOST", "relative", "/", "/a//b", "/a/../b", "/a\\b"):
        with pytest.raises(ValidationError, match="canonical cgroup"):
            IoPressureObservation(
                scope=invalid_scope,
                status="available",
                some=row,
                full=row,
            )
    boundary_scope = "/" + "a" * 255
    boundary = IoPressureObservation(scope=boundary_scope, status="unavailable", errors=["fixture"])
    complete = IoObservation(
        status="disabled",
        inventory_complete=True,
        registered_pressure_scopes=["host", boundary_scope],
        pressure=[
            IoPressureObservation(scope="host", status="unavailable", errors=["fixture"]),
            boundary,
        ],
        pressure_coverage="complete",
    )
    assert complete.registered_pressure_scopes[-1] == boundary_scope


def test_pressure_coverage_includes_host_and_all_eight_registered_cgroups() -> None:
    scopes = ["host", *[f"/workload/io-{index}" for index in range(8)]]
    pressure = [
        IoPressureObservation(scope=scope, status="unavailable", errors=["fixture"])
        for scope in scopes
    ]
    observation = IoObservation(
        status="partial",
        inventory_complete=False,
        configured_scopes=["/io"],
        mapping_errors={"/io": "fixture"},
        registered_pressure_scopes=scopes,
        pressure=pressure,
        pressure_coverage="complete",
    )
    assert [item.scope for item in observation.pressure] == scopes

    with pytest.raises(ValidationError, match="registered scope"):
        IoObservation.model_validate(
            observation.model_dump() | {"pressure": [item.model_dump() for item in pressure[:-1]]}
        )
    with pytest.raises(ValidationError, match="coverage"):
        IoObservation.model_validate(
            observation.model_dump()
            | {
                "pressure": [
                    *[item.model_dump() for item in pressure[:-1]],
                    IoPressureObservation(
                        scope="/unregistered", status="unavailable", errors=["fixture"]
                    ).model_dump(),
                ]
            }
        )


def test_wire_recomputes_arithmetic_idle_and_resource() -> None:
    valid = device(idle=True)
    payload = valid.model_dump()
    payload["average_outstanding"] = 1
    with pytest.raises(ValidationError, match="arithmetic"):
        IoDeviceObservation.model_validate(payload)
    payload = valid.model_dump()
    payload["counters_before"]["inflight"] = 1
    with pytest.raises(ValidationError, match="confirmed idle"):
        IoDeviceObservation.model_validate(payload)
    payload = valid.model_dump()
    payload["resource"] = "io:" + "0" * 32
    with pytest.raises(ValidationError, match="fingerprint"):
        IoDeviceObservation.model_validate(payload)
    payload = valid.model_dump()
    payload.update(
        status="unavailable",
        rate_status="available",
        counters=None,
        counters_before=None,
        elapsed_seconds=None,
        completion_count=None,
        completion_latency_ms=1,
        average_outstanding=None,
        read_bytes_per_second=None,
        write_bytes_per_second=None,
        completions_per_second=None,
        confirmed_idle=False,
        errors=["fixture"],
    )
    with pytest.raises(ValidationError, match="unavailable I/O device"):
        IoDeviceObservation.model_validate(payload)


def test_complete_inventory_covers_each_scope_exactly_once() -> None:
    value = device(scopes=["/a"])
    with pytest.raises(ValidationError, match="every configured scope"):
        IoObservation(
            status="available",
            inventory_complete=True,
            configured_scopes=["/a", "/b"],
            devices=[value],
        )
    duplicate = value.model_copy(update={"scopes": ["/a"], "mount_ids": {"/a": 20}})
    with pytest.raises(ValidationError, match="multiple resources|duplicate"):
        IoObservation(
            status="available",
            inventory_complete=True,
            configured_scopes=["/a"],
            devices=[value, duplicate],
        )


def test_io_coverage_counts_configured_scopes_not_deduplicated_devices() -> None:
    partial = IoObservation(
        status="partial",
        inventory_complete=False,
        configured_scopes=["/a", "/b"],
        devices=[device(scopes=["/a"])],
        mapping_errors={"/b": "configured_mount_not_found_or_subvolume"},
    )
    assert io_scope_coverage(partial, fresh=True) == (2, 1)
    assert io_scope_coverage(partial, fresh=False) == (2, 0)

    shared = IoObservation(
        status="available",
        inventory_complete=True,
        configured_scopes=["/a", "/b"],
        devices=[device(scopes=["/a", "/b"])],
    )
    assert len(shared.devices) == 1
    assert io_scope_coverage(shared, fresh=True) == (2, 2)
    unavailable = partial.model_copy(update={"status": "unavailable"})
    assert io_scope_coverage(unavailable, fresh=True) == (2, 0)
    assert io_scope_coverage(
        IoObservation(status="disabled", inventory_complete=True), fresh=True
    ) == (0, 0)


@pytest.mark.parametrize(
    ("observation", "available_scopes", "ratio"),
    [
        (
            IoObservation(
                status="partial",
                inventory_complete=False,
                configured_scopes=["/a", "/b"],
                devices=[device(scopes=["/a"])],
                mapping_errors={"/b": "configured_mount_not_found_or_subvolume"},
            ),
            1,
            "0.5",
        ),
        (
            IoObservation(
                status="available",
                inventory_complete=True,
                configured_scopes=["/a", "/b"],
                devices=[device(scopes=["/a", "/b"])],
            ),
            2,
            "1.0",
        ),
    ],
)
def test_api_and_prometheus_export_scope_based_io_coverage(
    observation: IoObservation, available_scopes: int, ratio: str
) -> None:
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    payload = make_sample(
        "node-a",
        BOOT,
        SESSION,
        0,
        [Filesystem(mountpoint="/", errors=["fixture"])],
        observed,
        cpu=CpuObservation(errors=["fixture"]),
        memory=MemoryObservation(host=HostMemoryObservation(errors=["fixture"])),
        fd=FdObservation(errors=["fixture"]),
        network=NetworkObservation.unavailable(None, "fixture"),
        dns=DnsObservation.unavailable(None, None, "fixture"),
        io=observation,
    )
    client = TestClient(
        create_app(
            {"node-a": SecretStr("a" * 40)},
            store=FixtureStore(),
            clock=lambda: observed,
        )
    )
    response = client.post(
        "/ingest",
        content=payload.model_dump_json(),
        headers={"Authorization": "Bearer " + "a" * 40},
    )
    assert response.status_code == 200
    coverage = client.get("/nodes/node-a/metrics").json()["io_coverage"]
    assert coverage["configured_scopes"] == 2
    assert coverage["available_scopes"] == available_scopes
    assert coverage["observed"] == 1
    assert f'fleetdoctor_io_coverage_ratio{{node="node-a"}} {ratio}' in client.get("/metrics").text


def bracket_race_observation(monkeypatch: pytest.MonkeyPatch, race: str) -> IoObservation:
    start_mount = "10 1 253:7 / /io rw - ext4 /dev/dm-7 rw"
    end_mount = "11 1 253:7 / /io rw - ext4 /dev/dm-7 rw" if race == "remount" else start_mount
    mount_reads = iter((start_mount, end_mount))
    diskstats = "253 7 dm-7 10 0 20 200 5 0 10 100 0 150 200 0 0 0 0 0 0"
    pressure = "some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0"

    def bounded(path: str | object, _limit: int = io_module.MAX_READ) -> str:
        value = str(path).replace("\\", "/")
        if value.endswith("/self/mountinfo"):
            return next(mount_reads)
        if value.endswith("/diskstats"):
            return diskstats
        if value.endswith("/pressure/io"):
            return pressure
        raise AssertionError(f"unexpected bounded read: {value}")

    monkeypatch.setattr(io_module, "_read_bounded", bounded)
    namespaces = iter(("mnt:[123]", "mnt:[124]" if race == "namespace" else "mnt:[123]"))
    monkeypatch.setattr(os, "readlink", lambda _path: next(namespaces))
    collector = IoCollector(monotonic=lambda: 1.0)
    start_identity = (
        "253:7",
        "/sys/devices/virtual/block/dm-7",
        "41",
        "fleetdoctor-ticket11-test",
        77,
    )
    end_identity = start_identity
    if race == "reused_major_minor":
        end_identity = (*start_identity[:2], "42", start_identity[3], start_identity[4])
    elif race == "filesystem":
        end_identity = (*start_identity[:4], 78)
    identities = iter((start_identity, end_identity))
    monkeypatch.setattr(collector, "_stable_mapping", lambda _record, _path: next(identities))
    monkeypatch.setattr(collector, "_slaves", lambda _path: set())
    collector.baselines[resource()] = io_module._Baseline(
        monotonic=0.0,
        counters=counters(),
        attachment=("mnt:[123]", (("/io", 10),)),
    )
    observation = collector.collect(("/io",))
    assert collector.baselines == {}
    return observation


@pytest.mark.parametrize("race", ["namespace", "remount", "reused_major_minor", "filesystem"])
def test_bracketed_inventory_races_cannot_rate_trigger_or_supersede(
    monkeypatch: pytest.MonkeyPatch, race: str
) -> None:
    observation = bracket_race_observation(monkeypatch, race)
    assert observation.status in ("partial", "unavailable")
    assert not observation.inventory_complete
    assert observation.devices == []
    assert "/io" in observation.mapping_errors
    assert any(
        "changed_during_io_collection" in error for error in observation.mapping_errors.values()
    )

    evaluator = IoEvaluator([])
    config = IoConfig(
        trigger_latency_ms=10,
        recovery_latency_ms=5,
        trigger_outstanding=0.5,
        recovery_outstanding=0.25,
        consecutive_samples=1,
    )
    observed = datetime(2026, 10, 29, tzinfo=UTC)
    baseline = device().model_copy(
        update={
            "rate_status": "baseline",
            "counters_before": None,
            "elapsed_seconds": None,
            "completion_count": None,
            "completion_latency_ms": None,
            "average_outstanding": None,
            "read_bytes_per_second": None,
            "write_bytes_per_second": None,
            "completions_per_second": None,
            "confirmed_idle": False,
        }
    )
    first = sample(0, baseline, observed)
    triggering = chained(baseline, idle=False)
    opening_sample = sample(1, triggering, observed + timedelta(seconds=5))
    opened = evaluator.evaluate(opening_sample, first, opening_sample.observed_at, config)[0]
    raced = make_sample(
        "node-a",
        BOOT,
        SESSION,
        2,
        [Filesystem(mountpoint="/", errors=["fixture"])],
        observed + timedelta(seconds=10),
        cpu=CpuObservation(errors=["fixture"]),
        memory=MemoryObservation(host=HostMemoryObservation(errors=["fixture"])),
        fd=FdObservation(errors=["fixture"]),
        network=NetworkObservation.unavailable(None, "fixture"),
        dns=DnsObservation.unavailable(None, None, "fixture"),
        io=observation,
    )
    changes = evaluator.evaluate(raced, opening_sample, raced.observed_at, config)
    assert len(changes) == 1
    assert changes[0].id == opened.id and changes[0].status == "active"
    assert changes[0].superseded_at is None and changes[0].resolved_at is None


def test_io_rule_opens_and_resolves_only_full_windows() -> None:
    evaluator = IoEvaluator([])
    config = IoConfig(
        trigger_latency_ms=10,
        recovery_latency_ms=5,
        trigger_outstanding=0.5,
        recovery_outstanding=0.25,
    )
    start = datetime(2026, 10, 29, tzinfo=UTC)
    changes = []
    baseline_device = device().model_copy(
        update={
            "rate_status": "baseline",
            "counters_before": None,
            "elapsed_seconds": None,
            "completion_count": None,
            "completion_latency_ms": None,
            "average_outstanding": None,
            "read_bytes_per_second": None,
            "write_bytes_per_second": None,
            "completions_per_second": None,
            "confirmed_idle": False,
        }
    )
    previous = sample(0, baseline_device, start)
    current_device = baseline_device
    for sequence in range(1, 4):
        current_device = chained(current_device, idle=False)
        current = sample(sequence, current_device, start + timedelta(seconds=sequence * 5))
        changes = evaluator.evaluate(current, previous, current.observed_at, config)
        previous = current
        if sequence < 3:
            assert changes == [] and not evaluator.active
    assert len(changes) == 1 and changes[0].status == "active"
    incident_id = changes[0].id
    for sequence in range(4, 7):
        current_device = chained(current_device, idle=True)
        current = sample(sequence, current_device, start + timedelta(seconds=sequence * 5))
        changes = evaluator.evaluate(current, previous, current.observed_at, config)
        previous = current
        if sequence < 6:
            assert evaluator.active
            assert all(change.status == "active" for change in changes)
    assert changes[-1].status == "resolved"
    assert changes[-1].id == incident_id
    assert changes[-1].opening_evidence != {}


def test_complete_replacement_is_superseded_not_healthy_resolution() -> None:
    evaluator = IoEvaluator([])
    config = IoConfig(
        trigger_latency_ms=10,
        recovery_latency_ms=5,
        trigger_outstanding=0.5,
        recovery_outstanding=0.25,
        consecutive_samples=1,
    )
    observed = datetime(2026, 10, 29, tzinfo=UTC)
    baseline = device().model_copy(
        update={
            "rate_status": "baseline",
            "counters_before": None,
            "elapsed_seconds": None,
            "completion_count": None,
            "completion_latency_ms": None,
            "average_outstanding": None,
            "read_bytes_per_second": None,
            "write_bytes_per_second": None,
            "completions_per_second": None,
            "confirmed_idle": False,
        }
    )
    first = sample(0, baseline, observed)
    original = chained(baseline, idle=False)
    opening_sample = sample(1, original, observed + timedelta(seconds=5))
    opened = evaluator.evaluate(opening_sample, first, opening_sample.observed_at, config)[0]
    payload = original.model_dump()
    payload.update(
        major_minor="253:8",
        sysfs_path="/sys/devices/virtual/block/dm-8",
        diskseq="42",
        dm_uuid="fleetdoctor-ticket11-replacement",
        filesystem_id=78,
    )
    material = {
        key: payload[key]
        for key in ("major_minor", "sysfs_path", "diskseq", "dm_uuid", "filesystem_id")
    }
    payload["resource"] = (
        "io:"
        + hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:32]
    )
    replacement = IoDeviceObservation.model_validate(payload)
    second = sample(2, replacement, observed + timedelta(seconds=10))
    changes = evaluator.evaluate(second, opening_sample, second.observed_at, config)
    retired = next(item for item in changes if item.id == opened.id)
    assert retired.status == "superseded"
    assert retired.resolved_at is None
    assert retired.supersession_reason == "positive_resource_replacement"
