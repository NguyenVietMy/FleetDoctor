"""Maximum bounded schema-v7 delivery fixture for native resource proof."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from uuid import UUID

from fleetdoctor.agent import make_sample
from fleetdoctor.schema import (
    CpuObservation,
    DnsObservation,
    FdObservation,
    FdProcessIdentity,
    FdProcessObservation,
    Filesystem,
    HostMemoryObservation,
    IoCounters,
    IoDeviceObservation,
    IoObservation,
    IoPressureObservation,
    IoProcessObservation,
    MemoryObservation,
    NetworkObservation,
    ProcessIdentity,
    ProcessObservation,
    Sample,
)


def maximum_io() -> IoObservation:
    before = IoCounters(
        reads_completed=1,
        sectors_read=2,
        read_ms=10,
        writes_completed=1,
        sectors_written=2,
        write_ms=10,
        inflight=0,
        io_ms=10,
        weighted_io_ms=10,
        discards_completed=0,
        discard_sectors=0,
        discard_ms=0,
        flushes_completed=0,
        flush_ms=0,
    )
    after = before.model_copy(
        update={
            "reads_completed": 2,
            "sectors_read": 4,
            "read_ms": 20,
            "writes_completed": 2,
            "sectors_written": 4,
            "write_ms": 20,
            "io_ms": 20,
            "weighted_io_ms": 1010,
        }
    )
    devices: list[IoDeviceObservation] = []
    scopes = [f"/io-{index}" for index in range(4)]
    for index, scope in enumerate(scopes):
        major_minor = f"253:{index}"
        sysfs_path = f"/sys/devices/virtual/block/dm-{index}"
        diskseq = str(100 + index)
        dm_uuid = f"fleetdoctor-payload-{index}"
        filesystem_id = 1000 + index
        material: dict[str, str | int] = {
            "major_minor": major_minor,
            "sysfs_path": sysfs_path,
            "diskseq": diskseq,
            "dm_uuid": dm_uuid,
            "filesystem_id": filesystem_id,
        }
        resource = (
            "io:"
            + hashlib.sha256(
                json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()[:32]
        )
        devices.append(
            IoDeviceObservation(
                resource=resource,
                status="available",
                rate_status="available",
                major_minor=major_minor,
                device_name=f"dm-{index}",
                sysfs_path=sysfs_path,
                diskseq=diskseq,
                dm_uuid=dm_uuid,
                filesystem_id=filesystem_id,
                scopes=[scope],
                mount_ids={scope: 100 + index},
                mount_namespace="mnt:[4026533000]",
                counters=after,
                counters_before=before,
                elapsed_seconds=1,
                completion_count=2,
                completion_latency_ms=10,
                average_outstanding=1,
                read_bytes_per_second=1024,
                write_bytes_per_second=1024,
                completions_per_second=2,
                confirmed_idle=False,
            )
        )
    pressure_scopes = ["host", *[f"/workload/io-{index}" for index in range(8)]]
    return IoObservation(
        status="available",
        inventory_complete=True,
        configured_scopes=scopes,
        devices=devices,
        processes=[
            IoProcessObservation(
                pid=5000 + index,
                starttime=6000 + index,
                status="available",
                rate_status="baseline",
                physical_read_bytes=2**64 - 1,
                physical_write_bytes=2**64 - 1,
                logical_read_characters=2**64 - 1,
                logical_write_characters=2**64 - 1,
                cancelled_write_bytes=2**64 - 1,
                net_write_balance_bytes=0,
            )
            for index in range(16)
        ],
        process_coverage="complete",
        registered_pressure_scopes=pressure_scopes,
        pressure=[
            IoPressureObservation(
                scope=scope, status="unavailable", errors=["pressure_unavailable"] * 4
            )
            for scope in pressure_scopes
        ],
        pressure_coverage="complete",
    )


def maximum_sample(
    dns: DnsObservation, *, boot: UUID, session: UUID, observed_at: datetime
) -> Sample:
    watched = [
        FdProcessObservation(
            identity=FdProcessIdentity(boot_id=boot, pid=100 + index, starttime_ticks=1000 + index),
            status="unknown",
            watched=True,
            errors=["watch_unknown"],
        )
        for index in range(32)
    ]
    candidates = [
        FdProcessObservation(
            identity=FdProcessIdentity(
                boot_id=boot, pid=1000 + index, starttime_ticks=2000 + index
            ),
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
    fd = FdObservation(
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
        boot,
        session,
        0,
        [Filesystem(mountpoint=f"/f{index}", errors=["e" * 256] * 8) for index in range(8)],
        observed_at,
        cpu=CpuObservation(
            logical_cores=1,
            online_cpu_ids=[0],
            runnable_processes=0,
            processes=cpu_processes,
            process_inventory="complete",
            scanned_processes=36,
            errors=["cpu_rate_baseline_unavailable"],
        ),
        memory=MemoryObservation(host=HostMemoryObservation(errors=["m" * 600] * 16)),
        fd=fd,
        network=NetworkObservation.unavailable("192.0.2.80", "fixture"),
        dns=dns,
        io=maximum_io(),
    )
