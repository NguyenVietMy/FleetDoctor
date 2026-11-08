"""Bounded Linux block-I/O collection with auditable same-generation rates."""

from __future__ import annotations

import hashlib
import json
import math
import os
import posixpath
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from fleetdoctor.memory import validate_cgroup_paths
from fleetdoctor.schema import (
    IoCounters,
    IoDeviceObservation,
    IoObservation,
    IoPressureObservation,
    IoProcessObservation,
)

MAX_READ = 1_048_576
MAX_IO_DEVICES = 4
MAX_IO_PIDS = 16
MAX_IO_CGROUP_PRESSURE = 8
UNSUPPORTED_FILESYSTEMS = {
    "9p",
    "autofs",
    "cgroup",
    "cgroup2",
    "devpts",
    "fusectl",
    "mqueue",
    "nfs",
    "nfs4",
    "overlay",
    "proc",
    "ramfs",
    "smb3",
    "sysfs",
    "tmpfs",
}


@dataclass(frozen=True)
class MountRecord:
    mount_id: int
    major_minor: str
    root: str
    mountpoint: str
    filesystem_type: str
    source: str


@dataclass(frozen=True)
class _Baseline:
    monotonic: float
    counters: IoCounters
    attachment: tuple[str, tuple[tuple[str, int], ...]]


@dataclass(frozen=True)
class _ProcessBaseline:
    monotonic: float
    starttime: int
    read_bytes: int
    write_bytes: int


def configured_io_mounts(raw: str) -> tuple[str, ...]:
    if not raw:
        return ()
    values = raw.split(",")
    if len(values) > MAX_IO_DEVICES:
        raise ValueError("FLEETDOCTOR_IO_MOUNTS accepts at most 4 mountpoints")
    result: list[str] = []
    for value in values:
        if (
            not value
            or len(value) > 128
            or not value.startswith("/")
            or value != posixpath.normpath(value)
            or re.fullmatch(r"/[a-zA-Z0-9_./-]*", value) is None
        ):
            raise ValueError("FLEETDOCTOR_IO_MOUNTS requires canonical absolute mountpoints")
        result.append(value)
    if len(set(result)) != len(result):
        raise ValueError("FLEETDOCTOR_IO_MOUNTS requires unique mountpoints")
    return tuple(sorted(result))


def configured_io_pids(raw: str) -> tuple[int, ...]:
    if not raw:
        return ()
    values = raw.split(",")
    if len(values) > MAX_IO_PIDS or any(not value.isdigit() for value in values):
        raise ValueError("FLEETDOCTOR_IO_PIDS requires at most 16 comma-separated numeric PIDs")
    result = tuple(int(value) for value in values)
    if len(set(result)) != len(result) or any(value < 1 or value > 2**31 - 1 for value in result):
        raise ValueError("FLEETDOCTOR_IO_PIDS requires unique positive PIDs")
    return result


def _read_bounded(path: str | Path, limit: int = MAX_READ) -> str:
    with open(path, "rb", buffering=0) as stream:
        chunks: list[bytes] = []
        size = 0
        while size <= limit:
            chunk = stream.read(limit + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        value = b"".join(chunks)
    if len(value) > limit:
        raise ValueError("io_source_oversize")
    return value.decode("utf-8", "strict")


def _unescape_mount(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 8))

    return re.sub(r"\\([0-7]{3})", replace, value)


def parse_mountinfo(text: str) -> list[MountRecord]:
    records: list[MountRecord] = []
    if len(text.encode()) > MAX_READ:
        raise ValueError("mountinfo_oversize")
    for line in text.splitlines():
        left, separator, right = line.partition(" - ")
        left_fields, right_fields = left.split(), right.split()
        if not separator or len(left_fields) < 6 or len(right_fields) < 2:
            raise ValueError("mountinfo_malformed")
        if re.fullmatch(r"[0-9]+:[0-9]+", left_fields[2]) is None:
            raise ValueError("mountinfo_device_malformed")
        records.append(
            MountRecord(
                mount_id=int(left_fields[0]),
                major_minor=left_fields[2],
                root=_unescape_mount(left_fields[3]),
                mountpoint=_unescape_mount(left_fields[4]),
                filesystem_type=right_fields[0],
                source=_unescape_mount(right_fields[1]),
            )
        )
    if len(records) > 4096:
        raise ValueError("mountinfo_record_limit")
    return records


def parse_diskstats(text: str) -> dict[str, tuple[str, IoCounters]]:
    result: dict[str, tuple[str, IoCounters]] = {}
    if len(text.encode()) > MAX_READ:
        raise ValueError("diskstats_oversize")
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 14:
            continue
        if not all(field.isdigit() for field in fields[:2] + fields[3:]):
            raise ValueError("diskstats_non_numeric")
        key = f"{int(fields[0])}:{int(fields[1])}"
        if key in result:
            raise ValueError("diskstats_duplicate_device")
        values = [int(item) for item in fields[3:]]
        if 11 < len(values) < 15 or 15 < len(values) < 17:
            raise ValueError("diskstats_truncated_optional_tail")
        if any(value > 2**64 - 1 for value in values):
            raise ValueError("diskstats_counter_overflow")
        result[key] = (
            fields[2],
            IoCounters(
                reads_completed=values[0],
                sectors_read=values[2],
                read_ms=values[3],
                writes_completed=values[4],
                sectors_written=values[6],
                write_ms=values[7],
                inflight=values[8],
                io_ms=values[9],
                weighted_io_ms=values[10],
                discards_completed=values[11] if len(values) >= 15 else None,
                discard_sectors=values[13] if len(values) >= 15 else None,
                discard_ms=values[14] if len(values) >= 15 else None,
                flushes_completed=values[15] if len(values) >= 17 else None,
                flush_ms=values[16] if len(values) >= 17 else None,
            ),
        )
    return result


def parse_pressure(text: str, scope: str) -> IoPressureObservation:
    values: dict[str, dict[str, float | int]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 5 or fields[0] not in ("some", "full"):
            raise ValueError("io_pressure_malformed")
        if fields[0] in values:
            raise ValueError("io_pressure_duplicate_row")
        row: dict[str, float | int] = {}
        for field in fields[1:]:
            name, separator, raw = field.partition("=")
            if not separator or name not in ("avg10", "avg60", "avg300", "total"):
                raise ValueError("io_pressure_malformed")
            if name in row:
                raise ValueError("io_pressure_duplicate_key")
            row[name] = int(raw) if name == "total" else float(raw)
        values[fields[0]] = row
    if set(values) != {"some", "full"}:
        raise ValueError("io_pressure_incomplete")
    return IoPressureObservation(
        scope=scope,
        status="available",
        some=values["some"],
        full=values["full"],
    )


def _proc_starttime(text: str) -> int:
    close = text.rfind(")")
    fields = text[close + 2 :].split() if close >= 0 else []
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError("process_stat_malformed")
    return int(fields[19])


def parse_process_io(text: str) -> dict[str, int]:
    accepted = {"rchar", "wchar", "read_bytes", "write_bytes", "cancelled_write_bytes"}
    result: dict[str, int] = {}
    for line in text.splitlines():
        name, separator, raw = line.partition(":")
        if name not in accepted:
            continue
        raw = raw.strip()
        if not separator or re.fullmatch(r"-?[0-9]+", raw) is None or name in result:
            raise ValueError("process_io_malformed")
        value = int(raw)
        if value < 0:
            raise ValueError("process_io_negative_counter")
        if not -(2**63) <= value <= 2**64 - 1:
            raise ValueError("process_io_counter_overflow")
        result[name] = value
    if set(result) != accepted:
        raise ValueError("process_io_incomplete")
    return result


def _counter_delta(before: IoCounters, after: IoCounters, name: str) -> int | None:
    old, new = getattr(before, name), getattr(after, name)
    if old is None or new is None:
        return None
    if new < old:
        raise ValueError("io_counter_reset")
    return cast(int, new - old)


class IoCollector:
    """Stateful collector. Baselines never cross attachment or durable generations."""

    def __init__(
        self,
        *,
        proc_root: str = "/proc",
        sys_root: str = "/sys",
        stat: Callable[[str], os.stat_result] = os.stat,
        statvfs: Callable[[str], Any] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.proc_root = proc_root
        self.sys_root = sys_root
        self.stat = stat
        self.statvfs = statvfs or getattr(os, "statvfs", None)
        self.monotonic = monotonic
        self.baselines: dict[str, _Baseline] = {}
        self.process_baselines: dict[int, _ProcessBaseline] = {}

    def _stable_mapping(
        self, record: MountRecord, configured_path: str
    ) -> tuple[str, str, str, str, int]:
        observed = self.stat(configured_path)
        observed_key = f"{os.major(observed.st_dev)}:{os.minor(observed.st_dev)}"
        if observed_key != record.major_minor:
            raise ValueError("mount_mapping_inconsistent")
        sysfs_link = Path(self.sys_root) / "dev" / "block" / record.major_minor
        sysfs_path = str(sysfs_link.resolve(strict=True))
        if not sysfs_path.startswith(str(Path(self.sys_root).resolve()) + os.sep):
            raise ValueError("sysfs_mapping_escape")
        diskseq_path = Path(sysfs_path) / "diskseq"
        dm_uuid_path = Path(sysfs_path) / "dm" / "uuid"
        diskseq = _read_bounded(diskseq_path, 64).strip() if diskseq_path.exists() else ""
        if not diskseq and (Path(sysfs_path) / "partition").exists():
            parent = Path(sysfs_path).parent
            parent_diskseq = parent / "diskseq"
            if parent_diskseq.exists():
                raw_parent_diskseq = _read_bounded(parent_diskseq, 64).strip()
                if raw_parent_diskseq:
                    diskseq = f"{raw_parent_diskseq}"
        dm_uuid = _read_bounded(dm_uuid_path, 256).strip() if dm_uuid_path.exists() else ""
        if not diskseq and not dm_uuid:
            raise ValueError("stable_device_binding_unavailable")
        if self.statvfs is None:
            raise ValueError("statvfs_unavailable")
        filesystem_id = getattr(self.statvfs(configured_path), "f_fsid", None)
        if filesystem_id is None:
            raise ValueError("stable_filesystem_binding_unavailable")
        return observed_key, sysfs_path, diskseq, dm_uuid, int(filesystem_id)

    def _slaves(self, sysfs_path: str) -> set[str]:
        result: set[str] = set()
        pending = [Path(sysfs_path)]
        original = Path(sysfs_path)
        if (original / "partition").exists():
            result.add(str(original.parent.resolve(strict=True)))
        while pending:
            current = pending.pop()
            slaves = current / "slaves"
            if not slaves.exists():
                continue
            for child in slaves.iterdir():
                resolved = str(child.resolve(strict=True))
                if resolved not in result:
                    result.add(resolved)
                    pending.append(Path(resolved))
            if len(result) > 64:
                raise ValueError("device_topology_oversize")
        return result

    def _process(self, pid: int, now: float) -> IoProcessObservation:
        try:
            stat_path = Path(self.proc_root) / str(pid) / "stat"
            before = _proc_starttime(_read_bounded(stat_path, 8192))
            counters = parse_process_io(_read_bounded(Path(self.proc_root) / str(pid) / "io", 8192))
            after = _proc_starttime(_read_bounded(stat_path, 8192))
            if before != after:
                raise ValueError("process_identity_changed")
            baseline = self.process_baselines.get(pid)
            read_rate = write_rate = None
            rate_status: Literal["available", "baseline", "reset", "gap", "unavailable"] = (
                "baseline"
            )
            if baseline is not None and baseline.starttime == before:
                elapsed = now - baseline.monotonic
                if 0 < elapsed <= 10:
                    if (
                        counters["read_bytes"] >= baseline.read_bytes
                        and counters["write_bytes"] >= baseline.write_bytes
                    ):
                        read_rate = (counters["read_bytes"] - baseline.read_bytes) / elapsed
                        write_rate = (counters["write_bytes"] - baseline.write_bytes) / elapsed
                        rate_status = "available"
                    else:
                        rate_status = "reset"
                else:
                    rate_status = "gap"
            self.process_baselines[pid] = _ProcessBaseline(
                now, before, counters["read_bytes"], counters["write_bytes"]
            )
            return IoProcessObservation(
                pid=pid,
                starttime=before,
                status="available",
                rate_status=rate_status,
                physical_read_bytes=counters["read_bytes"],
                physical_write_bytes=counters["write_bytes"],
                physical_read_bytes_per_second=read_rate,
                physical_write_bytes_per_second=write_rate,
                logical_read_characters=counters["rchar"],
                logical_write_characters=counters["wchar"],
                cancelled_write_bytes=counters["cancelled_write_bytes"],
                net_write_balance_bytes=(
                    counters["write_bytes"] - counters["cancelled_write_bytes"]
                ),
            )
        except (OSError, ValueError) as exc:
            self.process_baselines.pop(pid, None)
            return IoProcessObservation(
                pid=pid,
                status="unavailable",
                rate_status="unavailable",
                errors=[str(exc)[:256] or type(exc).__name__],
            )

    def collect(
        self,
        mounts: tuple[str, ...],
        pids: tuple[int, ...] = (),
        cgroups: tuple[str, ...] = (),
    ) -> IoObservation:
        if not mounts:
            self.baselines.clear()
            return IoObservation(status="disabled", inventory_complete=True)
        mounts = configured_io_mounts(",".join(mounts))
        configured_io_pids(",".join(str(pid) for pid in pids))
        cgroups = validate_cgroup_paths(",".join(cgroups))
        if len(cgroups) > MAX_IO_CGROUP_PRESSURE:
            raise ValueError("configure at most eight I/O pressure cgroups")
        registered_pressure_scopes = ["host", *sorted(cgroups)]
        try:
            namespace_path = Path(self.proc_root) / "self" / "ns" / "mnt"
            mountinfo_path = Path(self.proc_root) / "self" / "mountinfo"
            namespace = os.readlink(str(namespace_path))
            mountinfo = parse_mountinfo(_read_bounded(mountinfo_path))
            by_mount = {item.mountpoint: item for item in mountinfo}
            start_mappings: dict[str, tuple[tuple[str, str, str, str, int], MountRecord]] = {}
            mapping_errors: dict[str, str] = {}
            for mount in mounts:
                try:
                    record = by_mount.get(mount)
                    if record is None or record.root != "/":
                        raise ValueError("configured_mount_not_found_or_subvolume")
                    if record.filesystem_type in UNSUPPORTED_FILESYSTEMS:
                        raise ValueError("unsupported_filesystem_type")
                    start_mappings[mount] = (self._stable_mapping(record, mount), record)
                except (OSError, ValueError) as exc:
                    mapping_errors[mount] = str(exc)[:256] or type(exc).__name__
            diskstats = parse_diskstats(_read_bounded(Path(self.proc_root) / "diskstats"))
            now = self.monotonic()
            ending_namespace = os.readlink(str(namespace_path))
            if ending_namespace != namespace:
                raise ValueError("mount_namespace_changed_during_io_collection")
            ending_mountinfo = parse_mountinfo(_read_bounded(mountinfo_path))
            ending_by_mount = {item.mountpoint: item for item in ending_mountinfo}
            grouped: dict[tuple[str, str, str, str, int], list[tuple[str, MountRecord]]] = {}
            for mount in mounts:
                if mount in mapping_errors:
                    continue
                try:
                    starting_identity, starting_record = start_mappings[mount]
                    ending_record = ending_by_mount.get(mount)
                    if ending_record is None or ending_record != starting_record:
                        raise ValueError("mount_inventory_changed_during_io_collection")
                    ending_identity = self._stable_mapping(ending_record, mount)
                    if ending_identity != starting_identity:
                        raise ValueError("device_or_filesystem_changed_during_io_collection")
                    grouped.setdefault(starting_identity, []).append((mount, starting_record))
                except (OSError, ValueError) as exc:
                    mapping_errors[mount] = str(exc)[:256] or type(exc).__name__
            paths = {identity[1]: {identity[1], *self._slaves(identity[1])} for identity in grouped}
            overlapping: set[str] = set()
            selected_paths = sorted(paths)
            for index, path in enumerate(selected_paths):
                for other in selected_paths[index + 1 :]:
                    if paths[path].intersection(paths[other]):
                        overlapping.update((path, other))
            devices: list[IoDeviceObservation] = []
            seen_resources: set[str] = set()
            for identity, memberships in sorted(grouped.items(), key=lambda item: item[0]):
                major_minor, sysfs_path, diskseq, dm_uuid, filesystem_id = identity
                scopes = sorted(item[0] for item in memberships)
                mount_ids = sorted((item[0], item[1].mount_id) for item in memberships)
                material = {
                    "major_minor": major_minor,
                    "sysfs_path": sysfs_path,
                    "diskseq": diskseq or None,
                    "dm_uuid": dm_uuid or None,
                    "filesystem_id": filesystem_id,
                }
                resource = (
                    "io:"
                    + hashlib.sha256(
                        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()[:32]
                )
                if resource in seen_resources:
                    raise ValueError("durable_resource_collision")
                seen_resources.add(resource)
                errors: list[str] = []
                row = diskstats.get(major_minor)
                if sysfs_path in overlapping:
                    errors.append("configured_device_parent_slave_overlap")
                if row is None:
                    errors.append("diskstats_device_missing")
                if errors:
                    self.baselines.pop(resource, None)
                    devices.append(
                        IoDeviceObservation(
                            resource=resource,
                            status="unavailable",
                            rate_status="unavailable",
                            major_minor=major_minor,
                            device_name=row[0] if row else None,
                            sysfs_path=sysfs_path,
                            diskseq=diskseq or None,
                            dm_uuid=dm_uuid or None,
                            filesystem_id=filesystem_id,
                            scopes=scopes,
                            mount_ids={path: mount_id for path, mount_id in mount_ids},
                            mount_namespace=namespace,
                            errors=errors,
                        )
                    )
                    continue
                assert row is not None
                device_name, counters = row
                attachment = (namespace, tuple(mount_ids))
                baseline = self.baselines.get(resource)
                rate_status: Literal["available", "baseline", "reset", "unavailable"] = "baseline"
                elapsed_seconds: float | None = None
                counters_before: IoCounters | None = None
                completion_count: int | None = None
                completion_latency_ms: float | None = None
                average_outstanding: float | None = None
                read_bytes_per_second: float | None = None
                write_bytes_per_second: float | None = None
                completions_per_second: float | None = None
                confirmed_idle = False
                if baseline is not None:
                    elapsed = now - baseline.monotonic
                    try:
                        if attachment != baseline.attachment:
                            raise ValueError("io_attachment_changed")
                        if not math.isfinite(elapsed) or not 0 < elapsed <= 10:
                            raise ValueError("io_interval_gap")
                        names = (
                            "reads_completed",
                            "sectors_read",
                            "read_ms",
                            "writes_completed",
                            "sectors_written",
                            "write_ms",
                            "io_ms",
                            "weighted_io_ms",
                        )
                        deltas = {
                            name: _counter_delta(baseline.counters, counters, name)
                            for name in names
                        }
                        reads = int(deltas["reads_completed"] or 0)
                        writes = int(deltas["writes_completed"] or 0)
                        completions = reads + writes
                        optional_names = (
                            "discards_completed",
                            "discard_sectors",
                            "discard_ms",
                            "flushes_completed",
                            "flush_ms",
                        )
                        optional = {
                            name: _counter_delta(baseline.counters, counters, name)
                            for name in optional_names
                        }
                        optional_complete = all(value is not None for value in optional.values())
                        confirmed_idle = bool(
                            completions == 0
                            and deltas["sectors_read"] == 0
                            and deltas["sectors_written"] == 0
                            and deltas["read_ms"] == 0
                            and deltas["write_ms"] == 0
                            and deltas["io_ms"] == 0
                            and deltas["weighted_io_ms"] == 0
                            and baseline.counters.inflight == 0
                            and counters.inflight == 0
                            and optional_complete
                            and all(value == 0 for value in optional.values())
                        )
                        rate_status = "available"
                        elapsed_seconds = elapsed
                        counters_before = baseline.counters
                        completion_count = completions
                        completion_latency_ms = (
                            (int(deltas["read_ms"] or 0) + int(deltas["write_ms"] or 0))
                            / completions
                            if completions
                            else None
                        )
                        average_outstanding = int(deltas["weighted_io_ms"] or 0) / (1000 * elapsed)
                        read_bytes_per_second = int(deltas["sectors_read"] or 0) * 512 / elapsed
                        write_bytes_per_second = int(deltas["sectors_written"] or 0) * 512 / elapsed
                        completions_per_second = completions / elapsed
                    except ValueError as exc:
                        rate_status = "reset"
                        errors.append(str(exc))
                self.baselines[resource] = _Baseline(now, counters, attachment)
                devices.append(
                    IoDeviceObservation(
                        resource=resource,
                        status="available",
                        rate_status=rate_status,
                        major_minor=major_minor,
                        device_name=device_name,
                        sysfs_path=sysfs_path,
                        diskseq=diskseq or None,
                        dm_uuid=dm_uuid or None,
                        filesystem_id=filesystem_id,
                        scopes=scopes,
                        mount_ids={path: mount_id for path, mount_id in mount_ids},
                        mount_namespace=namespace,
                        counters=counters,
                        counters_before=counters_before,
                        elapsed_seconds=elapsed_seconds,
                        completion_count=completion_count,
                        completion_latency_ms=completion_latency_ms,
                        average_outstanding=average_outstanding,
                        read_bytes_per_second=read_bytes_per_second,
                        write_bytes_per_second=write_bytes_per_second,
                        completions_per_second=completions_per_second,
                        confirmed_idle=confirmed_idle,
                        errors=errors,
                    )
                )
            pressure: list[IoPressureObservation] = []
            for scope, pressure_path in [("host", Path(self.proc_root) / "pressure" / "io")]:
                try:
                    pressure.append(parse_pressure(_read_bounded(pressure_path, 8192), scope))
                except (OSError, ValueError) as exc:
                    pressure.append(
                        IoPressureObservation(
                            scope=scope,
                            status="unavailable",
                            errors=[str(exc)[:256] or type(exc).__name__],
                        )
                    )
            for cgroup in cgroups:
                pressure_path = Path("/sys/fs/cgroup") / cgroup.lstrip("/") / "io.pressure"
                try:
                    pressure.append(parse_pressure(_read_bounded(pressure_path, 8192), cgroup))
                except (OSError, ValueError) as exc:
                    pressure.append(
                        IoPressureObservation(
                            scope=cgroup,
                            status="unavailable",
                            errors=[str(exc)[:256] or type(exc).__name__],
                        )
                    )
            active_resources = {item.resource for item in devices}
            self.baselines = {
                key: value for key, value in self.baselines.items() if key in active_resources
            }
            processes = [self._process(pid, now) for pid in pids]
            return IoObservation(
                status="available" if not mapping_errors else "partial",
                inventory_complete=not mapping_errors,
                configured_scopes=list(mounts),
                devices=devices,
                processes=processes,
                process_coverage="complete",
                registered_pressure_scopes=registered_pressure_scopes,
                pressure=pressure,
                pressure_coverage="complete",
                mapping_errors=mapping_errors,
            )
        except (OSError, ValueError) as exc:
            self.baselines.clear()
            return IoObservation(
                status="unavailable",
                inventory_complete=False,
                configured_scopes=list(mounts),
                registered_pressure_scopes=registered_pressure_scopes,
                pressure=[
                    IoPressureObservation(
                        scope=scope,
                        status="unavailable",
                        errors=["io_collection_aborted"],
                    )
                    for scope in registered_pressure_scopes
                ],
                pressure_coverage="complete",
                process_coverage="unavailable",
                mapping_errors={mount: str(exc)[:256] or type(exc).__name__ for mount in mounts},
                errors=[str(exc)[:256] or type(exc).__name__],
            )
