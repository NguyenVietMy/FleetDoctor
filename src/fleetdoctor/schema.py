"""The versioned wire contract; missing observations are never zero-filled."""

import re
from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

Count = Annotated[StrictInt, Field(ge=0, le=2**64 - 1)]
Percent = Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)]
Ratio = Annotated[float, Field(ge=0, le=1_000_000, allow_inf_nan=False)]
UNITS = {"space": "bytes", "inodes": "count", "usage": "percent", "observation_time": "UTC"}
CPU_UNITS = {
    "cpu": "percent",
    "runnable": "count",
    "logical_cpus": "count",
    "load": "processes",
    "interval": "seconds",
    "process_cpu": "percent_of_one_logical_core",
    "process_rss": "bytes",
    "clock_ticks": "ticks",
}
UNITS_V2 = {**UNITS, **CPU_UNITS}
MEMORY_UNITS = {
    "memory": "bytes",
    "memory_usage": "ratio",
    "memory_events": "count",
    "page_faults": "count",
    "page_activity": "bytes_per_second",
}
UNITS_V3 = {**UNITS_V2, **MEMORY_UNITS}
FIELDS = (
    "total_bytes",
    "free_bytes",
    "available_bytes",
    "used_bytes",
    "block_usage_percent",
    "inodes_total",
    "inodes_free",
    "inode_usage_percent",
)


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Filesystem(WireModel):
    mountpoint: str = Field(min_length=1, max_length=128, pattern=r"^/[a-zA-Z0-9_./-]*$")
    total_bytes: Count | None = None
    free_bytes: Count | None = None
    available_bytes: Count | None = None
    used_bytes: Count | None = None
    block_usage_percent: Percent | None = None
    inodes_total: Count | None = None
    inodes_free: Count | None = None
    inode_usage_percent: Percent | None = None
    errors: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("errors")
    @classmethod
    def bounded_errors(cls, errors: list[str]) -> list[str]:
        if any(len(error) > 256 for error in errors):
            raise ValueError("collection error exceeds 256 characters")
        return errors

    @model_validator(mode="after")
    def consistent(self) -> Self:
        blocks = (self.total_bytes, self.free_bytes, self.available_bytes, self.used_bytes)
        if any(value is not None for value in blocks):
            if any(value is None for value in blocks):
                raise ValueError("block counters must all be present or unavailable")
            total, free, available, used = blocks
            assert (
                total is not None
                and free is not None
                and available is not None
                and used is not None
            )
            if not 0 <= available <= free <= total or used != total - free:
                raise ValueError("inconsistent block counters")
            expected = used / (used + available) * 100 if used + available else None
            if expected is None:
                if self.block_usage_percent is not None:
                    raise ValueError("zero capacity requires unavailable usage")
            elif (
                self.block_usage_percent is None or abs(self.block_usage_percent - expected) > 0.001
            ):
                raise ValueError("incorrect block usage")
        elif self.block_usage_percent is not None:
            raise ValueError("usage without block counters")
        if self.inodes_total is None or self.inodes_free is None:
            if (
                self.inodes_total is not None
                or self.inodes_free is not None
                or self.inode_usage_percent is not None
            ):
                raise ValueError("partial inode counters")
        else:
            if self.inodes_free > self.inodes_total:
                raise ValueError("inconsistent inode counters")
            expected = (
                (self.inodes_total - self.inodes_free) / self.inodes_total * 100
                if self.inodes_total
                else None
            )
            if expected is None:
                if self.inode_usage_percent is not None:
                    raise ValueError("zero inode capacity requires unavailable usage")
            elif (
                self.inode_usage_percent is None or abs(self.inode_usage_percent - expected) > 0.001
            ):
                raise ValueError("incorrect inode usage")
        if any(getattr(self, field) is None for field in FIELDS) and not self.errors:
            raise ValueError("unavailable fields require collection errors")
        return self


class Delivery(WireModel):
    discard_total: Count


class CpuCounters(WireModel):
    user: Count
    nice: Count
    system: Count
    idle: Count
    iowait: Count
    irq: Count
    softirq: Count
    steal: Count


class ProcessIdentity(WireModel):
    pid: Annotated[StrictInt, Field(ge=1, le=2**31 - 1)]
    starttime_ticks: Count


class ProcessObservation(WireModel):
    identity: ProcessIdentity
    comm: str = Field(min_length=1, max_length=128)
    cpu_percent: Annotated[float, Field(ge=0, le=409600, allow_inf_nan=False)] | None = None
    rss_bytes: Count | None = None
    configured: bool = False


class CpuObservation(WireModel):
    scope: Literal["host"] = "host"
    interval_seconds: Annotated[float, Field(gt=0, le=10, allow_inf_nan=False)] | None = None
    busy_percent: Percent | None = None
    iowait_percent: Percent | None = None
    steal_percent: Percent | None = None
    logical_cores: Annotated[StrictInt, Field(ge=1, le=4096)] | None = None
    online_cpu_ids: list[Annotated[StrictInt, Field(ge=0, le=1_000_000)]] = Field(
        default_factory=list, max_length=4096
    )
    runnable_processes: Count | None = None
    load_1m: Annotated[float, Field(ge=0, le=1_000_000, allow_inf_nan=False)] | None = None
    load_5m: Annotated[float, Field(ge=0, le=1_000_000, allow_inf_nan=False)] | None = None
    load_15m: Annotated[float, Field(ge=0, le=1_000_000, allow_inf_nan=False)] | None = None
    ticks_per_second: Annotated[StrictInt, Field(ge=1, le=1_000_000)] | None = None
    counters: CpuCounters | None = None
    processes: list[ProcessObservation] = Field(default_factory=list, max_length=36)
    process_inventory: Literal["complete", "partial", "unavailable"] = "unavailable"
    scanned_processes: Annotated[StrictInt, Field(ge=0, le=4096)] = 0
    errors: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("errors")
    @classmethod
    def bounded_cpu_errors(cls, errors: list[str]) -> list[str]:
        if any(not error or len(error) > 256 for error in errors):
            raise ValueError("CPU collection error must contain 1..256 characters")
        return errors

    @model_validator(mode="after")
    def consistent_cpu(self) -> Self:
        rates = (self.busy_percent, self.iowait_percent, self.steal_percent)
        if self.interval_seconds is None and any(value is not None for value in rates):
            raise ValueError("CPU rates require an interval")
        if self.interval_seconds is not None and any(value is None for value in rates):
            raise ValueError("CPU interval requires all host rate fields")
        if len({(p.identity.pid, p.identity.starttime_ticks) for p in self.processes}) != len(
            self.processes
        ):
            raise ValueError("duplicate process identity")
        if len(set(self.online_cpu_ids)) != len(self.online_cpu_ids):
            raise ValueError("duplicate online CPU identity")
        if self.logical_cores is not None and len(self.online_cpu_ids) != self.logical_cores:
            raise ValueError("online CPU identities disagree with logical core count")
        if self.process_inventory == "unavailable" and (self.processes or self.scanned_processes):
            raise ValueError("unavailable process inventory cannot contain observations")
        if self.process_inventory != "unavailable" and self.scanned_processes < len(self.processes):
            raise ValueError("process observations exceed scanned inventory")
        if (
            any(value is None for value in (self.logical_cores, self.runnable_processes))
            and not self.errors
        ):
            raise ValueError("unavailable CPU sources require collection errors")
        if self.busy_percent is None and not self.errors:
            raise ValueError("unavailable CPU rate requires a collection error")
        return self


class MemoryCounters(WireModel):
    pgfault: Count
    pgmajfault: Count
    pswpin: Count
    pswpout: Count


class MemoryEvents(WireModel):
    oom: Count
    oom_kill: Count
    high: Count | None = None
    max: Count | None = None


class KernelOomLog(WireModel):
    boot_id: UUID
    cursor: str = Field(min_length=1, max_length=256)
    realtime_timestamp: datetime
    message: str = Field(min_length=1, max_length=512)
    cgroup_path: str | None = Field(default=None, min_length=1, max_length=256)
    victim_pid: Annotated[StrictInt, Field(ge=1, le=2**31 - 1)] | None = None
    victim_comm: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("realtime_timestamp")
    @classmethod
    def aware_log_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("kernel log time must include timezone")
        return value


class HostMemoryObservation(WireModel):
    scope: Literal["host"] = "host"
    total_bytes: Count | None = None
    available_bytes: Count | None = None
    swap_total_bytes: Count | None = None
    swap_free_bytes: Count | None = None
    page_size_bytes: Annotated[StrictInt, Field(ge=1, le=1 << 30)] | None = None
    interval_seconds: Annotated[float, Field(gt=0, le=10, allow_inf_nan=False)] | None = None
    counters: MemoryCounters | None = None
    pgfault_per_second: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    pgmajfault_per_second: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    swap_in_bytes_per_second: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    swap_out_bytes_per_second: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    errors: list[str] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def consistent_host_memory(self) -> Self:
        capacities = (
            self.total_bytes,
            self.available_bytes,
            self.swap_total_bytes,
            self.swap_free_bytes,
        )
        if any(value is None for value in capacities) and not self.errors:
            raise ValueError("unavailable host memory requires collection errors")
        if self.total_bytes is not None and self.available_bytes is not None:
            if self.available_bytes > self.total_bytes:
                raise ValueError("available host memory exceeds total")
        if self.swap_total_bytes is not None and self.swap_free_bytes is not None:
            if self.swap_free_bytes > self.swap_total_bytes:
                raise ValueError("free swap exceeds total")
        rates = (
            self.pgfault_per_second,
            self.pgmajfault_per_second,
            self.swap_in_bytes_per_second,
            self.swap_out_bytes_per_second,
        )
        if self.interval_seconds is None and any(value is not None for value in rates):
            raise ValueError("memory rates require an interval")
        if self.interval_seconds is not None and any(value is None for value in rates):
            raise ValueError("memory interval requires all rate fields")
        return self


class WorkloadMemoryObservation(WireModel):
    scope: Literal["workload"] = "workload"
    cgroup_path: str = Field(min_length=2, max_length=256, pattern=r"^/[a-zA-Z0-9_.@/-]+$")
    boot_id: UUID
    st_dev: Count
    st_ino: Count
    current_bytes: Count | None = None
    max_bytes: Count | None = None
    max_unlimited: bool = False
    usage_ratio: Ratio | None = None
    swap_current_bytes: Count | None = None
    swap_max_bytes: Count | None = None
    swap_max_unlimited: bool = False
    events_before: MemoryEvents | None = None
    events: MemoryEvents | None = None
    events_stable: bool = False
    processes: list[ProcessObservation] = Field(default_factory=list, max_length=10)
    process_inventory: Literal["complete", "partial", "unavailable"] = "unavailable"
    errors: list[str] = Field(default_factory=list, max_length=16)

    @property
    def generation_key(self) -> str:
        return f"{self.cgroup_path}|{self.boot_id}|{self.st_dev}|{self.st_ino}"

    @property
    def snapshot_stable(self) -> bool:
        """Whether the bracket and collector markers both permit presentation/recovery."""
        return self.events_stable and "unstable_snapshot" not in self.errors

    @model_validator(mode="after")
    def consistent_workload_memory(self) -> Self:
        if self.max_unlimited and self.max_bytes is not None:
            raise ValueError("unlimited memory cannot have a finite limit")
        if self.swap_max_unlimited and self.swap_max_bytes is not None:
            raise ValueError("unlimited swap cannot have a finite limit")
        if self.usage_ratio is not None:
            if self.current_bytes is None or self.max_bytes is None or self.max_bytes == 0:
                raise ValueError("usage ratio requires current and a positive finite limit")
            expected = self.current_bytes / self.max_bytes
            if abs(self.usage_ratio - expected) > 0.000001:
                raise ValueError("incorrect workload memory ratio")
        if (self.events_before is None) != (self.events is None):
            raise ValueError("event bracket requires both counter reads")
        actual_stability = self.events_before is not None and self.events_before == self.events
        if self.events_stable != actual_stability:
            raise ValueError("events_stable must equal the event-bracket comparison")
        identities = {(p.identity.pid, p.identity.starttime_ticks) for p in self.processes}
        if len(identities) != len(self.processes):
            raise ValueError("duplicate workload process identity")
        if self.process_inventory == "unavailable" and self.processes:
            raise ValueError("unavailable workload inventory cannot contain processes")
        if (self.current_bytes is None or self.events is None) and not self.errors:
            raise ValueError("unavailable workload memory requires collection errors")
        return self


class MemoryObservation(WireModel):
    host: HostMemoryObservation
    workloads: list[WorkloadMemoryObservation] = Field(default_factory=list, max_length=4)
    kernel_logs: list[KernelOomLog] = Field(default_factory=list, max_length=16)
    kernel_log_coverage: Literal[
        "baseline", "available", "permission_denied", "cursor_lost", "unavailable"
    ] = "unavailable"
    kernel_log_errors: list[str] = Field(default_factory=list, max_length=8)
    workload_errors: dict[str, list[str]] = Field(default_factory=dict, max_length=4)

    @model_validator(mode="after")
    def unique_workloads(self) -> Self:
        if len({item.cgroup_path for item in self.workloads}) != len(self.workloads):
            raise ValueError("duplicate workload cgroup path")
        if len({item.generation_key for item in self.workloads}) != len(self.workloads):
            raise ValueError("duplicate workload generation")
        if set(self.workload_errors) & {item.cgroup_path for item in self.workloads}:
            raise ValueError("available workloads cannot also have collection errors")
        if any(
            len(path) > 256
            or path == "/"
            or not re.fullmatch(r"/[a-zA-Z0-9_.@/-]+", path)
            or "//" in path
            or any(part in ("", ".", "..") for part in path.split("/")[1:])
            or not errors
            or len(errors) > 4
            or any(not error or len(error) > 128 for error in errors)
            for path, errors in self.workload_errors.items()
        ):
            raise ValueError("invalid bounded workload collection errors")
        if sum(len(item.message.encode("utf-8")) for item in self.kernel_logs) > 8192:
            raise ValueError("kernel log evidence exceeds 8KiB")
        return self


class Sample(WireModel):
    schema_version: Literal[1, 2, 3]
    node_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    boot_id: UUID
    agent_session_id: UUID
    sequence: Count
    observed_at: datetime
    units: dict[str, str]
    filesystems: list[Filesystem] = Field(min_length=1, max_length=8)
    cpu: CpuObservation | None = Field(default=None, exclude_if=lambda value: value is None)
    memory: MemoryObservation | None = Field(default=None, exclude_if=lambda value: value is None)
    delivery: Delivery | None = None

    @field_validator("observed_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observation time must include timezone")
        return value

    @field_validator("units")
    @classmethod
    def exact_units(cls, value: dict[str, str]) -> dict[str, str]:
        if value not in (UNITS, UNITS_V2, UNITS_V3):
            raise ValueError("unsupported metric units")
        return value

    @model_validator(mode="after")
    def unique_paths(self) -> Self:
        if self.schema_version == 1 and (
            self.units != UNITS or self.cpu is not None or self.memory is not None
        ):
            raise ValueError("schema v1 cannot contain CPU telemetry")
        if self.schema_version == 2 and (
            self.units != UNITS_V2 or self.cpu is None or self.memory is not None
        ):
            raise ValueError("schema v2 requires CPU telemetry and v2 units")
        if self.schema_version == 3 and (
            self.units != UNITS_V3 or self.cpu is None or self.memory is None
        ):
            raise ValueError("schema v3 requires CPU and memory telemetry and v3 units")
        if self.memory is not None:
            if any(item.boot_id != self.boot_id for item in self.memory.workloads):
                raise ValueError("workload boot identity must match its sample")
            if any(item.boot_id != self.boot_id for item in self.memory.kernel_logs):
                raise ValueError("kernel-log boot identity must match its sample")
        if len({fs.mountpoint for fs in self.filesystems}) != len(self.filesystems):
            raise ValueError("duplicate filesystem")
        return self
