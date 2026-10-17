"""The versioned wire contract; missing observations are never zero-filled."""

from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

Count = Annotated[StrictInt, Field(ge=0, le=2**64 - 1)]
Percent = Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)]
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


class Sample(WireModel):
    schema_version: Literal[1, 2]
    node_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    boot_id: UUID
    agent_session_id: UUID
    sequence: Count
    observed_at: datetime
    units: dict[str, str]
    filesystems: list[Filesystem] = Field(min_length=1, max_length=8)
    cpu: CpuObservation | None = Field(default=None, exclude_if=lambda value: value is None)
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
        if value not in (UNITS, UNITS_V2):
            raise ValueError("unsupported metric units")
        return value

    @model_validator(mode="after")
    def unique_paths(self) -> Self:
        if self.schema_version == 1 and (self.units != UNITS or self.cpu is not None):
            raise ValueError("schema v1 cannot contain CPU telemetry")
        if self.schema_version == 2 and (self.units != UNITS_V2 or self.cpu is None):
            raise ValueError("schema v2 requires CPU telemetry and v2 units")
        if len({fs.mountpoint for fs in self.filesystems}) != len(self.filesystems):
            raise ValueError("duplicate filesystem")
        return self
