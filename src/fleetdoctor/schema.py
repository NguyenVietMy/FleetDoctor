"""The versioned wire contract; missing observations are never zero-filled."""

import ipaddress
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
FD_UNITS = {
    "file_descriptors": "count",
    "fd_limit": "count",
    "fd_pressure": "ratio",
    "fd_growth": "descriptors_per_second",
    "fd_growth_interval": "seconds",
}
UNITS_V4 = {**UNITS_V3, **FD_UNITS}
NETWORK_UNITS = {
    "network_loss": "packets_and_ratio",
    "network_rtt": "milliseconds",
    "tcp_counters": "count",
    "tcp_retransmit_rate": "per_second",
    "tcp_states": "instantaneous_count",
    "interface_counters": "count",
    "interface_counter_rate": "per_second",
}
UNITS_V5 = {**UNITS_V4, **NETWORK_UNITS}
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


class FdProcessIdentity(WireModel):
    boot_id: UUID
    pid: Annotated[StrictInt, Field(ge=1, le=2**31 - 1)]
    starttime_ticks: Count

    @property
    def resource(self) -> str:
        return f"boot:{self.boot_id}/pid:{self.pid}/start:{self.starttime_ticks}"


class FdProcessObservation(WireModel):
    identity: FdProcessIdentity
    status: Literal["present", "exited", "replaced", "unknown"]
    watched: bool = False
    configured: bool = False
    comm: str | None = Field(default=None, min_length=1, max_length=128)
    descriptor_count: Count | None = None
    soft_limit: Count | None = None
    limit_unlimited: bool = False
    pressure_ratio: Ratio | None = None
    count_delta: Annotated[StrictInt, Field(ge=-4096, le=4096)] | None = None
    growth_per_second: Annotated[float, Field(allow_inf_nan=False)] | None = None
    growth_interval_seconds: Annotated[float, Field(gt=0, le=10, allow_inf_nan=False)] | None = None
    cpu_percent: Annotated[float, Field(ge=0, le=409600, allow_inf_nan=False)] | None = None
    rss_bytes: Count | None = None
    errors: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("errors")
    @classmethod
    def bounded_fd_errors(cls, errors: list[str]) -> list[str]:
        if any(not error or len(error) > 128 for error in errors):
            raise ValueError("FD collection error must contain 1..128 characters")
        return errors

    @model_validator(mode="after")
    def consistent_fd_process(self) -> Self:
        if self.limit_unlimited and self.soft_limit is not None:
            raise ValueError("unlimited FD limit cannot also be finite")
        if self.pressure_ratio is not None:
            if self.descriptor_count is None or self.soft_limit is None or self.soft_limit <= 0:
                raise ValueError("FD pressure requires count and a positive finite limit")
            if abs(self.pressure_ratio - self.descriptor_count / self.soft_limit) > 0.000001:
                raise ValueError("incorrect FD pressure ratio")
        growth = (self.count_delta, self.growth_per_second, self.growth_interval_seconds)
        if any(value is None for value in growth) and any(value is not None for value in growth):
            raise ValueError("FD count delta, growth, and interval must be present together")
        if (
            self.count_delta is not None
            and self.growth_per_second is not None
            and self.growth_interval_seconds is not None
            and abs(self.growth_per_second - self.count_delta / self.growth_interval_seconds)
            > 0.000001
        ):
            raise ValueError("incorrect FD growth rate")
        if self.status != "present" and any(
            value is not None
            for value in (
                self.comm,
                self.descriptor_count,
                self.soft_limit,
                self.pressure_ratio,
                self.count_delta,
                self.growth_per_second,
                self.growth_interval_seconds,
                self.cpu_percent,
                self.rss_bytes,
            )
        ):
            raise ValueError("non-present FD identity cannot carry process measurements")
        if self.status == "present":
            exact = self.descriptor_count is not None and (
                self.soft_limit is not None or self.limit_unlimited
            )
            if not exact and not self.errors:
                raise ValueError("unavailable present FD measurements require errors")
        elif not self.watched:
            raise ValueError("exit/replacement/unknown status is only valid for a watched identity")
        return self


class FdObservation(WireModel):
    observations: list[FdProcessObservation] = Field(default_factory=list, max_length=68)
    watch_coverage: Literal["available", "degraded", "unavailable"] = "unavailable"
    watch_revision: Count | None = None
    selected_identities: Annotated[StrictInt, Field(ge=0, le=36)] = 0
    configured_pids: Annotated[StrictInt, Field(ge=0, le=16)] = 0
    context_trimmed: bool = False
    errors: list[str] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def consistent_fd(self) -> Self:
        resources = [item.identity.resource for item in self.observations]
        if len(resources) != len(set(resources)):
            raise ValueError("duplicate FD process identity")
        if self.watch_coverage == "available" and self.watch_revision is None:
            raise ValueError("available FD watch coverage requires a revision")
        if self.watch_coverage != "available" and not self.errors:
            raise ValueError("degraded FD watch coverage requires an error")
        if any(not error or len(error) > 128 for error in self.errors):
            raise ValueError("FD block error must contain 1..128 characters")
        if len(self.model_dump_json().encode("utf-8")) > 24 * 1024:
            raise ValueError("FD observation exceeds 24KiB")
        return self


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


class NetworkProbeObservation(WireModel):
    status: Literal["available", "unavailable", "unconfigured"]
    target: str | None = Field(default=None, pattern=r"^(?:\d{1,3}\.){3}\d{1,3}$")
    sent: Annotated[StrictInt, Field(ge=0, le=3)] | None = None
    received: Annotated[StrictInt, Field(ge=0, le=3)] | None = None
    lost: Annotated[StrictInt, Field(ge=0, le=3)] | None = None
    loss_ratio: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None = None
    successful_sequences: list[Annotated[StrictInt, Field(ge=1, le=3)]] = Field(
        default_factory=list, max_length=3
    )
    successful_rtts_ms: list[Annotated[float, Field(ge=0, allow_inf_nan=False)]] = Field(
        default_factory=list, max_length=3
    )
    median_rtt_ms: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    route_status: Literal["available", "unavailable"] = "unavailable"
    interface: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.:@-]{1,64}$")
    interface_ifindex: Annotated[StrictInt, Field(ge=1, le=2**31 - 1)] | None = None
    route_error: str | None = Field(default=None, min_length=1, max_length=128)
    errors: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("target")
    @classmethod
    def canonical_target(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("network target must be canonical IPv4") from exc
        if (
            address.version != 4
            or str(address) != value
            or address.is_unspecified
            or address.is_multicast
            or address.is_reserved
            or value == "255.255.255.255"
        ):
            raise ValueError("network target must be usable canonical IPv4")
        return value

    @classmethod
    def unavailable(cls, target: str | None, error: str) -> "NetworkProbeObservation":
        return cls(status="unavailable", target=target, route_error=error, errors=[error])

    @model_validator(mode="after")
    def consistent_probe(self) -> Self:
        measured = (self.sent, self.received, self.lost, self.loss_ratio)
        if self.status == "available":
            if self.target is None or any(value is None for value in measured):
                raise ValueError("available network probe requires target and loss measurements")
            assert self.sent is not None and self.received is not None and self.lost is not None
            assert self.loss_ratio is not None
            if self.sent != 3 or self.lost != self.sent - self.received:
                raise ValueError("network probe packet counts disagree")
            if abs(self.loss_ratio - self.lost / self.sent) > 0.000001:
                raise ValueError("network probe loss ratio disagrees")
            if (
                len(self.successful_sequences) != self.received
                or len(self.successful_rtts_ms) != self.received
            ):
                raise ValueError("network probe replies disagree with received count")
            if len(set(self.successful_sequences)) != len(self.successful_sequences):
                raise ValueError("network probe reply sequence is duplicated")
            expected = None
            if self.successful_rtts_ms:
                ordered = sorted(self.successful_rtts_ms)
                middle = len(ordered) // 2
                expected = ordered[middle] if len(ordered) % 2 else sum(ordered[:2]) / 2
            if (expected is None) != (self.median_rtt_ms is None) or (
                expected is not None
                and self.median_rtt_ms is not None
                and abs(expected - self.median_rtt_ms) > 0.000001
            ):
                raise ValueError("network probe median must use successful replies")
        elif (
            any(value is not None for value in measured)
            or self.successful_sequences
            or self.successful_rtts_ms
            or self.median_rtt_ms is not None
        ):
            raise ValueError("unavailable probe cannot carry measured loss or RTT")
        if self.status == "unconfigured" and self.target is not None:
            raise ValueError("unconfigured probe cannot carry a target")
        if self.status != "available" and not self.errors:
            raise ValueError("unavailable network probe requires an error")
        if self.route_status == "available":
            if (
                self.interface is None
                or self.interface_ifindex is None
                or self.route_error is not None
            ):
                raise ValueError("available route attribution requires interface identity")
        elif (
            self.interface is not None
            or self.interface_ifindex is not None
            or self.route_error is None
        ):
            raise ValueError("unavailable route attribution requires only a reason")
        if any(not error or len(error) > 128 for error in self.errors):
            raise ValueError("network probe error must contain 1..128 characters")
        return self


class TcpNetworkObservation(WireModel):
    scope: Literal["host"] = "host"
    retrans_segs: Count | None = None
    retrans_per_second: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    rate_interval_seconds: Annotated[float, Field(gt=0, le=10, allow_inf_nan=False)] | None = None
    rate_status: Literal[
        "available",
        "baseline",
        "baseline_expired",
        "counter_reset",
        "identity_changed",
        "nonpositive_interval",
        "unavailable",
    ] = "unavailable"
    curr_estab: Count | None = None
    state_counts: dict[str, Count] = Field(default_factory=dict, max_length=11)
    state_inventory: Literal["complete", "partial", "unavailable"] = "unavailable"
    errors: list[str] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def consistent_tcp(self) -> Self:
        if self.rate_status == "available":
            if self.retrans_per_second is None or self.rate_interval_seconds is None:
                raise ValueError("available retransmit rate requires value and interval")
        elif self.retrans_per_second is not None or self.rate_interval_seconds is not None:
            raise ValueError("unavailable retransmit rate cannot carry a value")
        allowed = {
            "established",
            "syn_sent",
            "syn_recv",
            "fin_wait1",
            "fin_wait2",
            "time_wait",
            "close",
            "close_wait",
            "last_ack",
            "listen",
            "closing",
        }
        if set(self.state_counts) - allowed:
            raise ValueError("unsupported TCP state")
        if self.state_inventory == "unavailable" and self.state_counts:
            raise ValueError("unavailable TCP inventory cannot carry counts")
        if (self.retrans_segs is None or self.curr_estab is None) and not self.errors:
            raise ValueError("unavailable TCP counters require an error")
        return self


class InterfaceNetworkObservation(WireModel):
    name: str = Field(pattern=r"^[a-zA-Z0-9_.:@-]{1,64}$")
    ifindex: Annotated[StrictInt, Field(ge=1, le=2**31 - 1)]
    rx_errors: Count
    rx_dropped: Count
    tx_errors: Count
    tx_dropped: Count
    rx_errors_per_second: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    rx_dropped_per_second: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    tx_errors_per_second: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    tx_dropped_per_second: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    rate_interval_seconds: Annotated[float, Field(gt=0, le=10, allow_inf_nan=False)] | None = None
    rate_status: dict[
        str,
        Literal[
            "available",
            "baseline",
            "baseline_expired",
            "counter_reset",
            "identity_changed",
            "nonpositive_interval",
        ],
    ] = Field(default_factory=dict, min_length=4, max_length=4)

    @model_validator(mode="after")
    def consistent_interface(self) -> Self:
        rates = (
            self.rx_errors_per_second,
            self.rx_dropped_per_second,
            self.tx_errors_per_second,
            self.tx_dropped_per_second,
        )
        names = ("rx_errors", "rx_dropped", "tx_errors", "tx_dropped")
        if set(self.rate_status) != set(names):
            raise ValueError("interface rate status must cover every cumulative counter")
        for name, value in zip(names, rates, strict=True):
            if (self.rate_status[name] == "available") != (value is not None):
                raise ValueError("interface rate value and field status disagree")
        if any(value is not None for value in rates) != (self.rate_interval_seconds is not None):
            raise ValueError("interface rate interval must accompany available fields")
        return self


class NetworkObservation(WireModel):
    probe: NetworkProbeObservation
    tcp: TcpNetworkObservation
    interfaces: list[InterfaceNetworkObservation] = Field(default_factory=list, max_length=16)
    interface_coverage: Literal["complete", "partial", "unavailable"] = "unavailable"
    elapsed_seconds: Annotated[float, Field(ge=0, le=3, allow_inf_nan=False)] | None = None
    context_trimmed: bool = False
    errors: list[str] = Field(default_factory=list, max_length=8)

    @classmethod
    def unavailable(cls, target: str | None, error: str) -> "NetworkObservation":
        probe = NetworkProbeObservation.unavailable(target, error)
        return cls(
            probe=probe,
            tcp=TcpNetworkObservation(errors=[error]),
            interface_coverage="unavailable",
            errors=[error],
        )

    @model_validator(mode="after")
    def consistent_network(self) -> Self:
        if len({item.name for item in self.interfaces}) != len(self.interfaces):
            raise ValueError("duplicate network interface")
        if self.interface_coverage == "unavailable" and self.interfaces:
            raise ValueError("unavailable interface coverage cannot carry records")
        if any(not error or len(error) > 128 for error in self.errors):
            raise ValueError("network error must contain 1..128 characters")
        if len(self.model_dump_json().encode("utf-8")) > 8 * 1024:
            raise ValueError("network observation exceeds 8KiB")
        return self


class Sample(WireModel):
    schema_version: Literal[1, 2, 3, 4, 5]
    node_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    boot_id: UUID
    agent_session_id: UUID
    sequence: Count
    observed_at: datetime
    units: dict[str, str]
    filesystems: list[Filesystem] = Field(min_length=1, max_length=8)
    cpu: CpuObservation | None = Field(default=None, exclude_if=lambda value: value is None)
    memory: MemoryObservation | None = Field(default=None, exclude_if=lambda value: value is None)
    fd: FdObservation | None = Field(default=None, exclude_if=lambda value: value is None)
    network: NetworkObservation | None = Field(default=None, exclude_if=lambda value: value is None)
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
        if value not in (UNITS, UNITS_V2, UNITS_V3, UNITS_V4, UNITS_V5):
            raise ValueError("unsupported metric units")
        return value

    @model_validator(mode="after")
    def unique_paths(self) -> Self:
        if self.schema_version == 1 and (
            self.units != UNITS
            or self.cpu is not None
            or self.memory is not None
            or self.fd is not None
            or self.network is not None
        ):
            raise ValueError("schema v1 cannot contain CPU telemetry")
        if self.schema_version == 2 and (
            self.units != UNITS_V2
            or self.cpu is None
            or self.memory is not None
            or self.fd is not None
            or self.network is not None
        ):
            raise ValueError("schema v2 requires CPU telemetry and v2 units")
        if self.schema_version == 3 and (
            self.units != UNITS_V3
            or self.cpu is None
            or self.memory is None
            or self.fd is not None
            or self.network is not None
        ):
            raise ValueError("schema v3 requires CPU and memory telemetry and v3 units")
        if self.schema_version == 4 and (
            self.units != UNITS_V4
            or self.cpu is None
            or self.memory is None
            or self.fd is None
            or self.network is not None
        ):
            raise ValueError("schema v4 requires CPU, memory, FD telemetry and v4 units")
        if self.schema_version == 5 and (
            self.units != UNITS_V5
            or self.cpu is None
            or self.memory is None
            or self.fd is None
            or self.network is None
        ):
            raise ValueError(
                "schema v5 requires CPU, memory, FD and network telemetry and v5 units"
            )
        if self.fd is not None and any(
            item.identity.boot_id != self.boot_id
            for item in self.fd.observations
            if item.status == "present"
        ):
            raise ValueError("present FD identity must match its sample boot")
        if self.memory is not None:
            if any(item.boot_id != self.boot_id for item in self.memory.workloads):
                raise ValueError("workload boot identity must match its sample")
            if any(item.boot_id != self.boot_id for item in self.memory.kernel_logs):
                raise ValueError("kernel-log boot identity must match its sample")
        if len({fs.mountpoint for fs in self.filesystems}) != len(self.filesystems):
            raise ValueError("duplicate filesystem")
        return self
