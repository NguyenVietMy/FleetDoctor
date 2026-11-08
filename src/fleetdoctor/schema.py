"""The versioned wire contract; missing observations are never zero-filled."""

import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime
from typing import Annotated, Any, Literal, Self
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
DNS_UNITS = {
    "dns_query_duration": "seconds",
    "dns_answer_count": "count",
    "dns_baseline_age": "seconds",
}
UNITS_V6 = {**UNITS_V5, **DNS_UNITS}
IO_UNITS = {
    "io_latency": "milliseconds",
    "io_average_outstanding": "requests",
    "io_counters": "count_and_milliseconds",
    "io_throughput": "bytes_per_second",
    "io_completion_rate": "completions_per_second",
    "io_pressure_average": "percent",
    "io_pressure_total": "microseconds",
    "io_interval": "seconds",
    "io_sectors": "512_bytes",
}
UNITS_V7 = {**UNITS_V6, **IO_UNITS}
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


def _canonical_dns_hostname(value: str) -> str:
    if value != value.lower() or not value.endswith("."):
        raise ValueError("DNS hostname must be lowercase and absolute")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("DNS hostname must be ASCII") from exc
    labels = value[:-1].split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise ValueError("DNS hostname contains an invalid label")
    if len(encoded) > 254 or sum(len(label) + 1 for label in labels) + 1 > 255:
        raise ValueError("DNS hostname exceeds wire length")
    return value


def _canonical_usable_ipv4(value: str) -> str:
    address = ipaddress.ip_address(value)
    if (
        address.version != 4
        or str(address) != value
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
        or value == "255.255.255.255"
    ):
        raise ValueError("target must be usable canonical IPv4")
    return value


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
    workloads: list[WorkloadMemoryObservation] = Field(default_factory=list, max_length=8)
    kernel_logs: list[KernelOomLog] = Field(default_factory=list, max_length=16)
    kernel_log_coverage: Literal[
        "baseline", "available", "permission_denied", "cursor_lost", "unavailable"
    ] = "unavailable"
    kernel_log_errors: list[str] = Field(default_factory=list, max_length=8)
    workload_errors: dict[str, list[str]] = Field(default_factory=dict, max_length=8)

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


class ResolverSnapshot(WireModel):
    status: Literal["available", "unavailable", "unconfigured"]
    nameservers: list[str] = Field(default_factory=list, max_length=3)
    fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    entry_type: Literal["regular", "symlink"] | None = None
    link_target: str | None = Field(default=None, min_length=1, max_length=4096)
    known_systemd_stub: bool = False
    errors: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("nameservers")
    @classmethod
    def canonical_nameservers(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("duplicate resolver nameserver")
        for value in values:
            address = ipaddress.ip_address(value)
            if str(address) != value:
                raise ValueError("resolver nameserver must be canonical numeric IP")
        return values

    @model_validator(mode="after")
    def consistent_resolver(self) -> Self:
        if self.status == "available":
            if not self.nameservers or self.fingerprint is None or self.entry_type is None:
                raise ValueError("available resolver requires nameservers and identity")
            if self.entry_type == "symlink" and self.link_target is None:
                raise ValueError("symlink resolver requires link target")
            if self.entry_type == "regular" and self.link_target is not None:
                raise ValueError("regular resolver cannot carry link target")
        elif self.nameservers or self.fingerprint is not None or self.entry_type is not None:
            raise ValueError("unavailable resolver cannot carry trusted configuration")
        if self.status != "available" and not self.errors:
            raise ValueError("unavailable resolver requires an error")
        if any(not error or len(error) > 128 for error in self.errors):
            raise ValueError("resolver error must contain 1..128 characters")
        return self


class DnsQueryObservation(WireModel):
    status: Literal["success", "failure", "unavailable", "unconfigured"]
    hostname: str | None = Field(default=None, min_length=3, max_length=254)
    qtype: Literal["A"] = "A"
    answers: list[str] = Field(default_factory=list, max_length=8)
    duration_seconds: Annotated[float, Field(ge=0, le=3, allow_inf_nan=False)] | None = None
    selected_server: str | None = None
    error: str | None = Field(default=None, min_length=1, max_length=128)
    adapter: Literal["dnspython", "systemd-resolved", "none"] = "none"

    @field_validator("hostname")
    @classmethod
    def canonical_query_hostname(cls, value: str | None) -> str | None:
        return _canonical_dns_hostname(value) if value is not None else None

    @field_validator("answers")
    @classmethod
    def canonical_answers(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("duplicate DNS answer")
        for value in values:
            address = ipaddress.ip_address(value)
            if address.version != 4 or str(address) != value:
                raise ValueError("DNS A answer must be canonical IPv4")
        return values

    @field_validator("selected_server")
    @classmethod
    def canonical_server(cls, value: str | None) -> str | None:
        if value is not None and str(ipaddress.ip_address(value)) != value:
            raise ValueError("selected resolver server must be canonical numeric IP")
        return value

    @model_validator(mode="after")
    def consistent_query(self) -> Self:
        measured = self.status in ("success", "failure")
        if measured and (self.hostname is None or self.duration_seconds is None):
            raise ValueError("measured DNS query requires hostname and duration")
        if measured and self.adapter == "none":
            raise ValueError("measured DNS query requires a supported adapter")
        if self.status == "success" and (not self.answers or self.error is not None):
            raise ValueError("successful DNS query requires answers and no error")
        if self.status in ("failure", "unavailable") and self.error is None:
            raise ValueError("failed or unavailable DNS query requires an error")
        if self.status != "success" and self.answers:
            raise ValueError("non-successful DNS query cannot carry answers")
        if self.status == "unconfigured" and self.hostname is not None:
            raise ValueError("unconfigured DNS query cannot carry a hostname")
        if self.status == "unconfigured" and self.error is None:
            raise ValueError("unconfigured DNS query requires an explanation")
        return self


class DnsBaselineObservation(WireModel):
    node_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    boot_id: UUID
    agent_session_id: UUID
    sequence: Count
    observed_at: datetime
    hostname: str = Field(min_length=3, max_length=254)
    direct_ip_target: str = Field(pattern=r"^(?:\d{1,3}\.){3}\d{1,3}$")
    query: DnsQueryObservation
    direct_ip_probe: NetworkProbeObservation
    resolver_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    resolver_nameservers: list[str] = Field(min_length=1, max_length=3)

    @field_validator("hostname")
    @classmethod
    def canonical_baseline_hostname(cls, value: str) -> str:
        return _canonical_dns_hostname(value)

    @field_validator("direct_ip_target")
    @classmethod
    def canonical_baseline_target(cls, value: str) -> str:
        return _canonical_usable_ipv4(value)

    @field_validator("resolver_nameservers")
    @classmethod
    def canonical_baseline_nameservers(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("duplicate baseline resolver nameserver")
        for value in values:
            if str(ipaddress.ip_address(value)) != value:
                raise ValueError("baseline nameserver must be canonical numeric IP")
        return values

    @field_validator("observed_at")
    @classmethod
    def aware_baseline_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("DNS baseline time must include timezone")
        return value

    @model_validator(mode="after")
    def consistent_baseline(self) -> Self:
        if self.query.status != "success" or self.query.hostname != self.hostname:
            raise ValueError("DNS baseline requires matching successful query")
        probe = self.direct_ip_probe
        if (
            probe.status != "available"
            or probe.target != self.direct_ip_target
            or probe.sent != 3
            or probe.received != 3
            or probe.lost != 0
            or probe.median_rtt_ms is None
        ):
            raise ValueError("DNS baseline requires exact successful three-packet IP probe")
        if len(self.model_dump_json().encode("utf-8")) > 3072:
            raise ValueError("DNS baseline exceeds 3072 bytes")
        return self


class DnsObservation(WireModel):
    hostname: str | None = Field(default=None, min_length=3, max_length=254)
    direct_ip_target: str | None = Field(default=None, pattern=r"^(?:\d{1,3}\.){3}\d{1,3}$")
    resolver: ResolverSnapshot
    query: DnsQueryObservation
    baseline: DnsBaselineObservation | None = None
    retention_coverage: Literal["complete", "incomplete", "unavailable"] = "unavailable"
    candidate_error: str | None = Field(default=None, min_length=1, max_length=128)
    context_trimmed: bool = False
    elapsed_seconds: Annotated[float, Field(ge=0, le=3, allow_inf_nan=False)] | None = None

    @field_validator("hostname")
    @classmethod
    def canonical_observation_hostname(cls, value: str | None) -> str | None:
        return _canonical_dns_hostname(value) if value is not None else None

    @field_validator("direct_ip_target")
    @classmethod
    def canonical_observation_target(cls, value: str | None) -> str | None:
        return _canonical_usable_ipv4(value) if value is not None else None

    @classmethod
    def unavailable(
        cls, hostname: str | None, direct_ip_target: str | None, error: str
    ) -> "DnsObservation":
        status: Literal["unavailable", "unconfigured"] = (
            "unconfigured" if hostname is None else "unavailable"
        )
        if hostname is None:
            direct_ip_target = None
        return cls(
            hostname=hostname,
            direct_ip_target=direct_ip_target,
            resolver=ResolverSnapshot(status=status, errors=[error]),
            query=DnsQueryObservation(status=status, hostname=hostname, error=error),
            retention_coverage="unavailable",
        )

    @model_validator(mode="after")
    def consistent_dns(self) -> Self:
        if self.hostname != self.query.hostname:
            raise ValueError("DNS observation hostname and query disagree")
        if self.query.status in ("success", "failure") and self.resolver.status != "available":
            raise ValueError("measured DNS query requires available resolver configuration")
        if (self.hostname is None) != (self.direct_ip_target is None):
            raise ValueError("DNS hostname and direct-IP target must be configured together")
        if self.baseline is not None and (
            self.baseline.hostname != self.hostname
            or self.baseline.direct_ip_target != self.direct_ip_target
        ):
            raise ValueError("DNS baseline scope mismatch")
        if self.context_trimmed and "payload_budget" not in self.resolver.errors:
            raise ValueError("trimmed DNS context requires visible payload-budget coverage")
        if len(self.model_dump_json().encode("utf-8")) > 8192:
            raise ValueError("DNS observation exceeds 8KiB")
        return self


class IoCounters(WireModel):
    reads_completed: Count
    sectors_read: Count
    read_ms: Count
    writes_completed: Count
    sectors_written: Count
    write_ms: Count
    inflight: Count
    io_ms: Count
    weighted_io_ms: Count
    discards_completed: Count | None = None
    discard_sectors: Count | None = None
    discard_ms: Count | None = None
    flushes_completed: Count | None = None
    flush_ms: Count | None = None

    @model_validator(mode="after")
    def optional_groups(self) -> Self:
        discard = (self.discards_completed, self.discard_sectors, self.discard_ms)
        flush = (self.flushes_completed, self.flush_ms)
        if any(value is not None for value in discard) and any(value is None for value in discard):
            raise ValueError("discard counters must be complete or unavailable")
        if any(value is not None for value in flush) and any(value is None for value in flush):
            raise ValueError("flush counters must be complete or unavailable")
        return self


class IoDeviceObservation(WireModel):
    resource: str = Field(pattern=r"^io:[0-9a-f]{32}$")
    status: Literal["available", "unavailable"]
    rate_status: Literal["available", "baseline", "reset", "unavailable"]
    major_minor: str = Field(pattern=r"^[0-9]+:[0-9]+$", max_length=32)
    device_name: str | None = Field(default=None, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    sysfs_path: str = Field(min_length=1, max_length=512)
    diskseq: str | None = Field(default=None, max_length=64, pattern=r"^[0-9]+$")
    dm_uuid: str | None = Field(default=None, max_length=256)
    filesystem_id: int = Field(ge=0, le=2**64 - 1)
    scopes: list[str] = Field(min_length=1, max_length=4)
    mount_ids: dict[str, int] = Field(max_length=4)
    mount_namespace: str = Field(min_length=1, max_length=128)
    counters: IoCounters | None = None
    counters_before: IoCounters | None = None
    elapsed_seconds: float | None = Field(default=None, gt=0, le=10)
    completion_count: Count | None = None
    completion_latency_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    average_outstanding: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    read_bytes_per_second: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    write_bytes_per_second: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    completions_per_second: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    confirmed_idle: bool = False
    errors: list[str] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def consistent_device(self) -> Self:
        if self.scopes != sorted(set(self.scopes)) or set(self.mount_ids) != set(self.scopes):
            raise ValueError("I/O scopes and mount IDs must be complete, unique and sorted")
        if not self.diskseq and not self.dm_uuid:
            raise ValueError("I/O device requires a stable binding")
        fingerprint_material = {
            "major_minor": self.major_minor,
            "sysfs_path": self.sysfs_path,
            "diskseq": self.diskseq,
            "dm_uuid": self.dm_uuid,
            "filesystem_id": self.filesystem_id,
        }
        expected_resource = (
            "io:"
            + hashlib.sha256(
                json.dumps(fingerprint_material, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()[:32]
        )
        if self.resource != expected_resource:
            raise ValueError("I/O durable resource fingerprint does not match its bindings")
        derived = (
            self.elapsed_seconds,
            self.counters_before,
            self.completion_count,
            self.average_outstanding,
            self.read_bytes_per_second,
            self.write_bytes_per_second,
            self.completions_per_second,
        )
        if self.status == "unavailable":
            if (
                self.rate_status != "unavailable"
                or self.counters is not None
                or any(value is not None for value in derived)
                or self.completion_latency_ms is not None
                or not self.errors
            ):
                raise ValueError("unavailable I/O device cannot carry measured counters")
        else:
            if self.counters is None:
                raise ValueError("available I/O device requires counters")
            if self.rate_status == "available":
                if any(value is None for value in derived):
                    raise ValueError("available I/O rate requires a complete interval")
                if (self.completion_count == 0) != (self.completion_latency_ms is None):
                    raise ValueError("I/O latency must be null exactly when completions are zero")
                assert self.counters_before is not None
                assert self.elapsed_seconds is not None
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
                deltas: dict[str, int] = {}
                for name in names:
                    before = getattr(self.counters_before, name)
                    after = getattr(self.counters, name)
                    if after < before:
                        raise ValueError("I/O interval crosses a counter reset")
                    deltas[name] = after - before
                completions = deltas["reads_completed"] + deltas["writes_completed"]
                expected_latency = (
                    (deltas["read_ms"] + deltas["write_ms"]) / completions if completions else None
                )
                expected = {
                    "completion_count": completions,
                    "completion_latency_ms": expected_latency,
                    "average_outstanding": deltas["weighted_io_ms"] / (1000 * self.elapsed_seconds),
                    "read_bytes_per_second": deltas["sectors_read"] * 512 / self.elapsed_seconds,
                    "write_bytes_per_second": deltas["sectors_written"]
                    * 512
                    / self.elapsed_seconds,
                    "completions_per_second": completions / self.elapsed_seconds,
                }
                for name, expected_value in expected.items():
                    actual = getattr(self, name)
                    if isinstance(expected_value, float):
                        if actual is None or not math.isclose(
                            actual, expected_value, rel_tol=1e-9, abs_tol=1e-9
                        ):
                            raise ValueError(f"I/O derived arithmetic mismatch: {name}")
                    elif actual != expected_value:
                        raise ValueError(f"I/O derived arithmetic mismatch: {name}")
                optional_names = (
                    "discards_completed",
                    "discard_sectors",
                    "discard_ms",
                    "flushes_completed",
                    "flush_ms",
                )
                optional_deltas: list[int] = []
                optional_complete = True
                for name in optional_names:
                    before = getattr(self.counters_before, name)
                    after = getattr(self.counters, name)
                    if before is None or after is None:
                        optional_complete = False
                        continue
                    if after < before:
                        raise ValueError("I/O optional counter reset")
                    optional_deltas.append(after - before)
                expected_idle = bool(
                    completions == 0
                    and deltas["sectors_read"] == 0
                    and deltas["sectors_written"] == 0
                    and deltas["read_ms"] == 0
                    and deltas["write_ms"] == 0
                    and deltas["io_ms"] == 0
                    and deltas["weighted_io_ms"] == 0
                    and self.counters_before.inflight == 0
                    and self.counters.inflight == 0
                    and optional_complete
                    and len(optional_deltas) == len(optional_names)
                    and all(value == 0 for value in optional_deltas)
                )
                if self.confirmed_idle != expected_idle:
                    raise ValueError("confirmed idle does not match raw endpoint activity")
            elif (
                any(value is not None for value in derived)
                or self.completion_latency_ms is not None
            ):
                raise ValueError("non-rate I/O observation cannot carry interval metrics")
        if self.confirmed_idle and (
            self.rate_status != "available"
            or self.completion_count != 0
            or self.completion_latency_ms is not None
            or self.counters is None
            or self.counters.inflight != 0
        ):
            raise ValueError("confirmed idle requires a valid zero-completion interval")
        if any(len(error) > 256 for error in self.errors):
            raise ValueError("I/O collection error exceeds 256 characters")
        return self


class IoProcessObservation(WireModel):
    pid: int = Field(ge=1, le=2**31 - 1, strict=True)
    starttime: Count | None = None
    status: Literal["available", "unavailable"]
    rate_status: Literal["available", "baseline", "reset", "gap", "unavailable"]
    physical_read_bytes: Count | None = None
    physical_write_bytes: Count | None = None
    physical_read_bytes_per_second: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    physical_write_bytes_per_second: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    logical_read_characters: Count | None = None
    logical_write_characters: Count | None = None
    cancelled_write_bytes: Count | None = None
    net_write_balance_bytes: int | None = Field(
        default=None, ge=-(2**64 - 1), le=2**64 - 1, strict=True
    )
    errors: list[str] = Field(default_factory=list, max_length=4)

    @model_validator(mode="after")
    def consistent_process_io(self) -> Self:
        counters = (
            self.physical_read_bytes,
            self.physical_write_bytes,
            self.logical_read_characters,
            self.logical_write_characters,
            self.cancelled_write_bytes,
            self.net_write_balance_bytes,
        )
        rates = (self.physical_read_bytes_per_second, self.physical_write_bytes_per_second)
        if self.status == "available":
            if self.starttime is None or any(value is None for value in counters):
                raise ValueError("available process I/O requires identity and distinct counters")
            assert self.physical_write_bytes is not None
            assert self.cancelled_write_bytes is not None
            if self.net_write_balance_bytes != (
                self.physical_write_bytes - self.cancelled_write_bytes
            ):
                raise ValueError("net write balance does not match raw counters")
            if (self.rate_status == "available") != all(value is not None for value in rates):
                raise ValueError("process I/O rate status and values disagree")
        elif (
            any(value is not None for value in counters + rates)
            or self.starttime is not None
            or not self.errors
        ):
            raise ValueError("unavailable process I/O requires only errors")
        return self


class IoPressureObservation(WireModel):
    scope: str = Field(min_length=1, max_length=256)
    status: Literal["available", "unavailable"]
    some: dict[str, float | int] | None = Field(default=None, max_length=4)
    full: dict[str, float | int] | None = Field(default=None, max_length=4)
    errors: list[str] = Field(default_factory=list, max_length=4)

    @field_validator("scope")
    @classmethod
    def pressure_scope_is_registered_label(cls, value: str) -> str:
        if value == "host":
            return value
        if (
            value == "/"
            or not re.fullmatch(r"/[a-zA-Z0-9_.@/-]+", value)
            or "//" in value
            or any(part in ("", ".", "..") for part in value.split("/")[1:])
        ):
            raise ValueError("I/O pressure scope must be host or a canonical cgroup path")
        return value

    @model_validator(mode="before")
    @classmethod
    def bounded_raw_pressure_values(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        for name in ("some", "full"):
            row = data.get(name)
            if row is None or not isinstance(row, dict):
                continue
            if set(row) != {"avg10", "avg60", "avg300", "total"}:
                raise ValueError("I/O pressure fields are incomplete")
            total = row["total"]
            if type(total) is not int or not 0 <= total <= 2**64 - 1:
                raise ValueError("I/O pressure total must be unsigned64 microseconds")
            for average_name in ("avg10", "avg60", "avg300"):
                average = row[average_name]
                if type(average) not in (int, float):
                    raise ValueError("I/O pressure averages must be finite numbers")
                if isinstance(average, float) and not math.isfinite(average):
                    raise ValueError("I/O pressure averages must be finite numbers")
                if not 0 <= average <= 100:
                    raise ValueError("I/O pressure averages are percentages")
        return data

    @model_validator(mode="after")
    def consistent_pressure(self) -> Self:
        for row in (self.some, self.full):
            if row is not None:
                if set(row) != {"avg10", "avg60", "avg300", "total"}:
                    raise ValueError("I/O pressure fields are incomplete")
                if any(row[name] < 0 or row[name] > 100 for name in ("avg10", "avg60", "avg300")):
                    raise ValueError("I/O pressure averages are percentages")
        if self.status == "available" and (self.some is None or self.full is None):
            raise ValueError("available I/O pressure requires some and full")
        if self.status == "unavailable" and (
            self.some is not None or self.full is not None or not self.errors
        ):
            raise ValueError("unavailable I/O pressure requires only errors")
        return self


class IoObservation(WireModel):
    status: Literal["available", "partial", "unavailable", "disabled"]
    inventory_complete: bool
    configured_scopes: list[str] = Field(default_factory=list, max_length=4)
    devices: list[IoDeviceObservation] = Field(default_factory=list, max_length=4)
    processes: list[IoProcessObservation] = Field(default_factory=list, max_length=16)
    process_coverage: Literal["complete", "compacted", "unavailable"] = "unavailable"
    registered_pressure_scopes: list[str] = Field(default_factory=list, max_length=9)
    pressure: list[IoPressureObservation] = Field(default_factory=list, max_length=9)
    pressure_coverage: Literal["complete", "compacted", "unavailable"] = "unavailable"
    context_trimmed: bool = False
    mapping_errors: dict[str, str] = Field(default_factory=dict, max_length=4)
    errors: list[str] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def consistent_io(self) -> Self:
        if self.configured_scopes != sorted(set(self.configured_scopes)):
            raise ValueError("configured I/O scopes must be unique and sorted")
        if len({item.resource for item in self.devices}) != len(self.devices):
            raise ValueError("duplicate I/O durable resource")
        if len({item.pid for item in self.processes}) != len(self.processes):
            raise ValueError("duplicate I/O process")
        if len({item.scope for item in self.pressure}) != len(self.pressure):
            raise ValueError("duplicate I/O pressure scope")
        if len(set(self.registered_pressure_scopes)) != len(self.registered_pressure_scopes):
            raise ValueError("duplicate registered I/O pressure scope")
        expected_pressure_scopes = ["host", *sorted(self.registered_pressure_scopes[1:])]
        if self.registered_pressure_scopes and (
            self.registered_pressure_scopes[0] != "host"
            or self.registered_pressure_scopes != expected_pressure_scopes
        ):
            raise ValueError("registered I/O pressure scopes must be host then sorted cgroups")
        if self.pressure_coverage == "complete" and {item.scope for item in self.pressure} != set(
            self.registered_pressure_scopes
        ):
            raise ValueError("I/O pressure coverage must match every registered scope")
        if self.pressure_coverage != "complete" and self.pressure:
            raise ValueError("non-complete I/O pressure coverage cannot carry records")
        if self.context_trimmed != (
            self.process_coverage == "compacted" or self.pressure_coverage == "compacted"
        ):
            raise ValueError("I/O context-trimmed flag and coverage disagree")
        if self.context_trimmed and "payload_budget" not in self.errors:
            raise ValueError("compacted I/O context requires payload budget evidence")
        if set(self.mapping_errors) - set(self.configured_scopes):
            raise ValueError("I/O mapping error outside configured scope")
        if self.status == "disabled" and (
            self.configured_scopes or self.devices or self.mapping_errors
        ):
            raise ValueError("disabled I/O collection cannot report configured mappings")
        if self.status == "available" and (not self.inventory_complete or self.mapping_errors):
            raise ValueError("available I/O collection requires complete mapping inventory")
        if self.status == "unavailable" and self.inventory_complete:
            raise ValueError("unavailable I/O collection cannot claim complete inventory")
        scope_owners: dict[str, str] = {}
        for device in self.devices:
            for scope in device.scopes:
                if scope in scope_owners:
                    raise ValueError("configured I/O scope appears on multiple resources")
                scope_owners[scope] = device.resource
        covered = set(scope_owners) | set(self.mapping_errors)
        if covered - set(self.configured_scopes):
            raise ValueError("I/O inventory reports an unconfigured scope")
        if self.inventory_complete and (
            self.mapping_errors or set(scope_owners) != set(self.configured_scopes)
        ):
            raise ValueError(
                "complete I/O inventory must cover every configured scope exactly once"
            )
        if len(self.model_dump_json().encode()) > 32768:
            raise ValueError("I/O observation exceeds 32KiB")
        return self


class Sample(WireModel):
    schema_version: Literal[1, 2, 3, 4, 5, 6, 7]
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
    dns: DnsObservation | None = Field(default=None, exclude_if=lambda value: value is None)
    io: IoObservation | None = Field(default=None, exclude_if=lambda value: value is None)
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
        if value not in (UNITS, UNITS_V2, UNITS_V3, UNITS_V4, UNITS_V5, UNITS_V6, UNITS_V7):
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
            or self.dns is not None
            or self.io is not None
        ):
            raise ValueError("schema v1 cannot contain CPU telemetry")
        if self.schema_version == 2 and (
            self.units != UNITS_V2
            or self.cpu is None
            or self.memory is not None
            or self.fd is not None
            or self.network is not None
            or self.dns is not None
            or self.io is not None
        ):
            raise ValueError("schema v2 requires CPU telemetry and v2 units")
        if self.schema_version == 3 and (
            self.units != UNITS_V3
            or self.cpu is None
            or self.memory is None
            or self.fd is not None
            or self.network is not None
            or self.dns is not None
            or self.io is not None
        ):
            raise ValueError("schema v3 requires CPU and memory telemetry and v3 units")
        if self.schema_version == 4 and (
            self.units != UNITS_V4
            or self.cpu is None
            or self.memory is None
            or self.fd is None
            or self.network is not None
            or self.dns is not None
            or self.io is not None
        ):
            raise ValueError("schema v4 requires CPU, memory, FD telemetry and v4 units")
        if self.schema_version == 5 and (
            self.units != UNITS_V5
            or self.cpu is None
            or self.memory is None
            or self.fd is None
            or self.network is None
            or self.dns is not None
            or self.io is not None
        ):
            raise ValueError(
                "schema v5 requires CPU, memory, FD and network telemetry and v5 units"
            )
        if self.schema_version == 6 and (
            self.units != UNITS_V6
            or self.cpu is None
            or self.memory is None
            or self.fd is None
            or self.network is None
            or self.dns is None
        ):
            raise ValueError(
                "schema v6 requires CPU, memory, FD, network and DNS telemetry and v6 units"
            )
        if self.schema_version == 6 and self.io is not None:
            raise ValueError("schema v6 cannot contain I/O telemetry")
        if self.schema_version == 7 and (
            self.units != UNITS_V7
            or self.cpu is None
            or self.memory is None
            or self.fd is None
            or self.network is None
            or self.dns is None
            or self.io is None
        ):
            raise ValueError(
                "schema v7 requires CPU, memory, FD, network, DNS and I/O telemetry and v7 units"
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
