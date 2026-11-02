"""Typed heterogeneous incident contract; opening evidence is immutable in practice."""

from datetime import datetime
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class DiskConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)
    trigger_percent: float = Field(default=95, gt=0, le=100)
    recovery_percent: float = Field(default=90, ge=0, lt=100)
    consecutive_samples: int = Field(default=3, ge=1, le=120, strict=True)
    max_gap_seconds: float = Field(default=10, gt=0, le=10)
    severity: Literal["info", "warning", "critical"] = "critical"

    @model_validator(mode="after")
    def hysteresis(self) -> Self:
        if self.recovery_percent >= self.trigger_percent:
            raise ValueError("recovery must be below trigger")
        return self


class InodeConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)
    trigger_percent: float = Field(default=95, gt=0, le=100)
    recovery_percent: float = Field(default=90, ge=0, lt=100)
    block_guard_percent: float = Field(default=95, gt=0, le=100)
    consecutive_samples: int = Field(default=3, ge=1, le=120, strict=True)
    max_gap_seconds: float = Field(default=10, gt=0, le=10)
    severity: Literal["info", "warning", "critical"] = "critical"

    @model_validator(mode="after")
    def hysteresis(self) -> Self:
        if self.recovery_percent >= self.trigger_percent:
            raise ValueError("inode recovery must be below trigger")
        return self


class CpuConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)
    trigger_busy_percent: float = Field(default=90, gt=0, le=100)
    recovery_busy_percent: float = Field(default=80, ge=0, lt=100)
    consecutive_samples: int = Field(default=3, ge=1, le=120, strict=True)
    max_gap_seconds: float = Field(default=10, gt=0, le=10)
    severity: Literal["info", "warning", "critical"] = "warning"

    @model_validator(mode="after")
    def hysteresis(self) -> Self:
        if self.recovery_busy_percent >= self.trigger_busy_percent:
            raise ValueError("CPU recovery must be below trigger")
        return self


class OomConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)
    recovery_percent: float = Field(default=80, ge=0, lt=100)
    consecutive_samples: int = Field(default=3, ge=1, le=120, strict=True)
    max_gap_seconds: float = Field(default=10, gt=0, le=10)
    severity: Literal["info", "warning", "critical"] = "critical"


class FdConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)
    trigger_percent: float = Field(default=90, gt=0, le=100)
    recovery_percent: float = Field(default=80, ge=0, lt=100)
    consecutive_samples: int = Field(default=3, ge=1, le=120, strict=True)
    max_gap_seconds: float = Field(default=10, gt=0, le=10)
    severity: Literal["info", "warning", "critical"] = "warning"

    @model_validator(mode="after")
    def hysteresis(self) -> Self:
        if self.recovery_percent >= self.trigger_percent:
            raise ValueError("FD recovery must be below trigger")
        return self


class NetworkConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)
    loss_trigger_packets: int = Field(default=1, ge=1, le=3, strict=True)
    rtt_trigger_ms: float = Field(default=200, gt=0, le=60_000)
    recovery_rtt_ms: float = Field(default=150, ge=0, le=60_000)
    consecutive_samples: int = Field(default=3, ge=1, le=120, strict=True)
    max_gap_seconds: float = Field(default=10, gt=0, le=10)
    severity: Literal["info", "warning", "critical"] = "warning"

    @model_validator(mode="after")
    def hysteresis(self) -> Self:
        if self.recovery_rtt_ms >= self.rtt_trigger_ms:
            raise ValueError("network RTT recovery must be below trigger")
        return self


class DnsConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)
    direct_ip_rtt_max_ms: float = Field(default=150, gt=0, le=60_000)
    consecutive_samples: int = Field(default=3, ge=1, le=120, strict=True)
    max_gap_seconds: float = Field(default=10, gt=0, le=10)
    severity: Literal["info", "warning", "critical"] = "warning"


class IoConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)
    trigger_latency_ms: float = Field(default=20, gt=0, le=60_000)
    trigger_outstanding: float = Field(default=1, ge=0, le=1_000_000)
    recovery_latency_ms: float = Field(default=10, ge=0, le=60_000)
    recovery_outstanding: float = Field(default=0.5, ge=0, le=1_000_000)
    consecutive_samples: int = Field(default=3, ge=1, le=120, strict=True)
    max_gap_seconds: float = Field(default=10, gt=0, le=10)
    severity: Literal["info", "warning", "critical"] = "warning"

    @model_validator(mode="after")
    def hysteresis(self) -> Self:
        if self.recovery_latency_ms >= self.trigger_latency_ms:
            raise ValueError("I/O latency recovery must be below trigger")
        if self.recovery_outstanding >= self.trigger_outstanding:
            raise ValueError("I/O backlog recovery must be below trigger")
        return self


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    node_id: str
    resource: str
    rule: Literal[
        "disk_block_exhaustion",
        "inode_exhaustion",
        "cpu_saturation",
        "workload_oom",
        "fd_pressure",
        "network_path_degradation",
        "dns_resolution_failure",
        "io_bottleneck",
    ] = "disk_block_exhaustion"
    status: Literal["active", "resolved", "superseded"] = "active"
    severity: Literal["info", "warning", "critical"] = "critical"
    diagnosis: str
    configuration: (
        DiskConfig
        | InodeConfig
        | CpuConfig
        | OomConfig
        | FdConfig
        | NetworkConfig
        | DnsConfig
        | IoConfig
    )
    opening_evidence: dict[str, JsonValue]
    latest_evidence: dict[str, JsonValue]
    opened_at: datetime
    observed_at: datetime
    evaluated_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    resolution_reason: Literal["descriptor_release", "confirmed_exit", "boot_replaced"] | None = (
        None
    )
    superseded_at: datetime | None = None
    supersession_reason: Literal["positive_resource_replacement"] | None = None
    replacement_resource_evidence: dict[str, JsonValue] | None = None
    investigation_steps: list[str]

    @model_validator(mode="before")
    @classmethod
    def deserialize_typed_configuration(cls, value: Any) -> Any:
        """Bind persisted JSON to the rule-specific config before union matching."""
        if not isinstance(value, dict) or not isinstance(value.get("configuration"), dict):
            return value
        rule = value.get("rule", "disk_block_exhaustion")
        configuration: (
            DiskConfig
            | InodeConfig
            | CpuConfig
            | OomConfig
            | FdConfig
            | NetworkConfig
            | DnsConfig
            | IoConfig
        )
        if rule == "disk_block_exhaustion":
            configuration = DiskConfig.model_validate(value["configuration"])
        elif rule == "inode_exhaustion":
            configuration = InodeConfig.model_validate(value["configuration"])
        elif rule == "cpu_saturation":
            configuration = CpuConfig.model_validate(value["configuration"])
        elif rule == "workload_oom":
            configuration = OomConfig.model_validate(value["configuration"])
        elif rule == "fd_pressure":
            configuration = FdConfig.model_validate(value["configuration"])
        elif rule == "network_path_degradation":
            configuration = NetworkConfig.model_validate(value["configuration"])
        elif rule == "dns_resolution_failure":
            configuration = DnsConfig.model_validate(value["configuration"])
        elif rule == "io_bottleneck":
            configuration = IoConfig.model_validate(value["configuration"])
        else:
            return value
        result = dict(value)
        result["configuration"] = configuration
        return result

    @model_validator(mode="after")
    def rule_contract(self) -> Self:
        expected = {
            "disk_block_exhaustion": DiskConfig,
            "inode_exhaustion": InodeConfig,
            "cpu_saturation": CpuConfig,
            "workload_oom": OomConfig,
            "fd_pressure": FdConfig,
            "network_path_degradation": NetworkConfig,
            "dns_resolution_failure": DnsConfig,
            "io_bottleneck": IoConfig,
        }[self.rule]
        if not isinstance(self.configuration, expected):
            raise ValueError("incident rule and configuration disagree")
        availability = {
            "disk_block_exhaustion": "block_available",
            "inode_exhaustion": "inode_available",
            "cpu_saturation": "cpu_available",
            "workload_oom": "memory_available",
            "fd_pressure": "fd_available",
            "network_path_degradation": "network_available",
            "dns_resolution_failure": "dns_available",
            "io_bottleneck": "io_available",
        }[self.rule]
        if availability not in self.opening_evidence or availability not in self.latest_evidence:
            raise ValueError("incident evidence does not match rule")
        if self.rule == "cpu_saturation" and self.resource != "cpu":
            raise ValueError("CPU saturation resource must be cpu")
        if self.rule == "workload_oom" and not self.resource.startswith("/"):
            raise ValueError("workload OOM resource must begin with its cgroup path")
        if self.rule == "fd_pressure":
            if not self.resource.startswith("boot:"):
                raise ValueError("FD pressure resource must include boot-scoped identity")
            if self.status == "resolved" and self.resolution_reason is None:
                raise ValueError("resolved FD incident requires a resolution reason")
            if self.status == "active" and self.resolution_reason is not None:
                raise ValueError("active FD incident cannot have a resolution reason")
        if self.rule == "network_path_degradation" and not self.resource.startswith("ipv4:"):
            raise ValueError("network path resource must be a configured IPv4 target")
        if self.rule == "dns_resolution_failure" and not self.resource.startswith("dns:"):
            raise ValueError(
                "DNS resource must include the configured hostname and direct-IP target"
            )
        if self.rule == "io_bottleneck" and not self.resource.startswith("io:"):
            raise ValueError("I/O bottleneck resource must use its durable device fingerprint")
        if self.status == "superseded":
            if (
                self.rule != "io_bottleneck"
                or self.superseded_at is None
                or self.supersession_reason != "positive_resource_replacement"
                or self.replacement_resource_evidence is None
                or self.resolved_at is not None
            ):
                raise ValueError("superseded I/O incident requires explicit replacement evidence")
        elif any(
            value is not None
            for value in (
                self.superseded_at,
                self.supersession_reason,
                self.replacement_resource_evidence,
            )
        ):
            raise ValueError("only superseded incidents carry supersession metadata")
        if not self.investigation_steps or any(
            len(step) > 512 for step in self.investigation_steps
        ):
            raise ValueError("incident investigation steps must be bounded")
        return self

    def view(self, now: datetime, *, detail: bool, reloaded: bool = False) -> dict[str, Any]:
        result = self.model_dump(mode="json")
        age = (now - self.observed_at).total_seconds()
        availability = {
            "disk_block_exhaustion": "block_available",
            "inode_exhaustion": "inode_available",
            "cpu_saturation": "cpu_available",
            "workload_oom": "memory_available",
            "fd_pressure": "fd_available",
            "network_path_degradation": "network_available",
            "dns_resolution_failure": "dns_available",
            "io_bottleneck": "io_available",
        }[self.rule]
        result.update(
            evidence_age_seconds=max(0, age),
            evidence_stale=reloaded or age > 15 or age < -2,
            evidence_available=self.latest_evidence[availability],
            evidence_fresh=not reloaded and -2 <= age <= 10,
        )
        if not detail:
            for field in ("opening_evidence", "latest_evidence", "investigation_steps"):
                result.pop(field)
        return result
