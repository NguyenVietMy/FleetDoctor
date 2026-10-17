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


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    node_id: str
    resource: str
    rule: Literal["disk_block_exhaustion", "cpu_saturation"] = "disk_block_exhaustion"
    status: Literal["active", "resolved"] = "active"
    severity: Literal["info", "warning", "critical"] = "critical"
    diagnosis: str
    configuration: DiskConfig | CpuConfig
    opening_evidence: dict[str, JsonValue]
    latest_evidence: dict[str, JsonValue]
    opened_at: datetime
    observed_at: datetime
    evaluated_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    investigation_steps: list[str]

    @model_validator(mode="after")
    def rule_contract(self) -> Self:
        expected = DiskConfig if self.rule == "disk_block_exhaustion" else CpuConfig
        if not isinstance(self.configuration, expected):
            raise ValueError("incident rule and configuration disagree")
        availability = (
            "block_available" if self.rule == "disk_block_exhaustion" else "cpu_available"
        )
        if availability not in self.opening_evidence or availability not in self.latest_evidence:
            raise ValueError("incident evidence does not match rule")
        if self.rule == "cpu_saturation" and self.resource != "cpu":
            raise ValueError("CPU saturation resource must be cpu")
        if not self.investigation_steps or any(
            len(step) > 512 for step in self.investigation_steps
        ):
            raise ValueError("incident investigation steps must be bounded")
        return self

    def view(self, now: datetime, *, detail: bool, reloaded: bool = False) -> dict[str, Any]:
        result = self.model_dump(mode="json")
        age = (now - self.observed_at).total_seconds()
        result.update(
            evidence_age_seconds=max(0, age),
            evidence_stale=reloaded or age > 15 or age < -2,
            evidence_available=self.latest_evidence[
                "block_available" if self.rule == "disk_block_exhaustion" else "cpu_available"
            ],
            evidence_fresh=not reloaded and -2 <= age <= 10,
        )
        if not detail:
            for field in ("opening_evidence", "latest_evidence", "investigation_steps"):
                result.pop(field)
        return result
