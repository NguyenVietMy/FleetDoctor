"""Disk incident contract; opening evidence is never overwritten."""

from datetime import datetime
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    node_id: str
    resource: str
    rule: Literal["disk_block_exhaustion"] = "disk_block_exhaustion"
    status: Literal["active", "resolved"] = "active"
    severity: Literal["info", "warning", "critical"] = "critical"
    diagnosis: str
    configuration: DiskConfig
    opening_evidence: dict[str, Any]
    latest_evidence: dict[str, Any]
    opened_at: datetime
    observed_at: datetime
    evaluated_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    investigation_steps: list[str]

    def view(self, now: datetime, *, detail: bool, reloaded: bool = False) -> dict[str, Any]:
        result = self.model_dump(mode="json")
        age = (now - self.observed_at).total_seconds()
        result.update(
            evidence_age_seconds=max(0, age),
            evidence_stale=reloaded or age > 15 or age < -2,
            evidence_available=self.latest_evidence["block_available"],
            evidence_fresh=not reloaded and -2 <= age <= 10,
        )
        if not detail:
            for field in ("opening_evidence", "latest_evidence", "investigation_steps"):
                result.pop(field)
        return result
