"""Staged evaluator for the disk rule. Only eligible observations enter here."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from fleetdoctor.incidents import DiskConfig, Incident
from fleetdoctor.schema import Filesystem, Sample


def evidence(sample: Sample, fs: Filesystem) -> dict[str, Any]:
    return {
        "node_id": sample.node_id,
        "boot_id": str(sample.boot_id),
        "agent_session_id": str(sample.agent_session_id),
        "sequence": sample.sequence,
        "observed_at": sample.observed_at.isoformat(),
        "block_available": fs.block_usage_percent is not None,
        "filesystem": fs.model_dump(mode="json"),
        "coverage": {
            "block": "available" if fs.block_usage_percent is not None else "unavailable",
            "errors": fs.errors,
        },
    }


@dataclass
class Window:
    opening: int = 0
    recovery: int = 0
    configuration: DiskConfig | None = None


class DiskEvaluator:
    def __init__(self, active: list[Incident]) -> None:
        self.active = {(i.node_id, i.resource): i for i in active}
        self.windows: dict[tuple[str, str], Window] = {}
        self.reloaded = {i.id for i in active}

    def evaluate(
        self, sample: Sample, previous: Sample | None, now: datetime, config: DiskConfig
    ) -> list[Incident]:
        changes: list[Incident] = []
        for fs in sample.filesystems:
            key = sample.node_id, fs.mountpoint
            incident = self.active.get(key)
            measured_config = incident.configuration if incident else config
            reset = previous is None or (
                previous.boot_id != sample.boot_id
                or previous.agent_session_id != sample.agent_session_id
                or (sample.observed_at - previous.observed_at).total_seconds()
                > measured_config.max_gap_seconds
            )
            window = self.windows.setdefault(key, Window())
            if reset or window.configuration != measured_config:
                window.opening = window.recovery = 0
                window.configuration = measured_config
            usage = fs.block_usage_percent
            facts = evidence(sample, fs)
            if incident:
                window.opening = 0
                window.recovery = (
                    window.recovery + 1
                    if usage is not None and usage < measured_config.recovery_percent
                    else 0
                )
                incident = incident.model_copy(deep=True)
                incident.latest_evidence = facts
                incident.observed_at = sample.observed_at
                incident.evaluated_at = incident.updated_at = now
                if window.recovery >= measured_config.consecutive_samples:
                    incident.status = "resolved"
                    incident.resolved_at = now
                    self.active.pop(key)
                    window.recovery = 0
                else:
                    self.active[key] = incident
                self.reloaded.discard(incident.id)
                changes.append(incident)
            else:
                window.recovery = 0
                window.opening = (
                    window.opening + 1
                    if usage is not None and usage >= measured_config.trigger_percent
                    else 0
                )
                if window.opening >= measured_config.consecutive_samples:
                    incident = Incident(
                        id=uuid4(),
                        node_id=sample.node_id,
                        resource=fs.mountpoint,
                        severity=measured_config.severity,
                        diagnosis=f"Filesystem {fs.mountpoint} has exhausted workload block space",
                        configuration=measured_config,
                        opening_evidence=facts,
                        latest_evidence=facts,
                        opened_at=now,
                        observed_at=sample.observed_at,
                        evaluated_at=now,
                        updated_at=now,
                        investigation_steps=[
                            f"Check df -B1 -- {fs.mountpoint} and df -i -- {fs.mountpoint}",
                            "Verify the mount/device identity with findmnt before changing files",
                            "Inspect known workload directories with du; check deleted open files with lsof +L1",
                            "Remove only owned expendable data or expand capacity; confirm fresh usage below recovery threshold",
                            "Writer PID and file path are unavailable from statvfs telemetry",
                        ],
                    )
                    self.active[key] = incident
                    window.opening = 0
                    changes.append(incident)
        return changes
