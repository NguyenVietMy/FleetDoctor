"""Staged heterogeneous evaluators. Only eligible observations enter here."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from fleetdoctor.incidents import CpuConfig, DiskConfig, Incident
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
    configuration: DiskConfig | CpuConfig | None = None


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
            assert isinstance(measured_config, DiskConfig)
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


def cpu_evidence(sample: Sample) -> dict[str, Any]:
    cpu = sample.cpu
    available = bool(
        cpu is not None
        and cpu.busy_percent is not None
        and cpu.runnable_processes is not None
        and cpu.logical_cores is not None
    )
    return {
        "node_id": sample.node_id,
        "boot_id": str(sample.boot_id),
        "agent_session_id": str(sample.agent_session_id),
        "sequence": sample.sequence,
        "observed_at": sample.observed_at.isoformat(),
        "cpu_available": available,
        "cpu": cpu.model_dump(mode="json") if cpu is not None else None,
        "coverage": {
            "host_rates": "available"
            if cpu is not None and cpu.busy_percent is not None
            else "unavailable",
            "runnable": "available"
            if cpu is not None and cpu.runnable_processes is not None
            else "unavailable",
            "logical_cores": "available"
            if cpu is not None and cpu.logical_cores is not None
            else "unavailable",
            "process_inventory": cpu.process_inventory if cpu is not None else "unavailable",
            "errors": cpu.errors if cpu is not None else ["cpu_observation_unavailable"],
        },
    }


class CpuEvaluator:
    def __init__(self, active: list[Incident]) -> None:
        self.active = {(incident.node_id, incident.resource): incident for incident in active}
        self.windows: dict[tuple[str, str], Window] = {}
        self.reloaded = {incident.id for incident in active}

    def evaluate(
        self, sample: Sample, previous: Sample | None, now: datetime, config: CpuConfig
    ) -> list[Incident]:
        key = sample.node_id, "cpu"
        incident = self.active.get(key)
        measured_config = incident.configuration if incident else config
        assert isinstance(measured_config, CpuConfig)
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
        cpu = sample.cpu
        busy = cpu.busy_percent if cpu is not None else None
        runnable = cpu.runnable_processes if cpu is not None else None
        cores = cpu.logical_cores if cpu is not None else None
        facts = cpu_evidence(sample)
        if incident:
            window.opening = 0
            window.recovery = (
                window.recovery + 1
                if busy is not None and busy < measured_config.recovery_busy_percent
                else 0
            )
            updated = incident.model_copy(deep=True)
            updated.latest_evidence = facts
            updated.observed_at = sample.observed_at
            updated.evaluated_at = updated.updated_at = now
            if window.recovery >= measured_config.consecutive_samples:
                updated.status = "resolved"
                updated.resolved_at = now
                self.active.pop(key)
                window.recovery = 0
            else:
                self.active[key] = updated
            self.reloaded.discard(updated.id)
            return [updated]
        window.recovery = 0
        window.opening = (
            window.opening + 1
            if busy is not None
            and runnable is not None
            and cores is not None
            and busy >= measured_config.trigger_busy_percent
            and runnable > cores
            else 0
        )
        if window.opening < measured_config.consecutive_samples:
            return []
        opened = Incident(
            id=uuid4(),
            node_id=sample.node_id,
            resource="cpu",
            rule="cpu_saturation",
            severity=measured_config.severity,
            diagnosis=(
                "Host CPU is saturated with runnable demand exceeding online logical cores; "
                "listed processes are observed contributors, not proven sole causes"
            ),
            configuration=measured_config,
            opening_evidence=facts,
            latest_evidence=facts,
            opened_at=now,
            observed_at=sample.observed_at,
            evaluated_at=now,
            updated_at=now,
            investigation_steps=[
                "Confirm busy, runnable, online-core, load, iowait, and steal values in the same interval",
                "Inspect top -H, ps, pidstat, and /proc/PID/stat for the recorded PID and start time",
                "Check cgroup CPU quotas, affinity, throttling, and cloud CPU credits before attribution",
                "Remove only the owned bounded workload and require fresh busy CPU below recovery threshold",
            ],
        )
        self.active[key] = opened
        window.opening = 0
        return [opened]


class CompositeEvaluator:
    def __init__(self, active: list[Incident]) -> None:
        self.disk = DiskEvaluator([i for i in active if i.rule == "disk_block_exhaustion"])
        self.cpu = CpuEvaluator([i for i in active if i.rule == "cpu_saturation"])

    @property
    def active(self) -> dict[tuple[str, str, str], Incident]:
        return {
            (incident.node_id, incident.rule, incident.resource): incident
            for incident in [*self.disk.active.values(), *self.cpu.active.values()]
        }

    @property
    def reloaded(self) -> set[Any]:
        return set(self.disk.reloaded) | set(self.cpu.reloaded)

    def reset_node(self, node: str) -> None:
        for evaluator in (self.disk, self.cpu):
            for key in list(evaluator.windows):
                if key[0] == node:
                    evaluator.windows.pop(key)

    def replace_active(self, records: list[Incident], affected: set[str]) -> None:
        self.disk.active = {
            (i.node_id, i.resource): i for i in records if i.rule == "disk_block_exhaustion"
        }
        self.cpu.active = {
            (i.node_id, i.resource): i for i in records if i.rule == "cpu_saturation"
        }
        for node in affected:
            self.reset_node(node)
        self.disk.reloaded.update(
            i.id for i in records if i.rule == "disk_block_exhaustion" and i.node_id in affected
        )
        self.cpu.reloaded.update(
            i.id for i in records if i.rule == "cpu_saturation" and i.node_id in affected
        )

    def evaluate(
        self,
        sample: Sample,
        previous: Sample | None,
        now: datetime,
        disk_config: DiskConfig,
        cpu_config: CpuConfig,
    ) -> list[Incident]:
        return [
            *self.disk.evaluate(sample, previous, now, disk_config),
            *self.cpu.evaluate(sample, previous, now, cpu_config),
        ]
