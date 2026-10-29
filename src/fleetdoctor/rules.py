"""Staged heterogeneous evaluators. Only eligible observations enter here."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from fleetdoctor.fd import MAX_ACTIVE_WATCHES, parse_resource
from fleetdoctor.incidents import (
    CpuConfig,
    DiskConfig,
    DnsConfig,
    FdConfig,
    Incident,
    InodeConfig,
    NetworkConfig,
    OomConfig,
)
from fleetdoctor.schema import (
    DnsBaselineObservation,
    FdProcessObservation,
    Filesystem,
    NetworkProbeObservation,
    Sample,
    WorkloadMemoryObservation,
)


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
    configuration: (
        DiskConfig
        | InodeConfig
        | CpuConfig
        | OomConfig
        | FdConfig
        | NetworkConfig
        | DnsConfig
        | None
    ) = None
    guard_percent: float | None = None
    exit_confirmations: int = 0
    replacement_boot: str | None = None
    replacement_confirmations: int = 0


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


def inode_evidence(
    sample: Sample, fs: Filesystem, effective_block_guard_percent: float
) -> dict[str, Any]:
    return {
        "node_id": sample.node_id,
        "boot_id": str(sample.boot_id),
        "agent_session_id": str(sample.agent_session_id),
        "sequence": sample.sequence,
        "observed_at": sample.observed_at.isoformat(),
        "inode_available": fs.inode_usage_percent is not None,
        "block_available": fs.block_usage_percent is not None and fs.available_bytes is not None,
        "effective_block_guard_percent": effective_block_guard_percent,
        "filesystem": fs.model_dump(mode="json"),
        "coverage": {
            "inode": "available" if fs.inode_usage_percent is not None else "unavailable",
            "block_guard": "available"
            if fs.block_usage_percent is not None and fs.available_bytes is not None
            else "unavailable",
            "errors": fs.errors,
        },
    }


class InodeEvaluator:
    def __init__(self, active: list[Incident]) -> None:
        self.active = {(incident.node_id, incident.resource): incident for incident in active}
        self.windows: dict[tuple[str, str], Window] = {}
        self.reloaded = {incident.id for incident in active}

    def evaluate(
        self,
        sample: Sample,
        previous: Sample | None,
        now: datetime,
        config: InodeConfig,
        disk_config: DiskConfig,
    ) -> list[Incident]:
        changes: list[Incident] = []
        for fs in sample.filesystems:
            key = sample.node_id, fs.mountpoint
            incident = self.active.get(key)
            measured = (
                incident.configuration
                if incident
                else config.model_copy(
                    update={
                        "block_guard_percent": min(
                            config.block_guard_percent, disk_config.trigger_percent
                        )
                    }
                )
            )
            assert isinstance(measured, InodeConfig)
            effective_guard = measured.block_guard_percent
            reset = previous is None or (
                previous.boot_id != sample.boot_id
                or previous.agent_session_id != sample.agent_session_id
                or (sample.observed_at - previous.observed_at).total_seconds()
                > measured.max_gap_seconds
            )
            window = self.windows.setdefault(key, Window())
            if reset or window.configuration != measured or window.guard_percent != effective_guard:
                window.opening = window.recovery = 0
                window.configuration = measured
                window.guard_percent = effective_guard
            inode_usage = fs.inode_usage_percent
            facts = inode_evidence(sample, fs, effective_guard)
            if incident:
                window.opening = 0
                window.recovery = (
                    window.recovery + 1
                    if inode_usage is not None and inode_usage < measured.recovery_percent
                    else 0
                )
                updated = incident.model_copy(deep=True)
                updated.latest_evidence = facts
                updated.observed_at = sample.observed_at
                updated.evaluated_at = updated.updated_at = now
                if window.recovery >= measured.consecutive_samples:
                    updated.status = "resolved"
                    updated.resolved_at = now
                    self.active.pop(key)
                    window.recovery = 0
                else:
                    self.active[key] = updated
                self.reloaded.discard(updated.id)
                changes.append(updated)
                continue
            window.recovery = 0
            opening = (
                inode_usage is not None
                and fs.block_usage_percent is not None
                and fs.available_bytes is not None
                and fs.available_bytes > 0
                and inode_usage >= measured.trigger_percent
                and fs.block_usage_percent < effective_guard
            )
            window.opening = window.opening + 1 if opening else 0
            if window.opening < measured.consecutive_samples:
                continue
            opened = Incident(
                id=uuid4(),
                node_id=sample.node_id,
                resource=fs.mountpoint,
                rule="inode_exhaustion",
                severity=measured.severity,
                diagnosis=(
                    f"Filesystem {fs.mountpoint} has exhausted workload inodes while block "
                    "space remains available"
                ),
                configuration=measured,
                opening_evidence=facts,
                latest_evidence=facts,
                opened_at=now,
                observed_at=sample.observed_at,
                evaluated_at=now,
                updated_at=now,
                investigation_steps=[
                    f"Confirm df -i -- {fs.mountpoint} and df -B1 -- {fs.mountpoint}",
                    "Verify the mount/device identity with findmnt before changing files",
                    "Inspect bounded known workload directories for file counts; statvfs does not identify a causal directory",
                    "Remove only owned expendable files and require fresh inode usage below recovery threshold",
                ],
            )
            self.active[key] = opened
            window.opening = 0
            changes.append(opened)
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


def oom_resource(workload: WorkloadMemoryObservation) -> str:
    """Unambiguous bounded key; the display path remains separate in evidence."""
    return workload.generation_key


def _matching_previous(
    previous: Sample | None, workload: WorkloadMemoryObservation
) -> WorkloadMemoryObservation | None:
    if previous is None or previous.memory is None:
        return None
    return next(
        (
            item
            for item in previous.memory.workloads
            if item.generation_key == workload.generation_key
        ),
        None,
    )


def oom_evidence(
    sample: Sample,
    workload: WorkloadMemoryObservation,
    previous: WorkloadMemoryObservation | None,
) -> tuple[dict[str, Any], int | None, int | None]:
    oom_delta = kill_delta = None
    if previous is not None and previous.events is not None and workload.events is not None:
        oom_delta = workload.events.oom - previous.events.oom
        kill_delta = workload.events.oom_kill - previous.events.oom_kill
        if oom_delta < 0 or kill_delta < 0:
            oom_delta = kill_delta = None
    scoped_logs = []
    if sample.memory is not None:
        scoped_logs = [
            value.model_dump(mode="json")
            for value in sample.memory.kernel_logs
            if value.cgroup_path == workload.cgroup_path
        ]
    return (
        {
            "node_id": sample.node_id,
            "boot_id": str(sample.boot_id),
            "agent_session_id": str(sample.agent_session_id),
            "sequence": sample.sequence,
            "observed_at": sample.observed_at.isoformat(),
            "memory_available": workload.events is not None,
            "resource": oom_resource(workload),
            "cgroup_path": workload.cgroup_path,
            "generation": {
                "boot_id": str(workload.boot_id),
                "st_dev": workload.st_dev,
                "st_ino": workload.st_ino,
            },
            "workload": workload.model_dump(mode="json"),
            "event_delta": {"oom": oom_delta, "oom_kill": kill_delta},
            "scoped_kernel_logs": scoped_logs,
            "kernel_log_coverage": sample.memory.kernel_log_coverage
            if sample.memory is not None
            else "unavailable",
            "coverage": {
                "local_events": "available" if workload.events is not None else "unavailable",
                "snapshot": "stable" if workload.snapshot_stable else "unstable",
                "usage_limit": "available"
                if workload.current_bytes is not None and workload.max_bytes is not None
                else ("unlimited" if workload.max_unlimited else "unavailable"),
                "process_inventory": workload.process_inventory,
                "errors": workload.errors,
            },
        },
        oom_delta,
        kill_delta,
    )


class OomEvaluator:
    def __init__(self, active: list[Incident]) -> None:
        self.active = {(incident.node_id, incident.resource): incident for incident in active}
        self.windows: dict[tuple[str, str], Window] = {}
        self.reloaded = {incident.id for incident in active}

    def evaluate(
        self, sample: Sample, previous: Sample | None, now: datetime, config: OomConfig
    ) -> list[Incident]:
        if sample.memory is None:
            return []
        changes: list[Incident] = []
        for workload in sample.memory.workloads:
            resource = oom_resource(workload)
            key = sample.node_id, resource
            incident = self.active.get(key)
            measured = incident.configuration if incident else config
            assert isinstance(measured, OomConfig)
            prior = _matching_previous(previous, workload)
            continuity = bool(
                prior is not None
                and previous is not None
                and previous.boot_id == sample.boot_id
                and previous.agent_session_id == sample.agent_session_id
                and 0
                < (sample.observed_at - previous.observed_at).total_seconds()
                <= measured.max_gap_seconds
            )
            facts, oom_delta, kill_delta = oom_evidence(
                sample, workload, prior if continuity else None
            )
            new_oom = continuity and oom_delta is not None and oom_delta > 0
            new_kill = continuity and kill_delta is not None and kill_delta > 0
            counter_valid = continuity and oom_delta is not None and kill_delta is not None
            window = self.windows.setdefault(key, Window(configuration=measured))
            if not continuity or window.configuration != measured:
                window.opening = window.recovery = 0
                window.configuration = measured
            if incident is not None:
                updated = incident.model_copy(deep=True)
                updated.latest_evidence = facts
                updated.observed_at = sample.observed_at
                updated.evaluated_at = updated.updated_at = now
                if new_oom or new_kill:
                    window.recovery = 0
                else:
                    eligible_recovery = bool(
                        counter_valid
                        and oom_delta == 0
                        and kill_delta == 0
                        and workload.snapshot_stable
                        and workload.usage_ratio is not None
                        and workload.usage_ratio * 100 < measured.recovery_percent
                    )
                    window.recovery = window.recovery + 1 if eligible_recovery else 0
                if window.recovery >= measured.consecutive_samples:
                    updated.status = "resolved"
                    updated.resolved_at = now
                    self.active.pop(key)
                    window.recovery = 0
                else:
                    self.active[key] = updated
                self.reloaded.discard(updated.id)
                changes.append(updated)
                continue
            window.recovery = 0
            if not new_kill:
                continue
            opened = Incident(
                id=uuid4(),
                node_id=sample.node_id,
                resource=resource,
                rule="workload_oom",
                severity=measured.severity,
                diagnosis=(
                    f"Workload {workload.cgroup_path} observed a new local OOM-kill event; "
                    "the local counter proves a scoped kill but does not by itself prove which limit caused it"
                ),
                configuration=measured,
                opening_evidence=facts,
                latest_evidence=facts,
                opened_at=now,
                observed_at=sample.observed_at,
                evaluated_at=now,
                updated_at=now,
                investigation_steps=[
                    f"Inspect memory.current, memory.max, memory.swap.max, and memory.events.local for {workload.cgroup_path}",
                    "Correlate exact scoped kernel-log lines when available; do not infer a victim from an unrelated PID",
                    "Inspect bounded PID/start-time/RSS evidence and application logs for the recorded generation",
                    "Stop only the owned workload while retaining the cgroup for three fresh recovery observations",
                ],
            )
            self.active[key] = opened
            changes.append(opened)
        return changes


def fd_evidence(
    sample: Sample,
    observation: FdProcessObservation | None,
    resource: str,
    *,
    admission_capacity: str = "available",
) -> dict[str, Any]:
    available = bool(
        observation is not None
        and observation.status == "present"
        and observation.descriptor_count is not None
        and observation.soft_limit is not None
        and observation.soft_limit > 0
    )
    return {
        "node_id": sample.node_id,
        "boot_id": str(sample.boot_id),
        "agent_session_id": str(sample.agent_session_id),
        "sequence": sample.sequence,
        "observed_at": sample.observed_at.isoformat(),
        "resource": resource,
        "identity": observation.identity.model_dump(mode="json")
        if observation is not None
        else parse_resource(resource).model_dump(mode="json"),
        "fd_available": available,
        "status": observation.status if observation is not None else "unknown",
        "observation": observation.model_dump(mode="json") if observation is not None else None,
        "suspected_leak": bool(
            available
            and observation is not None
            and observation.growth_per_second is not None
            and observation.growth_per_second > 0
        ),
        "coverage": {
            "watch": sample.fd.watch_coverage if sample.fd is not None else "unavailable",
            "watch_revision": sample.fd.watch_revision if sample.fd is not None else None,
            "admission_capacity": admission_capacity,
            "errors": (
                observation.errors
                if observation is not None
                else ["watched_identity_missing_from_fd_block"]
            ),
        },
    }


class FdEvaluator:
    def __init__(self, active: list[Incident]) -> None:
        self.active = {(incident.node_id, incident.resource): incident for incident in active}
        self.windows: dict[tuple[str, str], Window] = {}
        self.reloaded = {incident.id for incident in active}
        self.admission_overflow_nodes: set[str] = set()

    @staticmethod
    def _reset(window: Window, configuration: FdConfig) -> None:
        window.opening = window.recovery = window.exit_confirmations = 0
        window.replacement_boot = None
        window.replacement_confirmations = 0
        window.configuration = configuration

    def evaluate(
        self, sample: Sample, previous: Sample | None, now: datetime, config: FdConfig
    ) -> list[Incident]:
        changes: list[Incident] = []
        observations = {
            item.identity.resource: item
            for item in (sample.fd.observations if sample.fd is not None else [])
        }
        active_for_node = {
            resource: incident
            for (node, resource), incident in self.active.items()
            if node == sample.node_id
        }
        candidate_continuity = bool(
            previous is not None
            and previous.agent_session_id == sample.agent_session_id
            and 0
            < (sample.observed_at - previous.observed_at).total_seconds()
            <= config.max_gap_seconds
        )
        for resource, incident in sorted(active_for_node.items()):
            measured = incident.configuration
            assert isinstance(measured, FdConfig)
            observation = observations.get(resource)
            window = self.windows.setdefault((sample.node_id, resource), Window())
            active_continuity = bool(
                previous is not None
                and previous.agent_session_id == sample.agent_session_id
                and 0
                < (sample.observed_at - previous.observed_at).total_seconds()
                <= measured.max_gap_seconds
            )
            if not active_continuity or window.configuration != measured:
                self._reset(window, measured)
            old_identity = parse_resource(resource)
            updated = incident.model_copy(deep=True)
            reason = None
            if sample.boot_id != old_identity.boot_id:
                current_boot = str(sample.boot_id)
                if window.replacement_boot != current_boot:
                    window.replacement_boot = current_boot
                    window.replacement_confirmations = 0
                window.replacement_confirmations += 1
                window.recovery = window.exit_confirmations = 0
                if window.replacement_confirmations >= measured.consecutive_samples:
                    reason = "boot_replaced"
            else:
                window.replacement_boot = None
                window.replacement_confirmations = 0
                status = observation.status if observation is not None else "unknown"
                if status in ("exited", "replaced"):
                    window.exit_confirmations += 1
                    window.recovery = 0
                    if window.exit_confirmations >= measured.consecutive_samples:
                        reason = "confirmed_exit"
                else:
                    window.exit_confirmations = 0
                    ratio = observation.pressure_ratio if observation is not None else None
                    window.recovery = (
                        window.recovery + 1
                        if ratio is not None and ratio * 100 < measured.recovery_percent
                        else 0
                    )
                    if window.recovery >= measured.consecutive_samples:
                        reason = "descriptor_release"
            facts = fd_evidence(sample, observation, resource)
            if reason is not None:
                facts["resolution_reason"] = reason
                if reason == "boot_replaced":
                    facts["prior_boot_id"] = str(old_identity.boot_id)
                    facts["current_boot_id"] = str(sample.boot_id)
                updated.status = "resolved"
                updated.resolved_at = now
                updated.resolution_reason = reason  # type: ignore[assignment]
                self.active.pop((sample.node_id, resource))
                self._reset(window, measured)
            else:
                self.active[(sample.node_id, resource)] = updated
            updated.latest_evidence = facts
            updated.observed_at = sample.observed_at
            updated.evaluated_at = updated.updated_at = now
            self.reloaded.discard(updated.id)
            changes.append(updated)

        self.admission_overflow_nodes.discard(sample.node_id)
        for key in list(self.windows):
            if (
                key[0] == sample.node_id
                and key[1] not in observations
                and key[1] not in active_for_node
            ):
                self.windows.pop(key)
        candidates: list[tuple[bool, str, FdProcessObservation, Window]] = []
        for resource, observation in observations.items():
            if (sample.node_id, resource) in self.active or resource in active_for_node:
                continue
            window = self.windows.setdefault((sample.node_id, resource), Window())
            if not candidate_continuity or window.configuration != config:
                self._reset(window, config)
            eligible = bool(
                observation.status == "present"
                and observation.descriptor_count is not None
                and observation.soft_limit is not None
                and observation.soft_limit > 0
                and observation.pressure_ratio is not None
                and observation.pressure_ratio * 100 >= config.trigger_percent
            )
            window.opening = window.opening + 1 if eligible else 0
            window.recovery = window.exit_confirmations = 0
            if window.opening >= config.consecutive_samples:
                candidates.append((not observation.configured, resource, observation, window))
        candidates.sort(key=lambda item: (item[0], item[1]))
        slots = MAX_ACTIVE_WATCHES - len(active_for_node)
        if len(candidates) > max(0, slots):
            self.admission_overflow_nodes.add(sample.node_id)
        for _, resource, observation, window in candidates[: max(0, slots)]:
            facts = fd_evidence(sample, observation, resource)
            opened = Incident(
                id=uuid4(),
                node_id=sample.node_id,
                resource=resource,
                rule="fd_pressure",
                severity=config.severity,
                diagnosis=(
                    f"Process {observation.identity.pid} has sustained file-descriptor pressure; "
                    "positive measured growth supports suspected leakage but does not prove a cause"
                ),
                configuration=config,
                opening_evidence=facts,
                latest_evidence=facts,
                opened_at=now,
                observed_at=sample.observed_at,
                evaluated_at=now,
                updated_at=now,
                investigation_steps=[
                    "Confirm the recorded boot ID, PID, and /proc start time before inspecting the process",
                    "Compare /proc/PID/fd count with the process Max open files soft limit without reading descriptor targets",
                    "Use lsof or application diagnostics only after identity confirmation; observed growth is not causal proof",
                    "Release only owned descriptors or stop only the owned process, then require three fresh confirmations",
                ],
            )
            self.active[(sample.node_id, resource)] = opened
            window.opening = 0
            changes.append(opened)
        return changes


MAX_ACTIVE_NETWORK_RESOURCES = 16


def network_evidence(sample: Sample, *, target_changed: bool = False) -> dict[str, Any]:
    network = sample.network
    probe = network.probe if network is not None else None
    if target_changed:
        return {
            "node_id": sample.node_id,
            "boot_id": str(sample.boot_id),
            "agent_session_id": str(sample.agent_session_id),
            "sequence": sample.sequence,
            "observed_at": sample.observed_at.isoformat(),
            "network_available": False,
            "probe": None,
            "tcp": None,
            "interfaces": [],
            "coverage": {
                "probe": "unavailable",
                "limitation": "target_changed",
                "host_counters": "not_attributed_to_target",
                "interface_counters": "not_attributed_to_path_cause",
            },
        }
    return {
        "node_id": sample.node_id,
        "boot_id": str(sample.boot_id),
        "agent_session_id": str(sample.agent_session_id),
        "sequence": sample.sequence,
        "observed_at": sample.observed_at.isoformat(),
        "network_available": bool(probe is not None and probe.status == "available"),
        "probe": probe.model_dump(mode="json") if probe is not None else None,
        "tcp": network.tcp.model_dump(mode="json") if network is not None else None,
        "interfaces": [item.model_dump(mode="json") for item in network.interfaces]
        if network is not None
        else [],
        "coverage": {
            "probe": probe.status if probe is not None else "unavailable",
            "route": probe.route_status if probe is not None else "unavailable",
            "route_error": probe.route_error if probe is not None else "network_unavailable",
            "host_counters": "context_only_not_target_attributed",
            "interface_counters": "interface_scoped_context_not_causal",
            "errors": network.errors if network is not None else ["network_unavailable"],
        },
    }


class NetworkEvaluator:
    def __init__(self, active: list[Incident]) -> None:
        self.active = {(item.node_id, item.resource): item for item in active}
        self.windows: dict[tuple[str, str], Window] = {}
        self.reloaded = {item.id for item in active}
        self.admission_overflow_nodes: set[str] = set()

    def evaluate(
        self, sample: Sample, previous: Sample | None, now: datetime, config: NetworkConfig
    ) -> list[Incident]:
        changes: list[Incident] = []
        # Candidate overflow describes only the current accepted evaluation. Capacity
        # itself is derived from durable active rows by the API/metrics view.
        self.admission_overflow_nodes.discard(sample.node_id)
        probe = sample.network.probe if sample.network is not None else None
        target = probe.target if probe is not None else None
        resource = f"ipv4:{target}" if target is not None else None
        previous_target = (
            previous.network.probe.target
            if previous is not None and previous.network is not None
            else None
        )
        for key, active_incident in list(self.active.items()):
            if active_incident.node_id != sample.node_id or key[1] == resource:
                continue
            updated = active_incident.model_copy(deep=True)
            updated.latest_evidence = network_evidence(sample, target_changed=True)
            updated.observed_at = sample.observed_at
            updated.evaluated_at = updated.updated_at = now
            self.active[key] = updated
            self.windows.pop(key, None)
            self.reloaded.discard(updated.id)
            changes.append(updated)
        if resource is None:
            return changes
        key = sample.node_id, resource
        incident = self.active.get(key)
        measured = incident.configuration if incident is not None else config
        assert isinstance(measured, NetworkConfig)
        continuity = bool(
            previous is not None
            and previous.boot_id == sample.boot_id
            and previous.agent_session_id == sample.agent_session_id
            and (sample.observed_at - previous.observed_at).total_seconds()
            <= measured.max_gap_seconds
            and previous_target == target
        )
        for pending_key in list(self.windows):
            if (
                pending_key[0] == sample.node_id
                and pending_key != key
                and pending_key not in self.active
            ):
                self.windows.pop(pending_key)
        window = self.windows.setdefault(key, Window())
        if not continuity or window.configuration != measured:
            window.opening = window.recovery = 0
            window.configuration = measured
        facts = network_evidence(sample)
        available = probe is not None and probe.status == "available"
        lost = probe.lost if probe is not None and available else None
        median = probe.median_rtt_ms if probe is not None and available else None
        opening = bool(
            available
            and (
                (lost is not None and lost >= measured.loss_trigger_packets)
                or (median is not None and median >= measured.rtt_trigger_ms)
            )
        )
        recovery = bool(
            available and lost == 0 and median is not None and median < measured.recovery_rtt_ms
        )
        if incident is not None:
            window.opening = 0
            window.recovery = window.recovery + 1 if recovery else 0
            updated = incident.model_copy(deep=True)
            updated.latest_evidence = facts
            updated.observed_at = sample.observed_at
            updated.evaluated_at = updated.updated_at = now
            if window.recovery >= measured.consecutive_samples:
                updated.status = "resolved"
                updated.resolved_at = now
                self.active.pop(key)
                window.recovery = 0
            else:
                self.active[key] = updated
            self.reloaded.discard(updated.id)
            changes.append(updated)
            return changes
        window.recovery = 0
        window.opening = window.opening + 1 if opening else 0
        if window.opening < measured.consecutive_samples:
            return changes
        active_for_node = sum(node == sample.node_id for node, _ in self.active)
        if active_for_node >= MAX_ACTIVE_NETWORK_RESOURCES:
            self.admission_overflow_nodes.add(sample.node_id)
            window.opening = 0
            return changes
        opened = Incident(
            id=uuid4(),
            node_id=sample.node_id,
            resource=resource,
            rule="network_path_degradation",
            severity=measured.severity,
            diagnosis=f"Network path to {target} has sustained packet loss or latency",
            configuration=measured,
            opening_evidence=facts,
            latest_evidence=facts,
            opened_at=now,
            observed_at=sample.observed_at,
            evaluated_at=now,
            updated_at=now,
            investigation_steps=[
                f"Repeat a bounded numeric ping to {target} and compare individual successful RTTs",
                "Inspect ip -4 route get for path context; do not treat the interface as a proven culprit",
                "Compare host retransmits and interface error/drop counters using their recorded scopes",
                "Check shaping and upstream path changes while preserving ingestion and administration traffic",
                "Remove only an owned matching fault and require three fresh zero-loss observations below recovery RTT",
            ],
        )
        self.active[key] = opened
        window.opening = 0
        changes.append(opened)
        return changes


MAX_ACTIVE_DNS_RESOURCES = 16


def _healthy_direct_ip(
    probe: NetworkProbeObservation | None, target: str, threshold: float
) -> bool:
    return bool(
        probe is not None
        and probe.status == "available"
        and probe.target == target
        and probe.sent == 3
        and probe.received == 3
        and probe.lost == 0
        and probe.median_rtt_ms is not None
        and probe.median_rtt_ms < threshold
    )


def _valid_dns_baseline(
    sample: Sample, baseline: DnsBaselineObservation | None, threshold: float
) -> tuple[bool, str | None]:
    dns = sample.dns
    if dns is None or dns.hostname is None or dns.direct_ip_target is None:
        return False, "dns_unconfigured"
    if baseline is None:
        return False, "known_good_baseline_missing"
    if (
        baseline.node_id != sample.node_id
        or baseline.boot_id != sample.boot_id
        or baseline.agent_session_id != sample.agent_session_id
        or baseline.hostname != dns.hostname
        or baseline.direct_ip_target != dns.direct_ip_target
    ):
        return False, "known_good_baseline_scope_mismatch"
    age = (sample.observed_at - baseline.observed_at).total_seconds()
    if not 0 <= age <= 3600 or baseline.sequence > sample.sequence:
        return False, "known_good_baseline_expired_or_future"
    current_identity = (
        baseline.sequence == sample.sequence and baseline.observed_at == sample.observed_at
    )
    if dns.query.status == "failure" and (
        baseline.sequence >= sample.sequence or baseline.observed_at >= sample.observed_at
    ):
        return False, "known_good_baseline_not_historical"
    if current_identity:
        probe = sample.network.probe if sample.network is not None else None
        if (
            baseline.query != dns.query
            or probe is None
            or baseline.direct_ip_probe != probe
            or baseline.resolver_fingerprint != dns.resolver.fingerprint
            or baseline.resolver_nameservers != dns.resolver.nameservers
        ):
            return False, "known_good_baseline_current_fact_mismatch"
    if not _healthy_direct_ip(baseline.direct_ip_probe, dns.direct_ip_target, threshold):
        return False, "known_good_baseline_ip_not_healthy"
    return True, None


def dns_evidence(
    sample: Sample,
    config: DnsConfig,
    *,
    scope_changed: bool = False,
) -> dict[str, Any]:
    dns = sample.dns
    probe = sample.network.probe if sample.network is not None else None
    if dns is None or dns.hostname is None or dns.direct_ip_target is None or scope_changed:
        reason = "scope_changed" if scope_changed else "dns_unavailable"
        return {
            "node_id": sample.node_id,
            "boot_id": str(sample.boot_id),
            "agent_session_id": str(sample.agent_session_id),
            "sequence": sample.sequence,
            "observed_at": sample.observed_at.isoformat(),
            "dns_available": False,
            "dns_conclusive": False,
            "inconclusive_reason": reason,
            "dns": dns.model_dump(mode="json") if dns is not None else None,
            "direct_ip_probe": probe.model_dump(mode="json") if probe is not None else None,
            "frozen_direct_ip_rtt_max_ms": config.direct_ip_rtt_max_ms,
        }
    direct_healthy = _healthy_direct_ip(probe, dns.direct_ip_target, config.direct_ip_rtt_max_ms)
    baseline_valid, baseline_reason = _valid_dns_baseline(
        sample, dns.baseline, config.direct_ip_rtt_max_ms
    )
    measured = dns.query.status in ("success", "failure")
    conclusive = measured and direct_healthy and (dns.query.status == "success" or baseline_valid)
    inconclusive_reason: str | None = None
    if not measured:
        inconclusive_reason = "dns_query_unavailable"
    elif not direct_healthy:
        inconclusive_reason = "direct_ip_not_healthy"
    elif dns.query.status == "failure" and not baseline_valid:
        inconclusive_reason = baseline_reason
    return {
        "node_id": sample.node_id,
        "boot_id": str(sample.boot_id),
        "agent_session_id": str(sample.agent_session_id),
        "sequence": sample.sequence,
        "observed_at": sample.observed_at.isoformat(),
        "dns_available": measured,
        "dns_conclusive": conclusive,
        "inconclusive_reason": inconclusive_reason,
        "hostname": dns.hostname,
        "direct_ip_target": dns.direct_ip_target,
        "query": dns.query.model_dump(mode="json"),
        "resolver": dns.resolver.model_dump(mode="json"),
        "baseline": dns.baseline.model_dump(mode="json") if dns.baseline is not None else None,
        "retention_coverage": dns.retention_coverage,
        "candidate_error": dns.candidate_error,
        "direct_ip_probe": probe.model_dump(mode="json") if probe is not None else None,
        "direct_ip_healthy": direct_healthy,
        "frozen_direct_ip_rtt_max_ms": config.direct_ip_rtt_max_ms,
    }


class DnsEvaluator:
    def __init__(self, active: list[Incident]) -> None:
        self.active = {(item.node_id, item.resource): item for item in active}
        self.windows: dict[tuple[str, str], Window] = {}
        self.reloaded = {item.id for item in active}
        self.admission_overflow_nodes: set[str] = set()

    @staticmethod
    def resource(hostname: str, target: str) -> str:
        return f"dns:{hostname}|ipv4:{target}"

    def evaluate(
        self, sample: Sample, previous: Sample | None, now: datetime, config: DnsConfig
    ) -> list[Incident]:
        changes: list[Incident] = []
        self.admission_overflow_nodes.discard(sample.node_id)
        dns = sample.dns
        hostname = dns.hostname if dns is not None else None
        target = dns.direct_ip_target if dns is not None else None
        resource = self.resource(hostname, target) if hostname and target else None
        for key, active_incident in list(self.active.items()):
            if active_incident.node_id != sample.node_id or key[1] == resource:
                continue
            measured = active_incident.configuration
            assert isinstance(measured, DnsConfig)
            updated = active_incident.model_copy(deep=True)
            updated.latest_evidence = dns_evidence(sample, measured, scope_changed=True)
            updated.observed_at = sample.observed_at
            updated.evaluated_at = updated.updated_at = now
            self.active[key] = updated
            self.windows.pop(key, None)
            self.reloaded.discard(updated.id)
            changes.append(updated)
        if resource is None or dns is None or hostname is None or target is None:
            return changes
        key = sample.node_id, resource
        incident = self.active.get(key)
        measured = incident.configuration if incident is not None else config
        assert isinstance(measured, DnsConfig)
        previous_dns = previous.dns if previous is not None else None
        continuity = bool(
            previous is not None
            and previous.boot_id == sample.boot_id
            and previous.agent_session_id == sample.agent_session_id
            and 0
            < (sample.observed_at - previous.observed_at).total_seconds()
            <= measured.max_gap_seconds
            and previous_dns is not None
            and previous_dns.hostname == hostname
            and previous_dns.direct_ip_target == target
        )
        for pending_key in list(self.windows):
            if (
                pending_key[0] == sample.node_id
                and pending_key != key
                and pending_key not in self.active
            ):
                self.windows.pop(pending_key)
        window = self.windows.setdefault(key, Window())
        if not continuity or window.configuration != measured:
            window.opening = window.recovery = 0
            window.configuration = measured
        facts = dns_evidence(sample, measured)
        conclusive = facts["dns_conclusive"] is True
        opening = conclusive and dns.query.status == "failure"
        recovery = conclusive and dns.query.status == "success"
        if incident is not None:
            window.opening = 0
            window.recovery = window.recovery + 1 if recovery else 0
            updated = incident.model_copy(deep=True)
            updated.latest_evidence = facts
            updated.observed_at = sample.observed_at
            updated.evaluated_at = updated.updated_at = now
            if window.recovery >= measured.consecutive_samples:
                updated.status = "resolved"
                updated.resolved_at = now
                self.active.pop(key)
                window.recovery = 0
            else:
                self.active[key] = updated
            self.reloaded.discard(updated.id)
            changes.append(updated)
            return changes
        window.recovery = 0
        window.opening = window.opening + 1 if opening else 0
        if window.opening < measured.consecutive_samples:
            return changes
        active_for_node = sum(node == sample.node_id for node, _ in self.active)
        if active_for_node >= MAX_ACTIVE_DNS_RESOURCES:
            self.admission_overflow_nodes.add(sample.node_id)
            window.opening = 0
            return changes
        opened = Incident(
            id=uuid4(),
            node_id=sample.node_id,
            resource=resource,
            rule="dns_resolution_failure",
            severity=measured.severity,
            diagnosis=f"DNS resolution for {hostname} failed while direct-IP reachability remained healthy",
            configuration=measured,
            opening_evidence=facts,
            latest_evidence=facts,
            opened_at=now,
            observed_at=sample.observed_at,
            evaluated_at=now,
            updated_at=now,
            investigation_steps=[
                "Confirm the recorded uncached A-query failure and current resolver fingerprint",
                "Compare the bounded current nameserver list with the immutable known-good baseline",
                "Verify the exact three-packet direct-IP probe remains zero-loss below the frozen RTT limit",
                "Inspect systemd-resolved service and resolver configuration without changing ingestion addressing",
                "Restore only the owned resolver fault and require three fresh matching DNS/IP successes",
            ],
        )
        self.active[key] = opened
        window.opening = 0
        changes.append(opened)
        return changes


class CompositeEvaluator:
    def __init__(self, active: list[Incident]) -> None:
        self.disk = DiskEvaluator([i for i in active if i.rule == "disk_block_exhaustion"])
        self.inode = InodeEvaluator([i for i in active if i.rule == "inode_exhaustion"])
        self.cpu = CpuEvaluator([i for i in active if i.rule == "cpu_saturation"])
        self.oom = OomEvaluator([i for i in active if i.rule == "workload_oom"])
        self.fd = FdEvaluator([i for i in active if i.rule == "fd_pressure"])
        self.network = NetworkEvaluator([i for i in active if i.rule == "network_path_degradation"])
        self.dns = DnsEvaluator([i for i in active if i.rule == "dns_resolution_failure"])

    @property
    def active(self) -> dict[tuple[str, str, str], Incident]:
        return {
            (incident.node_id, incident.rule, incident.resource): incident
            for incident in [
                *self.disk.active.values(),
                *self.inode.active.values(),
                *self.cpu.active.values(),
                *self.oom.active.values(),
                *self.fd.active.values(),
                *self.network.active.values(),
                *self.dns.active.values(),
            ]
        }

    @property
    def reloaded(self) -> set[Any]:
        return (
            set(self.disk.reloaded)
            | set(self.inode.reloaded)
            | set(self.cpu.reloaded)
            | set(self.oom.reloaded)
            | set(self.fd.reloaded)
            | set(self.network.reloaded)
            | set(self.dns.reloaded)
        )

    def reset_node(self, node: str) -> None:
        for evaluator in (
            self.disk,
            self.inode,
            self.cpu,
            self.oom,
            self.fd,
            self.network,
            self.dns,
        ):
            for key in list(evaluator.windows):
                if key[0] == node:
                    evaluator.windows.pop(key)

    def replace_active(self, records: list[Incident], affected: set[str]) -> None:
        self.disk.active = {
            (i.node_id, i.resource): i for i in records if i.rule == "disk_block_exhaustion"
        }
        self.inode.active = {
            (i.node_id, i.resource): i for i in records if i.rule == "inode_exhaustion"
        }
        self.cpu.active = {
            (i.node_id, i.resource): i for i in records if i.rule == "cpu_saturation"
        }
        self.oom.active = {(i.node_id, i.resource): i for i in records if i.rule == "workload_oom"}
        self.fd.active = {(i.node_id, i.resource): i for i in records if i.rule == "fd_pressure"}
        self.network.active = {
            (i.node_id, i.resource): i for i in records if i.rule == "network_path_degradation"
        }
        self.dns.active = {
            (i.node_id, i.resource): i for i in records if i.rule == "dns_resolution_failure"
        }
        for node in affected:
            self.reset_node(node)
        self.disk.reloaded.update(
            i.id for i in records if i.rule == "disk_block_exhaustion" and i.node_id in affected
        )
        self.inode.reloaded.update(
            i.id for i in records if i.rule == "inode_exhaustion" and i.node_id in affected
        )
        self.cpu.reloaded.update(
            i.id for i in records if i.rule == "cpu_saturation" and i.node_id in affected
        )
        self.oom.reloaded.update(
            i.id for i in records if i.rule == "workload_oom" and i.node_id in affected
        )
        self.fd.reloaded.update(
            i.id for i in records if i.rule == "fd_pressure" and i.node_id in affected
        )
        self.network.reloaded.update(
            i.id for i in records if i.rule == "network_path_degradation" and i.node_id in affected
        )
        self.dns.reloaded.update(
            i.id for i in records if i.rule == "dns_resolution_failure" and i.node_id in affected
        )

    def evaluate(
        self,
        sample: Sample,
        previous: Sample | None,
        now: datetime,
        disk_config: DiskConfig,
        inode_config: InodeConfig,
        cpu_config: CpuConfig,
        oom_config: OomConfig,
        fd_config: FdConfig,
        network_config: NetworkConfig | None = None,
        dns_config: DnsConfig | None = None,
    ) -> list[Incident]:
        return [
            *self.disk.evaluate(sample, previous, now, disk_config),
            *self.inode.evaluate(sample, previous, now, inode_config, disk_config),
            *self.cpu.evaluate(sample, previous, now, cpu_config),
            *self.oom.evaluate(sample, previous, now, oom_config),
            *self.fd.evaluate(sample, previous, now, fd_config),
            *self.network.evaluate(sample, previous, now, network_config or NetworkConfig()),
            *self.dns.evaluate(sample, previous, now, dns_config or DnsConfig()),
        ]
