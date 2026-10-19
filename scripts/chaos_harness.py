"""Reusable single-clock scenario reports and bounded disk lifecycle runner."""

import hashlib
import json
import os
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from fleetdoctor.incidents import DiskConfig, InodeConfig

DISK_PATH = "/var/lib/fleetdoctor/chaos/disk"
ROOT = Path(__file__).resolve().parents[1]
LEASE_DIRECTORY = Path.home() / ".fleetdoctor" / "chaos-leases"


class Backend(Protocol):
    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]: ...


class Injector(Protocol):
    def probe(self) -> dict[str, Any]: ...
    def start(self, token: str, duration: int) -> dict[str, Any]: ...
    def status(self, token: str) -> dict[str, Any]: ...
    def cleanup(self, token: str) -> dict[str, Any]: ...


def source_manifest() -> dict[str, Any]:
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, text=True
    ).splitlines()
    hashes = {
        p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
        for p in paths
        if (ROOT / p).is_file() and not p.startswith((".agents/", ".claude/", ".scratch/"))
    }
    return {
        "revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "dirty": bool(
            subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
        ),
        "sha256": hashes,
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(report, indent=2), encoding="utf-8")
    # Windows readers may briefly deny replacement. Retry only that atomic operation:
    # five attempts, four 50ms waits; permanent failures and interruptions propagate.
    for attempt in range(5):
        try:
            os.replace(temp, path)
        except PermissionError as exc:
            if getattr(exc, "winerror", None) not in (5, 32) or attempt == 4:
                raise
            time.sleep(0.05)
        else:
            return


class DiskHarness:
    def __init__(
        self,
        api: Backend,
        injector: Injector,
        target: str,
        reference: str,
        output: Path,
        environment: dict[str, Any],
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        lease_directory: Path = LEASE_DIRECTORY,
    ) -> None:
        if {target, reference} != {"node-a", "node-b"}:
            raise ValueError("use distinct registered lab target/reference nodes")
        self.api, self.injector, self.target, self.reference = api, injector, target, reference
        self.output, self.monotonic, self.sleep = output, monotonic, sleep
        self.lease_directory = lease_directory
        self.after_diagnosis: Callable[[dict[str, Any], float], dict[str, Any]] | None = None
        self.max_injection_seconds = 180
        self.report: dict[str, Any] = {
            "schema_version": 1,
            "scenario": "disk_fill",
            "token": uuid4().hex,
            "target": target,
            "reference": reference,
            "resource": DISK_PATH,
            "expected_diagnosis": "disk_block_exhaustion",
            "environment": environment,
            "poll_interval_seconds": 1,
            "diagnosis_timeout_seconds": 60,
            "recovery_timeout_seconds": 60,
            "max_injection_seconds": 180,
            "preparation_timeout_seconds": 30,
            "trigger_timeout_seconds": 45,
            "events": {},
            "polls": [],
            "cleanup_attempts": [],
            "errors": [],
            "status": "running",
            "injection_attempted": False,
            "source": source_manifest(),
        }

    def owned_status(self) -> dict[str, Any]:
        status = self.injector.status(self.report["token"])
        if (
            status.get("token") != self.report["token"]
            or status.get("cleanup_complete") is not False
            or not isinstance(status.get("filler_inode"), int)
            or status["filler_inode"] <= 0
            or status.get("mapping") != self.report["original_resource"].get("mapping")
        ):
            raise RuntimeError("owned disk filler/lease/mapping is no longer active")
        return status

    def event(self, name: str, observed: float | None = None) -> None:
        self.report["events"][name] = {
            "monotonic_seconds": self.monotonic() if observed is None else observed,
            "utc": datetime.now(UTC).isoformat(),
        }
        write_report(self.output, self.report)

    def nodes(self) -> dict[str, dict[str, Any]]:
        nodes = {n["node_id"]: n for n in self.api.get("/nodes")["nodes"]}
        if set(nodes) != {self.target, self.reference}:
            raise ValueError("expected both monitored nodes")
        ref = nodes[self.reference]
        if not ref["fresh"] or ref["stale"] or ref["active_incident_count"] != 0:
            raise ValueError("healthy reference lost freshness or acquired an incident")
        if not all(ref["diagnosis_coverage"].get(p) == "available" for p in ("/", DISK_PATH)):
            raise ValueError("healthy reference coverage lost")
        return nodes

    def filesystem(self, node: dict[str, Any]) -> dict[str, Any]:
        if not node["fresh"] or node["stale"]:
            raise ValueError("target telemetry is not fresh")
        fs: dict[str, Any] | None = next(
            (f for f in node["filesystems"] or [] if f["mountpoint"] == DISK_PATH), None
        )
        if fs is None or fs["block_usage_percent"] is None:
            raise ValueError("required dedicated block evidence unavailable")
        if not 256 * 1024**2 <= fs["total_bytes"] <= 512 * 1024**2:
            raise ValueError("telemetry capacity does not match bounded mount")
        return fs

    def incidents(self, status: str) -> list[dict[str, Any]]:
        return list(
            self.api.get(
                "/diagnoses",
                {
                    "node": self.target,
                    "rule": "disk_block_exhaustion",
                    "status": status,
                    "limit": 100,
                },
            )["diagnoses"]
        )

    def poll(self) -> tuple[dict[str, Any], list[dict[str, Any]], float, float]:
        nodes = self.nodes()
        fs = self.filesystem(nodes[self.target])
        resource_observed = self.monotonic()
        incidents = self.incidents("active")
        observed = self.monotonic()
        self.report["polls"].append(
            {
                "monotonic_seconds": observed,
                "resource_observed_monotonic_seconds": resource_observed,
                "utc": datetime.now(UTC).isoformat(),
                "nodes": nodes,
                "active": incidents,
            }
        )
        write_report(self.output, self.report)
        return (
            nodes[self.target]["sample"] | {"filesystem": fs},
            incidents,
            resource_observed,
            observed,
        )

    def run(self) -> dict[str, Any]:
        self.lease_directory.mkdir(parents=True, exist_ok=True)
        lease = self.lease_directory / ("filesystem-" + self.target + ".lease")
        self.report["local_lease"] = str(lease)
        acquired = attempted = False
        incident_id: str | None = None
        failure: BaseException | None = None
        try:
            fd = os.open(lease, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(self.report["token"])
            acquired = True
            self.event("preparation_start")
            deadline = self.monotonic() + 30
            cfg = self.api.get("/configuration")
            config = DiskConfig.model_validate(cfg["disk_rule"])
            if cfg["filesystems"] != ["/", DISK_PATH] or config.trigger_percent > 97:
                raise ValueError("both paths and trigger <=97 required for bounded disk scenario")
            self.report["configuration"] = cfg
            self.report["trigger_condition"] = (
                f"fresh exact-mount workload usage >= {config.trigger_percent}%"
            )
            self.report["recovery_condition"] = (
                f"fresh exact-mount workload usage < {config.recovery_percent}% and resolved incident"
            )
            self.report["original_resource"] = self.injector.probe()
            sample, active, _, _ = self.poll()
            self.report["original_observation"] = sample
            if active or sample["filesystem"]["block_usage_percent"] >= config.recovery_percent:
                raise ValueError("target must be healthy without an active disk incident")
            if self.monotonic() > deadline:
                raise TimeoutError("preparation deadline exceeded")
            self.event("preparation_complete")
            self.event("injection_start")
            self.report["max_injection_seconds"] = self.max_injection_seconds
            self.report["injection_attempted"] = True
            attempted = True  # includes failures after a remote side effect but before reply
            self.report["injector"] = self.injector.start(
                self.report["token"], self.max_injection_seconds
            )
            write_report(self.output, self.report)
            injection_deadline = (
                self.report["events"]["injection_start"]["monotonic_seconds"]
                + self.max_injection_seconds
                - 10
            )
            trigger_deadline = self.monotonic() + 45
            while True:
                before = self.monotonic()
                current, active, resource_observed, observed = self.poll()
                if observed > injection_deadline:
                    raise TimeoutError("controller injection deadline")
                if (
                    "threshold_observed" not in self.report["events"]
                    and resource_observed > trigger_deadline
                ):
                    raise TimeoutError("trigger observation timeout")
                if (
                    current["observed_at"] > sample["observed_at"]
                    and current["filesystem"]["block_usage_percent"] >= config.trigger_percent
                    and "threshold_observed" not in self.report["events"]
                ):
                    self.report["trigger_observation"] = current
                    self.event("threshold_observed", resource_observed)
                if "threshold_observed" in self.report["events"]:
                    if (
                        observed - self.report["events"]["threshold_observed"]["monotonic_seconds"]
                        > 60
                    ):
                        raise TimeoutError("diagnosis timeout after threshold observation")
                    matching = next(
                        (
                            i
                            for i in active
                            if i["resource"] == DISK_PATH
                            and i["configuration"] == config.model_dump()
                        ),
                        None,
                    )
                    if matching:
                        incident_id = matching["id"]
                        self.report["incident_id"] = incident_id
                        self.report["opening_detail"] = self.api.get("/diagnoses/" + incident_id)
                        self.report["actual_diagnosis"] = matching["rule"]
                        self.event("api_diagnosis", observed)
                        if self.after_diagnosis is not None:
                            callback_started = self.monotonic()
                            if injection_deadline - callback_started < 80:
                                raise RuntimeError(
                                    "at least 80 seconds must remain before collector restart"
                                )
                            owned_status_before_callback = self.owned_status()
                            callback_started = self.monotonic()
                            if injection_deadline - callback_started < 80:
                                raise RuntimeError(
                                    "at least 80 seconds must remain before collector restart"
                                )
                            self.report["owned_status_before_callback"] = (
                                owned_status_before_callback
                            )
                            callback_deadline = callback_started + 70
                            result = self.after_diagnosis(self.report, callback_deadline)
                            callback_finished = self.monotonic()
                            if (
                                callback_finished > callback_deadline
                                or callback_finished > injection_deadline
                            ):
                                raise RuntimeError(
                                    "collector restart callback returned after deadline"
                                )
                            owned_status_after_callback = self.owned_status()
                            acceptance_finished = self.monotonic()
                            if (
                                acceptance_finished > callback_deadline
                                or acceptance_finished > injection_deadline
                            ):
                                raise RuntimeError(
                                    "collector restart acceptance returned after deadline"
                                )
                            self.report["owned_status_after_callback"] = owned_status_after_callback
                            self.report["after_diagnosis"] = result
                            self.event("after_diagnosis_complete", acceptance_finished)
                        break
                elif observed > trigger_deadline:
                    raise TimeoutError("trigger observation timeout")
                if observed > injection_deadline:
                    raise TimeoutError("controller injection deadline")
                self.sleep(max(0, 1 - (self.monotonic() - before)))
        except BaseException as exc:
            failure = exc
            self.report["errors"].append(type(exc).__name__ + ": " + str(exc))
        finally:
            if attempted:
                cleaned = False
                for attempt in range(3):
                    try:
                        result = self.injector.cleanup(self.report["token"])
                        self.report["cleanup_attempts"].append(
                            {"attempt": attempt + 1, "result": result}
                        )
                        if not result["cleanup_complete"]:
                            raise ValueError("owned filler cleanup not confirmed")
                        cleaned = True
                        self.event("cleanup_complete")
                        break
                    except Exception as exc:
                        self.report["cleanup_attempts"].append(
                            {"attempt": attempt + 1, "error": type(exc).__name__ + ": " + str(exc)}
                        )
                        self.sleep(1)
                if cleaned:
                    deadline = self.monotonic() + 60
                    try:
                        while True:
                            before = self.monotonic()
                            recovery, active, _, observed = self.poll()
                            resolved = (
                                self.api.get("/diagnoses/" + incident_id) if incident_id else None
                            )
                            observed = self.monotonic()
                            if observed > deadline:
                                raise TimeoutError("recovery timeout after cleanup")
                            if (
                                recovery["filesystem"]["block_usage_percent"]
                                < config.recovery_percent
                                and not any(i["resource"] == DISK_PATH for i in active)
                                and (resolved is None or resolved["status"] == "resolved")
                            ):
                                if resolved and (
                                    not resolved["evidence_fresh"]
                                    or not resolved["evidence_available"]
                                ):
                                    raise ValueError("resolution evidence is unavailable/stale")
                                self.report["recovery_observation"] = recovery
                                self.report["resolved_detail"] = resolved
                                self.event("api_resolution", observed)
                                break
                            self.sleep(max(0, 1 - (self.monotonic() - before)))
                    except BaseException as exc:
                        self.report["errors"].append(
                            "recovery: " + type(exc).__name__ + ": " + str(exc)
                        )
                else:
                    self.report["errors"].append(
                        "cleanup failed after bounded reconnect attempts; remote watchdog must be checked"
                    )
            events = self.report["events"]
            if "api_diagnosis" in events:
                self.report["trigger_to_diagnosis_seconds"] = (
                    events["api_diagnosis"]["monotonic_seconds"]
                    - events["threshold_observed"]["monotonic_seconds"]
                )
                self.report["injection_to_diagnosis_seconds"] = (
                    events["api_diagnosis"]["monotonic_seconds"]
                    - events["injection_start"]["monotonic_seconds"]
                )
            self.report["status"] = (
                "passed"
                if incident_id and not self.report["errors"] and "api_resolution" in events
                else "failed"
            )
            self.event("finished")
            if acquired and (not attempted or self.report["status"] == "passed"):
                if lease.read_text() == self.report["token"]:
                    lease.unlink()
            # Failed lease/report retained for explicit recovery, never erased automatically.
        if failure:
            raise failure
        if self.report["status"] != "passed":
            raise RuntimeError("disk run failed; inspect retained report and lease")
        return self.report


class InodeHarness:
    """Measured inode lifecycle with one clock and a shared filesystem lease."""

    def __init__(
        self,
        api: Backend,
        injector: Injector,
        target: str,
        reference: str,
        output: Path,
        environment: dict[str, Any],
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        lease_directory: Path = LEASE_DIRECTORY,
    ) -> None:
        if {target, reference} != {"node-a", "node-b"}:
            raise ValueError("use distinct registered lab target/reference nodes")
        self.api, self.injector = api, injector
        self.target, self.reference = target, reference
        self.output, self.monotonic, self.sleep = output, monotonic, sleep
        self.lease_directory = lease_directory
        self.max_injection_seconds = 180
        self.report: dict[str, Any] = {
            "schema_version": 1,
            "scenario": "inode_exhaustion",
            "token": uuid4().hex,
            "target": target,
            "reference": reference,
            "resource": DISK_PATH,
            "expected_diagnosis": "inode_exhaustion",
            "environment": environment,
            "poll_interval_seconds": 1,
            "diagnosis_timeout_seconds": 60,
            "recovery_timeout_seconds": 60,
            "max_injection_seconds": self.max_injection_seconds,
            "events": {},
            "polls": [],
            "cleanup_attempts": [],
            "errors": [],
            "status": "running",
            "injection_attempted": False,
            "source": source_manifest(),
        }

    def event(self, name: str, observed: float | None = None) -> None:
        self.report["events"][name] = {
            "monotonic_seconds": self.monotonic() if observed is None else observed,
            "utc": datetime.now(UTC).isoformat(),
        }
        write_report(self.output, self.report)

    def nodes(self) -> dict[str, dict[str, Any]]:
        nodes = {node["node_id"]: node for node in self.api.get("/nodes")["nodes"]}
        if set(nodes) != {self.target, self.reference}:
            raise ValueError("expected both monitored nodes")
        reference = nodes[self.reference]
        if not reference["fresh"] or reference["stale"] or reference["active_incident_count"]:
            raise ValueError("healthy reference lost freshness or acquired an incident")
        if not all(
            reference["inode_diagnosis_coverage"].get(path) == "available"
            for path in ("/", DISK_PATH)
        ):
            raise ValueError("healthy reference inode coverage lost")
        return nodes

    def filesystem(self, node: dict[str, Any]) -> dict[str, Any]:
        if not node["fresh"] or node["stale"]:
            raise ValueError("target telemetry is not fresh")
        fs: dict[str, Any] | None = next(
            (value for value in node["filesystems"] or [] if value["mountpoint"] == DISK_PATH),
            None,
        )
        if (
            fs is None
            or fs["inode_usage_percent"] is None
            or fs["block_usage_percent"] is None
            or fs["available_bytes"] is None
        ):
            raise ValueError("required dedicated inode/block evidence unavailable")
        if not 1 <= fs["inodes_total"] <= 4096:
            raise ValueError("dedicated mount inode budget is outside 1..4096")
        return fs

    def incidents(self, status: str) -> list[dict[str, Any]]:
        return list(
            self.api.get(
                "/diagnoses",
                {
                    "node": self.target,
                    "rule": "inode_exhaustion",
                    "status": status,
                    "limit": 100,
                },
            )["diagnoses"]
        )

    def poll(self) -> tuple[dict[str, Any], list[dict[str, Any]], float, float]:
        nodes = self.nodes()
        fs = self.filesystem(nodes[self.target])
        resource_observed = self.monotonic()
        incidents = self.incidents("active")
        response_completed = self.monotonic()
        sample = nodes[self.target]["sample"] | {"filesystem": fs}
        self.report["polls"].append(
            {
                "monotonic_seconds": response_completed,
                "resource_observed_monotonic_seconds": resource_observed,
                "incident_response_completed_monotonic_seconds": response_completed,
                "utc": datetime.now(UTC).isoformat(),
                "nodes": nodes,
                "active": incidents,
            }
        )
        write_report(self.output, self.report)
        return sample, incidents, resource_observed, response_completed

    def owned_status(self) -> dict[str, Any]:
        status = self.injector.status(self.report["token"])
        if (
            status.get("token") != self.report["token"]
            or status.get("cleanup_complete") is not False
            or not isinstance(status.get("directory_inode"), int)
            or not isinstance(status.get("directory_dev"), int)
            or not isinstance(status.get("files"), list)
            or status.get("mapping") != self.report["original_resource"].get("mapping")
        ):
            raise RuntimeError("owned inode directory/lease/mapping is no longer active")
        return status

    def validate_opening_evidence(
        self, evidence: Any, config: InodeConfig, effective_guard: float
    ) -> None:
        if not isinstance(evidence, dict):
            raise ValueError("inode incident opening evidence is missing")
        if evidence.get("node_id") != self.target:
            raise ValueError("inode incident opening evidence node mismatch")
        if evidence.get("inode_available") is not True:
            raise ValueError("inode incident opening evidence is unavailable")
        if evidence.get("block_available") is not True:
            raise ValueError("inode incident opening block guard is unavailable")
        if evidence.get("effective_block_guard_percent") != effective_guard:
            raise ValueError("inode incident opening block guard mismatch")
        filesystem = evidence.get("filesystem")
        if not isinstance(filesystem, dict) or filesystem.get("mountpoint") != DISK_PATH:
            raise ValueError("inode incident opening filesystem mismatch")
        inode_usage = filesystem.get("inode_usage_percent")
        block_usage = filesystem.get("block_usage_percent")
        available = filesystem.get("available_bytes")
        if (
            isinstance(inode_usage, bool)
            or not isinstance(inode_usage, (int, float))
            or inode_usage < config.trigger_percent
        ):
            raise ValueError("inode incident opening threshold evidence mismatch")
        if (
            isinstance(block_usage, bool)
            or not isinstance(block_usage, (int, float))
            or block_usage >= effective_guard
            or isinstance(available, bool)
            or not isinstance(available, int)
            or available <= 0
        ):
            raise ValueError("inode incident opening health guard evidence mismatch")

    def validate_incident_summary(
        self,
        record: Any,
        config: InodeConfig,
        *,
        status: str,
        incident_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise ValueError("inode incident response is malformed")
        expected: dict[str, Any] = {
            "node_id": self.target,
            "resource": DISK_PATH,
            "rule": "inode_exhaustion",
            "configuration": config.model_dump(),
            "severity": config.severity,
            "status": status,
        }
        if incident_id is not None:
            expected["id"] = incident_id
        elif not isinstance(record.get("id"), str) or not record["id"]:
            raise ValueError("inode incident id is missing")
        for field, value in expected.items():
            if record.get(field) != value:
                raise ValueError(f"inode incident {field} mismatch")
        if record.get("evidence_fresh") is not True:
            raise ValueError("inode incident evidence is stale")
        if record.get("evidence_available") is not True:
            raise ValueError("inode incident evidence is unavailable")
        return record

    def validate_incident_detail(
        self,
        record: Any,
        config: InodeConfig,
        effective_guard: float,
        *,
        status: str,
        incident_id: str,
    ) -> dict[str, Any]:
        validated = self.validate_incident_summary(
            record, config, status=status, incident_id=incident_id
        )
        self.validate_opening_evidence(validated.get("opening_evidence"), config, effective_guard)
        return validated

    def validate_resolution_evidence(self, record: dict[str, Any], config: InodeConfig) -> None:
        evidence = record.get("latest_evidence")
        if not isinstance(evidence, dict):
            raise ValueError("inode resolution evidence is missing")
        if evidence.get("node_id") != self.target:
            raise ValueError("inode resolution evidence node mismatch")
        if evidence.get("inode_available") is not True:
            raise ValueError("inode resolution evidence is unavailable")
        filesystem = evidence.get("filesystem")
        if not isinstance(filesystem, dict) or filesystem.get("mountpoint") != DISK_PATH:
            raise ValueError("inode resolution filesystem mismatch")
        inode_usage = filesystem.get("inode_usage_percent")
        if (
            isinstance(inode_usage, bool)
            or not isinstance(inode_usage, (int, float))
            or inode_usage >= config.recovery_percent
        ):
            raise ValueError("inode resolution threshold evidence mismatch")

    def run(self) -> dict[str, Any]:
        self.lease_directory.mkdir(parents=True, exist_ok=True)
        lease = self.lease_directory / ("filesystem-" + self.target + ".lease")
        self.report["local_lease"] = str(lease)
        acquired = attempted = False
        incident_id: str | None = None
        failure: BaseException | None = None
        config = InodeConfig()
        try:
            fd = os.open(lease, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(self.report["token"])
            acquired = True
            self.event("preparation_start")
            cfg = self.api.get("/configuration")
            config = InodeConfig.model_validate(cfg["inode_rule"])
            disk_config = DiskConfig.model_validate(cfg["disk_rule"])
            effective_guard = min(config.block_guard_percent, disk_config.trigger_percent)
            if cfg["filesystems"] != ["/", DISK_PATH] or config.trigger_percent > 97:
                raise ValueError("both paths and inode trigger <=97 required")
            if cfg.get("effective_inode_block_guard_percent") != effective_guard:
                raise ValueError("collector effective inode block guard mismatch")
            self.report["configuration"] = cfg
            self.report["effective_block_guard_percent"] = effective_guard
            self.report["trigger_condition"] = (
                f"fresh inode usage >= {config.trigger_percent}% with available bytes and "
                f"block usage < {effective_guard}%"
            )
            self.report["recovery_condition"] = (
                f"{config.consecutive_samples} fresh inode readings < "
                f"{config.recovery_percent}% and resolved incident"
            )
            self.report["original_resource"] = self.injector.probe()
            sample, active, _, _ = self.poll()
            baseline = sample["filesystem"]
            if (
                active
                or baseline["inode_usage_percent"] >= config.recovery_percent
                or baseline["block_usage_percent"] >= effective_guard
            ):
                raise ValueError("target must have a healthy inode/block baseline and no incident")
            self.report["original_observation"] = sample
            self.event("preparation_complete")
            self.event("injection_start")
            attempted = True
            self.report["injection_attempted"] = True
            self.report["injector"] = self.injector.start(
                self.report["token"], self.max_injection_seconds
            )
            trigger_deadline = self.monotonic() + 45
            injection_deadline = self.monotonic() + self.max_injection_seconds - 10
            while True:
                before = self.monotonic()
                current, active, resource_observed, response_completed = self.poll()
                fs = current["filesystem"]
                if response_completed > injection_deadline:
                    raise TimeoutError("controller injection deadline")
                if (
                    current["observed_at"] > sample["observed_at"]
                    and fs["inode_usage_percent"] >= config.trigger_percent
                    and fs["available_bytes"] > 0
                    and fs["block_usage_percent"] < effective_guard
                    and "threshold_observed" not in self.report["events"]
                ):
                    self.report["trigger_observation"] = current
                    self.event("threshold_observed", resource_observed)
                if "threshold_observed" in self.report["events"]:
                    if (
                        response_completed
                        - self.report["events"]["threshold_observed"]["monotonic_seconds"]
                        > 60
                    ):
                        raise TimeoutError("diagnosis timeout after threshold observation")
                    matching = None
                    for item in active:
                        matching = self.validate_incident_summary(item, config, status="active")
                        break
                    if matching:
                        self.report["owned_status_at_diagnosis"] = self.owned_status()
                        incident_id = matching["id"]
                        self.report["incident_id"] = incident_id
                        opening_detail = self.api.get("/diagnoses/" + incident_id)
                        detail_completed = self.monotonic()
                        if (
                            detail_completed
                            - self.report["events"]["threshold_observed"]["monotonic_seconds"]
                            > 60
                        ):
                            raise TimeoutError("diagnosis timeout after threshold observation")
                        opening_detail = self.validate_incident_detail(
                            opening_detail,
                            config,
                            effective_guard,
                            status="active",
                            incident_id=incident_id,
                        )
                        self.report["opening_detail"] = opening_detail
                        self.event("api_diagnosis", detail_completed)
                        break
                elif resource_observed > trigger_deadline:
                    raise TimeoutError("trigger observation timeout")
                self.sleep(max(0, 1 - (self.monotonic() - before)))
        except BaseException as exc:
            failure = exc
            self.report["errors"].append(type(exc).__name__ + ": " + str(exc))
        finally:
            if attempted:
                cleaned = False
                for number in range(3):
                    try:
                        result = self.injector.cleanup(self.report["token"])
                        self.report["cleanup_attempts"].append(
                            {"attempt": number + 1, "result": result}
                        )
                        if not result.get("cleanup_complete"):
                            raise ValueError("owned inode cleanup not confirmed")
                        cleaned = True
                        self.event("cleanup_complete")
                        break
                    except Exception as exc:
                        self.report["cleanup_attempts"].append(
                            {"attempt": number + 1, "error": type(exc).__name__ + ": " + str(exc)}
                        )
                        self.sleep(1)
                if cleaned and incident_id and "opening_detail" in self.report:
                    deadline = self.monotonic() + 60
                    try:
                        while True:
                            before = self.monotonic()
                            recovery, active, _, _ = self.poll()
                            resolved = (
                                self.api.get("/diagnoses/" + incident_id) if incident_id else None
                            )
                            resolution_completed = self.monotonic()
                            if resolution_completed > deadline:
                                raise TimeoutError("recovery timeout after cleanup")
                            if (
                                recovery["filesystem"]["inode_usage_percent"]
                                < config.recovery_percent
                                and not active
                            ):
                                resolved = self.validate_incident_detail(
                                    resolved,
                                    config,
                                    effective_guard,
                                    status="resolved",
                                    incident_id=incident_id,
                                )
                                if (
                                    resolved["opening_evidence"]
                                    != self.report["opening_detail"]["opening_evidence"]
                                ):
                                    raise ValueError(
                                        "inode incident opening evidence changed at resolution"
                                    )
                                self.validate_resolution_evidence(resolved, config)
                                self.report["recovery_observation"] = recovery
                                self.report["resolved_detail"] = resolved
                                self.event("api_resolution", resolution_completed)
                                break
                            self.sleep(max(0, 1 - (self.monotonic() - before)))
                    except BaseException as exc:
                        self.report["errors"].append(
                            "recovery: " + type(exc).__name__ + ": " + str(exc)
                        )
                elif not cleaned:
                    self.report["errors"].append(
                        "cleanup failed; independent watchdog must be checked"
                    )
            events = self.report["events"]
            if "api_diagnosis" in events:
                self.report["trigger_to_diagnosis_seconds"] = (
                    events["api_diagnosis"]["monotonic_seconds"]
                    - events["threshold_observed"]["monotonic_seconds"]
                )
                self.report["injection_to_diagnosis_seconds"] = (
                    events["api_diagnosis"]["monotonic_seconds"]
                    - events["injection_start"]["monotonic_seconds"]
                )
            self.report["status"] = (
                "passed"
                if incident_id and not self.report["errors"] and "api_resolution" in events
                else "failed"
            )
            self.event("finished")
            if acquired and (not attempted or self.report["status"] == "passed"):
                if lease.read_text() == self.report["token"]:
                    lease.unlink()
        if failure:
            raise failure
        if self.report["status"] != "passed":
            raise RuntimeError("inode run failed; inspect retained report and shared lease")
        return self.report
