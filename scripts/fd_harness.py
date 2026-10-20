"""Reusable bounded FD-pressure lifecycle harness with one monotonic clock."""

import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import uuid4

from chaos_harness import source_manifest, write_report


class Backend(Protocol):
    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]: ...


class Injector(Protocol):
    def start(self, token: str, limit: int, seconds: int) -> dict[str, Any]: ...
    def status(self, token: str) -> dict[str, Any]: ...
    def pressure(self, token: str) -> dict[str, Any]: ...
    def release(self, token: str) -> dict[str, Any]: ...
    def cleanup(self, token: str) -> dict[str, Any]: ...


class FdHarness:
    def __init__(
        self,
        api: Backend,
        injector: Injector,
        target: str,
        reference: str,
        output: Path,
        *,
        environment: dict[str, Any] | None = None,
        manifest: Callable[[], dict[str, Any]] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        token: str | None = None,
    ) -> None:
        if target == reference:
            raise ValueError("target and reference nodes must be distinct")
        self.api, self.injector = api, injector
        self.target, self.reference, self.output = target, reference, output
        self.monotonic, self.sleep = monotonic, sleep
        self.manifest = manifest or source_manifest
        self.after_diagnosis: Callable[[dict[str, Any], str], dict[str, Any]] | None = None
        self.report: dict[str, Any] = {
            "schema_version": 1,
            "scenario": "fd_pressure",
            "token": token or uuid4().hex,
            "target": target,
            "reference": reference,
            "environment": environment or {},
            "preparation_timeout_seconds": 30,
            "trigger_timeout_seconds": 30,
            "diagnosis_timeout_seconds": 60,
            "recovery_timeout_seconds": 60,
            "poll_interval_seconds": 1,
            "events": {},
            "polls": [],
            "cleanup_attempts": [],
            "errors": [],
            "status": "running",
            "source": self.manifest(),
        }

    def event(self, name: str, observed: float | None = None) -> None:
        self.report["events"][name] = {
            "monotonic_seconds": self.monotonic() if observed is None else observed,
            "utc": datetime.now(UTC).isoformat(),
        }
        write_report(self.output, self.report)

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        before = self.monotonic()
        value = self.api.get(path, params)
        after = self.monotonic()
        self.report["polls"].append(
            {
                "path": path,
                "params": params,
                "started_monotonic": before,
                "completed_monotonic": after,
                "response_seconds": after - before,
            }
        )
        write_report(self.output, self.report)
        return value

    def incidents(self, status: str) -> list[dict[str, Any]]:
        value = self.get(
            "/diagnoses",
            {"node": self.target, "rule": "fd_pressure", "status": status, "limit": 100},
        )
        return list(value.get("diagnoses", []))

    def validate_reference(self) -> None:
        value = self.get(f"/nodes/{self.reference}/metrics")
        if not value.get("fresh") or value.get("stale"):
            raise RuntimeError("healthy reference FD telemetry is not fresh")
        coverage = value.get("fd_coverage", {})
        if coverage.get("total", 0) <= 0 or coverage.get("observed", 0) <= 0:
            raise RuntimeError("healthy reference lacks measured ordinary FD coverage")
        rows = self.get(
            "/diagnoses",
            {"node": self.reference, "rule": "fd_pressure", "status": "active", "limit": 100},
        )
        if rows.get("diagnoses"):
            raise RuntimeError("healthy reference acquired an FD incident")

    @staticmethod
    def helper_identity(injection: dict[str, Any]) -> dict[str, Any]:
        return {
            "boot_id": str(injection["boot_id"]),
            "pid": int(injection["worker_pid"]),
            "starttime_ticks": int(injection["worker_starttime_ticks"]),
            "uid": int(injection["worker_uid"]),
        }

    @staticmethod
    def resource(identity: dict[str, Any]) -> str:
        return (
            f"boot:{identity['boot_id']}/pid:{identity['pid']}/start:{identity['starttime_ticks']}"
        )

    @staticmethod
    def evidence_identity(evidence: dict[str, Any]) -> dict[str, Any]:
        identity = evidence.get("identity") or {}
        return {
            "boot_id": str(identity.get("boot_id")),
            "pid": identity.get("pid"),
            "starttime_ticks": identity.get("starttime_ticks"),
        }

    @staticmethod
    def growth_is_consistent(observation: dict[str, Any]) -> bool:
        delta = observation.get("count_delta")
        rate = observation.get("growth_per_second")
        interval = observation.get("growth_interval_seconds")
        return (
            isinstance(delta, int)
            and not isinstance(delta, bool)
            and isinstance(rate, (int, float))
            and not isinstance(rate, bool)
            and isinstance(interval, (int, float))
            and not isinstance(interval, bool)
            and 0 < float(interval) <= 10
            and abs(float(rate) - delta / float(interval)) <= 0.000001
        )

    def exact_observation(
        self, node: dict[str, Any], identity: dict[str, Any]
    ) -> dict[str, Any] | None:
        observations = (node.get("fd") or {}).get("observations", [])
        matches = [
            item
            for item in observations
            if self.evidence_identity({"identity": item.get("identity")})
            == {key: identity[key] for key in ("boot_id", "pid", "starttime_ticks")}
        ]
        if len(matches) > 1:
            raise RuntimeError("duplicate exact helper identity in FD telemetry")
        return matches[0] if matches else None

    def validate_summary(
        self,
        summary: dict[str, Any],
        identifier: str,
        resource: str,
        status: str,
        frozen: dict[str, Any],
    ) -> None:
        if (
            str(summary.get("id")) != identifier
            or summary.get("node_id") != self.target
            or summary.get("rule") != "fd_pressure"
            or summary.get("resource") != resource
            or summary.get("status") != status
            or summary.get("configuration") != frozen
        ):
            raise RuntimeError("FD incident summary contradicts exact helper incident")

    def validate_detail(
        self,
        detail: dict[str, Any],
        identifier: str,
        resource: str,
        status: str,
        frozen: dict[str, Any],
        identity: dict[str, Any],
    ) -> None:
        self.validate_summary(detail, identifier, resource, status, frozen)
        expected_identity = {key: identity[key] for key in ("boot_id", "pid", "starttime_ticks")}
        for evidence_name in ("opening_evidence", "latest_evidence"):
            evidence = detail.get(evidence_name) or {}
            if self.evidence_identity(evidence) != expected_identity:
                raise RuntimeError(f"{evidence_name} does not identify the exact helper process")
            observation = evidence.get("observation") or {}
            observation_status = observation.get("status")
            if observation_status == "present" and not self.growth_is_consistent(observation):
                raise RuntimeError(f"{evidence_name} lacks a consistent signed FD count delta")
            if observation_status != "present" and any(
                observation.get(field) is not None
                for field in ("count_delta", "growth_per_second", "growth_interval_seconds")
            ):
                raise RuntimeError(f"{evidence_name} gives growth to a non-present FD identity")
        if not detail.get("evidence_fresh"):
            raise RuntimeError("FD detail evidence is not fresh")
        if status == "active" and (
            detail.get("resolution_reason") is not None
            or not detail.get("latest_evidence", {}).get("fd_available")
        ):
            raise RuntimeError("active FD detail is stale, unavailable, or already resolved")

    def run(self, mode: Literal["release", "exit"], limit: int = 128) -> dict[str, Any]:
        if self.output.exists():
            raise FileExistsError("refusing to overwrite FD harness report")
        failure: BaseException | None = None
        incident_id: str | None = None
        opening: dict[str, Any] | None = None
        try:
            configuration = self.get("/configuration")["fd_rule"]
            self.report["configuration"] = configuration
            self.validate_reference()
            self.report["injection"] = self.injector.start(self.report["token"], limit, 120)
            injection_completed = self.monotonic()
            self.event("prepared_worker_started", injection_completed)
            identity = self.helper_identity(self.report["injection"])
            if identity["uid"] == 0:
                raise RuntimeError("helper worker unexpectedly runs as root")
            resource = self.resource(identity)
            self.report["identity"] = identity
            self.report["resource"] = resource

            preparation_deadline = injection_completed + 30
            baseline = None
            while self.monotonic() <= preparation_deadline:
                self.validate_reference()
                helper = self.injector.status(self.report["token"])
                helper_after = self.monotonic()
                node = self.get(f"/nodes/{self.target}/metrics")
                observation = self.exact_observation(node, identity)
                exact_active = [
                    row for row in self.incidents("active") if row["resource"] == resource
                ]
                measurement = helper.get("measurement", {})
                if (
                    helper.get("owned")
                    and measurement.get("boot_id") == identity["boot_id"]
                    and measurement.get("pid") == identity["pid"]
                    and measurement.get("starttime_ticks") == identity["starttime_ticks"]
                    and float(measurement.get("pressure_ratio", 1))
                    < configuration["recovery_percent"] / 100
                    and node.get("fresh")
                    and observation is not None
                    and observation.get("configured") is True
                    and observation.get("status") == "present"
                    and observation.get("soft_limit") == limit
                    and self.growth_is_consistent(observation)
                    and float(observation.get("pressure_ratio", 1))
                    < configuration["recovery_percent"] / 100
                    and not exact_active
                ):
                    baseline = {
                        "helper": helper,
                        "telemetry": observation,
                        "observed_after_response": helper_after,
                    }
                    break
                self.sleep(1)
            if baseline is None:
                raise TimeoutError("fresh configured low-count growth baseline was not established")
            self.report["baseline"] = baseline
            self.event("low_baseline_observed")

            self.report["pressure_action"] = self.injector.pressure(self.report["token"])
            pressure_completed = self.monotonic()
            self.event("pressure_requested", pressure_completed)
            trigger_deadline = pressure_completed + 30
            actual_trigger = None
            while self.monotonic() <= trigger_deadline:
                before = self.monotonic()
                helper = self.injector.status(self.report["token"])
                after = self.monotonic()
                measurement = helper.get("measurement", {})
                self.report["polls"].append(
                    {
                        "operation": "helper_status_for_trigger",
                        "started_monotonic": before,
                        "completed_monotonic": after,
                        "response_seconds": after - before,
                        "pressure_ratio": measurement.get("pressure_ratio"),
                    }
                )
                if (
                    float(measurement.get("pressure_ratio", 0))
                    >= configuration["trigger_percent"] / 100
                ):
                    actual_trigger = {"observed_monotonic": after, "helper": helper}
                    break
                self.sleep(0.25)
            if actual_trigger is None:
                raise TimeoutError("helper did not reach the actual measured FD trigger")
            self.report["actual_trigger"] = actual_trigger
            trigger_value = actual_trigger["observed_monotonic"]
            if not isinstance(trigger_value, (int, float)):
                raise RuntimeError("invalid monotonic trigger timestamp")
            trigger_time = float(trigger_value)
            self.event("actual_resource_trigger_observed", trigger_time)

            diagnosis_deadline = trigger_time + 60
            while self.monotonic() <= diagnosis_deadline:
                self.validate_reference()
                rows = [row for row in self.incidents("active") if row["resource"] == resource]
                if len(rows) > 1:
                    raise RuntimeError("multiple active incidents match the exact helper identity")
                if rows:
                    summary = rows[0]
                    incident_id = str(summary["id"])
                    self.validate_summary(summary, incident_id, resource, "active", configuration)
                    detail = self.get("/diagnoses/" + incident_id)
                    detail_after = self.monotonic()
                    if detail_after > diagnosis_deadline:
                        raise TimeoutError("FD detail response arrived after diagnosis deadline")
                    self.validate_detail(
                        detail,
                        incident_id,
                        resource,
                        "active",
                        configuration,
                        identity,
                    )
                    observation = detail["opening_evidence"]["observation"]
                    if (
                        observation["descriptor_count"] / observation["soft_limit"]
                        < configuration["trigger_percent"] / 100
                    ):
                        raise RuntimeError("opening evidence is below its frozen FD threshold")
                    opening = detail
                    self.report["incident_summary"] = summary
                    self.report["incident"] = detail
                    self.report["timing"] = {
                        "injection_to_diagnosis_seconds": detail_after - injection_completed,
                        "threshold_to_api_seconds": detail_after - trigger_time,
                        "diagnosis_poll_delay_seconds": self.report["polls"][-1][
                            "response_seconds"
                        ],
                    }
                    self.event("matching_incident_observed", detail_after)
                    if self.after_diagnosis is not None:
                        restart = self.after_diagnosis(detail, incident_id)
                        restarted_detail = self.get("/diagnoses/" + incident_id)
                        self.validate_detail(
                            restarted_detail,
                            incident_id,
                            resource,
                            "active",
                            configuration,
                            identity,
                        )
                        if restarted_detail["opening_evidence"] != detail["opening_evidence"]:
                            raise RuntimeError(
                                "FD opening evidence changed across collector restart"
                            )
                        self.report["restart"] = restart
                        self.report["incident_after_restart"] = restarted_detail
                    break
                self.sleep(1)
            if incident_id is None or opening is None:
                raise TimeoutError("exact FD incident did not open within 60 seconds of trigger")

            if mode == "release":
                self.report["release"] = self.injector.release(self.report["token"])
                recovery_trigger = self.monotonic()
                release_measurement = self.report["release"]["measurement"]
                if (
                    float(release_measurement["pressure_ratio"])
                    >= configuration["recovery_percent"] / 100
                ):
                    raise RuntimeError("release action did not produce actual recovery pressure")
            else:
                self.report["exit"] = self.injector.cleanup(self.report["token"])
                recovery_trigger = self.monotonic()
                if self.injector.status(self.report["token"]).get("owned"):
                    raise RuntimeError("exit action retained helper ownership")
            self.event("actual_recovery_trigger_observed", recovery_trigger)

            recovery_deadline = recovery_trigger + 60
            while self.monotonic() <= recovery_deadline:
                self.validate_reference()
                rows = [row for row in self.incidents("resolved") if str(row["id"]) == incident_id]
                if rows:
                    summary = rows[0]
                    self.validate_summary(summary, incident_id, resource, "resolved", configuration)
                    detail = self.get("/diagnoses/" + incident_id)
                    detail_after = self.monotonic()
                    if detail_after > recovery_deadline:
                        raise TimeoutError("FD detail response arrived after recovery deadline")
                    self.validate_detail(
                        detail,
                        incident_id,
                        resource,
                        "resolved",
                        configuration,
                        identity,
                    )
                    expected = "descriptor_release" if mode == "release" else "confirmed_exit"
                    if detail.get("resolution_reason") != expected:
                        raise RuntimeError("FD resolution reason contradicts measured lifecycle")
                    if detail["opening_evidence"] != opening["opening_evidence"]:
                        raise RuntimeError("immutable FD opening evidence changed")
                    latest = detail["latest_evidence"]
                    observation = latest.get("observation") or {}
                    descriptor_count = observation.get("descriptor_count")
                    soft_limit = observation.get("soft_limit")
                    if mode == "release" and (
                        not latest.get("fd_available")
                        or observation.get("status") != "present"
                        or not isinstance(descriptor_count, (int, float))
                        or not isinstance(soft_limit, (int, float))
                        or soft_limit <= 0
                        or descriptor_count / soft_limit >= configuration["recovery_percent"] / 100
                    ):
                        raise RuntimeError(
                            "release resolution lacks fresh exact low-count evidence"
                        )
                    if mode == "exit" and (
                        latest.get("fd_available")
                        or latest.get("status") not in {"exited", "replaced"}
                    ):
                        raise RuntimeError("exit resolution lacks fresh exact-exit evidence")
                    self.report["recovery_summary"] = summary
                    self.report["recovery"] = detail
                    self.report["timing"]["recovery_to_api_seconds"] = (
                        detail_after - recovery_trigger
                    )
                    self.report["status"] = "passed"
                    self.event("matching_recovery_observed", detail_after)
                    break
                self.sleep(1)
            else:
                raise TimeoutError("exact FD incident did not resolve within 60 seconds")
        except BaseException as exc:
            failure = exc
            self.report["errors"].append(f"{type(exc).__name__}: {exc}")
            self.report["status"] = "failed"
        finally:
            try:
                cleanup = self.injector.cleanup(self.report["token"])
                self.report["cleanup_attempts"].append(cleanup)
                status_after = self.injector.status(self.report["token"])
                if status_after.get("owned"):
                    raise RuntimeError("FD helper remained owned after cleanup")
            except BaseException as exc:
                self.report["cleanup_attempts"].append(
                    {"cleaned": False, "error": f"{type(exc).__name__}: {exc}"}
                )
                failure = failure or exc
                self.report["status"] = "failed"
            self.report["source_after"] = self.manifest()
            if self.report["source"] != self.report["source_after"]:
                failure = failure or RuntimeError("source changed during FD harness")
                self.report["status"] = "failed"
            self.report["finished_at"] = datetime.now(UTC).isoformat()
            write_report(self.output, self.report)
        if failure is not None:
            raise RuntimeError(
                "FD harness failed; retained report: " + str(self.output)
            ) from failure
        return self.report
