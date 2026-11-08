"""Single-clock I/O diagnosis harness with response-completion deadlines and exact cleanup."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from chaos_harness import source_manifest, write_report

RULE_CONFIGURATION: dict[str, Any] = {
    "trigger_latency_ms": 20.0,
    "trigger_outstanding": 1.0,
    "recovery_latency_ms": 10.0,
    "recovery_outstanding": 0.5,
    "consecutive_samples": 3,
    "max_gap_seconds": 10.0,
    "severity": "warning",
}


class API(Protocol):
    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]: ...


class Injector(Protocol):
    def start(self, token: str, duration: int) -> dict[str, Any]: ...
    def status(self, token: str) -> dict[str, Any]: ...
    def cleanup(self, token: str) -> dict[str, Any]: ...


class IoHarness:
    def __init__(
        self,
        api: API,
        injector: Injector,
        token: str,
        output: Path,
        *,
        target: str = "node-a",
        reference: str = "node-b",
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
        frozen_source: dict[str, Any] | None = None,
    ) -> None:
        if target == reference:
            raise ValueError("target and reference must differ")
        self.api, self.injector, self.token, self.output = api, injector, token, output
        self.target, self.reference = target, reference
        self.monotonic, self.sleep, self.utcnow = monotonic, sleep, utcnow
        self.report: dict[str, Any] = {
            "status": "running",
            "scenario": "io_bottleneck",
            "token": token,
            "target": target,
            "reference": reference,
            "diagnosis_timeout_seconds": 60,
            "recovery_timeout_seconds": 60,
            "configuration": dict(RULE_CONFIGURATION),
            "source": source_manifest() if frozen_source is None else frozen_source,
            "baseline_polls": [],
            "diagnosis_polls": [],
            "recovery_polls": [],
            "cleanup": [],
            "events": {},
        }

    def event(self, name: str, observed: float | None = None) -> float:
        completed = self.monotonic() if observed is None else observed
        self.report["events"][name] = {
            "monotonic": completed,
            "utc": self.utcnow().isoformat(),
        }
        write_report(self.output, self.report)
        return completed

    def metrics(self, node: str) -> tuple[dict[str, Any], float]:
        value = self.api.get(f"/nodes/{node}/metrics")
        return value, self.monotonic()

    @staticmethod
    def identity(view: dict[str, Any]) -> tuple[str, str, int, str]:
        sample = view.get("sample") or {}
        return (
            str(sample.get("boot_id")),
            str(sample.get("agent_session_id")),
            int(sample.get("sequence", 0)),
            str(sample.get("observed_at")),
        )

    @staticmethod
    def healthy(device: dict[str, Any]) -> bool:
        return bool(
            device.get("rate_status") == "available"
            and (
                device.get("confirmed_idle") is True
                or (
                    device.get("completion_latency_ms") is not None
                    and device["completion_latency_ms"] < RULE_CONFIGURATION["recovery_latency_ms"]
                    and device.get("average_outstanding") is not None
                    and device["average_outstanding"] < RULE_CONFIGURATION["recovery_outstanding"]
                )
            )
        )

    @staticmethod
    def only_device(view: dict[str, Any]) -> dict[str, Any] | None:
        devices = (view.get("io") or {}).get("devices", [])
        return devices[0] if len(devices) == 1 else None

    def require_reference(self, expected_resource: str | None = None) -> dict[str, Any]:
        view, completed = self.metrics(self.reference)
        device = self.only_device(view)
        if (
            not view.get("fresh")
            or view.get("active_incident_count") != 0
            or device is None
            or not self.healthy(device)
            or (expected_resource is not None and device.get("resource") != expected_resource)
        ):
            raise ValueError("healthy reference unavailable")
        return {"view": view, "response_completed": completed}

    def incidents(self, status: str) -> list[dict[str, Any]]:
        return list(
            self.api.get(
                "/diagnoses",
                {
                    "node": self.target,
                    "rule": "io_bottleneck",
                    "status": status,
                    "limit": 100,
                },
            )["diagnoses"]
        )

    def baselines(self) -> tuple[str, str]:
        deadline = self.monotonic() + 45
        accepted: dict[str, list[dict[str, Any]]] = {self.target: [], self.reference: []}
        while self.monotonic() < deadline and any(len(rows) < 3 for rows in accepted.values()):
            for node in (self.target, self.reference):
                view, completed = self.metrics(node)
                identity = self.identity(view)
                device = self.only_device(view)
                row = {"identity": identity, "view": view, "response_completed": completed}
                self.report["baseline_polls"].append({"node": node, **row})
                if (
                    view.get("fresh")
                    and view.get("active_incident_count") == 0
                    and device is not None
                    and self.healthy(device)
                    and identity not in {tuple(item["identity"]) for item in accepted[node]}
                ):
                    accepted[node].append(row)
            self.sleep(1)
        if any(len(rows) < 3 for rows in accepted.values()):
            raise TimeoutError("three distinct fresh healthy baselines unavailable")
        target_device = self.only_device(accepted[self.target][-1]["view"])
        reference_device = self.only_device(accepted[self.reference][-1]["view"])
        assert target_device is not None and reference_device is not None
        if target_device["resource"] == reference_device["resource"]:
            raise ValueError("target and reference require distinct durable resources")
        if self.incidents("active"):
            raise ValueError("target already has an active I/O incident")
        self.report["healthy_baselines"] = accepted
        self.report["frozen"] = {
            "target_resource": target_device["resource"],
            "reference_resource": reference_device["resource"],
            "target_mapping": target_device,
            "reference_mapping": reference_device,
            "configuration": dict(RULE_CONFIGURATION),
        }
        self.event("baseline_complete")
        return str(target_device["resource"]), str(reference_device["resource"])

    def diagnose(self, target_resource: str, reference_resource: str) -> dict[str, Any]:
        self.report["start"] = self.injector.start(self.token, 45)
        injection = self.event("injection_started")
        first_trigger: float | None = None
        trigger_deadline = injection + 60
        while self.monotonic() < trigger_deadline:
            target, target_completed = self.metrics(self.target)
            self.require_reference(reference_resource)
            device = next(
                (
                    item
                    for item in (target.get("io") or {}).get("devices", [])
                    if item.get("resource") == target_resource
                ),
                None,
            )
            eligible = bool(
                target.get("fresh")
                and device is not None
                and device.get("rate_status") == "available"
                and device.get("completion_latency_ms") is not None
                and device["completion_latency_ms"] >= RULE_CONFIGURATION["trigger_latency_ms"]
                and device.get("average_outstanding") is not None
                and device["average_outstanding"] >= RULE_CONFIGURATION["trigger_outstanding"]
            )
            if eligible and first_trigger is None:
                first_trigger = target_completed
                trigger_deadline = first_trigger + 60
                self.report["first_trigger"] = device
                self.event("first_trigger_response_complete", first_trigger)
            active = self.incidents("active")
            matching = next(
                (
                    item
                    for item in active
                    if item.get("node_id") == self.target
                    and item.get("rule") == "io_bottleneck"
                    and item.get("resource") == target_resource
                    and item.get("status") == "active"
                ),
                None,
            )
            self.report["diagnosis_polls"].append(
                {
                    "target_response_completed": target_completed,
                    "identity": self.identity(target),
                    "eligible": eligible,
                    "matching": matching,
                }
            )
            if first_trigger is not None and matching is not None:
                detail = self.api.get("/diagnoses/" + matching["id"])
                detail_completed = self.monotonic()
                if detail_completed > trigger_deadline:
                    raise TimeoutError("matching diagnosis detail completed after shared deadline")
                if (
                    detail.get("node_id") != self.target
                    or detail.get("rule") != "io_bottleneck"
                    or detail.get("resource") != target_resource
                    or detail.get("configuration") != RULE_CONFIGURATION
                    or detail.get("opening_evidence", {}).get("resource") != target_resource
                ):
                    raise ValueError("incident detail does not match frozen opening contract")
                self.report["diagnosis"] = detail
                self.report["injection_to_diagnosis_seconds"] = detail_completed - injection
                self.report["trigger_to_diagnosis_seconds"] = detail_completed - first_trigger
                self.event("diagnosis_detail_complete", detail_completed)
                return detail
            self.sleep(1)
        raise TimeoutError("no qualifying completed diagnosis")

    def recover(
        self,
        incident: dict[str, Any],
        target_resource: str,
        reference_resource: str,
        boundary: float,
    ) -> dict[str, Any]:
        deadline = boundary + 60
        accepted: list[dict[str, Any]] = []
        previous: tuple[str, str, int, str] | None = None
        while self.monotonic() < deadline:
            target, completed = self.metrics(self.target)
            self.require_reference(reference_resource)
            identity = self.identity(target)
            device = next(
                (
                    item
                    for item in (target.get("io") or {}).get("devices", [])
                    if item.get("resource") == target_resource
                ),
                None,
            )
            replay = previous is not None and identity == previous
            continuous = bool(
                previous is None
                or (
                    identity[0] == previous[0]
                    and identity[1] == previous[1]
                    and identity[2] > previous[2]
                    and (
                        datetime.fromisoformat(identity[3]) - datetime.fromisoformat(previous[3])
                    ).total_seconds()
                    <= float(RULE_CONFIGURATION["max_gap_seconds"])
                )
            )
            healthy_new = bool(
                not replay
                and target.get("fresh")
                and device is not None
                and self.healthy(device)
                and continuous
            )
            if healthy_new:
                accepted.append(
                    {"identity": identity, "device": device, "response_completed": completed}
                )
                previous = identity
            elif not replay:
                accepted = []
                previous = None
            detail = self.api.get("/diagnoses/" + incident["id"])
            detail_completed = self.monotonic()
            self.report["recovery_polls"].append(
                {
                    "identity": identity,
                    "replay": replay,
                    "healthy_new": healthy_new,
                    "accepted": len(accepted),
                    "status": detail.get("status"),
                    "detail_response_completed": detail_completed,
                }
            )
            if detail.get("status") == "superseded":
                raise ValueError("superseded incident is not healthy recovery")
            if detail.get("status") == "resolved" and len(accepted) >= 3:
                if detail_completed > deadline or detail.get("resource") != target_resource:
                    raise TimeoutError("matching resolved detail missed recovery contract")
                self.report["resolved"] = detail
                self.report["recovery_identities"] = accepted
                self.report["recovery_elapsed_seconds"] = detail_completed - boundary
                self.event("resolved_detail_complete", detail_completed)
                return detail
            self.sleep(1)
        raise TimeoutError("automatic recovery deadline")

    def run(self) -> dict[str, Any]:
        failure: BaseException | None = None
        incident: dict[str, Any] | None = None
        target_resource = reference_resource = ""
        boundary: float | None = None
        try:
            target_resource, reference_resource = self.baselines()
            incident = self.diagnose(target_resource, reference_resource)
        except BaseException as exc:
            failure = exc
            self.report["failure"] = type(exc).__name__ + ": " + str(exc)
        finally:
            boundary = self.event("stop_requested")
            try:
                self.report["cleanup"].append(self.injector.cleanup(self.token))
                self.event("cleanup_complete")
            except BaseException as exc:
                self.report["cleanup_error"] = repr(exc)
                failure = failure or exc
        if failure is None and incident is not None:
            try:
                assert boundary is not None
                self.recover(incident, target_resource, reference_resource, boundary)
            except BaseException as exc:
                failure = exc
                self.report["failure"] = type(exc).__name__ + ": " + str(exc)
        self.report["status"] = "failed" if failure is not None else "passed"
        write_report(self.output, self.report)
        if failure is not None:
            raise failure
        return self.report
