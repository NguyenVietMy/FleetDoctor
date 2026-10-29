"""Measured DNS-failure scenario driven by completed production API responses."""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from fleetdoctor.dns import require_private_numeric_ingest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy/dns_resource.py"
Recorder = Callable[[str, dict[str, Any]], None]


class DnsHarness:
    def __init__(
        self,
        api: str,
        node: str,
        reference_node: str,
        *,
        client: httpx.Client | None = None,
        helper: Callable[[str, str, str, int], dict[str, Any]] | None = None,
        recorder: Recorder | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        require_private_numeric_ingest(api, allow_loopback=True)
        self.api = api.rstrip("/")
        self.node, self.reference_node = node, reference_node
        self.client = client or httpx.Client(timeout=3, trust_env=False)
        self.helper = helper or self._helper
        self.recorder = recorder or (lambda _event, _value: None)
        self.monotonic, self.utcnow = monotonic, utcnow

    def _record(self, event: str, value: dict[str, Any]) -> None:
        self.recorder(event, value)

    def _helper(self, action: str, token: str, invalid: str, duration: int) -> dict[str, Any]:
        argv = [sys.executable, str(HELPER), action, "--token", token]
        if action == "start":
            argv += ["--invalid-resolver", invalid, "--duration", str(duration)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
        if result.returncode:
            raise RuntimeError(f"DNS helper {action} failed: {result.stderr[-1000:]}")
        value: dict[str, Any] = json.loads(result.stdout)
        return value

    def _get(self, path: str, **params: Any) -> tuple[dict[str, Any], float, str]:
        response = self.client.get(self.api + path, params=params or None)
        completed = self.monotonic()
        completed_utc = self.utcnow().isoformat()
        response.raise_for_status()
        value: dict[str, Any] = response.json()
        return value, completed, completed_utc

    @staticmethod
    def _identity(view: dict[str, Any]) -> dict[str, Any]:
        sample = view.get("sample") or {}
        return {
            field: sample[field]
            for field in ("boot_id", "agent_session_id", "sequence", "observed_at")
        }

    @staticmethod
    def _fingerprint(identity: dict[str, Any]) -> tuple[str, str, int, str]:
        return (
            str(identity["boot_id"]),
            str(identity["agent_session_id"]),
            int(identity["sequence"]),
            str(identity["observed_at"]),
        )

    @staticmethod
    def _scope(dns: dict[str, Any]) -> tuple[str, str]:
        return str(dns["hostname"]), str(dns["direct_ip_target"])

    def _healthy(self, node: str, threshold: float) -> dict[str, Any]:
        view, completed, completed_utc = self._get(f"/nodes/{node}/metrics")
        dns, network = view.get("dns") or {}, view.get("network") or {}
        query, probe = dns.get("query") or {}, network.get("probe") or {}
        if not view.get("fresh") or query.get("status") != "success":
            raise ValueError(f"{node} lacks a fresh successful DNS query")
        if (
            probe.get("target") != dns.get("direct_ip_target")
            or probe.get("status") != "available"
            or probe.get("sent") != 3
            or probe.get("received") != 3
            or probe.get("lost") != 0
            or probe.get("median_rtt_ms") is None
            or probe["median_rtt_ms"] >= threshold
        ):
            raise ValueError(f"{node} lacks the exact healthy direct-IP predicate")
        return {
            "identity": self._identity(view),
            "dns": dns,
            "network": network,
            "response_completed_monotonic": completed,
            "response_completed_utc": completed_utc,
        }

    def _admin_and_reference(self, config: dict[str, Any]) -> dict[str, Any]:
        health, completed, completed_utc = self._get("/health")
        if health.get("status") != "ok":
            raise ValueError("collector administrative health unavailable")
        reference = self._healthy(self.reference_node, float(config["direct_ip_rtt_max_ms"]))
        reference.update(
            admin_health=health,
            admin_response_completed_monotonic=completed,
            admin_response_completed_utc=completed_utc,
        )
        return reference

    def _three_healthy(
        self,
        after: dict[str, Any],
        scope: tuple[str, str],
        config: dict[str, Any],
        deadline: float,
    ) -> list[dict[str, Any]]:
        accepted: list[dict[str, Any]] = []
        expected = (str(after["boot_id"]), str(after["agent_session_id"]))
        last_sequence = int(after["sequence"])
        last_observed = datetime.fromisoformat(str(after["observed_at"]))
        last_polled = self._fingerprint(after)
        while self.monotonic() < deadline:
            try:
                target = self._healthy(self.node, float(config["direct_ip_rtt_max_ms"]))
                reference = self._admin_and_reference(config)
                completed = max(
                    float(target["response_completed_monotonic"]),
                    float(reference["response_completed_monotonic"]),
                    float(reference["admin_response_completed_monotonic"]),
                )
                if completed > deadline:
                    raise TimeoutError("healthy confirmation response completed after deadline")
                identity = target["identity"]
                fingerprint = self._fingerprint(identity)
                if fingerprint == last_polled:
                    time.sleep(0.25)
                    continue
                observed = datetime.fromisoformat(str(identity["observed_at"]))
                valid = bool(
                    (str(identity["boot_id"]), str(identity["agent_session_id"])) == expected
                    and int(identity["sequence"]) > last_sequence
                    and observed > last_observed
                    and (observed - last_observed).total_seconds()
                    <= float(config["max_gap_seconds"])
                    and self._scope(target["dns"]) == scope
                )
                last_polled = fingerprint
                if valid:
                    last_sequence, last_observed = int(identity["sequence"]), observed
                    accepted.append({**target, "reference": reference})
                    if len(accepted) == int(config["consecutive_samples"]):
                        return accepted
                else:
                    accepted.clear()
            except (httpx.HTTPError, KeyError, TypeError, ValueError):
                accepted.clear()
            time.sleep(0.25)
        raise TimeoutError("identity- and scope-bound healthy confirmations missed deadline")

    def _active(self) -> tuple[dict[str, Any], float, str]:
        return self._get(
            "/diagnoses",
            node=self.node,
            rule="dns_resolution_failure",
            status="active",
            limit=100,
        )

    def _qualifying_trigger(
        self,
        after: dict[str, Any],
        scope: tuple[str, str],
        config: dict[str, Any],
        deadline: float,
        trace: dict[str, Any],
    ) -> dict[str, Any]:
        expected = (str(after["boot_id"]), str(after["agent_session_id"]))
        last_sequence = int(after["sequence"])
        last_observed = datetime.fromisoformat(str(after["observed_at"]))
        last_polled = self._fingerprint(after)
        while self.monotonic() < deadline:
            reference = self._admin_and_reference(config)
            view, completed, completed_utc = self._get(f"/nodes/{self.node}/metrics")
            completed_all = max(
                completed,
                float(reference["response_completed_monotonic"]),
                float(reference["admin_response_completed_monotonic"]),
            )
            if completed_all > deadline:
                raise TimeoutError("trigger response completed after deadline")
            identity = self._identity(view)
            fingerprint = self._fingerprint(identity)
            if fingerprint == last_polled:
                time.sleep(0.25)
                continue
            dns, network = view.get("dns") or {}, view.get("network") or {}
            query, probe = dns.get("query") or {}, network.get("probe") or {}
            observed = datetime.fromisoformat(str(identity["observed_at"]))
            continuous = bool(
                (str(identity["boot_id"]), str(identity["agent_session_id"])) == expected
                and int(identity["sequence"]) > last_sequence
                and observed > last_observed
                and (observed - last_observed).total_seconds() <= float(config["max_gap_seconds"])
                and self._scope(dns) == scope
            )
            qualifies = bool(
                continuous
                and view.get("fresh")
                and query.get("status") == "failure"
                and probe.get("status") == "available"
                and probe.get("target") == dns.get("direct_ip_target")
                and probe.get("sent") == 3
                and probe.get("received") == 3
                and probe.get("lost") == 0
                and probe.get("median_rtt_ms") is not None
                and probe["median_rtt_ms"] < config["direct_ip_rtt_max_ms"]
            )
            entry = {
                "identity": identity,
                "dns": dns,
                "network": network,
                "fresh": bool(view.get("fresh")),
                "predicate_reason": "qualifies" if qualifies else "predicate_or_identity_mismatch",
                "response_completed_monotonic": completed,
                "response_completed_utc": completed_utc,
                "reference": reference,
            }
            if len(trace["observations"]) < trace["limit"]:
                trace["observations"].append(entry)
            else:
                trace["truncated_observations"] += 1
            trace["last_observation"] = entry
            last_polled = fingerprint
            if continuous:
                last_sequence, last_observed = int(identity["sequence"]), observed
            if qualifies:
                return entry
            time.sleep(0.25)
        raise TimeoutError("matching DNS trigger missed deadline")

    def _assert_incident(
        self,
        detail: dict[str, Any],
        config: dict[str, Any],
        scope: tuple[str, str],
        trigger: dict[str, Any],
    ) -> None:
        opening = detail.get("opening_evidence") or {}
        probe = opening.get("direct_ip_probe") or {}
        trigger_identity = trigger["identity"]
        if (
            detail.get("node_id") != self.node
            or detail.get("rule") != "dns_resolution_failure"
            or detail.get("resource") != f"dns:{scope[0]}|ipv4:{scope[1]}"
            or detail.get("severity") != config["severity"]
            or detail.get("configuration") != config
            or opening.get("node_id") != self.node
            or self._scope(opening) != scope
            or (opening.get("query") or {}).get("status") != "failure"
            or probe.get("status") != "available"
            or probe.get("target") != scope[1]
            or probe.get("sent") != probe.get("received")
            or probe.get("sent") != 3
            or probe.get("lost") != 0
        ):
            raise ValueError("DNS incident identity, evidence, or frozen configuration mismatch")
        if any(
            str(opening.get(field)) != str(trigger_identity.get(field))
            for field in ("boot_id", "agent_session_id")
        ):
            raise ValueError("DNS incident opening scope does not match measured trigger")
        opening_sequence = int(opening["sequence"])
        trigger_sequence = int(trigger_identity["sequence"])
        opening_observed = datetime.fromisoformat(str(opening["observed_at"]))
        trigger_observed = datetime.fromisoformat(str(trigger_identity["observed_at"]))
        if opening_sequence < trigger_sequence or opening_observed < trigger_observed:
            raise ValueError("DNS incident opening evidence predates measured trigger")

    def run(
        self, *, invalid_resolver: str = "203.0.113.254", deadline_seconds: int = 60
    ) -> dict[str, Any]:
        configuration, _, _ = self._get("/configuration")
        config = configuration["dns_rule"]
        result: dict[str, Any] = {
            "status": "running",
            "node": self.node,
            "reference_node": self.reference_node,
            "configuration": config,
            "clock": "single_process_time.monotonic_with_utc_correlation",
            "started_utc": self.utcnow().isoformat(),
        }
        self._record("scenario", result)
        initial = self._healthy(self.node, float(config["direct_ip_rtt_max_ms"]))
        scope = self._scope(initial["dns"])
        baseline_deadline = self.monotonic() + deadline_seconds
        result["baseline"] = self._three_healthy(
            initial["identity"], scope, config, baseline_deadline
        )
        result["reference_before"] = self._admin_and_reference(config)
        active, active_completed, _ = self._active()
        if active_completed > baseline_deadline or active["total"]:
            raise ValueError("target already has an active DNS incident or preflight expired")
        prior_ids = {item["id"] for item in active["diagnoses"]}
        token = uuid4().hex
        result["token"] = token
        injection_started = self.monotonic()
        result.update(
            injection_started_monotonic=injection_started,
            injection_started_utc=self.utcnow().isoformat(),
        )
        trigger_deadline = injection_started + deadline_seconds
        primary: BaseException | None = None
        cleanup_error: BaseException | None = None
        recovery_error: BaseException | None = None
        incident_id: str | None = None
        cleanup_completed: float | None = None
        try:
            result["injection"] = self.helper(
                "start", token, invalid_resolver, deadline_seconds * 3
            )
            self._record("injection", result)
            result["trigger_trace"] = {
                "limit": 32,
                "observations": [],
                "truncated_observations": 0,
                "last_observation": None,
            }
            trigger = self._qualifying_trigger(
                result["baseline"][-1]["identity"],
                scope,
                config,
                trigger_deadline,
                result["trigger_trace"],
            )
            result["trigger"] = trigger
            diagnosis_deadline = float(trigger["response_completed_monotonic"]) + deadline_seconds
            result["diagnosis_deadline_monotonic"] = diagnosis_deadline
            self._record("trigger", result)
            while self.monotonic() < diagnosis_deadline:
                reference = self._admin_and_reference(config)
                active, listed_completed, listed_utc = self._active()
                completed = max(
                    listed_completed,
                    float(reference["response_completed_monotonic"]),
                    float(reference["admin_response_completed_monotonic"]),
                )
                if completed > diagnosis_deadline:
                    raise TimeoutError("diagnosis list response completed after deadline")
                matches = [
                    item
                    for item in active["diagnoses"]
                    if item["id"] not in prior_ids
                    and item["resource"] == f"dns:{scope[0]}|ipv4:{scope[1]}"
                ]
                result["last_diagnosis_list"] = active
                if matches:
                    incident_id = matches[0]["id"]
                    detail, detail_completed, detail_utc = self._get("/diagnoses/" + incident_id)
                    if detail_completed > diagnosis_deadline:
                        raise TimeoutError("diagnosis detail response completed after deadline")
                    self._assert_incident(detail, config, scope, trigger)
                    result["incident"] = {
                        "detail": detail,
                        "list_response_completed_monotonic": listed_completed,
                        "list_response_completed_utc": listed_utc,
                        "response_completed_monotonic": detail_completed,
                        "response_completed_utc": detail_utc,
                    }
                    result["diagnosis_seconds"] = detail_completed - float(
                        trigger["response_completed_monotonic"]
                    )
                    result["injection_to_diagnosis_seconds"] = detail_completed - injection_started
                    break
                self._record("diagnosis_poll", result)
                time.sleep(0.25)
            else:
                raise TimeoutError("matching DNS diagnosis missed deadline")
        except BaseException as exc:
            primary = exc
            result["primary_failure"] = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                result["cleanup"] = self.helper(
                    "cleanup", token, invalid_resolver, deadline_seconds * 3
                )
                cleanup_completed = self.monotonic()
                result["cleanup_response_completed_monotonic"] = cleanup_completed
                result["cleanup_response_completed_utc"] = self.utcnow().isoformat()
                if (
                    result["cleanup"].get("cleanup_complete") is not True
                    or result["cleanup"].get("cleanup_phase") != "complete"
                ):
                    raise ValueError("DNS helper did not prove completed cleanup")
            except BaseException as exc:
                cleanup_error = exc
                result["cleanup_failure"] = f"{type(exc).__name__}: {exc}"
            self._record("cleanup", result)
        if cleanup_completed is not None and cleanup_error is None:
            recovery_deadline = cleanup_completed + deadline_seconds
            result["recovery_deadline_monotonic"] = recovery_deadline
            try:
                after = (
                    (result.get("incident") or {}).get("detail", {}).get("opening_evidence")
                    or result.get("trigger", {}).get("identity")
                    or result["baseline"][-1]["identity"]
                )
                result["recovery"] = self._three_healthy(after, scope, config, recovery_deadline)
                if incident_id is not None:
                    while self.monotonic() < recovery_deadline:
                        reference = self._admin_and_reference(config)
                        detail, completed, completed_utc = self._get("/diagnoses/" + incident_id)
                        completed_all = max(
                            completed,
                            float(reference["response_completed_monotonic"]),
                            float(reference["admin_response_completed_monotonic"]),
                        )
                        if completed_all > recovery_deadline:
                            raise TimeoutError(
                                "resolution response completed after shared recovery deadline"
                            )
                        result["last_resolution_detail"] = detail
                        if detail["status"] == "resolved":
                            result["resolution"] = {
                                "detail": detail,
                                "response_completed_monotonic": completed,
                                "response_completed_utc": completed_utc,
                            }
                            result["recovery_seconds"] = completed - cleanup_completed
                            break
                        self._record("recovery_poll", result)
                        time.sleep(0.25)
                    else:
                        raise TimeoutError("DNS incident missed shared recovery deadline")
                result["reference_after"] = self._admin_and_reference(config)
                final_completed = max(
                    float(result["reference_after"]["response_completed_monotonic"]),
                    float(result["reference_after"]["admin_response_completed_monotonic"]),
                )
                if final_completed > recovery_deadline:
                    raise TimeoutError("final reference response completed after deadline")
            except BaseException as exc:
                recovery_error = exc
                result["recovery_failure"] = f"{type(exc).__name__}: {exc}"
        if primary or cleanup_error or recovery_error:
            result["status"] = "failed"
            self._record("scenario", result)
            raise RuntimeError(
                "; ".join(
                    result[key]
                    for key in ("primary_failure", "cleanup_failure", "recovery_failure")
                    if key in result
                )
            )
        result["status"] = "passed"
        result["diagnosis_under_30_seconds"] = float(result["diagnosis_seconds"]) < 30
        self._record("scenario", result)
        return result


def aggregate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "failed",
        "required_runs": 5,
        "attempts": runs,
        "complete_runs": 0,
        "aws_execution": False,
    }
    if len(runs) != 5:
        result["failure"] = "DNS aggregation requires exactly five retained attempts"
        return result
    scenarios = [run.get("scenario", run) for run in runs]
    complete = [
        (run, scenario)
        for run, scenario in zip(runs, scenarios, strict=True)
        if run.get("status") == "passed" and scenario.get("status") == "passed"
    ]
    result["complete_runs"] = len(complete)
    if len(complete) != 5:
        result["failure"] = "DNS aggregation requires five complete passed runs"
        return result
    comparable = {
        json.dumps(
            {
                "nodes": sorted([scenario["node"], scenario["reference_node"]]),
                "configuration": scenario["configuration"],
                "hostname": scenario["trigger"]["dns"]["hostname"],
                "target": scenario["trigger"]["dns"]["direct_ip_target"],
                "resolver_entry_type": scenario["injection"]["original"]["entry_type"],
                "source_manifest": run.get("source_manifest"),
                "environment_metadata": run.get("environment_metadata"),
                "topology": run.get("topology"),
            },
            sort_keys=True,
        )
        for run, scenario in complete
    }
    if len(comparable) != 1 or any(
        run.get("source_manifest") is None
        or run.get("environment_metadata") is None
        or run.get("topology") is None
        for run, _ in complete
    ):
        result["failure"] = "DNS measured runs are not source/config/runtime/topology comparable"
        return result
    timings = [float(scenario["diagnosis_seconds"]) for _, scenario in complete]
    result.update(
        diagnosis_seconds=timings,
        diagnosis_median_seconds=statistics.median(timings),
        slow_or_failed_attempts=[index for index, value in enumerate(timings) if value >= 30],
    )
    result["median_strictly_under_30_seconds"] = result["diagnosis_median_seconds"] < 30
    result["status"] = "passed" if result["median_strictly_under_30_seconds"] else "failed"
    if result["status"] == "failed":
        result["failure"] = "DNS diagnosis median is 30 seconds or more"
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--reference-node", required=True)
    parser.add_argument("--invalid-resolver", default="203.0.113.254")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    receipt: dict[str, Any] = {"status": "running", "events": []}

    def persist(event: str, value: dict[str, Any]) -> None:
        receipt["events"].append(
            {"event": event, "at": datetime.now(UTC).isoformat(), "snapshot": value}
        )
        temporary = args.output.with_suffix(args.output.suffix + ".partial")
        temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(args.output)

    try:
        receipt["scenario"] = DnsHarness(
            args.api, args.node, args.reference_node, recorder=persist
        ).run(invalid_resolver=args.invalid_resolver)
        receipt["status"] = "passed"
    except BaseException as exc:
        receipt["status"] = "failed"
        receipt["failure"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        receipt["finished_at"] = datetime.now(UTC).isoformat()
        temporary = args.output.with_suffix(args.output.suffix + ".partial")
        temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(args.output)


if __name__ == "__main__":
    main()
