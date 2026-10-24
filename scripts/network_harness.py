"""Measured network scenario driven only by production API observations."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy/network_resource.py"
Recorder = Callable[[str, dict[str, Any]], None]
Surrogate = Callable[[], dict[str, Any]]


class NetworkHarness:
    def __init__(
        self,
        api: str,
        node: str,
        reference_node: str,
        target: str,
        surrogate_url: str,
        *,
        client: httpx.Client | None = None,
        helper: Callable[[str, str, str, int], dict[str, Any]] | None = None,
        surrogate: Surrogate | None = None,
        recorder: Recorder | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.api = api.rstrip("/")
        self.node = node
        self.reference_node = reference_node
        self.target = target
        self.surrogate_url = surrogate_url
        self.client = client or httpx.Client(timeout=3, trust_env=False)
        self.helper = helper or self._helper
        self.surrogate = surrogate or self._surrogate
        self.recorder = recorder or (lambda _event, _value: None)
        self.monotonic, self.utcnow = monotonic, utcnow

    def _record(self, event: str, value: dict[str, Any]) -> None:
        self.recorder(event, value)

    def _helper(self, action: str, token: str, profile: str, duration: int) -> dict[str, Any]:
        argv = [sys.executable, str(HELPER), action, "--token", token]
        if action == "start":
            argv += ["--target", self.target, "--profile", profile, "--duration", str(duration)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
        if result.returncode:
            raise RuntimeError(f"network helper {action} failed: {result.stderr[-1000:]}")
        value: dict[str, Any] = json.loads(result.stdout)
        return value

    def _surrogate(self) -> dict[str, Any]:
        response = self.client.get(self.surrogate_url)
        response.raise_for_status()
        return {
            "status_code": response.status_code,
            "scope": "caller_network_namespace",
            "response_completed_monotonic": self.monotonic(),
            "response_completed_utc": self.utcnow().isoformat(),
        }

    def _get(self, path: str, **params: Any) -> tuple[dict[str, Any], float, str]:
        response = self.client.get(self.api + path, params=params or None)
        completed = self.monotonic()
        completed_utc = self.utcnow().isoformat()
        response.raise_for_status()
        value: dict[str, Any] = response.json()
        return value, completed, completed_utc

    def _node(self, node: str) -> tuple[dict[str, Any], float, str]:
        return self._get(f"/nodes/{node}/metrics")

    def _incident_ids(self) -> set[str]:
        value, _, _ = self._get(
            "/diagnoses", node=self.node, rule="network_path_degradation", limit=100
        )
        return {item["id"] for item in value["diagnoses"]}

    @staticmethod
    def _identity(node: dict[str, Any]) -> dict[str, Any]:
        sample = node.get("sample") or {}
        return {
            "boot_id": sample.get("boot_id"),
            "agent_session_id": sample.get("agent_session_id"),
            "sequence": sample.get("sequence"),
            "observed_at": sample.get("observed_at"),
        }

    def _healthy(self, node_id: str, config: dict[str, Any]) -> dict[str, Any]:
        node, completed, completed_utc = self._node(node_id)
        network = node.get("network") or {}
        probe, tcp, interfaces = (
            network.get("probe") or {},
            network.get("tcp") or {},
            network.get("interfaces") or [],
        )
        median = probe.get("median_rtt_ms")
        if not node.get("fresh") or probe.get("target") != self.target:
            raise ValueError(f"{node_id} lacks fresh exact-target telemetry")
        if probe.get("status") != "available" or probe.get("lost") != 0:
            raise ValueError(f"{node_id} lacks measured zero-loss baseline")
        if median is None or median >= config["recovery_rtt_ms"]:
            raise ValueError(f"{node_id} lacks healthy RTT baseline")
        if tcp.get("retrans_segs") is None or tcp.get("rate_status") != "available":
            raise ValueError(f"{node_id} lacks cumulative TCP rate baseline")
        if not interfaces or not all(
            set(item.get("rate_status", {}).values()) == {"available"} for item in interfaces
        ):
            raise ValueError(f"{node_id} lacks per-field interface rate baselines")
        active, _, _ = self._get(
            "/diagnoses", node=node_id, rule="network_path_degradation", status="active"
        )
        if active["total"]:
            raise ValueError(f"{node_id} already has an active network incident")
        return {
            "identity": self._identity(node),
            "probe": probe,
            "tcp": tcp,
            "interfaces": interfaces,
            "response_completed_monotonic": completed,
            "response_completed_utc": completed_utc,
        }

    def _admin_and_reference(self, config: dict[str, Any]) -> dict[str, Any]:
        health, completed, completed_utc = self._get("/health")
        if health.get("status") != "ok":
            raise ValueError("collector administration health is unavailable")
        reference = self._healthy(self.reference_node, config)
        reference.update(
            admin_health=health,
            admin_response_completed_monotonic=completed,
            admin_response_completed_utc=completed_utc,
        )
        return reference

    def _preflight(self, config: dict[str, Any]) -> dict[str, Any]:
        target, reference = self._healthy(self.node, config), self._admin_and_reference(config)
        probe = target["probe"]
        if probe.get("route_status") == "available":
            branch = "available_attribution"
        elif (
            probe.get("route_status") == "unavailable"
            and probe.get("route_error") == "route_netlink_denied"
            and probe.get("interface") is None
        ):
            branch = "netlink_denied_unknown_interface"
        else:
            raise ValueError("unsupported unknown-interface preflight reason")
        return {"branch": branch, "target": target, "reference": reference, "configuration": config}

    def _healthy_confirmations(
        self, after: dict[str, Any], deadline: float, config: dict[str, Any]
    ) -> list[dict[str, Any]]:
        confirmations: list[dict[str, Any]] = []
        expected = (after.get("boot_id"), after.get("agent_session_id"))
        after_sequence = after.get("sequence")
        last_sequence = int(after_sequence) if after_sequence is not None else -1
        last_observed: datetime | None = None
        last_polled = (
            expected[0],
            expected[1],
            last_sequence,
            after.get("observed_at"),
        )
        while self.monotonic() < deadline:
            try:
                target, reference = (
                    self._healthy(self.node, config),
                    self._admin_and_reference(config),
                )
                identity = target["identity"]
                completed = max(
                    float(target["response_completed_monotonic"]),
                    float(reference["response_completed_monotonic"]),
                    float(reference["admin_response_completed_monotonic"]),
                )
                if completed > deadline:
                    raise TimeoutError("healthy confirmation response completed after deadline")
                fingerprint = (
                    identity.get("boot_id"),
                    identity.get("agent_session_id"),
                    identity.get("sequence"),
                    identity.get("observed_at"),
                )
                if fingerprint == last_polled:
                    time.sleep(0.25)
                    continue
                observed = datetime.fromisoformat(identity["observed_at"])
                valid = bool(
                    (identity["boot_id"], identity["agent_session_id"]) == expected
                    and int(identity["sequence"]) > last_sequence
                    and (last_observed is None or observed > last_observed)
                    and (
                        last_observed is None
                        or (observed - last_observed).total_seconds() <= config["max_gap_seconds"]
                    )
                )
                if valid:
                    last_sequence, last_observed = int(identity["sequence"]), observed
                    last_polled = fingerprint
                    confirmations.append({**target, "reference": reference})
                    if len(confirmations) == config["consecutive_samples"]:
                        return confirmations
                else:
                    confirmations.clear()
                    expected = (identity.get("boot_id"), identity.get("agent_session_id"))
                    sequence = identity.get("sequence")
                    last_sequence = int(sequence) if sequence is not None else -1
                    last_observed = None
                    last_polled = fingerprint
            except (httpx.HTTPError, KeyError, TypeError, ValueError):
                confirmations.clear()
                last_observed = None
            time.sleep(0.25)
        raise TimeoutError("identity-bound fresh healthy confirmations missed deadline")

    def _qualifying_trigger(
        self,
        profile: str,
        after: dict[str, Any],
        config: dict[str, Any],
        deadline: float,
        trace: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        last_sequence = int(after["sequence"])
        expected = (after["boot_id"], after["agent_session_id"])
        previous_observed: datetime | None = datetime.fromisoformat(after["observed_at"])
        last_polled = (
            after.get("boot_id"),
            after.get("agent_session_id"),
            after.get("sequence"),
            after.get("observed_at"),
        )
        while self.monotonic() < deadline:
            reference = self._admin_and_reference(config)
            node, completed, completed_utc = self._node(self.node)
            reference_completed = max(
                float(reference["response_completed_monotonic"]),
                float(reference["admin_response_completed_monotonic"]),
            )
            if max(completed, reference_completed) > deadline:
                raise TimeoutError("trigger response completed after deadline")
            identity, probe = self._identity(node), (node.get("network") or {}).get("probe") or {}
            fingerprint = (
                identity.get("boot_id"),
                identity.get("agent_session_id"),
                identity.get("sequence"),
                identity.get("observed_at"),
            )
            if fingerprint == last_polled:
                time.sleep(0.25)
                continue
            observed = datetime.fromisoformat(identity["observed_at"])
            continuous = bool(
                (identity["boot_id"], identity["agent_session_id"]) == expected
                and int(identity["sequence"]) > last_sequence
                and (previous_observed is None or observed > previous_observed)
                and (
                    previous_observed is None
                    or (observed - previous_observed).total_seconds() <= config["max_gap_seconds"]
                )
            )
            reason = "qualifies"
            if (identity["boot_id"], identity["agent_session_id"]) != expected:
                reason = "identity_mismatch"
            elif int(identity["sequence"]) <= last_sequence:
                reason = "sequence_not_increasing"
            elif previous_observed is not None and observed <= previous_observed:
                reason = "observed_at_not_increasing"
            elif (
                previous_observed is not None
                and (observed - previous_observed).total_seconds() > config["max_gap_seconds"]
            ):
                reason = "sample_gap_exceeded"
            elif not node.get("fresh"):
                reason = "sample_not_fresh"
            elif probe.get("status") != "available":
                reason = "probe_" + str(probe.get("status", "missing"))
            elif probe.get("target") != self.target:
                reason = "target_mismatch"
            elif profile == "loss" and probe.get("lost", 0) < config["loss_trigger_packets"]:
                reason = "loss_below_threshold"
            elif profile == "latency" and (
                probe.get("median_rtt_ms") is None
                or probe["median_rtt_ms"] < config["rtt_trigger_ms"]
            ):
                reason = "latency_below_threshold"
            if trace is not None:
                entry = {
                    "identity": {
                        field: identity.get(field)
                        for field in ("boot_id", "agent_session_id", "sequence", "observed_at")
                    },
                    "fresh": bool(node.get("fresh")),
                    "probe": {
                        field: probe.get(field)
                        for field in (
                            "status",
                            "target",
                            "sent",
                            "received",
                            "lost",
                            "loss_ratio",
                            "median_rtt_ms",
                            "route_status",
                            "route_error",
                            "errors",
                        )
                    },
                    "response_completed_monotonic": completed,
                    "response_completed_utc": completed_utc,
                    "predicate_reason": reason,
                }
                observations = trace.setdefault("observations", [])
                if len(observations) < 32:
                    observations.append(entry)
                else:
                    trace["truncated_observations"] = trace.get("truncated_observations", 0) + 1
                trace["last_observation"] = entry
            qualifies = bool(
                continuous
                and node.get("fresh")
                and probe.get("status") == "available"
                and probe.get("target") == self.target
                and (
                    (profile == "loss" and probe.get("lost", 0) >= config["loss_trigger_packets"])
                    or (
                        profile == "latency"
                        and probe.get("median_rtt_ms") is not None
                        and probe["median_rtt_ms"] >= config["rtt_trigger_ms"]
                    )
                )
            )
            if qualifies:
                observation = {
                    "identity": identity,
                    "probe": probe,
                    "response_completed_monotonic": completed,
                    "response_completed_utc": completed_utc,
                    "reference": reference,
                }
                return {**observation, "qualifying_observations": [observation]}
            last_polled = fingerprint
            if continuous:
                last_sequence, previous_observed = int(identity["sequence"]), observed
            else:
                previous_observed = None
            time.sleep(0.25)
        raise TimeoutError("measured network trigger not observed")

    def _assert_incident(
        self,
        detail: dict[str, Any],
        profile: str,
        target: str,
        config: dict[str, Any],
        trigger: dict[str, Any],
    ) -> None:
        opening = detail.get("opening_evidence") or {}
        if (
            detail.get("node_id") != self.node
            or opening.get("node_id") != self.node
            or detail.get("rule") != "network_path_degradation"
            or detail.get("resource") != "ipv4:" + target
            or detail.get("severity") != config["severity"]
            or detail.get("configuration") != config
        ):
            raise ValueError("incident identity or frozen configuration mismatch")
        trigger_identity = trigger["identity"]
        for field in ("boot_id", "agent_session_id"):
            if opening.get(field) != trigger_identity.get(field):
                raise ValueError("incident evidence does not match trigger identity")
        try:
            opening_sequence = int(opening["sequence"])
            trigger_sequence = int(trigger_identity["sequence"])
            opening_observed = datetime.fromisoformat(opening["observed_at"])
            trigger_observed = datetime.fromisoformat(trigger_identity["observed_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("incident opening identity is malformed") from exc
        if opening_sequence < trigger_sequence or opening_observed < trigger_observed:
            raise ValueError("incident opening evidence predates the measured trigger")
        probe = opening.get("probe") or {}
        if (
            probe.get("target") != target
            or (profile == "loss" and probe.get("lost", 0) < config["loss_trigger_packets"])
            or (
                profile == "latency"
                and (
                    probe.get("median_rtt_ms") is None
                    or probe["median_rtt_ms"] < config["rtt_trigger_ms"]
                )
            )
        ):
            raise ValueError("incident opening evidence does not qualify for profile")

    def run_phase(self, profile: str, config: dict[str, Any]) -> dict[str, Any]:
        if profile not in ("latency", "loss"):
            raise ValueError("unknown network profile")
        phase: dict[str, Any] = {"profile": profile, "status": "running"}
        self._record(profile, phase)
        preflight = self._preflight(config)
        preflight["healthy_confirmations"] = self._healthy_confirmations(
            preflight["target"]["identity"], self.monotonic() + 60, config
        )
        preflight = {
            **self._preflight(config),
            "healthy_confirmations": preflight["healthy_confirmations"],
        }
        phase["preflight"] = preflight
        prior_ids, baseline_identity = self._incident_ids(), preflight["target"]["identity"]
        token = uuid4().hex
        injection_started = self.monotonic()
        phase.update(
            token=token,
            injection_started_monotonic=injection_started,
            injection_started_utc=self.utcnow().isoformat(),
        )
        deadline = injection_started + 60
        primary: BaseException | None = None
        cleanup_error: BaseException | None = None
        incident_id: str | None = None
        try:
            phase["helper_start"] = self.helper("start", token, profile, 90)
            self._record(profile, phase)
            phase["helper_status"] = self.helper("status", token, profile, 90)
            helper_status = phase["helper_status"]
            if helper_status["route_before"] != helper_status["route_active"]:
                raise ValueError("helper route changed during setup")
            if preflight["branch"] == "available_attribution":
                probe = preflight["target"]["probe"]
                if (
                    probe.get("interface") != helper_status["interface"]
                    or probe.get("interface_ifindex") != helper_status["ifindex"]
                ):
                    raise ValueError("agent and helper route attribution disagree")
            phase["surrogate"] = self.surrogate()
            if self.monotonic() > deadline:
                raise TimeoutError("helper or surrogate completed after trigger deadline")
            phase["trigger_probe_trace"] = {
                "limit": 32,
                "observations": [],
                "truncated_observations": 0,
                "last_observation": None,
            }
            phase["trigger_observation"] = self._qualifying_trigger(
                profile,
                baseline_identity,
                config,
                deadline,
                phase["trigger_probe_trace"],
            )
            trigger = phase["trigger_observation"]
            diagnosis_deadline = trigger["response_completed_monotonic"] + 60
            phase["diagnosis_deadline_monotonic"] = diagnosis_deadline
            while self.monotonic() < diagnosis_deadline:
                listed, list_completed, list_utc = self._get(
                    "/diagnoses", node=self.node, rule="network_path_degradation", status="active"
                )
                if list_completed > diagnosis_deadline:
                    raise TimeoutError("diagnosis list response completed after deadline")
                phase["last_diagnosis_list_response"] = listed
                matches = [
                    item
                    for item in listed["diagnoses"]
                    if item["id"] not in prior_ids and item["resource"] == "ipv4:" + self.target
                ]
                if matches:
                    incident_id = matches[0]["id"]
                    phase.update(
                        diagnosis_list_response_completed_monotonic=list_completed,
                        diagnosis_list_response_completed_utc=list_utc,
                    )
                    detail, detail_completed, detail_utc = self._get("/diagnoses/" + incident_id)
                    if detail_completed > diagnosis_deadline:
                        raise TimeoutError("diagnosis detail response completed after deadline")
                    self._assert_incident(detail, profile, self.target, config, trigger)
                    opening = detail["opening_evidence"]
                    opening_identity = {
                        field: opening.get(field)
                        for field in ("boot_id", "agent_session_id", "sequence", "observed_at")
                    }
                    observations = trigger.setdefault("qualifying_observations", [])
                    fingerprints = {
                        tuple(item["identity"].get(field) for field in opening_identity)
                        for item in observations
                    }
                    opening_fingerprint = tuple(opening_identity.values())
                    if opening_fingerprint not in fingerprints:
                        observations.append(
                            {
                                "identity": opening_identity,
                                "probe": opening.get("probe") or {},
                                "source": "incident_opening_evidence",
                            }
                        )
                    if (
                        preflight["branch"] == "netlink_denied_unknown_interface"
                        and detail["opening_evidence"]["probe"].get("interface") is not None
                    ):
                        raise ValueError("denied branch invented interface attribution")
                    phase.update(
                        incident_id=incident_id,
                        diagnosis_detail=detail,
                        diagnosis_detail_response_completed_monotonic=detail_completed,
                        diagnosis_detail_response_completed_utc=detail_utc,
                        trigger_to_diagnosis_seconds=detail_completed
                        - trigger["response_completed_monotonic"],
                        injection_to_diagnosis_seconds=detail_completed - injection_started,
                    )
                    break
                self._record(profile, phase)
                time.sleep(0.25)
            else:
                raise TimeoutError("matching diagnosis detail did not complete")
        except BaseException as exc:
            primary = exc
            phase["primary_failure"] = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                cleanup = self.helper("cleanup", token, profile, 90)
                phase["helper_cleanup"] = cleanup
                if (
                    cleanup.get("cleanup_complete") is not True
                    or cleanup.get("cleanup_phase") != "complete"
                    or cleanup.get("route_after") != cleanup.get("route_before")
                    or cleanup.get("restored_state") != cleanup.get("prestate")
                ):
                    raise ValueError("helper did not prove exact cleanup restoration")
            except BaseException as exc:
                cleanup_error = exc
                phase["cleanup_failure"] = f"{type(exc).__name__}: {exc}"
            self._record(profile, phase)
        recovery_error: BaseException | None = None
        try:
            recovery_started = self.monotonic()
            recovery_deadline = recovery_started + 60
            phase.update(
                recovery_started_monotonic=recovery_started,
                recovery_deadline_monotonic=recovery_deadline,
            )
            phase["healthy_confirmations"] = self._healthy_confirmations(
                baseline_identity, recovery_deadline, config
            )
            if incident_id is not None:
                while self.monotonic() < recovery_deadline:
                    detail, completed, completed_utc = self._get("/diagnoses/" + incident_id)
                    phase["last_recovery_detail"] = detail
                    if completed > recovery_deadline:
                        raise TimeoutError("recovery detail completed after deadline")
                    if detail["status"] == "resolved":
                        phase.update(
                            recovery_response_completed_monotonic=completed,
                            recovery_response_completed_utc=completed_utc,
                        )
                        break
                    time.sleep(0.25)
                else:
                    raise TimeoutError("matching incident did not resolve")
            phase["reference_final"] = self._admin_and_reference(config)
            final_completed = max(
                float(phase["reference_final"]["response_completed_monotonic"]),
                float(phase["reference_final"]["admin_response_completed_monotonic"]),
            )
            if final_completed > recovery_deadline:
                raise TimeoutError("final recovery health response completed after deadline")
        except BaseException as exc:
            recovery_error = exc
            phase["recovery_failure"] = f"{type(exc).__name__}: {exc}"
        if primary or cleanup_error or recovery_error:
            phase["status"] = "failed"
            self._record(profile, phase)
            raise RuntimeError(
                "; ".join(
                    phase[key]
                    for key in ("primary_failure", "cleanup_failure", "recovery_failure")
                    if key in phase
                )
            )
        phase["status"] = "passed"
        self._record(profile, phase)
        return phase

    def run(self) -> dict[str, Any]:
        configuration, _, _ = self._get("/configuration")
        config = configuration["network_rule"]
        result: dict[str, Any] = {
            "status": "running",
            "node": self.node,
            "reference_node": self.reference_node,
            "target": self.target,
            "configuration": config,
            "clock": "single_process_time.monotonic_with_utc_correlation",
        }
        self._record("scenario", result)
        result["latency"] = self.run_phase("latency", config)
        result["loss"] = self.run_phase("loss", config)
        result["scenario_latency_seconds"] = max(
            result["latency"]["trigger_to_diagnosis_seconds"],
            result["loss"]["trigger_to_diagnosis_seconds"],
        )
        result["status"] = "passed"
        self._record("scenario", result)
        return result
