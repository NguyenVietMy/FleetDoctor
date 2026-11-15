from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import campaign_connection as connection
import chaos_campaign as campaign
import pytest
from chaos_campaign import (
    ADAPTERS,
    ASSIGNMENT,
    BASELINE,
    PLAN_SHA256,
    SCENARIOS,
    AdapterContext,
    attempt_token,
    campaign_lock,
    digest,
    lab_lease_path,
    oom_leaf_path,
    recover_campaign_lock,
    stable_lab_identity,
    validate_attempts,
    validate_manifest,
)
from chaos_oom import generation_key


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def monotonic(self) -> float:
        self.now += 0.01
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, dict[str, Any]]] = []
        self.cgroups: list[str] = []
        self.pids: list[int] = []

    def inventory(self) -> dict[str, Any]:
        snapshot = {
            "env_sha256": "a" * 64,
            "selectors": {
                "FLEETDOCTOR_CGROUPS": self.cgroups,
                "FLEETDOCTOR_CPU_PIDS": self.pids,
            },
            "missing_keys": [],
        }
        return {
            **snapshot,
            "mode": 0o600,
            "uid": 0,
            "gid": 0,
            "service_state": {"ActiveState": "active", "UnitFileState": "enabled"},
        }

    def call(
        self, scenario: str, action: str, token: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        self.calls.append((scenario, action, token, arguments or {}))
        if scenario == "config" and action == "inventory":
            return self.inventory()
        if scenario == "config" and action == "status":
            return {
                "phase": "active",
                "current_sha256": "a" * 64,
                "changes": {"FLEETDOCTOR_CGROUPS": ",".join(self.cgroups)},
            }
        if scenario == "config" and action == "begin":
            before = arguments["expected_before"] if arguments else {}
            if arguments and "FLEETDOCTOR_CPU_PIDS" in arguments["changes"]:
                self.pids = [
                    int(item) for item in arguments["changes"]["FLEETDOCTOR_CPU_PIDS"].split(",")
                ]
            return {"phase": "applied", "original_selectors": before}
        if action in {"cleanup", "release", "destroy"}:
            return {"cleaned": True, "released": True}
        if scenario == "config" and action == "restore":
            return {"phase": "restored"}
        return {"owned": True, "phase": action}


def context(
    tmp_path: Path,
    scenario: str,
    *,
    api: Any = None,
    transport: Any = None,
    clock: Any = None,
) -> AdapterContext:
    selected_transport = transport or RecordingTransport()
    value = manifest()
    if isinstance(selected_transport, RecordingTransport):
        selected_transport.cgroups = [
            *value["resources"]["oom"]["existing_cgroups"]["node-a"],
            *value["resources"]["oom"]["leaf_paths"],
        ]
    return AdapterContext(
        api=api,
        transport=selected_transport,
        manifest=value,
        target="node-a",
        reference="node-b",
        repetition=0,
        output=tmp_path / f"{scenario}.json",
        token="a" * 32,
        clock=clock or FakeClock(),
        transports={"node-a": selected_transport, "node-b": selected_transport},
    )


def manifest() -> dict[str, Any]:
    source_hashes = {"scripts/chaos_campaign.py": "a" * 64}
    instances = {
        role: {
            "id": "i-" + character * 8,
            "private_ip": f"10.0.0.{index}",
            "type": "t3.small",
            "kernel": "6.1",
            "cpu_credit_mode": "standard",
            "cpu_credit_balance": 100.0,
            "state": "running",
        }
        for index, (role, character) in enumerate(
            (("monitor", "a"), ("node-a", "b"), ("node-b", "c")), start=10
        )
    }
    result: dict[str, Any] = {
        "schema_version": 2,
        "kind": "measured",
        "batch_id": "batch-1",
        "baseline": BASELINE,
        "plan_sha256": PLAN_SHA256,
        "original_plan_sha256": campaign.ORIGINAL_PLAN_SHA256,
        "ticket14_gate": {
            "status": "passed",
            "revision": BASELINE,
            "coverage_receipt_sha256": "d" * 64,
        },
        "source": {
            "revision": BASELINE,
            "dirty": True,
            "sha256": source_hashes,
            "aggregate_sha256": digest(source_hashes),
        },
        "installed": {
            "monitor": {
                "source": "1" * 64,
                "controller": "2" * 64,
                "config_transaction": "3" * 64,
                "protected_manifest": "c" * 64,
                "controller_bundle": "d" * 64,
            },
            "node-a": {
                "source": "4" * 64,
                "controller": "5" * 64,
                "config_transaction": "6" * 64,
                "helpers": "7" * 64,
                "protected_manifest": "e" * 64,
                "controller_bundle": "f" * 64,
            },
            "node-b": {
                "source": "8" * 64,
                "controller": "9" * 64,
                "config_transaction": "a" * 64,
                "helpers": "b" * 64,
                "protected_manifest": "1" * 64,
                "controller_bundle": "2" * 64,
            },
        },
        "configuration": {
            "collector": {"disk_rule": {"trigger_percent": 95}, "cadence_seconds": 5},
            "sha256": digest({"disk_rule": {"trigger_percent": 95}, "cadence_seconds": 5}),
        },
        "lab": {
            "account_id": "123456789012",
            "region": "us-east-1",
            "availability_zone": "us-east-1a",
            "instances": instances,
        },
        "platform": {"node-a": {"online_logical_cores": 2}, "node-b": {"online_logical_cores": 2}},
        "resources": {
            "api_url": "http://10.0.0.10:8000",
            "oom": {
                "leaf_paths": [],
                "existing_cgroups": {"monitor": [], "node-a": [], "node-b": []},
            },
            "fd": {
                "node-a": {"existing_cpu_pids": []},
                "node-b": {"existing_cpu_pids": []},
            },
            "network": {
                "probe_target": "10.0.0.10",
                "surrogate_url": "http://10.0.0.10:8000/health",
            },
        },
        "cadence_seconds": 5,
        "deadlines": {
            "preparation_seconds": 60,
            "trigger_seconds": 60,
            "diagnosis_seconds": 60,
            "recovery_seconds": 60,
        },
        "assignments": {scenario: list(ASSIGNMENT) for scenario in SCENARIOS},
        "supersedes": [],
        "evidence_class": "synthetic",
        "runtime_receipt_sha256": "e" * 64,
        "preparation_receipt_sha256": "f" * 64,
        "connection_receipt_sha256": "0" * 64,
    }
    result["resources"]["oom"]["leaf_paths"] = [
        oom_leaf_path(attempt_token(result, "oom", repetition, target))
        for repetition, target in enumerate(result["assignments"]["oom"])
    ]
    return result


def connection_receipt(value: dict[str, Any]) -> dict[str, Any]:
    public_key = "ssh-ed25519 AAAA"
    fingerprint = connection._fingerprint(public_key)
    roles: dict[str, Any] = {}
    for index, role in enumerate(("monitor", "node-a", "node-b"), start=20):
        instance = value["lab"]["instances"][role]
        ssh_host = f"198.51.100.{index}"
        inventory = {
            "account_id": value["lab"]["account_id"],
            "region": value["lab"]["region"],
            "availability_zone": value["lab"]["availability_zone"],
            "role": role,
            "instance_id": instance["id"],
            "private_ip": instance["private_ip"],
            "boot_id": f"00000000-0000-0000-0000-0000000000{index}",
            "ssh_host": ssh_host,
            "ssh_port": 22,
        }
        host_key_attestation = {
            "host": ssh_host,
            "port": 22,
            "algorithm": "ssh-ed25519",
            "public_key": public_key,
            "fingerprint": fingerprint,
        }
        roles[role] = {
            "instance_id": instance["id"],
            "private_ip": instance["private_ip"],
            "boot_id": inventory["boot_id"],
            "ssh_host": ssh_host,
            "ssh_port": 22,
            "host_public_key": public_key,
            "host_key_fingerprint": fingerprint,
            "protected_manifest_sha256": value["installed"][role]["protected_manifest"],
            "controller_bundle_sha256": value["installed"][role]["controller_bundle"],
            "inventory": inventory,
            "inventory_sha256": digest(inventory),
            "host_key_attestation": host_key_attestation,
            "host_key_attestation_sha256": digest(host_key_attestation),
        }
    receipt = {
        "schema_version": 1,
        "batch_id": value["batch_id"],
        "checked_at": datetime.now(UTC).isoformat(),
        "plan_sha256": PLAN_SHA256,
        "lab": value["lab"],
        "roles": roles,
    }
    value["connection_receipt_sha256"] = digest(receipt)
    return receipt


def hello_receipt(
    live_connection: dict[str, Any], role: str, *, nonce: str = "1", session: str = "2"
) -> dict[str, Any]:
    facts = live_connection["roles"][role]
    return {
        "type": "hello",
        "ok": True,
        "batch_id": live_connection["batch_id"],
        "nonce": nonce * 64,
        "session_id": session * 64,
        "protected_manifest_sha256": facts["protected_manifest_sha256"],
        "controller_bundle_sha256": facts["controller_bundle_sha256"],
        "identity": {
            "role": role,
            "account_id": facts["inventory"]["account_id"],
            "region": facts["inventory"]["region"],
            "availability_zone": facts["inventory"]["availability_zone"],
            "instance_id": facts["instance_id"],
            "private_ip": facts["private_ip"],
            "boot_id": facts["boot_id"],
            "host_public_key": facts["host_public_key"],
            "host_key_fingerprint": facts["host_key_fingerprint"],
        },
    }


def attempts(value: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for scenario in SCENARIOS:
        for repetition, target in enumerate(ASSIGNMENT):
            phase_names = ("latency", "loss") if scenario == "network" else (scenario,)
            phases: list[dict[str, Any]] = [
                {
                    "name": name,
                    "injection_started_monotonic": 95.0,
                    "injection_started_utc": "2026-11-11T00:00:00+00:00",
                    "trigger_monotonic": 100.0,
                    "diagnosis_monotonic": 110.0,
                    "cleanup_monotonic": 120.0,
                    "resolution_monotonic": 130.0,
                    "trigger_to_diagnosis_seconds": 10.0,
                    "cleanup_to_resolution_seconds": 10.0,
                    "injection_to_diagnosis_seconds": 15.0,
                }
                for name in phase_names
            ]
            incident_ids = [f"{scenario}-{repetition}-{name}" for name in phase_names]
            raw_report: dict[str, Any] = {
                "campaign_linkage": {"incident_ids": incident_ids, "phases": phases},
            }
            if scenario in {"disk", "inode"}:
                raw_report.update(
                    incident_id=incident_ids[0],
                    events={
                        name: {
                            "monotonic_seconds": phases[0][field],
                            "utc": phases[0]["injection_started_utc"],
                        }
                        for name, field in (
                            ("injection_start", "injection_started_monotonic"),
                            ("threshold_observed", "trigger_monotonic"),
                            ("api_diagnosis", "diagnosis_monotonic"),
                            ("cleanup_complete", "cleanup_monotonic"),
                            ("api_resolution", "resolution_monotonic"),
                        )
                    },
                )
            elif scenario == "fd":
                raw_report.update(
                    incident={"id": incident_ids[0]},
                    events={
                        name: {
                            "monotonic_seconds": phases[0][field],
                            "utc": phases[0]["injection_started_utc"],
                        }
                        for name, field in (
                            ("pressure_requested", "injection_started_monotonic"),
                            ("actual_resource_trigger_observed", "trigger_monotonic"),
                            ("matching_incident_observed", "diagnosis_monotonic"),
                            ("actual_recovery_trigger_observed", "cleanup_monotonic"),
                            ("matching_recovery_observed", "resolution_monotonic"),
                        )
                    },
                )
            elif scenario in {"cpu", "oom"}:
                raw_report.update(
                    injection_started_monotonic=phases[0]["injection_started_monotonic"],
                    injection_started_utc=phases[0]["injection_started_utc"],
                    trigger_monotonic=phases[0]["trigger_monotonic"],
                    incident={
                        "id": incident_ids[0],
                        "observed_monotonic": phases[0]["diagnosis_monotonic"],
                    },
                    cleanup_monotonic=phases[0]["cleanup_monotonic"],
                    resolution_monotonic=phases[0]["resolution_monotonic"],
                )
            elif scenario == "network":
                for phase, incident_id in zip(phases, incident_ids, strict=True):
                    raw_report[phase["name"]] = {
                        "incident_id": incident_id,
                        "injection_started_monotonic": phase["injection_started_monotonic"],
                        "injection_started_utc": phase["injection_started_utc"],
                        "trigger_observation": {
                            "response_completed_monotonic": phase["trigger_monotonic"]
                        },
                        "diagnosis_detail_response_completed_monotonic": phase[
                            "diagnosis_monotonic"
                        ],
                        "recovery_started_monotonic": phase["cleanup_monotonic"],
                        "recovery_response_completed_monotonic": phase["resolution_monotonic"],
                    }
            elif scenario == "dns":
                phase = phases[0]
                raw_report.update(
                    injection_started_monotonic=phase["injection_started_monotonic"],
                    injection_started_utc=phase["injection_started_utc"],
                    trigger={"response_completed_monotonic": phase["trigger_monotonic"]},
                    incident={
                        "detail": {"id": incident_ids[0]},
                        "response_completed_monotonic": phase["diagnosis_monotonic"],
                    },
                    cleanup_response_completed_monotonic=phase["cleanup_monotonic"],
                    resolution={"response_completed_monotonic": phase["resolution_monotonic"]},
                )
            else:
                phase = phases[0]
                raw_report.update(
                    diagnosis={"id": incident_ids[0]},
                    events={
                        name: {
                            "monotonic": phase[field],
                            "utc": phase["injection_started_utc"],
                        }
                        for name, field in (
                            ("injection_started", "injection_started_monotonic"),
                            ("first_trigger_response_complete", "trigger_monotonic"),
                            ("diagnosis_detail_complete", "diagnosis_monotonic"),
                            ("cleanup_complete", "cleanup_monotonic"),
                            ("resolved_detail_complete", "resolution_monotonic"),
                        )
                    },
                )
            result.append(
                {
                    "schema_version": 1,
                    "batch_id": value["batch_id"],
                    "kind": value["kind"],
                    "scenario": scenario,
                    "repetition": repetition,
                    "target": target,
                    "reference": "node-b" if target == "node-a" else "node-a",
                    "token": attempt_token(value, scenario, repetition, target),
                    "status": "passed",
                    "source_sha256": digest(value["source"]),
                    "configuration_sha256": digest(value["configuration"]),
                    "lab_sha256": digest(value["lab"]),
                    "incident_ids": incident_ids,
                    "phases": phases,
                    "cleanup_complete": True,
                    "automatic_resolution": True,
                    "evidence_validated": True,
                    "unexpected_incidents": False,
                    "evidence_class": "synthetic",
                    "raw_report": raw_report,
                    "raw_report_sha256": digest(raw_report),
                    "runtime_receipt_sha256": None,
                }
            )
    return result


def test_manifest_accepts_dirty_inspected_source_separate_from_prebuild_baseline() -> None:
    value = manifest()
    assert validate_manifest(value) is value
    value["source"]["revision"] = "f" * 40
    value["source"]["dirty"] = False
    assert validate_manifest(value) is value


@pytest.mark.parametrize(
    ("kind", "targets"),
    [("measured", ASSIGNMENT), ("calibration", ("node-a", "node-b"))],
)
def test_batch_kind_binds_oom_leaf_count_and_required_attempts(
    kind: str, targets: tuple[str, ...]
) -> None:
    value = manifest()
    value["kind"] = kind
    value["assignments"] = {scenario: list(targets) for scenario in SCENARIOS}
    value["resources"]["oom"]["leaf_paths"] = [
        oom_leaf_path(attempt_token(value, "oom", repetition, target))
        for repetition, target in enumerate(targets)
    ]
    assert validate_manifest(value) is value
    rows = [row for row in attempts(value) if row["repetition"] < len(targets)]
    report = validate_attempts(value, rows)
    assert report["required_attempts"] == len(targets) * len(SCENARIOS)
    assert report["status"] == "passed" and report["aws_acceptance"] is False
    value["resources"]["oom"]["leaf_paths"].append("/extra/workload")
    with pytest.raises(ValueError):
        validate_manifest(value)


def test_manifest_rejects_wrong_assignment_ticket_gate_and_oom_scope() -> None:
    value = manifest()
    value["assignments"]["cpu"][0] = "node-b"
    with pytest.raises(ValueError, match="assignment"):
        validate_manifest(value)
    value = manifest()
    value["ticket14_gate"]["status"] = "failed"
    with pytest.raises(ValueError, match="Ticket14"):
        validate_manifest(value)
    value = manifest()
    value["resources"]["oom"]["leaf_paths"].pop()
    with pytest.raises(ValueError, match="per assigned trial"):
        validate_manifest(value)


@pytest.mark.parametrize(
    "damage",
    ("oom-path", "existing-scope", "fd-pid", "platform", "installed", "api", "network"),
)
def test_manifest_rejects_every_adapter_identity_shape_before_execution(damage: str) -> None:
    value = manifest()
    if damage == "oom-path":
        value["resources"]["oom"]["leaf_paths"][0] = "/arbitrary/not-the-helper-unit"
    elif damage == "existing-scope":
        value["resources"]["oom"]["existing_cgroups"]["node-a"] = ["relative"]
    elif damage == "fd-pid":
        value["resources"]["fd"]["node-a"]["existing_cpu_pids"] = [0]
    elif damage == "platform":
        value["platform"]["node-a"]["online_logical_cores"] = True
    elif damage == "installed":
        value["installed"]["node-a"].pop("helpers")
    elif damage == "api":
        value["resources"]["api_url"] = "file:///etc/passwd"
    else:
        value["resources"]["network"]["probe_target"] = "not-an-ip"
    with pytest.raises((ValueError, TypeError)):
        validate_manifest(value)


@pytest.mark.parametrize(
    ("role", "selector", "extra"),
    [
        ("monitor", "FLEETDOCTOR_CGROUPS", "/monitor-only"),
        ("node-a", "FLEETDOCTOR_CGROUPS", "/undeclared-node"),
        ("node-b", "FLEETDOCTOR_CPU_PIDS", 991),
    ],
)
def test_initial_selector_mismatch_reads_all_roles_but_sends_no_mutation(
    role: str, selector: str, extra: object
) -> None:
    value = manifest()

    class InventoryTransport:
        def __init__(self, current_role: str) -> None:
            self.role = current_role
            self.calls: list[str] = []

        def call(
            self,
            scenario: str,
            action: str,
            token: str,
            arguments: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            self.calls.append(action)
            if action != "inventory":
                raise AssertionError("no mutation may be sent after an initial mismatch")
            cgroups = list(value["resources"]["oom"]["existing_cgroups"][self.role])
            pids = (
                []
                if self.role == "monitor"
                else list(value["resources"]["fd"][self.role]["existing_cpu_pids"])
            )
            if self.role == role and selector == "FLEETDOCTOR_CGROUPS":
                cgroups.append(cast(str, extra))
            if self.role == role and selector == "FLEETDOCTOR_CPU_PIDS":
                pids.append(cast(int, extra))
            return {
                "env_sha256": "a" * 64,
                "selectors": {
                    "FLEETDOCTOR_CGROUPS": cgroups,
                    "FLEETDOCTOR_CPU_PIDS": pids,
                },
                "missing_keys": [],
                "mode": 0o600,
                "uid": 0,
                "gid": 0,
                "service_state": {"ActiveState": "active", "UnitFileState": "enabled"},
            }

    transports = {
        current_role: InventoryTransport(current_role)
        for current_role in ("monitor", "node-a", "node-b")
    }
    with pytest.raises(ValueError, match="differ"):
        campaign.prepare_runtime(value, transports)
    assert all(transport.calls == ["inventory"] for transport in transports.values())


def test_late_selector_cas_failure_rolls_back_earlier_role_in_reverse() -> None:
    value = manifest()
    events: list[tuple[str, str]] = []

    class Transport:
        def __init__(self, role: str) -> None:
            self.role = role
            self.hello_receipt = {"role": role}

        def call(
            self,
            scenario: str,
            action: str,
            token: str,
            arguments: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            events.append((self.role, action))
            if action == "inventory":
                return {
                    "env_sha256": "a" * 64,
                    "selectors": {
                        "FLEETDOCTOR_CGROUPS": [],
                        "FLEETDOCTOR_CPU_PIDS": [],
                    },
                    "missing_keys": [],
                    "mode": 0o600,
                    "uid": 0,
                    "gid": 0,
                    "service_state": {"ActiveState": "active", "UnitFileState": "enabled"},
                }
            if self.role == "node-a" and action == "begin":
                raise ValueError("selector environment changed since inventory")
            if action == "begin":
                assert arguments is not None
                return {"phase": "applied", "original_selectors": arguments["expected_before"]}
            if action in {"handoff", "adopt"}:
                return {"phase": "active"}
            if action == "restore":
                return {"phase": "restored"}
            raise AssertionError(action)

    transports = {role: Transport(role) for role in ("monitor", "node-a", "node-b")}
    with pytest.raises(ValueError, match="changed since inventory"):
        campaign.prepare_runtime(value, transports)
    assert events[-2:] == [("monitor", "adopt"), ("monitor", "restore")]


def test_fd_selector_mismatch_before_worker_sends_no_fd_start(tmp_path: Path) -> None:
    value = manifest()
    transport = RecordingTransport()
    transport.cgroups = ["/unexpected"]
    item = AdapterContext(
        api=cast(Any, None),
        transport=transport,
        manifest=value,
        target="node-a",
        reference="node-b",
        repetition=0,
        output=tmp_path / "fd-before.json",
        token="a" * 32,
    )
    with pytest.raises(ValueError, match="before worker creation"):
        ADAPTERS["fd"].execute(item)
    assert not [call for call in transport.calls if call[0] == "fd"]


def test_fd_post_start_selector_race_cleans_worker_without_environment_begin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = manifest()
    expected_cgroups = list(value["resources"]["oom"]["leaf_paths"])

    class RacingTransport(RecordingTransport):
        def __init__(self) -> None:
            super().__init__()
            self.cgroups = expected_cgroups
            self.inventory_reads = 0

        def call(
            self,
            scenario: str,
            action: str,
            token: str,
            arguments: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            if scenario == "config" and action == "inventory":
                self.inventory_reads += 1
                result = self.inventory()
                if self.inventory_reads == 2:
                    result["env_sha256"] = "f" * 64
                self.calls.append((scenario, action, token, arguments or {}))
                return result
            return super().call(scenario, action, token, arguments)

    class CleanupHarness:
        after_prepare: Any = None

        def __init__(self, api: Any, injector: Any, *args: Any, **kwargs: Any) -> None:
            self.injector = injector

        def run(self, phase: str, *, limit: int) -> dict[str, Any]:
            self.injector.start("a" * 32, limit, 30)
            try:
                assert self.after_prepare is not None
                self.after_prepare({"pid": 321, "starttime_ticks": 99, "boot_id": "boot"})
            finally:
                self.injector.cleanup("a" * 32)
            raise AssertionError("race must abort configuration")

    monkeypatch.setattr(campaign, "FdHarness", CleanupHarness)
    transport = RacingTransport()
    item = AdapterContext(
        api=cast(Any, None),
        transport=transport,
        manifest=value,
        target="node-a",
        reference="node-b",
        repetition=0,
        output=tmp_path / "fd-race.json",
        token="a" * 32,
    )
    with pytest.raises(ValueError, match="raced after worker"):
        ADAPTERS["fd"].execute(item)
    assert ("fd", "cleanup") in [(scenario, action) for scenario, action, _, _ in transport.calls]
    assert not [call for call in transport.calls if call[0] == "config" and call[1] == "begin"]


def test_lab_wide_lease_blocks_different_batches_and_output_parents(tmp_path: Path) -> None:
    value = manifest()
    lease = lab_lease_path(value["lab"], tmp_path / "common-leases")
    lease_identity_sha256 = digest(stable_lab_identity(value["lab"]))
    with campaign_lock(lease, "batch-from-output-a", lease_identity_sha256):
        with pytest.raises(FileExistsError):
            with campaign_lock(lease, "different-batch-from-output-b", lease_identity_sha256):
                pass
    assert not lease.exists()


def test_lab_lease_key_ignores_refreshed_runtime_and_credit_metadata(tmp_path: Path) -> None:
    first = manifest()["lab"]
    refreshed = deepcopy(first)
    refreshed["instances"]["node-a"].update(
        kernel="different-kernel",
        cpu_credit_balance=1.25,
        state="stopped",
        private_ip="10.99.0.44",
    )
    assert lab_lease_path(first, tmp_path) == lab_lease_path(refreshed, tmp_path)
    refreshed["instances"]["node-a"]["id"] = "i-deadbeef"
    assert lab_lease_path(first, tmp_path) != lab_lease_path(refreshed, tmp_path)


def test_lab_lease_recovery_requires_stale_exact_owned_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = manifest()
    lease = lab_lease_path(value["lab"], tmp_path)
    lease.parent.mkdir(parents=True, exist_ok=True)
    owner = {
        "schema_version": 1,
        "batch_id": "interrupted-batch",
        "lease_identity_sha256": digest(stable_lab_identity(value["lab"])),
        "pid": 999999,
        "process_identity": "stale-process",
        "created_at": datetime.now(UTC).isoformat(),
    }
    lease.write_text(campaign.canonical(owner).decode() + "\n", encoding="utf-8")
    monkeypatch.setattr(campaign, "_pid_is_live", lambda pid, identity: False)
    identity_sha256 = digest(stable_lab_identity(value["lab"]))
    result = recover_campaign_lock(lease, identity_sha256)
    assert result["status"] == "recovered"
    assert not lease.exists()

    owner["lease_identity_sha256"] = "f" * 64
    lease.write_text(campaign.canonical(owner).decode() + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="foreign"):
        recover_campaign_lock(lease, identity_sha256)


@pytest.mark.skipif(os.name != "nt", reason="Windows liveness route")
@pytest.mark.parametrize(
    ("state", "expected_identity", "expected"),
    [
        ((True, "same"), "same", True),
        ((True, None), "protected", True),
        ((False, None), "missing", False),
        ((True, "reused"), "original", False),
    ],
)
def test_windows_pid_liveness_is_read_only_and_detects_reuse(
    monkeypatch: pytest.MonkeyPatch,
    state: tuple[bool, str | None],
    expected_identity: str,
    expected: bool,
) -> None:
    monkeypatch.setattr(campaign, "_windows_process_state", lambda pid: state)
    monkeypatch.setattr(
        os,
        "kill",
        lambda *args: (_ for _ in ()).throw(AssertionError("os.kill must not run on Windows")),
    )
    assert campaign._pid_is_live(1234, expected_identity) is expected


def test_all_eight_concrete_adapters_are_registered() -> None:
    assert set(ADAPTERS) == set(SCENARIOS)
    assert len({type(adapter) for adapter in ADAPTERS.values()}) == 8


def test_six_harness_adapters_execute_real_transport_shapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def events(prefix: str) -> dict[str, Any]:
        return {
            "status": "passed",
            "incident_id": prefix + "-incident",
            "events": {
                "injection_start": {
                    "monotonic_seconds": 100.0,
                    "utc": "2026-11-11T00:00:00+00:00",
                },
                "threshold_observed": {"monotonic_seconds": 101.0},
                "api_diagnosis": {"monotonic_seconds": 102.0},
                "cleanup_complete": {"monotonic_seconds": 103.0},
                "api_resolution": {"monotonic_seconds": 104.0},
            },
        }

    class DiskFixture:
        def __init__(self, api: Any, injector: Any, *args: Any, **kwargs: Any) -> None:
            self.injector = injector

        def run(self) -> dict[str, Any]:
            self.injector.start("a" * 32, 30)
            self.injector.cleanup("a" * 32)
            return events("disk")

    class InodeFixture(DiskFixture):
        def run(self) -> dict[str, Any]:
            self.injector.start("a" * 32, 30)
            self.injector.cleanup("a" * 32)
            return events("inode")

    class FdFixture:
        after_prepare: Any = None

        def __init__(self, api: Any, injector: Any, *args: Any, **kwargs: Any) -> None:
            self.injector = injector

        def run(self, phase: str, *, limit: int) -> dict[str, Any]:
            self.injector.start("a" * 32, limit, 30)
            assert self.after_prepare is not None
            self.after_prepare({"pid": 321, "starttime_ticks": 99, "boot_id": "boot"})
            self.injector.pressure("a" * 32)
            self.injector.release("a" * 32)
            self.injector.cleanup("a" * 32)
            return {
                "status": "passed",
                "incident": {"id": "fd-incident"},
                "events": {
                    "pressure_requested": {
                        "monotonic_seconds": 100.0,
                        "utc": "2026-11-11T00:00:00+00:00",
                    },
                    "actual_resource_trigger_observed": {"monotonic_seconds": 101.0},
                    "matching_incident_observed": {"monotonic_seconds": 102.0},
                    "actual_recovery_trigger_observed": {"monotonic_seconds": 103.0},
                    "matching_recovery_observed": {"monotonic_seconds": 104.0},
                },
            }

    class NetworkFixture:
        def __init__(self, *args: Any, helper: Any, **kwargs: Any) -> None:
            self.helper = helper

        def run(self) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for offset, profile in enumerate(("latency", "loss")):
                self.helper("start", "a" * 32, profile, 30)
                self.helper("cleanup", "a" * 32, profile, 0)
                base = 101.0 + offset * 10
                result[profile] = {
                    "incident_id": f"network-{profile}",
                    "injection_started_monotonic": base - 1,
                    "injection_started_utc": "2026-11-11T00:00:00+00:00",
                    "trigger_observation": {"response_completed_monotonic": base},
                    "diagnosis_detail_response_completed_monotonic": base + 1,
                    "recovery_started_monotonic": base + 2,
                    "recovery_response_completed_monotonic": base + 3,
                }
            return result

    class DnsFixture:
        def __init__(self, *args: Any, helper: Any, **kwargs: Any) -> None:
            self.helper = helper

        def run(self) -> dict[str, Any]:
            self.helper("start", "a" * 32, "203.0.113.254", 30)
            self.helper("cleanup", "a" * 32, "203.0.113.254", 0)
            return {
                "status": "passed",
                "injection_started_monotonic": 100.0,
                "injection_started_utc": "2026-11-11T00:00:00+00:00",
                "trigger": {"response_completed_monotonic": 101.0},
                "incident": {
                    "response_completed_monotonic": 102.0,
                    "detail": {"id": "dns-incident"},
                },
                "cleanup_response_completed_monotonic": 103.0,
                "resolution": {"response_completed_monotonic": 104.0},
            }

    class IoFixture:
        def __init__(self, api: Any, injector: Any, *args: Any, **kwargs: Any) -> None:
            self.injector = injector

        def run(self) -> dict[str, Any]:
            self.injector.start("a" * 32, 30)
            self.injector.cleanup("a" * 32)
            return {
                "status": "passed",
                "diagnosis": {"id": "io-incident"},
                "events": {
                    "injection_started": {
                        "monotonic": 100.0,
                        "utc": "2026-11-11T00:00:00+00:00",
                    },
                    "first_trigger_response_complete": {"monotonic": 101.0},
                    "diagnosis_detail_complete": {"monotonic": 102.0},
                    "cleanup_complete": {"monotonic": 103.0},
                    "resolved_detail_complete": {"monotonic": 104.0},
                },
            }

    monkeypatch.setattr(campaign, "DiskHarness", DiskFixture)
    monkeypatch.setattr(campaign, "InodeHarness", InodeFixture)
    monkeypatch.setattr(campaign, "FdHarness", FdFixture)
    monkeypatch.setattr(campaign, "NetworkHarness", NetworkFixture)
    monkeypatch.setattr(campaign, "DnsHarness", DnsFixture)
    monkeypatch.setattr(campaign, "IoHarness", IoFixture)

    transports: dict[str, RecordingTransport] = {}
    for scenario in ("disk", "inode", "fd", "network", "dns", "io"):
        transport = RecordingTransport()
        transports[scenario] = transport
        result = ADAPTERS[scenario].execute(context(tmp_path, scenario, transport=transport))
        assert result["status"] == "passed"
        assert result["scenario"] == scenario
        assert result["raw_report_sha256"] == digest(result["raw_report"])
        assert any(call[0] == scenario for call in transport.calls)

    assert any(call[:2] == ("config", "begin") for call in transports["fd"].calls)
    assert [call[1] for call in transports["io"].calls if call[0] == "io"] == [
        "prepare",
        "prepare",
        "start",
        "cleanup",
        "destroy",
        "destroy",
    ]


def test_actual_io_adapter_prepares_distinct_both_node_resources_across_role_swaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class IoFixture:
        def __init__(self, api: Any, injector: Any, *args: Any, **kwargs: Any) -> None:
            self.injector = injector

        def run(self) -> dict[str, Any]:
            self.injector.start(self.injector.transport.calls[-1][2], 30)
            self.injector.cleanup(self.injector.transport.calls[-1][2])
            return {
                "diagnosis": {"id": f"io-{len(self.injector.transport.calls)}"},
                "events": {
                    "injection_started": {"monotonic": 100.0, "utc": "2026-11-11T00:00:00+00:00"},
                    "first_trigger_response_complete": {
                        "monotonic": 101.0,
                        "utc": "2026-11-11T00:00:01+00:00",
                    },
                    "diagnosis_detail_complete": {
                        "monotonic": 102.0,
                        "utc": "2026-11-11T00:00:02+00:00",
                    },
                    "cleanup_complete": {"monotonic": 103.0, "utc": "2026-11-11T00:00:03+00:00"},
                    "resolved_detail_complete": {
                        "monotonic": 104.0,
                        "utc": "2026-11-11T00:00:04+00:00",
                    },
                },
            }

    monkeypatch.setattr(campaign, "IoHarness", IoFixture)
    value = manifest()
    transports = {"node-a": RecordingTransport(), "node-b": RecordingTransport()}
    tokens: set[str] = set()
    for repetition, target in enumerate(ASSIGNMENT):
        reference = "node-b" if target == "node-a" else "node-a"
        token = attempt_token(value, "io", repetition, target)
        tokens.add(token)
        ADAPTERS["io"].execute(
            AdapterContext(
                api=cast(Any, None),
                transport=transports[target],
                manifest=value,
                target=target,
                reference=reference,
                repetition=repetition,
                output=tmp_path / f"io-{repetition}.json",
                token=token,
                clock=FakeClock(),
                transports=transports,
            )
        )
    prepared = [
        (node, call[2])
        for node, transport in transports.items()
        for call in transport.calls
        if call[:2] == ("io", "prepare")
    ]
    destroyed = [
        (node, call[2])
        for node, transport in transports.items()
        for call in transport.calls
        if call[:2] == ("io", "destroy")
    ]
    assert len(tokens) == 5 and len(prepared) == 10
    assert len({token for _, token in prepared}) == 10
    assert sorted(prepared) == sorted(destroyed)


def sample(sequence: int, *, busy: float = 10.0, active: int = 0) -> dict[str, Any]:
    observed = datetime(2026, 11, 11, tzinfo=UTC) + timedelta(seconds=sequence)
    return {
        "fresh": True,
        "active_incident_count": active,
        "sample": {
            "boot_id": "boot-a",
            "agent_session_id": "session-a",
            "sequence": sequence,
            "observed_at": observed.isoformat(),
        },
        "cpu_coverage": {
            "host_rates": "available",
            "runnable": "available",
            "logical_cores": "available",
        },
        "cpu": {
            "busy_percent": busy,
            "runnable_processes": 4 if busy >= 90 else 1,
            "logical_cores": 2,
        },
    }


@pytest.mark.parametrize("unexpected", [False, True])
def test_cpu_adapter_executes_clocked_trigger_evidence_and_recovery(
    tmp_path: Path, unexpected: bool
) -> None:
    config = {
        "trigger_busy_percent": 90,
        "recovery_busy_percent": 80,
        "consecutive_samples": 3,
        "max_gap_seconds": 10,
        "severity": "warning",
    }
    opening = {
        "node_id": "node-a",
        "boot_id": "boot-a",
        "agent_session_id": "session-a",
        "sequence": 4,
        "observed_at": (datetime(2026, 11, 11, tzinfo=UTC) + timedelta(seconds=4)).isoformat(),
        "cpu_available": True,
        "cpu": {"busy_percent": 95.0, "runnable_processes": 4, "logical_cores": 2},
    }

    class Transport(RecordingTransport):
        started = False

        def call(
            self,
            scenario: str,
            action: str,
            token: str,
            arguments: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            result = super().call(scenario, action, token, arguments)
            if action == "start":
                self.started = True
            return result

    transport = Transport()

    class Api:
        target_reads = 0
        detail_reads = 0
        reference_reads = 0

        def __init__(self) -> None:
            self.unexpected = unexpected

        def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
            if path == "/configuration":
                return {"cpu_rule": config}
            if path == "/nodes/node-a/metrics":
                self.target_reads += 1
                if self.target_reads <= 3:
                    return sample(self.target_reads)
                if self.target_reads == 4:
                    return sample(4, busy=95, active=1)
                sequence = self.target_reads
                return sample(sequence, active=1 if sequence < 5 else 0)
            if path == "/nodes/node-b/metrics":
                self.reference_reads += 1
                view = sample(self.reference_reads)
                view["sample"]["boot_id"] = "boot-b"
                view["sample"]["agent_session_id"] = "session-b"
                return view
            if path == "/diagnoses":
                if params and params.get("node") == "node-a" and params.get("status") == "active":
                    rows = (
                        [{"id": "cpu-incident", "rule": "cpu_saturation", "resource": "cpu"}]
                        if transport.started and self.detail_reads < 3
                        else []
                    )
                    if self.unexpected and transport.started:
                        rows.append({"id": "foreign", "rule": "inode_exhaustion", "resource": "/"})
                    return {"diagnoses": rows}
                return {"diagnoses": []}
            if path == "/diagnoses/cpu-incident":
                self.detail_reads += 1
                return {
                    "id": "cpu-incident",
                    "node_id": "node-a",
                    "rule": "cpu_saturation",
                    "resource": "cpu",
                    "configuration": config,
                    "severity": "warning",
                    "status": "resolved" if self.detail_reads >= 4 else "active",
                    "opening_evidence": opening,
                    "latest_evidence": opening,
                    "investigation_steps": ["inspect CPU"],
                }
            raise AssertionError((path, params))

    if unexpected:
        with pytest.raises(ValueError, match="unexpected target incident"):
            ADAPTERS["cpu"].execute(
                context(tmp_path, "cpu", api=Api(), transport=transport, clock=FakeClock())
            )
        assert transport.calls[-1][1] == "cleanup"
        return
    result = ADAPTERS["cpu"].execute(
        context(tmp_path, "cpu", api=Api(), transport=transport, clock=FakeClock())
    )
    assert result["status"] == "passed"
    assert result["incident_ids"] == ["cpu-incident"]
    assert result["phases"][0]["trigger_to_diagnosis_seconds"] < 60
    assert [call[1] for call in transport.calls] == ["start", "cleanup"]


class OomTransport(RecordingTransport):
    def __init__(self, cgroup: str) -> None:
        super().__init__()
        self.cgroup = cgroup
        self.started = False

    def call(
        self, scenario: str, action: str, token: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        self.calls.append((scenario, action, token, arguments or {}))
        if action == "prepare":
            return {
                "phase": "prepared",
                "leaf_path": self.cgroup,
                "processes": [],
                "generation": {"st_dev": 7, "st_ino": 9},
                "events": {"oom": 0, "oom_kill": 0},
            }
        if action == "start":
            self.started = True
            return {
                "phase": "running",
                "limits": {
                    "memory.max": str(48 * 1024 * 1024),
                    "memory.swap.max": "0",
                    "pids.max": "4",
                },
                "caller_cgroup": "/system.slice/controller.service",
                "monitor_control_groups": {"agent": "/system.slice/fleetdoctor-agent.service"},
            }
        if action == "status":
            return {"events": {"oom": 1, "oom_kill": 1}, "processes": []}
        if action == "stop":
            return {"stopped": True}
        if action == "release":
            return {"released": True, "owned": False}
        return {"phase": action}


class OomApi:
    def __init__(self, transport: OomTransport, *, replace_generation: bool = False) -> None:
        self.transport = transport
        self.replace_generation = replace_generation
        self.target_reads = 0
        self.reference_reads = 0
        self.detail_reads = 0
        self.config = {
            "recovery_percent": 80,
            "consecutive_samples": 3,
            "max_gap_seconds": 10,
            "severity": "critical",
        }

    def workload(self, sequence: int) -> dict[str, Any]:
        triggered = sequence >= 4
        return {
            "cgroup_path": self.transport.cgroup,
            "boot_id": "boot-a",
            "st_dev": 7,
            "st_ino": 10 if self.replace_generation and triggered else 9,
            "generation_stable": True,
            "events_stable": True,
            "events": {"oom": 1 if triggered else 0, "oom_kill": 1 if triggered else 0},
            "processes": [],
            "usage_ratio": 0.1,
            "max_bytes": 48 * 1024 * 1024,
        }

    def metrics(self, sequence: int, reference: bool = False) -> dict[str, Any]:
        observed = datetime(2026, 11, 11, tzinfo=UTC) + timedelta(seconds=sequence)
        return {
            "fresh": True,
            "memory_coverage": {"host": "available"},
            "sample": {
                "boot_id": "boot-b" if reference else "boot-a",
                "agent_session_id": "session-b" if reference else "session-a",
                "sequence": sequence,
                "observed_at": observed.isoformat(),
            },
            "memory": {"workloads": [] if reference else [self.workload(sequence)]},
        }

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/configuration":
            return {"cgroups": [self.transport.cgroup], "oom_rule": self.config}
        if path == "/nodes/node-a/metrics":
            self.target_reads += 1
            return self.metrics(self.target_reads)
        if path == "/nodes/node-b/metrics":
            self.reference_reads += 1
            return self.metrics(self.reference_reads, reference=True)
        if path == "/diagnoses":
            if (
                params
                and params.get("node") == "node-a"
                and self.transport.started
                and self.detail_reads < 3
            ):
                resource = generation_key(self.transport.cgroup, self.workload(4))
                return {"diagnoses": [{"id": "oom-incident", "resource": resource}]}
            return {"diagnoses": []}
        if path == "/diagnoses/oom-incident":
            self.detail_reads += 1
            generation = {"boot_id": "boot-a", "st_dev": 7, "st_ino": 9}
            opening = {
                "cgroup_path": self.transport.cgroup,
                "generation": generation,
                "event_delta": {"oom": 1, "oom_kill": 1},
            }
            return {
                "id": "oom-incident",
                "node_id": "node-a",
                "rule": "workload_oom",
                "resource": generation_key(self.transport.cgroup, self.workload(3)),
                "configuration": self.config,
                "severity": "critical",
                "status": "resolved" if self.detail_reads >= 4 else "active",
                "opening_evidence": opening,
                "latest_evidence": opening,
                "investigation_steps": ["inspect cgroup"],
            }
        raise AssertionError((path, params))


def test_oom_adapter_executes_exact_generation_real_kill_and_recovery(tmp_path: Path) -> None:
    cgroup = manifest()["resources"]["oom"]["leaf_paths"][0]
    transport = OomTransport(cgroup)
    api = OomApi(transport)
    result = ADAPTERS["oom"].execute(
        context(tmp_path, "oom", api=api, transport=transport, clock=FakeClock())
    )
    exact = f"{cgroup}|boot-a|7|9"
    assert result["status"] == "passed"
    assert result["raw_report"]["exact_resource"] == exact
    assert result["raw_report"]["real_kill_status"]["processes"] == []
    assert [call[1] for call in transport.calls][-1] == "release"


def test_oom_generation_replacement_fails_closed_and_releases(tmp_path: Path) -> None:
    cgroup = manifest()["resources"]["oom"]["leaf_paths"][0]
    transport = OomTransport(cgroup)
    api = OomApi(transport, replace_generation=True)
    with pytest.raises(ValueError, match="generation changed"):
        ADAPTERS["oom"].execute(
            context(tmp_path, "oom-failure", api=api, transport=transport, clock=FakeClock())
        )
    assert transport.calls[-1][1] == "release"


def test_complete_batch_recomputes_timings_and_passes_strict_medians() -> None:
    value = manifest()
    report = validate_attempts(value, attempts(value))
    assert report["status"] == "passed"
    assert report["aws_acceptance"] is False
    assert report["measured_criteria_consistent"] is True
    assert all(item["median_seconds"] == 10 for item in report["scenarios"].values())


def test_aws_acceptance_requires_exact_live_runtime_receipt() -> None:
    value = manifest()
    live_connection = connection_receipt(value)
    value["evidence_class"] = "aws"
    runtime_receipt = {
        "schema_version": 2,
        "evidence_class": "aws",
        "checked_at": datetime.now(UTC).isoformat(),
        "source": value["source"],
        "installed": value["installed"],
        "configuration": value["configuration"]["collector"],
        "lab": value["lab"],
        "raw_receipts": {"inventory": "a" * 64, "deployment": "b" * 64},
        "preparation_receipt_sha256": value["preparation_receipt_sha256"],
        "connection_receipt_sha256": value["connection_receipt_sha256"],
        "handshakes": {
            role: hello_receipt(live_connection, role) for role in ("monitor", "node-a", "node-b")
        },
    }
    value["runtime_receipt_sha256"] = digest(runtime_receipt)
    rows = attempts(value)
    for row in rows:
        row["evidence_class"] = "aws"
        row["runtime_receipt_sha256"] = value["runtime_receipt_sha256"]
    assert validate_attempts(value, rows)["aws_acceptance"] is False
    assert validate_attempts(value, rows, runtime_receipt)["aws_acceptance"] is True
    runtime_receipt["lab"] = {**value["lab"], "account_id": "000000000000"}
    assert validate_attempts(value, rows, runtime_receipt)["aws_acceptance"] is False


def test_runtime_receipt_accepts_fresh_sessions_only_when_stable_attestation_matches() -> None:
    value = manifest()
    live_connection = connection_receipt(value)
    stored = {
        role: hello_receipt(live_connection, role, nonce="1", session="2")
        for role in ("monitor", "node-a", "node-b")
    }
    runtime_receipt = {
        "schema_version": 2,
        "evidence_class": "aws",
        "checked_at": datetime.now(UTC).isoformat(),
        "source": value["source"],
        "installed": value["installed"],
        "configuration": value["configuration"]["collector"],
        "lab": value["lab"],
        "raw_receipts": {"inventory": "a" * 64},
        "preparation_receipt_sha256": value["preparation_receipt_sha256"],
        "connection_receipt_sha256": value["connection_receipt_sha256"],
        "handshakes": stored,
    }
    value["runtime_receipt_sha256"] = digest(runtime_receipt)

    class Session:
        def __init__(self, role: str) -> None:
            self.hello_receipt = hello_receipt(live_connection, role, nonce="3", session="4")

    sessions = {role: Session(role) for role in ("monitor", "node-a", "node-b")}
    assert campaign.runtime_receipt_binds(value, runtime_receipt, sessions)
    sessions["node-a"].hello_receipt["identity"]["boot_id"] = "99999999-0000-0000-0000-000000000020"
    assert not campaign.runtime_receipt_binds(value, runtime_receipt, sessions)


def test_attempt_boundary_boot_mismatch_aborts_before_adapter_injection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = manifest()
    live_connection = connection_receipt(value)
    injected: list[str] = []

    class Transport:
        def __init__(self, role: str) -> None:
            self.role_receipt = live_connection["roles"][role]

        def call(
            self,
            scenario: str,
            action: str,
            token: str,
            arguments: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            assert (scenario, action) == ("config", "status")
            return {
                "phase": "active",
                "changes": campaign.declared_preparation_changes(value)[
                    self.role_receipt["inventory"]["role"]
                ],
            }

    class Api:
        def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
            if path == "/configuration":
                return cast(dict[str, Any], value["configuration"]["collector"])
            node = path.split("/")[2]
            boot_id = live_connection["roles"][node]["boot_id"]
            if node == "node-a":
                boot_id = "99999999-0000-0000-0000-000000000020"
            return {
                "fresh": True,
                "active_incident_count": 0,
                "sample": {"boot_id": boot_id},
            }

    class NeverAdapter:
        def execute(self, item: AdapterContext) -> dict[str, Any]:
            injected.append(item.target)
            raise AssertionError("adapter must not run")

    monkeypatch.setattr(campaign, "ADAPTERS", {name: NeverAdapter() for name in SCENARIOS})
    transports = {role: Transport(role) for role in ("monitor", "node-a", "node-b")}
    with pytest.raises(ValueError, match="boot identity changed"):
        campaign.run_campaign(
            value,
            tmp_path / "boundary-output",
            Api(),
            transports,
            lease_root=tmp_path / "leases",
        )
    assert not injected


@pytest.mark.parametrize(
    ("kind", "targets", "attempt_count", "phase_count"),
    [
        ("calibration", ("node-a", "node-b"), 16, 18),
        ("measured", ASSIGNMENT, 40, 45),
    ],
)
def test_full_synthetic_composition_uses_verified_sessions_and_monitor_relay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    targets: tuple[str, ...],
    attempt_count: int,
    phase_count: int,
) -> None:
    value = manifest()
    value["kind"] = kind
    value["assignments"] = {scenario: list(targets) for scenario in SCENARIOS}
    value["resources"]["oom"]["leaf_paths"] = [
        oom_leaf_path(attempt_token(value, "oom", repetition, target))
        for repetition, target in enumerate(targets)
    ]
    live_connection = connection_receipt(value)

    class VerifiedSession:
        def __init__(self, role: str) -> None:
            self.role = role
            self.role_receipt = live_connection["roles"][role]
            self.hello_receipt = hello_receipt(live_connection, role)
            self.cgroups = list(value["resources"]["oom"]["existing_cgroups"][role])
            self.pids = (
                []
                if role == "monitor"
                else list(value["resources"]["fd"][role]["existing_cpu_pids"])
            )
            self.saved: dict[str, tuple[list[str], list[int]]] = {}
            self.changes: dict[str, dict[str, str]] = {}
            self.begins: dict[str, dict[str, Any]] = {}

        def inventory(self) -> dict[str, Any]:
            selectors = {
                "FLEETDOCTOR_CGROUPS": list(self.cgroups),
                "FLEETDOCTOR_CPU_PIDS": list(self.pids),
            }
            snapshot = {
                "env_sha256": digest(selectors),
                "selectors": selectors,
                "missing_keys": [],
            }
            return {
                **snapshot,
                "mode": 0o600,
                "uid": 0,
                "gid": 0,
                "service_state": {"ActiveState": "active", "UnitFileState": "enabled"},
            }

        def call(
            self,
            scenario: str,
            action: str,
            token: str,
            arguments: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            arguments = arguments or {}
            if scenario == "api":
                path = arguments["path"]
                if path == "/configuration":
                    body = value["configuration"]["collector"]
                elif path.startswith("/nodes/"):
                    node = path.split("/")[2]
                    body = {
                        "fresh": True,
                        "active_incident_count": 0,
                        "sample": {"boot_id": live_connection["roles"][node]["boot_id"]},
                    }
                else:
                    body = {"status": "ok"}
                return {"status_code": 200, "body": body}
            assert scenario == "config"
            if action == "inventory":
                return self.inventory()
            if action == "begin":
                before = self.inventory()
                expected = {key: before[key] for key in ("env_sha256", "selectors", "missing_keys")}
                assert arguments["expected_before"] == expected
                self.saved[token] = (list(self.cgroups), list(self.pids))
                self.changes[token] = arguments["changes"]
                if "FLEETDOCTOR_CGROUPS" in arguments["changes"]:
                    self.cgroups = arguments["changes"]["FLEETDOCTOR_CGROUPS"].split(",")
                result = {
                    "phase": "applied",
                    "original_selectors": expected,
                    "prepared_selectors": {
                        key: self.inventory()[key]
                        for key in ("env_sha256", "selectors", "missing_keys")
                    },
                }
                self.begins[token] = result
                return result
            if action == "lookup":
                if token not in self.saved:
                    return {"token": token, "state": "absent"}
                current = self.inventory()
                return {
                    "token": token,
                    "state": "active",
                    "phase": "active",
                    "original_sha256": self.begins[token]["original_selectors"]["env_sha256"],
                    "updated_sha256": self.begins[token]["prepared_selectors"]["env_sha256"],
                    "current_sha256": current["env_sha256"],
                    "changes": self.changes[token],
                    "original_selectors": self.begins[token]["original_selectors"],
                    "prepared_selectors": self.begins[token]["prepared_selectors"],
                    "service_state": current["service_state"],
                }
            if action in {"handoff", "adopt", "status"}:
                return {
                    "phase": "active",
                    "changes": self.changes[token],
                    "current_sha256": self.inventory()["env_sha256"],
                }
            if action == "restore":
                self.cgroups, self.pids = self.saved.pop(token)
                self.changes.pop(token)
                self.begins.pop(token)
                return {"phase": "restored"}
            raise AssertionError((scenario, action))

    sessions = {role: VerifiedSession(role) for role in ("monitor", "node-a", "node-b")}
    prepared = campaign.prepare_runtime(value, sessions)
    value["preparation_receipt_sha256"] = digest(prepared)
    expected = {(row["scenario"], row["repetition"], row["target"]): row for row in attempts(value)}
    observed: list[tuple[str, str]] = []

    class Adapter:
        def __init__(self, scenario: str) -> None:
            self.scenario = scenario

        def execute(self, item: AdapterContext) -> dict[str, Any]:
            observed.append((self.scenario, item.target))
            return deepcopy(expected[(self.scenario, item.repetition, item.target)])

    monkeypatch.setattr(campaign, "ADAPTERS", {name: Adapter(name) for name in SCENARIOS})
    completed = campaign.run_campaign(
        value,
        tmp_path / f"verified-{kind}",
        connection.MonitorBackend(sessions["monitor"]),
        sessions,
        lease_root=tmp_path / f"leases-{kind}",
    )
    assert len(completed) == attempt_count and len(observed) == attempt_count
    assert sum(2 if scenario == "network" else 1 for scenario, _ in observed) == phase_count
    restored = campaign.restore_prepared_runtime(value, prepared, sessions)
    assert restored["status"] == "passed"


@pytest.mark.parametrize(
    ("kind", "targets", "attempt_count", "phase_count"),
    [
        ("calibration", ("node-a", "node-b"), 16, 18),
        ("measured", ASSIGNMENT, 40, 45),
    ],
)
def test_actual_authenticated_transport_and_serve_compose_full_schedule_and_relay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    targets: tuple[str, ...],
    attempt_count: int,
    phase_count: int,
) -> None:
    value = manifest()
    value["kind"] = kind
    value["assignments"] = {scenario: list(targets) for scenario in SCENARIOS}
    value["resources"]["oom"]["leaf_paths"] = [
        oom_leaf_path(attempt_token(value, "oom", repetition, target))
        for repetition, target in enumerate(targets)
    ]
    live_connection = connection_receipt(value)
    role_hosts = {"monitor": "127.0.0.1", "node-a": "127.0.0.2", "node-b": "127.0.0.3"}
    for role, host in role_hosts.items():
        facts = live_connection["roles"][role]
        facts["ssh_host"] = host
        facts["inventory"]["ssh_host"] = host
        facts["inventory_sha256"] = digest(facts["inventory"])
        facts["host_key_attestation"]["host"] = host
        facts["host_key_attestation_sha256"] = digest(facts["host_key_attestation"])
    value["connection_receipt_sha256"] = digest(live_connection)
    key = tmp_path / "synthetic-key"
    key.write_bytes(b"synthetic test key; never used by a network client")
    real_popen = subprocess.Popen
    server_code = r"""
import hashlib
import json
import sys
from pathlib import Path
from chaos_controller import HELPERS, serve

role = sys.argv[1]
session = json.loads(sys.argv[2])
facts = json.loads(sys.argv[3])
selectors = facts["selectors"]
saved = {}
changes = {}
records = {}
def option(argv, name): return argv[argv.index(name) + 1]
def snapshot():
    body = json.dumps(selectors, sort_keys=True, separators=(",", ":")).encode()
    return {"env_sha256": hashlib.sha256(body).hexdigest(), "selectors": selectors, "missing_keys": []}
def runner(argv):
    scenario = next(name for name, relative in HELPERS.items() if Path(argv[1]).name == Path(relative).name)
    action = argv[2]
    token = option(argv, "--token") if "--token" in argv else (argv[3] if scenario == "io" else "")
    if scenario == "config":
        if action == "inventory":
            return {**snapshot(), "mode": 384, "uid": 0, "gid": 0, "service_state": {"ActiveState": "active", "UnitFileState": "enabled"}}
        if action == "begin":
            expected = json.loads(option(argv, "--expected-before-json"))
            if expected != snapshot(): raise ValueError("stale expected-before")
            saved[token] = json.loads(json.dumps(selectors))
            changes[token] = json.loads(option(argv, "--changes-json"))
            for key, value in changes[token].items():
                selectors[key] = [] if value == "" else ([int(item) for item in value.split(",")] if key.endswith("PIDS") else value.split(","))
            records[token] = {"original": expected, "prepared": snapshot()}
            return {"phase": "applied", "original_selectors": expected, "prepared_selectors": records[token]["prepared"]}
        if action == "lookup":
            if token not in records: return {"token": token, "state": "absent"}
            return {"token": token, "state": "active", "phase": "active", "original_sha256": records[token]["original"]["env_sha256"], "updated_sha256": records[token]["prepared"]["env_sha256"], "current_sha256": snapshot()["env_sha256"], "changes": changes[token], "original_selectors": records[token]["original"], "prepared_selectors": records[token]["prepared"], "service_state": {"ActiveState": "active", "UnitFileState": "enabled"}}
        if action == "status":
            return {"phase": "active", "changes": changes[token], "current_sha256": snapshot()["env_sha256"]}
        if action == "restore":
            selectors.clear(); selectors.update(saved.pop(token)); changes.pop(token, None); records.pop(token, None)
            return {"phase": "restored"}
        if action == "recover": return []
    if scenario == "io" and action == "cleanup": return {"phase": "stopped", "workload_cleanup_complete": True}
    if scenario == "io" and action == "destroy": return {"phase": "destroyed", "cleanup_complete": True}
    if scenario == "oom" and action == "release": return {"released": True, "owned": False}
    if action == "cleanup": return {"cleaned": True, "cleanup_complete": True, "owned": False}
    if action in {"release", "stop"}: return {"released": True, "owned": action != "release", "stopped": True}
    return {"phase": action, "owned": True}
def api_reader(path, params):
    if path == "/configuration": body = facts["configuration"]
    elif path.startswith("/nodes/"):
        node = path.split("/")[2]
        body = {"fresh": True, "active_incident_count": 0, "sample": {"boot_id": facts["boots"][node]}}
    else: body = {"status": "ok"}
    return {"status_code": 200, "body": body}
class NoFd:
    def readline(self, limit): return sys.stdin.buffer.readline(limit)
serve(Path("/protected"), NoFd(), sys.stdout.buffer, runner=runner, session=session, api_reader=api_reader)
"""

    def factory(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        host = next(part.split("@", 1)[1] for part in argv if part.startswith("ec2-user@"))
        role = next(name for name, address in role_hosts.items() if address == host)
        hello = hello_receipt(live_connection, role)
        session = {
            "batch_id": value["batch_id"],
            "session_id": hello["session_id"],
            "protected_manifest_sha256": hello["protected_manifest_sha256"],
            "controller_bundle_sha256": hello["controller_bundle_sha256"],
            "identity": hello["identity"],
        }
        facts = {
            "selectors": {
                "FLEETDOCTOR_CGROUPS": list(value["resources"]["oom"]["existing_cgroups"][role]),
                "FLEETDOCTOR_CPU_PIDS": (
                    []
                    if role == "monitor"
                    else list(value["resources"]["fd"][role]["existing_cpu_pids"])
                ),
            },
            "configuration": value["configuration"]["collector"],
            "boots": {
                node: live_connection["roles"][node]["boot_id"] for node in ("node-a", "node-b")
            },
        }
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            [os.fspath(Path.cwd() / "deploy"), environment.get("PYTHONPATH", "")]
        )
        return real_popen(
            [sys.executable, "-c", server_code, role, json.dumps(session), json.dumps(facts)],
            env=environment,
            **kwargs,
        )

    monkeypatch.setattr(subprocess, "Popen", factory)
    transports = {
        role: connection.PersistentSshTransport(
            role,
            live_connection["roles"][role],
            key,
            value["batch_id"],
            call_timeout_seconds=5,
        )
        for role in ("monitor", "node-a", "node-b")
    }
    try:
        prepared = campaign.prepare_runtime(value, transports)
        value["preparation_receipt_sha256"] = digest(prepared)
        expected = {
            (row["scenario"], row["repetition"], row["target"]): row for row in attempts(value)
        }
        observed: list[tuple[str, str]] = []

        class Adapter:
            def __init__(self, scenario: str) -> None:
                self.scenario = scenario

            def execute(self, item: AdapterContext) -> dict[str, Any]:
                observed.append((self.scenario, item.target))
                return deepcopy(expected[(self.scenario, item.repetition, item.target)])

        monkeypatch.setattr(campaign, "ADAPTERS", {name: Adapter(name) for name in SCENARIOS})
        completed = campaign.run_campaign(
            value,
            tmp_path / f"authenticated-{kind}",
            connection.MonitorBackend(transports["monitor"]),
            transports,
            lease_root=tmp_path / f"authenticated-leases-{kind}",
        )
        assert len(completed) == attempt_count
        assert sum(2 if scenario == "network" else 1 for scenario, _ in observed) == phase_count
        restored = campaign.restore_prepared_runtime(value, prepared, transports)
        assert restored["status"] == "passed"
    finally:
        for transport in transports.values():
            transport.close()


def test_network_median_of_per_run_maxima_is_independently_enforced() -> None:
    value = manifest()
    rows = attempts(value)
    network = [item for item in rows if item["scenario"] == "network"]
    latency = [31.0, 31.0, 1.0, 1.0, 1.0]
    loss = [1.0, 1.0, 31.0, 31.0, 1.0]
    for item, left, right in zip(network, latency, loss, strict=True):
        for phase, timing in zip(item["phases"], (left, right), strict=True):
            phase["diagnosis_monotonic"] = phase["trigger_monotonic"] + timing
            phase["trigger_to_diagnosis_seconds"] = timing
    report = validate_attempts(value, rows)
    assert report["scenarios"]["network"]["phase_values_seconds"]["latency"] == latency
    assert report["scenarios"]["network"]["median_seconds"] == 31
    assert report["status"] == "failed"


@pytest.mark.parametrize(
    "damage",
    ["missing", "duplicate", "mixed", "failed", "late", "forged", "nonfinite", "replayed_incident"],
)
def test_incomplete_mixed_failed_late_and_forged_batches_fail_closed(damage: str) -> None:
    value = manifest()
    rows = attempts(value)
    if damage == "missing":
        rows.pop()
    elif damage == "duplicate":
        rows[-1] = deepcopy(rows[0])
    elif damage == "mixed":
        rows[0]["source_sha256"] = "0" * 64
    elif damage == "failed":
        rows[0]["cleanup_complete"] = False
    elif damage == "late":
        rows[0]["phases"][0]["diagnosis_monotonic"] = 161.0
        rows[0]["phases"][0]["trigger_to_diagnosis_seconds"] = 61.0
    elif damage == "forged":
        rows[0]["phases"][0]["trigger_to_diagnosis_seconds"] = 1.0
    elif damage == "nonfinite":
        rows[0]["phases"][0]["diagnosis_monotonic"] = float("inf")
    else:
        rows[1]["incident_ids"] = list(rows[0]["incident_ids"])
    assert validate_attempts(value, rows)["status"] == "failed"


def test_raw_linkage_cannot_be_rewritten_around_unchanged_helper_events() -> None:
    value = manifest()
    rows = attempts(value)
    row = rows[0]
    row["phases"][0]["diagnosis_monotonic"] += 1
    row["phases"][0]["trigger_to_diagnosis_seconds"] += 1
    row["phases"][0]["injection_to_diagnosis_seconds"] += 1
    row["raw_report"]["campaign_linkage"] = {
        "incident_ids": row["incident_ids"],
        "phases": row["phases"],
    }
    row["raw_report_sha256"] = digest(row["raw_report"])
    assert validate_attempts(value, rows)["status"] == "failed"


def test_transport_close_allows_declared_root_teardown_reserve() -> None:
    class CleanupProcess:
        stdin = None
        waits: list[float]

        def __init__(self) -> None:
            self.waits = []

        def wait(self, timeout: float) -> int:
            self.waits.append(timeout)
            if timeout < 150:
                raise subprocess.TimeoutExpired("owned controller cleanup", timeout)
            return 0

    process = CleanupProcess()
    transport = object.__new__(campaign.LegacyPersistentSshTransport)
    transport.closed = False
    transport.broken = False
    transport.process = cast(subprocess.Popen[bytes], process)
    transport.close()
    assert process.waits == [campaign.CAMPAIGN_TEARDOWN_RESERVE_SECONDS]
    assert transport.closed and not transport.broken


def test_recovery_cli_restores_monitor_and_both_agent_scopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = manifest()
    live_connection = connection_receipt(value)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    connection_path = tmp_path / "connection.json"
    connection_path.write_text(json.dumps(live_connection), encoding="utf-8")
    output = tmp_path / "recovery.json"
    calls: list[tuple[str, str]] = []

    class RecoveryTransport:
        def __init__(self, role: str) -> None:
            self.role = role
            self.hello_receipt = {"role": role}

        def call(
            self,
            scenario: str,
            action: str,
            token: str,
            arguments: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            assert scenario == "config" and action == "lookup"
            assert token == campaign.preparation_token(value, self.role)
            assert arguments is not None
            calls.append((self.role, arguments["scope"]))
            return {"token": token, "state": "absent"}

        def __enter__(self) -> RecoveryTransport:
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
            return None

    @contextmanager
    def fake_transports(*args: Any, **kwargs: Any) -> Any:
        yield {role: RecoveryTransport(role) for role in ("monitor", "node-a", "node-b")}

    monkeypatch.setattr(campaign, "verified_transports", fake_transports)
    monkeypatch.setattr(campaign, "recover_campaign_lock", lambda *args: {"status": "absent"})
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chaos_campaign.py",
            "recover",
            "--manifest",
            str(manifest_path),
            "--connection-receipt",
            str(connection_path),
            "--key",
            str(tmp_path / "key"),
            "--output",
            str(output),
        ],
    )
    campaign.main()
    assert calls == [("node-b", "agent"), ("node-a", "agent"), ("monitor", "monitor")]
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "passed" and set(result["nodes"]) == {"monitor", "node-a", "node-b"}


def test_recover_cli_reopens_authenticated_cleanup_sessions_after_receipt_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = manifest()
    live_connection = connection_receipt(value)
    live_connection["checked_at"] = (datetime.now(UTC) - timedelta(seconds=601)).isoformat()
    role_hosts = {"monitor": "127.0.0.1", "node-a": "127.0.0.2", "node-b": "127.0.0.3"}
    for role, host in role_hosts.items():
        facts = live_connection["roles"][role]
        facts["ssh_host"] = host
        facts["inventory"]["ssh_host"] = host
        facts["inventory_sha256"] = digest(facts["inventory"])
        facts["host_key_attestation"]["host"] = host
        facts["host_key_attestation_sha256"] = digest(facts["host_key_attestation"])
    value["connection_receipt_sha256"] = digest(live_connection)
    original_connection = json.dumps(live_connection, sort_keys=True)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    connection_path = tmp_path / "connection.json"
    connection_path.write_text(original_connection, encoding="utf-8")
    key = tmp_path / "synthetic-key"
    key.write_bytes(b"synthetic test key; never used by a network client")
    output = tmp_path / "recovery.json"
    real_popen = subprocess.Popen
    server_code = r"""
import json
import sys
from pathlib import Path
from chaos_controller import HELPERS, serve

session = json.loads(sys.argv[1])
def option(argv, name): return argv[argv.index(name) + 1]
def runner(argv):
    scenario = next(name for name, relative in HELPERS.items() if Path(argv[1]).name == Path(relative).name)
    action = argv[2]
    token = option(argv, "--token") if "--token" in argv else ""
    if scenario == "config" and action == "lookup":
        return {"token": token, "state": "absent"}
    raise AssertionError((scenario, action, token))
class NoFd:
    def readline(self, limit): return sys.stdin.buffer.readline(limit)
serve(Path("/protected"), NoFd(), sys.stdout.buffer, runner=runner, session=session)
"""

    def factory(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        host = next(part.split("@", 1)[1] for part in argv if part.startswith("ec2-user@"))
        role = next(name for name, address in role_hosts.items() if address == host)
        hello = hello_receipt(live_connection, role)
        session = {
            "batch_id": value["batch_id"],
            "session_id": hello["session_id"],
            "protected_manifest_sha256": hello["protected_manifest_sha256"],
            "controller_bundle_sha256": hello["controller_bundle_sha256"],
            "identity": hello["identity"],
        }
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            [os.fspath(Path.cwd() / "deploy"), environment.get("PYTHONPATH", "")]
        )
        return real_popen(
            [sys.executable, "-c", server_code, json.dumps(session)],
            env=environment,
            **kwargs,
        )

    monkeypatch.setattr(subprocess, "Popen", factory)
    monkeypatch.setattr(campaign, "recover_campaign_lock", lambda *args: {"status": "absent"})
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chaos_campaign.py",
            "recover",
            "--manifest",
            str(manifest_path),
            "--connection-receipt",
            str(connection_path),
            "--key",
            str(key),
            "--output",
            str(output),
        ],
    )
    campaign.main()
    assert connection_path.read_text(encoding="utf-8") == original_connection
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "passed"
    assert all(item["state"] == "absent" for item in result["nodes"].values())


@pytest.mark.parametrize("action", ["validate", "dry", "prepare-runtime", "preflight", "run"])
def test_stale_receipt_rejects_every_new_work_cli_before_transport_or_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    value = manifest()
    stale = connection_receipt(value)
    stale["checked_at"] = (datetime.now(UTC) - timedelta(seconds=601)).isoformat()
    value["connection_receipt_sha256"] = digest(stale)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    connection_path = tmp_path / "connection.json"
    connection_path.write_text(json.dumps(stale), encoding="utf-8")
    runtime_path = tmp_path / "runtime.json"
    runtime_path.write_text("{}", encoding="utf-8")
    key = tmp_path / "key"
    key.write_bytes(b"not opened")

    def forbidden_popen(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("stale new-work receipt reached transport creation")

    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)
    argv = [
        "chaos_campaign.py",
        action,
        "--manifest",
        str(manifest_path),
        "--connection-receipt",
        str(connection_path),
    ]
    if action == "dry":
        argv.extend(["--checkout", str(Path.cwd()), "--output", str(tmp_path / "dry.json")])
    elif action == "prepare-runtime":
        argv.extend(["--key", str(key), "--output", str(tmp_path / "prepare.json")])
    elif action == "preflight":
        argv.extend(
            [
                "--checkout",
                str(Path.cwd()),
                "--key",
                str(key),
                "--runtime-receipt",
                str(runtime_path),
                "--output",
                str(tmp_path / "preflight.json"),
            ]
        )
    elif action == "run":
        argv.extend(
            [
                "--checkout",
                str(Path.cwd()),
                "--key",
                str(key),
                "--runtime-receipt",
                str(runtime_path),
                "--output-dir",
                str(tmp_path / "run"),
            ]
        )
    monkeypatch.setattr(sys, "argv", argv)

    with pytest.raises(ValueError, match="stale for new work"):
        campaign.main()


def test_cleanup_lookup_rejects_altered_prepared_environment_before_adopt() -> None:
    value = manifest()
    role = "node-a"
    original: dict[str, Any] = {
        "env_sha256": "1" * 64,
        "selectors": {
            "FLEETDOCTOR_CGROUPS": list(value["resources"]["oom"]["existing_cgroups"][role]),
            "FLEETDOCTOR_CPU_PIDS": list(value["resources"]["fd"][role]["existing_cpu_pids"]),
        },
        "missing_keys": [],
    }
    changes = campaign.declared_preparation_changes(value)[role]
    prepared_selectors = {key: list(items) for key, items in original["selectors"].items()}
    for key, raw in changes.items():
        prepared_selectors[key] = (
            [int(item) for item in raw.split(",")]
            if key.endswith("PIDS") and raw
            else (raw.split(",") if raw else [])
        )
    observed = {
        "token": campaign.preparation_token(value, role),
        "state": "active",
        "phase": "active",
        "original_sha256": original["env_sha256"],
        "updated_sha256": "2" * 64,
        "current_sha256": "3" * 64,
        "changes": changes,
        "original_selectors": original,
        "prepared_selectors": {
            "env_sha256": "2" * 64,
            "selectors": prepared_selectors,
            "missing_keys": [],
        },
        "service_state": {"ActiveState": "active", "UnitFileState": "enabled"},
    }

    with pytest.raises(ValueError, match="exact active owner"):
        campaign._validate_cleanup_lookup(value, role, observed)


@pytest.mark.parametrize(
    ("kind", "targets", "attempt_count", "phase_count"),
    [
        ("calibration", ("node-a", "node-b"), 16, 18),
        ("measured", ASSIGNMENT, 40, 45),
    ],
)
def test_delayed_cli_lifecycle_restores_exact_state_through_fresh_cleanup_sessions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    targets: tuple[str, ...],
    attempt_count: int,
    phase_count: int,
) -> None:
    validation_time = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)

    class FrozenDateTime(datetime):
        current = validation_time

        @classmethod
        def now(cls, tz: Any = None) -> FrozenDateTime:
            current = cls.current if tz is not None else cls.current.replace(tzinfo=None)
            return cls(
                current.year,
                current.month,
                current.day,
                current.hour,
                current.minute,
                current.second,
                current.microsecond,
                tzinfo=current.tzinfo,
                fold=current.fold,
            )

    monkeypatch.setattr(connection, "datetime", FrozenDateTime)
    value = manifest()
    value["kind"] = kind
    value["assignments"] = {scenario: list(targets) for scenario in SCENARIOS}
    value["resources"]["oom"]["leaf_paths"] = [
        oom_leaf_path(attempt_token(value, "oom", repetition, target))
        for repetition, target in enumerate(targets)
    ]
    live_connection = connection_receipt(value)
    live_connection["checked_at"] = validation_time.isoformat()
    role_hosts = {"monitor": "127.0.0.1", "node-a": "127.0.0.2", "node-b": "127.0.0.3"}
    state_paths: dict[str, Path] = {}
    original_states: dict[str, dict[str, Any]] = {}
    foreign_token = "f" * 32
    for role, host in role_hosts.items():
        facts = live_connection["roles"][role]
        facts["ssh_host"] = host
        facts["inventory"]["ssh_host"] = host
        facts["inventory_sha256"] = digest(facts["inventory"])
        facts["host_key_attestation"]["host"] = host
        facts["host_key_attestation_sha256"] = digest(facts["host_key_attestation"])
        selectors = {
            "FLEETDOCTOR_CGROUPS": list(value["resources"]["oom"]["existing_cgroups"][role]),
            "FLEETDOCTOR_CPU_PIDS": (
                []
                if role == "monitor"
                else list(value["resources"]["fd"][role]["existing_cpu_pids"])
            ),
        }
        raw = (f"SECRET_{role}=preserved\n" + json.dumps(selectors, sort_keys=True)).encode()
        state = {
            "env_hex": raw.hex(),
            "selectors": selectors,
            "metadata": {"mode": 0o600, "uid": 0, "gid": 0},
            "service_state": {"ActiveState": "active", "UnitFileState": "enabled"},
            "transactions": {},
            "foreign_transactions": {
                foreign_token: {"batch": "another-batch", "bytes": "unchanged"}
            },
        }
        state_path = tmp_path / f"state-{role}.json"
        state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        state_paths[role] = state_path
        original_states[role] = deepcopy(state)
    value["connection_receipt_sha256"] = digest(live_connection)
    manifest_path = tmp_path / f"manifest-{kind}.json"
    connection_path = tmp_path / f"connection-{kind}.json"
    key = tmp_path / f"synthetic-{kind}.key"
    key.write_bytes(b"synthetic fixture key; no network use")
    connection_bytes = json.dumps(live_connection, sort_keys=True)
    connection_path.write_text(connection_bytes, encoding="utf-8")
    manifest_path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    real_popen = subprocess.Popen
    opened_roles: list[str] = []
    server_code = r"""
import hashlib
import json
import sys
from pathlib import Path
from chaos_controller import HELPERS, serve

role = sys.argv[1]
session = json.loads(sys.argv[2])
state_path = Path(sys.argv[3])
facts = json.loads(sys.argv[4])
def read_state(): return json.loads(state_path.read_text())
def write_state(state): state_path.write_text(json.dumps(state, sort_keys=True))
def option(argv, name): return argv[argv.index(name) + 1]
def selector_snapshot(state):
    return {"env_sha256": hashlib.sha256(bytes.fromhex(state["env_hex"])).hexdigest(), "selectors": json.loads(json.dumps(state["selectors"])), "missing_keys": []}
def runner(argv):
    scenario = next(name for name, relative in HELPERS.items() if Path(argv[1]).name == Path(relative).name)
    action = argv[2]
    token = option(argv, "--token") if "--token" in argv else (argv[3] if scenario == "io" else "")
    state = read_state()
    if scenario == "config":
        if action == "inventory":
            return {**selector_snapshot(state), **state["metadata"], "service_state": state["service_state"]}
        if action == "begin":
            expected = json.loads(option(argv, "--expected-before-json"))
            if expected != selector_snapshot(state): raise ValueError("stale expected-before")
            changes = json.loads(option(argv, "--changes-json"))
            original = selector_snapshot(state)
            original_hex = state["env_hex"]
            for key, value in changes.items():
                state["selectors"][key] = [] if value == "" else ([int(item) for item in value.split(",")] if key.endswith("PIDS") else value.split(","))
            state["env_hex"] = (bytes.fromhex(original_hex) + json.dumps(changes, sort_keys=True).encode()).hex()
            prepared = selector_snapshot(state)
            state["transactions"][token] = {"original_hex": original_hex, "original": original, "prepared": prepared, "changes": changes}
            write_state(state)
            return {"phase": "applied", "original_selectors": original, "prepared_selectors": prepared}
        if action == "status":
            record = state["transactions"][token]
            return {"phase": "active", "changes": record["changes"], "current_sha256": selector_snapshot(state)["env_sha256"]}
        if action == "lookup":
            if token not in state["transactions"]: return {"token": token, "state": "absent"}
            record = state["transactions"][token]
            return {"token": token, "state": "active", "phase": "active", "original_sha256": record["original"]["env_sha256"], "updated_sha256": record["prepared"]["env_sha256"], "current_sha256": selector_snapshot(state)["env_sha256"], "changes": record["changes"], "original_selectors": record["original"], "prepared_selectors": record["prepared"], "service_state": state["service_state"]}
        if action == "restore":
            record = state["transactions"].pop(token)
            state["env_hex"] = record["original_hex"]
            state["selectors"] = record["original"]["selectors"]
            write_state(state)
            return {"token": token, "phase": "restored", "original_sha256": record["original"]["env_sha256"], "restored_sha256": selector_snapshot(state)["env_sha256"], "service_state": state["service_state"], "observed_service_state": state["service_state"]}
    if scenario == "io" and action == "cleanup": return {"phase": "stopped", "workload_cleanup_complete": True}
    if scenario == "io" and action == "destroy": return {"phase": "destroyed", "cleanup_complete": True}
    if scenario == "oom" and action == "release": return {"released": True, "owned": False}
    if action == "cleanup": return {"cleaned": True, "cleanup_complete": True, "owned": False}
    if action in {"release", "stop"}: return {"released": True, "owned": action != "release", "stopped": True}
    return {"phase": action, "owned": True}
def api_reader(path, params):
    if path == "/configuration": body = facts["configuration"]
    elif path.startswith("/nodes/"):
        node = path.split("/")[2]
        body = {"fresh": True, "active_incident_count": 0, "sample": {"boot_id": facts["boots"][node]}}
    else: body = {"status": "ok"}
    return {"status_code": 200, "body": body}
class NoFd:
    def readline(self, limit): return sys.stdin.buffer.readline(limit)
serve(Path("/protected"), NoFd(), sys.stdout.buffer, runner=runner, session=session, api_reader=api_reader)
"""

    def factory(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        host = next(part.split("@", 1)[1] for part in argv if part.startswith("ec2-user@"))
        role = next(name for name, address in role_hosts.items() if address == host)
        opened_roles.append(role)
        hello = hello_receipt(live_connection, role, session=str((len(opened_roles) % 8) + 1))
        session = {
            "batch_id": value["batch_id"],
            "session_id": hello["session_id"],
            "protected_manifest_sha256": hello["protected_manifest_sha256"],
            "controller_bundle_sha256": hello["controller_bundle_sha256"],
            "identity": hello["identity"],
        }
        facts = {
            "configuration": value["configuration"]["collector"],
            "boots": {
                node: live_connection["roles"][node]["boot_id"] for node in ("node-a", "node-b")
            },
        }
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            [os.fspath(Path.cwd() / "deploy"), environment.get("PYTHONPATH", "")]
        )
        return real_popen(
            [
                sys.executable,
                "-c",
                server_code,
                role,
                json.dumps(session),
                str(state_paths[role]),
                json.dumps(facts),
            ],
            env=environment,
            **kwargs,
        )

    monkeypatch.setattr(subprocess, "Popen", factory)
    monkeypatch.setattr(campaign, "verify_source", lambda *args: value["source"])
    monkeypatch.setattr(
        campaign,
        "live_preflight",
        lambda *args, **kwargs: {"status": "passed", "batch_id": value["batch_id"]},
    )
    monkeypatch.setattr(campaign, "lab_lease_path", lambda *args: tmp_path / f"lease-{kind}.json")
    monkeypatch.setattr(campaign, "recover_campaign_lock", lambda *args: {"status": "absent"})
    expected = {(row["scenario"], row["repetition"], row["target"]): row for row in attempts(value)}
    observed: list[tuple[str, str]] = []

    class Adapter:
        def __init__(self, scenario: str) -> None:
            self.scenario = scenario

        def execute(self, item: AdapterContext) -> dict[str, Any]:
            observed.append((self.scenario, item.target))
            return deepcopy(expected[(self.scenario, item.repetition, item.target)])

    monkeypatch.setattr(campaign, "ADAPTERS", {name: Adapter(name) for name in SCENARIOS})
    prepare_path = tmp_path / f"prepared-{kind}.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chaos_campaign.py",
            "prepare-runtime",
            "--manifest",
            str(manifest_path),
            "--connection-receipt",
            str(connection_path),
            "--key",
            str(key),
            "--output",
            str(prepare_path),
        ],
    )
    campaign.main()
    prepared = json.loads(prepare_path.read_text(encoding="utf-8"))
    value["preparation_receipt_sha256"] = digest(prepared)
    manifest_path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    runtime_path = tmp_path / f"runtime-{kind}.json"
    runtime_path.write_text("{}", encoding="utf-8")
    run_output = tmp_path / f"run-{kind}"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chaos_campaign.py",
            "run",
            "--manifest",
            str(manifest_path),
            "--checkout",
            str(Path.cwd()),
            "--connection-receipt",
            str(connection_path),
            "--runtime-receipt",
            str(runtime_path),
            "--key",
            str(key),
            "--output-dir",
            str(run_output),
        ],
    )
    campaign.main()
    assert len(observed) == attempt_count
    assert sum(2 if scenario == "network" else 1 for scenario, _ in observed) == phase_count
    manifest_bytes = manifest_path.read_text(encoding="utf-8")
    preparation_bytes = prepare_path.read_text(encoding="utf-8")
    FrozenDateTime.current = validation_time + timedelta(seconds=601)
    before_stale_check = len(opened_roles)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chaos_campaign.py",
            "validate",
            "--manifest",
            str(manifest_path),
            "--connection-receipt",
            str(connection_path),
        ],
    )
    with pytest.raises(ValueError, match="stale for new work"):
        campaign.main()
    assert len(opened_roles) == before_stale_check
    # Model a prior cleanup attempt that completed one exact role before interruption.
    state_paths["node-b"].write_text(
        json.dumps(original_states["node-b"], sort_keys=True), encoding="utf-8"
    )
    restore_path = tmp_path / f"restore-{kind}.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chaos_campaign.py",
            "restore-runtime",
            "--manifest",
            str(manifest_path),
            "--preparation-receipt",
            str(prepare_path),
            "--connection-receipt",
            str(connection_path),
            "--key",
            str(key),
            "--output",
            str(restore_path),
        ],
    )
    campaign.main()
    assert json.loads(restore_path.read_text(encoding="utf-8"))["status"] == "passed"
    recovery_path = tmp_path / f"recovery-{kind}.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chaos_campaign.py",
            "recover",
            "--manifest",
            str(manifest_path),
            "--connection-receipt",
            str(connection_path),
            "--key",
            str(key),
            "--output",
            str(recovery_path),
        ],
    )
    campaign.main()
    recovery = json.loads(recovery_path.read_text(encoding="utf-8"))
    assert recovery["status"] == "passed"
    assert all(item["state"] == "absent" for item in recovery["nodes"].values())
    assert opened_roles == ["monitor", "node-a", "node-b"] * 4
    assert connection_path.read_text(encoding="utf-8") == connection_bytes
    assert manifest_path.read_text(encoding="utf-8") == manifest_bytes
    assert prepare_path.read_text(encoding="utf-8") == preparation_bytes
    for role, state_path in state_paths.items():
        restored = json.loads(state_path.read_text(encoding="utf-8"))
        assert restored == original_states[role]


def test_persistent_ssh_transport_bounds_stalled_partial_and_dead_peers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_popen = subprocess.Popen
    launched: list[list[str]] = []

    def run_case(code: str) -> campaign.LegacyPersistentSshTransport:
        def factory(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
            launched.append(argv)
            return real_popen([sys.executable, "-c", code], **kwargs)

        monkeypatch.setattr(subprocess, "Popen", factory)
        return campaign.LegacyPersistentSshTransport(
            "127.0.0.1",
            tmp_path / "key",
            tmp_path / "known-hosts",
            call_timeout_seconds=1,
        )

    stalled = run_case("import sys,time; sys.stdin.buffer.readline(); time.sleep(30)")
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="finite deadline"):
        stalled.call("cpu", "status", "1" * 32)
    assert time.monotonic() - started < 8 and stalled.broken
    with pytest.raises(RuntimeError, match="not live"):
        stalled.call("cpu", "status", "1" * 32)

    partial = run_case(
        "import sys,time; sys.stdin.buffer.readline(); "
        "sys.stdout.buffer.write(b'{\\\"id\\\":'); sys.stdout.buffer.flush(); time.sleep(30)"
    )
    with pytest.raises(TimeoutError, match="finite deadline"):
        partial.call("cpu", "status", "2" * 32)

    dead = run_case("raise SystemExit(7)")
    dead.process.wait(timeout=5)
    with pytest.raises(RuntimeError, match="not live"):
        dead.call("cpu", "status", "3" * 32)
    with pytest.raises(RuntimeError, match="controller failed"):
        dead.close()
    assert any("ConnectTimeout=10" in argument for argument in launched[-1])
    assert any("ServerAliveCountMax=3" in argument for argument in launched[-1])


def test_persistent_transport_close_drives_owned_fault_then_config_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "actions.json"
    real_popen = subprocess.Popen
    code = r"""
import json
import sys
from pathlib import Path
from chaos_controller import serve

marker = Path(sys.argv[1])
actions = []
def runner(argv):
    actions.append(argv[2])
    marker.write_text(json.dumps(actions))
    if argv[2] == "restore": return {"phase": "restored"}
    if argv[2] == "cleanup": return {"cleaned": True, "owned": False}
    return {"phase": "active", "owned": True}
class NoFd:
    def readline(self, limit): return sys.stdin.buffer.readline(limit)
serve(Path("/protected"), NoFd(), sys.stdout.buffer, runner=runner)
"""

    def factory(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            [os.fspath(Path.cwd() / "deploy"), environment.get("PYTHONPATH", "")]
        )
        return real_popen(
            [sys.executable, "-c", code, os.fspath(marker)], env=environment, **kwargs
        )

    monkeypatch.setattr(subprocess, "Popen", factory)
    transport = campaign.LegacyPersistentSshTransport(
        "127.0.0.1", tmp_path / "key", tmp_path / "known-hosts", call_timeout_seconds=5
    )
    transport.call(
        "config",
        "begin",
        "1" * 32,
        {
            "scope": "agent",
            "changes": {"FLEETDOCTOR_CGROUPS": "/owned"},
            "expected_before": {
                "env_sha256": "a" * 64,
                "selectors": {"FLEETDOCTOR_CGROUPS": [], "FLEETDOCTOR_CPU_PIDS": []},
                "missing_keys": [],
            },
        },
    )
    transport.call("cpu", "start", "2" * 32, {"workers": 2, "seconds": 30})
    transport.close()
    assert json.loads(marker.read_text()) == ["begin", "start", "cleanup", "restore"]


def test_real_run_campaign_schedule_uses_prepared_serve_transports_and_restores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_popen = subprocess.Popen
    controller_code = r"""
import json
import sys
from pathlib import Path
from chaos_controller import HELPERS, serve

configs = {}
records = {}
def option(argv, name):
    return argv[argv.index(name) + 1]
def runner(argv):
    scenario = next(name for name, relative in HELPERS.items() if Path(argv[1]).name == Path(relative).name)
    action = argv[2]
    token = option(argv, "--token") if "--token" in argv else (argv[3] if scenario == "io" else "")
    if scenario == "config":
        if action == "inventory":
            return {"env_sha256": "a" * 64, "selectors": {"FLEETDOCTOR_CGROUPS": [], "FLEETDOCTOR_CPU_PIDS": []}, "missing_keys": [], "mode": 384, "uid": 0, "gid": 0, "service_state": {"ActiveState": "active", "UnitFileState": "enabled"}}
        if action == "begin":
            configs[token] = json.loads(option(argv, "--changes-json"))
            original = json.loads(option(argv, "--expected-before-json"))
            prepared = {"env_sha256": "a" * 64, "selectors": {"FLEETDOCTOR_CGROUPS": [] if not configs[token].get("FLEETDOCTOR_CGROUPS") else configs[token]["FLEETDOCTOR_CGROUPS"].split(","), "FLEETDOCTOR_CPU_PIDS": []}, "missing_keys": []}
            records[token] = {"original": original, "prepared": prepared}
            return {"phase": "applied", "changes": configs[token], "original_selectors": original, "prepared_selectors": prepared}
        if action == "lookup":
            if token not in records: return {"token": token, "state": "absent"}
            return {"token": token, "state": "active", "phase": "active", "original_sha256": records[token]["original"]["env_sha256"], "updated_sha256": "a" * 64, "current_sha256": "a" * 64, "changes": configs[token], "original_selectors": records[token]["original"], "prepared_selectors": records[token]["prepared"], "service_state": {"ActiveState": "active", "UnitFileState": "enabled"}}
        if action == "status":
            return {"phase": "active", "changes": configs[token]}
        if action == "restore":
            configs.pop(token); records.pop(token)
            return {"phase": "restored"}
    if scenario == "io" and action == "cleanup":
        return {"phase": "stopped", "workload_cleanup_complete": True}
    if scenario == "io" and action == "destroy":
        return {"phase": "destroyed", "cleanup_complete": True}
    if scenario == "fd" and action == "release":
        return {"phase": "released", "released": True, "owned": True}
    if scenario == "oom" and action == "release":
        return {"released": True, "owned": False}
    if action == "cleanup":
        return {"cleaned": True, "cleanup_complete": True, "owned": False}
    return {"phase": action, "owned": True, "stopped": action == "stop"}
class NoFd:
    def readline(self, limit): return sys.stdin.buffer.readline(limit)
serve(Path("/protected"), NoFd(), sys.stdout.buffer, runner=runner)
"""

    def factory(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            [os.fspath(Path.cwd() / "deploy"), environment.get("PYTHONPATH", "")]
        )
        return real_popen([sys.executable, "-c", controller_code], env=environment, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", factory)
    value = manifest()
    live_connection = connection_receipt(value)
    transports = {
        role: campaign.LegacyPersistentSshTransport(
            address,
            tmp_path / "key",
            tmp_path / "known-hosts",
            call_timeout_seconds=5,
        )
        for role, address in (
            ("monitor", "127.0.0.1"),
            ("node-a", "127.0.0.2"),
            ("node-b", "127.0.0.3"),
        )
    }
    for role, transport in transports.items():
        cast(Any, transport).hello_receipt = hello_receipt(live_connection, role)
        cast(Any, transport).role_receipt = live_connection["roles"][role]
    prepared = campaign.prepare_runtime(value, transports)
    value["preparation_receipt_sha256"] = digest(prepared)
    expected = {(row["scenario"], row["repetition"], row["target"]): row for row in attempts(value)}
    contexts: list[tuple[str, str, str]] = []

    class FixtureAdapter:
        def __init__(self, name: str) -> None:
            self.name = name

        def execute(self, item: AdapterContext) -> dict[str, Any]:
            contexts.append((self.name, item.target, item.reference))
            item.clock.sleep(25)
            if self.name in {"disk", "inode"}:
                item.transport.call(self.name, "start", item.token, {"duration": 30})
                item.transport.call(self.name, "cleanup", item.token)
            elif self.name == "fd":
                selector = digest(item.token + "selector")[:32]
                item.transport.call("fd", "start", item.token, {"limit": 128, "seconds": 30})
                item.transport.call(
                    "config",
                    "begin",
                    selector,
                    {
                        "scope": "agent",
                        "parent_token": campaign.preparation_token(value, item.target),
                        "changes": {"FLEETDOCTOR_CPU_PIDS": "123"},
                        "expected_before": {
                            "env_sha256": "a" * 64,
                            "selectors": {"FLEETDOCTOR_CGROUPS": [], "FLEETDOCTOR_CPU_PIDS": []},
                            "missing_keys": [],
                        },
                    },
                )
                item.transport.call("fd", "pressure", item.token)
                item.transport.call("fd", "release", item.token)
                item.transport.call("fd", "cleanup", item.token)
                item.transport.call("config", "restore", selector, {"scope": "agent"})
            elif self.name == "oom":
                item.transport.call("oom", "prepare", item.token, {"lease_seconds": 360})
                item.transport.call("oom", "start", item.token)
                item.transport.call("oom", "stop", item.token)
                item.transport.call("oom", "release", item.token)
            elif self.name == "network":
                for profile in ("latency", "loss"):
                    item.transport.call(
                        "network",
                        "start",
                        item.token,
                        {"target": "10.0.0.10", "profile": profile, "duration": 30},
                    )
                    item.transport.call("network", "cleanup", item.token)
            elif self.name == "io":
                assert item.transports is not None
                reference_token = digest(item.token + ":reference")[:32]
                item.transport.call("io", "prepare", item.token)
                item.transports[item.reference].call("io", "prepare", reference_token)
                item.transport.call("io", "start", item.token, {"duration": 30})
                item.transport.call("io", "cleanup", item.token)
                item.transport.call("io", "destroy", item.token)
                item.transports[item.reference].call("io", "destroy", reference_token)
            else:
                arguments = (
                    {"workers": 2, "seconds": 30} if self.name == "cpu" else {"duration": 30}
                )
                item.transport.call(self.name, "start", item.token, arguments)
                item.transport.call(self.name, "cleanup", item.token)
            return deepcopy(expected[(self.name, item.repetition, item.target)])

    monkeypatch.setattr(
        campaign, "ADAPTERS", {scenario: FixtureAdapter(scenario) for scenario in SCENARIOS}
    )

    class CleanApi:
        def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
            if path == "/configuration":
                return cast(dict[str, Any], value["configuration"]["collector"])
            if path.startswith("/nodes/"):
                node = path.split("/")[2]
                return {
                    "fresh": True,
                    "active_incident_count": 0,
                    "sample": {"boot_id": live_connection["roles"][node]["boot_id"]},
                }
            raise AssertionError((path, params))

    clock = FakeClock()
    completed = campaign.run_campaign(
        value,
        tmp_path / "campaign-output",
        CleanApi(),
        transports,
        lease_root=tmp_path / "leases",
        clock_factory=lambda: clock,
    )
    assert len(completed) == 40 and len(contexts) == 40
    assert sum(2 if scenario == "network" else 1 for scenario, _, _ in contexts) == 45
    assert clock.now > 900
    assert [target for scenario, target, _ in contexts if scenario == "io"] == list(ASSIGNMENT)
    restored = campaign.restore_prepared_runtime(value, prepared, transports)
    assert restored["status"] == "passed" and set(restored["restored"]) == set(transports)
    for transport in transports.values():
        transport.close()
