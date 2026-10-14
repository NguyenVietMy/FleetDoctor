import argparse
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import restart_demo
import source_freeze
from chaos_harness import write_report
from lab import ROOT
from source_freeze import aggregate_digest

INCIDENT_ID = "00000000-0000-0000-0000-000000000001"


def canonical_incident(
    *, incident_id: str = INCIDENT_ID, status: str = "active", sequence: int = 1
) -> dict[str, Any]:
    return {
        "id": incident_id,
        "status": status,
        "opening_evidence": {"sequence": 1},
        "configuration": {"consecutive_samples": 3},
        "severity": "critical",
        "opened_at": "2026-10-13T12:00:00Z",
        "latest_evidence": {"sequence": sequence},
    }


class API:
    def __init__(self, healthy: bool = True, incidents: list[dict[str, Any]] | None = None) -> None:
        self.healthy = healthy
        self.incidents = incidents or [canonical_incident()]
        self.incident_calls = 0

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/health":
            if not self.healthy:
                raise ValueError("not ready")
            return {"status": "ok"}
        if path == "/nodes/node-b/metrics":
            return {"active_incident_count": 0}
        value = self.incidents[min(self.incident_calls, len(self.incidents) - 1)]
        self.incident_calls += 1
        return deepcopy(value)


def test_collector_identity_parses_real_space_separated_inspect_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        restart_demo,
        "bounded_command",
        lambda *args: '"container-id" 1234 "2026-10-13T18:00:00Z"\n',
    )
    assert restart_demo.collector_identity([], 100) == {
        "container_id": "container-id",
        "pid": 1234,
        "started_at": "2026-10-13T18:00:00Z",
    }


def test_restart_source_drift_is_rejected_before_inventory_or_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual: dict[str, Any] = {
        "repo": str(ROOT),
        "base": "f91267d5be2db914088f3f3c34375346621eafc4",
        "head": "f91267d5be2db914088f3f3c34375346621eafc4",
        "tree": "70216499b0ae8c809025234de37911eefa2fe1be",
        "files": [{"path": "README.md", "kind": "file", "sha256": "1" * 64}],
        "changed_files": ["README.md"],
        "diff_sha256": "2" * 64,
        "plan_sha256": "3" * 64,
    }
    actual["sha256"] = aggregate_digest(actual)
    monkeypatch.setattr(source_freeze, "current_inventory", lambda plan: deepcopy(actual))
    frozen = deepcopy(actual)
    frozen["files"][0]["sha256"] = "0" * 64
    frozen["sha256"] = aggregate_digest(frozen)
    source = tmp_path / "freeze.json"
    source.write_text(json.dumps(frozen), encoding="utf-8")

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("live boundary reached after invalid source")

    monkeypatch.setattr(restart_demo, "inventory", forbidden)
    monkeypatch.setattr(restart_demo, "addresses", forbidden)
    args = argparse.Namespace(source_freeze=source, preflight=tmp_path / "unused.json")
    with pytest.raises(ValueError, match="differs"):
        restart_demo.execute(args)


def configure_successful_execute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    validations: list[dict[str, Any] | BaseException],
) -> argparse.Namespace:
    source_hash = {"scripts/restart_demo.py": "1" * 64}
    preflight = tmp_path / "preflight.json"
    preflight.write_text(
        json.dumps(
            {
                "status": "passed",
                "source_sha256": source_hash,
                "finished_at": datetime.now(UTC).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    validation_calls = 0

    def validate(path: Path) -> dict[str, Any]:
        nonlocal validation_calls
        value = validations[validation_calls]
        validation_calls += 1
        if isinstance(value, BaseException):
            raise value
        return value

    class Injector:
        def __init__(self, ssh: list[str]) -> None:
            self.commands: list[list[str]] = []

        def probe(self) -> dict[str, Any]:
            return {"mapping": {"target": "/var/lib/fleetdoctor/chaos/disk"}}

    class SuccessfulHarness:
        def __init__(
            self,
            api: Any,
            injector: Any,
            target: str,
            reference: str,
            output: Path,
            environment: dict[str, Any],
        ) -> None:
            self.output = output
            self.report: dict[str, Any] = {
                "schema_version": 1,
                "scenario": "disk_fill_collector_restart",
                "status": "running",
                "errors": [],
            }
            self.max_injection_seconds = 180
            self.after_diagnosis: Any = None

        def run(self) -> dict[str, Any]:
            self.report["status"] = "passed"
            write_report(self.output, self.report)
            return self.report

    monkeypatch.setattr(restart_demo, "validate_source_freeze", validate)
    monkeypatch.setattr(restart_demo, "source_hashes", lambda: source_hash)
    monkeypatch.setattr(restart_demo, "inventory", lambda path: {})
    monkeypatch.setattr(restart_demo, "validate_live_scope", lambda profile, values: None)
    monkeypatch.setattr(
        restart_demo,
        "addresses",
        lambda profile, values: {"monitor": "monitor", "node-a": "a", "node-b": "b"},
    )
    monkeypatch.setattr(restart_demo, "load_env", lambda path: {})
    monkeypatch.setattr(restart_demo, "RemoteInjector", Injector)
    monkeypatch.setattr(restart_demo, "API", lambda value: object())
    monkeypatch.setattr(restart_demo, "DiskHarness", SuccessfulHarness)
    return argparse.Namespace(
        source_freeze=tmp_path / "freeze.json",
        preflight=preflight,
        inventory=tmp_path / "inventory.json",
        profile="fleetdoctor",
        env=tmp_path / "env",
        key=tmp_path / "key",
        api="http://127.0.0.1:8000",
        output=tmp_path / "result.json",
    )


def test_final_source_drift_atomically_replaces_retained_pass_with_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    freeze = {"sha256": "a" * 64, "plan_sha256": "b" * 64}
    failure = ValueError("injected final source drift")
    args = configure_successful_execute(tmp_path, monkeypatch, [freeze, failure])

    with pytest.raises(ValueError, match="injected final source drift") as raised:
        restart_demo.execute(args)
    assert raised.value is failure
    retained = json.loads(args.output.read_text(encoding="utf-8"))
    assert retained["status"] == "failed"
    assert retained["source_validation_final"] == {
        "status": "failed",
        "matched": False,
        "error_type": "ValueError",
        "error": "injected final source drift",
    }
    assert retained["errors"] == [
        "final source validation: ValueError: injected final source drift"
    ]


def test_successful_final_source_validation_retains_matched_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    freeze = {"sha256": "a" * 64, "plan_sha256": "b" * 64}
    args = configure_successful_execute(tmp_path, monkeypatch, [freeze, freeze])

    restart_demo.execute(args)
    retained = json.loads(args.output.read_text(encoding="utf-8"))
    assert retained["status"] == "passed"
    assert retained["source_validation_final"] == {
        "status": "matched",
        "aggregate_sha256": "a" * 64,
    }
    assert retained["errors"] == []


def configure_restart_seams(monkeypatch: pytest.MonkeyPatch) -> None:
    checkpoint = {
        "node_id": "node-a",
        "revision": 3,
        "latest": {"sequence": 3},
    }
    monkeypatch.setattr(
        restart_demo,
        "database_snapshot",
        lambda *args, **kwargs: {
            "incident": {"id": INCIDENT_ID, "status": "active"},
            "checkpoint": checkpoint,
        },
    )
    identities = iter(
        [
            {"container_id": "old", "pid": 1, "started_at": "before"},
            {"container_id": "new", "pid": 2, "started_at": "after"},
        ]
    )
    monkeypatch.setattr(restart_demo, "collector_identity", lambda *args: next(identities))
    monkeypatch.setattr(restart_demo, "grafana_incident", lambda *args: {"results": {}})


@pytest.mark.parametrize("source", ["api", "database"])
@pytest.mark.parametrize("defect", ["resolved", "identity"])
def test_restart_rejects_invalid_incident_precondition_before_stop(
    monkeypatch: pytest.MonkeyPatch, source: str, defect: str
) -> None:
    configure_restart_seams(monkeypatch)
    invalid_id = "00000000-0000-0000-0000-000000000002"
    invalid = canonical_incident(
        incident_id=invalid_id if defect == "identity" else INCIDENT_ID,
        status="resolved" if defect == "resolved" else "active",
    )
    api = API(incidents=[invalid]) if source == "api" else API()
    if source == "database":
        monkeypatch.setattr(
            restart_demo,
            "database_snapshot",
            lambda *args, **kwargs: {
                "incident": {"id": invalid["id"], "status": invalid["status"]},
                "checkpoint": {
                    "node_id": "node-a",
                    "revision": 3,
                    "latest": {"sequence": 3},
                },
            },
        )
    commands: list[str] = []

    def remote(ssh: list[str], value: str, deadline: float) -> str:
        commands.append(value)
        return ""

    monkeypatch.setattr(restart_demo, "bounded_command", remote)
    report: dict[str, Any] = {
        "incident_id": INCIDENT_ID,
        "target": "node-a",
        "errors": [],
    }
    with pytest.raises(ValueError, match="canonical incident"):
        restart_demo.restart_collector([], api, {}, report, 100, monotonic=lambda: 0)
    assert not any("stop collector" in command for command in commands)
    assert not any("--force-recreate" in command for command in commands)
    assert not any("--wait-timeout 45 collector" in command for command in commands)
    assert "collector_restart_failure" not in report


@pytest.mark.parametrize("source", ["api", "database"])
@pytest.mark.parametrize("defect", ["resolved", "identity"])
def test_restart_rejects_invalid_post_restart_incident_and_restores(
    monkeypatch: pytest.MonkeyPatch, source: str, defect: str
) -> None:
    configure_restart_seams(monkeypatch)
    invalid = canonical_incident(
        incident_id=(
            "00000000-0000-0000-0000-000000000002" if defect == "identity" else INCIDENT_ID
        ),
        status="resolved" if defect == "resolved" else "active",
    )
    api = API(incidents=[canonical_incident(), invalid]) if source == "api" else API()
    if source == "database":
        snapshots = iter(
            [
                {
                    "incident": {"id": INCIDENT_ID, "status": "active"},
                    "checkpoint": {
                        "node_id": "node-a",
                        "revision": 3,
                        "latest": {"sequence": 3},
                    },
                },
                {
                    "incident": {"id": invalid["id"], "status": invalid["status"]},
                    "checkpoint": {
                        "node_id": "node-a",
                        "revision": 4,
                        "latest": {"sequence": 4},
                    },
                },
            ]
        )
        monkeypatch.setattr(
            restart_demo, "database_snapshot", lambda *args, **kwargs: next(snapshots)
        )
    commands: list[str] = []

    def remote(ssh: list[str], value: str, deadline: float) -> str:
        commands.append(value)
        return ""

    monkeypatch.setattr(restart_demo, "bounded_command", remote)
    report: dict[str, Any] = {
        "incident_id": INCIDENT_ID,
        "target": "node-a",
        "errors": [],
    }
    with pytest.raises(ValueError, match="canonical incident"):
        restart_demo.restart_collector([], api, {}, report, 100, monotonic=lambda: 0)
    assert any("stop collector" in command for command in commands)
    assert any("--force-recreate" in command for command in commands)
    assert any("--wait-timeout 45 collector" in command for command in commands)
    assert report["collector_restart_failure"] == {
        "type": "ValueError",
        "restoration": "confirmed_active",
    }


def test_restart_accepts_same_active_incident_with_advancing_latest_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_restart_seams(monkeypatch)
    snapshots = iter(
        [
            {
                "incident": {
                    "id": INCIDENT_ID,
                    "status": "active",
                    "observed_at": "2026-10-13T12:00:00Z",
                },
                "checkpoint": {
                    "node_id": "node-a",
                    "revision": 3,
                    "latest": {"sequence": 3},
                },
            },
            {
                "incident": {
                    "id": INCIDENT_ID,
                    "status": "active",
                    "observed_at": "2026-10-13T12:00:05Z",
                },
                "checkpoint": {
                    "node_id": "node-a",
                    "revision": 4,
                    "latest": {"sequence": 4},
                },
            },
        ]
    )
    monkeypatch.setattr(restart_demo, "database_snapshot", lambda *args, **kwargs: next(snapshots))
    monkeypatch.setattr(restart_demo, "bounded_command", lambda *args, **kwargs: "")
    report: dict[str, Any] = {
        "incident_id": INCIDENT_ID,
        "target": "node-a",
        "errors": [],
    }

    result = restart_demo.restart_collector(
        [],
        API(incidents=[canonical_incident(sequence=3), canonical_incident(sequence=4)]),
        {},
        report,
        100,
        monotonic=lambda: 0,
    )
    assert result["api_before"]["latest_evidence"]["sequence"] == 3
    assert result["api_after"]["latest_evidence"]["sequence"] == 4
    assert result["database_before"]["checkpoint"]["revision"] == 3
    assert result["database_after"]["checkpoint"]["revision"] == 4
    assert result["collector_restoration"] == "confirmed_active"


def test_post_restart_incident_failure_remains_primary_when_restoration_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_restart_seams(monkeypatch)
    commands: list[str] = []

    def remote(ssh: list[str], value: str, deadline: float) -> str:
        commands.append(value)
        if "--wait-timeout 45 collector" in value:
            raise RuntimeError("restoration failure")
        return ""

    monkeypatch.setattr(restart_demo, "bounded_command", remote)
    report: dict[str, Any] = {
        "incident_id": INCIDENT_ID,
        "target": "node-a",
        "errors": [],
    }
    api = API(incidents=[canonical_incident(), canonical_incident(status="resolved")])

    with pytest.raises(ValueError, match="post-restart API canonical incident is not active"):
        restart_demo.restart_collector([], api, {}, report, 100, monotonic=lambda: 0)
    assert any("--wait-timeout 45 collector" in command for command in commands)
    assert report["collector_restart_failure"] == {
        "type": "ValueError",
        "restoration": "failed",
    }
    assert report["secondary_errors"] == ["collector restoration: RuntimeError"]


def test_restart_failure_still_restores_collector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_restart_seams(monkeypatch)
    commands: list[str] = []

    def remote(ssh: list[str], value: str, deadline: float) -> str:
        commands.append(value)
        if "--force-recreate" in value:
            raise RuntimeError("injected restart failure")
        return ""

    monkeypatch.setattr(restart_demo, "bounded_command", remote)
    report: dict[str, Any] = {
        "incident_id": "00000000-0000-0000-0000-000000000001",
        "target": "node-a",
        "errors": [],
    }
    with pytest.raises(RuntimeError, match="injected"):
        restart_demo.restart_collector([], API(), {}, report, 100, monotonic=lambda: 0)
    assert any("--wait-timeout 45 collector" in value for value in commands)
    assert report["collector_restart_failure"]["restoration"] == "confirmed_active"


def test_restart_preserves_primary_and_restoration_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_restart_seams(monkeypatch)

    def remote(ssh: list[str], value: str, deadline: float) -> str:
        if "--force-recreate" in value:
            raise RuntimeError("primary")
        if "--wait-timeout 45 collector" in value:
            raise RuntimeError("restore")
        return ""

    monkeypatch.setattr(restart_demo, "bounded_command", remote)
    report: dict[str, Any] = {
        "incident_id": "00000000-0000-0000-0000-000000000001",
        "target": "node-a",
        "errors": [],
    }
    with pytest.raises(RuntimeError, match="primary"):
        restart_demo.restart_collector([], API(), {}, report, 100, monotonic=lambda: 0)
    assert report["secondary_errors"] == ["collector restoration: RuntimeError"]
    assert report["collector_restart_failure"]["restoration"] == "failed"


def test_expired_action_deadline_uses_fresh_restoration_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_restart_seams(monkeypatch)
    now = [0.0]
    commands: list[tuple[str, float]] = []

    def remote(ssh: list[str], value: str, deadline: float) -> str:
        if deadline <= now[0]:
            raise TimeoutError("command deadline expired before execution")
        commands.append((value, deadline))
        if "--force-recreate" in value:
            now[0] = 11.0
            raise TimeoutError("primary action deadline expired")
        return ""

    monkeypatch.setattr(restart_demo, "bounded_command", remote)
    report: dict[str, Any] = {
        "incident_id": "00000000-0000-0000-0000-000000000001",
        "target": "node-a",
        "errors": [],
    }
    with pytest.raises(TimeoutError, match="primary action deadline expired"):
        restart_demo.restart_collector([], API(), {}, report, 10, monotonic=lambda: now[0])

    assert any("stop collector" in command for command, _ in commands)
    assert any("--force-recreate" in command for command, _ in commands)
    restoration = [
        (command, deadline)
        for command, deadline in commands
        if "--wait-timeout 45 collector" in command
    ]
    assert restoration == [
        (
            "cd /opt/fleetdoctor/current && sudo docker compose up -d --no-deps "
            "--wait --wait-timeout 45 collector",
            101.0,
        )
    ]
    assert report["collector_restart_failure"]["restoration"] == "confirmed_active"


def test_expired_action_deadline_preserves_primary_when_restoration_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_restart_seams(monkeypatch)
    now = [0.0]
    commands: list[tuple[str, float]] = []

    def remote(ssh: list[str], value: str, deadline: float) -> str:
        if deadline <= now[0]:
            raise TimeoutError("command deadline expired before execution")
        commands.append((value, deadline))
        if "--force-recreate" in value:
            now[0] = 11.0
            raise RuntimeError("primary restart failure")
        if "--wait-timeout 45 collector" in value:
            raise RuntimeError("restoration failure")
        return ""

    monkeypatch.setattr(restart_demo, "bounded_command", remote)
    report: dict[str, Any] = {
        "incident_id": "00000000-0000-0000-0000-000000000001",
        "target": "node-a",
        "errors": [],
    }
    with pytest.raises(RuntimeError, match="primary restart failure"):
        restart_demo.restart_collector([], API(), {}, report, 10, monotonic=lambda: now[0])

    restoration_deadlines = [
        deadline for command, deadline in commands if "--wait-timeout 45 collector" in command
    ]
    assert restoration_deadlines == [101.0]
    assert report["secondary_errors"] == ["collector restoration: RuntimeError"]
    assert report["collector_restart_failure"]["restoration"] == "failed"


def test_restart_readiness_is_bounded_and_late_success_cannot_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_restart_seams(monkeypatch)
    monkeypatch.setattr(restart_demo, "bounded_command", lambda *args, **kwargs: "")
    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    report: dict[str, Any] = {
        "incident_id": "00000000-0000-0000-0000-000000000001",
        "target": "node-a",
        "errors": [],
    }
    with pytest.raises(TimeoutError, match="readiness"):
        restart_demo.restart_collector(
            [], API(healthy=False), {}, report, 100, monotonic=lambda: now[0], sleep=sleep
        )
    assert report["collector_restart_failure"]["restoration"] == "confirmed_active"


def test_restart_accepts_nonzero_handoff_inside_allocated_absolute_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_restart_seams(monkeypatch)
    monkeypatch.setattr(restart_demo, "bounded_command", lambda *args, **kwargs: "")
    report: dict[str, Any] = {
        "incident_id": "00000000-0000-0000-0000-000000000001",
        "target": "node-a",
        "errors": [],
    }
    result = restart_demo.restart_collector([], API(), {}, report, 70, monotonic=lambda: 0.25)
    assert result["collector_after"]["container_id"] == "new"
    assert result["collector_restoration"] == "confirmed_active"


def test_restart_rejects_health_response_finishing_after_readiness_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_restart_seams(monkeypatch)
    monkeypatch.setattr(restart_demo, "bounded_command", lambda *args, **kwargs: "")
    now = [0.0]

    class SlowSuccessfulHealth(API):
        def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
            if path == "/health":
                now[0] = 46.0
                return {"status": "ok"}
            return super().get(path, params)

    report: dict[str, Any] = {
        "incident_id": "00000000-0000-0000-0000-000000000001",
        "target": "node-a",
        "errors": [],
    }
    with pytest.raises(TimeoutError, match="readiness"):
        restart_demo.restart_collector(
            [], SlowSuccessfulHealth(), {}, report, 100, monotonic=lambda: now[0]
        )
    assert report["collector_restart_failure"]["restoration"] == "confirmed_active"
