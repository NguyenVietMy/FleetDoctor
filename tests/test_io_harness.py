from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from io_harness import RULE_CONFIGURATION, IoHarness


class Clock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds

    def advance(self, seconds: float) -> None:
        self.value += seconds


def device(resource: str, *, healthy: bool = True, eligible: bool = False) -> dict[str, Any]:
    return {
        "resource": resource,
        "rate_status": "available",
        "confirmed_idle": healthy and not eligible,
        "completion_latency_ms": 45.0 if eligible else (4.0 if healthy else None),
        "average_outstanding": 2.0 if eligible else (0.1 if healthy else None),
    }


def view(
    sequence: int,
    resource: str,
    *,
    healthy: bool = True,
    eligible: bool = False,
) -> dict[str, Any]:
    observed = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=sequence * 5)
    return {
        "fresh": True,
        "active_incident_count": 0,
        "sample": {
            "boot_id": "11111111-1111-4111-8111-111111111111",
            "agent_session_id": "22222222-2222-4222-8222-222222222222",
            "sequence": sequence,
            "observed_at": observed.isoformat(),
        },
        "io": {"devices": [device(resource, healthy=healthy, eligible=eligible)]},
    }


class ScriptedAPI:
    def __init__(self, clock: Clock, *, delayed_detail: bool = False) -> None:
        self.clock = clock
        self.delayed_detail = delayed_detail
        self.target_resource = "io:" + "a" * 32
        self.reference_resource = "io:" + "b" * 32
        self.target = [
            view(1, self.target_resource),
            view(2, self.target_resource),
            view(3, self.target_resource),
            view(4, self.target_resource, eligible=True),
            view(5, self.target_resource, eligible=True),
            view(6, self.target_resource, eligible=True),
            view(7, self.target_resource),
            view(7, self.target_resource),
            view(8, self.target_resource, healthy=False),
            view(9, self.target_resource),
            view(9, self.target_resource),
            view(10, "io:" + "c" * 32),
            view(11, self.target_resource),
            view(11, self.target_resource),
            view(12, self.target_resource),
            view(13, self.target_resource),
        ]
        self.reference = [view(index, self.reference_resource) for index in range(1, 30)]
        self.target_calls = 0
        self.reference_calls = 0
        self.diagnosis_queries = 0

    def incident(self, status: str = "active") -> dict[str, Any]:
        return {
            "id": "incident-1",
            "node_id": "node-a",
            "rule": "io_bottleneck",
            "resource": self.target_resource,
            "status": status,
            "configuration": dict(RULE_CONFIGURATION),
            "opening_evidence": {"resource": self.target_resource},
        }

    @staticmethod
    def next_value(values: list[dict[str, Any]], index: int) -> dict[str, Any]:
        return values[min(index, len(values) - 1)]

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/nodes/node-a/metrics":
            result = self.next_value(self.target, self.target_calls)
            self.target_calls += 1
            return result
        if path == "/nodes/node-b/metrics":
            result = self.next_value(self.reference, self.reference_calls)
            self.reference_calls += 1
            return result
        if path == "/diagnoses":
            self.diagnosis_queries += 1
            active = self.diagnosis_queries >= 4
            return {"diagnoses": [self.incident()] if active else []}
        if path == "/diagnoses/incident-1":
            if self.delayed_detail:
                self.clock.advance(61)
            status = "resolved" if self.target_calls >= len(self.target) else "active"
            return self.incident(status)
        raise AssertionError((path, params))


class Injector:
    def __init__(self, *, cleanup_failure: bool = False) -> None:
        self.cleanup_failure = cleanup_failure
        self.cleaned = 0

    def start(self, token: str, duration: int) -> dict[str, Any]:
        return {"token": token, "duration": duration, "phase": "running"}

    def status(self, token: str) -> dict[str, Any]:
        return {"token": token}

    def cleanup(self, token: str) -> dict[str, Any]:
        self.cleaned += 1
        if self.cleanup_failure:
            raise RuntimeError("cleanup failed")
        return {"token": token, "phase": "stopped"}


def harness(
    tmp_path: Path,
    api: ScriptedAPI,
    injector: Injector,
    clock: Clock,
) -> IoHarness:
    return IoHarness(
        api,
        injector,
        "d" * 32,
        tmp_path / "io.json",
        monotonic=clock,
        sleep=clock.sleep,
        utcnow=lambda: datetime(2026, 1, 1, tzinfo=UTC),
        frozen_source={"fixture": "io-harness-tests"},
    )


def test_harness_uses_three_baselines_and_consecutive_recovery_with_replays(
    tmp_path: Path,
) -> None:
    clock = Clock()
    api = ScriptedAPI(clock)
    injector = Injector()
    result = harness(tmp_path, api, injector, clock).run()
    assert result["status"] == "passed"
    assert len(result["healthy_baselines"]["node-a"]) == 3
    assert len(result["recovery_identities"]) == 3
    assert any(row["replay"] for row in result["recovery_polls"])
    assert any(row["accepted"] == 0 for row in result["recovery_polls"])
    assert injector.cleaned == 1


def test_harness_checks_detail_response_completion_after_delay_and_cleans(
    tmp_path: Path,
) -> None:
    clock = Clock()
    api = ScriptedAPI(clock, delayed_detail=True)
    injector = Injector()
    runner = harness(tmp_path, api, injector, clock)
    with pytest.raises(TimeoutError, match="detail completed after"):
        runner.run()
    receipt = json.loads((tmp_path / "io.json").read_text())
    assert receipt["status"] == "failed"
    assert injector.cleaned == 1


def test_harness_cleanup_failure_forces_failed_status(tmp_path: Path) -> None:
    clock = Clock()
    api = ScriptedAPI(clock)
    injector = Injector(cleanup_failure=True)
    runner = harness(tmp_path, api, injector, clock)
    with pytest.raises(RuntimeError, match="cleanup failed"):
        runner.run()
    receipt = json.loads((tmp_path / "io.json").read_text())
    assert receipt["status"] == "failed"
    assert "cleanup failed" in receipt["cleanup_error"]
