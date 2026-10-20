import json
from pathlib import Path
from typing import Any

import fd_harness
import pytest

CONFIG = {
    "trigger_percent": 90.0,
    "recovery_percent": 80.0,
    "consecutive_samples": 3,
    "max_gap_seconds": 10.0,
    "severity": "warning",
}
IDENTITY = {
    "boot_id": "11111111-1111-4111-8111-111111111111",
    "pid": 42,
    "starttime_ticks": 99,
}
RESOURCE = "boot:11111111-1111-4111-8111-111111111111/pid:42/start:99"


class Clock:
    def __init__(self) -> None:
        self.value = 10.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class Injector:
    def __init__(self) -> None:
        self.pressured = False
        self.released = False
        self.cleaned = False
        self.cleanup_calls = 0

    def measurement(self, ratio: float) -> dict[str, Any]:
        return IDENTITY | {
            "uid": 1000,
            "descriptor_count": int(128 * ratio),
            "soft_limit": 128,
            "pressure_ratio": ratio,
        }

    def start(self, token: str, limit: int, seconds: int) -> dict[str, Any]:
        return {
            "token": token,
            "boot_id": IDENTITY["boot_id"],
            "worker_pid": IDENTITY["pid"],
            "worker_starttime_ticks": IDENTITY["starttime_ticks"],
            "worker_uid": 1000,
            "measurement": self.measurement(0.25),
        }

    def status(self, token: str) -> dict[str, Any]:
        if self.cleaned:
            return {"token": token, "owned": False, "state": "absent"}
        ratio = 0.5 if self.released else (0.95 if self.pressured else 0.25)
        return {"token": token, "owned": True, "measurement": self.measurement(ratio)}

    def pressure(self, token: str) -> dict[str, Any]:
        self.pressured = True
        return {"token": token, "pressuring": True, "measurement": self.measurement(0.25)}

    def release(self, token: str) -> dict[str, Any]:
        self.released = True
        return {"token": token, "released": True, "measurement": self.measurement(0.5)}

    def cleanup(self, token: str) -> dict[str, Any]:
        self.cleanup_calls += 1
        self.cleaned = True
        return {"token": token, "owned": False, "cleaned": True}


class Backend:
    def __init__(self, injector: Injector, clock: Clock) -> None:
        self.injector = injector
        self.clock = clock
        self.detail_delay = 0.0
        self.contradict_detail = False
        self.include_baseline = True

    def summary(self, status: str) -> dict[str, Any]:
        return {
            "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "node_id": "node-a",
            "rule": "fd_pressure",
            "resource": RESOURCE,
            "status": status,
            "configuration": CONFIG,
        }

    def evidence(self, high: bool) -> dict[str, Any]:
        ratio = 0.95 if high else 0.5
        return {
            "identity": IDENTITY,
            "fd_available": True,
            "status": "present",
            "observation": {
                "identity": IDENTITY,
                "status": "present",
                "descriptor_count": int(128 * ratio),
                "soft_limit": 128,
                "pressure_ratio": ratio,
                "count_delta": 4 if high else -4,
                "growth_per_second": 0.8 if high else -0.8,
                "growth_interval_seconds": 5.0,
            },
        }

    def exit_evidence(self) -> dict[str, Any]:
        return {
            "identity": IDENTITY,
            "fd_available": False,
            "status": "exited",
            "observation": {
                "identity": IDENTITY,
                "status": "exited",
                "watched": True,
            },
        }

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/configuration":
            return {"fd_rule": CONFIG}
        if path == "/nodes/node-b/metrics":
            return {
                "fresh": True,
                "stale": False,
                "fd_coverage": {"observed": 1, "total": 1},
            }
        if path == "/nodes/node-a/metrics":
            observations = []
            if self.include_baseline:
                observations = [
                    {
                        "identity": IDENTITY,
                        "configured": True,
                        "status": "present",
                        "soft_limit": 128,
                        "pressure_ratio": 0.25,
                        "count_delta": 0,
                        "growth_per_second": 0.0,
                        "growth_interval_seconds": 5.0,
                    }
                ]
            return {"fresh": True, "fd": {"observations": observations}}
        if path == "/diagnoses":
            assert params is not None
            if params["node"] == "node-b":
                return {"diagnoses": []}
            status = params["status"]
            present = (
                status == "active"
                and self.injector.pressured
                and not self.injector.released
                and not self.injector.cleaned
            ) or (status == "resolved" and (self.injector.released or self.injector.cleaned))
            return {"diagnoses": [self.summary(status)] if present else []}
        if path.startswith("/diagnoses/"):
            self.clock.value += self.detail_delay
            resolved = self.injector.released or self.injector.cleaned
            status = "resolved" if resolved else "active"
            resolution_reason: str | None
            if self.injector.cleaned and not self.injector.released:
                resolution_reason = "confirmed_exit"
                latest_evidence = self.exit_evidence()
            else:
                resolution_reason = "descriptor_release" if resolved else None
                latest_evidence = self.evidence(not resolved)
            value = self.summary(status) | {
                "evidence_fresh": True,
                "resolution_reason": resolution_reason,
                "opening_evidence": self.evidence(True),
                "latest_evidence": latest_evidence,
                "evaluated_at": "2026-10-19T00:00:00+00:00",
            }
            if self.contradict_detail:
                value["node_id"] = "other-node"
            return value
        raise AssertionError(path)


def harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[fd_harness.FdHarness, Backend, Injector, Clock]:
    monkeypatch.setattr(fd_harness, "source_manifest", lambda: {"revision": "fixed"})
    clock = Clock()
    injector = Injector()
    backend = Backend(injector, clock)
    value = fd_harness.FdHarness(
        backend,
        injector,
        "node-a",
        "node-b",
        tmp_path / "fd-report.json",
        monotonic=clock,
        sleep=clock.sleep,
    )
    return value, backend, injector, clock


def test_harness_measures_trigger_and_matches_exact_incident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, _, injector, _ = harness(tmp_path, monkeypatch)
    report = value.run("release")
    assert report["status"] == "passed"
    assert report["resource"] == RESOURCE
    assert report["timing"]["threshold_to_api_seconds"] <= 60
    assert report["incident_summary"]["id"] == report["recovery"]["id"]
    assert injector.cleanup_calls == 1


def test_harness_accepts_exact_exit_without_invented_growth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, _, injector, _ = harness(tmp_path, monkeypatch)
    report = value.run("exit")
    assert report["status"] == "passed"
    latest = report["recovery"]["latest_evidence"]
    assert latest["status"] == "exited"
    assert latest["fd_available"] is False
    assert latest["observation"]["status"] == "exited"
    assert latest["observation"].get("count_delta") is None
    assert latest["observation"].get("growth_per_second") is None
    assert latest["observation"].get("growth_interval_seconds") is None
    assert injector.cleanup_calls == 2


def test_harness_rejects_late_detail_and_retains_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, backend, injector, _ = harness(tmp_path, monkeypatch)
    backend.detail_delay = 61
    with pytest.raises(RuntimeError, match="retained report"):
        value.run("release")
    retained = json.loads((tmp_path / "fd-report.json").read_text())
    assert retained["status"] == "failed"
    assert any("after diagnosis deadline" in error for error in retained["errors"])
    assert injector.cleanup_calls == 1


def test_harness_rejects_contradictory_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, backend, injector, _ = harness(tmp_path, monkeypatch)
    backend.contradict_detail = True
    with pytest.raises(RuntimeError, match="retained report"):
        value.run("release")
    retained = json.loads((tmp_path / "fd-report.json").read_text())
    assert any("contradicts exact helper" in error for error in retained["errors"])
    assert injector.cleanup_calls == 1


def test_harness_preparation_failure_is_bounded_and_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, backend, injector, clock = harness(tmp_path, monkeypatch)
    backend.include_baseline = False
    with pytest.raises(RuntimeError, match="retained report"):
        value.run("release")
    assert clock.value <= 42
    retained = json.loads((tmp_path / "fd-report.json").read_text())
    assert any("baseline" in error for error in retained["errors"])
    assert injector.cleanup_calls == 1
