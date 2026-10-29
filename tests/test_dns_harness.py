from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from dns_harness import DnsHarness, aggregate

NOW = datetime(2026, 10, 27, tzinfo=UTC)
CONFIG = {
    "direct_ip_rtt_max_ms": 150.0,
    "consecutive_samples": 3,
    "max_gap_seconds": 10.0,
    "severity": "warning",
}
SCOPE = ("baseline.fleetdoctor.test.", "10.0.0.10")


def identity(sequence: int, *, boot: str = "boot-a") -> dict[str, Any]:
    return {
        "boot_id": boot,
        "agent_session_id": "session-a",
        "sequence": sequence,
        "observed_at": (NOW + timedelta(seconds=sequence * 5)).isoformat(),
    }


def dns(status: str = "failure") -> dict[str, Any]:
    return {
        "hostname": SCOPE[0],
        "direct_ip_target": SCOPE[1],
        "query": {"status": status},
    }


def network() -> dict[str, Any]:
    return {
        "probe": {
            "status": "available",
            "target": SCOPE[1],
            "sent": 3,
            "received": 3,
            "lost": 0,
            "median_rtt_ms": 20.0,
        }
    }


def run(index: int = 0) -> dict[str, Any]:
    scenario = {
        "status": "passed",
        "node": "node-a",
        "reference_node": "node-b",
        "configuration": CONFIG,
        "trigger": {"dns": dns()},
        "injection": {"original": {"entry_type": "regular"}},
        "diagnosis_seconds": float(index + 1),
    }
    return {
        "status": "passed",
        "scenario": scenario,
        "source_manifest": {"source_sha256": "a" * 64},
        "environment_metadata": {"image": "fixture@sha256:" + "b" * 64},
        "topology": "two-node-owned-linux",
    }


def test_aggregate_retains_five_attempts_and_enforces_comparability_and_strict_median() -> None:
    value = aggregate([run(index) for index in range(5)])
    assert value["status"] == "passed"
    assert value["complete_runs"] == 5
    assert value["diagnosis_median_seconds"] == 3.0
    incomplete = aggregate([run(index) for index in range(4)])
    assert incomplete["status"] == "failed" and len(incomplete["attempts"]) == 4
    changed = [run(index) for index in range(5)]
    changed[-1]["scenario"]["trigger"]["dns"]["hostname"] = "different.fleetdoctor.test."
    assert "not source/config" in aggregate(changed)["failure"]
    slow = [run(index) for index in range(5)]
    for item, timing in zip(slow, [1.0, 2.0, 30.0, 31.0, 32.0], strict=True):
        item["scenario"]["diagnosis_seconds"] = timing
    result = aggregate(slow)
    assert result["status"] == "failed"
    assert result["diagnosis_median_seconds"] == 30.0
    assert result["slow_or_failed_attempts"] == [2, 3, 4]


def test_first_qualifying_trigger_is_immutable_and_response_completed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = DnsHarness("http://127.0.0.1:8000", "node-a", "node-b", monotonic=lambda: 1)
    monkeypatch.setattr(
        harness,
        "_admin_and_reference",
        lambda _config: {
            "response_completed_monotonic": 1.0,
            "admin_response_completed_monotonic": 1.0,
        },
    )
    views = iter(
        [
            (
                {
                    "fresh": True,
                    "sample": identity(1),
                    "dns": dns(),
                    "network": network(),
                },
                2.0,
                "2026-10-27T00:00:02+00:00",
            ),
            (
                {
                    "fresh": True,
                    "sample": identity(2),
                    "dns": dns(),
                    "network": network(),
                },
                7.0,
                "2026-10-27T00:00:07+00:00",
            ),
        ]
    )
    monkeypatch.setattr(harness, "_get", lambda *_args, **_kwargs: next(views))
    trace: dict[str, Any] = {"limit": 32, "observations": [], "truncated_observations": 0}
    trigger = harness._qualifying_trigger(identity(0), SCOPE, CONFIG, 60.0, trace)
    assert trigger["identity"]["sequence"] == 1
    assert trigger["response_completed_monotonic"] == 2.0
    assert len(trace["observations"]) == 1


def test_trigger_and_healthy_response_cuts_reject_completion_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = DnsHarness("http://127.0.0.1:8000", "node-a", "node-b", monotonic=lambda: 1)
    monkeypatch.setattr(
        harness,
        "_admin_and_reference",
        lambda _config: {
            "response_completed_monotonic": 101.0,
            "admin_response_completed_monotonic": 101.0,
        },
    )
    monkeypatch.setattr(
        harness,
        "_get",
        lambda *_args, **_kwargs: (
            {"fresh": True, "sample": identity(1), "dns": dns(), "network": network()},
            101.0,
            "late",
        ),
    )
    trace = {"limit": 32, "observations": [], "truncated_observations": 0}
    with pytest.raises(TimeoutError, match="completed after deadline"):
        harness._qualifying_trigger(identity(0), SCOPE, CONFIG, 100.0, trace)


def test_three_healthy_requires_same_scope_identity_and_strict_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = DnsHarness("http://127.0.0.1:8000", "node-a", "node-b", monotonic=lambda: 1)
    values = iter([identity(1), identity(2), identity(3)])

    def healthy(_node: str, _threshold: float) -> dict[str, Any]:
        current = next(values)
        return {
            "identity": current,
            "dns": dns("success"),
            "network": network(),
            "response_completed_monotonic": float(current["sequence"]),
            "response_completed_utc": "fixture",
        }

    monkeypatch.setattr(harness, "_healthy", healthy)
    monkeypatch.setattr(
        harness,
        "_admin_and_reference",
        lambda _config: {
            "response_completed_monotonic": 0.0,
            "admin_response_completed_monotonic": 0.0,
        },
    )
    accepted = harness._three_healthy(identity(0), SCOPE, CONFIG, 100.0)
    assert [item["identity"]["sequence"] for item in accepted] == [1, 2, 3]


def test_incident_binding_requires_frozen_config_scope_and_nonpredating_opening() -> None:
    harness = DnsHarness("http://127.0.0.1:8000", "node-a", "node-b")
    trigger = {"identity": identity(1), "dns": dns(), "network": network()}
    opening = {
        "node_id": "node-a",
        **identity(3),
        **dns(),
        "direct_ip_probe": network()["probe"],
    }
    detail = {
        "node_id": "node-a",
        "rule": "dns_resolution_failure",
        "resource": f"dns:{SCOPE[0]}|ipv4:{SCOPE[1]}",
        "severity": "warning",
        "configuration": CONFIG,
        "opening_evidence": opening,
    }
    harness._assert_incident(detail, CONFIG, SCOPE, trigger)
    detail["opening_evidence"] = {**opening, **identity(0)}
    with pytest.raises(ValueError, match="predates"):
        harness._assert_incident(detail, CONFIG, SCOPE, trigger)


def test_harness_rejects_named_api_and_allows_explicit_local_surrogate() -> None:
    with pytest.raises(ValueError):
        DnsHarness("http://collector.example:8000", "node-a", "node-b")
    DnsHarness("http://127.0.0.1:8000", "node-a", "node-b")
