import subprocess
from pathlib import Path
from typing import Any

import pytest
from chaos_network import aggregate
from chaos_network import main as chaos_network_main
from network_harness import NetworkHarness
from network_helper_integration import (
    INTERRUPTION_WATCHDOG_DURATION_SECONDS,
    collector_base_url,
    configure_owned_ping_group_range,
    network_prepare_argv,
    validate_interruption_barrier,
    validate_interruption_timing,
)

CONFIG = {
    "loss_trigger_packets": 1,
    "rtt_trigger_ms": 200.0,
    "recovery_rtt_ms": 150.0,
    "consecutive_samples": 3,
    "max_gap_seconds": 10.0,
    "severity": "warning",
}
IDENTITY = {
    "boot_id": "00000000-0000-0000-0000-000000000001",
    "agent_session_id": "00000000-0000-0000-0000-000000000002",
    "sequence": 10,
    "observed_at": "2026-10-19T12:00:00+00:00",
}


def test_native_agent_uses_collector_base_url_not_ingest_endpoint() -> None:
    assert collector_base_url("192.0.2.10") == "http://192.0.2.10:8000"


def test_network_preparer_invokes_mode_0644_repository_script_through_shell() -> None:
    assert network_prepare_argv("owned-anchor", Path("owned-sysctl"), "owned-image") == [
        "docker",
        "run",
        "--rm",
        "--network",
        "container:owned-anchor",
        "--privileged",
        "--user",
        "0:0",
        "-v",
        "owned-sysctl:/etc/sysctl.d",
        "owned-image",
        "/bin/sh",
        "/app/deploy/network_prepare.sh",
        "fleetdoctor",
    ]


def test_interrupted_setup_barrier_requires_real_durable_partial_mutation() -> None:
    token = "a" * 32
    record = {
        "token": token,
        "interface": "eth0",
        "setup_state": "starting",
        "completed_steps": 1,
        "parent_pid": 42,
        "parent_start": "8001",
        "watchdog_pid": 43,
        "watchdog_start": "9001",
        "commands": [
            {
                "argv": [
                    "/usr/sbin/tc",
                    "qdisc",
                    "add",
                    "dev",
                    "eth0",
                    "root",
                    "handle",
                    "1:",
                    "prio",
                ],
                "returncode": 0,
            }
        ],
    }
    barrier = {
        "attribution": "test_driver_after_first_durable_tc_command",
        "token": token,
        "driver_pid": 42,
        "driver_start": "8001",
        "watchdog_pid": 43,
        "watchdog_start": "9001",
        "setup_state": "starting",
        "completed_steps": 1,
    }
    kernel = [{"kind": "prio", "handle": "1:", "root": True}]

    assert validate_interruption_barrier(token, barrier, record, kernel) == (42, "8001")
    with pytest.raises(ValueError, match="durable barrier"):
        validate_interruption_barrier(token, {**barrier, "completed_steps": 0}, record, kernel)
    with pytest.raises(ValueError, match="durable barrier"):
        validate_interruption_barrier(token, barrier, {**record, "parent_pid": 44}, kernel)
    with pytest.raises(ValueError, match="durable barrier"):
        validate_interruption_barrier(token, barrier, {**record, "parent_start": "8002"}, kernel)
    with pytest.raises(ValueError, match="partial tc mutation"):
        validate_interruption_barrier(
            token, barrier, record, [{"kind": "noqueue", "handle": "0:", "root": True}]
        )


def test_interrupted_setup_watchdog_outlasts_all_bounded_pre_kill_work() -> None:
    assert validate_interruption_timing(INTERRUPTION_WATCHDOG_DURATION_SECONDS, 8) == 15
    with pytest.raises(ValueError, match="pre-kill margin"):
        validate_interruption_timing(19, 8)
    with pytest.raises(ValueError, match="timing values"):
        validate_interruption_timing(INTERRUPTION_WATCHDOG_DURATION_SECONDS, float("nan"))


def test_owned_ping_permission_preparer_is_namespace_scoped_and_readback_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    outputs = iter(
        [
            "10001\t10001\n",
            "net.ipv4.ping_group_range = 20000 20000\n",
            "20000 20000\n",
        ]
    )

    def fake_run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, next(outputs), "")

    monkeypatch.setattr("network_helper_integration.run", fake_run)
    result = configure_owned_ping_group_range("owned-anchor", "owned-image", "20000 20000")

    prefix = [
        "docker",
        "run",
        "--rm",
        "--network",
        "container:owned-anchor",
        "--privileged",
        "--user",
        "0:0",
        "owned-image",
    ]
    assert result["before"] == "10001 10001"
    assert result["after"] == "20000 20000"
    assert all(command[:9] == prefix for command in calls)
    assert calls[1][-2:] == ["-w", "net.ipv4.ping_group_range=20000 20000"]


def test_owned_ping_permission_preparer_rejects_failed_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(["10001 10001\n", "written\n", "10001 10001\n"])

    def fake_run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, next(outputs), "")

    monkeypatch.setattr("network_helper_integration.run", fake_run)
    with pytest.raises(RuntimeError, match="does not match"):
        configure_owned_ping_group_range("owned-anchor", "owned-image", "20000 20000")


def healthy(route_status: str, route_error: str | None, interface: str | None) -> dict[str, Any]:
    return {
        "identity": IDENTITY,
        "probe": {
            "status": "available",
            "target": "192.0.2.10",
            "lost": 0,
            "median_rtt_ms": 20,
            "route_status": route_status,
            "route_error": route_error,
            "interface": interface,
        },
        "tcp": {"retrans_segs": 1, "rate_status": "available"},
        "interfaces": [{"rate_status": {"rx_errors": "available"}}],
    }


@pytest.mark.parametrize(
    ("route_status", "route_error", "interface", "expected"),
    [
        ("available", None, "eth0", "available_attribution"),
        ("unavailable", "route_netlink_denied", None, "netlink_denied_unknown_interface"),
    ],
)
def test_harness_accepts_only_the_two_approved_attribution_branches(
    monkeypatch: pytest.MonkeyPatch,
    route_status: str,
    route_error: str | None,
    interface: str | None,
    expected: str,
) -> None:
    harness = NetworkHarness("http://api", "node-a", "node-b", "192.0.2.10", "http://x")
    value = healthy(route_status, route_error, interface)
    monkeypatch.setattr(harness, "_healthy", lambda node, config: value)
    monkeypatch.setattr(harness, "_admin_and_reference", lambda config: value)
    assert harness._preflight(CONFIG)["branch"] == expected


def test_phase_attempts_cleanup_even_when_start_acknowledgement_is_lost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def helper(action: str, token: str, profile: str, duration: int) -> dict[str, Any]:
        calls.append(action)
        if action == "start":
            raise TimeoutError("lost acknowledgement")
        baseline: dict[str, Any] = {"qdiscs": [], "classes": [], "filters": []}
        return {
            "cleanup_complete": True,
            "cleanup_phase": "complete",
            "route_before": {"interface": "eth0"},
            "route_after": {"interface": "eth0"},
            "prestate": baseline,
            "restored_state": baseline,
        }

    harness = NetworkHarness(
        "http://api", "node-a", "node-b", "192.0.2.10", "http://x", helper=helper
    )
    preflight = {
        "branch": "available_attribution",
        "target": healthy("available", None, "eth0"),
        "reference": {},
        "configuration": CONFIG,
    }
    monkeypatch.setattr(harness, "_preflight", lambda config: preflight)
    monkeypatch.setattr(harness, "_healthy_confirmations", lambda after, deadline, config: [])
    monkeypatch.setattr(harness, "_incident_ids", lambda: set())
    monkeypatch.setattr(harness, "_admin_and_reference", lambda config: {})
    with pytest.raises(RuntimeError, match="lost acknowledgement"):
        harness.run_phase("loss", CONFIG)
    assert calls == ["start", "cleanup"]


def test_repeated_polls_do_not_clear_healthy_or_trigger_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("network_harness.time.sleep", lambda _seconds: None)
    harness = NetworkHarness("http://api", "node-a", "node-b", "192.0.2.10", "http://x")

    def identity(sequence: int) -> dict[str, Any]:
        return {
            **IDENTITY,
            "sequence": sequence,
            "observed_at": f"2026-10-19T12:00:{sequence * 5:02d}+00:00",
        }

    healthy_values = iter([identity(1), identity(1), identity(2), identity(2), identity(3)])
    monkeypatch.setattr(
        harness,
        "_healthy",
        lambda node, config: {
            "identity": next(healthy_values),
            "response_completed_monotonic": 1.0,
        },
    )
    reference = {
        "response_completed_monotonic": 1.0,
        "admin_response_completed_monotonic": 1.0,
    }
    monkeypatch.setattr(harness, "_admin_and_reference", lambda config: reference)
    confirmations = harness._healthy_confirmations(
        {**IDENTITY, "sequence": 0, "observed_at": "2026-10-19T12:00:00+00:00"},
        harness.monotonic() + 10,
        CONFIG,
    )
    assert [item["identity"]["sequence"] for item in confirmations] == [1, 2, 3]

    trigger_values = iter([identity(1), identity(1), identity(2), identity(2), identity(3)])

    def node(_node: str) -> tuple[dict[str, Any], float, str]:
        current = next(trigger_values)
        return (
            {
                "fresh": True,
                "sample": current,
                "network": {
                    "probe": {
                        "status": "available",
                        "target": "192.0.2.10",
                        "lost": 1,
                        "median_rtt_ms": 20,
                    }
                },
            },
            1.0,
            "2026-10-19T12:00:00+00:00",
        )

    monkeypatch.setattr(harness, "_node", node)
    trigger = harness._qualifying_trigger(
        "loss",
        {**IDENTITY, "sequence": 0, "observed_at": "2026-10-19T12:00:00+00:00"},
        CONFIG,
        harness.monotonic() + 10,
    )
    assert [item["identity"]["sequence"] for item in trigger["qualifying_observations"]] == [1]


def test_trigger_trace_retains_each_new_identity_and_predicate_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("network_harness.time.sleep", lambda _seconds: None)
    harness = NetworkHarness("http://api", "node-a", "node-b", "192.0.2.10", "http://x")
    values = iter(
        [
            (11, 20.0),
            (11, 20.0),
            (12, 250.0),
        ]
    )

    def node(_node: str) -> tuple[dict[str, Any], float, str]:
        sequence, rtt = next(values)
        observed = f"2026-10-19T12:00:{(sequence - 10) * 5:02d}+00:00"
        return (
            {
                "fresh": True,
                "sample": {**IDENTITY, "sequence": sequence, "observed_at": observed},
                "network": {
                    "probe": {
                        "status": "available",
                        "target": "192.0.2.10",
                        "sent": 3,
                        "received": 3,
                        "lost": 0,
                        "loss_ratio": 0,
                        "median_rtt_ms": rtt,
                        "route_status": "unavailable",
                        "route_error": "route_netlink_denied",
                        "errors": [],
                    }
                },
            },
            float(sequence),
            observed,
        )

    monkeypatch.setattr(harness, "_node", node)
    monkeypatch.setattr(
        harness,
        "_admin_and_reference",
        lambda config: {
            "response_completed_monotonic": 1.0,
            "admin_response_completed_monotonic": 1.0,
        },
    )
    trace: dict[str, Any] = {"observations": [], "truncated_observations": 0}
    trigger = harness._qualifying_trigger(
        "latency", IDENTITY, CONFIG, harness.monotonic() + 10, trace
    )
    assert [item["identity"]["sequence"] for item in trace["observations"]] == [11, 12]
    assert [item["predicate_reason"] for item in trace["observations"]] == [
        "latency_below_threshold",
        "qualifies",
    ]
    assert trace["last_observation"] == trace["observations"][-1]
    assert trigger["identity"]["sequence"] == 12


def test_recovery_confirmations_and_resolution_share_one_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Clock:
        value = 0.0

        def __call__(self) -> float:
            return self.value

    clock = Clock()
    harness = NetworkHarness(
        "http://api",
        "node-a",
        "node-b",
        "192.0.2.10",
        "http://x",
        monotonic=clock,
    )
    preflight = {
        "branch": "netlink_denied_unknown_interface",
        "target": {"identity": IDENTITY, "probe": {}},
        "reference": {},
        "configuration": CONFIG,
    }
    monkeypatch.setattr(harness, "_preflight", lambda config: preflight)
    monkeypatch.setattr(harness, "_incident_ids", lambda: set())
    deadlines: list[float] = []

    def confirmations(after: dict[str, Any], deadline: float, config: dict[str, Any]) -> list[Any]:
        deadlines.append(deadline)
        if len(deadlines) == 2:
            clock.value = 100
        return []

    monkeypatch.setattr(harness, "_healthy_confirmations", confirmations)
    monkeypatch.setattr(
        harness,
        "_qualifying_trigger",
        lambda profile, after, config, deadline, trace=None: {
            "identity": IDENTITY,
            "response_completed_monotonic": 10.0,
        },
    )
    monkeypatch.setattr(harness, "_assert_incident", lambda *args: None)

    def helper(action: str, token: str, profile: str, duration: int) -> dict[str, Any]:
        baseline: dict[str, Any] = {"qdisc": [], "class": [], "filter_root": []}
        if action == "cleanup":
            clock.value = 50
            return {
                "cleanup_complete": True,
                "cleanup_phase": "complete",
                "route_before": {"interface": "eth0"},
                "route_after": {"interface": "eth0"},
                "prestate": baseline,
                "restored_state": baseline,
            }
        return {
            "route_before": {"interface": "eth0"},
            "route_active": {"interface": "eth0"},
        }

    harness.helper = helper
    harness.surrogate = lambda: {"status_code": 200}
    detail_calls = 0

    def get(path: str, **params: Any) -> tuple[dict[str, Any], float, str]:
        nonlocal detail_calls
        if path == "/diagnoses":
            return (
                {"diagnoses": [{"id": "incident", "resource": "ipv4:192.0.2.10"}]},
                10,
                "fixture",
            )
        detail_calls += 1
        if detail_calls == 1:
            return {"status": "active", "opening_evidence": {"probe": {}}}, 20, "fixture"
        clock.value = 105
        return {"status": "resolved"}, 105, "fixture"

    monkeypatch.setattr(harness, "_get", get)
    monkeypatch.setattr(
        harness,
        "_admin_and_reference",
        lambda config: {
            "response_completed_monotonic": 105,
            "admin_response_completed_monotonic": 105,
        },
    )
    phase = harness.run_phase("loss", CONFIG)
    assert deadlines == [60, 110]
    assert phase["recovery_deadline_monotonic"] == 110
    assert phase["recovery_response_completed_monotonic"] == 105
    assert phase["trigger_to_diagnosis_seconds"] == 10


def test_incident_assertion_binds_detail_and_opening_to_faulted_node() -> None:
    harness = NetworkHarness("http://api", "node-a", "node-b", "192.0.2.10", "http://x")
    trigger = {"identity": IDENTITY}
    detail: dict[str, Any] = {
        "node_id": "node-b",
        "rule": "network_path_degradation",
        "resource": "ipv4:192.0.2.10",
        "severity": "warning",
        "configuration": CONFIG,
        "opening_evidence": {
            **IDENTITY,
            "node_id": "node-b",
            "probe": {"target": "192.0.2.10", "lost": 1, "median_rtt_ms": 20},
        },
    }
    with pytest.raises(ValueError, match="identity"):
        harness._assert_incident(detail, "loss", "192.0.2.10", CONFIG, trigger)


def test_incident_opening_may_follow_trigger_but_may_not_precede_or_change_session() -> None:
    harness = NetworkHarness("http://api", "node-a", "node-b", "192.0.2.10", "http://x")
    trigger = {"identity": IDENTITY}
    detail: dict[str, Any] = {
        "node_id": "node-a",
        "rule": "network_path_degradation",
        "resource": "ipv4:192.0.2.10",
        "severity": "warning",
        "configuration": CONFIG,
        "opening_evidence": {
            **IDENTITY,
            "node_id": "node-a",
            "sequence": 12,
            "observed_at": "2026-10-19T12:00:10+00:00",
            "probe": {"target": "192.0.2.10", "lost": 1, "median_rtt_ms": 20},
        },
    }
    harness._assert_incident(detail, "loss", "192.0.2.10", CONFIG, trigger)
    detail["opening_evidence"]["sequence"] = 9
    with pytest.raises(ValueError, match="predates"):
        harness._assert_incident(detail, "loss", "192.0.2.10", CONFIG, trigger)
    detail["opening_evidence"]["sequence"] = 12
    detail["opening_evidence"]["agent_session_id"] = "00000000-0000-0000-0000-000000000099"
    with pytest.raises(ValueError, match="identity"):
        harness._assert_incident(detail, "loss", "192.0.2.10", CONFIG, trigger)


def test_five_run_aggregate_rejects_incomplete_attempts(tmp_path: Path) -> None:
    paths = []
    for index in range(5):
        path = tmp_path / f"attempt-{index}.json"
        path.write_text('{"status":"failed"}', encoding="utf-8")
        paths.append(path)
    result = aggregate(paths)
    assert result["status"] == "failed"
    assert result["required_runs"] == 5
    with pytest.raises(ValueError, match="exactly five"):
        aggregate(paths[:4])


def test_five_run_aggregate_accepts_two_faulted_node_orientations(tmp_path: Path) -> None:
    paths = []
    timings = [10, 20, 25, 35, 40]
    for index in range(5):
        node, reference = ("node-a", "node-b") if index % 2 == 0 else ("node-b", "node-a")
        attempt = {
            "status": "passed",
            "source_manifest": {"revision": "abc", "sha256": {"a": "b"}},
            "environment_metadata": {"label": "lab", "topology": "two-node"},
            "scenario": {
                "status": "passed",
                "node": node,
                "reference_node": reference,
                "target": "192.0.2.10",
                "configuration": CONFIG,
                "latency": {
                    "status": "passed",
                    "trigger_to_diagnosis_seconds": timings[index],
                },
                "loss": {"status": "passed", "trigger_to_diagnosis_seconds": timings[index]},
            },
        }
        path = tmp_path / f"complete-{index}.json"
        path.write_text(__import__("json").dumps(attempt), encoding="utf-8")
        paths.append(path)
    result = aggregate(paths)
    assert result["status"] == "passed"
    assert set(result["faulted_nodes"]) == {"node-a", "node-b"}
    assert result["phase_latency_acceptance"] and result["phase_loss_acceptance"]
    assert result["latency_phase_median_seconds"] == 25
    assert result["latency_under_30_seconds"] == [True, True, True, False, False]


def test_five_run_aggregate_rejects_profile_median_at_thirty(tmp_path: Path) -> None:
    paths = []
    for index, timing in enumerate([10, 29, 30, 35, 40]):
        attempt = {
            "status": "passed",
            "source_manifest": {"revision": "abc", "sha256": {"a": "b"}},
            "environment_metadata": {"label": "lab", "topology": "two-node"},
            "scenario": {
                "status": "passed",
                "node": "node-a",
                "reference_node": "node-b",
                "target": "192.0.2.10",
                "configuration": CONFIG,
                "latency": {"status": "passed", "trigger_to_diagnosis_seconds": timing},
                "loss": {"status": "passed", "trigger_to_diagnosis_seconds": 10},
            },
        }
        path = tmp_path / f"median-fail-{index}.json"
        path.write_text(__import__("json").dumps(attempt), encoding="utf-8")
        paths.append(path)
    result = aggregate(paths)
    assert result["status"] == "failed"
    assert result["latency_phase_median_seconds"] == 30
    assert not result["phase_latency_acceptance"]
    assert result["phase_loss_acceptance"]


def test_single_complete_slow_run_is_retained_for_later_median(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output = tmp_path / "slow-complete.json"
    scenario = {
        "status": "passed",
        "latency": {"status": "passed", "trigger_to_diagnosis_seconds": 35},
        "loss": {"status": "passed", "trigger_to_diagnosis_seconds": 20},
    }

    class Harness:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def run(self) -> dict[str, Any]:
            return scenario

    monkeypatch.setattr("chaos_network.NetworkHarness", Harness)
    monkeypatch.setattr(
        "chaos_network.source_manifest",
        lambda: {"revision": "fixture", "dirty": False, "sha256": {}},
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "chaos_network.py",
            "--api",
            "http://api",
            "--node",
            "node-a",
            "--reference-node",
            "node-b",
            "--target",
            "192.0.2.10",
            "--surrogate-url",
            "http://surrogate",
            "--output",
            str(output),
        ],
    )
    chaos_network_main()
    result = __import__("json").loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "passed"
    assert result["scenario"]["latency"]["diagnosis_under_30_seconds"] is False
    assert result["scenario"]["loss"]["diagnosis_under_30_seconds"] is True
