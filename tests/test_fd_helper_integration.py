import importlib
import subprocess

import fd_helper_integration
import integration_fd
import pytest


def result(returncode: int, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["docker", "inspect"], returncode, "", stderr)


def test_cleanup_absence_requires_authoritative_docker_result() -> None:
    name = "fd08-native-owned"
    assert fd_helper_integration.absence_status(result(0), "container", name) == "present"
    assert (
        fd_helper_integration.absence_status(result(124, "command timed out"), "container", name)
        == "unknown"
    )
    assert (
        fd_helper_integration.absence_status(
            result(1, "Error response from daemon: connection reset"), "container", name
        )
        == "unknown"
    )
    assert (
        fd_helper_integration.absence_status(
            result(1, f"Error response from daemon: No such object: {name}"),
            "container",
            name,
        )
        == "absent"
    )
    assert (
        fd_helper_integration.absence_status(
            result(1, f"Error response from daemon: get {name}: no such volume"),
            "volume",
            name,
        )
        == "absent"
    )


def test_native_expiry_verifier_accepts_exact_terminated_zombie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEETDOCTOR_TARGET_TOKEN", "f" * 40)
    probe = importlib.import_module("fd_helper_probe")
    resource = importlib.import_module("fd_resource")
    identity = {"pid": 42, "starttime_ticks": 99, "uid": 10001, "boot_id": "boot-a"}
    monkeypatch.setattr(resource, "process_identity", lambda pid: identity)
    monkeypatch.setattr(resource, "process_state", lambda pid: "Z")
    assert probe.wait_identity_terminated(identity, 1) < 1


def test_service_history_requires_exact_measured_node_value() -> None:
    current = {
        "result": [
            {"metric": {"node": "node-b"}, "value": [1, "0.96875"]},
            {"metric": {"node": "node-a"}, "value": [1, "0.96875"]},
        ]
    }
    history = {
        "result": [
            {
                "metric": {"node": "node-a"},
                "values": [[1, "0.5"], [2, "0.96875"]],
            }
        ]
    }
    assert integration_fd.prometheus_has_value(current, "node-a", 124 / 128)
    assert integration_fd.prometheus_has_value(history, "node-a", 124 / 128)
    assert not integration_fd.prometheus_has_value(current, "node-a", 0.5)
    assert not integration_fd.prometheus_has_value({"result": []}, "node-a", 124 / 128)
