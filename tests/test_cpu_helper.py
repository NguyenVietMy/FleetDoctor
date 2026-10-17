import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import cpu_resource
import pytest


def configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cpu_resource, "STATE_ROOT", tmp_path)


def test_token_and_workload_bounds_are_strict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    for token in ("x" * 16, "a" * 15, "../" + "a" * 16):
        with pytest.raises(ValueError):
            cpu_resource.unit_name(token)
    with pytest.raises(ValueError, match="workers"):
        cpu_resource.start("a" * 16, 65, 5)
    with pytest.raises(ValueError, match="workers"):
        cpu_resource.start("a" * 16, 2, 181)


def test_start_records_systemd_identity_and_cleanup_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    token = "a" * 16
    unit = cpu_resource.unit_name(token)
    states = [
        {"Id": unit, "LoadState": "not-found"},
        {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "InvocationID": "1" * 32,
            "ControlGroup": "/system.slice/" + unit,
            "User": "fleetdoctor",
        },
        {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "InvocationID": "1" * 32,
            "ControlGroup": "/system.slice/" + unit,
            "User": "fleetdoctor",
        },
    ]
    monkeypatch.setattr(cpu_resource, "show", lambda value: states.pop(0))
    commands: list[list[str]] = []

    def run(argv: list[str], timeout: float = 8) -> Any:
        commands.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cpu_resource, "command", run)
    record = cpu_resource.start(token, 2, 5)
    assert record["invocation_id"] == "1" * 32
    assert "--property=RuntimeMaxSec=5" in commands[0]
    assert "--property=KillMode=control-group" in commands[0]
    assert "--uid=fleetdoctor" in commands[0]
    stored = json.loads((tmp_path / (token + ".json")).read_text())
    assert stored["control_group"] == "/system.slice/" + unit
    assert cpu_resource.cleanup(token)["cleaned"]
    assert commands[-1] == ["systemctl", "stop", unit]
    assert cpu_resource.cleanup(token) == {
        "token": token,
        "state": "absent",
        "owned": False,
        "cleaned": True,
    }


def test_replaced_unit_is_never_stopped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configure(tmp_path, monkeypatch)
    token = "b" * 16
    unit = cpu_resource.unit_name(token)
    tmp_path.mkdir(exist_ok=True)
    path = tmp_path / (token + ".json")
    path.write_text(
        json.dumps(
            {
                "token": token,
                "unit": unit,
                "invocation_id": "1" * 32,
                "control_group": "/owned",
                "worker_user": "fleetdoctor",
            }
        )
    )
    path.chmod(0o600)
    monkeypatch.setattr(
        cpu_resource,
        "show",
        lambda value: {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "InvocationID": "2" * 32,
            "ControlGroup": "/reused",
            "User": "fleetdoctor",
        },
    )
    monkeypatch.setattr(
        cpu_resource,
        "command",
        lambda *args, **kwargs: pytest.fail("replaced unit must not be stopped"),
    )
    with pytest.raises(ValueError, match="replaced"):
        cpu_resource.cleanup(token)


def test_worker_always_terminates_remaining_children(monkeypatch: pytest.MonkeyPatch) -> None:
    class Child:
        def __init__(self) -> None:
            self.terminated = False
            self.waits = 0

        def poll(self) -> int | None:
            return None if not self.terminated else 0

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float) -> int:
            self.waits += 1
            return 0

        def kill(self) -> None:
            self.terminated = True

    children: list[Child] = []

    def popen(*args: object, **kwargs: object) -> Child:
        child = Child()
        children.append(child)
        return child

    monotonic = iter((0.0, 10.0))
    monkeypatch.setattr("cpu_resource.subprocess.Popen", popen)
    monkeypatch.setattr("cpu_resource.time.monotonic", lambda: next(monotonic))
    cpu_resource.worker(2, 1)
    assert len(children) == 1 and all(child.terminated and child.waits for child in children)
