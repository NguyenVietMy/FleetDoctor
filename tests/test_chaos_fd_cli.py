import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import chaos_fd
import pytest


def completed(value: dict[str, object]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 0, json.dumps(value), "")


def test_checkout_helper_uses_interpreter_without_executable_bit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper_path = tmp_path / "fd_resource.py"
    helper_path.write_text("not executed by this test")
    helper_path.chmod(0o644)
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return completed({"state": "active"})

    monkeypatch.setattr(subprocess, "run", run)
    assert chaos_fd.Helper(helper_path).status("a" * 16)["state"] == "active"
    assert calls == [["sudo", sys.executable, str(helper_path), "status", "--token", "a" * 16]]


def test_prepared_adapter_reuses_identity_through_pressure_and_owned_cleanup() -> None:
    token = "b" * 16
    helper = chaos_fd.Helper(Path("fixture.py"), prepared=True, monotonic=lambda: 110)
    helper.call = Mock(  # type: ignore[method-assign]
        side_effect=[
            {
                "token": token,
                "state": "active",
                "phase": "prepared",
                "limit": 128,
                "seconds": 180,
                "started_monotonic": 100,
                "worker_pid": 42,
                "worker_starttime_ticks": 99,
            },
            {"token": token, "pressuring": True, "worker_pid": 42},
            {"token": token, "cleaned": True, "worker_pid": 42},
        ]
    )
    prepared = helper.start(token, 128, 120)
    pressured = helper.pressure(token)
    cleaned = helper.cleanup(token)
    assert prepared["worker_pid"] == pressured["worker_pid"] == cleaned["worker_pid"] == 42
    assert [call.args[1] for call in helper.call.call_args_list] == [token, token, token]
    assert [call.args[0] for call in helper.call.call_args_list] == [
        "status",
        "pressure",
        "cleanup",
    ]
