import json
import os
import signal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import memory_resource
import pytest


def configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory_resource, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(memory_resource, "boot_identity", lambda: "test-boot")
    monkeypatch.setattr(memory_resource, "source_hash", lambda: "test-source")
    monkeypatch.setattr(memory_resource, "available_memory", lambda: 1 << 40)
    monkeypatch.setattr(memory_resource, "current_cgroup", lambda: "0::/controller\n")
    monkeypatch.setattr(memory_resource, "STATE_OWNER_UID", tmp_path.stat().st_uid)


def local_state_writer(tmp_path: Path) -> Any:
    def write(record: dict[str, Any]) -> None:
        tmp_path.mkdir(exist_ok=True)
        path = tmp_path / (str(record["token"]) + ".json")
        path.write_text(json.dumps(record))
        path.chmod(0o600)

    return write


def local_trusted_state(tmp_path: Path) -> Any:
    def read(token: str) -> dict[str, Any] | None:
        path = tmp_path / (token + ".json")
        return json.loads(path.read_text()) if path.exists() else None

    return read


def test_bounds_and_tokens_are_strict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert memory_resource.STATE_OWNER_UID == 0
    configure(tmp_path, monkeypatch)
    for token in ("x" * 16, "a" * 15, "../" + "a" * 16):
        with pytest.raises(ValueError):
            memory_resource.unit_name(token)
        with pytest.raises(ValueError):
            memory_resource.state_path(token)
    with pytest.raises(ValueError, match="330"):
        memory_resource.prepare("a" * 16, 329)
    with pytest.raises(ValueError, match="32..64"):
        memory_resource.start("a" * 16, 96 << 20, 31 << 20, 30)
    with pytest.raises(ValueError, match="128"):
        memory_resource.start("a" * 16, 129 << 20, 48 << 20, 30)


def test_root_state_rejects_replacement_before_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    token = "b" * 16
    unit = memory_resource.unit_name(token)
    tmp_path.mkdir(exist_ok=True)
    path = tmp_path / (token + ".json")
    path.write_text(
        json.dumps(
            {
                "token": token,
                "unit": unit,
                "invocation_id": "1" * 32,
                "control_group": "/owned",
                "leaf_path": "/owned/workload",
                "boot_id": "test-boot",
                "script_sha256": "test-source",
            }
        )
    )
    path.chmod(0o600)
    stored = json.loads(path.read_text())
    monkeypatch.setattr(memory_resource, "trusted_state", lambda value: stored)
    monkeypatch.setattr(
        memory_resource,
        "show",
        lambda value: {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "InvocationID": "2" * 32,
            "ControlGroup": "/replaced",
        },
    )
    monkeypatch.setattr(
        memory_resource,
        "command",
        lambda *args, **kwargs: pytest.fail("replaced unit must not be stopped"),
    )
    with pytest.raises(ValueError, match="replaced"):
        memory_resource.release(token)


def test_prepare_requests_required_systemd_properties(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    token = "c" * 16
    unit = memory_resource.unit_name(token)
    states: list[dict[str, Any] | None] = [None]
    prepared = {
        "token": token,
        "unit": unit,
        "phase": "prepared",
        "invocation_id": "1" * 32,
        "control_group": "/system.slice/" + unit,
        "leaf_path": "/system.slice/" + unit + "/workload",
        "generation": {"st_dev": 1, "st_ino": 2},
        "lease_seconds": 360,
        "lease_origin_monotonic": 0,
        "boot_id": "test-boot",
        "script_sha256": "test-source",
    }
    monkeypatch.setattr(
        memory_resource, "trusted_state", lambda value: states.pop(0) if states else prepared
    )
    show_calls = [0]

    def show(value: str) -> dict[str, str]:
        show_calls[0] += 1
        return (
            {"LoadState": "not-found"}
            if show_calls[0] == 1
            else {"Id": unit, "LoadState": "loaded"}
        )

    monkeypatch.setattr(memory_resource, "show", show)
    commands: list[list[str]] = []

    def run(argv: list[str], timeout: float = 10) -> Any:
        commands.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(memory_resource, "command", run)
    monkeypatch.setattr(memory_resource, "verify_live", lambda value: ({}, Path("/owned")))
    monkeypatch.setattr(memory_resource, "write_state", lambda value: None)
    monkeypatch.setattr("memory_resource.time.monotonic", lambda: 0.0)
    result = memory_resource.prepare(token)
    assert result["phase"] == "prepared"
    launched = commands[0]
    for expected in (
        "--property=Delegate=yes",
        "--property=OOMPolicy=continue",
        "--property=KillMode=control-group",
        "--property=RuntimeMaxSec=360",
        "--property=MemoryMax=256M",
    ):
        assert expected in launched


def test_prepare_prelaunch_interruption_removes_starting_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    token = "f" * 16
    previous = {signal.SIGINT: object(), signal.SIGTERM: object()}
    handlers = previous.copy()

    def install(signum: signal.Signals, handler: object) -> object:
        prior = handlers[signum]
        handlers[signum] = handler
        return prior

    write = local_state_writer(tmp_path)

    def protected_write(record: dict[str, Any]) -> None:
        assert callable(handlers[signal.SIGINT]) and callable(handlers[signal.SIGTERM])
        write(record)

    monkeypatch.setattr("memory_resource.signal.signal", install)
    monkeypatch.setattr(memory_resource, "write_state", protected_write)
    monkeypatch.setattr(memory_resource, "trusted_state", local_trusted_state(tmp_path))
    monkeypatch.setattr(memory_resource, "show", lambda unit: {"LoadState": "not-found"})
    monkeypatch.setattr(
        memory_resource,
        "command",
        lambda *args, **kwargs: pytest.fail("prelaunch interruption must not start systemd"),
    )
    with pytest.raises(KeyboardInterrupt, match="prelaunch"):
        memory_resource.prepare(
            token,
            15,
            expiry_probe=True,
            proof_fault="prelaunch_interrupt",
        )
    assert memory_resource.trusted_state(token) is None
    assert not memory_resource.gate_path(token).exists()
    assert handlers == previous


def test_partial_cleanup_failure_retains_identity_and_release_retries_safely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    token = "1" * 16
    unit = memory_resource.unit_name(token)
    cgroup_root = tmp_path / "cgroup"
    cgroup_root.mkdir()
    monkeypatch.setattr(memory_resource, "CGROUP_ROOT", cgroup_root)
    monkeypatch.setattr(memory_resource, "write_state", local_state_writer(tmp_path))
    monkeypatch.setattr(memory_resource, "trusted_state", local_trusted_state(tmp_path))
    record = {
        "token": token,
        "unit": unit,
        "phase": "starting",
        "invocation_id": "2" * 32,
        "control_group": "/owned",
        "lease_seconds": 15,
        "lease_origin_monotonic": 0,
        "boot_id": "test-boot",
        "script_sha256": "test-source",
    }
    memory_resource.write_state(record)
    active = [True]

    def show(value: str) -> dict[str, str]:
        return {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "active" if active[0] else "inactive",
            "InvocationID": "2" * 32,
            "ControlGroup": "/owned",
        }

    def command(argv: list[str], timeout: float = 10) -> Any:
        active[0] = False
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(memory_resource, "show", show)
    monkeypatch.setattr(memory_resource, "command", command)
    with pytest.raises(RuntimeError, match="injected"):
        memory_resource.cleanup_partial_prepare(token, proof_fail=True)
    failure = RuntimeError("owned stop unavailable")
    memory_resource._record_cleanup_failure(token, failure)
    retained = memory_resource.trusted_state(token)
    assert retained is not None and "owned stop unavailable" in retained["cleanup_error"]
    released = memory_resource.release(token)
    assert released["released"] is True and memory_resource.trusted_state(token) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX privilege-drop contract")
def test_allocator_gate_opens_only_after_exact_confinement_and_nonroot_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pwd

    configure(tmp_path, monkeypatch)
    token = "2" * 16
    leaf = tmp_path / "leaf"
    leaf.mkdir()
    (leaf / "cgroup.procs").write_text("")
    record = {
        "token": token,
        "unit": memory_resource.unit_name(token),
        "phase": "prepared",
        "leaf_path": "/owned/workload",
        "lease_seconds": 360,
        "lease_origin_monotonic": 0,
        "boot_id": "test-boot",
        "script_sha256": "test-source",
    }
    monkeypatch.setattr(memory_resource, "trusted_state", lambda value: record)
    monkeypatch.setattr(
        memory_resource, "verify_live", lambda value: ({"ActiveState": "active"}, leaf)
    )
    monkeypatch.setattr(memory_resource, "show", lambda service: {"LoadState": "not-found"})
    monkeypatch.setattr("memory_resource.time.monotonic", lambda: 1.0)
    monkeypatch.setattr(pwd, "getpwnam", lambda user: SimpleNamespace(pw_uid=65534, pw_gid=65534))
    killed = [False]

    class Process:
        pid = 123

        def poll(self) -> None:
            return None

        def kill(self) -> None:
            killed[0] = True

        def wait(self, timeout: float) -> int:
            return 0

    def popen(argv: list[str], **kwargs: object) -> Process:
        assert kwargs["extra_groups"] == ()
        return Process()

    def misplaced(pid: int) -> str:
        assert not memory_resource.gate_path(token).exists()
        return "/owned/workload-child"

    monkeypatch.setattr("memory_resource.subprocess.Popen", popen)
    monkeypatch.setattr(memory_resource, "process_cgroup", misplaced)
    with pytest.raises(RuntimeError, match="exact"):
        memory_resource.start(token, 96 << 20, 48 << 20, 30, "nobody")
    assert killed[0] and not memory_resource.gate_path(token).exists()
    (leaf / "cgroup.procs").write_text("")

    monkeypatch.setattr(pwd, "getpwnam", lambda user: SimpleNamespace(pw_uid=0, pw_gid=0))
    with pytest.raises(ValueError, match="non-root UID"):
        memory_resource.start(token, 96 << 20, 48 << 20, 30, "root-alias")
    assert not memory_resource.gate_path(token).exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode contract")
def test_trusted_state_binds_root_file_boot_and_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    token = "d" * 16
    path = memory_resource.state_path(token)
    record = {
        "token": token,
        "unit": memory_resource.unit_name(token),
        "boot_id": "test-boot",
        "script_sha256": "test-source",
    }
    path.write_text(json.dumps(record))
    path.chmod(0o600)
    assert memory_resource.trusted_state(token) == record
    monkeypatch.setattr(memory_resource, "boot_identity", lambda: "other-boot")
    with pytest.raises(ValueError, match="another boot"):
        memory_resource.trusted_state(token)
    monkeypatch.setattr(memory_resource, "boot_identity", lambda: "test-boot")
    monkeypatch.setattr(memory_resource, "source_hash", lambda: "other-source")
    with pytest.raises(ValueError, match="source changed"):
        memory_resource.trusted_state(token)


def test_start_rejects_headroom_and_monitoring_overlap_before_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    token = "e" * 16
    leaf = tmp_path / "leaf"
    leaf.mkdir()
    (leaf / "cgroup.procs").write_text("")
    record = {
        "token": token,
        "unit": memory_resource.unit_name(token),
        "phase": "prepared",
        "leaf_path": "/owned/workload",
        "lease_seconds": 360,
        "lease_origin_monotonic": 0,
        "boot_id": "test-boot",
        "script_sha256": "test-source",
    }
    monkeypatch.setattr(memory_resource, "trusted_state", lambda value: record)
    monkeypatch.setattr(
        memory_resource,
        "verify_live",
        lambda value: ({"ActiveState": "active"}, leaf),
    )
    monkeypatch.setattr("memory_resource.time.monotonic", lambda: 1.0)
    monkeypatch.setattr(memory_resource, "available_memory", lambda: 1)
    with pytest.raises(ValueError, match="headroom"):
        memory_resource.start(token, 96 << 20, 48 << 20, 30, "nobody")
    monkeypatch.setattr(memory_resource, "available_memory", lambda: 1 << 40)
    monkeypatch.setattr(
        memory_resource,
        "show",
        lambda service: {
            "LoadState": "loaded",
            "ActiveState": "active",
            "ControlGroup": "/owned/workload",
        },
    )
    with pytest.raises(ValueError, match="not separated"):
        memory_resource.start(token, 96 << 20, 48 << 20, 30, "nobody")
