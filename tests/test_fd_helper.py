import json
import os
import signal
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import fd_resource
import pytest


def configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tmp_path.mkdir(exist_ok=True)
    tmp_path.chmod(0o700)
    monkeypatch.setattr(fd_resource, "STATE_ROOT", tmp_path)
    if os.name == "posix":
        monkeypatch.setattr(fd_resource, "STATE_OWNER_UID", os.getuid())


def process_line(pid: int, start: int, state: str = "R") -> str:
    rest = [state] + ["0"] * 21
    rest[19] = str(start)
    return f"{pid} (fd worker) " + " ".join(rest)


def fake_proc(tmp_path: Path, *, pid: int = 42, start: int = 99, uid: int = 1000) -> Path:
    proc = tmp_path / "proc"
    process = proc / str(pid)
    (process / "fd").mkdir(parents=True)
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text("boot-a\n")
    (process / "stat").write_text(process_line(pid, start))
    (process / "status").write_text(f"Name:\tfd-worker\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    (process / "limits").write_text(
        "Max open files            128                  128                  files\n"
    )
    for number in range(120):
        (process / "fd" / str(number)).write_text("")
    return proc


def test_bounds_token_and_actual_proc_measurement(tmp_path: Path) -> None:
    for token in ("x" * 16, "a" * 15, "../" + "a" * 16):
        with pytest.raises(ValueError):
            fd_resource.state_path(token)
    with pytest.raises(ValueError, match="limit"):
        fd_resource.start("a" * 16, 1025, 30)
    with pytest.raises(ValueError, match="limit"):
        fd_resource.start("a" * 16, 128, 181)
    with pytest.raises(ValueError, match="limit"):
        fd_resource.start("a" * 16, 128, 19)

    proc = fake_proc(tmp_path)
    result = fd_resource.process_measurement(
        42, 99, expected_uid=1000, expected_boot="boot-a", proc=proc
    )
    assert result["descriptor_count"] == 120
    assert result["soft_limit"] == 128
    assert result["pressure_ratio"] == 0.9375
    (proc / "42/stat").write_text(process_line(42, 100))
    with pytest.raises(ValueError, match="replaced"):
        fd_resource.process_measurement(42, 99, proc=proc)


@pytest.mark.skipif(os.name != "posix", reason="POSIX signal masks")
def test_worker_entry_unblocks_inherited_controller_signals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mask = Mock()
    monkeypatch.setattr(signal, "pthread_sigmask", mask)
    fd_resource._unblock_lifecycle_signals()
    mask.assert_called_once_with(
        signal.SIG_UNBLOCK,
        {signal.SIGINT, signal.SIGTERM},
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX pending-signal spawn handoff")
def test_spawn_rolls_back_pidfd_when_unmask_delivers_pending_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = SimpleNamespace(pid=321, wait=Mock(return_value=0))
    masks = Mock(side_effect=[{signal.SIGUSR1}, InterruptedError("pending signal")])
    sends: list[tuple[int, int]] = []
    closes: list[int] = []
    monkeypatch.setattr(signal, "pthread_sigmask", masks)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: child)
    monkeypatch.setattr(os, "pidfd_open", lambda pid: 77)
    monkeypatch.setattr(
        fd_resource,
        "process_identity",
        lambda pid: {"pid": pid, "starttime_ticks": 9, "uid": 1000, "boot_id": "boot-a"},
    )
    monkeypatch.setattr(
        fd_resource, "_pidfd_send", lambda descriptor, signum: sends.append((descriptor, signum))
    )
    monkeypatch.setattr(os, "close", lambda descriptor: closes.append(descriptor))

    with pytest.raises(InterruptedError, match="pending signal"):
        fd_resource._spawn_pidfd(["ignored"])

    assert sends == [(77, signal.SIGKILL)]
    child.wait.assert_called_once_with(timeout=5)
    assert closes == [77]
    assert masks.call_args_list == [
        ((signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}),),
        ((signal.SIG_SETMASK, {signal.SIGUSR1}),),
    ]


@pytest.mark.skipif(os.name != "posix", reason="POSIX uncertain rollback authority")
def test_uncertain_spawn_rollback_blocks_admission_until_exact_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    configure(state, monkeypatch)
    monkeypatch.setattr(fd_resource, "_preflight_pidfd", lambda: None)
    monkeypatch.setattr(
        fd_resource.pwd,  # type: ignore[attr-defined]
        "getpwnam",
        lambda _: SimpleNamespace(pw_uid=1000, pw_gid=1000),
    )
    identity = {"pid": 321, "starttime_ticks": 9, "uid": 1000, "boot_id": "boot-a"}
    monkeypatch.setattr(
        fd_resource,
        "_spawn_pidfd",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            fd_resource.SpawnRollbackError("pidfd rollback failed", identity)
        ),
    )

    with pytest.raises(fd_resource.SpawnRollbackError, match="pidfd rollback failed"):
        fd_resource.start("e" * 16, 128, 30)
    retained = fd_resource.trusted_state("e" * 16)
    assert retained is not None
    assert retained["phase"] == "rollback_uncertain"
    assert retained["rollback_verified"] is False
    assert fd_resource.status("e" * 16)["owned"] is True
    with pytest.raises(ValueError, match="already owned"):
        fd_resource.start("f" * 16, 128, 30)

    monkeypatch.setattr(fd_resource, "process_identity", lambda pid: identity)
    monkeypatch.setattr(fd_resource, "process_state", lambda pid: "R")
    terminated: list[dict[str, object]] = []

    def terminate(value: dict[str, object]) -> list[str]:
        terminated.append(value)
        return ["pidfd"]

    monkeypatch.setattr(fd_resource, "_terminate", terminate)
    cleaned = fd_resource.cleanup("e" * 16)
    assert terminated == [identity]
    assert cleaned["phase"] == "cleaned"
    assert cleaned["rollback_verified"] is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX uncertain rollback authority")
def test_uncertain_cleanup_never_signals_replaced_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    configure(state, monkeypatch)
    identity = {"pid": 321, "starttime_ticks": 9, "uid": 1000, "boot_id": "boot-a"}
    with fd_resource.locked_authority() as (_, descriptor, _):
        fd_resource._write_locked(
            descriptor,
            {
                "token": "a" * 16,
                "phase": "rollback_uncertain",
                "rollback_verified": False,
                "rollback_identities": [identity],
            },
        )
    monkeypatch.setattr(
        fd_resource,
        "process_identity",
        lambda pid: identity | {"starttime_ticks": 10},
    )
    monkeypatch.setattr(
        fd_resource,
        "_terminate",
        lambda value: pytest.fail("a replacement must never be signalled"),
    )

    cleaned = fd_resource.cleanup("a" * 16)
    assert cleaned["phase"] == "cleaned"
    assert cleaned["cleanup_methods"] == ["already_terminated_or_replaced"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX authority contract")
def test_authority_root_and_file_are_private_nofollow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    configure(state, monkeypatch)
    token = "a" * 16
    with fd_resource.locked_authority() as (_, descriptor, _):
        fd_resource._write_locked(
            descriptor, {"token": token, "phase": "prepared", "worker_pid": 1}
        )
    assert fd_resource.trusted_state(token)["worker_pid"] == 1  # type: ignore[index]
    with pytest.raises(ValueError, match="different token"):
        fd_resource.trusted_state("b" * 16)

    authority = state / fd_resource.AUTHORITY_NAME
    authority.unlink()
    target = state / "target"
    target.write_text("{}")
    authority.symlink_to(target)
    with pytest.raises(OSError):
        fd_resource.trusted_state(token)


@pytest.mark.skipif(os.name != "posix", reason="POSIX authority contract")
def test_symlink_authority_root_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    monkeypatch.setattr(fd_resource, "STATE_ROOT", linked)
    monkeypatch.setattr(fd_resource, "STATE_OWNER_UID", os.getuid())
    with pytest.raises(ValueError, match="root"):
        fd_resource.trusted_state("a" * 16)


@pytest.mark.skipif(os.name != "posix", reason="pidfd contract")
def test_replaced_or_wrong_boot_process_is_never_signalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = {"pid": 42, "starttime_ticks": 100, "uid": 1000, "boot_id": "boot-a"}
    monkeypatch.setattr(fd_resource, "current_boot_id", lambda: "boot-b")
    monkeypatch.setattr(
        fd_resource,
        "_pidfd_send",
        lambda *args: pytest.fail("stale process must not be signalled"),
    )
    with pytest.raises(ValueError, match="stale-boot"):
        fd_resource.signal_owned(identity, 15)


@pytest.mark.skipif(os.name != "posix", reason="POSIX authority contract")
def test_cleanup_refuses_replaced_authority_before_signalling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    configure(state, monkeypatch)
    token = "c" * 16
    record = {
        "token": token,
        "phase": "prepared",
        "boot_id": "boot-a",
        "worker_pid": 42,
        "worker_starttime_ticks": 100,
        "worker_uid": 1000,
        "watchdog_pid": 43,
        "watchdog_starttime_ticks": 101,
        "watchdog_uid": 0,
    }
    with fd_resource.locked_authority() as (_, descriptor, _):
        fd_resource._write_locked(descriptor, record)

    def replace(boundary: str) -> None:
        assert boundary == "cleanup_before_signal"
        path = state / fd_resource.AUTHORITY_NAME
        path.unlink()
        path.write_text(json.dumps(record))
        path.chmod(0o600)

    monkeypatch.setattr(
        fd_resource,
        "_terminate",
        lambda *args: pytest.fail("replacement must be rejected before signal"),
    )
    with pytest.raises(ValueError, match="replaced"):
        fd_resource.cleanup(token, boundary_hook=replace)


@pytest.mark.skipif(os.name != "posix", reason="POSIX rollback contract")
@pytest.mark.parametrize(
    "boundary",
    [
        "worker_spawn_pidfd",
        "worker_identity",
        "watchdog_spawn_pidfd",
        "watchdog_identity",
        "prepared",
    ],
)
def test_start_rolls_back_and_retains_failure_at_every_boundary(
    boundary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / boundary
    configure(state, monkeypatch)
    monkeypatch.setattr(fd_resource, "_preflight_pidfd", lambda: None)
    monkeypatch.setattr(
        fd_resource.pwd,  # type: ignore[attr-defined]
        "getpwnam",
        lambda _: SimpleNamespace(pw_uid=1000, pw_gid=1000),
    )
    children: list[SimpleNamespace] = []
    pipe_writes: list[int] = []

    def spawn(*args: object, **kwargs: object) -> tuple[SimpleNamespace, int]:
        pid = 101 + len(children)
        child = SimpleNamespace(pid=pid, wait=lambda timeout: 0)
        children.append(child)
        read_fd, write_fd = os.pipe()
        pipe_writes.append(write_fd)
        return child, read_fd

    identities = {
        101: {"pid": 101, "starttime_ticks": 11, "uid": 1000, "boot_id": "boot-a"},
        102: {"pid": 102, "starttime_ticks": 12, "uid": os.getuid(), "boot_id": "boot-a"},
    }
    sends: list[tuple[int, int]] = []
    monkeypatch.setattr(fd_resource, "_spawn_pidfd", spawn)
    monkeypatch.setattr(fd_resource, "process_identity", lambda pid: identities[pid])
    monkeypatch.setattr(fd_resource, "current_boot_id", lambda: "boot-a")
    monkeypatch.setattr(
        fd_resource,
        "process_measurement",
        lambda *args, **kwargs: {"soft_limit": 128, "pressure_ratio": 0.25},
    )
    monkeypatch.setattr(
        fd_resource, "_pidfd_send", lambda descriptor, signum: sends.append((descriptor, signum))
    )

    def fail(name: str) -> None:
        if name == boundary:
            raise InterruptedError("injected interruption")

    try:
        with pytest.raises(InterruptedError, match="injected"):
            fd_resource.start("d" * 16, 128, 30, boundary_hook=fail)
        retained = fd_resource.trusted_state("d" * 16)
        assert retained is not None
        assert retained["phase"] == "failed"
        assert "InterruptedError" in retained["failure"]
        expected_processes = 1 if boundary in {"worker_spawn_pidfd", "worker_identity"} else 2
        assert len(sends) == expected_processes
        cleaned = fd_resource.cleanup("d" * 16)
        assert cleaned["phase"] == "cleaned"
    finally:
        for descriptor in pipe_writes:
            os.close(descriptor)
