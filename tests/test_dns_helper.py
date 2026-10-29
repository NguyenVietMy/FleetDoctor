import os
import socket
import threading
import time
from pathlib import Path
from typing import Any, cast

import pytest

pytest.importorskip("fcntl")
helper = pytest.importorskip("dns_resource")
pytestmark = pytest.mark.skipif(
    getattr(os, "geteuid", lambda: -1)() != 0,
    reason="DNS helper fixture requires root-owned metadata",
)


def configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, symlink: bool = False) -> Path:
    base = tmp_path / "run" / "dns"
    target = tmp_path / "real-resolv.conf"
    target.write_bytes(b"nameserver 10.0.0.53\noptions edns0\n")
    resolver = tmp_path / "resolv.conf"
    if symlink:
        resolver.symlink_to(target.name)
    else:
        resolver.write_bytes(target.read_bytes())
    monkeypatch.setattr(helper, "BASE", base)
    monkeypatch.setattr(helper, "LEASE", base / "lease.json")
    monkeypatch.setattr(helper, "LOCK", base / "control.lock")
    monkeypatch.setattr(helper, "RUNS", base / "runs")
    monkeypatch.setattr(helper, "RESOLV_CONF", resolver)
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    return target


class FakeProcess:
    pid = 4242

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.terminated = False
        self.waited = False

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.waited = True
        assert self.returncode is not None
        return self.returncode


def fake_popen(*args: Any, **kwargs: Any) -> FakeProcess:
    return FakeProcess()


def identities(monkeypatch: pytest.MonkeyPatch) -> None:
    real_pid = os.getpid()
    monkeypatch.setattr(
        helper,
        "process_identity",
        lambda pid: {"pid": pid, "starttime": 9 if pid == real_pid else 10},
    )
    monkeypatch.setattr(helper.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(helper, "_wait_line", lambda *args, **kwargs: None)
    monkeypatch.setattr(helper, "_send_control", lambda *args, **kwargs: None)


@pytest.mark.parametrize("symlink", [False, True])
def test_start_and_cleanup_restore_exact_entry_without_changing_symlink_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, symlink: bool
) -> None:
    target = configure(tmp_path, monkeypatch, symlink=symlink)
    identities(monkeypatch)
    original_target = target.read_bytes()
    token = "a" * 32
    record = helper.start(token, "203.0.113.254", 30)
    assert record["phase"] == "active"
    assert helper.RESOLV_CONF.read_bytes() == b"nameserver 203.0.113.254\n"
    assert target.read_bytes() == original_target
    cleaned = helper.cleanup(token)
    assert cleaned["cleanup_complete"] is True
    assert helper.RESOLV_CONF.is_symlink() is symlink
    assert helper.RESOLV_CONF.read_bytes() == original_target
    if symlink:
        assert os.readlink(helper.RESOLV_CONF) == target.name
    assert not helper.LEASE.exists()


def test_foreign_resolver_change_is_refused_and_remains_actionable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    identities(monkeypatch)
    token = "b" * 32
    helper.start(token, "203.0.113.254", 30)
    helper.RESOLV_CONF.write_bytes(b"nameserver 198.51.100.9\n")
    with pytest.raises(RuntimeError, match="foreign resolver change"):
        helper.cleanup(token)
    assert helper.LEASE.exists()
    assert helper.load(helper.run_path(token))["cleanup_complete"] is False


def test_spawn_failure_occurs_before_global_lease_and_does_not_mutate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    original = helper.RESOLV_CONF.read_bytes()
    monkeypatch.setattr(
        helper,
        "process_identity",
        lambda pid: {"pid": pid, "starttime": 9},
    )
    monkeypatch.setattr(
        helper.subprocess,
        "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("spawn failed")),
    )
    with pytest.raises(OSError, match="spawn failed"):
        helper.start("c" * 32, "203.0.113.254", 30)
    assert not helper.LEASE.exists()
    assert helper.RESOLV_CONF.read_bytes() == original
    assert helper.load(helper.run_path("c" * 32))["cleanup_complete"] is True


def test_authority_handshake_failure_after_publication_rolls_back_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    original = helper.RESOLV_CONF.read_bytes()
    identities(monkeypatch)
    calls = [0]

    def wait(*args: Any, **kwargs: Any) -> None:
        calls[0] += 1
        if calls[0] == 2:
            raise TimeoutError("authority failed")

    monkeypatch.setattr(helper, "_wait_line", wait)
    monkeypatch.setattr(helper, "_terminate_watchdog", lambda *args: None)
    with pytest.raises(TimeoutError, match="authority failed"):
        helper.start("d" * 32, "203.0.113.254", 30)
    assert not helper.LEASE.exists()
    assert helper.RESOLV_CONF.read_bytes() == original
    record = helper.load(helper.run_path("d" * 32))
    assert record["cleanup_complete"] is True


def test_status_and_cleanup_refuse_foreign_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    identities(monkeypatch)
    token = "e" * 32
    helper.start(token, "203.0.113.254", 30)
    helper.save(helper.LEASE, {"complete": True, "token": "f" * 32})
    with pytest.raises(RuntimeError, match="foreign DNS lease"):
        helper.cleanup(token)
    assert helper.status(token)["phase"] == "active"


def test_parent_persists_identity_between_ready_and_armed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    identities(monkeypatch)
    waits: list[bytes] = []
    controls: list[bytes] = []
    monkeypatch.setattr(helper, "_wait_line", lambda _fd, value, _deadline: waits.append(value))
    monkeypatch.setattr(helper, "_send_control", lambda _fd, value: controls.append(value))
    helper.start("1" * 32, "203.0.113.254", 30)
    assert waits == [b"READY\n", b"ARMED\n", b"AUTHORIZED\n"]
    assert controls[:2] == [b"IDENTITY\n", b"AUTHORITY\n"]


def test_parent_fast_schedule_keeps_prepared_until_child_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    identities(monkeypatch)
    token = "7" * 32
    phases: list[str] = []

    def wait(_fd: int, value: bytes, _deadline: float) -> None:
        phases.append(helper.load(helper.run_path(token))["phase"])
        assert (
            phases[-1]
            == {
                b"READY\n": "prepared",
                b"ARMED\n": "watchdog_identity_pending",
                b"AUTHORIZED\n": "lease_publication_pending",
            }[value]
        )

    monkeypatch.setattr(helper, "_wait_line", wait)
    helper.start(token, "203.0.113.254", 30)
    assert phases == ["prepared", "watchdog_identity_pending", "lease_publication_pending"]


@pytest.mark.parametrize("symlink", [False, True])
def test_partial_write_is_authorized_only_by_durable_intent_and_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, symlink: bool
) -> None:
    target = configure(tmp_path, monkeypatch, symlink=symlink)
    identities(monkeypatch)
    original = helper.RESOLV_CONF.read_bytes()
    target_original = target.read_bytes()
    actual_write = helper._write_regular
    interrupted = False

    def partial(content: bytes, metadata: dict[str, Any]) -> None:
        nonlocal interrupted
        if interrupted:
            actual_write(content, metadata)
            return
        interrupted = True
        if helper.RESOLV_CONF.is_symlink():
            helper.RESOLV_CONF.unlink()
            fd = os.open(
                helper.RESOLV_CONF,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        else:
            fd = os.open(helper.RESOLV_CONF, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        try:
            assert os.write(fd, content[:7]) == 7
            os.fsync(fd)
        finally:
            os.close(fd)
        raise OSError("injected partial write cut")

    monkeypatch.setattr(helper, "_write_regular", partial)
    with pytest.raises(OSError, match="partial write cut"):
        helper.start("2" * 32, "203.0.113.254", 30)
    record = helper.load(helper.run_path("2" * 32))
    assert record["cleanup_complete"] is True
    assert record["cleanup_reason"] == "start_failed"
    assert not helper.LEASE.exists()
    assert helper.RESOLV_CONF.read_bytes() == original
    assert helper.RESOLV_CONF.is_symlink() is symlink
    assert target.read_bytes() == target_original


def test_foreign_lease_is_rejected_before_any_resolver_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    identities(monkeypatch)
    token = "3" * 32
    helper.start(token, "203.0.113.254", 30)
    injected = helper.RESOLV_CONF.read_bytes()
    helper.save(helper.LEASE, {"complete": True, "token": "4" * 32})
    monkeypatch.setattr(
        helper,
        "_restore_entry",
        lambda _value: pytest.fail("foreign lease must be refused before resolver mutation"),
    )
    with pytest.raises(RuntimeError, match="foreign DNS lease"):
        helper.cleanup(token)
    assert helper.RESOLV_CONF.read_bytes() == injected


def test_same_bytes_at_foreign_regular_identity_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    identities(monkeypatch)
    token = "5" * 32
    helper.start(token, "203.0.113.254", 30)
    injected = helper.RESOLV_CONF.read_bytes()
    original_inode = helper.RESOLV_CONF.stat().st_ino
    replacement = helper.RESOLV_CONF.with_suffix(".replacement")
    replacement.write_bytes(injected)
    os.replace(replacement, helper.RESOLV_CONF)
    assert helper.RESOLV_CONF.stat().st_ino != original_inode
    with pytest.raises(RuntimeError, match="foreign resolver change"):
        helper.cleanup(token)
    assert helper.RESOLV_CONF.read_bytes() == injected


def test_actual_spawn_handle_is_terminated_and_reaped(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess()
    identity = {"pid": process.pid, "starttime": 10, "argv_sha256": "a" * 64}
    monkeypatch.setattr(helper, "process_identity", lambda _pid: identity)
    helper._terminate_watchdog({"watchdog": identity}, process)
    assert process.terminated is True
    assert process.waited is True


def test_spawn_handle_is_reaped_when_identity_read_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    process = FakeProcess()
    parent_pid = os.getpid()
    monkeypatch.setattr(helper.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(helper, "_wait_line", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        helper,
        "process_identity",
        lambda pid: {"pid": pid, "starttime": 9} if pid == parent_pid else None,
    )
    with pytest.raises(RuntimeError, match="watchdog identity unavailable"):
        helper.start("8" * 32, "203.0.113.254", 30)
    assert process.terminated is True
    assert process.waited is True
    record = helper.load(helper.run_path("8" * 32))
    assert record["start_error"].endswith("watchdog identity unavailable")


def test_symlink_unlink_before_create_is_an_authorized_recoverable_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = configure(tmp_path, monkeypatch, symlink=True)
    identities(monkeypatch)
    original = target.read_bytes()
    actual_write = helper._write_regular
    interrupted = False

    def unlink_then_fail(content: bytes, metadata: dict[str, Any]) -> None:
        nonlocal interrupted
        if interrupted:
            actual_write(content, metadata)
            return
        interrupted = True
        helper.RESOLV_CONF.unlink()
        raise OSError("injected unlink/create cut")

    monkeypatch.setattr(helper, "_write_regular", unlink_then_fail)
    with pytest.raises(OSError, match="unlink/create cut"):
        helper.start("9" * 32, "203.0.113.254", 30)
    record = helper.load(helper.run_path("9" * 32))
    assert record["cleanup_complete"] is True
    assert helper.RESOLV_CONF.is_symlink()
    assert os.readlink(helper.RESOLV_CONF) == target.name
    assert helper.RESOLV_CONF.read_bytes() == original


def test_symlink_replacement_is_root_owned_readable_and_not_unprivileged_writable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = configure(tmp_path, monkeypatch, symlink=True)
    identities(monkeypatch)
    target_before = helper._stat_identity(target.stat()) | {
        "sha256": helper.hashlib.sha256(target.read_bytes()).hexdigest()
    }
    token = "a1" * 16
    helper.start(token, "203.0.113.254", 30)
    active = helper.RESOLV_CONF.stat(follow_symlinks=False)
    assert (active.st_uid, active.st_gid, active.st_mode & 0o777) == (0, 0, 0o644)
    assert active.st_mode & 0o022 == 0
    assert (
        helper._stat_identity(target.stat())
        | {"sha256": helper.hashlib.sha256(target.read_bytes()).hexdigest()}
        == target_before
    )
    helper.cleanup(token)


def test_symlink_target_snapshot_is_bounded_and_rejects_unsupported_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = configure(tmp_path, monkeypatch, symlink=True)
    target.write_bytes(b"x" * (helper.MAX_FILE + 1))
    with pytest.raises(ValueError, match="exceeds 32KiB"):
        helper.snapshot()
    target.unlink()
    os.mkfifo(target)
    with pytest.raises(ValueError, match="trusted regular file"):
        helper.snapshot()


def test_symlink_target_race_is_rejected_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = configure(tmp_path, monkeypatch, symlink=True)
    original_fstat = helper.os.fstat
    calls = 0

    def raced(fd: int) -> os.stat_result:
        nonlocal calls
        calls += 1
        if calls == 2:
            target.write_bytes(target.read_bytes() + b"# changed\n")
        return cast(os.stat_result, original_fstat(fd))

    monkeypatch.setattr(helper.os, "fstat", raced)
    with pytest.raises(RuntimeError, match="target changed during snapshot"):
        helper.snapshot()


def test_stale_watchdog_update_cannot_resurrect_completed_parent_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    helper.safe_base()
    token = "0" * 32
    path = helper.run_path(token)
    completed = {
        "token": token,
        "phase": "cleaned",
        "cleanup_complete": True,
        "cleanup_reason": "start_failed",
    }
    helper.save(path, completed)
    assert (
        helper._watchdog_update(
            path,
            {"prepared", "start_failed"},
            phase="watchdog_failed",
            cleanup_complete=False,
        )
        is None
    )
    assert helper.load(path) == completed


def test_original_start_error_survives_cleanup_failure_and_retains_recovery_actor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    identities(monkeypatch)

    def primary_failure(_content: bytes, _metadata: dict[str, Any]) -> None:
        raise OSError("primary write failure")

    monkeypatch.setattr(helper, "_write_regular", primary_failure)
    monkeypatch.setattr(
        helper,
        "cleanup_locked",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("secondary cleanup failure")),
    )
    token = "b1" * 16
    with pytest.raises(OSError, match="primary write failure"):
        helper.start(token, "203.0.113.254", 30)
    record = helper.load(helper.run_path(token))
    assert record["start_error"].endswith("primary write failure")
    assert record["cleanup_error"].endswith("secondary cleanup failure")
    assert record["watchdog_retained_for_recovery"] is True
    assert record["secondary_errors"][0].endswith("secondary cleanup failure")


def test_watchdog_may_start_on_prepared_record_then_arm_after_identity_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    helper.safe_base()
    token = "6" * 32
    parent = helper.process_identity(os.getpid())
    assert parent is not None
    record = {
        "version": 1,
        "token": token,
        "phase": "prepared",
        "cleanup_complete": False,
        "deadline_monotonic": time.monotonic() - 1,
        "parent": parent,
        "original": helper.snapshot(),
        "intent_sha256": "b" * 64,
    }
    helper.save(helper.run_path(token), record)
    ready_read, ready_write = os.pipe()
    parent_socket, child_socket = socket.socketpair()
    parent_control, child_control = parent_socket.detach(), child_socket.detach()
    result: list[int] = []
    thread = threading.Thread(
        target=lambda: result.append(
            helper._watchdog(token, os.getpid(), ready_write, child_control)
        )
    )
    thread.start()
    helper._wait_line(ready_read, b"READY\n", time.monotonic() + 2)
    record.update(phase="watchdog_identity_pending", watchdog=parent)
    helper.save(helper.run_path(token), record)
    helper._send_control(parent_control, b"IDENTITY\n")
    helper._wait_line(ready_read, b"ARMED\n", time.monotonic() + 2)
    thread.join(timeout=3)
    os.close(ready_read)
    os.close(parent_control)
    assert not thread.is_alive()
    assert result == [0]
    final = helper.load(helper.run_path(token))
    assert final["phase"] == "abandoned_prelease"
    assert final["cleanup_complete"] is True


def test_ready_timeout_reaps_known_process_without_lease_or_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    original = helper.RESOLV_CONF.read_bytes()
    process = FakeProcess()
    parent_pid = os.getpid()
    monkeypatch.setattr(helper.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        helper,
        "process_identity",
        lambda pid: {"pid": pid, "starttime": 9 if pid == parent_pid else 10},
    )
    monkeypatch.setattr(
        helper,
        "_wait_line",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("READY timeout")),
    )
    token = "c1" * 16
    with pytest.raises(TimeoutError, match="READY timeout"):
        helper.start(token, "203.0.113.254", 30)
    record = helper.load(helper.run_path(token))
    assert record["start_error"].endswith("READY timeout")
    assert record["cleanup_complete"] is True
    assert process.terminated and process.waited
    assert not helper.LEASE.exists()
    assert helper.RESOLV_CONF.read_bytes() == original


def test_initial_metadata_storage_failure_prevents_spawn_and_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    original = helper.RESOLV_CONF.read_bytes()
    helper.safe_base()
    spawned = False

    def popen(*args: Any, **kwargs: Any) -> FakeProcess:
        nonlocal spawned
        spawned = True
        return FakeProcess()

    monkeypatch.setattr(helper.subprocess, "Popen", popen)
    monkeypatch.setattr(
        helper, "save", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("storage full"))
    )
    token = "c2" * 16
    with pytest.raises(OSError, match="storage full"):
        helper.start(token, "203.0.113.254", 30)
    assert not spawned
    assert not helper.run_path(token).exists()
    assert not helper.LEASE.exists()
    assert helper.RESOLV_CONF.read_bytes() == original


def test_identity_metadata_storage_failure_reaps_and_records_original_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    original = helper.RESOLV_CONF.read_bytes()
    process = FakeProcess()
    parent_pid = os.getpid()
    monkeypatch.setattr(helper.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(helper, "_wait_line", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        helper,
        "process_identity",
        lambda pid: {"pid": pid, "starttime": 9 if pid == parent_pid else 10},
    )
    actual_save = helper.save
    failed = False

    def save(path: Path, value: dict[str, Any]) -> None:
        nonlocal failed
        if value.get("phase") == "watchdog_identity_pending" and not failed:
            failed = True
            raise OSError("identity metadata storage failed")
        actual_save(path, value)

    monkeypatch.setattr(helper, "save", save)
    token = "c3" * 16
    with pytest.raises(OSError, match="identity metadata storage failed"):
        helper.start(token, "203.0.113.254", 30)
    record = helper.load(helper.run_path(token))
    assert record["start_error"].endswith("identity metadata storage failed")
    assert record["cleanup_complete"] is True
    assert process.terminated and process.waited
    assert not helper.LEASE.exists()
    assert helper.RESOLV_CONF.read_bytes() == original


def test_lease_link_storage_failure_rolls_back_candidate_and_reaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    original = helper.RESOLV_CONF.read_bytes()
    process = FakeProcess()
    identities(monkeypatch)
    monkeypatch.setattr(helper.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        helper.os,
        "link",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("lease link storage failed")),
    )
    token = "c4" * 16
    with pytest.raises(OSError, match="lease link storage failed"):
        helper.start(token, "203.0.113.254", 30)
    record = helper.load(helper.run_path(token))
    assert record["start_error"].endswith("lease link storage failed")
    assert record["cleanup_complete"] is True
    assert process.terminated and process.waited
    assert not helper.LEASE.exists()
    assert not list(helper.BASE.glob("lease.*.prepared"))
    assert helper.RESOLV_CONF.read_bytes() == original


def test_restoration_failure_remains_active_and_actionable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch)
    identities(monkeypatch)
    token = "c5" * 16
    helper.start(token, "203.0.113.254", 30)
    injected = helper.RESOLV_CONF.read_bytes()
    monkeypatch.setattr(
        helper,
        "_restore_entry",
        lambda _value: (_ for _ in ()).throw(OSError("restore storage failed")),
    )
    with pytest.raises(OSError, match="restore storage failed"):
        helper.cleanup(token)
    record = helper.load(helper.run_path(token))
    assert record["phase"] == "active" and record["cleanup_complete"] is False
    assert helper.LEASE.exists()
    assert helper.RESOLV_CONF.read_bytes() == injected
