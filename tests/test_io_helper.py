from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

fcntl = pytest.importorskip("fcntl")
import io_resource as helper  # noqa: E402


def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state, target, reference = (
        tmp_path / "state",
        tmp_path / "target",
        tmp_path / "reference",
    )
    state.mkdir(mode=0o700)
    target.mkdir(mode=0o755)
    reference.mkdir(mode=0o755)
    monkeypatch.setattr(helper, "STATE", state)
    monkeypatch.setattr(helper, "TARGET", target)
    monkeypatch.setattr(helper, "REFERENCE_TARGET", reference)
    monkeypatch.setattr(helper, "LOCK", state / "lock")
    monkeypatch.setattr(helper, "LEASE", state / "lease.json")
    monkeypatch.setattr(helper, "LEASE_PENDING", state / "lease.pending")


def test_atomic_retries_partial_writes_and_fsyncs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "record.json"
    real_write = os.write

    def partial(descriptor: int, value: Any) -> int:
        return real_write(descriptor, bytes(value[: max(1, len(value) // 2)]))

    monkeypatch.setattr(os, "write", partial)
    helper.atomic(path, {"token": "a" * 32})
    assert '"token"' in path.read_text()
    assert not path.with_name("record.json.new").exists()


def test_atomic_zero_write_retains_original_and_removes_owned_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "record.json"
    path.write_text("original")
    monkeypatch.setattr(os, "write", lambda _fd, _value: 0)
    with pytest.raises(OSError, match="short"):
        helper.atomic(path, {"replacement": True})
    assert path.read_text() == "original"
    assert not path.with_name("record.json.new").exists()


def test_unmount_owned_revalidates_identity_while_retrying_busy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validations: list[Path] = []
    states = iter(("owned", "owned", "absent"))
    attempts = iter(
        (
            subprocess.CompletedProcess([], 1, "", "target is busy"),
            subprocess.CompletedProcess([], 0, "", ""),
        )
    )

    def state(_record: dict[str, Any], path: Path) -> str:
        validations.append(path)
        return next(states)

    monkeypatch.setattr(helper, "mount_state", state)
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: next(attempts))
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    helper.unmount_owned({"token": "a" * 32, "boot_id": "boot"}, helper.TARGET)
    assert validations == [helper.TARGET, helper.TARGET, helper.TARGET]


def test_safe_roots_refuses_foreign_mode_without_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    os.chmod(helper.TARGET, 0o777)
    with pytest.raises(ValueError, match="unsafe owned directory"):
        helper.safe_roots()
    assert helper.TARGET.stat().st_mode & 0o777 == 0o777


def test_owned_parent_rejects_group_or_world_writable_directory(tmp_path: Path) -> None:
    parent = tmp_path / "unsafe-parent"
    parent.mkdir(mode=0o777)
    os.chmod(parent, 0o777)
    with pytest.raises(ValueError, match="unsafe fixed parent"):
        helper.validate_owned_parent(parent)


def test_repeat_destroy_returns_terminal_record_without_touching_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal = {"token": "a" * 32, "phase": "destroyed", "cleanup_complete": True}
    monkeypatch.setattr(helper, "load", lambda _token: terminal)
    monkeypatch.setattr(
        helper,
        "resource_identity",
        lambda _record: (_ for _ in ()).throw(AssertionError("must not inspect deleted resource")),
    )
    assert helper.destroy("a" * 32) is terminal


def test_start_watchdog_death_runs_immediate_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    token = "b" * 32
    record = {"token": token, "phase": "prepared"}
    monkeypatch.setattr(helper, "load", lambda _token: dict(record))
    monkeypatch.setattr(helper, "resource_identity", lambda _record: None)
    monkeypatch.setattr(helper, "process_start", lambda _pid: "10")
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(helper, "atomic", lambda _path, value: record.update(value))
    rolled_back: list[str] = []

    def rollback(
        _token: str,
        original_error: str | None = None,
        record_override: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        assert record_override is not None
        assert record_override is not record
        assert record_override["token"] == token
        assert record_override["phase"] == "rollback_intent"
        assert record_override["controller_pid"] == 77
        assert record_override["controller_start"] == "parent-start"
        assert record_override["controller_source"] == "caller_parent"
        rolled_back.append(str(original_error))
        return record

    monkeypatch.setattr(helper, "cleanup_workload", rollback)

    class Dead:
        pid = 12345

        def poll(self) -> int:
            return 1

        def wait(self, timeout: int) -> int:
            return 1

    monkeypatch.setattr(helper, "launch", lambda *_args: Dead())
    with pytest.raises(RuntimeError, match="before readiness"):
        helper.start(token, 5, (77, "parent-start"))
    assert rolled_back and "watchdog exited" in rolled_back[0]


def test_start_refuses_foreign_activation_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    token = "c" * 32
    marker = helper.STATE / f"worker-{token}.activate"
    marker.write_bytes(b"foreign\n")
    original_inode = marker.stat().st_ino
    monkeypatch.setattr(helper, "load", lambda _token: {"token": token, "phase": "prepared"})
    monkeypatch.setattr(helper, "resource_identity", lambda _record: None)
    monkeypatch.setattr(
        helper,
        "launch",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must not launch")),
    )
    with pytest.raises(ValueError, match="foreign or stale marker refused"):
        helper.start(token, 5)
    assert marker.read_bytes() == b"foreign\n"
    assert marker.stat().st_ino == original_inode


def test_start_launch_failure_retains_original_and_runs_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    token = "d" * 32
    record: dict[str, Any] = {"token": token, "phase": "prepared"}
    monkeypatch.setattr(helper, "load", lambda _token: dict(record))
    monkeypatch.setattr(helper, "resource_identity", lambda _record: None)
    monkeypatch.setattr(helper, "process_start", lambda _pid: "10")
    monkeypatch.setattr(helper, "atomic", lambda _path, value: record.update(value))
    monkeypatch.setattr(helper, "launch", lambda *_args: (_ for _ in ()).throw(OSError("launch")))
    captured: list[tuple[str, dict[str, Any] | None]] = []

    def cleanup(
        _token: str,
        *,
        original_error: str | None = None,
        record_override: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        captured.append((str(original_error), record_override))
        return record

    monkeypatch.setattr(helper, "cleanup_workload", cleanup)
    with pytest.raises(OSError, match="launch"):
        helper.start(token, 5)
    assert captured and "launch" in captured[0][0]
    assert captured[0][1] is not None
    assert captured[0][1]["phase"] == "rollback_intent"


def test_after_child_activation_write_failure_stops_children_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    token = "e" * 32
    record: dict[str, Any] = {"token": token, "phase": "prepared", "dm_uuid": "dm"}
    monkeypatch.setattr(helper, "load", lambda _token: dict(record))
    monkeypatch.setattr(helper, "resource_identity", lambda _record: None)
    monkeypatch.setattr(helper, "process_start", lambda _pid: "10")
    monkeypatch.setattr(helper, "process_owned", lambda *_args: True)
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", lambda _pid, _signal: None)
    monkeypatch.setattr(helper, "owned_regular", lambda path, **_kwargs: path.stat())

    class Live:
        def __init__(self, pid: int) -> None:
            self.pid = pid

        def poll(self) -> None:
            return None

        def wait(self, timeout: int) -> int:
            return 0

    def launch(action: str, _token: str, _duration: int) -> Live:
        pid = 120 if action == "watchdog" else 121
        if action == "watchdog":
            ready = helper.STATE / f"watchdog-{token}.ready"
            ready.write_text(json.dumps({"token": token, "pid": pid, "start": "10"}))
            os.chmod(ready, 0o600)
        return Live(pid)

    def atomic(path: Path, value: dict[str, Any]) -> None:
        if path == helper.token_path(token):
            record.update(value)
            if value.get("phase") == "authority_registered":
                active = helper.STATE / f"watchdog-{token}.active"
                active.write_text(
                    json.dumps({"token": token, "pid": 120, "start": "10", "activated": True})
                )
                os.chmod(active, 0o600)
            return
        if path.name == f"worker-{token}.activate":
            raise OSError("injected activation persistence failure")
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)

    rolled_back: list[dict[str, Any]] = []

    def cleanup(
        _token: str,
        *,
        original_error: str | None = None,
        record_override: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        assert original_error and "injected activation" in original_error
        assert record_override is not None
        rolled_back.append(record_override)
        return record_override

    monkeypatch.setattr(helper, "launch", launch)
    monkeypatch.setattr(helper, "atomic", atomic)
    monkeypatch.setattr(helper, "cleanup_workload", cleanup)
    with pytest.raises(OSError, match="injected activation"):
        helper.start(token, 5)
    assert rolled_back and rolled_back[0]["worker_pid"] == 121
    assert rolled_back[0]["watchdog_pid"] == 120


def test_cleanup_refuses_replaced_marker_and_preserves_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    token = "f" * 32
    marker = helper.STATE / f"worker-{token}.activate"
    marker.write_text(json.dumps({"token": token, "pid": 5, "start": "6"}))
    os.chmod(marker, 0o600)
    inode = marker.stat().st_ino
    record = {
        "token": token,
        "phase": "stopped",
        "worker_activation_inode": inode + 1,
    }
    monkeypatch.setattr(helper, "load", lambda _token: dict(record))
    monkeypatch.setattr(helper, "resource_identity", lambda _record: None)
    monkeypatch.setattr(helper, "process_owned", lambda *_args: False)
    with pytest.raises(ValueError, match="marker identity changed"):
        helper.cleanup_workload(token)
    assert marker.stat().st_ino == inode
    assert json.loads(marker.read_text())["token"] == token


def resource_record(token: str = "9" * 32) -> dict[str, Any]:
    return {
        "token": token,
        "phase": "prepare_failed",
        "boot_id": "boot",
        "mount_namespace": "mnt:[1]",
        "image": str(helper.STATE / f"image-{token}.img"),
        "image_size": helper.IMAGE_BYTES,
        "image_create_intended": True,
        "reference_image": str(helper.STATE / f"reference-image-{token}.img"),
        "reference_image_size": helper.REFERENCE_IMAGE_BYTES,
        "reference_image_create_intended": True,
        "loop": "/dev/loop10",
        "loop_attach_intended": True,
        "reference_loop": "/dev/loop11",
        "reference_loop_attach_intended": True,
        "dm_name": f"fd11-{token[:12]}",
        "dm_uuid": f"FLEETDOCTOR-IO-{token}",
        "dm_table": "0 8 delay 7:10 0 40",
        "dm_create_intended": True,
        "mount_intended": True,
        "mount_source": f"/dev/mapper/fd11-{token[:12]}",
        "mount_id": "100",
        "reference_mount_intended": True,
        "reference_mount_source": "/dev/loop11",
        "reference_mount_id": "101",
        "original_error": "OSError('setup failed')",
        "cleanup_complete": False,
    }


def test_prepare_rollback_refuses_both_replaced_mounts_and_blocks_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    seen: list[Path] = []

    def mount_refusal(_record: dict[str, Any], path: Path, **_kwargs: Any) -> str:
        seen.append(path)
        raise ValueError(f"replacement mount: {path}")

    monkeypatch.setattr(helper, "release_mount", mount_refusal)
    monkeypatch.setattr(
        helper,
        "release_dm",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("dm must be blocked")),
    )
    monkeypatch.setattr(
        helper,
        "release_loop",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("loops must be blocked")),
    )
    monkeypatch.setattr(
        helper,
        "release_image",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("images must be blocked")),
    )
    saved: list[dict[str, Any]] = []
    monkeypatch.setattr(helper, "atomic", lambda _path, value: saved.append(dict(value)))

    result = helper.release_resource_stages(record, final_phase="prepare_failed")

    assert seen == [helper.REFERENCE_TARGET, helper.TARGET]
    assert result["original_error"] == "OSError('setup failed')"
    assert result["cleanup_complete"] is False
    assert result["release_stages"] == {
        "reference_mount": "refused",
        "mount": "refused",
        "dm": "blocked",
        "reference_loop": "blocked",
        "loop": "blocked",
        "reference_image": "blocked",
        "image": "blocked",
    }
    assert any("replacement mount" in error for error in result["cleanup_error_history"])
    assert saved[-1]["cleanup_complete"] is False


def test_prepare_rollback_refuses_replaced_dm_and_preserves_dependent_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    monkeypatch.setattr(helper, "release_mount", lambda *_args, **_kwargs: "absent")
    monkeypatch.setattr(
        helper,
        "release_dm",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("device-mapper UUID/table changed")
        ),
    )
    loop_calls: list[str] = []

    def loops(_record: dict[str, Any], key: str, **_kwargs: Any) -> str:
        loop_calls.append(key)
        return "absent"

    monkeypatch.setattr(helper, "release_loop", loops)
    monkeypatch.setattr(helper, "release_image", lambda *_args, **_kwargs: "absent")
    monkeypatch.setattr(helper, "atomic", lambda *_args: None)

    result = helper.release_resource_stages(record, final_phase="prepare_failed")

    assert result["release_stages"]["dm"] == "refused"
    assert loop_calls == ["reference_loop"]
    assert result["release_stages"]["loop"] == "blocked"
    assert result["release_stages"]["image"] == "blocked"
    assert result["release_stages"]["reference_image"] == "absent"


def test_prepare_rollback_refuses_both_replaced_loops_and_blocks_images(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    monkeypatch.setattr(helper, "release_mount", lambda *_args, **_kwargs: "absent")
    monkeypatch.setattr(helper, "release_dm", lambda *_args, **_kwargs: "absent")
    loop_calls: list[str] = []

    def loops(_record: dict[str, Any], key: str, **_kwargs: Any) -> str:
        loop_calls.append(key)
        raise ValueError(f"{key} backing changed")

    monkeypatch.setattr(helper, "release_loop", loops)
    monkeypatch.setattr(
        helper,
        "release_image",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("images must be blocked")),
    )
    monkeypatch.setattr(helper, "atomic", lambda *_args: None)

    result = helper.release_resource_stages(record, final_phase="prepare_failed")

    assert loop_calls == ["reference_loop", "loop"]
    assert result["release_stages"]["reference_loop"] == "refused"
    assert result["release_stages"]["loop"] == "refused"
    assert result["release_stages"]["reference_image"] == "blocked"
    assert result["release_stages"]["image"] == "blocked"


def test_prepare_rollback_refuses_both_replaced_images_without_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    monkeypatch.setattr(helper, "release_mount", lambda *_args, **_kwargs: "absent")
    monkeypatch.setattr(helper, "release_dm", lambda *_args, **_kwargs: "absent")
    monkeypatch.setattr(helper, "release_loop", lambda *_args, **_kwargs: "absent")
    image_calls: list[str] = []

    def images(_record: dict[str, Any], key: str) -> str:
        image_calls.append(key)
        raise ValueError(f"{key} dev/inode/owner/size changed")

    monkeypatch.setattr(helper, "release_image", images)
    monkeypatch.setattr(helper, "atomic", lambda *_args: None)

    result = helper.release_resource_stages(record, final_phase="prepare_failed")

    assert image_calls == ["reference_image", "image"]
    assert result["release_stages"]["reference_image"] == "refused"
    assert result["release_stages"]["image"] == "refused"
    assert result["cleanup_complete"] is False


def test_partial_release_retries_after_late_record_failure_and_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    releases: list[str] = []
    monkeypatch.setattr(helper, "release_mount", lambda *_args, **_kwargs: "not_acquired")
    monkeypatch.setattr(helper, "release_dm", lambda *_args, **_kwargs: "not_acquired")
    monkeypatch.setattr(helper, "release_loop", lambda *_args, **_kwargs: "not_acquired")

    def image_release(_record: dict[str, Any], key: str) -> str:
        releases.append(key)
        return "released" if releases.count(key) == 1 else "absent"

    monkeypatch.setattr(helper, "release_image", image_release)
    failures = iter((True, False))

    def persist(_path: Path, _value: dict[str, Any]) -> None:
        if next(failures, False):
            raise OSError("late record write")

    monkeypatch.setattr(helper, "atomic", persist)
    first = helper.release_resource_stages(record, final_phase="prepare_failed")
    assert first["cleanup_complete"] is False
    assert first["original_error"] == "OSError('setup failed')"
    assert any("late record write" in error for error in first["cleanup_error_history"])

    second = helper.release_resource_stages(record, final_phase="prepare_failed")
    assert second["cleanup_complete"] is True
    assert second["release_stages"]["reference_image"] == "absent"
    assert second["release_stages"]["image"] == "absent"
    assert second["original_error"] == "OSError('setup failed')"
    assert any("late record write" in error for error in second["cleanup_error_history"])


def test_release_commands_refuse_readback_failure_before_destructive_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    mutations: list[tuple[Any, ...]] = []
    monkeypatch.setattr(helper, "boot", lambda: "boot")

    def no_mutation(*args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        mutations.append(args)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(subprocess, "run", no_mutation)
    monkeypatch.setattr(
        helper,
        "mount_state",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("mount readback failed")),
    )
    for target in (helper.REFERENCE_TARGET, helper.TARGET):
        with pytest.raises(RuntimeError, match="mount readback failed"):
            helper.release_mount(record, target)

    monkeypatch.setattr(
        helper,
        "dm_state",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("dm readback failed")),
    )
    with pytest.raises(RuntimeError, match="dm readback failed"):
        helper.release_dm(record)

    monkeypatch.setattr(
        helper,
        "loop_state",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("loop readback failed")),
    )
    for key in ("reference_loop", "loop"):
        with pytest.raises(RuntimeError, match="loop readback failed"):
            helper.release_loop(record, key)

    assert mutations == []


@pytest.mark.parametrize(
    ("reported_uuid", "reported_table", "message"),
    (
        ("foreign-uuid", "0 8 delay 7:10 0 40", "UUID changed"),
        (f"FLEETDOCTOR-IO-{'9' * 32}", "0 8 linear 7:10 0", "table changed"),
    ),
)
def test_dm_state_refuses_uuid_and_table_replacements(
    monkeypatch: pytest.MonkeyPatch,
    reported_uuid: str,
    reported_table: str,
    message: str,
) -> None:
    record = resource_record()
    mutations: list[tuple[str, ...]] = []
    monkeypatch.setattr(helper, "boot", lambda: "boot")

    def readback(args: tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[1] == "info":
            return subprocess.CompletedProcess(args, 0, reported_uuid + "\n", "")
        if args[1] == "table":
            return subprocess.CompletedProcess(args, 0, reported_table + "\n", "")
        mutations.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", readback)
    with pytest.raises(ValueError, match=message):
        helper.release_dm(record)
    assert mutations == []


@pytest.mark.parametrize(
    ("path", "snapshot"),
    (
        (helper.REFERENCE_TARGET, ("foreign-reference", "/dev/loop11")),
        (helper.REFERENCE_TARGET, ("101", "/dev/loop99")),
        (helper.TARGET, ("foreign-target", "/dev/mapper/fd11-999999999999")),
        (helper.TARGET, ("100", "/dev/mapper/foreign")),
    ),
)
def test_release_mount_refuses_replaced_mount_ids_and_sources(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    snapshot: tuple[str, str],
) -> None:
    record = resource_record()
    mutations: list[tuple[Any, ...]] = []
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(os, "readlink", lambda _path: "mnt:[1]")
    monkeypatch.setattr(helper, "_mount_snapshot", lambda _path: snapshot)

    def mutate(*args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        mutations.append(args)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(subprocess, "run", mutate)
    with pytest.raises(ValueError, match="mounted resource identity changed"):
        helper.release_mount(record, path)
    assert mutations == []


def test_release_mount_refuses_real_snapshot_readback_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = resource_record()
    mutations: list[tuple[Any, ...]] = []
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(os, "readlink", lambda _path: "mnt:[1]")
    monkeypatch.setattr(
        helper,
        "_mount_snapshot",
        lambda _path: (_ for _ in ()).throw(RuntimeError("mount inventory readback failed")),
    )

    def mutate(*args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        mutations.append(args)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(subprocess, "run", mutate)
    with pytest.raises(RuntimeError, match="mount inventory readback failed"):
        helper.release_mount(record, helper.TARGET)
    assert mutations == []


def test_release_mount_refuses_torn_same_source_mount_snapshot_without_umount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = resource_record()
    target = helper.TARGET
    source = str(record["mount_source"])
    mountinfo = iter(
        (
            f"100 1 0:1 / {target} rw - ext4 {source} rw\n",
            f"200 1 0:1 / {target} rw - ext4 {source} rw\n",
        )
    )
    commands: list[tuple[str, ...]] = []
    real_read_text = Path.read_text
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(os, "readlink", lambda _path: "mnt:[1]")

    def read_text(path: Path, *args: Any, **kwargs: Any) -> str:
        if path == Path("/proc/self/mountinfo"):
            return next(mountinfo)
        return real_read_text(path, *args, **kwargs)

    def run(args: tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        commands.append(args)
        if args[0] == "findmnt":
            payload = json.dumps({"filesystems": [{"source": source, "target": str(target)}]})
            return subprocess.CompletedProcess(args, 0, payload, "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(subprocess, "run", run)

    with pytest.raises(ValueError, match="mount inventory changed during source readback"):
        helper.release_mount(record, target)

    assert [args[0] for args in commands] == ["findmnt"]


@pytest.mark.parametrize(
    ("key", "readback"),
    (
        ("reference_loop", "/foreign/reference.img"),
        ("loop", "/foreign/image.img"),
        ("reference_loop", RuntimeError("loop readback failed")),
        ("loop", RuntimeError("loop readback failed")),
    ),
)
def test_release_loop_refuses_real_backing_replacement_and_readback_failure(
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    readback: str | RuntimeError,
) -> None:
    record = resource_record()
    mutations: list[tuple[Any, ...]] = []
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(helper, "image_state", lambda *_args: "owned")

    def read_loop(args: tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:4] == ("losetup", "--noheadings", "--output", "BACK-FILE"):
            if isinstance(readback, RuntimeError):
                return subprocess.CompletedProcess(args, 1, "", "readback failed")
            return subprocess.CompletedProcess(args, 0, readback + "\n", "")
        if args == ("losetup", "--json", "--list", "--output", "NAME,BACK-FILE"):
            inventory = json.dumps({"loopdevices": [{"name": record[key]}]})
            return subprocess.CompletedProcess(args, 0, inventory, "")
        mutations.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", read_loop)
    message = (
        "readback failed" if isinstance(readback, RuntimeError) else "backing identity changed"
    )
    with pytest.raises((RuntimeError, ValueError), match=message):
        helper.release_loop(record, key)
    assert mutations == []


def test_release_images_refuses_identity_failure_without_unlinking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    for key in ("reference_image", "image"):
        path = Path(record[key])
        path.write_bytes(b"foreign")

    monkeypatch.setattr(
        helper,
        "image_state",
        lambda _record, key: (_ for _ in ()).throw(ValueError(f"{key} identity changed")),
    )
    for key in ("reference_image", "image"):
        with pytest.raises(ValueError, match="identity changed"):
            helper.release_image(record, key)
        assert Path(record[key]).read_bytes() == b"foreign"


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned image identity fixture")
def test_release_images_refuses_real_inode_and_size_replacements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    image = Path(record["image"])
    image.write_bytes(b"owned-image")
    image_info = image.stat()
    record.update(
        image_inode=image_info.st_ino,
        image_dev=image_info.st_dev,
        image_uid=0,
        image_identity_size=image_info.st_size,
    )
    retained_original = image.with_suffix(".retained")
    image.rename(retained_original)
    image.write_bytes(b"foreign-inode")

    reference = Path(record["reference_image"])
    reference.write_bytes(b"owned-reference")
    reference_info = reference.stat()
    record.update(
        reference_image_inode=reference_info.st_ino,
        reference_image_dev=reference_info.st_dev,
        reference_image_uid=0,
        reference_image_identity_size=reference_info.st_size,
    )
    reference.write_bytes(b"foreign-size-change")

    with pytest.raises(ValueError, match="image identity changed"):
        helper.release_image(record, "image")
    with pytest.raises(ValueError, match="reference_image identity changed"):
        helper.release_image(record, "reference_image")

    assert image.read_bytes() == b"foreign-inode"
    assert reference.read_bytes() == b"foreign-size-change"


def test_release_refuses_other_boot_before_state_readback_or_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = resource_record()
    state_reads: list[str] = []
    mutations: list[tuple[Any, ...]] = []
    monkeypatch.setattr(helper, "boot", lambda: "replacement-boot")

    def mount_read(*_args: Any) -> str:
        state_reads.append("mount")
        return "owned"

    def mutate(*args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        mutations.append(args)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(helper, "mount_state", mount_read)
    monkeypatch.setattr(subprocess, "run", mutate)

    with pytest.raises(ValueError, match="another boot"):
        helper.release_mount(record, helper.TARGET)

    assert state_reads == []
    assert mutations == []


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr", "expected"),
    (
        (0, "", "", set()),
        (0, "alpha\nbeta\n", "", {"alpha", "beta"}),
    ),
)
def test_dm_inventory_uses_supported_info_command_and_accepts_successful_empty(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    stdout: str,
    stderr: str,
    expected: set[str],
) -> None:
    commands: list[tuple[str, ...]] = []

    def inventory(args: tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        commands.append(args)
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)

    monkeypatch.setattr(subprocess, "run", inventory)
    assert helper._dm_names() == expected
    assert commands == [("dmsetup", "info", "-c", "--noheadings", "-o", "name")]


def test_dm_inventory_readback_failure_is_not_treated_as_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **_kwargs: subprocess.CompletedProcess(args, 1, "", "permission denied"),
    )
    with pytest.raises(RuntimeError, match="inventory failed.*permission denied"):
        helper._dm_names()


def test_release_dm_refuses_uuid_readback_failure_when_inventory_still_contains_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = resource_record()
    mutations: list[tuple[str, ...]] = []
    monkeypatch.setattr(helper, "boot", lambda: "boot")

    def readback(args: tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[-2:] == ("-o", "name"):
            return subprocess.CompletedProcess(args, 0, record["dm_name"] + "\n", "")
        if args[1] == "info":
            return subprocess.CompletedProcess(args, 1, "", "transient readback failure")
        mutations.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", readback)
    with pytest.raises(RuntimeError, match="UUID readback failed.*transient"):
        helper.release_dm(record)
    assert mutations == []


def test_already_removed_release_is_repeatable_and_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    calls: list[str] = []

    def absent_mount(_record: dict[str, Any], path: Path, **_kwargs: Any) -> str:
        calls.append(f"mount:{path}")
        return "absent"

    def absent_dm(*_args: Any, **_kwargs: Any) -> str:
        calls.append("dm")
        return "absent"

    def absent_loop(_record: dict[str, Any], key: str, **_kwargs: Any) -> str:
        calls.append(key)
        return "absent"

    def absent_image(_record: dict[str, Any], key: str) -> str:
        calls.append(key)
        return "absent"

    monkeypatch.setattr(helper, "release_mount", absent_mount)
    monkeypatch.setattr(helper, "release_dm", absent_dm)
    monkeypatch.setattr(helper, "release_loop", absent_loop)
    monkeypatch.setattr(helper, "release_image", absent_image)
    monkeypatch.setattr(helper, "atomic", lambda *_args: None)

    first = helper.release_resource_stages(record, final_phase="destroyed")
    first_calls = list(calls)
    calls.clear()
    second = helper.release_resource_stages(record, final_phase="destroyed")

    assert first["cleanup_complete"] is True
    assert second["cleanup_complete"] is True
    assert second["phase"] == "destroyed"
    assert calls == first_calls
    assert set(second["release_stages"].values()) == {"absent"}


def test_prepare_revalidates_every_acquired_layer_before_destructive_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    token = "8" * 32
    events: list[str] = []
    loop_values = iter(("/dev/loop10", "/dev/loop11"))
    real_open = os.open
    real_fallocate = os.posix_fallocate
    real_readlink = os.readlink

    monkeypatch.setattr(helper, "IMAGE_BYTES", 4096)
    monkeypatch.setattr(helper, "REFERENCE_IMAGE_BYTES", 4096)
    monkeypatch.setattr(helper, "FILE_BYTES", 4096)
    monkeypatch.setattr(helper, "WORKERS", 1)
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(
        os,
        "readlink",
        lambda path: "mnt:[1]" if str(path) == "/proc/self/ns/mnt" else real_readlink(path),
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "not mounted"),
    )

    def image_state(_record: dict[str, Any], key: str) -> str:
        events.append(f"image:{key}")
        return "owned"

    def loop_state(_record: dict[str, Any], key: str) -> str:
        events.append(f"loop:{key}")
        return "owned"

    def dm_state(_record: dict[str, Any]) -> str:
        events.append("dm")
        return "owned"

    def mount_state(_record: dict[str, Any], path: Path) -> str:
        events.append(f"mount-state:{path.name}")
        return "owned"

    def command(*args: str, **_kwargs: Any) -> str:
        if args[0] == "losetup":
            return next(loop_values)
        if args[0] == "lsblk":
            return "7:10"
        events.append("command:" + ":".join(args))
        return ""

    def tracked_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if Path(path).parent == helper.TARGET:
            events.append("file-open")
        return real_open(path, flags, *args, **kwargs)

    def tracked_fallocate(descriptor: int, offset: int, length: int) -> None:
        linked = Path(f"/proc/self/fd/{descriptor}")
        if linked.exists() and Path(real_readlink(linked)).parent == helper.TARGET:
            events.append("file-allocate")
        real_fallocate(descriptor, offset, length)

    monkeypatch.setattr(helper, "image_state", image_state)
    monkeypatch.setattr(helper, "loop_state", loop_state)
    monkeypatch.setattr(helper, "dm_state", dm_state)
    monkeypatch.setattr(helper, "mount_state", mount_state)
    monkeypatch.setattr(helper, "command", command)
    monkeypatch.setattr(
        helper,
        "_mount_snapshot",
        lambda path: (
            ("100", "/dev/loop11")
            if path == helper.REFERENCE_TARGET
            else ("101", f"/dev/mapper/fd11-{token[:12]}")
        ),
    )
    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "posix_fallocate", tracked_fallocate)

    result = helper.prepare(token)

    def immediately_before(event: str) -> str:
        position = events.index(event)
        return events[position - 1]

    assert result["phase"] == "prepared"
    assert immediately_before("command:mkfs.ext4:-q:-F:-m:0:/dev/loop11") == "loop:reference_loop"
    assert (
        immediately_before(f"command:mount:-o:noatime:/dev/loop11:{helper.REFERENCE_TARGET}")
        == "loop:reference_loop"
    )
    assert (
        immediately_before(
            f"command:dmsetup:create:fd11-{token[:12]}:--uuid:FLEETDOCTOR-IO-{token}:--table:0 8 delay /dev/loop10 0 40"
        )
        == "loop:loop"
    )
    assert (
        immediately_before(f"command:mkfs.ext4:-q:-F:-m:0:/dev/mapper/fd11-{token[:12]}")
        == "loop:loop"
    )
    assert (
        immediately_before(
            f"command:mount:-o:noatime:/dev/mapper/fd11-{token[:12]}:{helper.TARGET}"
        )
        == "dm"
    )
    assert immediately_before("file-open") == f"mount-state:{helper.TARGET.name}"
    assert immediately_before("file-allocate") == f"mount-state:{helper.TARGET.name}"


def test_prepare_refuses_replaced_loop_before_format_and_retains_original_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    token = "7" * 32
    commands: list[tuple[str, ...]] = []
    loop_values = iter(("/dev/loop20", "/dev/loop21"))
    rolled_back: list[dict[str, Any]] = []
    monkeypatch.setattr(helper, "IMAGE_BYTES", 4096)
    monkeypatch.setattr(helper, "REFERENCE_IMAGE_BYTES", 4096)
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(os, "readlink", lambda _path: "mnt:[1]")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "not mounted"),
    )
    monkeypatch.setattr(helper, "image_state", lambda *_args: "owned")

    def loop_state(_record: dict[str, Any], key: str) -> str:
        if key == "reference_loop":
            raise ValueError("reference loop backing changed")
        return "owned"

    def command(*args: str, **_kwargs: Any) -> str:
        commands.append(args)
        return next(loop_values) if args[0] == "losetup" else ""

    def rollback(record: dict[str, Any], *, final_phase: str) -> dict[str, Any]:
        assert final_phase == "prepare_failed"
        rolled_back.append(dict(record))
        return record

    monkeypatch.setattr(helper, "loop_state", loop_state)
    monkeypatch.setattr(helper, "command", command)
    monkeypatch.setattr(helper, "release_resource_stages", rollback)

    with pytest.raises(ValueError, match="reference loop backing changed"):
        helper.prepare(token)

    assert not any(args[0] == "mkfs.ext4" for args in commands)
    assert rolled_back[0]["reference_loop"] == "/dev/loop21"
    assert "reference loop backing changed" in rolled_back[0]["original_error"]


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned partial image fixture")
@pytest.mark.parametrize("failure_mode", ("fallocate", "fsync", "atomic"))
def test_prepare_partial_image_failure_refreshes_identity_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    roots(tmp_path, monkeypatch)
    token = "6" * 32
    image = helper.STATE / f"image-{token}.img"
    mutations: list[tuple[Any, ...]] = []
    real_atomic = helper.atomic
    real_fallocate = os.posix_fallocate
    real_fsync = os.fsync
    real_readlink = os.readlink
    failed = False
    monkeypatch.setattr(helper, "IMAGE_BYTES", 4096)
    monkeypatch.setattr(helper, "REFERENCE_IMAGE_BYTES", 4096)
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(os, "readlink", lambda _path: "mnt:[1]")

    def run(args: list[str] | tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[0] == "mountpoint":
            return subprocess.CompletedProcess(args, 1, "", "not mounted")
        mutations.append(tuple(args))
        return subprocess.CompletedProcess(args, 0, "", "")

    def fallocate(descriptor: int, offset: int, length: int) -> None:
        if failure_mode == "fallocate":
            os.ftruncate(descriptor, length)
            raise OSError("late fallocate failure")
        real_fallocate(descriptor, offset, length)

    def fsync(descriptor: int) -> None:
        nonlocal failed
        try:
            linked = Path(real_readlink(f"/proc/self/fd/{descriptor}"))
        except OSError:
            linked = Path()
        if failure_mode == "fsync" and linked == image and not failed:
            failed = True
            raise OSError("late image fsync failure")
        real_fsync(descriptor)

    def atomic(path: Path, value: dict[str, Any]) -> None:
        nonlocal failed
        if failure_mode == "atomic" and value.get("image_identity_size") == 4096 and not failed:
            failed = True
            raise OSError("late image identity persistence failure")
        real_atomic(path, value)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(os, "posix_fallocate", fallocate)
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(helper, "atomic", atomic)

    expected = {
        "fallocate": "late fallocate failure",
        "fsync": "late image fsync failure",
        "atomic": "late image identity persistence failure",
    }[failure_mode]
    with pytest.raises(OSError, match=expected):
        helper.prepare(token)

    record = helper.load(token)
    assert record["phase"] == "prepare_failed"
    assert record["cleanup_complete"] is True
    assert record["release_stages"]["image"] == "released"
    assert expected in record["original_error"]
    assert not image.exists()
    assert mutations == []

    repeated = helper.release_resource_stages(record, final_phase="prepare_failed")
    assert repeated["cleanup_complete"] is True
    assert repeated["release_stages"]["image"] == "absent"


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned loop/image fixture")
def test_prepare_real_loop_replacement_preserves_foreign_branch_and_cleans_safe_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    token = "5" * 32
    main_image = helper.STATE / f"image-{token}.img"
    reference_image = helper.STATE / f"reference-image-{token}.img"
    detached: set[str] = set()
    destructive: list[tuple[str, ...]] = []
    command_calls: list[tuple[str, ...]] = []
    loop_values = iter(("/dev/loop30", "/dev/loop31"))
    monkeypatch.setattr(helper, "IMAGE_BYTES", 4096)
    monkeypatch.setattr(helper, "REFERENCE_IMAGE_BYTES", 4096)
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(os, "readlink", lambda _path: "mnt:[1]")

    def command(*args: str, **_kwargs: Any) -> str:
        command_calls.append(args)
        if args[0] == "losetup":
            return next(loop_values)
        raise AssertionError(args)

    def backing(loop: str) -> str | None:
        if loop in detached:
            return None
        if loop == "/dev/loop30":
            return str(main_image)
        if loop == "/dev/loop31":
            return "/foreign/replacement-reference.img"
        raise AssertionError(loop)

    def run(args: list[str] | tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[0] == "mountpoint":
            return subprocess.CompletedProcess(args, 1, "", "not mounted")
        destructive.append(tuple(args))
        if tuple(args[:2]) == ("losetup", "--detach"):
            detached.add(str(args[2]))
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(args)

    monkeypatch.setattr(helper, "command", command)
    monkeypatch.setattr(helper, "_loop_backing", backing)
    monkeypatch.setattr(subprocess, "run", run)

    with pytest.raises(ValueError, match="reference_loop backing identity changed"):
        helper.prepare(token)

    record = helper.load(token)
    assert record["phase"] == "prepare_failed"
    assert record["cleanup_complete"] is False
    assert record["release_stages"]["reference_loop"] == "refused"
    assert record["release_stages"]["reference_image"] == "blocked"
    assert record["release_stages"]["loop"] == "released"
    assert record["release_stages"]["image"] == "released"
    assert "reference_loop backing identity changed" in record["original_error"]
    assert destructive == [("losetup", "--detach", "/dev/loop30")]
    assert reference_image.exists()
    assert not main_image.exists()
    assert not any(args[0] == "mkfs.ext4" for args in command_calls)


@pytest.mark.parametrize("query_exit", (0, 1))
def test_unbound_loop_requires_successful_absence_inventory(
    monkeypatch: pytest.MonkeyPatch, query_exit: int
) -> None:
    calls: list[tuple[str, ...]] = []

    def run(args: tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if "--json" in args:
            return subprocess.CompletedProcess(args, 0, '{"loopdevices": []}', "")
        return subprocess.CompletedProcess(args, query_exit, "", "unbound")

    monkeypatch.setattr(subprocess, "run", run)
    assert helper._loop_backing("/dev/loop2") is None
    assert calls == [
        ("losetup", "--noheadings", "--output", "BACK-FILE", "/dev/loop2"),
        ("losetup", "--json", "--list", "--output", "NAME,BACK-FILE"),
    ]


@pytest.mark.parametrize("inventory_case", ("present", "failed", "malformed"))
def test_empty_loop_readback_cannot_hide_present_or_unknown_device(
    monkeypatch: pytest.MonkeyPatch, inventory_case: str
) -> None:
    calls: list[tuple[str, ...]] = []

    def run(args: tuple[str, ...], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if "--json" not in args:
            return subprocess.CompletedProcess(args, 0, "", "")
        if inventory_case == "failed":
            return subprocess.CompletedProcess(args, 1, "", "inventory permission denied")
        value = (
            '{"loopdevices": [{"name": "/dev/loop2", "back-file": "/foreign.img"}]}'
            if inventory_case == "present"
            else '{"loopdevices": [{"back-file": "/foreign.img"}]}'
        )
        return subprocess.CompletedProcess(args, 0, value, "")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(RuntimeError, match="loop (inventory|backing)"):
        helper._loop_backing("/dev/loop2")
    assert all("--detach" not in args for args in calls)


def test_destroy_resumes_partial_teardown_after_confirmed_workload_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    record.update(phase="cleanup_failed", workload_cleanup_complete=True, worker_pid=43)
    monkeypatch.setattr(helper, "load", lambda _token: record)
    monkeypatch.setattr(helper, "process_owned", lambda *_args: False)
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(helper, "mount_state", lambda *_args: "absent")
    monkeypatch.setattr(
        helper,
        "cleanup_workload",
        lambda *_args: (_ for _ in ()).throw(AssertionError("fully mounted resources are gone")),
    )
    released: list[dict[str, Any]] = []

    def release(value: dict[str, Any], *, final_phase: str) -> dict[str, Any]:
        released.append(value)
        value.update(phase=final_phase, cleanup_complete=True)
        return value

    monkeypatch.setattr(helper, "release_resource_stages", release)
    result = helper.destroy(record["token"])
    assert released == [record]
    assert result["phase"] == "destroyed"
    assert result["cleanup_complete"] is True
    assert result["original_error"] == "OSError('setup failed')"


@pytest.mark.parametrize("remaining", ("worker", "watchdog", "lease", "marker"))
def test_destroy_refuses_remaining_workload_authority_before_partial_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, remaining: str
) -> None:
    roots(tmp_path, monkeypatch)
    record = resource_record()
    record.update(
        phase="cleanup_failed", workload_cleanup_complete=True, worker_pid=43, watchdog_pid=44
    )
    monkeypatch.setattr(helper, "load", lambda _token: record)
    target_pid = {"worker": 43, "watchdog": 44}.get(remaining)
    monkeypatch.setattr(helper, "process_owned", lambda pid, *_args: pid == target_pid)
    if remaining == "lease":
        helper.LEASE.write_text("{}")
    if remaining == "marker":
        next(iter(helper.marker_paths(record["token"]).values())).write_text("{}")
    monkeypatch.setattr(
        helper,
        "release_resource_stages",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not release")),
    )
    with pytest.raises(ValueError, match="completed workload cleanup still has"):
        helper.destroy(record["token"])


def test_destroy_retains_worker_file_identity_guard_on_remaining_owned_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots(tmp_path, monkeypatch)
    monkeypatch.setattr(helper, "FILE_BYTES", 16)
    file = helper.TARGET / "worker-0.bin"
    file.write_bytes(b"a" * 16)
    original_inode = file.stat().st_ino
    replacement = helper.TARGET / "replacement.bin"
    replacement.write_bytes(b"b" * 16)
    replacement.replace(file)
    replaced_inode = file.stat().st_ino
    record = resource_record()
    record.update(
        phase="cleanup_failed",
        workload_cleanup_complete=True,
        files=[{"path": str(file), "inode": original_inode, "size": 16}],
    )
    monkeypatch.setattr(helper, "load", lambda _token: record)
    monkeypatch.setattr(helper, "process_owned", lambda *_args: False)
    monkeypatch.setattr(helper, "boot", lambda: "boot")
    monkeypatch.setattr(helper, "mount_state", lambda *_args: "owned")
    monkeypatch.setattr(
        helper,
        "release_resource_stages",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("must preserve replacement")
        ),
    )
    with pytest.raises(ValueError, match="worker file identity changed"):
        helper.destroy(record["token"])
    assert file.stat().st_ino == replaced_inode
    assert file.read_bytes() == b"b" * 16
