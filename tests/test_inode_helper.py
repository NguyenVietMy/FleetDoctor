"""Linux-only safety contracts for the bounded inode helper."""

import importlib
import json
import os
import signal
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import uuid4

import pytest


@pytest.fixture
def helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    pytest.importorskip("fcntl")
    if os.geteuid() != 0:
        pytest.skip("inode ownership safety fixtures run as root in the Linux container")
    disk = importlib.import_module("disk_resource")
    module = importlib.import_module("inode_resource")
    mount = tmp_path / "disk"
    runs = tmp_path / "inode-runs"
    mount.mkdir(mode=0o700)
    runs.mkdir(mode=0o700)
    mapping = {
        "target": str(mount),
        "source": "/dev/loop42",
        "backing_file": str(tmp_path / "owned.img"),
        "mount_id": "42",
    }
    for key, value in (
        ("BASE", tmp_path),
        ("MOUNT", mount),
        ("LEASE", tmp_path / "inode-lease.json"),
        ("DISK_LEASE", tmp_path / "disk-lease.json"),
        ("RUNS", runs),
    ):
        monkeypatch.setattr(module, key, value)
    monkeypatch.setattr(disk, "verify", lambda: {"mapping": mapping})
    monkeypatch.setattr(disk, "mapping", lambda: mapping)
    monkeypatch.setattr(disk, "boot_identity", lambda: "boot")
    monkeypatch.setattr(module, "counters", healthy_counters)
    return module


def healthy_counters() -> dict[str, int | float]:
    return {
        "inodes_total": 1024,
        "inodes_free": 1000,
        "inode_usage_percent": 2.34375,
        "total_bytes": 384 * 1024 * 1024,
        "available_bytes": 350 * 1024 * 1024,
        "block_usage_percent": 8.0,
    }


def make_active(
    helper: ModuleType, entries: list[dict[str, Any]]
) -> tuple[str, Path, dict[str, Any]]:
    token = uuid4().hex
    helper.LEASE.write_text(json.dumps({"token": token}))
    helper.LEASE.chmod(0o600)
    lease_marker = uuid4().hex
    os.setxattr(helper.LEASE, helper.OWNER_XATTR, lease_marker.encode("ascii"))
    directory = helper.token_directory(token)
    directory.mkdir(mode=0o700)
    directory_marker = uuid4().hex
    os.setxattr(directory, helper.OWNER_XATTR, directory_marker.encode("ascii"))
    for entry in entries:
        if entry.get("present", True):
            path = directory / entry["name"]
            path.touch(mode=0o600)
            marker = entry.setdefault("marker", uuid4().hex)
            os.setxattr(path, helper.OWNER_XATTR, marker.encode("ascii"))
            entry.setdefault("dev", path.stat().st_dev)
            entry.setdefault("inode", path.stat().st_ino)
            entry.setdefault("ctime_ns", path.stat().st_ctime_ns)
        entry.pop("present", None)
    directory_stat = directory.stat()
    record = {
        "token": token,
        "boot_id": "boot",
        "mapping": helper.disk.mapping(),
        "lease_inode": helper.LEASE.stat().st_ino,
        "lease_marker": lease_marker,
        "directory_inode": directory_stat.st_ino,
        "directory_dev": directory_stat.st_dev,
        "directory_marker": directory_marker,
        "files": entries,
        "cleanup_complete": False,
    }
    helper.disk.save(helper.run_path(token), record)
    return token, directory, record


def test_partial_creation_write_ahead_entries_are_independently_cleanable(
    helper: ModuleType,
) -> None:
    entries: list[dict[str, Any]] = [
        {"name": "f-0000", "state": "created"},
        {"name": "f-0001", "state": "pending"},
        {"name": "f-0002", "state": "pending", "present": False},
    ]
    token, directory, _ = make_active(helper, entries)
    result = helper.cleanup(token)
    assert result["cleanup_complete"]
    assert not directory.exists() and not helper.LEASE.exists()


def test_atomic_create_interruption_before_marker_leaves_no_visible_file(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = {"name": "f-0000", "state": "pending", "marker": uuid4().hex, "present": False}
    _, directory, _ = make_active(helper, [entry])
    original = os.setxattr
    original_open = os.open

    def open_unnamed(
        path: str | bytes | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == "." and flags & os.O_TMPFILE:
            return os.memfd_create("fleetdoctor-inode-boundary")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def interrupt_before_marker(
        target: int | Path, name: bytes, value: bytes, **kwargs: Any
    ) -> None:
        if isinstance(target, int):
            raise InterruptedError("pre-marker interruption")
        original(target, name, value, **kwargs)

    monkeypatch.setattr(os, "open", open_unnamed)
    monkeypatch.setattr(os, "setxattr", interrupt_before_marker)
    with pytest.raises(InterruptedError, match="pre-marker"):
        helper.create_owned_file(directory, entry)
    assert list(directory.iterdir()) == []


def test_cleanup_refuses_visible_unmarked_pending_replacement(helper: ModuleType) -> None:
    entry = {"name": "f-0000", "state": "pending"}
    token, directory, _ = make_active(helper, [entry])
    os.removexattr(directory / entry["name"], helper.OWNER_XATTR)
    with pytest.raises(ValueError, match="marker identity"):
        helper.cleanup(token)
    assert (directory / entry["name"]).exists()
    assert helper.LEASE.exists()


@pytest.mark.parametrize("change", ["unexpected", "replaced", "symlink"])
def test_cleanup_refuses_unowned_or_replaced_files(helper: ModuleType, change: str) -> None:
    token, directory, record = make_active(helper, [{"name": "f-0000", "state": "created"}])
    owned = directory / "f-0000"
    if change == "unexpected":
        (directory / "unexpected").touch(mode=0o600)
    else:
        owned.unlink()
        if change == "replaced":
            owned.touch(mode=0o600)
        else:
            owned.symlink_to(helper.run_path(token))
    with pytest.raises(ValueError, match="unexpected|identity|symlink"):
        helper.cleanup(token)
    assert directory.exists() and helper.LEASE.exists()
    assert not helper.load_record(token)["cleanup_complete"]
    assert record["files"][0]["inode"] != 0


@pytest.mark.parametrize("failure", [OSError("unlink failed"), InterruptedError("signal")])
def test_cleanup_resumes_after_interruption_following_owned_unlink(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    failure: OSError,
) -> None:
    token, directory, _ = make_active(
        helper,
        [
            {"name": "f-0000", "state": "created"},
            {"name": "f-0001", "state": "created"},
            {"name": "f-0002", "state": "created"},
        ],
    )
    original = Path.unlink
    calls = 0

    def interrupted(path: Path, missing_ok: bool = False) -> None:
        nonlocal calls
        if path.parent == directory:
            calls += 1
            if calls == 2:
                raise failure
        original(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", interrupted)
    with pytest.raises(type(failure), match="unlink|signal"):
        helper.cleanup(token)
    retained = helper.load_record(token)
    assert retained["cleanup_phase"] == "files_authorized_for_deletion"
    assert all(item["state"] == "deleting" for item in retained["files"])
    assert retained["files"][0]["state"] == "deleting"
    assert not (directory / "f-0000").exists()
    assert (directory / "f-0001").exists()

    monkeypatch.setattr(Path, "unlink", original)
    result = helper.cleanup(token)
    assert result["cleanup_complete"]
    assert not directory.exists() and not helper.LEASE.exists()


@pytest.mark.parametrize("boundary", ["directory", "lease"])
@pytest.mark.parametrize("replacement", [False, True])
def test_cleanup_terminal_phases_resume_and_refuse_replacements(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    replacement: bool,
) -> None:
    token, directory, _ = make_active(helper, [{"name": "f-0000", "state": "created"}])
    if boundary == "directory":
        original = Path.rmdir

        def fail_after_rmdir(path: Path) -> None:
            original(path)
            if path == directory:
                raise OSError("post-rmdir interruption")

        monkeypatch.setattr(Path, "rmdir", fail_after_rmdir)
    else:
        original_unlink = Path.unlink

        def fail_after_lease_unlink(path: Path, missing_ok: bool = False) -> None:
            original_unlink(path, missing_ok=missing_ok)
            if path == helper.LEASE:
                raise OSError("post-lease-unlink interruption")

        monkeypatch.setattr(Path, "unlink", fail_after_lease_unlink)
    with pytest.raises(OSError, match="post-"):
        helper.cleanup(token)
    retained = helper.load_record(token)
    expected_phase = (
        "directory_removal_authorized" if boundary == "directory" else "lease_removal_authorized"
    )
    assert retained["cleanup_phase"] == expected_phase

    if boundary == "directory":
        monkeypatch.setattr(Path, "rmdir", original)
        if replacement:
            directory.mkdir(mode=0o700)
    else:
        monkeypatch.setattr(Path, "unlink", original_unlink)
        if replacement:
            helper.LEASE.write_text(json.dumps({"token": token}))
            helper.LEASE.chmod(0o600)
    if replacement:
        with pytest.raises(ValueError, match="directory|lease|marker|identity"):
            helper.cleanup(token)
    else:
        result = helper.cleanup(token)
        assert result["cleanup_complete"]
        assert not directory.exists() and not helper.LEASE.exists()


def test_process_identity_requires_exact_inode_helper_path(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = uuid4().hex
    record = {"token": token, "worker_pid": 123, "worker_start": "456"}
    monkeypatch.setattr(helper.disk, "process_identity", lambda pid: "456")
    original = Path.read_bytes
    assert helper.__file__ is not None
    helper_path = str(Path(helper.__file__).resolve()).encode()

    def read_bytes(path: Path) -> bytes:
        if str(path) == "/proc/123/cmdline":
            return b"\0".join(
                [
                    sys.executable.encode(),
                    helper_path,
                    b"worker",
                    b"--token",
                    token.encode(),
                ]
            )
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    assert helper.owned_process(record, "worker")

    def wrong_helper(path: Path) -> bytes:
        if str(path) == "/proc/123/cmdline":
            return b"\0".join(
                [
                    sys.executable.encode(),
                    b"/app/deploy/disk_resource.py",
                    b"worker",
                    token.encode(),
                ]
            )
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", wrong_helper)
    assert not helper.owned_process(record, "worker")


def test_disk_lease_excludes_inode_start(helper: ModuleType) -> None:
    helper.DISK_LEASE.write_text('{"token":"other"}')
    with pytest.raises(ValueError, match="disk injection lease"):
        helper.start(uuid4().hex, 10)
    assert helper.DISK_LEASE.read_text() == '{"token":"other"}'


@pytest.mark.parametrize("duration", [True, 0, 1, 241])
def test_start_rejects_unbounded_duration(helper: ModuleType, duration: Any) -> None:
    with pytest.raises(ValueError, match="duration"):
        helper.start(uuid4().hex, duration)
    assert not helper.LEASE.exists()


def test_start_validates_token_before_owned_effects(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="token"):
        helper.start("not-a-token", 10)
    assert not helper.LEASE.exists()


@pytest.mark.parametrize("field,value", [("inode_usage_percent", 90), ("block_usage_percent", 95)])
def test_start_requires_healthy_inode_and_block_headroom(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: int,
) -> None:
    current = healthy_counters() | {field: value}
    monkeypatch.setattr(helper, "counters", lambda: current)
    with pytest.raises(ValueError, match="baseline|headroom"):
        helper.start(uuid4().hex, 10)
    assert not helper.LEASE.exists()


def test_cleanup_is_idempotent_and_mapping_change_fails_closed(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    token, _, _ = make_active(helper, [{"name": "f-0000", "state": "created"}])
    first = helper.cleanup(token)
    assert helper.cleanup(token) == first

    token, directory, record = make_active(helper, [{"name": "f-0000", "state": "created"}])
    changed = record["mapping"] | {"mount_id": "different"}
    monkeypatch.setattr(helper.disk, "verify", lambda: {"mapping": changed})
    with pytest.raises(ValueError, match="mount identity"):
        helper.cleanup(token)
    assert directory.exists() and helper.LEASE.exists()


@pytest.mark.parametrize(
    "failure_stage",
    [
        "lease_dup",
        "lease_only",
        "directory_authority",
        "directory_marker",
        "initial_save",
        "spawn",
    ],
)
def test_partial_start_failure_rolls_back_proven_effects_and_cleanup_is_idempotent(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    class Process:
        pid = 123
        killed = False

        def poll(self) -> None:
            return None

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: int) -> int:
            assert timeout == 5
            return 0

    process = Process()
    calls = 0
    token = uuid4().hex

    if failure_stage == "lease_dup":

        def fail_lease_dup(fd: int) -> int:
            raise OSError("lease authority dup failure")

        monkeypatch.setattr(os, "dup", fail_lease_dup)
    elif failure_stage == "lease_only":
        original_mkdir = Path.mkdir

        def fail_token_directory(path: Path, *args: Any, **kwargs: Any) -> None:
            if path == helper.token_directory(token):
                raise OSError("lease-only failure")
            original_mkdir(path, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", fail_token_directory)
    elif failure_stage == "directory_authority":
        original_open = os.open

        def fail_directory_authority(
            path: str | bytes | Path,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if Path(os.fsdecode(path)) == helper.token_directory(token) and flags & os.O_DIRECTORY:
                raise OSError("directory authority open failure")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(os, "open", fail_directory_authority)
    elif failure_stage == "directory_marker":
        original_setxattr = os.setxattr

        def fail_directory_marker(
            target: int | Path, name: bytes, value: bytes, **kwargs: Any
        ) -> None:
            if target == helper.token_directory(token):
                raise OSError("directory-marker failure")
            original_setxattr(target, name, value, **kwargs)

        monkeypatch.setattr(os, "setxattr", fail_directory_marker)
    elif failure_stage == "initial_save":
        original_save = helper.disk.save
        save_calls = 0

        def fail_initial_save(path: Path, value: dict[str, Any], **kwargs: Any) -> None:
            nonlocal save_calls
            save_calls += 1
            if save_calls == 1:
                raise OSError("initial-save failure")
            original_save(path, value, **kwargs)

        monkeypatch.setattr(helper.disk, "save", fail_initial_save)

    def launch(mode: str, token: str, duration: int) -> Process:
        nonlocal calls
        calls += 1
        if failure_stage == "spawn" and calls == 2:
            raise RuntimeError("worker spawn failed")
        return process

    monkeypatch.setattr(helper, "launch", launch)
    monkeypatch.setattr(helper.disk, "process_identity", lambda pid: "123")
    expected = RuntimeError if failure_stage == "spawn" else OSError
    with pytest.raises(expected, match="failure|spawn"):
        helper.start(token, 10)
    assert process.killed is (failure_stage == "spawn")
    assert not helper.LEASE.exists() and not helper.token_directory(token).exists()
    assert helper.run_path(token).exists()
    first = helper.cleanup(token)
    second = helper.cleanup(token)
    assert first == second
    assert first["cleanup_complete"] is True
    assert first["cleanup_reason"] == "partial_start_rollback"


@pytest.mark.parametrize(
    "boundary,signum",
    [
        ("lease_create", signal.SIGTERM),
        ("lease_marker", signal.SIGINT),
        ("directory_create", signal.SIGTERM),
        ("directory_marker", signal.SIGINT),
    ],
)
def test_partial_start_real_signal_at_create_and_marker_boundaries_rolls_back(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    signum: signal.Signals,
) -> None:
    token = uuid4().hex
    directory = helper.token_directory(token)
    previous = signal.getsignal(signum)
    if boundary == "lease_create":
        original_open = os.open

        def signal_after_lease_create(
            path: str | bytes | Path,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            if Path(os.fsdecode(path)) == helper.LEASE and flags & os.O_EXCL:
                os.kill(os.getpid(), signum)
            return fd

        monkeypatch.setattr(os, "open", signal_after_lease_create)
    elif boundary == "directory_create":
        original_mkdir = Path.mkdir

        def signal_after_directory_create(path: Path, *args: Any, **kwargs: Any) -> None:
            original_mkdir(path, *args, **kwargs)
            if path == directory:
                os.kill(os.getpid(), signum)

        monkeypatch.setattr(Path, "mkdir", signal_after_directory_create)
    else:
        original_setxattr = os.setxattr

        def signal_after_marker(
            target: int | Path, name: bytes, value: bytes, **kwargs: Any
        ) -> None:
            original_setxattr(target, name, value, **kwargs)
            is_directory = target == directory
            if (boundary == "directory_marker") is is_directory:
                os.kill(os.getpid(), signum)

        monkeypatch.setattr(os, "setxattr", signal_after_marker)

    with pytest.raises(InterruptedError, match="startup interrupted by signal"):
        helper.start(token, 10)
    assert signal.getsignal(signum) == previous
    assert not helper.LEASE.exists() and not directory.exists()
    first = helper.cleanup(token)
    assert helper.cleanup(token) == first
    assert first["cleanup_complete"] is True
    assert first["cleanup_reason"] == "partial_start_rollback"


def test_pre_record_directory_replacement_is_retained_then_explicitly_recoverable(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = uuid4().hex
    directory = helper.token_directory(token)
    original_open = os.open

    def replace_before_directory_authority(
        path: str | bytes | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if Path(os.fsdecode(path)) == directory and flags & os.O_DIRECTORY:
            directory.rmdir()
            directory.mkdir(mode=0o700)
            (directory / "replacement").write_text("unrelated")
            raise OSError("directory authority replacement failure")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", replace_before_directory_authority)
    with pytest.raises(OSError, match="authority replacement"):
        helper.start(token, 10)
    retained = helper.load_record(token)
    assert retained["startup_partial"] is True
    assert retained["cleanup_complete"] is False
    assert helper.LEASE.exists()
    assert (directory / "replacement").read_text() == "unrelated"
    with pytest.raises(ValueError, match="directory|marker|unexpected"):
        helper.cleanup(token)

    (directory / "replacement").unlink()
    directory.rmdir()
    first = helper.cleanup(token)
    assert helper.cleanup(token) == first
    assert first["cleanup_complete"] is True
    assert first["cleanup_reason"] == "partial_start_recovery"
    assert not helper.LEASE.exists()


@pytest.mark.parametrize("replacement", [False, True])
def test_partial_start_rollback_never_removes_preexisting_or_replaced_directory(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, replacement: bool
) -> None:
    token = uuid4().hex
    directory = helper.token_directory(token)
    if not replacement:
        directory.mkdir(mode=0o700)
        (directory / "preexisting").write_text("unrelated")
    else:

        def replace_before_spawn(mode: str, token: str, duration: int) -> Any:
            directory.rmdir()
            directory.mkdir(mode=0o700)
            (directory / "replacement").write_text("unrelated")
            raise RuntimeError("spawn replacement failure")

        monkeypatch.setattr(helper, "launch", replace_before_spawn)

    with pytest.raises((FileExistsError, RuntimeError)):
        helper.start(token, 10)
    expected_name = "replacement" if replacement else "preexisting"
    assert (directory / expected_name).read_text() == "unrelated"
    if replacement:
        assert helper.LEASE.exists()
        with pytest.raises(ValueError, match="directory|marker|identity"):
            helper.cleanup(token)
    else:
        assert not helper.LEASE.exists()
        first = helper.cleanup(token)
        assert helper.cleanup(token) == first
        assert first["cleanup_complete"] is True


def test_partial_spawn_rollback_refuses_unproven_owned_effects(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Process:
        pid = 123

        def poll(self) -> None:
            return None

        def kill(self) -> None:
            pass

        def wait(self, timeout: int) -> int:
            return 0

    process = Process()
    calls = 0

    def launch(mode: str, token: str, duration: int) -> Process:
        nonlocal calls
        calls += 1
        if calls == 2:
            (helper.token_directory(token) / "unrelated").touch(mode=0o600)
            raise RuntimeError("worker spawn failed")
        return process

    monkeypatch.setattr(helper, "launch", launch)
    monkeypatch.setattr(helper.disk, "process_identity", lambda pid: "123")
    token = uuid4().hex
    with pytest.raises(RuntimeError, match="spawn"):
        helper.start(token, 10)
    retained = helper.load_record(token)
    assert retained["cleanup_complete"] is False
    assert helper.LEASE.exists() and helper.token_directory(token).exists()
    with pytest.raises(ValueError, match="unexpected"):
        helper.cleanup(token)
