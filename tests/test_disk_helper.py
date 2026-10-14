"""Linux helper contracts without mounting anything in ordinary pytest."""

import importlib
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock
from uuid import uuid4

import pytest


@pytest.fixture
def helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    pytest.importorskip(
        "fcntl", reason="root mount helper is Linux-only; Linux CI runs these contracts"
    )
    module = importlib.import_module("disk_resource")
    mount = tmp_path / "disk"
    mount.mkdir()
    (tmp_path / "runs").mkdir()
    for key, value in (
        ("BASE", tmp_path),
        ("MOUNT", mount),
        ("RESOURCE", tmp_path / "resource.json"),
        ("IDENTITY", tmp_path / "identity.json"),
        ("LEASE", tmp_path / "disk-lease.json"),
    ):
        monkeypatch.setattr(module, key, value)
    mapping = {
        "target": str(mount),
        "source": "/dev/loop42",
        "backing_file": str(tmp_path / "owned.img"),
        "mount_id": "42",
    }
    monkeypatch.setattr(
        module, "verify", lambda: {"mapping": mapping, "root_available_bytes": 3 * 1024**3}
    )
    monkeypatch.setattr(module, "mapping", lambda: mapping)
    return module


@contextmanager
def live_status_run(helper: ModuleType, token: str) -> Iterator[dict[str, Any]]:
    if os.geteuid() != 0:
        pytest.skip("live helper status contract requires root-owned fixture files")
    helper.LEASE.write_text(json.dumps({"token": token}))
    filler = helper.MOUNT / ("filler-" + token)
    filler.write_bytes(b"fixture")
    processes = {
        mode: subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)", mode, "--token", token]
        )
        for mode in ("watchdog", "worker")
    }
    try:
        record = {
            "token": token,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "mapping": helper.mapping(),
            "lease_inode": helper.LEASE.stat().st_ino,
            "filler_inode": filler.stat().st_ino,
            "watchdog_pid": processes["watchdog"].pid,
            "watchdog_start": helper.process_identity(processes["watchdog"].pid),
            "worker_pid": processes["worker"].pid,
            "worker_start": helper.process_identity(processes["worker"].pid),
            "cleanup_complete": False,
        }
        helper.save(helper.run_path(token), record)
        yield record
    finally:
        for process in processes.values():
            process.terminate()
        for process in processes.values():
            process.wait(timeout=5)


def test_status_validates_live_active_run_and_missing_lease(helper: ModuleType) -> None:
    token = uuid4().hex
    with live_status_run(helper, token) as record:
        assert helper.status(token) == record
        helper.LEASE.unlink()
        with pytest.raises(ValueError, match="lease"):
            helper.status(token)


def test_completed_status_remains_available_without_live_resources(helper: ModuleType) -> None:
    token = uuid4().hex
    record = {"token": token, "cleanup_complete": True, "cleanup_utc": "fixture"}
    helper.save(helper.run_path(token), record)
    assert helper.status(token) == record


@pytest.mark.parametrize(
    ("target", "change"),
    [
        ("lease", "removed"),
        ("lease", "replaced"),
        ("lease", "symlink"),
        ("filler", "removed"),
        ("filler", "replaced"),
        ("filler", "symlink"),
    ],
)
def test_active_status_rejects_missing_replaced_or_symlink_owned_files(
    helper: ModuleType, target: str, change: str
) -> None:
    token = uuid4().hex
    with live_status_run(helper, token):
        path = helper.LEASE if target == "lease" else helper.MOUNT / ("filler-" + token)
        retained_fd = os.open(path, os.O_RDONLY) if change == "replaced" else None
        try:
            path.unlink()
            if change == "replaced":
                path.write_text(
                    json.dumps({"token": token}) if target == "lease" else "replacement"
                )
            elif change == "symlink":
                replacement = helper.BASE / (target + "-replacement")
                replacement.write_text("replacement")
                path.symlink_to(replacement)
            with pytest.raises(ValueError, match=target):
                helper.status(token)
        finally:
            if retained_fd is not None:
                os.close(retained_fd)


@pytest.mark.parametrize(
    ("mode", "failure"),
    [
        ("worker", "dead"),
        ("worker", "reused"),
        ("watchdog", "dead"),
        ("watchdog", "reused"),
    ],
)
def test_active_status_rejects_dead_or_reused_process_identity(
    helper: ModuleType, mode: str, failure: str
) -> None:
    token = uuid4().hex
    with live_status_run(helper, token) as record:
        if failure == "dead":
            os.kill(record[mode + "_pid"], 9)
        else:
            record[mode + "_start"] = "0"
            helper.save(helper.run_path(token), record)
        with pytest.raises(ValueError, match=mode):
            helper.status(token)


@pytest.mark.parametrize("identity", ["boot", "mount"])
def test_active_status_rejects_boot_or_mount_remap(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, identity: str
) -> None:
    token = uuid4().hex
    with live_status_run(helper, token):
        if identity == "boot":
            monkeypatch.setattr(helper, "boot_identity", lambda: "different-boot")
        else:
            monkeypatch.setattr(
                helper,
                "verify",
                lambda: {
                    "mapping": {"target": str(helper.MOUNT), "source": "/dev/loop99"},
                    "root_available_bytes": 3 * 1024**3,
                },
            )
        with pytest.raises(ValueError, match=identity):
            helper.status(token)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("lease_inode", None),
        ("filler_inode", "invalid"),
        ("worker_pid", True),
        ("worker_start", None),
        ("watchdog_pid", -1),
        ("watchdog_start", "invalid"),
        ("boot_id", None),
        ("mapping", None),
        ("cleanup_complete", None),
    ],
)
def test_active_status_rejects_missing_or_corrupt_identity_metadata(
    helper: ModuleType, field: str, value: object
) -> None:
    token = uuid4().hex
    with live_status_run(helper, token) as record:
        if value is None:
            record.pop(field)
        else:
            record[field] = value
        helper.save(helper.run_path(token), record)
        with pytest.raises(ValueError):
            helper.status(token)


def test_active_status_rejects_stale_record_token(helper: ModuleType) -> None:
    token = uuid4().hex
    with live_status_run(helper, token) as record:
        record["token"] = uuid4().hex
        helper.save(helper.run_path(token), record)
        with pytest.raises(ValueError, match="token"):
            helper.status(token)


def test_start_persists_all_live_status_identities(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = uuid4().hex
    watchdog = Mock(spec=subprocess.Popen)
    watchdog.pid = 101
    watchdog.poll.return_value = None
    worker = Mock(spec=subprocess.Popen)
    worker.pid = 202
    worker.poll.return_value = None
    monkeypatch.setattr(helper, "launch", Mock(side_effect=[watchdog, worker]))
    monkeypatch.setattr(helper, "process_identity", lambda pid: str(pid * 10))

    record = helper.start(token, 10)

    assert record["lease_inode"] == helper.LEASE.stat().st_ino
    assert record["filler_inode"] == (helper.MOUNT / ("filler-" + token)).stat().st_ino
    assert record["watchdog_pid"] == 101 and record["watchdog_start"] == "1010"
    assert record["worker_pid"] == 202 and record["worker_start"] == "2020"


@pytest.mark.parametrize("failure", ["save", "first_launch", "second_launch"])
def test_partial_start_rolls_back_only_created_files(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    token = uuid4().hex
    process = Mock(spec=subprocess.Popen)
    process.pid = 12345
    process.poll.return_value = None
    monkeypatch.setattr(helper, "process_identity", lambda pid: str(pid))
    if failure == "save":
        monkeypatch.setattr(helper, "save", Mock(side_effect=OSError("forced manifest failure")))
    else:
        monkeypatch.setattr(
            helper,
            "launch",
            Mock(
                side_effect=[OSError("launch failed")]
                if failure == "first_launch"
                else [process, OSError("launch failed")]
            ),
        )
    with pytest.raises(OSError):
        helper.start(token, 10)
    assert not helper.LEASE.exists()
    assert not (helper.MOUNT / ("filler-" + token)).exists()
    if failure == "second_launch":
        process.kill.assert_called_once()


def test_existing_lease_or_filler_is_never_deleted(helper: ModuleType) -> None:
    token = uuid4().hex
    helper.LEASE.write_text('{"token":"other"}')
    with pytest.raises(FileExistsError):
        helper.start(token, 10)
    assert helper.LEASE.read_text() == '{"token":"other"}'
    helper.LEASE.unlink()
    filler = helper.MOUNT / ("filler-" + token)
    filler.write_text("unowned")
    with pytest.raises(FileExistsError):
        helper.start(token, 10)
    assert filler.read_text() == "unowned" and not helper.LEASE.exists()


def test_cleanup_rejects_wrong_inode_and_mapping(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = uuid4().hex
    filler = helper.MOUNT / ("filler-" + token)
    filler.write_text("owned")
    record = {"token": token, "mapping": helper.mapping(), "filler_inode": filler.stat().st_ino + 1}
    helper.save(helper.run_path(token), record)
    with pytest.raises(ValueError, match="ownership"):
        helper.cleanup(token)
    assert filler.read_text() == "owned"
    record["filler_inode"] = filler.stat().st_ino
    helper.save(helper.run_path(token), record)
    monkeypatch.setattr(helper, "mapping", lambda: {"source": "/dev/other"})
    with pytest.raises(ValueError, match="identity"):
        helper.cleanup(token)
    assert filler.exists()


def test_retained_image_remounts_without_formatting_and_rejects_changed_image(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "safe_directory", lambda: None)
    image = helper.BASE / ("disk-" + uuid4().hex + ".img")
    with image.open("wb") as stream:
        stream.truncate(helper.CAPACITY)
    monkeypatch.setattr(helper.os, "getuid", lambda: 0)
    # Fixture owner may be a non-root Linux CI user: only synthetic stat ownership is patched.
    original_stat = Path.stat

    def stat(path: Path, *args: Any, **kwargs: Any) -> Any:
        result = original_stat(path, *args, **kwargs)
        if path == image:
            return Mock(
                st_uid=0, st_ino=result.st_ino, st_size=result.st_size, st_mode=result.st_mode
            )
        return result

    monkeypatch.setattr(Path, "stat", stat)
    helper.save(
        helper.RESOURCE,
        {"image": str(image), "image_inode": image.stat().st_ino, "mapping": {"old": True}},
    )
    commands: list[tuple[str, ...]] = []

    def command(*args: str) -> str:
        commands.append(args)
        if "--json" in args:
            return json.dumps({"loopdevices": []})
        return "/dev/loop42"

    monkeypatch.setattr(helper, "command", command)
    monkeypatch.setattr(helper.os.path, "ismount", lambda _: False)
    helper.prepare()
    assert any(cmd[0] == "mount" for cmd in commands)
    assert not any(cmd[0] == "mkfs.ext4" for cmd in commands)
    assert json.loads(helper.RESOURCE.read_text())["mapping"] == helper.mapping()
    image.write_bytes(b"changed")
    with pytest.raises(ValueError, match="identity"):
        helper.prepare()


def test_prepare_rejects_unrelated_mounted_resource(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "safe_directory", lambda: None)
    monkeypatch.setattr(helper.os.path, "ismount", lambda _: True)
    with pytest.raises(ValueError, match="unowned mount"):
        helper.prepare()


@pytest.mark.parametrize("failure", ["allocation", "attach", "save"])
def test_fresh_preparation_rollback(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    monkeypatch.setattr(helper, "safe_directory", lambda: None)
    mounted = [False]
    devices: list[str] = []
    commands: list[tuple[str, ...]] = []
    monkeypatch.setattr(helper.os.path, "ismount", lambda _: mounted[0])
    monkeypatch.setattr(helper, "image_devices", lambda _: devices.copy())

    def command(*args: str) -> str:
        commands.append(args)
        if args[0] == "losetup" and "--find" in args:
            if failure == "attach":
                raise OSError("forced attach failure")
            devices.append("/dev/loop42")
            return "/dev/loop42"
        if args[0] == "mount":
            mounted[0] = True
        if args[0] == "umount":
            mounted[0] = False
        if args[0] == "losetup" and "--detach" in args:
            devices.clear()
        return ""

    monkeypatch.setattr(helper, "command", command)

    def mapping() -> dict[str, Any]:
        image = next(helper.BASE.glob("disk-*.img"))
        return {"source": "/dev/loop42", "backing_file": str(image)}

    monkeypatch.setattr(helper, "mapping", mapping)
    if failure == "allocation":
        monkeypatch.setattr(
            helper.os, "posix_fallocate", Mock(side_effect=OSError("allocation failed"))
        )
    else:
        monkeypatch.setattr(
            helper.os, "posix_fallocate", lambda fd, offset, size: os.ftruncate(fd, size)
        )
    if failure == "save":
        monkeypatch.setattr(helper, "save", Mock(side_effect=OSError("manifest save failed")))
    with pytest.raises(OSError):
        helper.prepare()
    assert not mounted[0] and not devices
    assert not list(helper.BASE.glob("disk-*.img"))
    if failure == "save":
        assert any(cmd[0] == "umount" for cmd in commands)
        assert any(cmd[:2] == ("losetup", "--detach") for cmd in commands)


def test_installer_exit_trap_removes_staged_credentials_on_hash_failure(tmp_path: Path) -> None:
    pytest.importorskip("fcntl")
    root = Path(__file__).resolve().parents[1]
    # Redirect only the install working directory into the fixture; run the actual trap/hash path.
    script = (
        (root / "deploy/install-agent.sh")
        .read_text()
        .replace("cd /opt/fleetdoctor/current", 'cd "' + str(tmp_path) + '"')
    )
    (tmp_path / "wheel.sha256").write_text("invalid checksum\n")
    env, token = tmp_path / "staged.env", tmp_path / "staged.token"
    env.write_text("private fixture")
    token.write_text("private fixture")
    result = subprocess.run(
        ["bash", "-c", script, "installer", str(env), str(token)], capture_output=True, timeout=10
    )
    assert result.returncode != 0
    assert not env.exists() and not token.exists()


@pytest.mark.parametrize("already_attached", [False, True])
def test_remount_failure_detaches_only_new_device(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, already_attached: bool
) -> None:
    monkeypatch.setattr(helper, "safe_directory", lambda: None)
    monkeypatch.setattr(helper.os.path, "ismount", lambda _: False)
    image = helper.BASE / ("disk-" + uuid4().hex + ".img")
    with image.open("wb") as stream:
        stream.truncate(helper.CAPACITY)
    original_stat = Path.stat

    def stat(path: Path, *args: Any, **kwargs: Any) -> Any:
        value = original_stat(path, *args, **kwargs)
        return (
            Mock(st_uid=0, st_ino=value.st_ino, st_size=value.st_size, st_mode=value.st_mode)
            if path == image
            else value
        )

    monkeypatch.setattr(Path, "stat", stat)
    helper.save(helper.RESOURCE, {"image": str(image), "image_inode": image.stat().st_ino})
    devices = ["/dev/loop42"] if already_attached else []
    detached: list[str] = []
    monkeypatch.setattr(helper, "image_devices", lambda _: devices.copy())

    def command(*args: str) -> str:
        if args[0] == "mount":
            raise OSError("forced remount failure")
        if "--find" in args:
            devices.append("/dev/loop42")
            return "/dev/loop42"
        if "--detach" in args:
            detached.append(args[-1])
        return ""

    monkeypatch.setattr(helper, "command", command)
    with pytest.raises(OSError):
        helper.prepare()
    assert detached == ([] if already_attached else ["/dev/loop42"])
    assert image.exists() and helper.RESOURCE.exists()


def test_missing_required_mount_never_reads_root_statvfs(monkeypatch: pytest.MonkeyPatch) -> None:
    from fleetdoctor.collection import DISK_PATH, collect_filesystem

    monkeypatch.setattr(
        "fleetdoctor.collection.required_mount_identity", Mock(side_effect=ValueError("unmounted"))
    )
    stat = Mock()
    monkeypatch.setattr(os, "statvfs", stat, raising=False)
    value = collect_filesystem(DISK_PATH)
    assert value.block_usage_percent is None and value.errors
    stat.assert_not_called()
