"""Actual privileged helper proof. Run only inside its unique disposable container."""

import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
import disk_resource as helper  # noqa: E402


def main() -> None:
    report: dict[str, Any] = {
        "environment": "privileged-disposable-docker-ext4-loop-on-private-tmpfs"
    }
    resource: dict[str, Any] | None = None
    tmpfs_overlay = False
    try:
        resource = helper.prepare()
        report["prepared"] = resource
        assert helper.prepare()["mapping"] == resource["mapping"]
        # ProtectSystem/PrivateTmp keep the same filesystem through a cloned namespace,
        # but kernel mount IDs change. Validate the exact production collection path there.
        namespace = helper.command(
            "unshare",
            "--mount",
            "--propagation",
            "private",
            "/app/.venv/bin/python",
            "-c",
            "import json; from pathlib import Path; from fleetdoctor.collection import collect_filesystem,DISK_PATH; expected=json.loads(Path('/var/lib/fleetdoctor/chaos/identity.json').read_text()); local=next(line.split()[0] for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4]==DISK_PATH); fs=collect_filesystem(DISK_PATH); assert local != expected['mount_id']; assert fs.block_usage_percent is not None,fs; print(json.dumps({'root_mount_id':expected['mount_id'],'private_mount_id':local,'filesystem':fs.model_dump()}))",
        )
        report["private_namespace_collection"] = json.loads(namespace)
        identity = json.loads(helper.IDENTITY.read_text())
        helper.save(helper.IDENTITY, identity | {"f_fsid": identity["f_fsid"] + 1}, mode=0o644)
        rejected = helper.command(
            "/app/.venv/bin/python",
            "-c",
            "from fleetdoctor.collection import collect_filesystem,DISK_PATH; fs=collect_filesystem(DISK_PATH); assert fs.block_usage_percent is None and fs.errors; print(fs.model_dump_json())",
        )
        report["wrong_filesystem_identity_unavailable"] = json.loads(rejected)
        helper.save(helper.IDENTITY, identity, mode=0o644)
        run = helper.start(uuid4().hex, 30)
        report["run"] = run
        deadline = time.monotonic() + 25
        while True:
            fs = os.statvfs(helper.MOUNT)
            used = fs.f_blocks - fs.f_bfree
            percent = used / (used + fs.f_bavail) * 100
            if percent >= 95:
                report["trigger_usage_percent"] = percent
                report["trigger_statvfs"] = helper.verify()["statvfs"]
                break
            if time.monotonic() > deadline:
                raise TimeoutError("real isolated mount did not reach95%")
            time.sleep(0.2)
        assert helper.owned_pid(run)
        os.kill(run["worker_pid"], signal.SIGKILL)
        report["worker_killed_to_prove_independent_watchdog"] = True
        deadline = time.monotonic() + 35
        filler = helper.MOUNT / ("filler-" + run["token"])
        while filler.exists() or helper.LEASE.exists():
            if time.monotonic() > deadline:
                raise TimeoutError("watchdog did not remove owned filler/lease")
            time.sleep(0.2)
        record = json.loads(helper.run_path(run["token"]).read_text())
        assert record["cleanup_complete"]
        report["watchdog_cleanup"] = record
        marker = helper.MOUNT / "retained-marker"
        marker.write_text("retained image contents")
        old_inode = Path(resource["image"]).stat().st_ino
        helper.command("umount", str(helper.MOUNT))
        helper.command("losetup", "--detach", resource["mapping"]["source"])
        resource = helper.prepare()
        assert Path(resource["image"]).stat().st_ino == old_inode
        assert marker.read_text() == "retained image contents"
        report["verified_remount_without_reformat"] = resource
        orphan_token = uuid4().hex
        orphan = helper.MOUNT / ("filler-" + orphan_token)
        orphan.write_text("owned orphan")
        helper.save(
            helper.run_path(orphan_token),
            {
                "token": orphan_token,
                "boot_id": "prior-boot-fixture",
                "mapping": resource["mapping"],
                "filler_inode": orphan.stat().st_ino,
            },
        )
        helper.cleanup(orphan_token, reboot=True)
        assert not orphan.exists() and marker.exists()
        report["owned_reboot_cleanup"] = True
        helper.command("umount", str(helper.MOUNT))
        helper.command("mount", "-t", "tmpfs", "-o", "size=1m", "tmpfs", str(helper.MOUNT))
        tmpfs_overlay = True
        try:
            helper.prepare()
        except ValueError:
            report["unrelated_mount_refused"] = True
        else:
            raise AssertionError("unrelated mount accepted")
        helper.command("umount", str(helper.MOUNT))
        tmpfs_overlay = False
        resource = helper.prepare()
        second = helper.start(uuid4().hex, 30)
        helper.cleanup(second["token"])
        assert not helper.LEASE.exists()
        assert marker.read_text() == "retained image contents"
        report["explicit_cleanup_preserves_unrelated_files"] = True
        report["status"] = "passed"
    except BaseException as exc:
        report["status"] = "failed"
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        try:
            if tmpfs_overlay:
                helper.command("umount", str(helper.MOUNT))
            if resource:
                if os.path.ismount(helper.MOUNT):
                    helper.verify()
                    helper.command("umount", str(helper.MOUNT))
                loops = json.loads(
                    helper.command("losetup", "--json", "--list", "--output", "NAME,BACK-FILE")
                )["loopdevices"]
                for loop in loops:
                    if str(Path(loop["back-file"]).resolve()) == resource["image"]:
                        helper.command("losetup", "--detach", loop["name"])
                report["cleanup"] = (
                    "owned mount unmounted and owned loop detached; container tmpfs owns image"
                )
        except BaseException as exc:
            report["status"] = "failed"
            report["cleanup_error"] = str(exc)
        print(json.dumps(report))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
