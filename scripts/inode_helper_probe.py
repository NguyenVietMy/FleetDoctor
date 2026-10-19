"""Privileged native inode proof inside an owned container and PostgreSQL network."""

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient
from pydantic import SecretStr

from fleetdoctor.agent import make_sample
from fleetdoctor.collection import DISK_PATH, collect_filesystem
from fleetdoctor.collector import create_app
from fleetdoctor.incidents import InodeConfig
from fleetdoctor.store import PostgresStore

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import disk_resource as disk  # noqa: E402
import inode_resource as inode  # noqa: E402

TOKEN_VALUE = "native-inode-proof-token-value-0000"


def command(script: Path, action: str, token: str = "", duration: int = 30) -> dict[str, Any]:
    argv = [sys.executable, str(script), action, "--duration", str(duration)]
    if token:
        argv.extend(["--token", token])
    result = subprocess.run(argv, capture_output=True, text=True, timeout=duration + 15)
    if result.returncode:
        raise RuntimeError(
            f"{script.name} {action} failed: {(result.stderr or result.stdout)[-2000:]}"
        )
    value: dict[str, Any] = json.loads(result.stdout)
    return value


def source_hashes() -> dict[str, str]:
    paths = [
        path
        for directory in ("src", "deploy", "scripts", "monitoring")
        for path in (ROOT / directory).rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    ]
    paths.extend(
        ROOT / name for name in ("compose.yaml", "Dockerfile", "pyproject.toml", "uv.lock")
    )
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(paths)
    }


def wait_postgres(dsn: str) -> None:
    import psycopg

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(dsn, connect_timeout=2) as connection:
                if connection.execute("SELECT 1").fetchone() == (1,):
                    return
        except psycopg.Error:
            time.sleep(0.25)
    raise TimeoutError("owned PostgreSQL service was not ready")


def owned_disk_process(record: dict[str, Any], mode: str) -> bool:
    """Proof-only exact identity check for the disk worker and watchdog."""
    try:
        pid = record[mode + "_pid"]
        started = record[mode + "_start"]
        token = record["token"]
        command_line = [
            part for part in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if part
        ]
        token_index = command_line.index(b"--token")
        return (
            type(pid) is int
            and pid > 0
            and isinstance(started, str)
            and disk.process_identity(pid) == started
            and len(command_line) >= 3
            and command_line[1] == str((ROOT / "deploy/disk_resource.py").resolve()).encode()
            and command_line[2] == mode.encode()
            and token_index + 1 < len(command_line)
            and command_line[token_index + 1] == token.encode()
        )
    except (IndexError, KeyError, OSError, ProcessLookupError, TypeError, ValueError):
        return False


def wait_for_disk_helpers(record: dict[str, Any], initial: dict[str, bool]) -> dict[str, Any]:
    modes = ("worker", "watchdog")
    started = time.monotonic()
    deadline = started + float(record["max_duration_seconds"]) + 5
    while time.monotonic() < deadline:
        remaining = [mode for mode in modes if owned_disk_process(record, mode)]
        if not remaining:
            return {
                "initial_exact_identity": initial,
                "remaining_exact_identities": [],
                "elapsed_seconds": time.monotonic() - started,
            }
        time.sleep(0.05)
    remaining = [mode for mode in modes if owned_disk_process(record, mode)]
    raise TimeoutError("owned disk helpers did not exit: " + ",".join(remaining))


def main() -> None:
    proof_started = time.monotonic()
    dsn = os.environ["FLEETDOCTOR_PROOF_DSN"]
    reader_password = os.environ["FLEETDOCTOR_READER_PASSWORD"]
    report: dict[str, Any] = {
        "status": "failed",
        "environment": "privileged-disposable-Docker-ext4-private-tmpfs-real-PostgreSQL",
        "persistence": "PostgresStore",
        "fixture_store_used": False,
        "source_hashes": source_hashes(),
        "events": [],
        "phase_timings_seconds": {},
        "cleanup": {},
    }
    failure: BaseException | None = None
    resource: dict[str, Any] | None = None
    partial_token = uuid4().hex
    active_token = uuid4().hex
    disk_token = uuid4().hex
    try:
        phase_started = time.monotonic()
        wait_postgres(dsn)
        store = PostgresStore(dsn, reader_password)
        resource = disk.prepare()
        report["prepared"] = resource
        total_inodes = int(resource["statvfs"]["f_files"])
        if not 1 <= total_inodes <= inode.MAX_INODES:
            raise RuntimeError("new image does not have the bounded inode budget")
        report["phase_timings_seconds"]["postgres_ready_and_ext4_prepare"] = (
            time.monotonic() - phase_started
        )

        # Kill between write-ahead ledger updates and the target, then require the
        # detached watchdog to remove only the partial owned set.
        phase_started = time.monotonic()
        partial = command(ROOT / "deploy/inode_resource.py", "start", partial_token, 5)
        partial_deadline = time.monotonic() + 3
        partial_record: dict[str, Any] | None = None
        while time.monotonic() < partial_deadline:
            partial_record = json.loads(inode.run_path(partial_token).read_text())
            usage = inode.counters()["inode_usage_percent"]
            ledger = partial_record.get("files", [])
            if (
                ledger
                and all(item.get("state") == "created" for item in ledger)
                and float(usage) < inode.TARGET_PERCENT
            ):
                break
            time.sleep(0.005)
        else:
            raise TimeoutError("could not capture partial inode creation before target")
        os.kill(partial["worker_pid"], signal.SIGKILL)
        watchdog_deadline = time.monotonic() + 12
        while time.monotonic() < watchdog_deadline:
            completed = json.loads(inode.run_path(partial_token).read_text())
            if completed.get("cleanup_complete") is True:
                break
            time.sleep(0.05)
        else:
            raise TimeoutError("independent watchdog did not clean partial inode creation")
        if inode.token_directory(partial_token).exists() or inode.LEASE.exists():
            raise RuntimeError("watchdog retained partial owned files or lease")
        report["partial_sigkill_watchdog_cleanup"] = {
            "files_ledgered_before_kill": len((partial_record or {}).get("files", [])),
            "inode_usage_before_kill": usage,
            "cleanup_complete": True,
        }
        report["phase_timings_seconds"]["partial_sigkill_watchdog_cleanup"] = (
            time.monotonic() - phase_started
        )

        baseline = collect_filesystem(DISK_PATH)
        if baseline.inode_usage_percent is None or baseline.block_usage_percent is None:
            raise RuntimeError("production statvfs collector did not read prepared mount")
        store = PostgresStore(dsn, reader_password)
        app = create_app(
            {"node-a": SecretStr(TOKEN_VALUE)},
            ("/", DISK_PATH),
            store=store,
        )
        client = TestClient(app)
        boot, session = uuid4(), uuid4()
        sequence = 0

        def observe() -> dict[str, Any]:
            nonlocal sequence
            value = make_sample(
                "node-a",
                boot,
                session,
                sequence,
                [collect_filesystem("/"), collect_filesystem(DISK_PATH)],
                datetime.now(UTC),
            )
            sequence += 1
            response = client.post(
                "/ingest",
                headers={"Authorization": "Bearer " + TOKEN_VALUE},
                content=value.model_dump_json(),
            )
            if response.status_code != 200 or response.json()["status"] != "accepted":
                raise RuntimeError("native statvfs observation was rejected: " + response.text)
            target = next(fs for fs in value.filesystems if fs.mountpoint == DISK_PATH)
            event = {
                "sequence": value.sequence,
                "observed_at": value.observed_at.isoformat(),
                "inode_usage_percent": target.inode_usage_percent,
                "block_usage_percent": target.block_usage_percent,
                "available_bytes": target.available_bytes,
            }
            report["events"].append(event)
            return event

        observe()
        phase_started = time.monotonic()
        command(ROOT / "deploy/inode_resource.py", "start", active_token, 60)
        conflict = subprocess.run(
            [
                sys.executable,
                str(ROOT / "deploy/disk_resource.py"),
                "start",
                "--token",
                uuid4().hex,
                "--duration",
                "10",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if conflict.returncode == 0 or "inode injection lease is active" not in conflict.stderr:
            raise RuntimeError("disk helper did not refuse the active inode lease")
        report["disk_start_refused_inode_lease"] = True
        trigger_deadline = time.monotonic() + 35
        triggered: dict[str, Any] | None = None
        while time.monotonic() < trigger_deadline:
            time.sleep(0.1)
            event = observe()
            if (
                event["inode_usage_percent"] is not None
                and event["inode_usage_percent"] >= 95
                and event["block_usage_percent"] is not None
                and event["block_usage_percent"] < 95
                and int(event["available_bytes"] or 0) > 0
            ):
                triggered = event
                diagnoses = client.get(
                    "/diagnoses", params={"rule": "inode_exhaustion", "status": "active"}
                ).json()
                if diagnoses["total"] == 1:
                    break
        if triggered is None or diagnoses["total"] != 1:
            raise RuntimeError("actual inode pressure did not persist one active incident")
        incident_id = diagnoses["diagnoses"][0]["id"]
        opening = client.get("/diagnoses/" + incident_id).json()
        if opening["configuration"] != InodeConfig().model_dump():
            raise RuntimeError("persisted inode incident configuration was not typed")
        report["opening_incident"] = opening
        report["trigger"] = triggered
        report["phase_timings_seconds"]["native_injection_to_persisted_opening"] = (
            time.monotonic() - phase_started
        )

        # Reconstruct the whole state from PostgreSQL while the incident remains active.
        restarted_store = PostgresStore(dsn, reader_password)
        restarted = create_app(
            {"node-a": SecretStr(TOKEN_VALUE)},
            ("/", DISK_PATH),
            store=restarted_store,
        )
        client = TestClient(restarted)
        reloaded = client.get("/diagnoses/" + incident_id).json()
        if (
            reloaded["rule"] != "inode_exhaustion"
            or reloaded["configuration"] != InodeConfig().model_dump()
        ):
            raise RuntimeError("PostgreSQL restart did not rule-decode InodeConfig")
        report["postgres_restart_typed_config"] = True

        phase_started = time.monotonic()
        report["explicit_cleanup"] = command(
            ROOT / "deploy/inode_resource.py", "cleanup", active_token, 60
        )
        report["phase_timings_seconds"]["explicit_cleanup"] = time.monotonic() - phase_started
        phase_started = time.monotonic()
        for _ in range(3):
            time.sleep(0.1)
            observe()
        resolved = client.get("/diagnoses/" + incident_id).json()
        if (
            resolved["status"] != "resolved"
            or resolved["opening_evidence"] != opening["opening_evidence"]
        ):
            raise RuntimeError("native PostgreSQL inode incident did not resolve correctly")
        report["resolved_incident"] = resolved
        report["phase_timings_seconds"]["fresh_recovery_to_persisted_resolution"] = (
            time.monotonic() - phase_started
        )

        disk_run = command(ROOT / "deploy/disk_resource.py", "start", disk_token, 20)
        inode_conflict = subprocess.run(
            [
                sys.executable,
                str(ROOT / "deploy/inode_resource.py"),
                "start",
                "--token",
                uuid4().hex,
                "--duration",
                "10",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if (
            inode_conflict.returncode == 0
            or "disk injection lease is active" not in inode_conflict.stderr
        ):
            raise RuntimeError("inode helper did not refuse the active disk lease")
        initial_disk_helpers = {
            mode: owned_disk_process(disk_run, mode) for mode in ("worker", "watchdog")
        }
        if not all(initial_disk_helpers.values()):
            raise RuntimeError("disk helper identity was not live before cleanup")
        disk.cleanup(disk_run["token"])
        report["disk_helper_exit_wait"] = wait_for_disk_helpers(disk_run, initial_disk_helpers)
        report["inode_start_refused_disk_lease"] = True
        report["status"] = "passed"
    except BaseException as exc:
        failure = exc
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for token in (active_token, partial_token):
            try:
                if inode.run_path(token).exists():
                    report["cleanup"][token] = inode.request_cleanup(token)
            except BaseException as exc:
                report["cleanup"][token] = f"{type(exc).__name__}: {exc}"
                if failure is None:
                    failure = exc
        try:
            if disk.run_path(disk_token).exists():
                report["cleanup"][disk_token] = disk.cleanup(disk_token)
        except BaseException as exc:
            report["cleanup"][disk_token] = f"{type(exc).__name__}: {exc}"
            if failure is None:
                failure = exc
        if resource is not None:
            image = Path(resource["image"])
            device = resource["mapping"]["source"]
            try:
                rollback_started = time.monotonic()
                disk.rollback_mount(
                    image,
                    int(resource["image_inode"]),
                    [device],
                    delete_image=True,
                )
                remaining_devices = disk.image_devices(image)
                if (
                    os.path.ismount(disk.MOUNT)
                    or image.exists()
                    or remaining_devices
                    or disk.RESOURCE.exists()
                ):
                    raise RuntimeError(
                        "owned ext4 rollback left mount, image, mapping, or manifest"
                    )
                identity_removed = False
                if disk.IDENTITY.exists():
                    identity = json.loads(disk.IDENTITY.read_text())
                    if identity != resource["mapping"]:
                        raise RuntimeError("owned filesystem identity changed before rollback")
                    disk.IDENTITY.unlink()
                    identity_removed = True
                report["cleanup"]["loop_resource"] = {
                    "rollback_mount": True,
                    "prepared_image": str(image),
                    "prepared_device": device,
                    "mount_absent": True,
                    "image_absent": True,
                    "loop_mappings_remaining": remaining_devices,
                    "resource_manifest_absent": True,
                    "identity_removed": identity_removed,
                }
                report["phase_timings_seconds"]["exact_loop_resource_rollback"] = (
                    time.monotonic() - rollback_started
                )
            except BaseException as exc:
                report["cleanup"]["loop_resource"] = f"{type(exc).__name__}: {exc}"
                if failure is None:
                    failure = exc
        report["source_hashes_after"] = source_hashes()
        if report["source_hashes_after"] != report["source_hashes"]:
            failure = failure or RuntimeError("source changed during native inode proof")
        if failure is not None:
            report["status"] = "failed"
        report["phase_timings_seconds"]["total"] = time.monotonic() - proof_started
        print(json.dumps(report))
    if failure is not None:
        raise RuntimeError("native inode helper proof failed") from failure


if __name__ == "__main__":
    main()
