#!/usr/bin/env python3
"""Run one bounded native memcg OOM through production collection, rules, API, and PostgreSQL."""

import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from chaos_harness import source_manifest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from fleetdoctor.agent import make_sample
from fleetdoctor.collector import create_app
from fleetdoctor.memory import MemoryCollector
from fleetdoctor.schema import CpuObservation, Filesystem
from fleetdoctor.store import PostgresStore

TOKEN_VALUE = "native-oom-proof-token-value-000000"


def command(argv: list[str], timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)


def helper(script: Path, action: str, token: str, *args: str) -> dict[str, Any]:
    result = command([sys.executable, str(script), action, "--token", token, *args], timeout=30)
    if result.returncode:
        raise RuntimeError(f"helper {action} failed: {(result.stderr or result.stdout)[-1000:]}")
    value: dict[str, Any] = json.loads(result.stdout)
    return value


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_postgres(name: str, dsn: str) -> None:
    import psycopg

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = command(
            [
                "docker",
                "exec",
                name,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-p",
                "5432",
                "-U",
                "fleetdoctor",
                "-d",
                "fleetdoctor",
            ],
            timeout=5,
        )
        if result.returncode == 0:
            try:
                with psycopg.connect(dsn, connect_timeout=2) as connection:
                    if connection.execute("SELECT 1").fetchone() == (1,):
                        return
            except psycopg.Error:
                # pg_isready can race a listener transition; require the real DSN
                # round trip to succeed before initializing PostgresStore.
                pass
        time.sleep(0.25)
    raise RuntimeError("owned PostgreSQL container did not become TCP-ready")


def filesystem() -> Filesystem:
    return Filesystem(
        mountpoint="/",
        total_bytes=100,
        free_bytes=90,
        available_bytes=90,
        used_bytes=10,
        block_usage_percent=10,
        inodes_total=100,
        inodes_free=90,
        inode_usage_percent=10,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker-user", default="nobody")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("native OOM smoke requires a root Linux cgroup-v2 host")
    if args.output.exists():
        raise FileExistsError("refusing to overwrite OOM proof report")
    helper_script = Path(__file__).resolve().parents[1] / "deploy/memory_resource.py"
    helper_sha256 = hashlib.sha256(helper_script.read_bytes()).hexdigest()
    token = secrets.token_hex(16)
    container = "fleetdoctor-oom-proof-" + token[:12]
    port = free_port()
    password = secrets.token_hex(24)
    reader_password = secrets.token_hex(24)
    report: dict[str, Any] = {
        "status": "failed",
        "environment": {
            "kernel": os.uname().release,
            "python": sys.version,
            "uid": os.geteuid(),
        },
        "token": token,
        "helper_sha256": helper_sha256,
        "source_manifest": source_manifest(),
        "events": [],
        "cleanup": {},
    }
    prepared = False
    postgres_started = False
    failure: BaseException | None = None
    scenario_passed = False
    try:
        docker = command(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                container,
                "--publish",
                f"127.0.0.1:{port}:5432",
                "--env",
                "POSTGRES_DB=fleetdoctor",
                "--env",
                "POSTGRES_USER=fleetdoctor",
                "--env",
                "POSTGRES_PASSWORD=" + password,
                "postgres:17.6-alpine",
            ],
            timeout=60,
        )
        if docker.returncode:
            raise RuntimeError("failed to start owned PostgreSQL proof container")
        postgres_started = True
        dsn = f"host=127.0.0.1 port={port} dbname=fleetdoctor user=fleetdoctor password={password}"
        wait_postgres(container, dsn)
        store = PostgresStore(dsn, reader_password)
        prepared_record = helper(helper_script, "prepare", token)
        prepared = True
        cgroup = str(prepared_record["leaf_path"])
        boot_text = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if (
            prepared_record.get("script_sha256") != helper_sha256
            or prepared_record.get("boot_id") != boot_text
            or int(prepared_record.get("available_memory_before", 0)) < 512 * 1024 * 1024
        ):
            raise RuntimeError("helper preparation did not bind source, boot, and host headroom")
        state = Path("/run/fleetdoctor-oom") / (token + ".json")
        state_stat = state.stat()
        if state_stat.st_uid != 0 or state_stat.st_mode & 0o077:
            raise RuntimeError("helper state is not trusted root-owned mode 0600")
        report["prepared"] = prepared_record
        collector = MemoryCollector()
        boot = UUID(boot_text)
        session = uuid4()
        app = create_app(
            {"node-a": SecretStr(TOKEN_VALUE)},
            store=store,
            cgroup_paths=(cgroup,),
        )
        client = TestClient(app)
        sequence = 0

        def observe() -> tuple[dict[str, Any], Any]:
            nonlocal sequence
            memory = collector.collect((cgroup,))
            value = make_sample(
                "node-a",
                boot,
                session,
                sequence,
                [filesystem()],
                datetime.now(UTC),
                cpu=CpuObservation(errors=["native_smoke_cpu_not_sampled"]),
                memory=memory,
            )
            response = client.post(
                "/ingest",
                headers={"Authorization": "Bearer " + TOKEN_VALUE},
                content=value.model_dump_json(),
            )
            if response.status_code != 200 or response.json()["status"] != "accepted":
                raise RuntimeError(f"native observation rejected: {response.text}")
            sequence += 1
            record = memory.workloads[0]
            event = {
                "sequence": sequence - 1,
                "observed_at": value.observed_at.isoformat(),
                "current_bytes": record.current_bytes,
                "limit_bytes": record.max_bytes,
                "usage_ratio": record.usage_ratio,
                "oom": record.events.oom if record.events else None,
                "oom_kill": record.events.oom_kill if record.events else None,
                "stable": record.events_stable,
            }
            report["events"].append(event)
            return event, response

        baseline, _ = observe()
        started = helper(
            helper_script,
            "start",
            token,
            "--allocation-bytes",
            str(96 * 1024 * 1024),
            "--limit-bytes",
            str(48 * 1024 * 1024),
            "--seconds",
            "60",
            "--worker-user",
            args.worker_user,
        )
        report["started"] = started
        limits = started.get("limits") or {}
        caller = str(started.get("caller_cgroup", ""))
        monitors = started.get("monitor_control_groups") or {}
        if (
            limits.get("memory.max") != str(48 * 1024 * 1024)
            or limits.get("memory.swap.max") != "0"
            or limits.get("pids.max") != "4"
            or cgroup in caller
            or any(
                group == cgroup or str(group).startswith(cgroup + "/")
                for group in monitors.values()
                if group is not None
            )
        ):
            raise RuntimeError("helper limits or monitoring separation proof is invalid")
        deadline = time.monotonic() + 45
        triggered: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            time.sleep(0.25)
            observed, _ = observe()
            if (
                observed["oom_kill"] is not None
                and baseline["oom_kill"] is not None
                and observed["oom_kill"] > baseline["oom_kill"]
            ):
                triggered = observed
                break
        if triggered is None:
            raise RuntimeError("real local oom_kill counter did not advance")
        death_deadline = time.monotonic() + 10
        helper_status: dict[str, Any] | None = None
        while time.monotonic() < death_deadline:
            helper_status = helper(helper_script, "status", token)
            if (
                helper_status["events"]["oom_kill"] > baseline["oom_kill"]
                and not helper_status["processes"]
            ):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("allocator did not die from the kernel OOM before controller stop")
        active = client.get("/diagnoses", params={"rule": "workload_oom", "status": "active"})
        if active.status_code != 200 or active.json()["total"] != 1:
            raise RuntimeError("native OOM did not create one persisted active incident")
        incident_id = active.json()["diagnoses"][0]["id"]
        stopped = helper(helper_script, "stop", token)
        report["stopped"] = stopped
        report["stopped_again"] = helper(helper_script, "stop", token)
        for _ in range(3):
            time.sleep(0.1)
            observe()
        resolved = client.get(f"/diagnoses/{incident_id}")
        if resolved.status_code != 200 or resolved.json()["status"] != "resolved":
            raise RuntimeError(
                "native persisted incident did not resolve from three fresh observations"
            )
        helper_status = helper(helper_script, "status", token)
        if helper_status["events"]["oom_kill"] <= baseline["oom_kill"]:
            raise RuntimeError("helper ground truth did not retain the real kernel kill counter")
        report.update(
            cgroup_path=cgroup,
            generation=prepared_record["generation"],
            incident=resolved.json(),
            native_ground_truth={
                "baseline_oom_kill": baseline["oom_kill"],
                "final_oom_kill": helper_status["events"]["oom_kill"],
                "allocator_absent_before_stop": True,
                "allocator_absent_after_stop": not helper_status["processes"],
                "finite_memory_max": helper_status["limits"]["memory.max"],
                "swap_max": helper_status["limits"]["memory.swap.max"],
                "production_memory_collector": True,
                "postgres_persistence": True,
                "api_lifecycle": True,
            },
        )
        scenario_passed = True
    except BaseException as exc:
        failure = exc
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if prepared:
            try:
                report["cleanup"]["stop"] = helper(helper_script, "stop", token)
            except BaseException as exc:
                report["cleanup"]["stop_error"] = f"{type(exc).__name__}: {exc}"
                if failure is None:
                    failure = exc
            try:
                report["cleanup"]["release"] = helper(helper_script, "release", token)
            except BaseException as exc:
                report["cleanup"]["release_error"] = f"{type(exc).__name__}: {exc}"
                if failure is None:
                    failure = exc
            try:
                report["cleanup"]["release_again"] = helper(helper_script, "release", token)
                absent = helper(helper_script, "status", token)
                state_root = Path("/run/fleetdoctor-oom")
                if (
                    absent.get("state") != "absent"
                    or (state_root / (token + ".json")).exists()
                    or (state_root / (token + ".gate")).exists()
                ):
                    raise RuntimeError("helper cleanup retained trusted state or placement gate")
                report["cleanup"]["state_and_gate_removed"] = True
            except BaseException as exc:
                report["cleanup"]["verification_error"] = f"{type(exc).__name__}: {exc}"
                if failure is None:
                    failure = exc
        if postgres_started:
            try:
                removed = command(["docker", "rm", "--force", container], timeout=30)
                if removed.returncode:
                    raise RuntimeError("owned PostgreSQL proof container cleanup failed")
                report["cleanup"]["postgres_removed"] = True
            except BaseException as exc:
                report["cleanup"]["postgres_removed"] = False
                report["cleanup"]["postgres_error"] = f"{type(exc).__name__}: {exc}"
                if failure is None:
                    failure = exc
        report["status"] = "passed" if scenario_passed and failure is None else "failed"
        report["source_manifest_after"] = source_manifest()
        if report["source_manifest"] != report["source_manifest_after"]:
            source_failure = RuntimeError("source changed during native OOM smoke")
            report["status"] = "failed"
            if failure is None:
                failure = source_failure
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if failure is not None:
        raise RuntimeError(
            "native OOM smoke failed; retained report: " + str(args.output)
        ) from failure


if __name__ == "__main__":
    main()
