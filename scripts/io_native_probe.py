"""Linux-side actual-systemd Ticket11 lifecycle using the production agent and owned helper."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from chaos_harness import source_manifest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import io_resource as helper  # noqa: E402


def run(*args: str, timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(args)}: {result.stderr[-2000:]}")
    return result


def write_private(path: Path, text: str, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())


def unit_text(*, name: str, node: str, url: str, env: Path, credential: Path, io_mount: str) -> str:
    return f"""[Unit]
Description=FleetDoctor Ticket11 owned actual-systemd agent {name}
After=network-online.target

[Service]
Type=simple
User=nobody
EnvironmentFile={env}
LoadCredential=ingest-token:{credential}
ExecStart={sys.executable} -m fleetdoctor.agent
ExecStartPre=/bin/sh {ROOT / "deploy/check-agent-mount.sh"}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryMax=100M
TasksMax=16
UMask=0077
Environment=FLEETDOCTOR_NODE_ID={node}
Environment=FLEETDOCTOR_COLLECTOR_URL={url}
Environment=FLEETDOCTOR_FILESYSTEMS=/
Environment=FLEETDOCTOR_IO_MOUNTS={io_mount}

[Install]
WantedBy=multi-user.target
"""


def get(url: str, path: str, **params: Any) -> dict[str, Any]:
    response = httpx.get(url + path, params=params or None, timeout=3, trust_env=False)
    response.raise_for_status()
    value: dict[str, Any] = response.json()
    return value


def wait_node(url: str, node: str, predicate: Any, timeout: float = 60) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        try:
            latest = get(url, f"/nodes/{node}/metrics")
            if predicate(latest):
                return latest
        except (httpx.HTTPError, ValueError):
            pass
        time.sleep(1)
    raise TimeoutError(f"node predicate deadline: {json.dumps(latest)[-2000:]}")


def healthy_device(device: dict[str, Any]) -> bool:
    return bool(
        device.get("rate_status") == "available"
        and (
            device.get("confirmed_idle") is True
            or (
                device.get("completion_latency_ms") is not None
                and device["completion_latency_ms"] < 10
                and device.get("average_outstanding") is not None
                and device["average_outstanding"] < 0.5
            )
        )
    )


def actual_systemd_envelope_probe(unit: str, token: str) -> dict[str, Any]:
    host_tmp = Path("/tmp") / f"fleetdoctor-envelope-{token}"
    if host_tmp.exists() or host_tmp.is_symlink():
        raise FileExistsError("envelope host temporary path already exists")
    command = [
        "systemd-run",
        f"--unit={unit}",
        "--wait",
        "--pipe",
        "--property=User=nobody",
        "--property=NoNewPrivileges=true",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=true",
        "--property=PrivateTmp=true",
        "--property=ProtectKernelTunables=true",
        "--property=ProtectKernelModules=true",
        "--property=ProtectControlGroups=true",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "--property=MemoryMax=100M",
        "--property=TasksMax=16",
        "--property=UMask=0077",
        "--property=RuntimeMaxSec=20",
        sys.executable,
        str(ROOT / "scripts/service_envelope_probe.py"),
        "--token",
        token,
    ]
    result = run(*command, timeout=30, check=False)
    lines = [line for line in result.stdout.splitlines() if line.strip().startswith("{")]
    value = json.loads(lines[-1]) if lines else None
    host_tmp_absent = not host_tmp.exists() and not host_tmp.is_symlink()
    receipt = {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout[-8000:],
        "stderr": result.stderr[-8000:],
        "probe": value,
        "private_tmp_hidden_from_host": host_tmp_absent,
    }
    if result.returncode or not isinstance(value, dict) or not host_tmp_absent:
        raise AssertionError(
            "actual systemd security envelope probe failed: " + json.dumps(receipt)
        )
    return receipt


def actual_systemd_supervisor_probe(unit: str, token: str) -> dict[str, Any]:
    command = [
        "systemd-run",
        f"--unit={unit}",
        "--wait",
        "--pipe",
        "--property=User=nobody",
        "--property=NoNewPrivileges=true",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=true",
        "--property=PrivateTmp=true",
        "--property=ProtectKernelTunables=true",
        "--property=ProtectKernelModules=true",
        "--property=ProtectControlGroups=true",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "--property=MemoryMax=100M",
        "--property=TasksMax=16",
        "--property=UMask=0077",
        "--property=RuntimeMaxSec=30",
        "--setenv=PYTHONDONTWRITEBYTECODE=1",
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-s",
        "-p",
        "no:cacheprovider",
        "--basetemp",
        f"/tmp/fleetdoctor-supervisor-{token}",
        str(ROOT / "tests/test_supervisor.py"),
        "-k",
        "production_io_stall or partial_io_frame",
    ]
    result = run(*command, timeout=40, check=False)
    measurements: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        start = line.find('{"probe":')
        if start >= 0:
            measurements.append(json.loads(line[start:]))
    receipt = {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout[-12000:],
        "stderr": result.stderr[-12000:],
        "measurements": measurements,
    }
    if (
        result.returncode
        or "2 passed" not in result.stdout
        or {item.get("probe") for item in measurements}
        != {"production_io_stall", "partial_io_frame"}
        or any(float(item.get("collect_all_seconds", 3)) >= 3 for item in measurements)
    ):
        raise AssertionError("actual systemd supervisor probe failed: " + json.dumps(receipt))
    return receipt


def actual_systemd_resource_probe(unit: str) -> dict[str, Any]:
    command = [
        "systemd-run",
        f"--unit={unit}",
        "--wait",
        "--pipe",
        "--property=User=nobody",
        "--property=NoNewPrivileges=true",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=true",
        "--property=PrivateTmp=true",
        "--property=ProtectKernelTunables=true",
        "--property=ProtectKernelModules=true",
        "--property=ProtectControlGroups=true",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "--property=MemoryMax=100M",
        "--property=TasksMax=16",
        "--property=UMask=0077",
        "--property=RuntimeMaxSec=60",
        "--setenv=PYTHONDONTWRITEBYTECODE=1",
        sys.executable,
        str(ROOT / "scripts/dns_history_resource_probe.py"),
    ]
    result = run(*command, timeout=75, check=False)
    properties = run(
        "systemctl",
        "show",
        unit,
        "-p",
        "Result,ExecMainStatus,MemoryMax,MemoryPeak,TasksMax,TasksCurrent",
        "--no-pager",
        check=False,
    )
    lines = [line for line in result.stdout.splitlines() if line.strip().startswith("{")]
    value = json.loads(lines[-1]) if lines else None
    receipt = {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout[-16000:],
        "stderr": result.stderr[-16000:],
        "probe": value,
        "systemd_properties": properties.stdout,
    }
    if result.returncode or not isinstance(value, dict) or value.get("status") != "passed":
        raise AssertionError("actual systemd resource probe failed: " + json.dumps(receipt))
    return receipt


def actual_cli_lifecycle_probe(token: str, native_root: Path) -> dict[str, Any]:
    helper_path = ROOT / "deploy/io_resource.py"

    def cli(action: str, duration: int | None = None) -> dict[str, Any]:
        command = [sys.executable, str(helper_path), action, token]
        if duration is not None:
            command.extend(("--duration", str(duration)))
        result = run(*command, timeout=40, check=False)
        if result.returncode:
            raise RuntimeError(
                "normal helper CLI failed: "
                + json.dumps({"command": command, "stdout": result.stdout, "stderr": result.stderr})
            )
        value: dict[str, Any] = json.loads(result.stdout)
        return value

    started = cli("start", 25)
    if (
        started.get("phase") != "running"
        or started.get("controller_pid") != os.getpid()
        or started.get("controller_start") != helper.process_start(os.getpid())
        or started.get("controller_source") != "caller_parent"
    ):
        raise AssertionError("normal helper CLI did not bind its live caller")
    sustained: list[dict[str, Any]] = []
    worker_identity = (
        started.get("worker_pid"),
        started.get("worker_start"),
        started.get("worker_pgid"),
    )
    for index in range(4):
        current = cli("status")
        sustained.append(
            {
                "elapsed_seconds": time.monotonic() - float(started["deadline_monotonic"]) + 25,
                "phase": current.get("phase"),
                "worker_pid": current.get("worker_pid"),
            }
        )
        if current.get("phase") != "running" or not helper.process_owned(*worker_identity):
            raise AssertionError("normal helper CLI workload did not remain live")
        if index < 3:
            time.sleep(5.1)
    stopped = cli("cleanup")
    if stopped.get("phase") != "stopped" or helper.process_owned(*worker_identity):
        raise AssertionError("normal helper CLI cleanup did not reap its worker")

    ready = native_root / "cli-controller-ready.json"
    if ready.exists() or ready.is_symlink():
        raise FileExistsError("CLI controller ready path already exists")
    controller = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "scripts/io_cli_controller_probe.py"),
            "--helper",
            str(helper_path),
            "--token",
            token,
            "--duration",
            "30",
            "--ready",
            str(ready),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    interruption: dict[str, Any] = {}
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < deadline:
            if controller.poll() is not None:
                stdout, stderr = controller.communicate()
                raise RuntimeError(f"CLI controller exited before readiness: {stdout} {stderr}")
            time.sleep(0.1)
        if not ready.exists() or ready.is_symlink():
            raise TimeoutError("CLI controller readiness deadline")
        ready_info = ready.lstat()
        value = json.loads(ready.read_text())
        record = value["record"]
        if (
            value.get("pid") != controller.pid
            or record.get("controller_pid") != controller.pid
            or record.get("controller_source") != "caller_parent"
            or record.get("phase") != "running"
        ):
            raise AssertionError("CLI controller authority record mismatch")
        controller.terminate()
        controller.wait(timeout=5)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            current = helper.load(token)
            if (
                current.get("phase") == "stopped"
                and not helper.LEASE.exists()
                and not helper.process_owned(
                    record.get("worker_pid"),
                    record.get("worker_start"),
                    record.get("worker_pgid"),
                )
                and not helper.process_owned(
                    record.get("watchdog_pid"),
                    record.get("watchdog_start"),
                    record.get("watchdog_pgid"),
                )
            ):
                interruption = {
                    "controller_pid": controller.pid,
                    "controller_exit": controller.returncode,
                    "record": current,
                }
                break
            time.sleep(0.2)
        else:
            raise TimeoutError("CLI caller interruption cleanup deadline")
        if ready.lstat().st_ino != ready_info.st_ino or ready_info.st_uid != 0:
            raise ValueError("CLI controller ready identity changed")
        ready.unlink()
    finally:
        if controller.poll() is None:
            controller.terminate()
            try:
                controller.wait(timeout=3)
            except subprocess.TimeoutExpired:
                controller.kill()
                controller.wait(timeout=3)
        if ready.exists() and not ready.is_symlink() and ready.lstat().st_uid == 0:
            ready.unlink()
    return {
        "normal_start": started,
        "sustained_statuses": sustained,
        "normal_cleanup": stopped,
        "caller_interruption": interruption,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--api", required=True)
    parser.add_argument("--tokens-stdin", action="store_true", required=True)
    parser.add_argument("--run-token", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or len(args.run_token) != 32:
        raise ValueError("native probe requires root and a strong run token")
    token_document = sys.stdin.read(8193)
    if len(token_document.encode()) > 8192:
        raise ValueError("token document exceeds 8KiB")
    tokens = json.loads(token_document)
    if set(tokens) != {"node-a", "node-b"} or any(
        not isinstance(value, str) or len(value) < 32 for value in tokens.values()
    ):
        raise ValueError("native probe requires exactly two strong node tokens")
    suffix = args.run_token[:12]
    target_unit = f"fleetdoctor-io-target-{suffix}.service"
    reference_unit = f"fleetdoctor-io-reference-{suffix}.service"
    envelope_unit = f"fleetdoctor-io-envelope-{suffix}.service"
    supervisor_unit = f"fleetdoctor-io-supervisor-{suffix}.service"
    resource_unit = f"fleetdoctor-io-resource-{suffix}.service"
    native_root = ROOT.parent / "probe"
    report: dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "api": args.api,
        "units": [target_unit, reference_unit],
        "run_token": args.run_token,
        "events": [],
        "cleanup": [],
        "production_agent": True,
        "actual_systemd": True,
    }
    prepared = False
    unit_inodes: dict[str, int] = {}
    cleanup_exception: BaseException | None = None
    try:
        if native_root.exists() or native_root.is_symlink():
            raise FileExistsError("owned native probe directory already exists")
        native_root.mkdir(mode=0o755)
        report["linux_source_before"] = source_manifest()
        target_env = native_root / "target.env"
        reference_env = native_root / "reference.env"
        target_credential = native_root / "target.token"
        reference_credential = native_root / "reference.token"
        write_private(target_env, "FLEETDOCTOR_CPU_PIDS=\nFLEETDOCTOR_CGROUPS=\n")
        write_private(reference_env, "FLEETDOCTOR_CPU_PIDS=\nFLEETDOCTOR_CGROUPS=\n")
        write_private(target_credential, tokens["node-a"] + "\n")
        write_private(reference_credential, tokens["node-b"] + "\n")
        with helper.locked():
            resource = helper.prepare(args.run_token)
        prepared = True
        report["resource"] = resource
        units = {
            target_unit: unit_text(
                name="target",
                node="node-a",
                url=args.api,
                env=target_env,
                credential=target_credential,
                io_mount=str(helper.TARGET),
            ),
            reference_unit: unit_text(
                name="reference",
                node="node-b",
                url=args.api,
                env=reference_env,
                credential=reference_credential,
                io_mount=str(helper.REFERENCE_TARGET),
            ),
        }
        for name, text in units.items():
            path = Path("/run/systemd/system") / name
            write_private(path, text, 0o644)
            unit_inodes[name] = path.stat().st_ino
        run("systemctl", "daemon-reload")
        run("systemctl", "start", target_unit, reference_unit)
        healthy_baselines: dict[str, list[dict[str, Any]]] = {"node-a": [], "node-b": []}
        baseline_deadline = time.monotonic() + 45
        while time.monotonic() < baseline_deadline and any(
            len(values) < 3 for values in healthy_baselines.values()
        ):
            for node in ("node-a", "node-b"):
                view = get(args.api, f"/nodes/{node}/metrics")
                report.setdefault("latest_baseline_views", {})[node] = view
                devices = (view.get("io") or {}).get("devices", [])
                sample = view.get("sample") or {}
                identity = (
                    sample.get("boot_id"),
                    sample.get("agent_session_id"),
                    sample.get("sequence"),
                    sample.get("observed_at"),
                )
                rows = healthy_baselines[node]
                if (
                    view.get("fresh")
                    and view.get("active_incident_count") == 0
                    and len(devices) == 1
                    and healthy_device(devices[0])
                    and identity
                    not in {
                        (
                            row["sample"]["boot_id"],
                            row["sample"]["agent_session_id"],
                            row["sample"]["sequence"],
                            row["sample"]["observed_at"],
                        )
                        for row in rows
                    }
                ):
                    rows.append(view)
            time.sleep(1)
        if any(len(values) < 3 for values in healthy_baselines.values()):
            diagnostics: dict[str, Any] = {}
            for unit, mountpoint in (
                (target_unit, str(helper.TARGET)),
                (reference_unit, str(helper.REFERENCE_TARGET)),
            ):
                pid = int(run("systemctl", "show", unit, "-p", "MainPID", "--value").stdout.strip())
                diagnostics[unit] = {
                    "pid": pid,
                    "namespace": os.readlink(f"/proc/{pid}/ns/mnt"),
                    "mountinfo": [
                        line
                        for line in Path(f"/proc/{pid}/mountinfo").read_text().splitlines()
                        if mountpoint in line
                    ],
                    "findmnt": run(
                        "findmnt",
                        "--json",
                        "--task",
                        str(pid),
                        "--target",
                        mountpoint,
                        "-o",
                        "SOURCE,TARGET,FSROOT,FSTYPE,MAJ:MIN",
                        check=False,
                    ).stdout,
                }
            report["mount_namespace_diagnostics"] = diagnostics
            raise TimeoutError("three distinct healthy target/reference baselines unavailable")
        target_device = healthy_baselines["node-a"][-1]["io"]["devices"][0]
        reference_device = healthy_baselines["node-b"][-1]["io"]["devices"][0]
        if target_device["resource"] == reference_device["resource"]:
            raise AssertionError("target and reference must use separate durable resources")
        report["healthy_baselines"] = healthy_baselines
        report["frozen_measurement"] = {
            "target_resource": target_device["resource"],
            "target_mapping": target_device,
            "reference_resource": reference_device["resource"],
            "reference_mapping": reference_device,
            "rule_configuration": {
                "trigger_latency_ms": 20,
                "trigger_outstanding": 1,
                "recovery_latency_ms": 10,
                "recovery_outstanding": 0.5,
                "consecutive_samples": 3,
                "max_gap_seconds": 10,
                "severity": "warning",
            },
            "resource_record": resource,
            "source_manifest": report["linux_source_before"],
        }
        report["namespace_before_restart"] = target_device["mount_namespace"]
        report["injection_requested"] = {
            "monotonic": time.monotonic(),
            "utc": datetime.now(UTC).isoformat(),
        }
        with helper.locked():
            started = helper.start(args.run_token, 45)
        report["workload_start"] = started
        first_trigger: dict[str, Any] | None = None
        trigger_completed = None
        diagnosis_deadline = None
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            view = get(args.api, "/nodes/node-a/metrics")
            target_completed = time.monotonic()
            ref = get(args.api, "/nodes/node-b/metrics")
            ref_devices = (ref.get("io") or {}).get("devices", [])
            if (
                not ref.get("fresh")
                or ref.get("active_incident_count") != 0
                or len(ref_devices) != 1
                or ref_devices[0].get("resource") != reference_device["resource"]
                or not healthy_device(ref_devices[0])
            ):
                raise AssertionError("healthy reference failed during I/O injection")
            devices = (view.get("io") or {}).get("devices", [])
            eligible = next(
                (
                    item
                    for item in devices
                    if item.get("resource") == target_device["resource"]
                    and item.get("rate_status") == "available"
                    and (item.get("completion_latency_ms") or 0) >= 20
                    and (item.get("average_outstanding") or 0) >= 1
                ),
                None,
            )
            if eligible is not None and first_trigger is None:
                first_trigger = eligible
                trigger_completed = target_completed
                diagnosis_deadline = trigger_completed + 60
            active = get(
                args.api,
                "/diagnoses",
                node="node-a",
                rule="io_bottleneck",
                status="active",
                limit=100,
            )["diagnoses"]
            matching = next(
                (
                    item
                    for item in active
                    if item.get("node_id") == "node-a"
                    and item.get("rule") == "io_bottleneck"
                    and item.get("resource") == target_device["resource"]
                    and item.get("status") == "active"
                ),
                None,
            )
            if first_trigger is not None and matching is not None:
                detail = get(args.api, "/diagnoses/" + matching["id"])
                detail_completed = time.monotonic()
                if diagnosis_deadline is None or detail_completed > diagnosis_deadline:
                    raise TimeoutError("matching diagnosis detail completed after shared deadline")
                if (
                    detail.get("node_id") != "node-a"
                    or detail.get("rule") != "io_bottleneck"
                    or detail.get("resource") != target_device["resource"]
                    or detail.get("configuration")
                    != report["frozen_measurement"]["rule_configuration"]
                    or detail.get("opening_evidence", {}).get("resource")
                    != target_device["resource"]
                ):
                    raise AssertionError("diagnosis detail does not match frozen opening contract")
                report["first_trigger"] = first_trigger
                report["diagnosis"] = detail
                assert trigger_completed is not None
                report["trigger_to_diagnosis_seconds"] = detail_completed - trigger_completed
                report["injection_to_diagnosis_seconds"] = (
                    detail_completed - report["injection_requested"]["monotonic"]
                )
                report["diagnosis_detail_response_completed_monotonic"] = detail_completed
                break
            if diagnosis_deadline is not None and time.monotonic() >= diagnosis_deadline:
                raise TimeoutError("shared diagnosis deadline")
            time.sleep(1)
        else:
            raise TimeoutError("qualifying observation/diagnosis deadline")
        report["workload_envelope"] = run(
            "systemctl",
            "show",
            target_unit,
            "-p",
            "User,NoNewPrivileges,MemoryMax,MemoryPeak,TasksMax,TasksCurrent,PrivateTmp,ProtectSystem,RestrictAddressFamilies,MainPID,MemoryLimit,TasksAccounting,MemoryAccounting",
        ).stdout
        main_pid = int(
            run("systemctl", "show", target_unit, "-p", "MainPID", "--value").stdout.strip()
        )
        status_lines = Path(f"/proc/{main_pid}/status").read_text().splitlines()
        report["effective_process_envelope"] = {
            line.split(":", 1)[0]: line.split(":", 1)[1].strip()
            for line in status_lines
            if line.split(":", 1)[0] in {"Uid", "Gid", "CapEff", "NoNewPrivs", "Seccomp"}
        }
        report["effective_process_envelope"].update(
            {
                "pid": main_pid,
                "mount_namespace": os.readlink(f"/proc/{main_pid}/ns/mnt"),
                "private_tmp_mounts": [
                    line
                    for line in Path(f"/proc/{main_pid}/mountinfo").read_text().splitlines()
                    if "/tmp" in line or "/var/tmp" in line
                ],
            }
        )
        try:
            report["actual_systemd_security_envelope"] = actual_systemd_envelope_probe(
                envelope_unit, args.run_token
            )
        finally:
            run("systemctl", "stop", envelope_unit, timeout=20, check=False)
            run("systemctl", "reset-failed", envelope_unit, timeout=20, check=False)
        try:
            report["actual_systemd_supervisor_envelope"] = actual_systemd_supervisor_probe(
                supervisor_unit, args.run_token
            )
        finally:
            run("systemctl", "stop", supervisor_unit, timeout=20, check=False)
            run("systemctl", "reset-failed", supervisor_unit, timeout=20, check=False)
        try:
            report["actual_systemd_maximum_resource_envelope"] = actual_systemd_resource_probe(
                resource_unit
            )
        finally:
            run("systemctl", "stop", resource_unit, timeout=20, check=False)
            run("systemctl", "reset-failed", resource_unit, timeout=20, check=False)
        stop_instant = time.monotonic()
        with helper.locked():
            cleanup = helper.cleanup_workload(args.run_token)
        report["stop_monotonic"] = stop_instant
        report["workload_cleanup"] = cleanup
        cleanup_complete = time.monotonic()
        report["cleanup_complete_monotonic"] = cleanup_complete
        report["recovery_boundary_monotonic"] = stop_instant
        recovery_deadline = stop_instant + 60
        old_main_pid = main_pid
        old_namespace_descriptor = os.open(f"/proc/{old_main_pid}/ns/mnt", os.O_RDONLY)
        run("systemctl", "stop", target_unit)
        if Path(f"/proc/{old_main_pid}").exists():
            raise AssertionError("old production agent survived explicit stop")
        target_unit_path = Path("/run/systemd/system") / target_unit
        target_unit_info = target_unit_path.lstat()
        if (
            target_unit_path.is_symlink()
            or not target_unit_path.is_file()
            or target_unit_info.st_uid != 0
            or target_unit_info.st_ino != unit_inodes[target_unit]
        ):
            raise ValueError("target unit identity changed before namespace recreation")
        target_unit_path.unlink()
        run("systemctl", "daemon-reload")
        write_private(target_unit_path, units[target_unit], 0o644)
        unit_inodes[target_unit] = target_unit_path.stat().st_ino
        run("systemctl", "daemon-reload")
        run("systemctl", "start", target_unit)
        report["restart_properties"] = run(
            "systemctl",
            "show",
            target_unit,
            "-p",
            "User,NoNewPrivileges,MemoryMax,TasksMax,PrivateTmp,ProtectSystem,RestrictAddressFamilies,MemoryPeak,TasksCurrent",
        ).stdout
        incident_id = report["diagnosis"]["id"]
        idle_identities: list[dict[str, Any]] = []
        previous_identity: tuple[str, str, int, str] | None = None
        while time.monotonic() < recovery_deadline:
            view = get(args.api, "/nodes/node-a/metrics")
            ref = get(args.api, "/nodes/node-b/metrics")
            ref_devices = (ref.get("io") or {}).get("devices", [])
            if (
                not ref.get("fresh")
                or ref.get("active_incident_count") != 0
                or len(ref_devices) != 1
                or ref_devices[0].get("resource") != reference_device["resource"]
                or not healthy_device(ref_devices[0])
            ):
                raise AssertionError("healthy reference failed during recovery")
            devices = (view.get("io") or {}).get("devices", [])
            device = next(
                (item for item in devices if item.get("resource") == target_device["resource"]),
                None,
            )
            sample = view.get("sample") or {}
            identity = (
                str(sample.get("boot_id")),
                str(sample.get("agent_session_id")),
                int(sample.get("sequence", 0)),
                str(sample.get("observed_at")),
            )
            replay = previous_identity is not None and identity == previous_identity
            valid_new = bool(
                view.get("fresh")
                and device is not None
                and healthy_device(device)
                and not replay
                and (
                    previous_identity is None
                    or (
                        identity[0] == previous_identity[0]
                        and identity[1] == previous_identity[1]
                        and identity[2] > previous_identity[2]
                        and (
                            datetime.fromisoformat(identity[3])
                            - datetime.fromisoformat(previous_identity[3])
                        ).total_seconds()
                        <= 10
                    )
                )
            )
            if valid_new:
                assert device is not None
                idle_identities.append(
                    {"identity": identity, "device": device, "response_completed": time.monotonic()}
                )
                previous_identity = identity
                if len(idle_identities) == 1:
                    report["namespace_after_restart"] = device["mount_namespace"]
            elif not replay:
                idle_identities = []
                previous_identity = None
            detail = get(args.api, "/diagnoses/" + incident_id)
            detail_completed = time.monotonic()
            if detail["status"] == "superseded":
                raise AssertionError("superseded incident is not healthy recovery")
            if detail["status"] == "resolved" and len(idle_identities) >= 3:
                if detail_completed > recovery_deadline:
                    raise TimeoutError("resolved detail completed after recovery deadline")
                if detail.get("resource") != target_device["resource"]:
                    raise AssertionError("resolved detail changed durable resource")
                report["resolved"] = detail
                report["idle_identities"] = idle_identities
                report["recovery_elapsed_seconds"] = detail_completed - stop_instant
                break
            time.sleep(1)
        else:
            raise TimeoutError("automatic recovery deadline")
        if report.get("namespace_after_restart") == report["namespace_before_restart"]:
            raise AssertionError("service restart did not recreate the mount namespace")
        os.close(old_namespace_descriptor)
        report["unit_status"] = {
            name: run(
                "systemctl", "show", name, "-p", "ActiveState,SubState,MainPID,ExecMainStatus"
            ).stdout
            for name in units
        }
        report["journal"] = {
            name: run("journalctl", "-u", name, "--no-pager", "-n", "100", check=False).stdout
            for name in units
        }
        report["native_cli_lifecycle"] = actual_cli_lifecycle_probe(args.run_token, native_root)
        activation = helper.STATE / f"worker-{args.run_token}.activate"
        write_private(activation, "foreign partial activation\n")
        foreign_inode = activation.stat().st_ino
        foreign_bytes = activation.read_bytes()
        try:
            with helper.locked():
                helper.start(args.run_token, 15)
        except BaseException as exc:
            partial = helper.status(args.run_token)
            if helper.LEASE.exists() or helper.process_owned(
                partial.get("worker_pid"),
                partial.get("worker_start"),
                partial.get("worker_pgid"),
            ):
                raise AssertionError("partial activation left authority or worker") from exc
            report["native_partial_activation_rollback"] = {
                "failure": repr(exc),
                "record": partial,
                "foreign_bytes_preserved": activation.read_bytes() == foreign_bytes,
                "foreign_inode_preserved": activation.stat().st_ino == foreign_inode,
            }
            if (
                activation.read_bytes() != foreign_bytes
                or activation.stat().st_ino != foreign_inode
            ):
                raise AssertionError("foreign activation state was changed on refusal") from exc
        else:
            raise AssertionError("partial activation fault unexpectedly succeeded")
        activation.unlink()
        real_atomic = helper.atomic

        def fail_after_child_start(path: Path, value: dict[str, Any]) -> None:
            if path == activation:
                raise OSError("native injected activation persistence failure")
            real_atomic(path, value)

        helper.atomic = fail_after_child_start
        try:
            with helper.locked():
                helper.start(args.run_token, 15)
        except BaseException as exc:
            failed_status = helper.load(args.run_token)
            if (
                helper.LEASE.exists()
                or helper.process_owned(
                    failed_status.get("worker_pid"),
                    failed_status.get("worker_start"),
                    failed_status.get("worker_pgid"),
                )
                or helper.process_owned(
                    failed_status.get("watchdog_pid"),
                    failed_status.get("watchdog_start"),
                    failed_status.get("watchdog_pgid"),
                )
            ):
                raise AssertionError("after-child-start fault left authority or process") from exc
            report["native_after_child_start_rollback"] = {
                "failure": repr(exc),
                "record": failed_status,
            }
        else:
            raise AssertionError("after-child-start persistence fault unexpectedly succeeded")
        finally:
            helper.atomic = real_atomic
        with helper.locked():
            interrupted = helper.start(args.run_token, 20)
        os.killpg(interrupted["worker_pid"], 15)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            interrupted_status = helper.load(args.run_token)
            if (
                interrupted_status.get("phase") == "stopped"
                and not helper.LEASE.exists()
                and not helper.process_owned(
                    interrupted.get("worker_pid"),
                    interrupted.get("worker_start"),
                    interrupted.get("worker_pgid"),
                )
            ):
                report["native_worker_interruption_cleanup"] = interrupted_status
                break
            time.sleep(0.2)
        else:
            raise TimeoutError("watchdog did not clean interrupted worker")
        report["status"] = "passed"
        report["linux_source_after"] = source_manifest()
        if report["linux_source_before"] != report["linux_source_after"]:
            raise AssertionError("Linux-visible source changed during native proof")
    except BaseException as exc:
        report["status"] = "failed"
        report["failure"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        report["final_journal"] = {
            unit: run("journalctl", "-u", unit, "--no-pager", "-n", "120", check=False).stdout
            for unit in (target_unit, reference_unit)
        }
        run("systemctl", "stop", envelope_unit, timeout=20, check=False)
        run("systemctl", "reset-failed", envelope_unit, timeout=20, check=False)
        run("systemctl", "stop", supervisor_unit, timeout=20, check=False)
        run("systemctl", "reset-failed", supervisor_unit, timeout=20, check=False)
        run("systemctl", "stop", resource_unit, timeout=20, check=False)
        run("systemctl", "reset-failed", resource_unit, timeout=20, check=False)
        for unit in (target_unit, reference_unit):
            result = run("systemctl", "stop", unit, timeout=30, check=False)
            report["cleanup"].append({"stop_unit": unit, "exit": result.returncode})
            path = Path("/run/systemd/system") / unit
            if path.exists() or path.is_symlink():
                info = path.lstat()
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or info.st_uid != 0
                    or info.st_ino != unit_inodes.get(unit)
                ):
                    cleanup_exception = ValueError(f"unit replacement refused: {unit}")
                    report["cleanup_failure"] = repr(cleanup_exception)
                    report["status"] = "failed"
                else:
                    path.unlink()
        run("systemctl", "daemon-reload", check=False)
        if prepared:
            try:
                with helper.locked():
                    report["resource_destroy"] = helper.destroy(args.run_token)
                report["cleanup"].append("owned dm/loop/mount/image destroyed")
            except BaseException as exc:
                cleanup_exception = exc
                report["cleanup_failure"] = repr(exc)
                report["status"] = "failed"
        if native_root.exists() and native_root.is_dir() and not native_root.is_symlink():
            shutil.rmtree(native_root)
        report["finished_at"] = datetime.now(UTC).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(temporary, args.output)
        if cleanup_exception is not None and sys.exc_info()[0] is None:
            raise RuntimeError("native exact cleanup failed") from cleanup_exception


if __name__ == "__main__":
    main()
