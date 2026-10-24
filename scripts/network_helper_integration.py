"""Native isolated netem and hardened production-agent proof; never touches host tc."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import secrets
import socket
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import httpx
from chaos_harness import source_manifest, write_report
from create_env import create
from integration_disk import PATH as DISK_PATH
from integration_oom import CGROUP, MISSING_CGROUP
from network_harness import NetworkHarness

ROOT = Path(__file__).resolve().parents[1]
INTERRUPTION_BARRIER_LABEL = "test_driver_after_first_durable_tc_command"
INTERRUPTION_BARRIER_BUDGET_SECONDS = 8.0
INTERRUPTION_RECORD_TIMEOUT_SECONDS = 2.0
INTERRUPTION_KERNEL_TIMEOUT_SECONDS = 2.0
INTERRUPTION_KILL_TIMEOUT_SECONDS = 3.0
INTERRUPTION_WATCHDOG_MARGIN_SECONDS = 5.0
INTERRUPTION_WATCHDOG_DURATION_SECONDS = 30
INTERRUPTION_CLEANUP_BUDGET_SECONDS = 10.0
INTERRUPTED_SETUP_DRIVER = r"""
import json
import os
import signal
import sys
from datetime import UTC, datetime

sys.path.insert(0, "/app/deploy")
import network_resource as helper

token, target, profile, raw_duration = sys.argv[1:]
duration = int(raw_duration)
barrier_path = helper.RUNS / f"{token}.barrier.json"
original_save = helper.save
paused = False

def save_with_barrier(path, record):
    global paused
    original_save(path, record)
    commands = record.get("commands")
    if (
        not paused
        and path == helper.run_path(token)
        and record.get("setup_state") == "starting"
        and record.get("completed_steps") == 1
        and isinstance(commands, list)
        and len(commands) == 1
        and isinstance(commands[0], dict)
        and commands[0].get("returncode") == 0
        and helper.owned_watchdog(record)
    ):
        paused = True
        original_save(
            barrier_path,
            {
                "attribution": "test_driver_after_first_durable_tc_command",
                "created_utc": datetime.now(UTC).isoformat(),
                "token": token,
                "driver_pid": os.getpid(),
                "driver_start": helper.process_start(os.getpid()),
                "watchdog_pid": record["watchdog_pid"],
                "watchdog_start": record["watchdog_start"],
                "setup_state": record["setup_state"],
                "completed_steps": record["completed_steps"],
            },
        )
        os.kill(os.getpid(), signal.SIGSTOP)

helper.save = save_with_barrier
helper.safe_base()
print(json.dumps(helper.start(token, target, profile, duration)))
"""
KILL_INTERRUPTED_DRIVER = r"""
import os
import pathlib
import signal
import sys

pid = int(sys.argv[1])
expected_start = sys.argv[2]
raw = pathlib.Path(f"/proc/{pid}/stat").read_text()
tail = raw[raw.rfind(")") + 2:].split()
if tail[19] != expected_start:
    raise SystemExit("driver process identity changed")
os.kill(pid, signal.SIGKILL)
"""


def collector_base_url(address: str) -> str:
    return f"http://{address}:8000"


def network_prepare_argv(anchor: str, sysctl_dir: Path, image: str) -> list[str]:
    """Run the checked-out mode-0644 preparation script through its interpreter."""
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "container:" + anchor,
        "--privileged",
        "--user",
        "0:0",
        "-v",
        f"{sysctl_dir}:/etc/sysctl.d",
        image,
        "/bin/sh",
        "/app/deploy/network_prepare.sh",
        "fleetdoctor",
    ]


def validate_interruption_barrier(
    token: str,
    barrier: dict[str, Any],
    record: dict[str, Any],
    kernel_qdisc: Any,
) -> tuple[int, str]:
    """Validate the real partial-mutation barrier before killing its exact driver."""
    driver_pid = barrier.get("driver_pid")
    driver_start = barrier.get("driver_start")
    commands = record.get("commands")
    if (
        barrier.get("attribution") != INTERRUPTION_BARRIER_LABEL
        or barrier.get("token") != token
        or not isinstance(driver_pid, int)
        or isinstance(driver_pid, bool)
        or driver_pid <= 1
        or not isinstance(driver_start, str)
        or not driver_start.isdigit()
        or record.get("parent_pid") != driver_pid
        or record.get("parent_start") != driver_start
        or barrier.get("setup_state") != "starting"
        or barrier.get("completed_steps") != 1
        or record.get("token") != token
        or record.get("setup_state") != "starting"
        or record.get("completed_steps") != 1
        or barrier.get("watchdog_pid") != record.get("watchdog_pid")
        or barrier.get("watchdog_start") != record.get("watchdog_start")
        or not isinstance(record.get("watchdog_pid"), int)
        or not isinstance(record.get("watchdog_start"), str)
        or not isinstance(commands, list)
        or len(commands) != 1
        or not isinstance(commands[0], dict)
        or commands[0].get("returncode") != 0
    ):
        raise ValueError("interrupted-setup durable barrier is invalid")
    argv = commands[0].get("argv")
    interface = record.get("interface")
    if (
        not isinstance(argv, list)
        or len(argv) < 9
        or Path(str(argv[0])).name != "tc"
        or argv[1:8] != ["qdisc", "add", "dev", interface, "root", "handle", "1:"]
        or argv[8] != "prio"
        or not isinstance(kernel_qdisc, list)
        or len(kernel_qdisc) != 1
        or not isinstance(kernel_qdisc[0], dict)
        or kernel_qdisc[0].get("kind") != "prio"
        or kernel_qdisc[0].get("handle") != "1:"
        or kernel_qdisc[0].get("root") is not True
    ):
        raise ValueError("interrupted-setup partial tc mutation is not proven")
    return driver_pid, driver_start


def validate_interruption_timing(duration: int, barrier_budget: float) -> float:
    """Require watchdog expiry to remain beyond every bounded pre-kill operation."""
    if (
        not isinstance(duration, int)
        or isinstance(duration, bool)
        or duration < 1
        or duration > 180
        or not isinstance(barrier_budget, (int, float))
        or isinstance(barrier_budget, bool)
        or not math.isfinite(barrier_budget)
        or barrier_budget <= 0
    ):
        raise ValueError("interrupted-setup timing values are invalid")
    pre_kill_bound = (
        float(barrier_budget)
        + INTERRUPTION_RECORD_TIMEOUT_SECONDS
        + INTERRUPTION_KERNEL_TIMEOUT_SECONDS
        + INTERRUPTION_KILL_TIMEOUT_SECONDS
    )
    required_duration = pre_kill_bound + INTERRUPTION_WATCHDOG_MARGIN_SECONDS
    if duration < required_duration:
        raise ValueError("interrupted-setup watchdog duration lacks the required pre-kill margin")
    return pre_kill_bound


def configure_owned_ping_group_range(anchor: str, image: str, range_value: str) -> dict[str, str]:
    """Set and verify one owned network namespace through an ephemeral preparer."""
    parts = range_value.split()
    if (
        len(parts) != 2
        or any(not part.isdigit() for part in parts)
        or " ".join(parts) != range_value
    ):
        raise ValueError("ping_group_range must be two canonical nonnegative integers")

    prefix = [
        "docker",
        "run",
        "--rm",
        "--network",
        "container:" + anchor,
        "--privileged",
        "--user",
        "0:0",
        image,
        "sysctl",
    ]

    def readback() -> str:
        value = " ".join(run([*prefix, "-n", "net.ipv4.ping_group_range"]).stdout.split())
        fields = value.split()
        if len(fields) != 2 or any(not field.isdigit() for field in fields):
            raise RuntimeError("owned ping_group_range readback is malformed")
        return value

    before = readback()
    mutation = run([*prefix, "-w", "net.ipv4.ping_group_range=" + range_value])
    after = readback()
    if after != range_value:
        raise RuntimeError("owned ping_group_range readback does not match requested value")
    return {
        "scope": "owned_anchor_network_namespace_only",
        "preparer": "ephemeral_privileged_root_container",
        "before": before,
        "requested": range_value,
        "write_output": mutation.stdout.strip(),
        "after": after,
    }


def run_interrupted_setup_proof(
    helper_container: str,
    target: str,
    token: str,
    *,
    duration: int = INTERRUPTION_WATCHDOG_DURATION_SECONDS,
    barrier_budget: float = INTERRUPTION_BARRIER_BUDGET_SECONDS,
) -> dict[str, Any]:
    """Kill one exact paused real helper and prove watchdog rollback."""
    pre_kill_bound = validate_interruption_timing(duration, barrier_budget)
    barrier_path = f"/run/fleetdoctor/network/runs/{token}.barrier.json"
    record_path = f"/run/fleetdoctor/network/runs/{token}.json"
    driver = subprocess.Popen(
        [
            "docker",
            "exec",
            helper_container,
            "/app/.venv/bin/python",
            "-c",
            INTERRUPTED_SETUP_DRIVER,
            token,
            target,
            "latency",
            str(duration),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    barrier: dict[str, Any] | None = None
    driver_pid: int | None = None
    driver_start: str | None = None
    killed = False
    try:
        deadline = time.monotonic() + barrier_budget
        while time.monotonic() < deadline:
            value = run(
                ["docker", "exec", helper_container, "cat", barrier_path],
                timeout=1,
                check=False,
            )
            if value.returncode == 0:
                parsed = json.loads(value.stdout)
                if not isinstance(parsed, dict):
                    raise ValueError("interrupted-setup barrier is not an object")
                barrier = parsed
                break
            if driver.poll() is not None:
                break
            time.sleep(0.02)
        if barrier is None:
            raise TimeoutError("durable interrupted-setup barrier was not reached")
        record_result = run(
            ["docker", "exec", helper_container, "cat", record_path],
            timeout=INTERRUPTION_RECORD_TIMEOUT_SECONDS,
        )
        record: dict[str, Any] = json.loads(record_result.stdout)
        kernel_result = run(
            [
                "docker",
                "exec",
                helper_container,
                record["tools"]["tc"],
                "-j",
                "qdisc",
                "show",
                "dev",
                record["interface"],
            ],
            timeout=INTERRUPTION_KERNEL_TIMEOUT_SECONDS,
        )
        kernel_qdisc = json.loads(kernel_result.stdout)
        driver_pid, driver_start = validate_interruption_barrier(
            token, barrier, record, kernel_qdisc
        )
        if driver.poll() is not None:
            raise RuntimeError("interrupted-setup driver exited before exact kill")
        run(
            [
                "docker",
                "exec",
                helper_container,
                "/app/.venv/bin/python",
                "-c",
                KILL_INTERRUPTED_DRIVER,
                str(driver_pid),
                driver_start,
            ],
            timeout=INTERRUPTION_KILL_TIMEOUT_SECONDS,
        )
        killed = True
        stdout, stderr = driver.communicate(timeout=INTERRUPTION_KILL_TIMEOUT_SECONDS)
        cleanup_deadline = time.monotonic() + INTERRUPTION_CLEANUP_BUDGET_SECONDS
        cleanup: dict[str, Any] | None = None
        while time.monotonic() < cleanup_deadline:
            status = run(
                [
                    "docker",
                    "exec",
                    helper_container,
                    "/app/.venv/bin/python",
                    "/app/deploy/network_resource.py",
                    "status",
                    "--token",
                    token,
                ],
                timeout=2,
                check=False,
            )
            if status.returncode == 0:
                parsed = json.loads(status.stdout)
                if isinstance(parsed, dict) and parsed.get("cleanup_complete"):
                    cleanup = parsed
                    break
            time.sleep(0.05)
        if cleanup is None:
            raise TimeoutError("independent watchdog did not complete interrupted setup cleanup")
        if (
            cleanup.get("cleanup_reason") != "setup_parent_lost"
            or cleanup.get("cleanup_phase") != "complete"
            or cleanup.get("restored_state") != record.get("prestate")
        ):
            raise AssertionError("interrupted setup was not rolled back exactly")
        return {
            **cleanup,
            "test_only_barrier": barrier,
            "before_kill_record": record,
            "before_kill_kernel_qdisc": kernel_qdisc,
            "timing_policy": {
                "watchdog_duration_seconds": duration,
                "barrier_budget_seconds": barrier_budget,
                "record_timeout_seconds": INTERRUPTION_RECORD_TIMEOUT_SECONDS,
                "kernel_timeout_seconds": INTERRUPTION_KERNEL_TIMEOUT_SECONDS,
                "kill_timeout_seconds": INTERRUPTION_KILL_TIMEOUT_SECONDS,
                "bounded_pre_kill_seconds": pre_kill_bound,
                "required_margin_seconds": INTERRUPTION_WATCHDOG_MARGIN_SECONDS,
                "cleanup_budget_seconds": INTERRUPTION_CLEANUP_BUDGET_SECONDS,
            },
            "driver_exit": driver.returncode,
            "driver_stdout": stdout[-2000:],
            "driver_stderr": stderr[-2000:],
        }
    finally:
        if driver.poll() is None:
            if driver_pid is not None and driver_start is not None and not killed:
                run(
                    [
                        "docker",
                        "exec",
                        helper_container,
                        "/app/.venv/bin/python",
                        "-c",
                        KILL_INTERRUPTED_DRIVER,
                        str(driver_pid),
                        driver_start,
                    ],
                    timeout=INTERRUPTION_KILL_TIMEOUT_SECONDS,
                    check=False,
                )
            try:
                driver.communicate(timeout=INTERRUPTION_KILL_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                driver.kill()
                driver.communicate(timeout=1)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run(
    argv: list[str], *, timeout: float = 240, check: bool = True, cwd: Path = ROOT
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout
        )
        stderr = (
            exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr
        )
        result = subprocess.CompletedProcess(argv, 124, stdout or "", stderr or "command timed out")
    except OSError as exc:
        result = subprocess.CompletedProcess(argv, 127, "", f"{type(exc).__name__}: {exc}")
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(argv[:5])}: {result.stderr[-2000:]}"
        )
    return result


def wait_json(url: str, predicate: Any, *, deadline: float = 90) -> dict[str, Any]:
    end = time.monotonic() + deadline
    last: BaseException | None = None
    while time.monotonic() < end:
        try:
            response = httpx.get(url, timeout=3, trust_env=False)
            response.raise_for_status()
            value: dict[str, Any] = response.json()
            if predicate(value):
                return value
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            last = exc
        time.sleep(0.5)
    raise TimeoutError(
        f"readiness deadline for {url}; last={type(last).__name__ if last else 'none'}"
    )


def write_private(path: Path, value: str, mode: int) -> None:
    path.write_text(value, encoding="utf-8")
    os.chmod(path, mode)


def absence_status(
    result: subprocess.CompletedProcess[str],
    kind: Literal["container", "network", "image", "volume"],
    name: str,
) -> Literal["absent", "present", "unknown"]:
    if result.returncode == 0:
        return "present"
    diagnostic = (result.stderr or "") + "\n" + (result.stdout or "")
    expected = {
        "container": (f"No such object: {name}",),
        "network": (f"network {name} not found",),
        "image": (f"No such image: {name}", f"No such object: {name}"),
        "volume": (f"No such volume: {name}", f"get {name}: no such volume"),
    }
    return "absent" if any(value in diagnostic for value in expected[kind]) else "unknown"


def verify_absence(
    argv: list[str], kind: Literal["container", "network", "image", "volume"], name: str
) -> dict[str, Any]:
    result = run(argv, timeout=30, check=False)
    status = absence_status(result, kind, name)
    return {
        "status": status,
        "exit": result.returncode,
        "diagnostic": "" if status == "absent" else (result.stderr or result.stdout)[-500:],
    }


def _sanitized(text: str, secret_values: tuple[str, ...], limit: int = 12000) -> str:
    for secret in secret_values:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text[-limit:]


def capture_agent_diagnostics(agent: str, secret_values: tuple[str, ...]) -> dict[str, Any]:
    """Capture bounded credential-free runtime evidence before an owned agent is removed."""
    report: dict[str, Any] = {}
    commands = {
        "state": ["docker", "inspect", "-f", "{{json .State}}", agent],
        "logs": ["docker", "logs", "--tail", "400", agent],
        "stats": [
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
            agent,
        ],
        "processes": ["docker", "top", agent, "-eo", "pid,ppid,pgid,sid,rss,nlwp,comm"],
    }
    for label, argv in commands.items():
        result = run(argv, timeout=20, check=False)
        output = (result.stdout or "") + (result.stderr or "")
        item: dict[str, Any] = {
            "exit": result.returncode,
            "output": _sanitized(output, secret_values),
        }
        if label == "state" and result.returncode == 0:
            try:
                state = json.loads(result.stdout)
                item["state"] = {
                    key: state.get(key)
                    for key in (
                        "Status",
                        "Running",
                        "Paused",
                        "Restarting",
                        "OOMKilled",
                        "Dead",
                        "Pid",
                        "ExitCode",
                        "Error",
                        "StartedAt",
                        "FinishedAt",
                    )
                }
            except (TypeError, ValueError):
                item["parse_error"] = "invalid Docker State JSON"
        report[label] = item
    cgroup_script = """import json,os
def read(path):
 try: return open(path,encoding='ascii').read().strip()
 except OSError as exc: return type(exc).__name__
events={}
for line in read('/sys/fs/cgroup/memory.events').splitlines():
 parts=line.split()
 if len(parts)==2 and parts[1].isdigit(): events[parts[0]]=int(parts[1])
processes=[]
for name in sorted((item for item in os.listdir('/proc') if item.isdigit()),key=int)[:64]:
 try:
  status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in open('/proc/'+name+'/status',encoding='ascii') if ':' in line}
  processes.append({'pid':int(name),'name':status.get('Name'),'ppid':status.get('PPid'),'rss':status.get('VmRSS'),'threads':status.get('Threads'),'fds':len(os.listdir('/proc/'+name+'/fd'))})
 except OSError: pass
print(json.dumps({'memory_current':read('/sys/fs/cgroup/memory.current'),'memory_peak':read('/sys/fs/cgroup/memory.peak'),'memory_max':read('/sys/fs/cgroup/memory.max'),'memory_events':events,'pids_current':read('/sys/fs/cgroup/pids.current'),'pids_max':read('/sys/fs/cgroup/pids.max'),'processes':processes}))
"""
    cgroup = run(
        ["docker", "exec", agent, "/app/.venv/bin/python", "-c", cgroup_script],
        timeout=20,
        check=False,
    )
    report["cgroup"] = {
        "exit": cgroup.returncode,
        "output": _sanitized((cgroup.stdout or "") + (cgroup.stderr or ""), secret_values),
    }
    if cgroup.returncode == 0:
        try:
            report["cgroup"]["values"] = json.loads(cgroup.stdout)
        except (TypeError, ValueError):
            report["cgroup"]["parse_error"] = "invalid cgroup diagnostic JSON"
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("refusing to overwrite a retained native attempt")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    project = "fd09-" + uuid4().hex[:10]
    image = "fleetdoctor-task09-native:" + uuid4().hex[:10]
    names = {
        "anchor_a": project + "-anchor-a",
        "anchor_b": project + "-anchor-b",
        "agent_a": project + "-agent-a",
        "agent_b": project + "-agent-b",
        "helper": project + "-helper",
    }
    volumes = {
        "config_a": project + "-config-a",
        "config_b": project + "-config-b",
        "helper": project + "-helper-state",
    }
    evidence: dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "environment": "owned-disposable-docker-network-namespaces",
        "aws_execution": False,
        "ssh_execution": False,
        "host_tc_mutation": False,
        "project": project,
        "owned_image": image,
        "controller_platform": os.name,
        "source_manifest": source_manifest(),
        "environment_metadata": {
            "controller_platform": platform.platform(),
            "controller_kernel": platform.release(),
            "docker_server": run(
                ["docker", "version", "--format", "{{json .Server}}"], check=False
            ).stdout.strip()
            or "unknown",
            "topology": "two-agent-containers-with-distinct-network-namespaces",
        },
        "measurement_contract": {
            "sample_interval_seconds": 5,
            "probe_echoes": 3,
            "probe_worker_budget_seconds": 3,
            "http_timeout_seconds": 3,
            "diagnosis_deadline_seconds": 60,
            "recovery_deadline_seconds": 60,
            "phase_acceptance_seconds_strictly_less_than": 30,
        },
        "cleanup": {"status": "not_started"},
    }
    write_report(args.output, evidence)
    cleanup_errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix=project + "-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        env_file = root / "stack.env"
        ports = (free_port(), free_port(), free_port())
        values = create(env_file, ports=ports, disk=True, cgroups=(CGROUP, MISSING_CGROUP))
        tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
        compose = [
            "docker",
            "compose",
            "--project-name",
            project,
            "--env-file",
            str(env_file),
            "-f",
            str(ROOT / "compose.yaml"),
        ]

        def dc(*command: str, timeout: float = 240) -> str:
            return run(compose + list(command), timeout=timeout).stdout

        api = f"http://127.0.0.1:{ports[0]}"
        seccomp = root / "service-seccomp.json"
        seccomp.write_text(
            json.dumps(
                {
                    "defaultAction": "SCMP_ACT_ALLOW",
                    "architectures": [
                        "SCMP_ARCH_X86_64",
                        "SCMP_ARCH_X86",
                        "SCMP_ARCH_X32",
                        "SCMP_ARCH_AARCH64",
                        "SCMP_ARCH_ARM",
                    ],
                    "syscalls": [
                        {
                            "names": ["socket"],
                            "action": "SCMP_ACT_ERRNO",
                            "errnoRet": 97,
                            "args": [{"index": 0, "value": family, "op": "SCMP_CMP_EQ"}],
                        }
                        for family in [3, 4, 5, 6, 7, 8, 9, *range(11, 46)]
                    ],
                }
            ),
            encoding="utf-8",
        )
        os.chmod(seccomp, 0o600)
        sysctl_dir = root / "sysctl"
        helper_run = args.output.parent / (args.output.stem + "-helper-state")
        if helper_run.exists():
            raise FileExistsError("refusing to overwrite retained helper-state directory")
        sysctl_dir.mkdir(mode=0o700)
        helper_run.mkdir(mode=0o700)
        agent_commands: dict[str, list[str]] = {}
        try:
            run(["docker", "build", "--target", "test", "-t", image, "."], timeout=600)
            for volume in volumes.values():
                run(["docker", "volume", "create", volume])
            dc("up", "-d", "--build", "--wait", "--wait-timeout", "120")
            wait_json(api + "/health", lambda value: value.get("status") == "ok")
            network = project + "_default"
            collector_id = dc("ps", "-q", "collector").strip()
            collector_ip = run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}',
                    collector_id,
                ]
            ).stdout.strip()
            if not collector_ip:
                raise RuntimeError("collector numeric address unavailable")
            evidence["collector_target"] = collector_ip
            for anchor in (names["anchor_a"], names["anchor_b"]):
                run(
                    [
                        "docker",
                        "run",
                        "-d",
                        "--name",
                        anchor,
                        "--network",
                        network,
                        "--sysctl",
                        "net.ipv4.ping_group_range=10001 10001",
                        image,
                        "sleep",
                        "infinity",
                    ]
                )
                prep = run(network_prepare_argv(anchor, sysctl_dir, image))
                evidence.setdefault("provisioning", []).append(
                    {
                        "anchor": anchor,
                        "repository_script": "deploy/network_prepare.sh",
                        "stdout": prep.stdout,
                        "status": "passed",
                    }
                )
            for node, anchor, agent in (
                ("node-a", names["anchor_a"], names["agent_a"]),
                ("node-b", names["anchor_b"], names["agent_b"]),
            ):
                private = root / node
                private.mkdir(mode=0o700)
                credential = private / "ingest-token"
                service_env = private / "agent.env"
                write_private(credential, tokens[node], 0o400)
                environment = {
                    "FLEETDOCTOR_NODE_ID": node,
                    "FLEETDOCTOR_COLLECTOR_URL": collector_base_url(collector_ip),
                    "FLEETDOCTOR_NETWORK_TARGET": collector_ip,
                    "FLEETDOCTOR_FILESYSTEMS": f"/,{DISK_PATH}",
                    "FLEETDOCTOR_CGROUPS": f"{CGROUP},{MISSING_CGROUP}",
                    "CREDENTIALS_DIRECTORY": "/run/credentials",
                    "PATH": "/app/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                }
                write_private(
                    service_env,
                    "".join(f"{key}={value}\n" for key, value in environment.items()),
                    0o400,
                )
                config_volume = volumes["config_a" if node == "node-a" else "config_b"]
                run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--user",
                        "0:0",
                        "-v",
                        f"{config_volume}:/dest",
                        "-v",
                        f"{private}:/source:ro",
                        image,
                        "sh",
                        "-c",
                        "cp /source/ingest-token /dest/ingest-token && "
                        "cp /source/agent.env /dest/agent.env && "
                        "chown root:10001 /dest /dest/ingest-token /dest/agent.env && "
                        "chmod 0750 /dest && chmod 0440 /dest/ingest-token /dest/agent.env",
                    ]
                )
                argv = [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    agent,
                    "--network",
                    "container:" + anchor,
                    "--user",
                    "10001:10001",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--security-opt",
                    "seccomp=" + str(seccomp),
                    "--pids-limit",
                    "16",
                    "--memory",
                    "100m",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,mode=700,uid=10001,gid=10001",
                    "--env-file",
                    str(service_env),
                    "-v",
                    f"{config_volume}:/run/credentials:ro",
                    "-v",
                    f"{config_volume}:/etc/fleetdoctor:ro",
                    "-v",
                    f"{sysctl_dir}:/etc/sysctl.d:ro",
                    image,
                    "/app/.venv/bin/python",
                    "-m",
                    "fleetdoctor.agent",
                ]
                agent_commands[node] = argv
                run(argv)
            nodes = wait_json(
                api + "/nodes",
                lambda value: (
                    len(value.get("nodes", [])) == 2
                    and all(
                        item.get("fresh")
                        and (item.get("network") or {}).get("probe", {}).get("status")
                        == "available"
                        and (item.get("network") or {}).get("probe", {}).get("received") == 3
                        and (item.get("network") or {}).get("tcp", {}).get("rate_status")
                        == "available"
                        for item in value["nodes"]
                    )
                ),
                deadline=60,
            )
            evidence["native_agent_observations"] = nodes
            cadence: list[dict[str, Any]] = []
            last_sequence = -1
            cadence_deadline = time.monotonic() + 30
            while len(cadence) < 4 and time.monotonic() < cadence_deadline:
                snapshot = wait_json(
                    api + "/nodes/node-a/metrics",
                    lambda value, minimum_sequence=last_sequence: (
                        value.get("fresh")
                        and (value.get("sample") or {}).get("sequence", -1) > minimum_sequence
                    ),
                    deadline=8,
                )
                sample = snapshot["sample"]
                last_sequence = sample["sequence"]
                cadence.append(
                    {
                        "boot_id": sample["boot_id"],
                        "agent_session_id": sample["agent_session_id"],
                        "sequence": sample["sequence"],
                        "observed_at": sample["observed_at"],
                    }
                )
            gaps = [
                (
                    datetime.fromisoformat(right["observed_at"])
                    - datetime.fromisoformat(left["observed_at"])
                ).total_seconds()
                for left, right in zip(cadence, cadence[1:], strict=False)
            ]
            if len(cadence) != 4 or not all(4 <= gap <= 7 for gap in gaps):
                raise AssertionError("production agent cadence is not near five seconds")
            evidence["production_agent_cadence"] = {"observations": cadence, "gaps_seconds": gaps}
            unit = (ROOT / "deploy/fleetdoctor-agent.service").read_text(encoding="utf-8")
            required_unit = [
                "User=fleetdoctor",
                "NoNewPrivileges=true",
                "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                "MemoryMax=100M",
                "TasksMax=16",
                "ProtectSystem=strict",
                "PrivateTmp=true",
                "LoadCredential=ingest-token:/etc/fleetdoctor/ingest-token",
            ]
            if any(item not in unit for item in required_unit):
                raise AssertionError("installed service contract is incomplete")
            context_script = """import json,os,socket
def socket_result(f,t=socket.SOCK_STREAM,p=0):
 try:
  s=socket.socket(f,t,p); s.close(); return {'allowed':True,'errno':None}
 except OSError as e: return {'allowed':False,'errno':e.errno}
status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in open('/proc/self/status')}
tmp=os.stat('/tmp')
events={line.split()[0]:int(line.split()[1]) for line in open('/sys/fs/cgroup/memory.events') if len(line.split())==2}
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'nnp':status['NoNewPrivs'],'cap_eff':status['CapEff'],'unix':socket_result(socket.AF_UNIX),'inet':socket_result(socket.AF_INET),'inet6':socket_result(socket.AF_INET6),'netlink':socket_result(socket.AF_NETLINK,socket.SOCK_RAW,0),'bluetooth':socket_result(31,socket.SOCK_RAW,0),'pids_current':open('/sys/fs/cgroup/pids.current').read().strip(),'pids_max':open('/sys/fs/cgroup/pids.max').read().strip(),'memory_current':open('/sys/fs/cgroup/memory.current').read().strip(),'memory_peak':open('/sys/fs/cgroup/memory.peak').read().strip(),'memory_max':open('/sys/fs/cgroup/memory.max').read().strip(),'memory_events':events,'credential':oct(os.stat('/run/credentials/ingest-token').st_mode & 0o777),'env':oct(os.stat('/etc/fleetdoctor/agent.env').st_mode & 0o777),'credential_readable':open('/run/credentials/ingest-token').read()!='','tmp':{'uid':tmp.st_uid,'gid':tmp.st_gid,'mode':oct(tmp.st_mode & 0o777),'writable':os.access('/tmp',os.W_OK)},'ping':shutil.which('ping'),'ip':shutil.which('ip')}))
"""
            context_script = "import shutil\n" + context_script
            service_context: dict[str, Any] = {}
            for node, agent in (("node-a", names["agent_a"]), ("node-b", names["agent_b"])):
                raw = run(
                    ["docker", "exec", agent, "/app/.venv/bin/python", "-c", context_script]
                ).stdout
                context = json.loads(raw)
                if not (
                    context["uid"] == context["gid"] == 10001
                    and context["nnp"] == "1"
                    and int(context["cap_eff"], 16) == 0
                    and context["unix"]["allowed"]
                    and context["inet"]["allowed"]
                    and context["inet6"]["allowed"]
                    and context["netlink"] == {"allowed": False, "errno": 97}
                    and context["bluetooth"] == {"allowed": False, "errno": 97}
                    and int(context["pids_current"]) <= 16
                    and context["pids_max"] == "16"
                    and int(context["memory_current"]) <= 100 * 1024 * 1024
                    and int(context["memory_peak"]) <= 100 * 1024 * 1024
                    and int(context["memory_max"]) <= 100 * 1024 * 1024
                    and context["memory_events"].get("oom", 0) == 0
                    and context["memory_events"].get("oom_kill", 0) == 0
                    and context["credential"] == "0o440"
                    and context["env"] == "0o440"
                    and context["credential_readable"]
                    and context["tmp"]
                    == {"uid": 10001, "gid": 10001, "mode": "0o700", "writable": True}
                    and context["ping"]
                    and context["ip"]
                ):
                    raise AssertionError("effective service restrictions mismatch")
                service_context[node] = context
            service_context["unit_required_directives"] = required_unit
            service_context["seccomp_profile"] = json.loads(seccomp.read_text())
            service_context["route_branch"] = "netlink_denied_unknown_interface"
            evidence["service_context"] = service_context
            run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--user",
                    "0:0",
                    "-v",
                    f"{volumes['helper']}:/state",
                    image,
                    "sh",
                    "-c",
                    "chown root:root /state && chmod 0700 /state",
                ]
            )
            run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    names["helper"],
                    "--network",
                    "container:" + names["anchor_a"],
                    "--user",
                    "0:0",
                    "--cap-add",
                    "NET_ADMIN",
                    "--security-opt",
                    "no-new-privileges",
                    "-v",
                    f"{volumes['helper']}:/run/fleetdoctor/network",
                    image,
                    "sleep",
                    "infinity",
                ]
            )

            def helper(action: str, token: str, profile: str, duration: int) -> dict[str, Any]:
                argv = [
                    "docker",
                    "exec",
                    names["helper"],
                    "/app/.venv/bin/python",
                    "/app/deploy/network_resource.py",
                    action,
                    "--token",
                    token,
                ]
                if action == "start":
                    argv += [
                        "--target",
                        collector_ip,
                        "--profile",
                        profile,
                        "--duration",
                        str(duration),
                    ]
                result = run(argv, timeout=15)
                value: dict[str, Any] = json.loads(result.stdout)
                return value

            def surrogate() -> dict[str, Any]:
                script = (
                    "import json,time,urllib.request; "
                    "s=time.monotonic(); r=urllib.request.urlopen('"
                    + f"http://{collector_ip}:8000"
                    + "/health',timeout=3); "
                    "print(json.dumps({'status_code':r.status,'elapsed_seconds':time.monotonic()-s,"
                    "'scope':'target_node_shared_network_namespace'}))"
                )
                result = run(
                    ["docker", "exec", names["helper"], "/app/.venv/bin/python", "-c", script],
                    timeout=5,
                )
                value: dict[str, Any] = json.loads(result.stdout)
                return value

            def record(event: str, value: dict[str, Any]) -> None:
                evidence.setdefault("harness_events", []).append(
                    {"event": event, "at": datetime.now(UTC).isoformat(), "snapshot": value}
                )
                write_report(args.output, evidence)

            harness = NetworkHarness(
                api,
                "node-a",
                "node-b",
                collector_ip,
                api + "/health",
                helper=helper,
                surrogate=surrogate,
                recorder=record,
            )
            evidence["scenario"] = harness.run()
            for phase in ("latency", "loss"):
                elapsed = evidence["scenario"][phase]["trigger_to_diagnosis_seconds"]
                evidence["scenario"][phase]["diagnosis_under_30_seconds"] = elapsed < 30
                if elapsed >= 30:
                    raise AssertionError(f"{phase} diagnosis took 30 seconds or more")
            watchdog_token = secrets.token_hex(16)
            watchdog_start = helper("start", watchdog_token, "latency", 2)
            time.sleep(3)
            watchdog_result = helper("status", watchdog_token, "latency", 2)
            if (
                not watchdog_result.get("cleanup_complete")
                or watchdog_result.get("cleanup_reason") != "watchdog_deadline"
                or watchdog_result.get("restored_state") != watchdog_start.get("prestate")
            ):
                raise AssertionError("independent watchdog did not restore exact baseline")
            evidence["independent_watchdog"] = watchdog_result
            interrupted_token = secrets.token_hex(16)
            evidence["interrupted_setup_rollback"] = run_interrupted_setup_proof(
                names["helper"], collector_ip, interrupted_token
            )
            cancellation_token = secrets.token_hex(16)
            helper("start", cancellation_token, "loss", 20)
            process_probe = f"""import json,pathlib
rows=[]
for cmdline in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
 try:
  raw=cmdline.read_bytes()
  argv=[part.decode(errors='replace') for part in raw.split(b'\\0') if part]
  if not argv or pathlib.Path(argv[0]).name != 'ping': continue
  if {collector_ip!r} not in argv or '-c' not in argv or argv[argv.index('-c')+1] != '3': continue
  stat=pathlib.Path('/proc/'+cmdline.parent.name+'/stat').read_text()
  tail=stat[stat.rfind(')')+2:].split()
  rows.append({{'pid':int(cmdline.parent.name),'argv':argv,'pgrp':int(tail[2]),'session':int(tail[3]),'starttime':tail[19]}})
 except (OSError,ValueError,IndexError): pass
print(json.dumps(rows))
"""
            ping_processes: list[dict[str, Any]] = []
            ping_deadline = time.monotonic() + 10
            while time.monotonic() < ping_deadline:
                probe = run(
                    [
                        "docker",
                        "exec",
                        names["agent_a"],
                        "/app/.venv/bin/python",
                        "-c",
                        process_probe,
                    ],
                    timeout=3,
                    check=False,
                )
                if probe.returncode == 0:
                    ping_processes = json.loads(probe.stdout)
                    if ping_processes:
                        break
                time.sleep(0.1)
            if not ping_processes:
                raise AssertionError("no active production ping was observed before SIGTERM")
            stop_started = time.monotonic()
            stop = run(["docker", "stop", "--time", "12", names["agent_a"]], timeout=16)
            stop_elapsed = time.monotonic() - stop_started
            cleanup = helper("cleanup", cancellation_token, "loss", 20)
            inspect = json.loads(
                run(["docker", "inspect", "-f", "{{json .State}}", names["agent_a"]]).stdout
            )
            if (
                inspect["Running"]
                or inspect["OOMKilled"]
                or inspect["ExitCode"] != 0
                or stop_elapsed >= 12
                or not cleanup["cleanup_complete"]
            ):
                raise AssertionError("SIGTERM worker cleanup proof failed")
            evidence["sigterm_no_orphan"] = {
                "active_ping_before_signal": ping_processes,
                "container_state": inspect,
                "graceful_stop_elapsed_seconds": stop_elapsed,
                "stop_output": stop.stdout.strip(),
                "owned_tc_cleanup": cleanup,
                "scope": "agent container process namespace and shared isolated network namespace",
            }
            run(["docker", "rm", names["agent_a"]])
            prior_session = cadence[-1]["agent_session_id"]
            permission_setup = configure_owned_ping_group_range(
                names["anchor_a"], image, "20000 20000"
            )
            run(agent_commands["node-a"])
            permission = wait_json(
                api + "/nodes/node-a/metrics",
                lambda value: (
                    (value.get("sample") or {}).get("agent_session_id") != prior_session
                    and ((value.get("network") or {}).get("probe") or {}).get("status")
                    == "unavailable"
                    and "ping_permission_denied"
                    in (((value.get("network") or {}).get("probe") or {}).get("errors") or [])
                ),
                deadline=30,
            )
            permission_probe = permission["network"]["probe"]
            if any(
                permission_probe.get(field) is not None
                for field in ("sent", "received", "lost", "loss_ratio", "median_rtt_ms")
            ):
                raise AssertionError("permission denial invented measured loss or RTT")
            run(["docker", "stop", "--time", "12", names["agent_a"]], timeout=16)
            run(["docker", "rm", names["agent_a"]])
            permission_restore = configure_owned_ping_group_range(
                names["anchor_a"], image, "10001 10001"
            )
            permission_session = permission["sample"]["agent_session_id"]
            run(agent_commands["node-a"])
            permission_recovery = wait_json(
                api + "/nodes/node-a/metrics",
                lambda value: (
                    (value.get("sample") or {}).get("agent_session_id") != permission_session
                    and ((value.get("network") or {}).get("probe") or {}).get("status")
                    == "available"
                    and ((value.get("network") or {}).get("probe") or {}).get("sent") == 3
                    and ((value.get("network") or {}).get("probe") or {}).get("received") == 3
                    and ((value.get("network") or {}).get("probe") or {}).get("lost") == 0
                ),
                deadline=30,
            )
            run(["docker", "stop", "--time", "12", names["agent_a"]], timeout=16)
            run(["docker", "rm", names["agent_a"]])
            missing_command = list(agent_commands["node-a"])
            image_index = missing_command.index(image)
            missing_command[image_index:image_index] = ["--env", "PATH=/app/.venv/bin"]
            run(missing_command)
            missing = wait_json(
                api + "/nodes/node-a/metrics",
                lambda value: (
                    ((value.get("network") or {}).get("probe") or {}).get("status") == "unavailable"
                    and "ping_tool_missing"
                    in (((value.get("network") or {}).get("probe") or {}).get("errors") or [])
                ),
                deadline=30,
            )
            missing_probe = missing["network"]["probe"]
            if any(
                missing_probe.get(field) is not None
                for field in ("sent", "received", "lost", "loss_ratio", "median_rtt_ms")
            ):
                raise AssertionError("missing tool invented measured loss or RTT")
            evidence["unavailable_contexts"] = {
                "permission": permission,
                "permission_setup": permission_setup,
                "permission_restore": permission_restore,
                "permission_recovery": permission_recovery,
                "missing_tool": missing,
                "measured_loss_from_unavailable": False,
            }
            evidence["status"] = "passed"
        except BaseException as exc:
            evidence["status"] = "failed"
            evidence["failure"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            cleanup_report: dict[str, Any] = {"status": "running", "commands": {}}
            evidence["cleanup"] = cleanup_report

            secret_values = tuple(tokens.values())
            evidence["precleanup_agent_diagnostics"] = {
                node: capture_agent_diagnostics(agent, secret_values)
                for node, agent in (("node-a", names["agent_a"]), ("node-b", names["agent_b"]))
            }
            evidence["diagnostics_captured_before_cleanup"] = True
            write_report(args.output, evidence)

            def cleanup_call(
                label: str, argv: list[str], timeout: float = 30
            ) -> subprocess.CompletedProcess[str]:
                result = run(argv, timeout=timeout, check=False)
                cleanup_report["commands"][label] = {
                    "exit": result.returncode,
                    "diagnostic": (result.stderr or result.stdout)[-1000:],
                }
                if result.returncode:
                    cleanup_errors.append(f"{label}: exit {result.returncode}")
                return result

            inventory = cleanup_call(
                "precleanup_owned_volume_inventory",
                [
                    "docker",
                    "volume",
                    "ls",
                    "--filter",
                    "label=com.docker.compose.project=" + project,
                    "--format",
                    "{{.Name}}",
                ],
            )
            cleanup_report["precleanup_compose_volumes"] = (
                inventory.stdout.split() if inventory.returncode == 0 else "unknown"
            )
            owned_inventory = cleanup_call(
                "precleanup_all_owned_volumes",
                ["docker", "volume", "ls", "--filter", "name=" + project, "--format", "{{.Name}}"],
            )
            owned_volumes = (
                owned_inventory.stdout.split() if owned_inventory.returncode == 0 else []
            )
            cleanup_report["precleanup_all_owned_volumes"] = (
                owned_volumes if owned_inventory.returncode == 0 else "unknown"
            )
            helper_copy = cleanup_call(
                "retain_helper_state",
                [
                    "docker",
                    "run",
                    "--rm",
                    "--user",
                    "0:0",
                    "-v",
                    f"{volumes['helper']}:/source:ro",
                    "-v",
                    f"{helper_run}:/retained",
                    image,
                    "sh",
                    "-c",
                    "cp -a /source/. /retained/",
                ],
            )
            cleanup_report["helper_state_retained"] = helper_copy.returncode == 0
            for name in (
                names["agent_a"],
                names["agent_b"],
                names["helper"],
                names["anchor_a"],
                names["anchor_b"],
            ):
                cleanup_call("remove_container_" + name, ["docker", "rm", "-f", name], 20)
            cleanup_call(
                "compose_down",
                compose + ["down", "--volumes", "--remove-orphans", "--rmi", "local"],
                180,
            )
            for label, volume in volumes.items():
                cleanup_call("remove_volume_" + label, ["docker", "volume", "rm", volume], 30)
            cleanup_call("remove_image", ["docker", "image", "rm", "-f", image], 60)
            verification: dict[str, Any] = {}
            for key, name in names.items():
                verification["container_" + key] = verify_absence(
                    ["docker", "inspect", name], "container", name
                )
            verification["network"] = verify_absence(
                ["docker", "network", "inspect", project + "_default"],
                "network",
                project + "_default",
            )
            for key, volume in volumes.items():
                verification["volume_" + key] = verify_absence(
                    ["docker", "volume", "inspect", volume], "volume", volume
                )
            for volume in owned_volumes:
                verification["discovered_volume_" + volume] = verify_absence(
                    ["docker", "volume", "inspect", volume], "volume", volume
                )
            verification["image"] = verify_absence(
                ["docker", "image", "inspect", image], "image", image
            )
            cleanup_report["verification"] = verification
            cleanup_report["errors"] = cleanup_errors
            cleanup_report["status"] = (
                "passed"
                if all(value["status"] == "absent" for value in verification.values())
                else "failed"
            )
            if cleanup_report["status"] != "passed":
                evidence["status"] = "failed"
                evidence["cleanup_failure"] = "owned Docker resource absence is not proven"
            evidence["source_manifest_after"] = source_manifest()
            if evidence["source_manifest_after"] != evidence["source_manifest"]:
                evidence["status"] = "failed"
                evidence["source_changed_during_proof"] = True
            evidence["finished_at"] = datetime.now(UTC).isoformat()
            write_report(args.output, evidence)
    if evidence["status"] != "passed":
        raise RuntimeError("native network proof failed; retained output describes failure")
    print(f"Native network proof passed; evidence: {args.output}")


if __name__ == "__main__":
    main()
