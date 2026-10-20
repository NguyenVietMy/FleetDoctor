"""Native helper, production agent/harness/API, and PostgreSQL FD lifecycle proof."""

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

import fd_resource  # noqa: E402
from fd_harness import Backend, FdHarness  # noqa: E402

TOKEN = os.environ["FLEETDOCTOR_TARGET_TOKEN"]
API = "http://127.0.0.1:8000"


def runtime_manifest() -> dict[str, Any]:
    files: list[Path] = []
    for name in ("src", "scripts", "deploy", "monitoring"):
        files.extend(
            path
            for path in (ROOT / name).rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
    files.extend(path for path in (ROOT / "compose.yaml", ROOT / "Dockerfile") if path.is_file())
    return {
        "scope": "files copied into disposable native proof image",
        "sha256": {
            path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(files)
        },
    }


class HttpBackend(Backend):
    def __init__(self) -> None:
        self.client = httpx.Client(base_url=API, timeout=2, trust_env=False)

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self.client.get(path, params=params)
        response.raise_for_status()
        return cast(dict[str, Any], response.json())

    def close(self) -> None:
        self.client.close()


class Server:
    def __init__(self) -> None:
        self.process: subprocess.Popen[bytes] | None = None
        self.restarts = 0

    def start(self) -> None:
        self.process = subprocess.Popen(
            [
                str(ROOT / ".venv/bin/python"),
                "-m",
                "uvicorn",
                "fleetdoctor.collector:app_factory",
                "--factory",
                "--host",
                "0.0.0.0",
                "--port",
                "8000",
                "--workers",
                "1",
                "--no-proxy-headers",
                "--no-access-log",
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 30
        with httpx.Client(timeout=1, trust_env=False) as client:
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("collector exited during startup")
                try:
                    response = client.get(API + "/health")
                    if response.is_success:
                        return
                except httpx.HTTPError:
                    pass
                time.sleep(0.25)
        raise TimeoutError("collector did not become ready")

    def stop(self) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)

    def restart(self, backend: HttpBackend, identifier: str) -> dict[str, Any]:
        started = time.monotonic()
        self.stop()
        self.start()
        self.restarts += 1
        deadline = time.monotonic() + 20
        restored: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            try:
                candidate = backend.get("/diagnoses/" + identifier)
                if candidate.get("status") == "active" and candidate.get("evidence_fresh"):
                    restored = candidate
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        if restored is None:
            raise TimeoutError("collector did not restore fresh exact incident after restart")
        return {
            "restart_number": self.restarts,
            "seconds": time.monotonic() - started,
            "incident_id": identifier,
            "opening_evidence": restored["opening_evidence"],
        }


class NativeInjector:
    def __init__(self) -> None:
        self.agent: subprocess.Popen[bytes] | None = None

    def start(self, token: str, limit: int, seconds: int) -> dict[str, Any]:
        result = fd_resource.start(token, limit, seconds)
        environment = os.environ.copy()
        environment.update(
            FLEETDOCTOR_NODE_ID="node-a",
            FLEETDOCTOR_COLLECTOR_URL=API,
            FLEETDOCTOR_PROOF_TOKEN=TOKEN,
            FLEETDOCTOR_FILESYSTEMS="/",
            FLEETDOCTOR_CPU_PIDS=str(result["worker_pid"]),
        )
        try:
            self.agent = subprocess.Popen(
                [str(ROOT / ".venv/bin/python"), "scripts/fd_agent_probe.py"],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except BaseException:
            fd_resource.cleanup(token)
            raise
        return result

    def status(self, token: str) -> dict[str, Any]:
        return fd_resource.status(token)

    def pressure(self, token: str) -> dict[str, Any]:
        return fd_resource.pressure(token)

    def release(self, token: str) -> dict[str, Any]:
        return fd_resource.release(token)

    def cleanup(self, token: str) -> dict[str, Any]:
        return fd_resource.cleanup(token)

    def stop_agent(self) -> dict[str, Any]:
        if self.agent is None:
            return {"started": False, "stopped": True}
        pid = self.agent.pid
        self.agent.terminate()
        try:
            code = self.agent.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.agent.kill()
            code = self.agent.wait(timeout=5)
        self.agent = None
        return {"started": True, "pid": pid, "exit_code": code, "stopped": True}


def wait_reference(backend: HttpBackend) -> dict[str, Any]:
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        try:
            value = backend.get("/nodes/node-b/metrics")
            coverage = value.get("fd_coverage", {})
            if value.get("fresh") and coverage.get("observed", 0) > 0:
                return value
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise TimeoutError("isolated reference production agent did not become fresh")


def wait_identity_terminated(identity: dict[str, Any], timeout: float) -> float:
    started = time.monotonic()
    deadline = started + timeout
    while time.monotonic() < deadline:
        try:
            pid = int(identity["pid"])
            if (
                fd_resource.process_identity(pid) != identity
                or fd_resource.process_state(pid) == "Z"
            ):
                return time.monotonic() - started
        except (FileNotFoundError, ProcessLookupError):
            return time.monotonic() - started
        time.sleep(0.1)
    raise TimeoutError("owned worker exceeded measured termination deadline")


def expiry_case(*, watchdog_first: bool) -> dict[str, Any]:
    token = uuid4().hex
    worker_seconds = 40 if watchdog_first else 20
    watchdog_seconds = 20 if watchdog_first else 25
    started = fd_resource.start(token, 64, worker_seconds, watchdog_seconds=watchdog_seconds)
    identity = {
        "pid": started["worker_pid"],
        "starttime_ticks": started["worker_starttime_ticks"],
        "uid": started["worker_uid"],
        "boot_id": started["boot_id"],
    }
    elapsed = wait_identity_terminated(identity, 30)
    cleaned = fd_resource.cleanup(token)
    return {
        "kind": "independent_watchdog" if watchdog_first else "worker_self_expiry",
        "worker_seconds": worker_seconds,
        "watchdog_seconds": watchdog_seconds,
        "termination_seconds_after_start_return": elapsed,
        "identity": identity,
        "cleanup": cleaned,
    }


def concurrent_lease_case() -> dict[str, Any]:
    tokens = [uuid4().hex, uuid4().hex]
    commands = [
        [
            str(ROOT / ".venv/bin/python"),
            "deploy/fd_resource.py",
            "start",
            "--token",
            token,
            "--limit",
            "64",
            "--seconds",
            "20",
        ]
        for token in tokens
    ]
    processes = [
        subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for command in commands
    ]
    results = []
    winner = None
    for token, process in zip(tokens, processes, strict=True):
        stdout, stderr = process.communicate(timeout=15)
        results.append(
            {
                "token": token,
                "exit_code": process.returncode,
                "stdout": stdout.decode(errors="replace")[-1000:],
                "stderr": stderr.decode(errors="replace")[-1000:],
            }
        )
        if process.returncode == 0:
            winner = token
    if sum(item["exit_code"] == 0 for item in results) != 1 or winner is None:
        raise RuntimeError("exclusive node-wide FD lease did not admit exactly one starter")
    cleanup = fd_resource.cleanup(winner)
    return {"attempts": results, "winner": winner, "cleanup": cleanup}


def main() -> None:
    report: dict[str, Any] = {
        "status": "failed",
        "environment": {
            "target": "native Linux production agent and helper in probe PID namespace",
            "reference": "production agent in a distinct Docker PID namespace",
            "shared_scope": "same disposable Docker network, host kernel, and PostgreSQL",
            "selection": "unmodified production CPU/RSS/configured FD selection",
            "configured_exclusion_subcase": (
                "controlled Linux selection fixtures cover configured priority outside top sets; "
                "the main lifecycle does not filter production top lists"
            ),
            "aws_execution": False,
        },
        "started_at": datetime.now(UTC).isoformat(),
        "source_manifest": runtime_manifest(),
        "cases": {},
        "cleanup": [],
    }
    failure: BaseException | None = None
    server = Server()
    backend = HttpBackend()
    injector: NativeInjector | None = None
    try:
        server.start()
        report["reference_baseline"] = wait_reference(backend)
        modes: tuple[Literal["release", "exit"], ...] = ("release", "exit")
        for mode in modes:
            injector = NativeInjector()
            output = Path("/tmp") / f"fd-harness-{mode}-{uuid4().hex}.json"
            harness = FdHarness(
                backend,
                injector,
                "node-a",
                "node-b",
                output,
                environment=report["environment"],
                manifest=runtime_manifest,
            )
            harness.after_diagnosis = lambda _, identifier: server.restart(backend, identifier)
            try:
                report["cases"][mode] = harness.run(mode, 128)
            finally:
                report["cleanup"].append(injector.stop_agent())
                if output.exists():
                    report["cases"][mode] = json.loads(output.read_text())
        report["exclusive_lease"] = concurrent_lease_case()
        report["watchdog_expiry"] = expiry_case(watchdog_first=True)
        report["worker_expiry"] = expiry_case(watchdog_first=False)
        bad_token = uuid4().hex
        try:
            fd_resource.start(bad_token, 64, 20, "root")
        except ValueError as exc:
            report["failed_start"] = {
                "error": f"{type(exc).__name__}: {exc}",
                "state": fd_resource.status(bad_token),
            }
        else:
            raise RuntimeError("invalid root worker start unexpectedly succeeded")
        metrics = backend.client.get("/metrics")
        metrics.raise_for_status()
        report["metrics"] = [
            line for line in metrics.text.splitlines() if line.startswith("fleetdoctor_fd_")
        ]
        if not any(line.startswith("fleetdoctor_fd_coverage_ratio") for line in report["metrics"]):
            raise RuntimeError("native collector did not export FD metrics")
        report["status"] = "passed"
    except BaseException as exc:
        failure = exc
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if injector is not None:
            try:
                report["cleanup"].append(injector.stop_agent())
            except BaseException as exc:
                failure = failure or exc
                report["cleanup"].append({"agent_stop_error": type(exc).__name__})
        backend.close()
        server.stop()
        report["source_manifest_after"] = runtime_manifest()
        if report["source_manifest_after"] != report["source_manifest"]:
            failure = failure or RuntimeError("source changed during native FD proof")
            report["status"] = "failed"
        report["finished_at"] = datetime.now(UTC).isoformat()
        print(json.dumps(report, sort_keys=True))
    if failure is not None:
        raise RuntimeError("native FD helper probe failed") from failure


if __name__ == "__main__":
    main()
