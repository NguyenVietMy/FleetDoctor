"""Run the native FD helper/API/PostgreSQL proof in uniquely owned Docker resources."""

import argparse
import json
import secrets
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from chaos_harness import source_manifest

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else exc.stdout
        )
        stderr = (
            exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else exc.stderr
        )
        return subprocess.CompletedProcess(argv, 124, stdout or "", stderr or "command timed out")
    except OSError as exc:
        return subprocess.CompletedProcess(argv, 127, "", f"{type(exc).__name__}: {exc}")


def absence_status(
    result: subprocess.CompletedProcess[str],
    kind: Literal["container", "network", "image", "volume"],
    name: str,
) -> Literal["absent", "present", "unknown"]:
    """Accept only an inspect success or Docker's exact no-such-object diagnostics."""
    if result.returncode == 0:
        return "present"
    error = (result.stderr or "") + "\n" + (result.stdout or "")
    expected = {
        "container": (f"No such object: {name}",),
        "network": (f"network {name} not found",),
        "image": (f"No such image: {name}", f"No such object: {name}"),
        "volume": (f"No such volume: {name}", f"get {name}: no such volume"),
    }
    return "absent" if any(message in error for message in expected[kind]) else "unknown"


def verify_absence(
    argv: list[str], kind: Literal["container", "network", "image", "volume"], name: str
) -> dict[str, Any]:
    result = run(argv, 30)
    status = absence_status(result, kind, name)
    return {
        "status": status,
        "exit": result.returncode,
        "diagnostic": (result.stderr or result.stdout)[-500:] if status != "absent" else "",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("refusing to overwrite FD proof report")
    scope = "fd08-native-" + uuid4().hex[:10]
    network, postgres, probe, reference = (
        scope + "-net",
        scope + "-pg",
        scope + "-probe",
        scope + "-reference",
    )
    tag = scope + ":test"
    postgres_volume = scope + "-pgdata"
    password, reader_password = secrets.token_hex(24), secrets.token_hex(24)
    report: dict[str, Any] = {
        "status": "failed",
        "scope": scope,
        "environment": "disposable-Linux-Docker-native-proc-production-API-real-PostgreSQL",
        "aws_execution": False,
        "started_at": datetime.now(UTC).isoformat(),
        "source_manifest": source_manifest(),
        "cleanup": {},
    }
    failure: BaseException | None = None
    try:
        built = run(["docker", "build", "--target", "test", "-t", tag, "."], 240)
        report["build_exit"] = built.returncode
        if built.returncode:
            report["build_log"] = (built.stderr or built.stdout)[-5000:]
            raise RuntimeError("FD proof image build failed")
        if run(["docker", "network", "create", network]).returncode:
            raise RuntimeError("owned FD proof network creation failed")
        if run(["docker", "volume", "create", postgres_volume]).returncode:
            raise RuntimeError("owned FD proof volume creation failed")
        started = run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                postgres,
                "--network",
                network,
                "--volume",
                postgres_volume + ":/var/lib/postgresql/data",
                "--env",
                "POSTGRES_DB=fleetdoctor",
                "--env",
                "POSTGRES_USER=fleetdoctor",
                "--env",
                "POSTGRES_PASSWORD=" + password,
                "postgres:17.6-alpine",
            ]
        )
        if started.returncode:
            raise RuntimeError("owned PostgreSQL container creation failed")
        ready = False
        for _ in range(60):
            check = run(["docker", "exec", postgres, "pg_isready", "-U", "fleetdoctor"], 5)
            if check.returncode == 0:
                ready = True
                break
            __import__("time").sleep(0.25)
        if not ready:
            raise TimeoutError("owned PostgreSQL did not become ready")
        node_tokens = json.dumps({"node-a": "f" * 40, "node-b": "e" * 40})
        probe_start = run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                probe,
                "--network",
                network,
                "--env",
                "PGHOST=" + postgres,
                "--env",
                "POSTGRES_PASSWORD=" + password,
                "--env",
                "GRAFANA_DB_PASSWORD=" + reader_password,
                "--env",
                "FLEETDOCTOR_NODE_TOKENS=" + node_tokens,
                "--env",
                "FLEETDOCTOR_TARGET_TOKEN=" + "f" * 40,
                tag,
                "/app/.venv/bin/python",
                "scripts/fd_helper_probe.py",
            ],
        )
        if probe_start.returncode:
            raise RuntimeError("native FD probe container failed to start")
        reference_start = run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                reference,
                "--network",
                network,
                "--env",
                "FLEETDOCTOR_NODE_ID=node-b",
                "--env",
                f"FLEETDOCTOR_COLLECTOR_URL=http://{probe}:8000",
                "--env",
                "FLEETDOCTOR_PROOF_TOKEN=" + "e" * 40,
                tag,
                "/app/.venv/bin/python",
                "scripts/fd_agent_probe.py",
            ]
        )
        if reference_start.returncode:
            raise RuntimeError("isolated reference agent container failed to start")
        waited = run(["docker", "wait", probe], 360)
        logs = run(["docker", "logs", probe], 30)
        report["run_exit"] = int(waited.stdout.strip()) if waited.returncode == 0 else -1
        report["stderr"] = logs.stderr[-5000:]
        try:
            lines = logs.stdout.splitlines()
            report["proof"] = json.loads(lines[-1]) if lines else None
        except ValueError:
            report["stdout"] = logs.stdout[-5000:]
        if report["run_exit"] or (report.get("proof") or {}).get("status") != "passed":
            raise RuntimeError("native FD/PostgreSQL probe failed")
        report["status"] = "passed"
    except BaseException as exc:
        failure = exc
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for kind, argv in (
            ("reference", ["docker", "rm", "--force", reference]),
            ("probe", ["docker", "rm", "--force", probe]),
            ("postgres", ["docker", "rm", "--force", "--volumes", postgres]),
            ("network", ["docker", "network", "rm", network]),
            ("volume", ["docker", "volume", "rm", postgres_volume]),
            ("image", ["docker", "image", "rm", tag]),
        ):
            report["cleanup"][kind] = run(argv, 30).returncode
        verification = {
            "reference_container": verify_absence(
                ["docker", "inspect", reference], "container", reference
            ),
            "probe_container": verify_absence(["docker", "inspect", probe], "container", probe),
            "postgres_container": verify_absence(
                ["docker", "inspect", postgres], "container", postgres
            ),
            "network": verify_absence(
                ["docker", "network", "inspect", network], "network", network
            ),
            "image": verify_absence(["docker", "image", "inspect", tag], "image", tag),
            "postgres_volume": verify_absence(
                ["docker", "volume", "inspect", postgres_volume], "volume", postgres_volume
            ),
        }
        absence = {
            name + "_absent": value["status"] == "absent" for name, value in verification.items()
        }
        report["cleanup"]["verification"] = verification
        report["cleanup"]["verified_absent"] = absence
        if not all(absence.values()):
            failure = failure or RuntimeError("owned FD proof resources were retained")
            report["status"] = "failed"
        report["source_manifest_after"] = source_manifest()
        if report["source_manifest_after"] != report["source_manifest"]:
            failure = failure or RuntimeError("source changed during FD integration")
            report["status"] = "failed"
        report["finished_at"] = datetime.now(UTC).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if failure is not None:
        raise RuntimeError("FD proof failed; retained report: " + str(args.output)) from failure


if __name__ == "__main__":
    main()
