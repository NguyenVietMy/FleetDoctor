"""Run bounded inode exhaustion on an existing lab node, or recover a retained run."""

import argparse
import hashlib
import json
import signal
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from chaos_harness import LEASE_DIRECTORY, InodeHarness, write_report
from lab import ROOT, addresses, command, inventory


class API:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = httpx.get(self.url + path, params=params, timeout=2, trust_env=False)
        response.raise_for_status()
        value: dict[str, Any] = response.json()
        return value


class RemoteInjector:
    def __init__(self, ssh: list[str]) -> None:
        self.ssh = ssh
        self.commands: list[str] = []

    def call(self, action: str, token: str = "", duration: int = 180) -> dict[str, Any]:
        from uuid import UUID

        if token and UUID(token).hex != token:
            raise ValueError("invalid inode cleanup token")
        cmd = f"sudo python3.11 /opt/fleetdoctor/current/deploy/inode_resource.py {action}"
        if token:
            cmd += f" --token {token} --duration {duration}"
        self.commands.append(cmd)
        value: dict[str, Any] = json.loads(command(self.ssh + [cmd], timeout=30))
        return value

    def probe(self) -> dict[str, Any]:
        return self.call("probe")

    def start(self, token: str, duration: int) -> dict[str, Any]:
        return self.call("start", token, duration)

    def status(self, token: str) -> dict[str, Any]:
        return self.call("status", token)

    def cleanup(self, token: str) -> dict[str, Any]:
        return self.call("cleanup", token)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--target", choices=("node-a", "node-b"), default="node-a")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--profile", default="fleetdoctor")
    parser.add_argument("--key", type=Path, default=Path.home() / ".ssh/fleetdoctor")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--cleanup-report", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("use a new report path; failed inode runs are retained")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    boundary: dict[str, Any] = {
        "schema_version": 1,
        "scenario": "inode_exhaustion",
        "target": args.target,
        "resource": "/var/lib/fleetdoctor/chaos/disk",
        "status": "preparing",
        "injection_attempted": False,
        "preflight_path": str(args.preflight),
        "started_at": datetime.now(UTC).isoformat(),
        "errors": [],
    }

    def interrupted(signum: int, frame: object) -> None:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise InterruptedError("inode controller interrupted")

    old_signals = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        execute(args)
    except BaseException as exc:
        if not args.output.exists():
            boundary["status"] = "failed"
            boundary["phase"] = "preparation"
            boundary["errors"].append(type(exc).__name__ + ": " + str(exc))
            boundary["finished_at"] = datetime.now(UTC).isoformat()
            write_report(args.output, boundary)
        raise
    finally:
        for sig, handler in old_signals.items():
            signal.signal(sig, handler)


def execute(args: argparse.Namespace) -> None:
    environment: dict[str, Any] = json.loads(args.preflight.read_text())
    if environment["status"] != "passed":
        raise ValueError("successful preflight required")
    local = {
        "src/fleetdoctor/" + path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (ROOT / "src/fleetdoctor").glob("*.py")
    }
    if local != environment["source_sha256"]:
        raise ValueError("preflight source differs from current build")
    if (
        not args.cleanup_report
        and not 0
        <= (datetime.now(UTC) - datetime.fromisoformat(environment["finished_at"])).total_seconds()
        <= 300
    ):
        raise ValueError("preflight must be completed within five minutes")
    hosts = addresses(args.profile, inventory(args.inventory))
    injectors = {
        role: RemoteInjector(
            [
                "ssh",
                "-i",
                str(args.key),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=accept-new",
                f"ec2-user@{host}",
            ]
        )
        for role, host in hosts.items()
        if role != "monitor"
    }
    api = API(args.api)
    if args.cleanup_report:
        retained = json.loads(args.cleanup_report.read_text())
        if retained["target"] != args.target or retained["scenario"] != "inode_exhaustion":
            raise ValueError("cleanup target/scenario differs from retained inode run")
        result = injectors[args.target].cleanup(retained["token"])
        retained["explicit_cleanup"] = result
        retained["explicit_cleanup_utc"] = datetime.now(UTC).isoformat()
        from time import monotonic, sleep

        deadline = monotonic() + 60
        while monotonic() <= deadline:
            nodes = api.get("/nodes")["nodes"]
            target = next(node for node in nodes if node["node_id"] == args.target)
            healthy = target["fresh"] and any(
                fs["mountpoint"] == retained["resource"]
                and fs["inode_usage_percent"] is not None
                and fs["inode_usage_percent"]
                < retained["configuration"]["inode_rule"]["recovery_percent"]
                for fs in target["filesystems"] or []
            )
            active = api.get(
                "/diagnoses",
                {"node": args.target, "rule": "inode_exhaustion", "status": "active"},
            )["diagnoses"]
            if healthy and not active:
                retained["explicit_recovery"] = nodes
                write_report(args.output, retained)
                lease = LEASE_DIRECTORY / ("filesystem-" + args.target + ".lease")
                if lease.exists() and lease.read_text() == retained["token"]:
                    lease.unlink()
                return
            sleep(1)
        write_report(args.output, retained)
        raise TimeoutError("explicit inode recovery deadline")

    harness = InodeHarness(
        api,
        injectors[args.target],
        args.target,
        "node-b" if args.target == "node-a" else "node-a",
        args.output,
        {
            "kind": "AWS-existing-three-node-lab",
            "preflight": environment,
            "visual_inspection": "unrun",
        },
    )
    try:
        harness.report["resource_mappings"] = {
            node: injector.probe() for node, injector in injectors.items()
        }
        harness.run()
    except BaseException as exc:
        if harness.report["status"] == "running":
            harness.report["status"] = "failed"
            harness.report["errors"].append("preparation: " + type(exc).__name__ + ": " + str(exc))
        raise
    finally:
        harness.report["remote_commands"] = {
            node: injector.commands for node, injector in injectors.items()
        }
        write_report(args.output, harness.report)
    print(f"Inode run passed; report: {args.output}")


if __name__ == "__main__":
    main()
