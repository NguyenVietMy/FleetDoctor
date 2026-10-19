"""Run the native inode/PostgreSQL proof in uniquely owned Docker resources."""

import argparse
import json
import secrets
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from chaos_harness import source_manifest

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("refusing to overwrite inode proof report")
    scope = "fd07-inode-" + uuid4().hex[:10]
    network, postgres, helper = scope + "-net", scope + "-pg", scope + "-helper"
    tag = scope + ":test"
    password, reader_password = secrets.token_hex(24), secrets.token_hex(24)
    result: dict[str, Any] = {
        "status": "failed",
        "scope": scope,
        "environment": "owned-network-plus-PostgreSQL-plus-privileged-private-tmpfs",
        "started_at": datetime.now(UTC).isoformat(),
        "source_manifest": source_manifest(),
        "aws_execution": False,
        "cleanup": {},
    }
    failure: BaseException | None = None
    postgres_volume = ""
    try:
        built = run(["docker", "build", "--target", "disk-test", "-t", tag, "."], 240)
        result["build_exit"] = built.returncode
        if built.returncode:
            result["build_log"] = (built.stderr or built.stdout)[-5000:]
            raise RuntimeError("inode proof image build failed")
        if run(["docker", "network", "create", network]).returncode:
            raise RuntimeError("owned proof network creation failed")
        pg = run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                postgres,
                "--network",
                network,
                "--env",
                "POSTGRES_DB=fleetdoctor",
                "--env",
                "POSTGRES_USER=fleetdoctor",
                "--env",
                "POSTGRES_PASSWORD=" + password,
                "postgres:17.6-alpine",
            ],
            60,
        )
        if pg.returncode:
            raise RuntimeError("owned PostgreSQL container creation failed")
        proof = run(
            [
                "docker",
                "run",
                "--name",
                helper,
                "--network",
                network,
                "--privileged",
                "--tmpfs",
                "/var/lib/fleetdoctor/chaos:rw,size=768m,mode=0755",
                "--env",
                f"FLEETDOCTOR_PROOF_DSN=host={postgres} port=5432 dbname=fleetdoctor user=fleetdoctor password={password}",
                "--env",
                "FLEETDOCTOR_READER_PASSWORD=" + reader_password,
                tag,
                "/app/.venv/bin/python",
                "scripts/inode_helper_probe.py",
            ],
            180,
        )
        result["run_exit"] = proof.returncode
        result["stderr"] = proof.stderr[-5000:]
        try:
            result["proof"] = json.loads(proof.stdout)
        except ValueError:
            result["stdout"] = proof.stdout[-5000:]
        if proof.returncode or result.get("proof", {}).get("status") != "passed":
            raise RuntimeError("native inode/PostgreSQL proof failed")
        result["status"] = "passed"
    except BaseException as exc:
        failure = exc
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        inspected = run(
            [
                "docker",
                "inspect",
                "--format",
                '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{end}}{{end}}',
                postgres,
            ],
            15,
        )
        if inspected.returncode == 0:
            postgres_volume = inspected.stdout.strip()
            result["postgres_anonymous_volume"] = postgres_volume
        loop_cleanup = result.get("proof", {}).get("cleanup", {}).get("loop_resource", {})
        loop_cleanup_proven = isinstance(loop_cleanup, dict) and all(
            (
                loop_cleanup.get("rollback_mount") is True,
                loop_cleanup.get("mount_absent") is True,
                loop_cleanup.get("image_absent") is True,
                loop_cleanup.get("loop_mappings_remaining") == [],
                loop_cleanup.get("resource_manifest_absent") is True,
            )
        )
        helper_exists = run(["docker", "inspect", helper], 15).returncode == 0
        result["cleanup"]["loop_cleanup_proven_before_container_removal"] = loop_cleanup_proven
        removals: list[tuple[str, list[str]]] = []
        if not helper_exists:
            result["cleanup"]["helper"] = "not_created_or_already_absent"
        elif loop_cleanup_proven:
            removals.append(("helper", ["docker", "rm", "--force", helper]))
        else:
            result["cleanup"]["helper"] = "retained_without_verified_loop_rollback"
            failure = failure or RuntimeError(
                "helper container retained because loop rollback is not proven"
            )
            result["status"] = "failed"
        removals.extend(
            (
                ("postgres", ["docker", "rm", "--force", "--volumes", postgres]),
                ("network", ["docker", "network", "rm", network]),
                ("image", ["docker", "image", "rm", tag]),
            )
        )
        for kind, argv in removals:
            removed = run(argv, 30)
            result["cleanup"][kind] = removed.returncode
        absence = {
            "helper_container_absent": run(["docker", "inspect", helper], 15).returncode != 0,
            "postgres_container_absent": run(["docker", "inspect", postgres], 15).returncode != 0,
            "network_absent": run(["docker", "network", "inspect", network], 15).returncode != 0,
            "image_absent": run(["docker", "image", "inspect", tag], 15).returncode != 0,
            "postgres_volume_absent": not postgres_volume
            or run(["docker", "volume", "inspect", postgres_volume], 15).returncode != 0,
        }
        result["cleanup"]["verified_absent"] = absence
        if not all(absence.values()):
            failure = failure or RuntimeError("owned Docker proof resources were retained")
            result["status"] = "failed"
        result["source_manifest_after"] = source_manifest()
        if result["source_manifest_after"] != result["source_manifest"]:
            failure = failure or RuntimeError("source changed during inode integration")
            result["status"] = "failed"
        result["finished_at"] = datetime.now(UTC).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if failure is not None:
        raise RuntimeError("inode proof failed; retained report: " + str(args.output)) from failure


if __name__ == "__main__":
    main()
