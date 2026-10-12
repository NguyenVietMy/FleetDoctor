"""Run uniquely scoped privileged Linux disk proof, retaining actual failures."""

import argparse
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    name = "fd02-disk-" + uuid4().hex[:10]
    tag = name + ":test"
    result: dict[str, Any] = {
        "name": name,
        "environment": "isolated-privileged-Docker",
        "started_at": datetime.now(UTC).isoformat(),
        "aws_execution": False,
    }
    try:
        built = subprocess.run(
            ["docker", "build", "--target", "disk-test", "-t", tag, "."],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=240,
        )
        result["build_exit"] = built.returncode
        if built.returncode:
            result["build_log"] = built.stderr[-5000:]
            raise RuntimeError("isolated helper image build failed")
        run = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                name,
                "--privileged",
                "--tmpfs",
                "/var/lib/fleetdoctor/chaos:rw,size=768m,mode=0755",
                tag,
                "/app/.venv/bin/python",
                "scripts/disk_helper_probe.py",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=150,
        )
        result["run_exit"] = run.returncode
        result["stderr"] = run.stderr[-5000:]
        try:
            result["proof"] = json.loads(run.stdout)
        except ValueError:
            result["stdout"] = run.stdout[-5000:]
        if run.returncode:
            raise RuntimeError("isolated helper proof failed")
        result["status"] = "passed"
    except BaseException as exc:
        result["status"] = "failed"
        result["error"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        removed = subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)
        image = subprocess.run(["docker", "image", "rm", tag], capture_output=True, timeout=15)
        result["cleanup"] = {
            "container_remove_exit": removed.returncode,
            "image_remove_exit": image.returncode,
            "scope": name,
        }
        result["finished_at"] = datetime.now(UTC).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
