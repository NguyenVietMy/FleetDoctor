#!/usr/bin/env python3
"""Run a non-saturating real Linux CPU collection/workload/cleanup smoke."""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from fleetdoctor.cpu import CpuCollector


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, choices=(1, 2), default=2)
    parser.add_argument("--seconds", type=int, choices=range(1, 6), default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "posix" or not Path("/proc/stat").is_file():
        raise RuntimeError("native Linux /proc is required")
    if args.output.exists():
        raise FileExistsError("refusing to overwrite smoke report")
    collector = CpuCollector()
    first = collector.collect()
    process = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).parents[1] / "deploy" / "cpu_resource.py"),
            "worker",
            "--workers",
            str(args.workers),
            "--seconds",
            str(args.seconds),
        ],
        start_new_session=True,
    )
    interrupted = False
    try:
        process_baseline = collector.collect((process.pid,))
        time.sleep(min(1.0, args.seconds / 2))
        second = collector.collect((process.pid,))
        process.wait(timeout=args.seconds + 3)
    except BaseException:
        interrupted = True
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
        raise
    finally:
        cleanup_ok = process.poll() is not None
    process_delta = next(
        (
            item.cpu_percent
            for item in second.processes
            if item.configured and item.identity.pid == process.pid
        ),
        None,
    )
    report = {
        "status": "passed"
        if cleanup_ok and second.busy_percent is not None and process_delta is not None
        else "failed",
        "scope": "limited_workload_smoke_not_host_saturation",
        "workers": args.workers,
        "seconds": args.seconds,
        "first": first.model_dump(mode="json"),
        "process_baseline": process_baseline.model_dump(mode="json"),
        "workload": second.model_dump(mode="json"),
        "configured_process_cpu_percent": process_delta,
        "cleanup_ok": cleanup_ok,
        "interrupted": interrupted,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2), encoding="utf-8")
    os.replace(temporary, args.output)
    if report["status"] != "passed":
        raise RuntimeError("CPU smoke did not observe a valid interval")


if __name__ == "__main__":
    main()
