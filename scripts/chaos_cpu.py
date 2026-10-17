#!/usr/bin/env python3
"""Bounded CPU saturation harness using ordinary FleetDoctor telemetry."""

import argparse
import hashlib
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.request import Request, urlopen

from chaos_harness import source_manifest


def api(url: str, token: str) -> dict[str, Any]:
    request = Request(url, headers={"Authorization": "Bearer " + token})
    with urlopen(request, timeout=2) as response:
        return cast(dict[str, Any], json.load(response))


def helper(
    path: Path, action: str, token: str, workers: int = 0, seconds: int = 0
) -> dict[str, Any]:
    argv = ["sudo", str(path), action, "--token", token]
    if action == "start":
        argv += ["--workers", str(workers), "--seconds", str(seconds)]
    result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("CPU helper " + action + " failed")
    return cast(dict[str, Any], json.loads(result.stdout))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-token", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--reference-node", required=True)
    parser.add_argument("--helper", type=Path, default=Path("deploy/cpu_resource.py"))
    parser.add_argument("--workers", type=int, required=True)
    parser.add_argument("--seconds", type=int, choices=range(15, 181), default=60)
    parser.add_argument("--timeout", type=int, choices=range(30, 301), default=180)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("refusing to overwrite CPU harness report")
    online = os.cpu_count() or 0
    expected = min(64, 2 * online)
    if args.workers != expected or online < 1:
        raise ValueError("host saturation requires exactly min(64, 2*online logical CPUs) workers")
    token = hashlib.sha256(os.urandom(32)).hexdigest()[:24]
    started = time.monotonic()
    report: dict[str, Any] = {
        "status": "failed",
        "scenario": "cpu_saturation",
        "node": args.node,
        "reference_node": args.reference_node,
        "token": token,
        "started_at": datetime.now(UTC).isoformat(),
        "workers": args.workers,
        "seconds": args.seconds,
        "observations": [],
        "cleanup": None,
        "source_manifest": source_manifest(),
        "environment": {
            "uname": list(os.uname()) if hasattr(os, "uname") else None,
            "online_logical_cores": online,
            "affinity": sorted(os.sched_getaffinity(0))
            if hasattr(os, "sched_getaffinity")
            else None,
            "scope": "host",
        },
    }
    failure: BaseException | None = None
    incident_id: str | None = None
    try:
        before = api(args.base_url + "/nodes/" + args.node + "/metrics", args.api_token)
        reference = api(
            args.base_url + "/nodes/" + args.reference_node + "/metrics", args.api_token
        )
        required = ("host_rates", "runnable", "logical_cores")
        if (
            not before.get("fresh")
            or before.get("active_incident_counts", {}).get("cpu_saturation")
            or any(before.get("cpu_coverage", {}).get(name) != "available" for name in required)
        ):
            raise RuntimeError("target preflight is not fresh and CPU-incident-free")
        if reference.get("active_incident_counts", {}).get("cpu_saturation"):
            raise RuntimeError("reference node already has a CPU incident")
        report["preflight"] = {"target": before, "reference": reference}
        report["configuration"] = api(args.base_url + "/configuration", args.api_token)
        report["configuration_sha256"] = hashlib.sha256(
            json.dumps(report["configuration"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        report["injection"] = helper(args.helper, "start", token, args.workers, args.seconds)
        deadline = started + args.timeout - 30
        incident = None
        while time.monotonic() < deadline:
            rows = api(
                args.base_url
                + "/diagnoses?node="
                + args.node
                + "&rule=cpu_saturation&status=active",
                args.api_token,
            )
            if rows.get("diagnoses"):
                incident = rows["diagnoses"][0]
                break
            time.sleep(1)
        if incident is None:
            raise TimeoutError("CPU incident did not open before cleanup reserve")
        detail = api(args.base_url + "/diagnoses/" + incident["id"], args.api_token)
        evidence = detail["opening_evidence"]
        cpu = evidence["cpu"]
        config = detail["configuration"]
        if (
            detail.get("node_id") != args.node
            or detail.get("rule") != "cpu_saturation"
            or detail.get("resource") != "cpu"
            or cpu["busy_percent"] < config["trigger_busy_percent"]
            or cpu["runnable_processes"] <= cpu["logical_cores"]
        ):
            raise RuntimeError("incident is not linked to an ordinary telemetry trigger")
        incident_id = str(detail["id"])
        report["incident"] = detail
        report["trigger_to_diagnosis_seconds"] = time.monotonic() - started
    except BaseException as exc:
        report["error"] = type(exc).__name__
        failure = exc
    finally:
        try:
            report["cleanup"] = helper(args.helper, "cleanup", token)
        except BaseException as exc:
            report["cleanup"] = {"cleaned": False, "error": type(exc).__name__}
            if failure is None:
                failure = exc
        if failure is None and incident_id is not None:
            recovery_deadline = time.monotonic() + 30
            while time.monotonic() < recovery_deadline:
                detail = api(args.base_url + "/diagnoses/" + incident_id, args.api_token)
                reference = api(
                    args.base_url + "/nodes/" + args.reference_node + "/metrics", args.api_token
                )
                if reference.get("active_incident_counts", {}).get("cpu_saturation"):
                    failure = RuntimeError("reference node opened a CPU incident")
                    break
                if detail.get("status") == "resolved":
                    report["recovery"] = detail
                    report["status"] = "passed"
                    break
                time.sleep(1)
            else:
                failure = TimeoutError("three-sample CPU recovery did not complete")
        report["finished_at"] = datetime.now(UTC).isoformat()
        report["source_manifest_after"] = source_manifest()
        if report["source_manifest"] != report["source_manifest_after"] and failure is None:
            failure = RuntimeError("source changed during CPU harness")
        if failure is not None:
            report["status"] = "failed"
            report.setdefault("error", type(failure).__name__)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if failure is not None:
        raise RuntimeError("CPU harness failed; retained report: " + str(args.output)) from failure


if __name__ == "__main__":
    main()
