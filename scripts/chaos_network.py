"""Run or aggregate retained measured network-degradation attempts."""

import argparse
import json
import os
import platform
import statistics
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chaos_harness import source_manifest
from network_harness import NetworkHarness


def save(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def aggregate(paths: list[Path]) -> dict[str, Any]:
    if len(paths) != 5 or len(set(paths)) != 5:
        raise ValueError("five-run aggregation requires exactly five unique attempts")
    attempts = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    complete = [
        item
        for item in attempts
        if item.get("status") == "passed"
        and item.get("scenario", {}).get("status") == "passed"
        and item["scenario"].get("latency", {}).get("status") == "passed"
        and item["scenario"].get("loss", {}).get("status") == "passed"
    ]
    result: dict[str, Any] = {
        "status": "passed" if len(complete) == 5 else "failed",
        "required_runs": 5,
        "complete_runs": len(complete),
        "inputs": [str(path) for path in paths],
        "attempts": attempts,
    }
    if len(complete) == 5:
        comparable = {
            (
                tuple(sorted((item["scenario"]["node"], item["scenario"]["reference_node"]))),
                item["scenario"]["target"],
                json.dumps(item["scenario"]["configuration"], sort_keys=True),
                json.dumps(item["source_manifest"], sort_keys=True),
                json.dumps(item["environment_metadata"], sort_keys=True),
            )
            for item in complete
        }
        if len(comparable) != 1:
            result["status"] = "failed"
            result["failure"] = "five runs are not configuration- and identity-comparable"
        else:
            latency = [
                item["scenario"]["latency"]["trigger_to_diagnosis_seconds"] for item in complete
            ]
            loss = [item["scenario"]["loss"]["trigger_to_diagnosis_seconds"] for item in complete]
            result.update(
                latency_phase_median_seconds=statistics.median(latency),
                loss_phase_median_seconds=statistics.median(loss),
                slower_per_run_seconds=[
                    max(left, right) for left, right in zip(latency, loss, strict=True)
                ],
                faulted_nodes=[item["scenario"]["node"] for item in complete],
                latency_under_30_seconds=[value < 30 for value in latency],
                loss_under_30_seconds=[value < 30 for value in loss],
            )
            result["phase_latency_acceptance"] = result["latency_phase_median_seconds"] < 30
            result["phase_loss_acceptance"] = result["loss_phase_median_seconds"] < 30
            if not result["phase_latency_acceptance"] or not result["phase_loss_acceptance"]:
                result["status"] = "failed"
                result["failure"] = "one or more profile medians were 30 seconds or more"
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api")
    parser.add_argument("--node")
    parser.add_argument("--reference-node")
    parser.add_argument("--target")
    parser.add_argument("--surrogate-url")
    parser.add_argument("--environment-label", default="local-unspecified")
    parser.add_argument("--topology-label", default="two-node-local")
    parser.add_argument("--input", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.with_suffix(args.output.suffix + ".partial").exists():
        raise FileExistsError("refusing to overwrite retained network attempt")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "environment": "caller-declared-local-or-lab",
        "environment_metadata": {
            "label": args.environment_label,
            "topology": args.topology_label,
            "platform": platform.platform(),
            "kernel": platform.release(),
            "python": platform.python_version(),
        },
        "source_manifest": source_manifest(),
        "measurement_contract": {
            "sample_interval_seconds": 5,
            "probe_echoes": 3,
            "probe_worker_budget_seconds": 3,
            "http_timeout_seconds": 3,
            "diagnosis_deadline_seconds": 60,
            "recovery_deadline_seconds": 60,
            "phase_acceptance_seconds_strictly_less_than": 30,
        },
        "aws_execution": False,
        "aws_region": None,
        "aws_instance_ids": None,
        "ssh_execution": False,
        "events": [],
    }
    save(args.output, result)
    try:
        if args.input:
            result["aggregate"] = aggregate(args.input)
            result["status"] = result["aggregate"]["status"]
            if result["status"] != "passed":
                raise RuntimeError("five-run aggregate is incomplete or incomparable")
        else:
            required = (args.api, args.node, args.reference_node, args.target, args.surrogate_url)
            if any(value is None for value in required):
                parser.error(
                    "single run requires api, node, reference-node, target, and surrogate-url"
                )

            def record(event: str, value: dict[str, Any]) -> None:
                result["events"].append(
                    {"event": event, "at": datetime.now(UTC).isoformat(), "snapshot": value}
                )
                save(args.output, result)

            result["scenario"] = NetworkHarness(
                args.api,
                args.node,
                args.reference_node,
                args.target,
                args.surrogate_url,
                recorder=record,
            ).run()
            for phase in ("latency", "loss"):
                elapsed = result["scenario"][phase]["trigger_to_diagnosis_seconds"]
                result["scenario"][phase]["diagnosis_under_30_seconds"] = elapsed < 30
            result["scenario"]["phase_latency_acceptance"] = result["scenario"]["latency"][
                "diagnosis_under_30_seconds"
            ]
            result["scenario"]["phase_loss_acceptance"] = result["scenario"]["loss"][
                "diagnosis_under_30_seconds"
            ]
            result["status"] = "passed"
    except BaseException as exc:
        result["status"] = "failed"
        result["failure"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        result["finished_at"] = datetime.now(UTC).isoformat()
        save(args.output, result)


if __name__ == "__main__":
    main()
