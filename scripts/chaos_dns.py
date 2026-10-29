#!/usr/bin/env python3
"""Run one DNS scenario or aggregate five retained complete run receipts."""

from __future__ import annotations

import argparse
import json
import os
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chaos_harness import source_manifest
from dns_harness import DnsHarness, aggregate


def save(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api")
    parser.add_argument("--node")
    parser.add_argument("--reference-node")
    parser.add_argument("--invalid-resolver", default="203.0.113.254")
    parser.add_argument("--environment-label", default="local-unspecified")
    parser.add_argument("--topology-label", default="two-node-local")
    parser.add_argument("--run", action="append", type=Path, default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    partial = args.output.with_suffix(args.output.suffix + ".partial")
    if args.output.exists() or partial.exists():
        raise FileExistsError("refusing to overwrite retained DNS attempt")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "environment_metadata": {
            "label": args.environment_label,
            "platform": platform.platform(),
            "kernel": platform.release(),
            "python": platform.python_version(),
        },
        "topology": args.topology_label,
        "source_manifest": source_manifest(),
        "measurement_contract": {
            "sample_interval_seconds": 5,
            "probe_echoes": 3,
            "http_timeout_seconds": 3,
            "diagnosis_deadline_after_trigger_seconds": 60,
            "recovery_deadline_after_cleanup_seconds": 60,
            "median_acceptance_seconds_strictly_less_than": 30,
        },
        "aws_execution": False,
        "aws_region": None,
        "aws_instance_ids": None,
        "ssh_execution": False,
        "events": [],
    }
    save(args.output, result)
    try:
        if args.run:
            if len(args.run) != 5 or len(set(args.run)) != 5:
                raise ValueError("five-run aggregation requires five unique retained paths")
            result["input_paths"] = [str(path) for path in args.run]
            result["aggregate"] = aggregate(
                [json.loads(path.read_text(encoding="utf-8")) for path in args.run]
            )
            result["status"] = result["aggregate"]["status"]
            if result["status"] != "passed":
                raise RuntimeError(str(result["aggregate"].get("failure", "aggregate failed")))
        else:
            if not args.api or not args.node or not args.reference_node:
                parser.error("single-run mode requires --api, --node and --reference-node")

            def record(event: str, value: dict[str, Any]) -> None:
                result["events"].append(
                    {"event": event, "at": datetime.now(UTC).isoformat(), "snapshot": value}
                )
                save(args.output, result)

            result["scenario"] = DnsHarness(
                args.api,
                args.node,
                args.reference_node,
                recorder=record,
            ).run(invalid_resolver=args.invalid_resolver)
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
