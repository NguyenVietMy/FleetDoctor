#!/usr/bin/env python3
"""Measured workload-OOM harness for a separately prepared, agent-observed resource."""

import argparse
import hashlib
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from chaos_harness import source_manifest


def remaining(deadline: float, operation: str) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError(operation + " exceeded its after-call deadline")
    return seconds


def api(url: str, token: str, deadline: float) -> dict[str, Any]:
    operation = "API call " + url
    request = Request(url, headers={"Authorization": "Bearer " + token})
    with urlopen(request, timeout=min(2, remaining(deadline, operation))) as response:
        value = cast(dict[str, Any], json.load(response))
    remaining(deadline, operation)
    return value


def helper(path: Path, action: str, token: str, deadline: float, *extra: str) -> dict[str, Any]:
    operation = "OOM helper " + action
    result = subprocess.run(
        ["sudo", str(path), action, "--token", token, *extra],
        check=False,
        capture_output=True,
        text=True,
        timeout=min(30, remaining(deadline, operation)),
    )
    remaining(deadline, operation)
    if result.returncode:
        raise RuntimeError(operation + " failed: " + (result.stderr or result.stdout)[-1000:])
    return cast(dict[str, Any], json.loads(result.stdout))


def sleep_until(deadline: float, seconds: float = 1) -> None:
    time.sleep(min(seconds, remaining(deadline, "polling interval")))


def workload(view: dict[str, Any], cgroup: str) -> dict[str, Any]:
    if not view.get("fresh"):
        raise RuntimeError("ordinary telemetry became stale during the scenario")
    result = next(
        (
            item
            for item in (view.get("memory") or {}).get("workloads", [])
            if item.get("cgroup_path") == cgroup
        ),
        None,
    )
    if result is None or result.get("events") is None:
        raise RuntimeError("exact workload ordinary telemetry is unavailable")
    return cast(dict[str, Any], result)


def sample_identity(view: dict[str, Any]) -> tuple[str, str, int, str]:
    sample = view.get("sample") or {}
    return (
        str(sample.get("boot_id")),
        str(sample.get("agent_session_id")),
        int(sample.get("sequence", -1)),
        str(sample.get("observed_at")),
    )


def generation_key(cgroup: str, item: dict[str, Any]) -> str:
    return "|".join((cgroup, str(item["boot_id"]), str(item["st_dev"]), str(item["st_ino"])))


def add_recovery_sample(
    identities: set[tuple[str, str, int, str]],
    identity: tuple[str, str, int, str],
    pre_stop_identity: tuple[str, str, int, str],
    observed: dict[str, Any],
    counters: tuple[int, int],
    expected_counters: tuple[int, int],
    recovery_percent: float,
) -> bool:
    eligible = (
        observed.get("events_stable") is True
        and observed.get("max_bytes") is not None
        and observed.get("usage_ratio") is not None
        and float(observed["usage_ratio"]) * 100 < recovery_percent
        and counters == expected_counters
        and identity != pre_stop_identity
        and identity not in identities
    )
    if eligible:
        identities.add(identity)
    return eligible


def active_ooms(base_url: str, api_token: str, node: str, deadline: float) -> list[dict[str, Any]]:
    query = urlencode({"node": node, "rule": "workload_oom", "status": "active", "limit": 100})
    result = api(base_url + "/diagnoses?" + query, api_token, deadline)
    return cast(list[dict[str, Any]], result.get("diagnoses", []))


def assert_reference(
    base_url: str,
    api_token: str,
    node: str,
    original_incidents: set[str],
    deadline: float,
) -> dict[str, Any]:
    view = api(base_url + "/nodes/" + node + "/metrics", api_token, deadline)
    if not view.get("fresh") or (view.get("memory_coverage") or {}).get("host") != "available":
        raise RuntimeError("reference ordinary memory telemetry became unhealthy")
    current = {str(row["id"]) for row in active_ooms(base_url, api_token, node, deadline)}
    if not current.issubset(original_incidents):
        raise RuntimeError("reference node opened a new workload OOM incident")
    return view


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-token", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--reference-node", required=True)
    parser.add_argument(
        "--token", required=True, help="token from the separately completed prepare step"
    )
    parser.add_argument(
        "--cgroup", required=True, help="exact prepared leaf configured in the agent"
    )
    parser.add_argument("--helper", type=Path, default=Path("deploy/memory_resource.py"))
    parser.add_argument("--allocation-bytes", type=int, default=96 * 1024 * 1024)
    parser.add_argument("--limit-bytes", type=int, default=48 * 1024 * 1024)
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--worker-user", default="fleetdoctor")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("refusing to overwrite OOM harness report")
    report: dict[str, Any] = {
        "status": "failed",
        "scenario": "workload_oom",
        "node": args.node,
        "reference_node": args.reference_node,
        "token": args.token,
        "cgroup_path": args.cgroup,
        "started_at": datetime.now(UTC).isoformat(),
        "source_manifest": source_manifest(),
        "environment": {
            "kernel": os.uname().release if hasattr(os, "uname") else None,
            "uid": os.geteuid() if hasattr(os, "geteuid") else None,
        },
        "ordinary_trigger_samples": [],
        "recovery_samples": [],
    }
    failure: BaseException | None = None
    stopped = False
    try:
        preflight_deadline = time.monotonic() + 30
        owned = helper(args.helper, "status", args.token, preflight_deadline)
        if owned.get("leaf_path") != args.cgroup or owned.get("phase") != "prepared":
            raise RuntimeError("exact prepared empty cgroup/token generation is unavailable")
        if owned.get("processes"):
            raise RuntimeError("prepared workload cgroup is not empty")
        target = api(
            args.base_url + "/nodes/" + args.node + "/metrics",
            args.api_token,
            preflight_deadline,
        )
        reference = api(
            args.base_url + "/nodes/" + args.reference_node + "/metrics",
            args.api_token,
            preflight_deadline,
        )
        target_workload = workload(target, args.cgroup)
        if not target_workload.get("events_stable"):
            raise RuntimeError("prepared cgroup baseline event bracket is unstable")
        if (
            not reference.get("fresh")
            or (reference.get("memory_coverage") or {}).get("host") != "available"
        ):
            raise RuntimeError("reference preflight ordinary telemetry is not fresh")
        generation = {
            "boot_id": target_workload["boot_id"],
            "st_dev": target_workload["st_dev"],
            "st_ino": target_workload["st_ino"],
        }
        exact_resource = generation_key(args.cgroup, target_workload)
        helper_generation = owned.get("generation")
        if not isinstance(helper_generation, dict) or generation != helper_generation | {
            "boot_id": target_workload["boot_id"]
        }:
            raise RuntimeError("agent and helper cgroup generations disagree")
        target_before = active_ooms(args.base_url, args.api_token, args.node, preflight_deadline)
        if any(row.get("resource") == exact_resource for row in target_before):
            raise RuntimeError(
                "the exact prepared cgroup generation already has an active incident"
            )
        reference_before = active_ooms(
            args.base_url, args.api_token, args.reference_node, preflight_deadline
        )
        reference_ids = {str(row["id"]) for row in reference_before}
        baseline_identity = sample_identity(target)
        baseline_counters = (
            int(target_workload["events"]["oom"]),
            int(target_workload["events"]["oom_kill"]),
        )
        while time.monotonic() < preflight_deadline:
            sleep_until(preflight_deadline)
            candidate = api(
                args.base_url + "/nodes/" + args.node + "/metrics",
                args.api_token,
                preflight_deadline,
            )
            candidate_workload = workload(candidate, args.cgroup)
            counters = (
                int(candidate_workload["events"]["oom"]),
                int(candidate_workload["events"]["oom_kill"]),
            )
            assert_reference(
                args.base_url,
                args.api_token,
                args.reference_node,
                reference_ids,
                preflight_deadline,
            )
            if (
                sample_identity(candidate) != baseline_identity
                and generation_key(args.cgroup, candidate_workload) == exact_resource
                and candidate_workload.get("events_stable") is True
                and counters == baseline_counters
            ):
                target = candidate
                target_workload = candidate_workload
                break
        else:
            raise TimeoutError("ordinary telemetry did not establish a stable empty baseline")
        if any(
            row.get("resource") == exact_resource
            for row in active_ooms(args.base_url, args.api_token, args.node, preflight_deadline)
        ):
            raise RuntimeError("exact prepared generation opened an incident during preflight")
        configuration = api(args.base_url + "/configuration", args.api_token, preflight_deadline)
        report["preflight"] = {
            "target": target,
            "reference": reference,
            "helper": owned,
            "exact_resource": exact_resource,
            "target_prior_generation_incidents": target_before,
            "reference_baseline_incidents": reference_before,
            "initialized_baseline_identity": sample_identity(target),
        }
        report["configuration"] = configuration
        report["configuration_sha256"] = hashlib.sha256(
            json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        start_deadline = time.monotonic() + 30
        report["injection"] = helper(
            args.helper,
            "start",
            args.token,
            start_deadline,
            "--allocation-bytes",
            str(args.allocation_bytes),
            "--limit-bytes",
            str(args.limit_bytes),
            "--seconds",
            str(args.seconds),
            "--worker-user",
            args.worker_user,
        )
        injection = report["injection"]
        limits = injection.get("limits") or {}
        monitors = injection.get("monitor_control_groups") or {}
        if (
            limits.get("memory.max") != str(args.limit_bytes)
            or limits.get("memory.swap.max") != "0"
            or limits.get("pids.max") != "4"
            or args.cgroup in str(injection.get("caller_cgroup", ""))
            or any(
                group == args.cgroup or str(group).startswith(args.cgroup + "/")
                for group in monitors.values()
                if group is not None
            )
        ):
            raise RuntimeError("finite limits or monitoring separation changed at injection")
        diagnosis_deadline = time.monotonic() + 60
        trigger_observed: float | None = None
        trigger_counters: tuple[int, int] | None = None
        detail: dict[str, Any] | None = None
        baseline_events = target_workload["events"]
        while time.monotonic() < diagnosis_deadline:
            target = api(
                args.base_url + "/nodes/" + args.node + "/metrics",
                args.api_token,
                diagnosis_deadline,
            )
            observed = workload(target, args.cgroup)
            if generation_key(args.cgroup, observed) != exact_resource:
                raise RuntimeError("prepared cgroup generation changed during the scenario")
            events = observed["events"]
            if int(events["oom_kill"]) > int(baseline_events["oom_kill"]):
                if trigger_observed is None:
                    trigger_observed = time.monotonic()
                    trigger_counters = (int(events["oom"]), int(events["oom_kill"]))
                    report["ordinary_trigger_samples"].append(
                        {
                            "observed_by_harness_at": datetime.now(UTC).isoformat(),
                            "identity": sample_identity(target),
                            "workload": observed,
                        }
                    )
            assert_reference(
                args.base_url,
                args.api_token,
                args.reference_node,
                reference_ids,
                diagnosis_deadline,
            )
            match = next(
                (
                    row
                    for row in active_ooms(
                        args.base_url, args.api_token, args.node, diagnosis_deadline
                    )
                    if row.get("resource") == exact_resource
                ),
                None,
            )
            if match is not None:
                if trigger_observed is None:
                    raise RuntimeError("diagnosis appeared before its ordinary telemetry trigger")
                detail = api(
                    args.base_url + "/diagnoses/" + str(match["id"]),
                    args.api_token,
                    diagnosis_deadline,
                )
                report["trigger_to_diagnosis_seconds"] = time.monotonic() - trigger_observed
                break
            sleep_until(diagnosis_deadline)
        if detail is None or trigger_counters is None:
            raise TimeoutError(
                "ordinary OOM trigger and diagnosis did not appear within 60 seconds"
            )
        delta = detail["opening_evidence"]["event_delta"]
        if (
            detail.get("rule") != "workload_oom"
            or detail.get("resource") != exact_resource
            or detail["opening_evidence"].get("cgroup_path") != args.cgroup
            or delta.get("oom_kill", 0) <= 0
            or detail["opening_evidence"].get("generation") != generation
        ):
            raise RuntimeError(
                "incident is not linked to the exact ordinary local-counter evidence"
            )
        report["incident"] = detail

        ground_deadline = time.monotonic() + 10
        while time.monotonic() < ground_deadline:
            ground = helper(args.helper, "status", args.token, ground_deadline)
            if (
                int(ground["events"]["oom_kill"]) > int(owned["events"]["oom_kill"])
                and not ground["processes"]
            ):
                report["real_kill_status"] = {
                    "kernel_local_oom_kill_advanced": True,
                    "allocator_absent_before_stop": True,
                    "helper": ground,
                }
                break
            sleep_until(ground_deadline, 0.1)
        else:
            raise RuntimeError("helper did not prove a real kernel kill before controller stop")

        pre_stop_identity = sample_identity(target)
        stop_deadline = time.monotonic() + 30
        report["stop"] = helper(args.helper, "stop", args.token, stop_deadline)
        stopped = True
        recovery_deadline = time.monotonic() + 60
        recovery_identities: set[tuple[str, str, int, str]] = set()
        recovery_counters = trigger_counters
        while time.monotonic() < recovery_deadline:
            target = api(
                args.base_url + "/nodes/" + args.node + "/metrics",
                args.api_token,
                recovery_deadline,
            )
            observed = workload(target, args.cgroup)
            if generation_key(args.cgroup, observed) != exact_resource:
                raise RuntimeError("prepared cgroup generation changed during recovery")
            events = observed["events"]
            counters = (int(events["oom"]), int(events["oom_kill"]))
            identity = sample_identity(target)
            if counters != recovery_counters:
                recovery_counters = counters
                recovery_identities.clear()
                report["recovery_samples"].clear()
                eligible = False
            else:
                eligible = add_recovery_sample(
                    recovery_identities,
                    identity,
                    pre_stop_identity,
                    observed,
                    counters,
                    recovery_counters,
                    float(detail["configuration"]["recovery_percent"]),
                )
            if eligible:
                report["recovery_samples"].append({"identity": identity, "workload": observed})
            assert_reference(
                args.base_url,
                args.api_token,
                args.reference_node,
                reference_ids,
                recovery_deadline,
            )
            detail = api(
                args.base_url + "/diagnoses/" + str(detail["id"]),
                args.api_token,
                recovery_deadline,
            )
            if detail.get("status") == "resolved" and len(recovery_identities) >= 3:
                report["recovery"] = detail
                report["recovery_distinct_sample_count"] = len(recovery_identities)
                report["status"] = "passed"
                break
            sleep_until(recovery_deadline)
        else:
            raise TimeoutError("three distinct ordinary recovery samples did not complete in 60s")
    except BaseException as exc:
        failure = exc
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        cleanup_deadline = time.monotonic() + 30
        if not stopped:
            try:
                report["stop"] = helper(args.helper, "stop", args.token, cleanup_deadline)
            except BaseException as exc:
                report["stop_error"] = f"{type(exc).__name__}: {exc}"
                if failure is None:
                    failure = exc
        try:
            report["release"] = helper(args.helper, "release", args.token, cleanup_deadline)
        except BaseException as exc:
            report["release_error"] = f"{type(exc).__name__}: {exc}"
            if failure is None:
                failure = exc
        report["finished_at"] = datetime.now(UTC).isoformat()
        report["source_manifest_after"] = source_manifest()
        if report["source_manifest"] != report["source_manifest_after"] and failure is None:
            failure = RuntimeError("source changed during OOM harness")
        if failure is not None:
            report["status"] = "failed"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if failure is not None:
        raise RuntimeError("OOM harness failed; retained report: " + str(args.output)) from failure


if __name__ == "__main__":
    main()
