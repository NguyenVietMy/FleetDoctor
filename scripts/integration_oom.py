"""Synthetic OOM lifecycle proof against the real isolated service stack."""

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx

from fleetdoctor.agent import make_sample
from fleetdoctor.collection import from_statvfs
from fleetdoctor.schema import (
    CpuObservation,
    HostMemoryObservation,
    MemoryEvents,
    MemoryObservation,
    WorkloadMemoryObservation,
)

CGROUP = "/fleetdoctor/integration-oom/workload"
MISSING_CGROUP = "/fleetdoctor/integration-oom/missing"
DISK_PATH = "/var/lib/fleetdoctor/chaos/disk"


def prove(
    api: str,
    prom: str,
    grafana: str,
    values: dict[str, str],
    compose: Callable[..., str],
    proof: dict[str, Any],
) -> None:
    tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
    boot, session = uuid4(), uuid4()
    sequence = 10_000
    observed = datetime.now(UTC)
    proof["environment"] = "real-isolated-services-synthetic-v3-memory-observations"

    def send(
        oom: int,
        kills: int,
        usage: int = 90,
        *,
        stable: bool = True,
        explicit_unstable: bool = False,
    ) -> None:
        nonlocal sequence, observed
        sequence += 1
        observed += timedelta(milliseconds=100)
        events = MemoryEvents(oom=oom, oom_kill=kills)
        events_before = events if stable else MemoryEvents(oom=max(0, oom - 1), oom_kill=kills)
        memory = MemoryObservation(
            host=HostMemoryObservation(
                total_bytes=1024,
                available_bytes=512,
                swap_total_bytes=0,
                swap_free_bytes=0,
                page_size_bytes=4096,
                errors=["synthetic_rate_baseline"],
            ),
            workloads=[
                WorkloadMemoryObservation(
                    cgroup_path=CGROUP,
                    boot_id=boot,
                    st_dev=7,
                    st_ino=42,
                    current_bytes=usage,
                    max_bytes=100,
                    usage_ratio=usage / 100,
                    swap_current_bytes=0,
                    swap_max_bytes=0,
                    events_before=events_before,
                    events=events,
                    events_stable=stable,
                    process_inventory="complete",
                    errors=["unstable_snapshot"] if explicit_unstable or not stable else [],
                )
            ],
            workload_errors={MISSING_CGROUP: ["cgroup_missing"]},
            kernel_log_coverage="permission_denied",
        )
        value = make_sample(
            "node-a",
            boot,
            session,
            sequence,
            [
                from_statvfs(
                    path,
                    {
                        "f_blocks": 100,
                        "f_bfree": 90,
                        "f_bavail": 90,
                        "f_frsize": 1,
                        "f_files": 100,
                        "f_ffree": 90,
                    },
                )
                for path in ("/", DISK_PATH)
            ],
            observed,
            cpu=CpuObservation(errors=["synthetic_cpu_baseline"]),
            memory=memory,
        )
        response = httpx.post(
            api + "/ingest",
            content=value.model_dump_json(),
            headers={"Authorization": "Bearer " + tokens["node-a"]},
            timeout=8,
            trust_env=False,
        )
        response.raise_for_status()
        assert response.json()["status"] == "accepted"

    send(0, 0)
    node_memory = httpx.get(api + "/nodes/node-a/metrics", timeout=8, trust_env=False).json()
    assert node_memory["memory_coverage"]["workloads"] == {
        CGROUP: "available",
        MISSING_CGROUP: "unavailable",
    }
    collector_metrics = httpx.get(api + "/metrics", timeout=8, trust_env=False).text
    assert (
        f'fleetdoctor_memory_coverage_ratio{{node="node-a",scope="{MISSING_CGROUP}"}} 0.0'
        in collector_metrics
    )
    assert f'cgroup="{MISSING_CGROUP}"' not in "\n".join(
        line
        for line in collector_metrics.splitlines()
        if not line.startswith("fleetdoctor_memory_coverage_ratio")
    )
    coverage_deadline = time.monotonic() + 20
    while time.monotonic() < coverage_deadline:
        missing_coverage = httpx.get(
            prom + "/api/v1/query",
            params={
                "query": f'fleetdoctor_memory_coverage_ratio{{node="node-a",scope="{MISSING_CGROUP}"}}'
            },
            timeout=4,
            trust_env=False,
        ).json()
        result = missing_coverage.get("data", {}).get("result", [])
        if result and result[0]["value"][1] == "0":
            break
        time.sleep(1)
    else:
        raise TimeoutError("missing configured cgroup zero coverage was not scraped")
    missing_data = httpx.get(
        prom + "/api/v1/query",
        params={
            "query": f'fleetdoctor_workload_memory_current_bytes{{node="node-a",cgroup="{MISSING_CGROUP}"}}'
        },
        timeout=4,
        trust_env=False,
    ).json()
    assert missing_data.get("data", {}).get("result") == []
    proof["missing_configured_cgroup"] = {
        "api": node_memory["memory_coverage"]["workloads"],
        "collector_coverage_zero": True,
        "collector_data_gauges_absent": True,
        "prometheus_coverage": missing_coverage,
        "prometheus_data_gauges_absent": True,
    }
    # The bracket is stable, but the collector's explicit marker makes the
    # observation presentation- and recovery-ineligible. Final counters remain
    # valid for positive-delta incident detection.
    send(1, 1, explicit_unstable=True)
    unstable_node = httpx.get(api + "/nodes/node-a/metrics", timeout=8, trust_env=False).json()
    assert unstable_node["memory_coverage"]["workloads"][CGROUP] == "unavailable"
    assert unstable_node["memory"]["workloads"][0]["events"]["oom_kill"] == 1
    unstable_metrics = httpx.get(api + "/metrics", timeout=8, trust_env=False).text
    assert (
        f'fleetdoctor_memory_coverage_ratio{{node="node-a",scope="{CGROUP}"}} 0.0'
        in unstable_metrics
    )
    assert not any(
        line.startswith("fleetdoctor_workload_") and f'cgroup="{CGROUP}"' in line
        for line in unstable_metrics.splitlines()
    )
    proof["unstable_configured_cgroup"] = {
        "api_coverage": "unavailable",
        "collector_coverage_zero": True,
        "collector_data_gauges_absent": True,
        "final_oom_kill_counter_retained": 1,
    }
    rows = httpx.get(
        api + "/diagnoses",
        params={"node": "node-a", "rule": "workload_oom", "status": "active"},
        timeout=8,
        trust_env=False,
    ).json()["diagnoses"]
    assert len(rows) == 1
    identifier = rows[0]["id"]
    compose("restart", "collector")
    restart_deadline = time.monotonic() + 30
    while time.monotonic() < restart_deadline:
        try:
            health = httpx.get(api + "/health", timeout=2, trust_env=False)
            if health.status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    else:
        raise TimeoutError("collector did not recover after persisted OOM restart")
    detail = httpx.get(api + "/diagnoses/" + identifier, timeout=8, trust_env=False).json()
    assert detail["configuration"]["recovery_percent"] == 80
    assert detail["evidence_stale"] is True
    assert detail["opening_evidence"]["event_delta"] == {"oom": 1, "oom_kill": 1}
    assert detail["opening_evidence"]["cgroup_path"] == CGROUP
    assert detail["opening_evidence"]["coverage"]["snapshot"] == "unstable"
    proof["opened"] = detail
    proof["postgres_restart_reload"] = True

    # Three fresh below-threshold, zero-delta marked observations must neither
    # accumulate nor resolve recovery.
    for _ in range(3):
        send(1, 1, usage=79, explicit_unstable=True)
        still_active = httpx.get(
            api + "/diagnoses/" + identifier, timeout=8, trust_env=False
        ).json()
        assert still_active["status"] == "active"
        assert still_active["latest_evidence"]["coverage"]["snapshot"] == "unstable"
    proof["explicit_marker_no_accumulation"] = True

    # A marked sample also resets a partially accumulated healthy sequence.
    for _ in range(2):
        send(1, 1, usage=79)
        assert (
            httpx.get(api + "/diagnoses/" + identifier, timeout=8, trust_env=False).json()["status"]
            == "active"
        )
    send(1, 1, usage=79, explicit_unstable=True)
    assert (
        httpx.get(api + "/diagnoses/" + identifier, timeout=8, trust_env=False).json()["status"]
        == "active"
    )
    for _ in range(2):
        send(1, 1, usage=79)
        assert (
            httpx.get(api + "/diagnoses/" + identifier, timeout=8, trust_env=False).json()["status"]
            == "active"
        )
    proof["explicit_marker_recovery_reset"] = True

    # The third genuinely stable observation after the reset resolves.
    send(1, 1, usage=79)
    stable_node = httpx.get(api + "/nodes/node-a/metrics", timeout=8, trust_env=False).json()
    assert stable_node["memory_coverage"]["workloads"][CGROUP] == "available"
    stable_metrics = httpx.get(api + "/metrics", timeout=8, trust_env=False).text
    assert (
        f'fleetdoctor_memory_coverage_ratio{{node="node-a",scope="{CGROUP}"}} 1.0' in stable_metrics
    )
    for metric in (
        "fleetdoctor_workload_memory_current_bytes",
        "fleetdoctor_workload_memory_max_bytes",
        "fleetdoctor_workload_memory_usage_ratio",
        "fleetdoctor_workload_swap_current_bytes",
        "fleetdoctor_workload_swap_max_bytes",
        "fleetdoctor_workload_memory_oom_total",
        "fleetdoctor_workload_memory_oom_kill_total",
    ):
        assert f'{metric}{{cgroup="{CGROUP}",node="node-a"}}' in stable_metrics
    proof["stable_configured_cgroup"] = {
        "api_coverage": "available",
        "collector_coverage_one": True,
        "collector_data_gauges_present": True,
    }
    resolved = httpx.get(api + "/diagnoses/" + identifier, timeout=8, trust_env=False).json()
    assert resolved["status"] == "resolved"
    proof["resolved"] = resolved
    sql = compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "fleetdoctor",
        "-d",
        "fleetdoctor",
        "-Atc",
        "SELECT rule||':'||status FROM incidents WHERE id='" + identifier + "';",
    ).strip()
    assert sql == "workload_oom:resolved"
    proof["postgres_record"] = sql
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        metric = httpx.get(
            prom + "/api/v1/query",
            params={"query": 'fleetdoctor_workload_memory_oom_kill_total{node="node-a"}'},
            timeout=4,
            trust_env=False,
        ).json()
        if metric.get("data", {}).get("result"):
            proof["prometheus_oom"] = metric
            break
        time.sleep(1)
    else:
        raise TimeoutError("OOM Prometheus series unavailable")
    for dashboard in ("fleet", "node"):
        body = httpx.get(
            grafana + "/api/dashboards/uid/fleetdoctor-" + dashboard,
            auth=("admin", values["GRAFANA_PASSWORD"]),
            timeout=8,
            trust_env=False,
        ).json()["dashboard"]
        titles = {panel["title"] for panel in body["panels"]}
        assert "Host memory available" in titles
        assert "Workload memory usage" in titles
        assert "Workload local OOM kills" in titles
    proof["grafana_memory_panels"] = True
