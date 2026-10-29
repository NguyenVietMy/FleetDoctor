"""Exercise v5 network persistence, lifecycle, API, and metrics in the isolated stack."""

import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx

from fleetdoctor.agent import make_sample
from fleetdoctor.schema import (
    CpuObservation,
    FdObservation,
    Filesystem,
    HostMemoryObservation,
    MemoryObservation,
    NetworkObservation,
    NetworkProbeObservation,
    TcpNetworkObservation,
)

TARGET = "10.42.1.10"
CHANGED_TARGET = "10.42.1.11"


def unavailable_value(target: str, error: str = "ping_permission_denied") -> NetworkObservation:
    return NetworkObservation.unavailable(target, error)


def prometheus_samples(prom: str, query: str, *, present: bool) -> dict[str, Any]:
    """Wait for a real matching Prometheus sample (or its stale-marker removal)."""
    deadline = time.monotonic() + 25
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = httpx.get(
            prom + "/api/v1/query", params={"query": query}, timeout=4, trust_env=False
        )
        response.raise_for_status()
        last = response.json()
        result = last.get("data", {}).get("result", [])
        if last.get("status") == "success" and bool(result) is present:
            return last
        time.sleep(1)
    raise AssertionError(
        f"Prometheus query did not become {'nonempty' if present else 'empty'}: {query}; "
        f"last={last}"
    )


def metric_data_lines(metrics: str, name: str, node: str) -> list[str]:
    prefix = name + "{"
    marker = f'node="{node}"'
    return [line for line in metrics.splitlines() if line.startswith(prefix) and marker in line]


def network_value(target: str, *, lost: int, median_ms: float | None) -> NetworkObservation:
    received = 3 - lost
    rtts = [median_ms] * received if median_ms is not None else []
    return NetworkObservation(
        probe=NetworkProbeObservation(
            status="available",
            target=target,
            sent=3,
            received=received,
            lost=lost,
            loss_ratio=lost / 3,
            successful_sequences=list(range(1, received + 1)),
            successful_rtts_ms=rtts,
            median_rtt_ms=median_ms,
            route_error="fixture_route_unavailable",
        ),
        tcp=TcpNetworkObservation(
            retrans_segs=10,
            retrans_per_second=0,
            rate_interval_seconds=5,
            rate_status="available",
            curr_estab=2,
            state_counts={"established": 2, "listen": 1},
            state_inventory="complete",
        ),
        interface_coverage="complete",
        elapsed_seconds=0.1,
    )


def prove(
    api: str,
    prom: str,
    values: dict[str, str],
    compose: Any,
    evidence: dict[str, Any],
) -> None:
    tokens: dict[str, str] = __import__("json").loads(values["FLEETDOCTOR_NODE_TOKENS"])
    node = sorted(tokens)[0]
    session, boot = uuid4(), uuid4()
    sequence = 0

    def post(value: NetworkObservation) -> dict[str, Any]:
        nonlocal sequence
        sample = make_sample(
            node,
            boot,
            session,
            sequence,
            [
                Filesystem(mountpoint="/", errors=["network_fixture"]),
                Filesystem(
                    mountpoint="/var/lib/fleetdoctor/chaos/disk", errors=["network_fixture"]
                ),
            ],
            datetime.now(UTC),
            cpu=CpuObservation(errors=["network_fixture"]),
            memory=MemoryObservation(
                host=HostMemoryObservation(errors=["network_fixture"]),
                workload_errors={
                    "/fleetdoctor/integration-oom/workload": ["network_fixture"],
                    "/fleetdoctor/integration-oom/missing": ["network_fixture"],
                },
            ),
            fd=FdObservation(errors=["network_fixture"]),
            network=value,
        )
        sequence += 1
        response = httpx.post(
            api + "/ingest",
            content=sample.model_dump_json(),
            headers={"Authorization": "Bearer " + tokens[node]},
            timeout=3,
            trust_env=False,
        )
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        assert result["status"] == "accepted"
        return result

    before = httpx.get(
        api + "/diagnoses", params={"node": node, "rule": "network_path_degradation"}, timeout=3
    ).json()["total"]
    for _ in range(3):
        post(network_value(TARGET, lost=0, median_ms=200))
    active = httpx.get(
        api + "/diagnoses",
        params={"node": node, "rule": "network_path_degradation", "status": "active"},
        timeout=3,
    ).json()["diagnoses"]
    assert len(active) == 1 and active[0]["resource"] == "ipv4:" + TARGET
    incident_id = active[0]["id"]
    latency_prometheus = prometheus_samples(
        prom, f'fleetdoctor_network_probe_median_rtt_seconds{{node="{node}"}}', present=True
    )
    compose("restart", "collector")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            detail = httpx.get(api + "/diagnoses/" + incident_id, timeout=3).json()
            if detail["status"] == "active":
                break
        except httpx.HTTPError:
            pass
        time.sleep(1)
    else:
        raise TimeoutError("network incident did not reload after collector restart")
    assert detail["configuration"]["rtt_trigger_ms"] == 200
    opening_before_unavailable = detail["opening_evidence"]
    post(unavailable_value(TARGET))
    unavailable_detail = httpx.get(api + "/diagnoses/" + incident_id, timeout=3).json()
    assert unavailable_detail["status"] == "active"
    assert unavailable_detail["opening_evidence"] == opening_before_unavailable
    assert unavailable_detail["latest_evidence"]["probe"]["status"] == "unavailable"
    assert unavailable_detail["latest_evidence"]["probe"]["lost"] is None
    assert unavailable_detail["latest_evidence"]["probe"]["median_rtt_ms"] is None
    unavailable_coverage = prometheus_samples(
        prom, f'fleetdoctor_network_probe_coverage_ratio{{node="{node}"}} == 0', present=True
    )
    prometheus_samples(
        prom, f'fleetdoctor_network_probe_loss_ratio{{node="{node}"}}', present=False
    )
    prometheus_samples(
        prom, f'fleetdoctor_network_probe_median_rtt_seconds{{node="{node}"}}', present=False
    )
    post(network_value(CHANGED_TARGET, lost=0, median_ms=20))
    changed = httpx.get(api + "/diagnoses/" + incident_id, timeout=3).json()
    assert changed["status"] == "active"
    assert changed["latest_evidence"]["coverage"]["limitation"] == "target_changed"
    for _ in range(3):
        post(network_value(TARGET, lost=0, median_ms=20))
    resolved = httpx.get(api + "/diagnoses/" + incident_id, timeout=3).json()
    assert resolved["status"] == "resolved"
    for _ in range(3):
        post(network_value(TARGET, lost=3, median_ms=None))
    recurrence = httpx.get(
        api + "/diagnoses",
        params={"node": node, "rule": "network_path_degradation", "status": "active"},
        timeout=3,
    ).json()["diagnoses"]
    assert len(recurrence) == 1 and recurrence[0]["id"] != incident_id
    no_reply_id = recurrence[0]["id"]
    detail = httpx.get(api + "/diagnoses/" + no_reply_id, timeout=3).json()
    assert detail["opening_evidence"]["probe"]["lost"] == 3
    assert detail["opening_evidence"]["probe"]["median_rtt_ms"] is None
    metrics = httpx.get(api + "/metrics", timeout=3).text
    assert f'fleetdoctor_network_probe_loss_packets{{node="{node}"}} 3.0' in metrics
    assert not metric_data_lines(metrics, "fleetdoctor_network_probe_median_rtt_seconds", node)
    loss_prometheus = prometheus_samples(
        prom, f'fleetdoctor_network_probe_loss_packets{{node="{node}"}} == 3', present=True
    )
    prometheus_samples(
        prom, f'fleetdoctor_network_probe_median_rtt_seconds{{node="{node}"}}', present=False
    )
    for _ in range(3):
        post(network_value(TARGET, lost=0, median_ms=20))
    final = httpx.get(api + "/diagnoses/" + no_reply_id, timeout=3).json()
    assert final["status"] == "resolved"
    prom_result = prometheus_samples(
        prom, f'fleetdoctor_network_probe_loss_ratio{{node="{node}"}} == 0', present=True
    )
    now = datetime.now(UTC)
    history = httpx.get(
        api + f"/nodes/{node}/metrics",
        params={
            "field": "network_loss_ratio",
            "start": (now - timedelta(minutes=3)).isoformat(),
            "end": now.isoformat(),
            "step": 5,
        },
        timeout=4,
        trust_env=False,
    )
    history.raise_for_status()
    history_result = history.json()
    series = history_result.get("history", {}).get("result", [])
    assert any(item.get("metric", {}).get("node") == node and item.get("values") for item in series)
    total = httpx.get(
        api + "/diagnoses", params={"node": node, "rule": "network_path_degradation"}, timeout=3
    ).json()["total"]
    assert total == before + 2
    evidence.update(
        node=node,
        target=TARGET,
        latency_incident_id=incident_id,
        loss_incident_id=no_reply_id,
        typed_restart=True,
        target_change_preserved_old=True,
        no_reply_rtt_omitted=True,
        unavailable_preserved_opening=True,
        recurrence_new_id=True,
        latency_prometheus=latency_prometheus,
        unavailable_prometheus=unavailable_coverage,
        loss_prometheus=loss_prometheus,
        prometheus_query=prom_result,
        history_query=history_result,
    )
