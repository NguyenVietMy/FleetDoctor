"""Exercise schema-v6 DNS persistence, lifecycle, API, and Prometheus in real services."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx

from fleetdoctor.agent import make_sample
from fleetdoctor.schema import (
    CpuObservation,
    DnsBaselineObservation,
    DnsObservation,
    DnsQueryObservation,
    FdObservation,
    Filesystem,
    HostMemoryObservation,
    MemoryObservation,
    NetworkObservation,
    NetworkProbeObservation,
    ResolverSnapshot,
    TcpNetworkObservation,
)

HOSTNAME = "baseline.fleetdoctor.test."
TARGET = "10.42.1.10"


def prove(
    api: str, prom: str, values: dict[str, str], compose: Any, evidence: dict[str, Any]
) -> None:
    tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
    node = sorted(tokens)[0]
    boot, session = uuid4(), uuid4()
    base_time = datetime.now(UTC) - timedelta(seconds=5)
    probe = NetworkProbeObservation(
        status="available",
        target=TARGET,
        sent=3,
        received=3,
        lost=0,
        loss_ratio=0,
        successful_sequences=[1, 2, 3],
        successful_rtts_ms=[20, 20, 20],
        median_rtt_ms=20,
        route_error="fixture_route_unavailable",
    )
    success_query = DnsQueryObservation(
        status="success",
        hostname=HOSTNAME,
        answers=["10.42.1.80"],
        duration_seconds=0.01,
        selected_server="10.42.1.53",
        adapter="dnspython",
    )
    resolver = ResolverSnapshot(
        status="available",
        nameservers=["10.42.1.53"],
        fingerprint="b" * 64,
        entry_type="regular",
    )
    baseline = DnsBaselineObservation(
        node_id=node,
        boot_id=boot,
        agent_session_id=session,
        sequence=0,
        observed_at=base_time,
        hostname=HOSTNAME,
        direct_ip_target=TARGET,
        query=success_query,
        direct_ip_probe=probe,
        resolver_fingerprint="b" * 64,
        resolver_nameservers=["10.42.1.53"],
    )
    sequence = 1

    def post(status: str) -> dict[str, Any]:
        nonlocal sequence
        query = (
            success_query
            if status == "success"
            else DnsQueryObservation(
                status="failure",
                hostname=HOSTNAME,
                duration_seconds=0.02,
                error="servfail",
                adapter="dnspython",
            )
        )
        value = make_sample(
            node,
            boot,
            session,
            sequence,
            [
                Filesystem(mountpoint="/", errors=["dns_fixture"]),
                Filesystem(mountpoint="/var/lib/fleetdoctor/chaos/disk", errors=["dns_fixture"]),
            ],
            datetime.now(UTC),
            cpu=CpuObservation(errors=["dns_fixture"]),
            memory=MemoryObservation(
                host=HostMemoryObservation(errors=["dns_fixture"]),
                workload_errors={
                    "/fleetdoctor/integration-oom/workload": ["dns_fixture"],
                    "/fleetdoctor/integration-oom/missing": ["dns_fixture"],
                },
            ),
            fd=FdObservation(errors=["dns_fixture"]),
            network=NetworkObservation(
                probe=probe,
                tcp=TcpNetworkObservation(errors=["dns_fixture"]),
                interface_coverage="unavailable",
                errors=["dns_fixture"],
            ),
            dns=DnsObservation(
                hostname=HOSTNAME,
                direct_ip_target=TARGET,
                resolver=resolver,
                query=query,
                baseline=baseline,
                retention_coverage="complete",
            ),
        )
        sequence += 1
        response = httpx.post(
            api + "/ingest",
            content=value.model_dump_json(),
            headers={"Authorization": "Bearer " + tokens[node]},
            timeout=3,
            trust_env=False,
        )
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        if result["status"] != "accepted":
            raise AssertionError(result)
        return result

    for _ in range(3):
        post("failure")
    active = httpx.get(
        api + "/diagnoses",
        params={"node": node, "rule": "dns_resolution_failure", "status": "active"},
        timeout=3,
        trust_env=False,
    ).json()["diagnoses"]
    if len(active) != 1:
        raise AssertionError(active)
    identifier = active[0]["id"]
    compose("restart", "collector")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            detail = httpx.get(api + "/diagnoses/" + identifier, timeout=3, trust_env=False).json()
            if detail["status"] == "active":
                break
        except httpx.HTTPError:
            pass
        time.sleep(1)
    for _ in range(3):
        post("success")
    detail = httpx.get(api + "/diagnoses/" + identifier, timeout=3, trust_env=False).json()
    if detail["status"] != "resolved":
        raise AssertionError(detail)
    deadline = time.monotonic() + 25
    prom_result: dict[str, Any] = {}
    while time.monotonic() < deadline:
        prom_result = httpx.get(
            prom + "/api/v1/query",
            params={"query": f'fleetdoctor_dns_query_success{{node="{node}"}}'},
            timeout=4,
            trust_env=False,
        ).json()
        if prom_result.get("data", {}).get("result"):
            break
        time.sleep(1)
    if not prom_result.get("data", {}).get("result"):
        raise AssertionError(prom_result)
    evidence.update(
        incident_id=identifier,
        opening=active[0],
        resolved=detail,
        prometheus=prom_result,
    )
