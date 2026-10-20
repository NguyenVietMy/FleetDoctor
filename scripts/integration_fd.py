"""Synthetic FD lifecycle proof against production API, PostgreSQL, Prometheus, and Grafana."""

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

import httpx
from integration_disk import PATH as DISK_PATH
from integration_oom import CGROUP as OOM_CGROUP
from integration_oom import MISSING_CGROUP as OOM_MISSING_CGROUP

from fleetdoctor.agent import make_sample
from fleetdoctor.collection import from_statvfs
from fleetdoctor.schema import (
    CpuObservation,
    FdObservation,
    FdProcessIdentity,
    FdProcessObservation,
    HostMemoryObservation,
    MemoryObservation,
)


def prometheus_has_value(result: dict[str, Any], node: str, expected: float) -> bool:
    for series in result.get("result", []):
        if series.get("metric", {}).get("node") != node:
            continue
        points = list(series.get("values", []))
        if "value" in series:
            points.append(series["value"])
        for point in points:
            if (
                isinstance(point, list)
                and len(point) == 2
                and abs(float(point[1]) - expected) <= 0.000001
            ):
                return True
    return False


def prove(
    api: str,
    prom: str,
    grafana: str,
    values: dict[str, str],
    compose: Callable[..., str],
    proof: dict[str, Any],
    stat: dict[str, int],
) -> None:
    tokens: dict[str, str] = __import__("json").loads(values["FLEETDOCTOR_NODE_TOKENS"])
    boot = UUID("11111111-1111-4111-8111-111111111111")
    session = UUID("22222222-2222-4222-8222-222222222222")
    identities = {
        "target": FdProcessIdentity(boot_id=boot, pid=4242, starttime_ticks=100),
        "exit": FdProcessIdentity(boot_id=boot, pid=4343, starttime_ticks=200),
        "reference": FdProcessIdentity(boot_id=boot, pid=4444, starttime_ticks=300),
    }
    sequence = 0
    sent: list[dict[str, Any]] = []
    client = httpx.Client(timeout=4, trust_env=False)

    def observation(
        item: FdProcessIdentity,
        count: int | None,
        *,
        status: Literal["present", "exited", "replaced", "unknown"] = "present",
        watched: bool = True,
        growth: float | None = None,
    ) -> FdProcessObservation:
        if status != "present":
            return FdProcessObservation(identity=item, status=status, watched=True)
        return FdProcessObservation(
            identity=item,
            status="present",
            watched=watched,
            configured=item == identities["target"],
            comm="synthetic-fd-worker",
            descriptor_count=count,
            soft_limit=128 if count is not None else None,
            pressure_ratio=count / 128 if count is not None else None,
            count_delta=int(growth * 5) if growth is not None else None,
            growth_per_second=growth,
            growth_interval_seconds=5 if growth is not None else None,
            cpu_percent=0,
            rss_bytes=4096,
            errors=[] if count is not None else ["limit_unavailable"],
        )

    def send(target: FdProcessObservation, *, replay: bool = False) -> dict[str, Any]:
        nonlocal sequence
        current_sequence = sequence - 1 if replay else sequence
        observed = (
            datetime.now(UTC) if not replay else datetime.fromisoformat(sent[-1]["observed_at"])
        )
        if replay:
            target = FdProcessObservation.model_validate(sent[-1]["target"])
        results = {}
        for node, item in (
            ("node-a", target),
            ("node-b", observation(identities["reference"], 16)),
        ):
            value = make_sample(
                node,
                boot,
                session,
                current_sequence,
                [from_statvfs("/", stat), from_statvfs(DISK_PATH, stat)],
                observed,
                cpu=CpuObservation(
                    logical_cores=2,
                    online_cpu_ids=[0, 1],
                    runnable_processes=0,
                    process_inventory="complete",
                    errors=["cpu_rate_baseline_unavailable"],
                ),
                memory=MemoryObservation(
                    host=HostMemoryObservation(errors=["memory_rate_baseline_unavailable"]),
                    workload_errors={
                        OOM_CGROUP: ["synthetic_not_collected"],
                        OOM_MISSING_CGROUP: ["synthetic_not_collected"],
                    },
                ),
                fd=FdObservation(
                    observations=[item],
                    watch_coverage="available",
                    watch_revision=current_sequence,
                ),
            )
            response = client.post(
                api + "/ingest",
                headers={"Authorization": "Bearer " + tokens[node]},
                content=value.model_dump_json(),
            )
            response.raise_for_status()
            results[node] = response.json()
        if not replay:
            sent.append(
                {
                    "sequence": sequence,
                    "observed_at": observed.isoformat(),
                    "target": target.model_dump(mode="json"),
                    "responses": results,
                }
            )
            sequence += 1
        return results

    try:
        for count, growth in ((112, None), (116, 0.8), (120, 0.8), (124, 0.8)):
            send(observation(identities["target"], count, watched=False, growth=growth))
        active = client.get(
            api + "/diagnoses",
            params={"node": "node-a", "rule": "fd_pressure", "status": "active"},
        )
        active.raise_for_status()
        opening = active.json()["diagnoses"][0]
        identifier = opening["id"]
        detail = client.get(api + "/diagnoses/" + identifier).json()
        assert detail["opening_evidence"]["observation"]["descriptor_count"] == 124
        assert detail["opening_evidence"]["suspected_leak"] is True
        expected_pressure = 124 / 128
        pressure_scrape = None
        history = None
        pressure_deadline = time.monotonic() + 25
        while time.monotonic() < pressure_deadline:
            # Keep the exact high-count state fresh until Prometheus has scraped
            # it. Later exit evidence deliberately removes the current ratio.
            send(observation(identities["target"], 124, growth=0))
            current = client.get(
                prom + "/api/v1/query",
                params={"query": 'fleetdoctor_fd_pressure_ratio{node="node-a"}'},
            )
            current.raise_for_status()
            current_payload = current.json()
            end = datetime.now(UTC)
            bounded = client.get(
                api + "/nodes/node-a/metrics",
                params={
                    "start": (end - timedelta(minutes=5)).isoformat(),
                    "end": end.isoformat(),
                    "step": 5,
                    "field": "fd_pressure_ratio",
                },
            )
            bounded.raise_for_status()
            bounded_payload = bounded.json()
            if prometheus_has_value(current_payload.get("data", {}), "node-a", expected_pressure):
                pressure_scrape = current_payload
            if prometheus_has_value(
                bounded_payload.get("history", {}), "node-a", expected_pressure
            ):
                history = bounded_payload
            if pressure_scrape is not None and history is not None:
                break
            time.sleep(1)
        if pressure_scrape is None:
            raise TimeoutError("known FD pressure state was not scraped while fresh")
        if history is None:
            raise TimeoutError("known FD pressure state was absent from bounded history")
        watch_before = client.get(
            api + "/nodes/node-a/fd-watch",
            headers={"Authorization": "Bearer " + tokens["node-a"]},
        )
        watch_before.raise_for_status()
        assert watch_before.json()["watches"][0]["resource"] == detail["resource"]
        duplicate = send(observation(identities["target"], 124), replay=True)
        assert duplicate["node-a"]["status"] == "duplicate"
        compose("restart", "collector")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                watch_after = client.get(
                    api + "/nodes/node-a/fd-watch",
                    headers={"Authorization": "Bearer " + tokens["node-a"]},
                )
                if watch_after.is_success:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        else:
            raise TimeoutError("collector did not restore durable FD watches")
        assert watch_after.json()["watches"] == watch_before.json()["watches"]
        unavailable = FdProcessObservation(
            identity=identities["target"],
            status="present",
            watched=True,
            configured=True,
            comm="synthetic-fd-worker",
            errors=["limit_unavailable"],
        )
        for _ in range(3):
            send(unavailable)
        assert client.get(api + "/diagnoses/" + identifier).json()["status"] == "active"
        for _ in range(3):
            send(observation(identities["target"], 16))
        released = client.get(api + "/diagnoses/" + identifier).json()
        assert released["status"] == "resolved"
        assert released["resolution_reason"] == "descriptor_release"

        for _ in range(3):
            send(observation(identities["exit"], 124, watched=False, growth=1))
        active_exit = client.get(
            api + "/diagnoses",
            params={"node": "node-a", "rule": "fd_pressure", "status": "active"},
        ).json()["diagnoses"][0]
        exit_id = active_exit["id"]
        for _ in range(3):
            send(observation(identities["exit"], None, status="exited"))
        exited = client.get(api + "/diagnoses/" + exit_id).json()
        assert exited["status"] == "resolved" and exited["resolution_reason"] == "confirmed_exit"

        metrics = client.get(api + "/metrics")
        metrics.raise_for_status()
        assert 'fleetdoctor_active_incidents{node="node-a",rule="fd_pressure"} 0.0' in metrics.text
        assert "fleetdoctor_fd_coverage_ratio" in metrics.text
        dashboard_targets: list[dict[str, Any]] = []
        query_results: dict[str, Any] = {}
        for dashboard_name in ("fleet", "node"):
            dashboard_response = client.get(
                grafana + f"/api/dashboards/uid/fleetdoctor-{dashboard_name}",
                auth=("admin", values["GRAFANA_PASSWORD"]),
            )
            dashboard_response.raise_for_status()
            panels = dashboard_response.json()["dashboard"]["panels"]
            relevant = [panel for panel in panels if panel["id"] >= 60 or panel["id"] == 20]
            expected_ids = {60, 61} if dashboard_name == "fleet" else {60, 61, 62, 63}
            assert expected_ids <= {panel["id"] for panel in relevant}
            for panel in relevant:
                for target in panel["targets"]:
                    ref = f"{dashboard_name}:{panel['id']}:{target['refId']}"
                    datasource = panel["datasource"]["uid"]
                    query: dict[str, Any] = {
                        "refId": target["refId"],
                        "datasource": {"uid": datasource},
                        "format": target.get("format", "time_series"),
                    }
                    if "expr" in target:
                        query.update(
                            expr=target["expr"].replace("$node", "node-a"),
                            range=True,
                            intervalMs=5000,
                            maxDataPoints=600,
                        )
                    else:
                        query["rawSql"] = (
                            target["rawSql"]
                            .replace("${status:raw}", "resolved")
                            .replace("${node:sqlstring}", "'node-a'")
                        )
                    executed = client.post(
                        grafana + "/api/ds/query",
                        auth=("admin", values["GRAFANA_PASSWORD"]),
                        json={
                            "from": str(
                                int((datetime.now(UTC) - timedelta(minutes=10)).timestamp() * 1000)
                            ),
                            "to": str(int(datetime.now(UTC).timestamp() * 1000)),
                            "queries": [query],
                        },
                    )
                    executed.raise_for_status()
                    result = executed.json()["results"][target["refId"]]
                    assert not result.get("error"), result
                    dashboard_targets.append(
                        {
                            "dashboard": dashboard_name,
                            "panel_id": panel["id"],
                            "title": panel["title"],
                            "ref_id": target["refId"],
                            "datasource_uid": datasource,
                            "query": query.get("expr", query.get("rawSql")),
                        }
                    )
                    query_results[ref] = result
        proof.update(
            environment="real-isolated-PostgreSQL-Prometheus-Grafana-synthetic-v4-observations",
            sent=sent,
            release_incident=released,
            exit_incident=exited,
            watch_before_restart=watch_before.json(),
            watch_after_restart=watch_after.json(),
            pressure_scrape=pressure_scrape,
            history=history,
            dashboard_targets=dashboard_targets,
            dashboard_query_results=query_results,
        )
    finally:
        client.close()
