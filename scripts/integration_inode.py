"""Real-service inode lifecycle proof using synthetic, explicitly labelled observations."""

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx

from fleetdoctor.agent import make_sample
from fleetdoctor.collection import from_statvfs
from fleetdoctor.schema import Filesystem

PATH = "/var/lib/fleetdoctor/chaos/disk"


def prove(
    api: str,
    prom: str,
    grafana: str,
    values: dict[str, str],
    compose: Callable[..., str],
    proof: dict[str, Any],
) -> None:
    proof["environment"] = "real-isolated-PostgreSQL-Prometheus-Grafana-synthetic-observations"
    proof["synthetic_observations"] = True
    proof["fixture_store_used"] = False
    tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
    boot, session = uuid4(), uuid4()
    sequence = 0

    def fs(inode_usage: int, path: str = PATH, block_usage: int = 10) -> Filesystem:
        return from_statvfs(
            path,
            {
                "f_blocks": 10000,
                "f_bfree": 10000 - block_usage * 100,
                "f_bavail": 10000 - block_usage * 100,
                "f_frsize": 4096,
                "f_files": 1000,
                "f_ffree": 1000 - inode_usage * 10,
            },
        )

    with httpx.Client(timeout=8, trust_env=False) as client:

        def get(path: str, **params: Any) -> dict[str, Any]:
            response = client.get(api + path, params=params)
            response.raise_for_status()
            value: dict[str, Any] = response.json()
            return value

        def send(inode_usage: int, block_usage: int | None = 10) -> None:
            nonlocal sequence
            target = fs(inode_usage, block_usage=block_usage or 10)
            if block_usage is None:
                target = Filesystem(
                    mountpoint=PATH,
                    inodes_total=target.inodes_total,
                    inodes_free=target.inodes_free,
                    inode_usage_percent=target.inode_usage_percent,
                    errors=["synthetic_block_unavailable"],
                )
            sample = make_sample(
                "node-a",
                boot,
                session,
                sequence,
                [fs(10, "/"), target],
                datetime.now(UTC),
            )
            sequence += 1
            response = client.post(
                api + "/ingest",
                headers={"Authorization": "Bearer " + tokens["node-a"]},
                content=sample.model_dump_json(),
            )
            assert response.status_code == 200, response.text
            assert response.json()["status"] == "accepted"

        configuration = get("/configuration")
        assert configuration["inode_rule"]["trigger_percent"] == 95
        assert configuration["effective_inode_block_guard_percent"] == min(
            configuration["inode_rule"]["block_guard_percent"],
            configuration["disk_rule"]["trigger_percent"],
        )
        for _ in range(3):
            send(96)
        active = get("/diagnoses", rule="inode_exhaustion", status="active")
        assert active["total"] == 1
        identifier = active["diagnoses"][0]["id"]
        opening = get("/diagnoses/" + identifier)
        assert opening["configuration"] == configuration["inode_rule"]
        assert opening["opening_evidence"]["filesystem"]["block_usage_percent"] < 95
        assert opening["opening_evidence"]["filesystem"]["available_bytes"] > 0
        node = get("/nodes/node-a/metrics")
        assert node["active_incident_counts"]["inode_exhaustion"] == 1
        assert node["inode_diagnosis_coverage"][PATH] == "available"
        metrics = client.get(api + "/metrics").text
        assert 'rule="inode_exhaustion"} 1.0' in metrics
        assert "fleetdoctor_inode_diagnosis_coverage_ratio" in metrics

        compose("up", "-d", "--force-recreate", "--no-deps", "collector")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if client.get(api + "/health").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        else:
            raise TimeoutError("collector restart did not become ready")
        reloaded = get("/diagnoses/" + identifier)
        assert (
            reloaded["evidence_stale"] and reloaded["configuration"] == configuration["inode_rule"]
        )
        for _ in range(3):
            send(80, block_usage=None)
        resolved = get("/diagnoses/" + identifier)
        assert resolved["status"] == "resolved"
        assert resolved["opening_evidence"] == opening["opening_evidence"]
        assert resolved["latest_evidence"]["inode_available"]
        assert not resolved["latest_evidence"]["block_available"]

        history_deadline = time.monotonic() + 25
        history: dict[str, Any] | None = None
        while time.monotonic() < history_deadline:
            end = datetime.now(UTC)
            start = end - timedelta(minutes=5)
            response = client.get(
                api + "/nodes/node-a/metrics",
                params={
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "step": 5,
                    "field": "inode_usage_ratio",
                },
            )
            if response.status_code == 200:
                history = response.json()
                if history.get("history", {}).get("result"):
                    break
            time.sleep(1)
        if history is None or not history.get("history", {}).get("result"):
            raise TimeoutError("inode Prometheus history was not scraped")

        dashboard_titles: dict[str, list[str]] = {}
        sql_datasource_proof: dict[str, Any] = {}
        for name in ("fleet", "node"):
            dashboard = client.get(
                grafana + f"/api/dashboards/uid/fleetdoctor-{name}",
                auth=("admin", values["GRAFANA_PASSWORD"]),
            )
            dashboard.raise_for_status()
            panels: list[dict[str, Any]] = dashboard.json()["dashboard"]["panels"]
            dashboard_titles[name] = [panel["title"] for panel in panels]
            assert any("Inode" in title for title in dashboard_titles[name])
            incident_panel = next(
                panel for panel in panels if panel.get("datasource", {}).get("uid") == "incidents"
            )
            raw_sql: str = incident_panel["targets"][0]["rawSql"]
            assert "WHEN 'inode_exhaustion'" in raw_sql
            raw_sql = raw_sql.replace("${status:raw}", "resolved")
            raw_sql = raw_sql.replace("${node:sqlstring}", "'node-a'")
            query = client.post(
                grafana + "/api/ds/query",
                auth=("admin", values["GRAFANA_PASSWORD"]),
                json={
                    "from": str(
                        int((datetime.now(UTC) - timedelta(minutes=10)).timestamp() * 1000)
                    ),
                    "to": str(int(datetime.now(UTC).timestamp() * 1000)),
                    "queries": [
                        {
                            "refId": "A",
                            "datasource": {"uid": "incidents"},
                            "format": "table",
                            "rawSql": raw_sql,
                        }
                    ],
                },
            )
            query.raise_for_status()
            result = query.json()["results"]["A"]
            assert not result.get("error"), result
            frames: list[dict[str, Any]] = result["frames"]
            assert frames
            fields = [field["name"] for field in frames[0]["schema"]["fields"]]
            columns: list[list[Any]] = frames[0]["data"]["values"]
            rows = [dict(zip(fields, values, strict=True)) for values in zip(*columns, strict=True)]
            incident_row = next(row for row in rows if row["id"] == identifier)
            assert incident_row["rule"] == "inode_exhaustion"
            assert incident_row["status"] == "resolved"
            assert incident_row["evidence_available"] is True
            sql_datasource_proof[name] = {
                "datasource_uid": "incidents",
                "provisioned_sql": raw_sql,
                "incident_row": incident_row,
            }
        prometheus_deadline = time.monotonic() + 25
        prometheus_payload: dict[str, Any] | None = None
        while time.monotonic() < prometheus_deadline:
            # The ordinary fixture producer is paused for rule isolation. Keep
            # this explicitly synthetic recovery stream fresh while waiting for
            # Prometheus; a historical/lookback value is not accepted as live.
            send(80, block_usage=None)
            prometheus = client.get(
                prom + "/api/v1/query",
                params={"query": "fleetdoctor_filesystem_inode_usage_ratio"},
            )
            prometheus.raise_for_status()
            prometheus_payload = prometheus.json()
            if prometheus_payload["data"]["result"]:
                break
            time.sleep(1)
        if prometheus_payload is None or not prometheus_payload["data"]["result"]:
            raise TimeoutError("inode Prometheus current sample was not scraped")
        proof.update(
            status="passed",
            opening=opening,
            resolved=resolved,
            postgres_restart_typed_configuration=True,
            filters=get("/diagnoses", rule="inode_exhaustion", status="resolved"),
            history=history,
            prometheus=prometheus_payload,
            dashboard_titles=dashboard_titles,
            sql_datasource_proof=sql_datasource_proof,
        )
