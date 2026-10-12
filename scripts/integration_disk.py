"""Real PostgreSQL/Grafana incident proofs, invoked by the isolated stack runner."""

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from fleetdoctor.agent import make_sample
from fleetdoctor.collection import from_statvfs
from fleetdoctor.schema import Filesystem, Sample

PATH = "/var/lib/fleetdoctor/chaos/disk"


def prove(
    api: str,
    grafana: str,
    values: dict[str, str],
    compose: Callable[..., str],
    proof: dict[str, Any],
) -> dict[str, Any]:
    tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
    boot, session = uuid4(), uuid4()
    sequence = 0
    proof["environment"] = "real-isolated-PostgreSQL-Grafana-synthetic-observations"

    def fs(usage: int, path: str = PATH) -> Filesystem:
        return from_statvfs(
            path,
            {
                "f_blocks": 98304,
                "f_bfree": 98304 - usage * 983,
                "f_bavail": 98304 - usage * 983,
                "f_frsize": 4096,
                "f_files": 1000,
                "f_ffree": 900,
            },
        )

    with httpx.Client(
        timeout=8, trust_env=False, limits=httpx.Limits(max_keepalive_connections=0)
    ) as client:

        def get(path: str, **params: Any) -> dict[str, Any]:
            result = client.get(api + path, params=params)
            result.raise_for_status()
            data: dict[str, Any] = result.json()
            return data

        def sample(usage: int | None, node: str = "node-a") -> Sample:
            nonlocal sequence
            sequence += 1
            return make_sample(
                node,
                boot,
                session,
                sequence,
                [
                    fs(10, "/"),
                    fs(usage)
                    if usage is not None
                    else Filesystem(mountpoint=PATH, errors=["integration_unavailable"]),
                ],
            )

        def post(value: Sample) -> httpx.Response:
            return client.post(
                api + "/ingest",
                content=value.model_dump_json(),
                headers={"Authorization": "Bearer " + tokens[value.node_id]},
            )

        def send(usage: int | None, node: str = "node-a") -> Sample:
            value = sample(usage, node)
            result = post(value)
            assert result.status_code == 200, result.text
            assert result.json()["status"] == "accepted" and result.json()["incidents_durable"]
            assert result.json()["durable"] is False
            return value

        def sql_query(raw: str) -> dict[str, Any]:
            response = client.post(
                grafana + "/api/ds/query",
                auth=("admin", values["GRAFANA_PASSWORD"]),
                json={
                    "queries": [
                        {
                            "refId": "A",
                            "datasource": {
                                "uid": "incidents",
                                "type": "grafana-postgresql-datasource",
                            },
                            "rawSql": raw,
                            "format": "table",
                        }
                    ],
                    "from": "now-1h",
                    "to": "now",
                },
            )
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            assert not data["results"]["A"].get("error"), data
            return data

        def sql_rows(query: str) -> list[dict[str, Any]]:
            data = sql_query(query)
            rows: list[dict[str, Any]] = []
            for frame in data["results"]["A"]["frames"]:
                names = [f["name"] for f in frame["schema"]["fields"]]
                rows.extend(
                    dict(zip(names, row, strict=True))
                    for row in zip(*frame["data"]["values"], strict=True)
                )
            return rows

        def psql(statement: str) -> str:
            return compose(
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "fleetdoctor",
                "-d",
                "fleetdoctor",
                "-v",
                "ON_ERROR_STOP=1",
                "-Atc",
                statement,
            )

        send(10, "node-b")
        send(96)
        send(96)
        before = get("/nodes/node-a/metrics")["sample"]
        psql("ALTER TABLE incidents RENAME TO incidents_temporarily_unavailable")
        failing = sample(97)
        try:
            failed = post(failing)
            assert failed.status_code == 503 and "incidents_durable" not in failed.text
        finally:
            psql("ALTER TABLE incidents_temporarily_unavailable RENAME TO incidents")
        after = get("/nodes/node-a/metrics")["sample"]
        assert after == before and get("/diagnoses")["total"] == 0
        retried = post(failing)
        assert retried.json()["status"] == "accepted"
        assert post(failing).json()["status"] == "duplicate"
        record = get("/diagnoses", status="active")["diagnoses"][0]
        identifier = record["id"]
        original = get("/diagnoses/" + identifier)
        assert original["severity"] == "critical" and original["resource"] == PATH
        proof["database_sql_failure_same_sample_retry"] = {
            "failed_status": failed.status_code,
            "retry": retried.json(),
            "unchanged_latest": True,
            "one_incident": identifier,
        }
        send(99)
        updated = get("/diagnoses/" + identifier)
        assert updated["opening_evidence"] == original["opening_evidence"]
        assert updated["latest_evidence"] != original["latest_evidence"]
        proof["opening_detail"] = original
        compose("up", "-d", "--force-recreate", "--no-deps", "collector")
        deadline = time.monotonic() + 30
        while True:
            try:
                reloaded = get("/diagnoses/" + identifier)
                break
            except httpx.HTTPError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
        assert reloaded["evidence_stale"] and not reloaded["evidence_fresh"]
        assert reloaded["opening_evidence"] == original["opening_evidence"]
        proof["reload_detail_before_observation"] = reloaded
        stale_query = "SELECT evidence_reloaded, (evidence_reloaded OR now()-observed_at > interval '15 seconds' OR observed_at-now() > interval '2 seconds') AS evidence_stale, (now()-observed_at <= interval '15 seconds') AS age_under_15, (record->'latest_evidence'->>'block_available')::boolean AS evidence_available FROM incidents WHERE status='active'"
        reloaded_sql = sql_rows(stale_query)
        assert reloaded_sql[0]["evidence_reloaded"] and reloaded_sql[0]["evidence_stale"]
        assert reloaded_sql[0][
            "age_under_15"
        ]  # fast restart actually proves reload, not age-only staleness
        proof["grafana_reload_before_observation"] = reloaded_sql
        send(None)
        missing = get("/diagnoses/" + identifier)
        assert (
            missing["evidence_fresh"]
            and not missing["evidence_available"]
            and not missing["evidence_stale"]
        )
        missing_sql = sql_rows(stale_query)[0]
        assert not missing_sql["evidence_stale"] and not missing_sql["evidence_available"]
        proof["fresh_missing_block_api_sql"] = {"api": missing, "sql": missing_sql}
        compose("stop", "postgres")
        try:
            aged_outage = sample(98)
            assert post(aged_outage).status_code == 503
            assert client.get(api + "/health").status_code == 503
            assert client.get(api + "/nodes").status_code == 503
            assert client.get(api + "/diagnoses").status_code == 503
            metrics = client.get(api + "/metrics").text
            assert "fleetdoctor_incident_storage_up 0.0" in metrics
            assert 'fleetdoctor_active_incidents{node="node-a"' not in metrics
            proof["startup_database_failure_no_memory_fallback"] = compose(
                "exec",
                "-T",
                "collector",
                "/app/.venv/bin/python",
                "-c",
                "from fleetdoctor.collector import app_factory; from fleetdoctor.store import StoreError;\ntry: app_factory()\nexcept StoreError: print('factory refuses unavailable required storage')\nelse: raise AssertionError('factory started without database')",
            ).strip()
            # Connection errors can return immediately on some Docker engines.
            # Explicitly age this first observation; create the fresh retry below
            # afterwards so expiry never depends on DNS/connect failure latency.
            expiry_delay = max(
                0.0, 11 - (datetime.now(UTC) - aged_outage.observed_at).total_seconds()
            )
            time.sleep(expiry_delay)
            proof["explicit_failed_observation_expiry_delay_seconds"] = expiry_delay
            outage = sample(98)
            failed_outage = post(outage)
            assert failed_outage.status_code == 503
        finally:
            compose("start", "postgres")
        deadline = time.monotonic() + 8
        while client.get(api + "/health").status_code != 200:
            if time.monotonic() > deadline:
                raise TimeoutError("DB recovery too slow for same-observation retry")
            time.sleep(0.1)
        aged_retry = post(aged_outage)
        proof["first_failure_freshness_reproduction"] = {
            "retry_status": aged_retry.status_code,
            "retry_body": aged_retry.json(),
            "observation_age_seconds": (
                datetime.now(UTC) - aged_outage.observed_at
            ).total_seconds(),
            "note": "First failed observation explicitly held until expired before retry; connection-error latency is not assumed",
        }
        assert aged_retry.json()["status"] == "ineligible"
        retried_outage = post(outage)
        proof["outage_retry_details"] = {
            "observation": outage.model_dump(mode="json"),
            "failed_status": failed_outage.status_code,
            "retry_status": retried_outage.status_code,
            "retry_body": retried_outage.json(),
            "observation_age_seconds": (datetime.now(UTC) - outage.observed_at).total_seconds(),
        }
        assert retried_outage.json()["status"] == "accepted", proof["outage_retry_details"]
        assert post(outage).json()["status"] == "duplicate"
        proof["real_database_outage_same_sample_retry"] = True
        for _ in range(3):
            send(80)
        resolved = get("/diagnoses/" + identifier)
        assert resolved["status"] == "resolved" and resolved["resolved_at"]
        assert resolved["opening_evidence"] == original["opening_evidence"]
        proof["resolved_detail"] = resolved
        for _ in range(3):
            send(98)
        new = get("/diagnoses", status="active")["diagnoses"][0]
        assert new["id"] != identifier and get("/diagnoses")["total"] == 2
        proof["recurrence_id"] = new["id"]
        assert get("/diagnoses", node="node-b")["total"] == 0
        assert get("/diagnoses", node="node-a' OR 1=1 --")["total"] == 0
        assert get("/diagnoses", rule="disk_block_exhaustion", status="resolved")["total"] == 1
        pages = [get("/diagnoses", limit=1, offset=i) for i in range(2)]
        assert [p["diagnoses"][0]["id"] for p in pages] == [new["id"], identifier]
        assert pages[0]["next_offset"] == 1 and pages[1]["next_offset"] is None
        assert (
            get("/diagnoses", start=(datetime.now(UTC) + timedelta(days=1)).isoformat())["total"]
            == 0
        )
        assert client.get(api + "/diagnoses/" + str(uuid4())).status_code == 404
        assert client.get(api + "/diagnoses", params={"offset": 10001}).status_code == 422
        proof["filters_pagination"] = pages
        dashboard_proof = {}
        for name in ("fleet", "node"):
            data = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "monitoring/grafana/dashboards"
                    / (name + ".json")
                ).read_text()
            )
            for panel in data["panels"]:
                if panel["datasource"]["uid"] == "incidents":
                    raw = (
                        panel["targets"][0]["rawSql"]
                        .replace("${status:raw}", ".*")
                        .replace("${node:sqlstring}", "'node-a'")
                    )
                    dashboard_proof[name + ":" + panel["title"]] = sql_query(raw)
        proof["actual_dashboard_queries"] = dashboard_proof
        privileges = psql(
            "SELECT has_table_privilege('fleetdoctor_reader','incidents','SELECT'),has_table_privilege('fleetdoctor_reader','incidents','INSERT'),has_table_privilege('fleetdoctor_reader','incidents','UPDATE'),has_table_privilege('fleetdoctor_reader','incidents','DELETE')"
        )
        assert privileges.strip() == "t|f|f|f"
        # Test a real reader write, with read-only default explicitly disabled: ACL must still deny it.
        compose(
            "exec",
            "-T",
            "collector",
            "/app/.venv/bin/python",
            "-c",
            "import os,psycopg; c=psycopg.connect(host='postgres',dbname='fleetdoctor',user='fleetdoctor_reader',password=os.environ['GRAFANA_DB_PASSWORD'],autocommit=True); c.execute('SET default_transaction_read_only=off');\ntry: c.execute(\"DELETE FROM incidents\")\nexcept psycopg.errors.InsufficientPrivilege: print('reader write denied by ACL')\nelse: raise AssertionError('reader can write')",
        )
        proof["reader_acl"] = privileges.strip()
        # Age is derived from observation timestamp, independently of updated_at.
        psql(
            "UPDATE incidents SET observed_at=now()-interval '16 seconds', record=jsonb_set(jsonb_set(record,'{observed_at}',to_jsonb(now()-interval '16 seconds')),'{latest_evidence,observed_at}',to_jsonb(now()-interval '16 seconds')) WHERE status='active'"
        )
        age_rows = sql_rows(stale_query)
        assert age_rows[0]["evidence_stale"] and not age_rows[0]["age_under_15"]
        age_api = get("/diagnoses/" + new["id"])
        assert age_api["evidence_stale"] and not age_api["evidence_fresh"]
        proof["grafana_age_stale"] = age_rows
        proof["api_age_stale"] = age_api
        probe = Path(__file__).with_name("commit_ack_probe.py").read_text(encoding="utf-8")
        proof["committed_acknowledgement_reconciliation"] = json.loads(
            compose("exec", "-T", "collector", "/app/.venv/bin/python", "-c", probe)
        )
        proof["status"] = "passed"
    return proof
