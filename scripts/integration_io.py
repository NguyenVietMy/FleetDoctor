"""Exercise schema-v7 I/O lifecycle, supersession, API, metrics, and PostgreSQL reload."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from fleetdoctor.agent import make_sample
from fleetdoctor.schema import (
    CpuObservation,
    DnsObservation,
    FdObservation,
    Filesystem,
    HostMemoryObservation,
    IoCounters,
    IoDeviceObservation,
    IoObservation,
    IoPressureObservation,
    MemoryObservation,
    NetworkObservation,
)


def identity(generation: int = 11) -> tuple[str, dict[str, Any]]:
    value = {
        "major_minor": f"253:{generation}",
        "sysfs_path": f"/sys/devices/virtual/block/dm-{generation}",
        "diskseq": str(100 + generation),
        "dm_uuid": f"FLEETDOCTOR-IO-INTEGRATION-{generation}",
        "filesystem_id": 100 + generation,
    }
    resource = (
        "io:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:32]
    )
    return resource, value


def raw(delta: bool) -> tuple[IoCounters, IoCounters]:
    before = IoCounters(
        reads_completed=100,
        sectors_read=200,
        read_ms=1000,
        writes_completed=100,
        sectors_written=200,
        write_ms=1000,
        inflight=0,
        io_ms=1000,
        weighted_io_ms=2000,
        discards_completed=0,
        discard_sectors=0,
        discard_ms=0,
        flushes_completed=0,
        flush_ms=0,
    )
    after = before.model_copy(deep=True)
    if delta:
        after.reads_completed += 25
        after.sectors_read += 50
        after.read_ms += 750
        after.writes_completed += 25
        after.sectors_written += 50
        after.write_ms += 750
        after.io_ms += 900
        after.weighted_io_ms += 1500
    return before, after


def io_device(
    *,
    trigger: bool,
    baseline: bool = False,
    previous: IoDeviceObservation | None = None,
    generation: int = 11,
) -> IoDeviceObservation:
    resource, binding = identity(generation)
    if previous is None:
        before, after = raw(False)
    else:
        assert previous.counters is not None
        before = previous.counters.model_copy(deep=True)
        after = before.model_copy(deep=True)
        if trigger:
            after.reads_completed += 25
            after.sectors_read += 50
            after.read_ms += 750
            after.writes_completed += 25
            after.sectors_written += 50
            after.write_ms += 750
            after.io_ms += 900
            after.weighted_io_ms += 1500
    common = dict(
        resource=resource,
        status="available",
        major_minor=binding["major_minor"],
        device_name=f"dm-{generation}",
        sysfs_path=binding["sysfs_path"],
        diskseq=binding["diskseq"],
        dm_uuid=binding["dm_uuid"],
        filesystem_id=binding["filesystem_id"],
        scopes=["/io-integration"],
        mount_ids={"/io-integration": 100 + generation},
        mount_namespace="mnt:[111]",
        counters=after,
    )
    if baseline or previous is None:
        return IoDeviceObservation(rate_status="baseline", **common)
    return IoDeviceObservation(
        rate_status="available",
        counters_before=before,
        elapsed_seconds=1,
        completion_count=50 if trigger else 0,
        completion_latency_ms=30 if trigger else None,
        average_outstanding=1.5 if trigger else 0,
        read_bytes_per_second=25_600 if trigger else 0,
        write_bytes_per_second=25_600 if trigger else 0,
        completions_per_second=50 if trigger else 0,
        confirmed_idle=not trigger,
        **common,
    )


def prove(
    api: str, prom: str, values: dict[str, str], compose: Any, evidence: dict[str, Any]
) -> None:
    tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
    node = sorted(tokens)[0]
    boot, session = uuid4(), uuid4()
    sequence = 0

    def post_observation(observation: IoObservation) -> None:
        nonlocal sequence
        value = make_sample(
            node,
            boot,
            session,
            sequence,
            [
                Filesystem(mountpoint="/", errors=["io_fixture"]),
                Filesystem(mountpoint="/var/lib/fleetdoctor/chaos/disk", errors=["io_fixture"]),
            ],
            datetime.now(UTC),
            cpu=CpuObservation(errors=["io_fixture"]),
            memory=MemoryObservation(
                host=HostMemoryObservation(errors=["io_fixture"]),
                workload_errors={
                    "/fleetdoctor/integration-oom/workload": ["io_fixture"],
                    "/fleetdoctor/integration-oom/missing": ["io_fixture"],
                },
            ),
            fd=FdObservation(errors=["io_fixture"]),
            network=NetworkObservation.unavailable(None, "io_fixture"),
            dns=DnsObservation.unavailable(None, None, "io_fixture"),
            io=observation,
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
        if response.json()["status"] != "accepted":
            raise AssertionError(response.json())

    def post(device: IoDeviceObservation) -> None:
        post_observation(
            IoObservation(
                status="available",
                inventory_complete=True,
                configured_scopes=["/io-integration"],
                devices=[device],
                process_coverage="complete",
                registered_pressure_scopes=["host"],
                pressure=[
                    IoPressureObservation(
                        scope="host",
                        status="available",
                        some={"avg10": 1.0, "avg60": 2.0, "avg300": 3.0, "total": 4},
                        full={"avg10": 0.1, "avg60": 0.2, "avg300": 0.3, "total": 5},
                    )
                ],
                pressure_coverage="complete",
            )
        )

    current_device = io_device(trigger=False, baseline=True)
    post(current_device)
    for _ in range(3):
        current_device = io_device(trigger=True, previous=current_device)
        post(current_device)
    active = httpx.get(
        api + "/diagnoses",
        params={"node": node, "rule": "io_bottleneck", "status": "active"},
        timeout=3,
        trust_env=False,
    ).json()["diagnoses"]
    if len(active) != 1:
        raise AssertionError(active)
    identifier = active[0]["id"]
    lifecycle_checks: list[dict[str, Any]] = []

    def assert_lifecycle_feed(
        stage: str, *, expected_status: str, expected_available: bool, expected_stale: bool
    ) -> None:
        api_value = httpx.get(api + "/diagnoses/" + identifier, timeout=3, trust_env=False).json()
        if (
            api_value["status"] != expected_status
            or api_value["evidence_available"] is not expected_available
            or api_value["evidence_stale"] is not expected_stale
        ):
            raise AssertionError({"stage": stage, "api": api_value})
        checked: dict[str, Any] = {"stage": stage, "api": api_value, "feeds": {}}
        for dashboard_name in ("fleet", "node"):
            dashboard = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / f"monitoring/grafana/dashboards/{dashboard_name}.json"
                ).read_text(encoding="utf-8")
            )
            panel = next(item for item in dashboard["panels"] if item.get("id") == 20)
            sql = panel["targets"][0]["rawSql"].replace(
                "${status:raw}", "active|resolved|superseded"
            )
            if dashboard_name == "node":
                sql = sql.replace("${node:sqlstring}", "'" + node.replace("'", "''") + "'")
            output = compose(
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
                "-At",
                "-F",
                "|",
                "-c",
                sql,
            )
            row = next(
                (
                    line.split("|")
                    for line in output.splitlines()
                    if line.startswith(identifier + "|")
                ),
                None,
            )
            if row is None or len(row) != 12:
                raise AssertionError(
                    {"stage": stage, "dashboard": dashboard_name, "output": output}
                )
            feed = {
                "status": row[5],
                "evidence_stale": row[10] == "t",
                "evidence_available": row[11] == "t",
            }
            if feed != {
                "status": api_value["status"],
                "evidence_stale": api_value["evidence_stale"],
                "evidence_available": api_value["evidence_available"],
            }:
                raise AssertionError(
                    {"stage": stage, "dashboard": dashboard_name, "api": api_value, "feed": feed}
                )
            checked["feeds"][dashboard_name] = {"row": row, "sql": sql}
        lifecycle_checks.append(checked)

    assert_lifecycle_feed(
        "active_available", expected_status="active", expected_available=True, expected_stale=False
    )
    dashboard_queries = (
        'fleetdoctor_io_completion_latency_seconds{node="' + node + '"}',
        'fleetdoctor_io_average_outstanding{node="' + node + '"}',
        'fleetdoctor_io_read_bytes_per_second{node="' + node + '"}',
        'fleetdoctor_io_write_bytes_per_second{node="' + node + '"}',
        'fleetdoctor_io_completions_per_second{node="' + node + '"}',
        'fleetdoctor_io_inflight{node="' + node + '"}',
        'fleetdoctor_io_coverage_ratio{node="' + node + '"}',
        'fleetdoctor_io_admission_capacity_available{node="' + node + '"}',
        'fleetdoctor_io_admission_candidate_overflow{node="' + node + '"}',
        'fleetdoctor_io_pressure_some_avg10_ratio{node="' + node + '"}',
        'fleetdoctor_active_incidents{node="' + node + '",rule="io_bottleneck"}',
    )
    query_results: dict[str, Any] = {}
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        query_results = {
            query: httpx.get(
                prom + "/api/v1/query",
                params={"query": query},
                timeout=4,
                trust_env=False,
            ).json()
            for query in dashboard_queries
        }
        if all(
            value.get("status") == "success" and value.get("data", {}).get("result")
            for value in query_results.values()
        ):
            break
        time.sleep(1)
    if any(
        value.get("status") != "success" or not value.get("data", {}).get("result")
        for value in query_results.values()
    ):
        raise AssertionError(query_results)
    post_observation(
        IoObservation(
            status="partial",
            inventory_complete=False,
            configured_scopes=["/io-integration"],
            mapping_errors={"/io-integration": "fixture_mapping_unavailable"},
        )
    )
    assert_lifecycle_feed(
        "active_unavailable",
        expected_status="active",
        expected_available=False,
        expected_stale=False,
    )
    time.sleep(16)
    assert_lifecycle_feed(
        "active_unavailable_stale",
        expected_status="active",
        expected_available=False,
        expected_stale=True,
    )
    compose("restart", "collector")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if httpx.get(api + "/diagnoses/" + identifier, timeout=3).json()["status"] == "active":
                break
        except httpx.HTTPError:
            pass
        time.sleep(1)
    current_device = io_device(trigger=False, baseline=True)
    post(current_device)
    for _ in range(3):
        current_device = io_device(trigger=False, previous=current_device)
        post(current_device)
    detail = httpx.get(api + "/diagnoses/" + identifier, timeout=3).json()
    if detail["status"] != "resolved" or not detail["opening_evidence"]["io_available"]:
        raise AssertionError(detail)
    assert_lifecycle_feed(
        "resolved_available",
        expected_status="resolved",
        expected_available=True,
        expected_stale=False,
    )

    # Prove the terminal positive-replacement contract through real PostgreSQL,
    # list/detail APIs, and a production collector restart. The replacement is a
    # new stable device/filesystem generation on the same configured scope.
    current_device = io_device(trigger=False, baseline=True)
    post(current_device)
    for _ in range(3):
        current_device = io_device(trigger=True, previous=current_device)
        post(current_device)
    recurrence = httpx.get(
        api + "/diagnoses",
        params={"node": node, "rule": "io_bottleneck", "status": "active"},
        timeout=3,
        trust_env=False,
    ).json()["diagnoses"]
    if len(recurrence) != 1 or recurrence[0]["id"] == identifier:
        raise AssertionError(recurrence)
    superseded_identifier = recurrence[0]["id"]
    replacement = io_device(trigger=False, baseline=True, generation=12)
    post(replacement)
    superseded_detail = httpx.get(
        api + "/diagnoses/" + superseded_identifier, timeout=3, trust_env=False
    ).json()
    if (
        superseded_detail["status"] != "superseded"
        or superseded_detail["resolved_at"] is not None
        or superseded_detail["supersession_reason"] != "positive_resource_replacement"
        or superseded_detail["replacement_resource_evidence"]["replacements"][0]["resource"]
        != replacement.resource
    ):
        raise AssertionError(superseded_detail)
    superseded_list = httpx.get(
        api + "/diagnoses",
        params={"node": node, "rule": "io_bottleneck", "status": "superseded"},
        timeout=3,
        trust_env=False,
    ).json()
    if superseded_identifier not in {item["id"] for item in superseded_list["diagnoses"]}:
        raise AssertionError(superseded_list)
    compose("restart", "collector")
    restart_deadline = time.monotonic() + 30
    while True:
        try:
            reloaded_superseded = httpx.get(
                api + "/diagnoses/" + superseded_identifier,
                timeout=3,
                trust_env=False,
            ).json()
            if reloaded_superseded.get("status") == "superseded":
                break
        except httpx.HTTPError:
            pass
        if time.monotonic() > restart_deadline:
            raise TimeoutError("superseded I/O incident did not survive collector restart")
        time.sleep(0.5)
    persisted_fields = (
        "id",
        "status",
        "superseded_at",
        "supersession_reason",
        "replacement_resource_evidence",
        "opening_evidence",
        "latest_evidence",
    )
    if any(reloaded_superseded[field] != superseded_detail[field] for field in persisted_fields):
        raise AssertionError(
            {"before_restart": superseded_detail, "after_restart": reloaded_superseded}
        )
    metrics = httpx.get(api + "/metrics", timeout=3).text
    required = (
        "fleetdoctor_io_completion_latency_seconds",
        "fleetdoctor_io_average_outstanding",
        "fleetdoctor_io_coverage_ratio",
    )
    if any(name not in metrics for name in required):
        raise AssertionError("I/O metrics missing")
    prometheus: dict[str, Any] = {}
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        prometheus = httpx.get(
            prom + "/api/v1/query",
            params={"query": f'fleetdoctor_io_coverage_ratio{{node="{node}"}}'},
            timeout=4,
            trust_env=False,
        ).json()
        if prometheus.get("data", {}).get("result"):
            break
        time.sleep(1)
    if not prometheus.get("data", {}).get("result"):
        raise AssertionError(prometheus)
    dashboard = json.loads(
        (Path(__file__).resolve().parents[1] / "monitoring/grafana/dashboards/node.json").read_text(
            encoding="utf-8"
        )
    )
    detail_panel = next(panel for panel in dashboard["panels"] if panel.get("id") == 90)
    raw_sql = detail_panel["targets"][0]["rawSql"]
    executable_sql = raw_sql.replace("${status:raw}", "active|resolved|superseded").replace(
        "${node:sqlstring}", "'" + node.replace("'", "''") + "'"
    )
    sql_output = compose(
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
        "-At",
        "-c",
        executable_sql,
    )
    if (
        "Incident ID / status / severity" not in sql_output
        or "Investigation step 5" not in sql_output
    ):
        raise AssertionError(sql_output)
    evidence.update(
        incident_id=identifier,
        opening=active[0],
        resolved=detail,
        prometheus=prometheus,
        dashboard_prometheus_queries=query_results,
        dashboard_postgres_query={"sql": executable_sql, "output": sql_output},
        lifecycle_feed_checks=lifecycle_checks,
        postgres_supersession={
            "id": superseded_identifier,
            "replacement_resource": replacement.resource,
            "detail_before_restart": superseded_detail,
            "list": superseded_list,
            "detail_after_restart": reloaded_superseded,
        },
    )
