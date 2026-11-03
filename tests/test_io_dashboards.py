import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def dashboard(name: str) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(
        (ROOT / "monitoring/grafana/dashboards" / name).read_text(encoding="utf-8")
    )
    return value


def test_io_manifest_matches_real_bounded_dashboard_queries() -> None:
    manifest = json.loads((ROOT / "monitoring/grafana/io-panel-manifest.json").read_text())
    dashboards = {
        value["uid"]: {panel["id"]: panel for panel in value["panels"]}
        for value in (dashboard("fleet.json"), dashboard("node.json"))
    }
    for declared in manifest["dashboards"]:
        actual = dashboards[declared["uid"]]
        for panel in declared["panels"]:
            assert panel["id"] in actual
            assert {target["refId"] for target in panel["targets"]} == {
                target["refId"] for target in actual[panel["id"]]["targets"]
            }

    prometheus = [
        target["expr"]
        for panels in dashboards.values()
        for panel in panels.values()
        for target in panel.get("targets", [])
        if "expr" in target and "io_" in target["expr"]
    ]
    assert prometheus
    assert all("pid" not in query and "resource" not in query for query in prometheus)
    assert any("fleetdoctor_io_completion_latency_seconds" in query for query in prometheus)
    assert any("fleetdoctor_io_average_outstanding" in query for query in prometheus)
    assert any("fleetdoctor_io_pressure_some_avg10_ratio" in query for query in prometheus)


def test_io_detail_query_covers_full_evidence_lifecycle_and_five_steps() -> None:
    node_dashboard = dashboard("node.json")
    fleet_dashboard = dashboard("fleet.json")
    node = {panel["id"]: panel for panel in node_dashboard["panels"]}
    query = node[90]["targets"][0]["rawSql"]
    for required in (
        "io_bottleneck",
        "opening_evidence",
        "Opening stable device / filesystem binding",
        "Opening raw counters before",
        "Opening raw counters after",
        "Opening interval / rate status",
        "latest_evidence",
        "Latest availability / rate coverage",
        "supersession_reason",
        "replacement_resource_evidence",
        "counters_before",
        "host_and_cgroup_pressure",
        "process_context",
        "investigation_steps",
        "WITH ORDINALITY",
    ):
        assert required in query
    assert node[90]["fieldConfig"]["defaults"]["custom"]["cellOptions"]["wrapText"] is True
    assert node[90]["options"]["cellHeight"] == "lg"
    assert node[86]["fieldConfig"]["overrides"][0]["matcher"]["options"] == "B"
    assert {item["matcher"]["options"] for item in node[87]["fieldConfig"]["overrides"]} == {
        "C",
        "D",
    }
    for value in (node_dashboard, fleet_dashboard):
        lifecycle = next(panel for panel in value["panels"] if panel["id"] == 20)
        lifecycle_query = lifecycle["targets"][0]["rawSql"]
        assert (
            "WHEN 'io_bottleneck' THEN (record->'latest_evidence'->>'io_available')::boolean"
            in lifecycle_query
        )
