import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def panels(name: str) -> dict[int, dict[str, Any]]:
    value = json.loads((ROOT / "monitoring/grafana/dashboards" / name).read_text())
    identifiers = [int(panel["id"]) for panel in value["panels"]]
    assert len(identifiers) == len(set(identifiers))
    return {int(panel["id"]): panel for panel in value["panels"]}


def test_dns_manifest_matches_dashboard_targets_and_uses_bounded_labels() -> None:
    manifest = json.loads(
        (ROOT / "monitoring/grafana/dns-panel-manifest.json").read_text(encoding="utf-8")
    )
    dashboards = {
        "fleetdoctor-fleet": panels("fleet.json"),
        "fleetdoctor-node": panels("node.json"),
    }
    for declared in manifest["dashboards"]:
        actual = dashboards[declared["uid"]]
        for expected in declared["panels"]:
            panel = actual[expected["id"]]
            actual_refs = {target["refId"] for target in panel["targets"]}
            assert actual_refs == {target["refId"] for target in expected["targets"]}
    expressions = [
        target.get("expr", "")
        for dashboard in dashboards.values()
        for panel in dashboard.values()
        for target in panel.get("targets", [])
    ]
    assert not any(
        "hostname=" in expression or "nameserver=" in expression for expression in expressions
    )
    assert manifest["required_states"] == [
        "healthy",
        "active_failure",
        "inconclusive",
        "unavailable",
        "stale",
        "resolved",
        "hostname_changed",
        "direct_ip_target_changed",
    ]


def test_dns_detail_contains_complete_bounded_evidence_and_investigation_steps() -> None:
    detail = panels("node.json")[85]
    query = detail["targets"][0]["rawSql"]
    for field in (
        "hostname",
        "direct_ip_target",
        "resolver",
        "baseline",
        "query",
        "configuration",
        "investigation_steps",
        "inconclusive_reason",
    ):
        assert field in query
    for required in (
        "Opening hostname / Direct-IP target",
        "Opening identity / observed at",
        "Opening known-good baseline identity / observed at",
        "Current hostname / Direct-IP target",
        "Current query status / error / duration",
        "Current resolver nameservers / selected",
        "latest_evidence'->'dns'",
        "opening_evidence'->'baseline'",
    ):
        assert required in query
    assert query.index("opening_evidence'->'baseline'") < query.index("latest_evidence'->'dns'")
    assert detail["type"] == "table"
    custom = detail["fieldConfig"]["defaults"]["custom"]
    assert custom["cellOptions"] == {"type": "auto", "wrapText": True}
    assert "wrapText" not in custom
    assert detail["options"]["cellHeight"] == "lg"
