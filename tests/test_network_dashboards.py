import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def panels(name: str) -> dict[int, dict[str, Any]]:
    value = json.loads((ROOT / "monitoring/grafana/dashboards" / name).read_text(encoding="utf-8"))
    return {panel["id"]: panel for panel in value["panels"]}


def test_network_dashboards_use_bounded_labels_and_correct_kinds() -> None:
    fleet, node = panels("fleet.json"), panels("node.json")
    assert set(range(70, 74)) <= set(fleet)
    assert set(range(70, 78)) <= set(node)
    expressions = [
        target.get("expr", "")
        for panel in [*fleet.values(), *node.values()]
        for target in panel.get("targets", [])
    ]
    assert not any("target=" in expression for expression in expressions)
    assert not any(
        "tcp_state" in expression and "per_second" in expression for expression in expressions
    )
    assert node[71]["fieldConfig"]["defaults"]["unit"] == "s"
    assert node[70]["fieldConfig"]["defaults"]["unit"] == "percentunit"
    assert node[73]["fieldConfig"]["defaults"]["unit"] == "ops"
    assert node[75]["fieldConfig"]["defaults"]["unit"] == "ops"
    assert "network_path_degradation" in node[77]["targets"][0]["rawSql"]
    for dashboard in (fleet, node):
        lifecycle_sql = dashboard[20]["targets"][0]["rawSql"]
        assert "WHEN 'network_path_degradation'" in lifecycle_sql
        assert "latest_evidence'->>'network_available'" in lifecycle_sql
    detail_sql = node[77]["targets"][0]["rawSql"]
    assert "coverage'->>'limitation'" in detail_sql
    assert "route_error','available'" not in detail_sql
