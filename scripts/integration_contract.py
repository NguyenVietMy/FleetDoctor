"""Exercise request and history boundaries against the actual isolated collector."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx

from fleetdoctor.agent import make_sample
from fleetdoctor.schema import Filesystem


def prove(api: str, tokens: dict[str, str], proof: dict[str, Any]) -> None:
    # Run before producers start: rejected requests must leave the node inventory empty.
    with httpx.Client(base_url=api, timeout=4, trust_env=False) as client:
        headers = {"Authorization": "Bearer " + tokens["node-a"]}
        for label, content, expected in (
            ("malformed_json", b"{", 422),
            ("invalid_schema", b'{"schema_version":999}', 422),
            ("payload_limit", b"x" * 65537, 413),
        ):
            response = client.post("/ingest", content=content, headers=headers)
            assert response.status_code == expected, (label, response.status_code)
            proof[label] = response.status_code
        candidate = make_sample(
            "node-b",
            uuid4(),
            uuid4(),
            0,
            [
                Filesystem(mountpoint=mount, errors=["fixture_unavailable"])
                for mount in ("/", "/var/lib/fleetdoctor/chaos/disk")
            ],
        ).model_dump(mode="json")
        assert client.post("/ingest", json=candidate).status_code == 403
        proof["authentication_required"] = True
        assert client.post("/ingest", json=candidate, headers=headers).status_code == 403
        proof["cross_node_identity_rejected"] = True
        candidate["node_id"] = "node-a"
        candidate["units"] = {}
        assert client.post("/ingest", json=candidate, headers=headers).status_code == 422
        proof["invalid_units_rejected"] = True
        nodes = client.get("/nodes")
        nodes.raise_for_status()
        assert all(node["observed_at"] is None for node in nodes.json()["nodes"])
        proof["rejected_ingest_did_not_publish"] = True

        now = datetime.now(UTC) - timedelta(seconds=1)
        start = now - timedelta(minutes=1)
        cases: dict[str, dict[str, str | int]] = {
            "partial_range": {"start": start.isoformat()},
            "reversed_range": {"start": now.isoformat(), "end": start.isoformat()},
            "future_range": {
                "start": start.isoformat(),
                "end": (now + timedelta(days=1)).isoformat(),
            },
            "over_seven_days": {
                "start": (now - timedelta(days=8)).isoformat(),
                "end": now.isoformat(),
                "step": 500,
            },
            "too_many_points": {
                "start": (now - timedelta(days=1)).isoformat(),
                "end": now.isoformat(),
                "step": 5,
            },
            "step_below_bound": {"start": start.isoformat(), "end": now.isoformat(), "step": 1},
            "step_above_bound": {
                "start": start.isoformat(),
                "end": now.isoformat(),
                "step": 86401,
            },
            "unknown_field": {
                "start": start.isoformat(),
                "end": now.isoformat(),
                "field": "arbitrary_promql",
            },
        }
        for label, params in cases.items():
            response = client.get("/nodes/node-a/metrics", params=params)
            assert response.status_code == 422, (label, response.status_code, response.text)
        proof["history_rejections"] = sorted(cases)
        valid = client.get(
            "/nodes/node-a/metrics",
            params={"start": start.isoformat(), "end": now.isoformat(), "step": 5},
        )
        valid.raise_for_status()
        assert valid.json()["history"]["resultType"] == "matrix"
        proof["valid_history_reaches_prometheus"] = True
