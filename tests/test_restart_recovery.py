from copy import deepcopy
from datetime import timedelta

from fastapi.testclient import TestClient
from test_disk import Rig

from fleetdoctor.collector import ACKNOWLEDGEMENT_HEADER, ACKNOWLEDGEMENT_VERSION, create_app
from fleetdoctor.schema import Delivery


def test_negotiated_acknowledgement_is_exact_and_unknown_version_is_pre_evaluation() -> None:
    rig = Rig()
    value = rig.sample(98)
    response = rig.client.post(
        "/ingest",
        content=value.model_dump_json(),
        headers={
            "Authorization": "Bearer " + "a" * 40,
            ACKNOWLEDGEMENT_HEADER: ACKNOWLEDGEMENT_VERSION,
        },
    )
    assert response.json() == {
        "status": "accepted",
        "durable": False,
        "incidents_durable": True,
        "checkpoint_durable": True,
        "identity": {
            "node_id": value.node_id,
            "boot_id": str(value.boot_id),
            "agent_session_id": str(value.agent_session_id),
            "sequence": value.sequence,
            "observed_at": value.observed_at.isoformat().replace("+00:00", "Z"),
        },
    }
    before = rig.store.snapshot({"node-a"}).checkpoints["node-a"]
    rejected = rig.client.post(
        "/ingest",
        content=rig.sample(98).model_dump_json(),
        headers={
            "Authorization": "Bearer " + "a" * 40,
            ACKNOWLEDGEMENT_HEADER: "future-v2",
        },
    )
    assert rejected.status_code == 422
    assert rig.store.snapshot({"node-a"}).checkpoints["node-a"] == before


def test_negotiated_retry_fails_closed_when_published_checkpoint_disappears() -> None:
    rig = Rig()
    value = rig.sample(10)
    headers = {
        "Authorization": "Bearer " + "a" * 40,
        ACKNOWLEDGEMENT_HEADER: ACKNOWLEDGEMENT_VERSION,
    }
    accepted = rig.client.post("/ingest", content=value.model_dump_json(), headers=headers)
    assert accepted.status_code == 200
    assert accepted.json()["checkpoint_durable"] is True

    state = rig.app.state.fleet
    published = state.published_checkpoints["node-a"].model_copy(deep=True)
    latest = state.latest["node-a"].model_copy(deep=True)
    identities = deepcopy(state.identities["node-a"])
    live = set(state.live)
    durable = rig.store.checkpoints.pop("node-a")

    failed = rig.client.post("/ingest", content=value.model_dump_json(), headers=headers)
    assert failed.status_code == 503
    assert failed.json() == {"detail": "incident storage unavailable"}
    assert "checkpoint_durable" not in failed.text
    assert state.published_checkpoints["node-a"] == published
    assert state.latest["node-a"] == latest
    assert state.identities["node-a"] == identities
    assert state.live == live

    rig.store.checkpoints["node-a"] = durable
    recovered = rig.client.post("/ingest", content=value.model_dump_json(), headers=headers)
    assert recovered.status_code == 200
    assert recovered.json()["status"] == "duplicate"
    assert recovered.json()["checkpoint_durable"] is True


def test_negotiated_retry_fails_closed_on_corrupt_checkpoint_metadata() -> None:
    rig = Rig()
    value = rig.sample(10)
    headers = {
        "Authorization": "Bearer " + "a" * 40,
        ACKNOWLEDGEMENT_HEADER: ACKNOWLEDGEMENT_VERSION,
    }
    accepted = rig.client.post("/ingest", content=value.model_dump_json(), headers=headers)
    assert accepted.status_code == 200
    durable = rig.store.checkpoints["node-a"]
    state = rig.app.state.fleet
    published = state.published_checkpoints["node-a"].model_copy(deep=True)
    rig.store.checkpoints["node-a"] = {"node_id": "node-a", "revision": 1}

    failed = rig.client.post("/ingest", content=value.model_dump_json(), headers=headers)
    assert failed.status_code == 503
    assert failed.json() == {"detail": "incident storage unavailable"}
    assert "checkpoint_durable" not in failed.text
    assert state.published_checkpoints["node-a"] == published

    rig.store.checkpoints["node-a"] = durable
    recovered = rig.client.post("/ingest", content=value.model_dump_json(), headers=headers)
    assert recovered.status_code == 200
    assert recovered.json()["status"] == "duplicate"
    assert recovered.json()["checkpoint_durable"] is True


def test_restart_restores_ordering_but_not_live_gauges_or_recovery_window() -> None:
    rig = Rig()
    for _ in range(3):
        rig.send(98)
    incident = rig.store.active()[0].model_copy(deep=True)
    rig.send(80)
    second_healthy = rig.sample(80)
    assert rig.post(second_healthy).json()["status"] == "accepted"

    restarted = create_app(
        rig.app.state.fleet.nodes,
        ("/", rig.app.state.fleet.paths[1]),
        clock=lambda: rig.now,
        store=rig.store,
    )
    rig.app = restarted
    rig.client = TestClient(restarted)
    restored = rig.client.get("/nodes/node-a/metrics").json()
    assert restored["observed_at"] is not None
    assert not restored["fresh"] and restored["filesystems"] is None
    assert not restored["delivery"]["available"]
    assert (
        'fleetdoctor_filesystem_available_bytes{filesystem="/",node="node-a"}'
        not in rig.client.get("/metrics").text
    )

    rig.now += timedelta(seconds=20)
    assert rig.post(second_healthy).json()["status"] == "duplicate"
    assert (
        rig.post(
            second_healthy.model_copy(update={"delivery": Delivery(discard_total=1)})
        ).status_code
        == 409
    )
    assert rig.store.active()[0].id == incident.id
    for _ in range(2):
        rig.send(80)
        assert rig.store.active()[0].id == incident.id
    rig.send(80)
    resolved = rig.store.get(incident.id)
    assert resolved and resolved.status == "resolved"
    assert resolved.opening_evidence == incident.opening_evidence
