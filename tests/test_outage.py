from datetime import timedelta
from uuid import uuid4

import pytest
from test_disk import LostAcknowledgementStore, Rig

from fleetdoctor.schema import Delivery


def test_delivery_publication_compatibility_conflict_and_failed_commit() -> None:
    store = LostAcknowledgementStore()
    rig = Rig(store)
    value = rig.sample(98).model_copy(update={"delivery": Delivery(discard_total=4)})
    assert rig.post(value).json()["status"] == "accepted"
    assert rig.post(value).json()["status"] == "duplicate"
    conflict = value.model_copy(update={"delivery": Delivery(discard_total=5)})
    assert rig.post(conflict).status_code == 409
    rig.send(98)
    third = rig.sample(98).model_copy(update={"delivery": Delivery(discard_total=10)})
    store.lose_next_commit = True
    assert rig.post(third).status_code == 503
    view = rig.client.get("/nodes/node-a/metrics").json()
    assert not view["delivery"]["available"] and view["delivery"]["discard_total"] is None
    assert rig.post(third).json()["status"] == "duplicate"
    assert not rig.client.get("/nodes/node-a/metrics").json()["delivery"]["available"]
    fresh = rig.sample(98).model_copy(update={"delivery": Delivery(discard_total=10)})
    assert rig.post(fresh).json()["status"] == "accepted"
    assert rig.client.get("/nodes/node-a/metrics").json()["delivery"]["discard_total"] == 10
    metrics = rig.client.get("/metrics").text
    assert 'fleetdoctor_delivery_discard_total{node="node-a"} 10.0' in metrics
    assert 'fleetdoctor_delivery_discard_total{node="node-b"}' not in metrics
    # An earlier accepted identity remains checked within bounded retention.
    assert rig.post(conflict).status_code == 409
    rig.session = uuid4()
    newer = rig.sample(98).model_copy(update={"delivery": Delivery(discard_total=0)})
    assert rig.post(newer).json()["status"] == "accepted"
    assert rig.client.get("/nodes/node-a/metrics").json()["delivery"]["discard_total"] == 0


@pytest.mark.parametrize(
    "age,status",
    [(-2, "accepted"), (10, "accepted"), (-2.000001, "ineligible"), (10.000001, "ineligible")],
)
def test_inclusive_freshness(age: float, status: str) -> None:
    rig = Rig()
    value = rig.sample(98)
    rig.now = value.observed_at + timedelta(seconds=age)
    assert rig.post(value).json()["status"] == status


def test_gap_replay_missing_and_three_new_recovery_samples() -> None:
    rig = Rig()
    for _ in range(3):
        rig.send(98)
    incident = rig.store.active()[0].model_copy(deep=True)
    old_healthy = rig.sample(10)
    rig.now += timedelta(seconds=20)
    rig.send(10, node="node-b", gap=0)
    view = rig.client.get("/nodes/node-a/metrics").json()
    assert view["stale"] and not view["fresh"] and view["filesystems"] is None
    assert rig.post(old_healthy).json()["status"] == "ineligible"
    assert rig.store.active()[0].opening_evidence == incident.opening_evidence
    rig.send(10)
    fresh = rig.sample(10)
    assert rig.post(fresh).json()["status"] == "accepted"
    assert rig.post(fresh).json()["status"] == "duplicate"
    assert rig.store.active()[0].id == incident.id
    rig.send(None)  # Missing block data resets recovery without resolving.
    for _ in range(2):
        rig.send(10)
        assert rig.store.active()[0].id == incident.id
    rig.send(10)
    assert not rig.store.active()
    for _ in range(3):
        rig.send(98)
    assert rig.store.active()[0].id != incident.id


def test_retirement_eviction_and_nonincreasing_time_cannot_revive() -> None:
    rig = Rig()
    oldest = rig.sample(98)
    assert rig.post(oldest).json()["status"] == "accepted"
    for _ in range(10):
        rig.session = uuid4()
        assert rig.post(rig.sample(98, gap=0)).json()["status"] == "superseded"
        # Time order supersedes equal-time changed sessions; then publish a newer one.
        rig.now += timedelta(microseconds=1)
        rig.send(98, gap=0)
    assert len(rig.app.state.fleet.retired["node-a"]) == 8
    # Evict fingerprints too; latest time still protects retired sessions beyond retention.
    for _ in range(61):
        rig.now += timedelta(microseconds=1)
        rig.send(98, gap=0)
    checkpoint = rig.store.snapshot({"node-a"}).checkpoints["node-a"]
    assert len(checkpoint.fingerprints) == 60
    assert len(checkpoint.retired_sessions) == 8
    assert rig.post(oldest).json()["status"] == "superseded"
    previous = rig.app.state.fleet.latest["node-a"]
    assert (
        rig.post(previous.model_copy(update={"sequence": previous.sequence + 1})).json()["status"]
        == "superseded"
    )
