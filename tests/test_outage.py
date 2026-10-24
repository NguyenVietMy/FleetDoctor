import asyncio
from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest
from integration_outage import assert_recovery_response_cut, observe_recovery_response_cut
from test_disk import LostAcknowledgementStore, Rig

from fleetdoctor.schema import Delivery


def recovery_evidence(sequence: int, usage: float) -> dict[str, Any]:
    return {
        "boot_id": "boot-a",
        "agent_session_id": "session-a",
        "sequence": sequence,
        "block_available": True,
        "filesystem": {
            "mountpoint": "/var/lib/fleetdoctor/chaos/disk",
            "block_usage_percent": usage,
        },
    }


def recovery_opening() -> dict[str, Any]:
    return {
        "configuration": {
            "recovery_percent": 90,
            "consecutive_samples": 3,
        },
        "opening_evidence": recovery_evidence(0, 98),
    }


def recovery_attempt(sequence: int, status: str | None = "accepted") -> dict[str, Any]:
    return {
        "boot_id": "boot-a",
        "agent_session_id": "session-a",
        "sequence": sequence,
        "status": status,
    }


def recovery_ticks() -> list[dict[str, Any]]:
    return [
        {"sequence": sequence, "usage": 10, "monotonic": float(sequence)} for sequence in (1, 2, 3)
    ]


def test_recovery_response_cut_counts_pending_third_response_annotation() -> None:
    attempts = [recovery_attempt(1), recovery_attempt(2), recovery_attempt(3, None)]

    async def detail() -> dict[str, Any]:
        await asyncio.sleep(0)
        return {
            "status": "resolved",
            "latest_evidence": recovery_evidence(3, 10),
        }

    current, cut = asyncio.run(
        observe_recovery_response_cut(detail, recovery_opening(), attempts, recovery_ticks(), 0)
    )
    assert cut["accepted_at_response_sequences"] == [1, 2]
    assert cut["response_proven_sequence"] == 3
    assert cut["eligible_committed_sequences"] == [1, 2, 3]
    assert_recovery_response_cut(current, cut)


def test_recovery_response_cut_observes_new_tick_committed_during_awaited_get() -> None:
    attempts = [recovery_attempt(1), recovery_attempt(2)]
    ticks = recovery_ticks()[:2]

    async def detail() -> dict[str, Any]:
        await asyncio.sleep(0)
        ticks.append({"sequence": 3, "usage": 10, "monotonic": 3.0})
        attempts.append(recovery_attempt(3, None))
        return {
            "status": "resolved",
            "latest_evidence": recovery_evidence(3, 10),
        }

    current, cut = asyncio.run(
        observe_recovery_response_cut(detail, recovery_opening(), attempts, ticks, 0)
    )
    assert cut["healthy_tick_sequences"] == [1, 2, 3]
    assert cut["accepted_at_response_sequences"] == [1, 2]
    assert cut["response_proven_sequence"] == 3
    assert cut["eligible_committed_count"] == 3
    assert_recovery_response_cut(current, cut)


def test_recovery_response_cut_excludes_third_commit_after_returned_evidence() -> None:
    attempts = [recovery_attempt(1), recovery_attempt(2)]

    async def detail() -> dict[str, Any]:
        response = {"status": "active", "latest_evidence": recovery_evidence(2, 10)}
        attempts.append(recovery_attempt(3))
        return response

    current, cut = asyncio.run(
        observe_recovery_response_cut(detail, recovery_opening(), attempts, recovery_ticks(), 0)
    )
    assert cut["accepted_at_response_sequences"] == [1, 2]
    assert cut["eligible_committed_count"] == 2
    assert_recovery_response_cut(current, cut)


def test_recovery_response_cut_rejects_true_early_resolution() -> None:
    attempts = [recovery_attempt(1), recovery_attempt(2)]

    async def detail() -> dict[str, Any]:
        return {"status": "resolved", "latest_evidence": recovery_evidence(2, 10)}

    current, cut = asyncio.run(
        observe_recovery_response_cut(detail, recovery_opening(), attempts, recovery_ticks(), 0)
    )
    with pytest.raises(AssertionError, match="response/count cut mismatch"):
        assert_recovery_response_cut(current, cut)


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
