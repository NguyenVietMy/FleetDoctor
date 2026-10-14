from datetime import UTC, datetime
from threading import BoundedSemaphore
from typing import Any
from uuid import uuid4

import psycopg
import pytest

from fleetdoctor.agent import make_sample
from fleetdoctor.checkpoint import Checkpoint, IdentityFingerprint, sample_fingerprint
from fleetdoctor.incidents import DiskConfig, Incident
from fleetdoctor.schema import Filesystem
from fleetdoctor.store import FixtureStore, PostgresStore, StoreError

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)


def checkpoint(revision: int = 1) -> Checkpoint:
    value = make_sample(
        "node-a",
        uuid4(),
        uuid4(),
        revision,
        [Filesystem(mountpoint="/", errors=["fixture"])],
        NOW,
    )
    return Checkpoint(
        node_id="node-a",
        revision=revision,
        latest=value,
        fingerprints=[
            IdentityFingerprint(
                boot_id=value.boot_id,
                agent_session_id=value.agent_session_id,
                sequence=value.sequence,
                fingerprint=sample_fingerprint(value),
            )
        ],
        retired_sessions=[],
    )


def incident() -> Incident:
    return Incident(
        id=uuid4(),
        node_id="node-a",
        resource="/",
        severity="critical",
        diagnosis="fixture",
        configuration=DiskConfig(),
        opening_evidence={"block_available": True},
        latest_evidence={"block_available": True},
        opened_at=NOW,
        observed_at=NOW,
        evaluated_at=NOW,
        updated_at=NOW,
        investigation_steps=["fixture"],
    )


def test_fixture_snapshot_and_commit_are_detached() -> None:
    store = FixtureStore()
    value, record = checkpoint(), incident()
    store.commit([record], value)
    snap = store.snapshot({"node-a"})
    assert snap.active == [record]
    assert snap.checkpoints == {"node-a": value}
    snap.active[0].latest_evidence["mutated"] = True
    assert "mutated" not in store.get(record.id).latest_evidence  # type: ignore[union-attr]


@pytest.mark.parametrize("boundary", ["after_incidents", "after_checkpoint"])
def test_fixture_ingestion_failure_rolls_back_incident_and_checkpoint(boundary: str) -> None:
    store = FixtureStore()
    value, record = checkpoint(), incident()
    setattr(store, "fail_" + boundary, True)
    with pytest.raises(StoreError, match=boundary):
        store.commit([record], value)
    snap = store.snapshot({"node-a"})
    assert snap.active == [] and snap.checkpoints == {}


def test_malformed_stored_checkpoint_fails_closed() -> None:
    store = FixtureStore()
    store.checkpoints["node-a"] = {"node_id": "node-a", "revision": 1}
    with pytest.raises(StoreError, match="invalid stored checkpoint"):
        store.snapshot({"node-a"})


@pytest.mark.parametrize(
    "corruption",
    ["missing_latest", "mismatched_latest", "latest_retired", "zero_revision", "revision_low"],
)
def test_incoherent_persisted_checkpoint_fails_closed(corruption: str) -> None:
    value = checkpoint().model_dump(mode="json")
    latest = value["latest"]
    if corruption == "missing_latest":
        value["fingerprints"] = []
    elif corruption == "mismatched_latest":
        value["fingerprints"][-1]["fingerprint"] = "0" * 64
    elif corruption == "latest_retired":
        value["retired_sessions"] = [
            {
                "boot_id": latest["boot_id"],
                "agent_session_id": latest["agent_session_id"],
            }
        ]
    elif corruption == "zero_revision":
        value["revision"] = 0
    else:
        value["fingerprints"].insert(
            0,
            {
                "boot_id": str(uuid4()),
                "agent_session_id": str(uuid4()),
                "sequence": 0,
                "fingerprint": "0" * 64,
            },
        )
    store = FixtureStore()
    store.checkpoints["node-a"] = value
    with pytest.raises(StoreError, match="invalid stored checkpoint"):
        store.snapshot({"node-a"})


def test_postgres_health_requires_checkpoint_table(monkeypatch: pytest.MonkeyPatch) -> None:
    class MissingCheckpointConnection:
        def __enter__(self) -> "MissingCheckpointConnection":
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def execute(self, statement: str, params: object = None) -> list[object]:
            if "ingestion_checkpoints" in statement:
                raise psycopg.errors.UndefinedTable("checkpoint table unavailable")
            return []

    store = object.__new__(PostgresStore)
    store.dsn = "fixture"
    store.slots = BoundedSemaphore(4)
    monkeypatch.setattr(store, "connect", MissingCheckpointConnection)
    assert store.health() is False
