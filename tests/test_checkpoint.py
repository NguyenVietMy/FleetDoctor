from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from fleetdoctor.agent import make_sample
from fleetdoctor.checkpoint import (
    MAX_CHECKPOINT_BYTES,
    Checkpoint,
    IdentityFingerprint,
    RetiredSession,
    sample_fingerprint,
)
from fleetdoctor.collector import MAX_BODY, create_app
from fleetdoctor.schema import UNITS, Filesystem, Sample
from fleetdoctor.store import FixtureStore

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)


def sample(*, node: str = "node-a", sequence: int = 1) -> Sample:
    return make_sample(
        node,
        uuid4(),
        uuid4(),
        sequence,
        [Filesystem(mountpoint="/", errors=["fixture"])],
        NOW,
    )


def fingerprint(value: Sample) -> IdentityFingerprint:
    return IdentityFingerprint(
        boot_id=value.boot_id,
        agent_session_id=value.agent_session_id,
        sequence=value.sequence,
        fingerprint=sample_fingerprint(value),
    )


def test_fingerprint_is_canonical_across_jsonb_key_order_and_utc_spelling() -> None:
    value = sample(sequence=2**64 - 1)
    reordered = Sample.model_validate(
        value.model_dump(mode="json")
        | {
            "units": dict(reversed(list(UNITS.items()))),
            "observed_at": value.observed_at.astimezone(timezone(timedelta(hours=-4))),
        }
    )
    assert sample_fingerprint(value) == sample_fingerprint(reordered)


def test_checkpoint_enforces_node_and_retention_bounds() -> None:
    value = sample()
    valid = Checkpoint(
        node_id="node-a",
        revision=1,
        latest=value,
        fingerprints=[fingerprint(value)],
        retired_sessions=[],
    )
    assert valid.latest.sequence == 1
    with pytest.raises(ValidationError, match="checkpoint node"):
        valid.model_copy(update={"node_id": "node-b"}).model_dump_json()
        Checkpoint.model_validate(valid.model_dump() | {"node_id": "node-b"})
    with pytest.raises(ValidationError):
        Checkpoint(
            node_id="node-a",
            revision=1,
            latest=value,
            fingerprints=[fingerprint(value)] * 61,
            retired_sessions=[],
        )
    retired = [RetiredSession(boot_id=uuid4(), agent_session_id=uuid4()) for _ in range(9)]
    with pytest.raises(ValidationError):
        Checkpoint(
            node_id="node-a",
            revision=1,
            latest=value,
            fingerprints=[fingerprint(value)],
            retired_sessions=retired,
        )


def test_near_limit_utf8_ingest_fits_full_checkpoint_metadata() -> None:
    paths = tuple(f"/m{index}" for index in range(8))
    boot, session = uuid4(), uuid4()
    latest = make_sample(
        "node-a",
        boot,
        session,
        1,
        [Filesystem(mountpoint=path, errors=["fixture"]) for path in paths],
        NOW - timedelta(seconds=5),
    )
    old = [
        IdentityFingerprint(
            boot_id=UUID(int=index + 1),
            agent_session_id=UUID(int=index + 101),
            sequence=0,
            fingerprint="0" * 64,
        )
        for index in range(58)
    ]
    store = FixtureStore()
    store.checkpoints["node-a"] = Checkpoint(
        node_id="node-a",
        revision=59,
        latest=latest,
        fingerprints=[*old, fingerprint(latest)],
        retired_sessions=[
            RetiredSession(boot_id=item.boot_id, agent_session_id=item.agent_session_id)
            for item in old[:8]
        ],
    )
    app = create_app(
        {"node-a": SecretStr("a" * 40)},
        paths,
        clock=lambda: NOW,
        store=store,
    )
    value = make_sample(
        "node-a",
        boot,
        session,
        2,
        [Filesystem(mountpoint=path, errors=[chr(0x1F600) * 247] * 8) for path in paths],
        NOW,
    )
    body = value.model_dump_json().encode("utf-8")
    assert MAX_BODY - 256 < len(body) <= MAX_BODY
    client = TestClient(app)
    assert (
        client.get("/configuration").json()["ingestion_checkpoint"]["max_record_bytes"]
        == MAX_CHECKPOINT_BYTES
    )
    response = client.post(
        "/ingest",
        content=body,
        headers={"Authorization": "Bearer " + "a" * 40},
    )
    assert response.status_code == 200 and response.json()["status"] == "accepted"
    checkpoint = store.snapshot({"node-a"}).checkpoints["node-a"]
    checkpoint_bytes = len(checkpoint.model_dump_json().encode("utf-8"))
    assert MAX_BODY < checkpoint_bytes <= MAX_CHECKPOINT_BYTES
