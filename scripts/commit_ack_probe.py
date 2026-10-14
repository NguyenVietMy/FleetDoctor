"""Real PostgreSQL commits with a client-side lost-acknowledgement fault.

Run inside the disposable integration collector. This simulates the connection
error after a real commit; it does not claim to drop an actual network packet.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import psycopg
from pydantic import SecretStr

from fleetdoctor.agent import make_sample
from fleetdoctor.checkpoint import (
    MAX_CHECKPOINT_BYTES,
    Checkpoint,
    IdentityFingerprint,
    RetiredSession,
    sample_fingerprint,
)
from fleetdoctor.collection import from_statvfs
from fleetdoctor.collector import State
from fleetdoctor.incidents import DiskConfig, Incident
from fleetdoctor.schema import Filesystem, Sample
from fleetdoctor.store import PostgresStore, StoreError

PATH = "/var/lib/fleetdoctor/chaos/disk"


def constant_clock(value: datetime) -> Callable[[], datetime]:
    return lambda: value


class LostAcknowledgementStore(PostgresStore):
    inside_commit = False
    lose_next_commit = False

    def connect(self) -> Any:
        connection = super().connect()
        owner = self

        class Context:
            def __enter__(self) -> Any:
                return connection.__enter__()

            def __exit__(self, *args: Any) -> Any:
                connection.__exit__(*args)  # Real PostgreSQL COMMIT first.
                if args[0] is None and owner.inside_commit and owner.lose_next_commit:
                    owner.lose_next_commit = False
                    raise psycopg.OperationalError("simulated lost acknowledgement after COMMIT")
                return None

        return Context()

    def commit(self, changes: list[Incident], checkpoint: Checkpoint) -> None:
        self.inside_commit = True
        try:
            super().commit(changes, checkpoint)
        finally:
            self.inside_commit = False


class TransactionBoundaryStore(PostgresStore):
    """Integration-only faults inside the real transaction, never runtime configuration."""

    boundary: str | None = None

    def _write_incidents(self, conn: Any, changes: list[Incident]) -> None:
        super()._write_incidents(conn, changes)
        if self.boundary == "after_incidents":
            raise psycopg.OperationalError("integration fault after incident SQL")

    def _write_checkpoint(self, conn: Any, checkpoint: Checkpoint) -> None:
        super()._write_checkpoint(conn, checkpoint)
        if self.boundary == "after_checkpoint":
            raise psycopg.OperationalError("integration fault after checkpoint SQL")


def prove_case(store: LostAcknowledgementStore, next_observation: str) -> dict[str, Any]:
    node = "ack-probe-" + uuid4().hex[:12]
    boot, session = uuid4(), uuid4()
    now, sequence = datetime.now(UTC), 0
    state = State({node: SecretStr("x" * 40)}, ("/", PATH), lambda: now, store, DiskConfig())

    def sample(usage: int) -> Sample:
        nonlocal now, sequence
        now += timedelta(seconds=5)
        sequence += 1
        filesystems = [
            from_statvfs(
                path,
                dict(
                    f_blocks=1000,
                    f_bfree=1000 - used * 10,
                    f_bavail=1000 - used * 10,
                    f_frsize=4096,
                    f_files=1000,
                    f_ffree=900,
                ),
            )
            for path, used in (("/", 10), (PATH, usage))
        ]
        return make_sample(node, boot, session, sequence, filesystems).model_copy(
            update={"observed_at": now}
        )

    def send(usage: int) -> None:
        assert state.accept(sample(usage)) == "accepted"

    def lost_ack(value: Sample) -> None:
        previous = state.latest[node]
        store.lose_next_commit = True
        try:
            state.accept(value)
        except StoreError:
            pass
        else:
            raise AssertionError("lost COMMIT acknowledgement was accepted")
        assert state.latest[node] == previous and not store.lose_next_commit

    try:
        send(98)
        send(98)
        opening_sample = sample(98)
        lost_ack(opening_sample)
        opening = store.query(node, None, "active", None, None, 100, 0)[0][0]
        assert state.view(node)["active_incident_count"] == 1
        now += timedelta(seconds=1)
        low_count = 0
        if next_observation == "same":
            assert state.accept(opening_sample) == "duplicate"
        else:
            send(80)
            low_count = 1
            assert state.accept(opening_sample) == "duplicate"
        reconciled = store.get(opening.id)
        assert reconciled and reconciled.opened_at == opening.opened_at
        assert reconciled.opening_evidence == opening.opening_evidence
        assert reconciled.configuration == opening.configuration
        for _ in range(2 - low_count):
            send(80)
        resolution_sample = sample(80)
        lost_ack(resolution_sample)
        resolved = store.get(opening.id)
        assert resolved and resolved.status == "resolved" and resolved.resolved_at
        assert state.view(node)["active_incident_count"] == 0
        now += timedelta(seconds=1)
        assert state.accept(resolution_sample) == "duplicate"
        retried = store.get(opening.id)
        assert retried and retried.resolved_at == resolved.resolved_at
        assert retried.opening_evidence == opening.opening_evidence
        for _ in range(3):
            send(98)
        recurrence = store.query(node, None, "active", None, None, 100, 0)[0][0]
        assert recurrence.id != opening.id
        assert store.query(node, None, None, None, None, 100, 0)[1] == 2
        return dict(
            next_observation=next_observation,
            opening_id=str(opening.id),
            recurrence_id=str(recurrence.id),
            original_resolution_preserved=True,
            latest_not_advanced_on_failed_ack=True,
            committed_counts_correct=True,
        )
    finally:
        # Remove only this uniquely named fixture, in the disposable test DB.
        with psycopg.connect(store.dsn) as connection:
            connection.execute("DELETE FROM incidents WHERE node_id=%s", (node,))
            connection.execute("DELETE FROM ingestion_checkpoints WHERE node_id=%s", (node,))


def prove_rollbacks() -> list[dict[str, Any]]:
    results = []
    for boundary in ("after_incidents", "after_checkpoint"):
        store = TransactionBoundaryStore.environment()
        assert isinstance(store, TransactionBoundaryStore)
        node = "rollback-" + uuid4().hex[:12]
        now = datetime.now(UTC)
        state = State(
            {node: SecretStr("x" * 40)},
            ("/", PATH),
            constant_clock(now),
            store,
            DiskConfig(consecutive_samples=1),
        )
        value = make_sample(
            node,
            uuid4(),
            uuid4(),
            2**64 - 1,
            [
                from_statvfs(
                    path,
                    dict(
                        f_blocks=1000,
                        f_bfree=1000 - used * 10,
                        f_bavail=1000 - used * 10,
                        f_frsize=4096,
                        f_files=1000,
                        f_ffree=900,
                    ),
                )
                for path, used in (("/", 10), (PATH, 98))
            ],
        ).model_copy(update={"observed_at": now})
        store.boundary = boundary
        try:
            state.accept(value)
        except StoreError:
            pass
        else:
            raise AssertionError(f"{boundary} fault unexpectedly committed")
        finally:
            store.boundary = None
        snapshot = store.snapshot({node})
        assert snapshot.active == [] and snapshot.checkpoints == {}
        assert store.query(node, None, None, None, None, 100, 0)[1] == 0
        results.append(
            {
                "boundary": boundary,
                "incident_rolled_back": True,
                "checkpoint_rolled_back": True,
                "sequence": str(value.sequence),
            }
        )
        with psycopg.connect(store.dsn) as connection:
            connection.execute("DELETE FROM incidents WHERE node_id=%s", (node,))
            connection.execute("DELETE FROM ingestion_checkpoints WHERE node_id=%s", (node,))
    return results


def prove_uint64_jsonb() -> dict[str, Any]:
    store = PostgresStore.environment()
    node = "uint64-" + uuid4().hex[:12]
    now = datetime.now(UTC)
    base = make_sample(
        node,
        uuid4(),
        uuid4(),
        2**64 - 1,
        [
            from_statvfs(
                path,
                dict(
                    f_blocks=1000,
                    f_bfree=900,
                    f_bavail=900,
                    f_frsize=4096,
                    f_files=1000,
                    f_ffree=900,
                ),
            )
            for path in ("/", PATH)
        ],
    )
    data = base.model_dump(mode="json")
    data["units"] = dict(reversed(list(data["units"].items())))
    data["observed_at"] = now.astimezone(timezone(timedelta(hours=-4))).isoformat()
    value = Sample.model_validate(data)
    state = State({node: SecretStr("x" * 40)}, ("/", PATH), lambda: now, store, DiskConfig())
    try:
        assert state.accept(value) == "accepted"
        checkpoint = store.snapshot({node}).checkpoints[node]
        assert checkpoint.latest.sequence == 2**64 - 1
        assert checkpoint.fingerprints[-1].fingerprint == sample_fingerprint(value)
        with psycopg.connect(store.dsn) as connection:
            row = connection.execute(
                "SELECT revision,record FROM ingestion_checkpoints WHERE node_id=%s", (node,)
            ).fetchone()
        assert row and int(row[0]) == 1
        assert row[1]["latest"]["sequence"] == 2**64 - 1
        now += timedelta(seconds=20)
        restarted = State(
            {node: SecretStr("x" * 40)}, ("/", PATH), lambda: now, store, DiskConfig()
        )
        assert restarted.accept(value) == "duplicate"
        return {
            "sequence": str(checkpoint.latest.sequence),
            "jsonb_roundtrip": True,
            "canonical_fingerprint": checkpoint.fingerprints[-1].fingerprint,
            "expired_restart_retry": "duplicate",
        }
    finally:
        with psycopg.connect(store.dsn) as connection:
            connection.execute("DELETE FROM incidents WHERE node_id=%s", (node,))
            connection.execute("DELETE FROM ingestion_checkpoints WHERE node_id=%s", (node,))


def prove_near_limit_checkpoint() -> dict[str, Any]:
    store = PostgresStore.environment()
    node = "near-limit-" + uuid4().hex[:12]
    value = make_sample(
        node,
        uuid4(),
        uuid4(),
        60,
        [
            Filesystem(mountpoint=f"/m{index}", errors=[chr(0x1F600) * 247] * 8)
            for index in range(8)
        ],
        datetime.now(UTC),
    )
    request_bytes = len(value.model_dump_json().encode("utf-8"))
    assert 65_280 < request_bytes <= 65_536
    older = [
        IdentityFingerprint(
            boot_id=UUID(int=index + 1),
            agent_session_id=UUID(int=index + 101),
            sequence=0,
            fingerprint="0" * 64,
        )
        for index in range(59)
    ]
    checkpoint = Checkpoint(
        node_id=node,
        revision=60,
        latest=value,
        fingerprints=[
            *older,
            IdentityFingerprint(
                boot_id=value.boot_id,
                agent_session_id=value.agent_session_id,
                sequence=value.sequence,
                fingerprint=sample_fingerprint(value),
            ),
        ],
        retired_sessions=[
            RetiredSession(boot_id=item.boot_id, agent_session_id=item.agent_session_id)
            for item in older[:8]
        ],
    )
    model_bytes = len(checkpoint.model_dump_json().encode("utf-8"))
    assert 65_536 < model_bytes <= MAX_CHECKPOINT_BYTES
    try:
        store.commit([], checkpoint)
        reloaded = store.snapshot({node}).checkpoints[node]
        assert reloaded == checkpoint
        with psycopg.connect(store.dsn) as connection:
            row = connection.execute(
                "SELECT octet_length(record::text) FROM ingestion_checkpoints WHERE node_id=%s",
                (node,),
            ).fetchone()
        assert row and 65_536 < row[0] <= MAX_CHECKPOINT_BYTES
        return {
            "request_utf8_bytes": request_bytes,
            "checkpoint_model_utf8_bytes": model_bytes,
            "postgres_jsonb_text_utf8_bytes": row[0],
            "fingerprints": len(checkpoint.fingerprints),
            "retired_sessions": len(checkpoint.retired_sessions),
            "reloaded_identically": True,
        }
    finally:
        with psycopg.connect(store.dsn) as connection:
            connection.execute("DELETE FROM ingestion_checkpoints WHERE node_id=%s", (node,))


def prove() -> dict[str, Any]:
    store = LostAcknowledgementStore.environment()
    assert isinstance(store, LostAcknowledgementStore)
    cases = [prove_case(store, option) for option in ("same", "newer_low")]
    return dict(
        status="passed",
        boundary="client error injected after actual PostgreSQL COMMIT; no network packet drop",
        cases=cases,
        rollback_boundaries=prove_rollbacks(),
        uint64_jsonb=prove_uint64_jsonb(),
        near_limit_checkpoint=prove_near_limit_checkpoint(),
    )


if __name__ == "__main__":
    print(json.dumps(prove()))
