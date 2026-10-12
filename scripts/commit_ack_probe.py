"""Real PostgreSQL commits with a client-side lost-acknowledgement fault.

Run inside the disposable integration collector. This simulates the connection
error after a real commit; it does not claim to drop an actual network packet.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import psycopg
from pydantic import SecretStr

from fleetdoctor.agent import make_sample
from fleetdoctor.collection import from_statvfs
from fleetdoctor.collector import State
from fleetdoctor.incidents import DiskConfig, Incident
from fleetdoctor.schema import Sample
from fleetdoctor.store import PostgresStore, StoreError

PATH = "/var/lib/fleetdoctor/chaos/disk"


class LostAcknowledgementStore(PostgresStore):
    inside_apply = False
    lose_next_commit = False

    def connect(self) -> Any:
        connection = super().connect()
        owner = self

        class Context:
            def __enter__(self) -> Any:
                return connection.__enter__()

            def __exit__(self, *args: Any) -> Any:
                connection.__exit__(*args)  # Real PostgreSQL COMMIT first.
                if args[0] is None and owner.inside_apply and owner.lose_next_commit:
                    owner.lose_next_commit = False
                    raise psycopg.OperationalError("simulated lost acknowledgement after COMMIT")
                return None

        return Context()

    def apply(self, changes: list[Incident]) -> None:
        self.inside_apply = bool(changes)
        try:
            super().apply(changes)
        finally:
            self.inside_apply = False


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
            assert state.accept(opening_sample) == "accepted"
            assert state.accept(opening_sample) == "duplicate"
        else:
            send(80)
            low_count = 1
            assert state.accept(opening_sample) == "superseded"
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
        assert state.accept(resolution_sample) == "accepted"
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


def prove() -> dict[str, Any]:
    store = LostAcknowledgementStore.environment()
    assert isinstance(store, LostAcknowledgementStore)
    cases = [prove_case(store, option) for option in ("same", "newer_low")]
    return dict(
        status="passed",
        boundary="client error injected after actual PostgreSQL COMMIT; no network packet drop",
        cases=cases,
    )


if __name__ == "__main__":
    print(json.dumps(prove()))
