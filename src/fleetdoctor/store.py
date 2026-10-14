"""Required incident storage; fixtures must explicitly inject FixtureStore."""

import os
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from threading import BoundedSemaphore
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from pydantic import ValidationError

from fleetdoctor.checkpoint import MAX_CHECKPOINT_BYTES, Checkpoint
from fleetdoctor.incidents import Incident

if TYPE_CHECKING:
    from psycopg import Connection


class StoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class StoreSnapshot:
    active: list[Incident]
    checkpoints: dict[str, Checkpoint]


class IncidentStore(Protocol):
    def apply(self, changes: list[Incident]) -> None: ...
    def commit(self, changes: list[Incident], checkpoint: Checkpoint) -> None: ...
    def snapshot(self, nodes: set[str]) -> StoreSnapshot: ...
    def active(self) -> list[Incident]: ...
    def health(self) -> bool: ...
    def get(self, identifier: UUID) -> Incident | None: ...
    def query(
        self,
        node: str | None,
        rule: str | None,
        status: str | None,
        start: datetime | None,
        end: datetime | None,
        limit: int,
        offset: int,
    ) -> tuple[list[Incident], int]: ...


class FixtureStore:
    """Explicit fixture dependency, never selected by environment or DB failure."""

    def __init__(self) -> None:
        self.records: dict[UUID, Incident] = {}
        self.checkpoints: dict[str, Checkpoint | dict[str, Any]] = {}
        self.fail = False
        self.fail_after_incidents = False
        self.fail_after_checkpoint = False

    def apply(self, changes: list[Incident]) -> None:
        if self.fail:
            raise StoreError("fixture failure")
        for incident in changes:
            self.records[incident.id] = incident.model_copy(deep=True)

    def commit(self, changes: list[Incident], checkpoint: Checkpoint) -> None:
        if self.fail:
            raise StoreError("fixture failure")
        records = deepcopy(self.records)
        checkpoints = deepcopy(self.checkpoints)
        for incident in changes:
            records[incident.id] = incident.model_copy(deep=True)
        if self.fail_after_incidents:
            raise StoreError("fixture failure after_incidents")
        checkpoints[checkpoint.node_id] = checkpoint.model_copy(deep=True)
        if self.fail_after_checkpoint:
            raise StoreError("fixture failure after_checkpoint")
        self.records, self.checkpoints = records, checkpoints

    def snapshot(self, nodes: set[str]) -> StoreSnapshot:
        if self.fail:
            raise StoreError("fixture failure")
        try:
            checkpoints = {
                node: Checkpoint.model_validate(deepcopy(value))
                for node, value in self.checkpoints.items()
                if node in nodes
            }
        except ValidationError as exc:
            raise StoreError("invalid stored checkpoint") from exc
        active = [
            incident.model_copy(deep=True)
            for incident in self.records.values()
            if incident.status == "active" and incident.node_id in nodes
        ]
        return StoreSnapshot(active=active, checkpoints=checkpoints)

    def active(self) -> list[Incident]:
        return self.query(None, None, "active", None, None, 100000, 0)[0]

    def health(self) -> bool:
        return not self.fail

    def get(self, identifier: UUID) -> Incident | None:
        self.apply([])
        record = self.records.get(identifier)
        return record.model_copy(deep=True) if record else None

    def query(
        self,
        node: str | None,
        rule: str | None,
        status: str | None,
        start: datetime | None,
        end: datetime | None,
        limit: int,
        offset: int,
    ) -> tuple[list[Incident], int]:
        self.apply([])
        rows = sorted(
            (
                i
                for i in self.records.values()
                if (node is None or i.node_id == node)
                and (rule is None or i.rule == rule)
                and (status is None or i.status == status)
                and (start is None or i.opened_at >= start)
                and (end is None or i.opened_at <= end)
            ),
            key=lambda i: (i.opened_at, str(i.id)),
            reverse=True,
        )
        return [i.model_copy(deep=True) for i in rows[offset : offset + limit]], len(rows)


DDL = f"""
CREATE TABLE IF NOT EXISTS incidents (
    id uuid PRIMARY KEY, node_id text NOT NULL, resource text NOT NULL,
    rule text NOT NULL, status text NOT NULL CHECK (status IN ('active','resolved')),
    severity text NOT NULL, opened_at timestamptz NOT NULL, observed_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL, resolved_at timestamptz, record jsonb NOT NULL
);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence_reloaded boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS incident_one_active ON incidents(node_id,rule,resource)
    WHERE status='active';
CREATE INDEX IF NOT EXISTS incident_opened ON incidents(opened_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS ingestion_checkpoints (
    node_id text PRIMARY KEY,
    revision numeric(20,0) NOT NULL,
    updated_at timestamptz NOT NULL,
    record jsonb NOT NULL,
    CONSTRAINT ingestion_checkpoint_revision
        CHECK (revision >= 1 AND revision <= 18446744073709551615),
    CONSTRAINT ingestion_checkpoint_record_size
        CHECK (octet_length(record::text) <= {MAX_CHECKPOINT_BYTES})
);
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='ingestion_checkpoint_revision'
          AND conrelid='ingestion_checkpoints'::regclass
    ) THEN
        ALTER TABLE ingestion_checkpoints
            ADD CONSTRAINT ingestion_checkpoint_revision
            CHECK (revision >= 1 AND revision <= 18446744073709551615);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='ingestion_checkpoint_record_size'
          AND conrelid='ingestion_checkpoints'::regclass
    ) THEN
        ALTER TABLE ingestion_checkpoints
            ADD CONSTRAINT ingestion_checkpoint_record_size
            CHECK (octet_length(record::text) <= {MAX_CHECKPOINT_BYTES});
    END IF;
END $$;
"""


class PostgresStore:
    def __init__(self, dsn: str, reader_password: str) -> None:
        import psycopg
        from psycopg import sql

        if len(reader_password) < 32:
            raise ValueError(
                "configure a private Grafana database password of at least 32 characters"
            )
        self.dsn = dsn
        self.slots = BoundedSemaphore(4)
        try:
            with self.connect() as conn:
                conn.execute(DDL)
                conn.execute("UPDATE incidents SET evidence_reloaded=true WHERE status='active'")
                conn.execute(
                    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='fleetdoctor_reader') THEN CREATE ROLE fleetdoctor_reader LOGIN; END IF; END $$"
                )
                conn.execute(
                    sql.SQL(
                        "ALTER ROLE fleetdoctor_reader WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION PASSWORD {}"
                    ).format(sql.Literal(reader_password))
                )
                conn.execute("ALTER ROLE fleetdoctor_reader SET default_transaction_read_only = on")
                conn.execute("ALTER ROLE fleetdoctor_reader SET statement_timeout = '2s'")
                conn.execute("ALTER ROLE fleetdoctor_reader SET lock_timeout = '1s'")
                conn.execute("GRANT CONNECT ON DATABASE fleetdoctor TO fleetdoctor_reader")
                conn.execute("GRANT USAGE ON SCHEMA public TO fleetdoctor_reader")
                conn.execute("GRANT SELECT ON incidents TO fleetdoctor_reader")
                conn.execute("REVOKE ALL ON ingestion_checkpoints FROM PUBLIC")
                conn.execute("REVOKE ALL ON ingestion_checkpoints FROM fleetdoctor_reader")
        except psycopg.Error as exc:
            raise StoreError("incident storage initialization failed") from exc

    def connect(self) -> "Connection[Any]":
        import psycopg

        return psycopg.connect(
            self.dsn, connect_timeout=2, options="-c statement_timeout=2000 -c lock_timeout=1000"
        )

    @classmethod
    def environment(cls) -> "PostgresStore":
        from psycopg.conninfo import make_conninfo

        return cls(
            make_conninfo(
                host=os.getenv("PGHOST", "postgres"),
                dbname="fleetdoctor",
                user="fleetdoctor",
                password=os.environ["POSTGRES_PASSWORD"],
            ),
            os.environ["GRAFANA_DB_PASSWORD"],
        )

    def apply(self, changes: list[Incident]) -> None:
        import psycopg

        if not self.slots.acquire(timeout=2):
            raise StoreError("incident storage busy")
        try:
            # Connection context commits on successful exit, before State publishes memory.
            with self.connect() as conn:
                conn.execute("SELECT id FROM incidents LIMIT 0")
                self._write_incidents(conn, changes)
        except psycopg.Error as exc:
            raise StoreError("incident storage write unavailable") from exc
        finally:
            self.slots.release()

    def _write_incidents(self, conn: "Connection[Any]", changes: list[Incident]) -> None:
        from psycopg.types.json import Jsonb

        for i in changes:
            conn.execute(
                """INSERT INTO incidents(id,node_id,resource,rule,status,severity,opened_at,observed_at,updated_at,resolved_at,record)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,
                observed_at=EXCLUDED.observed_at, updated_at=EXCLUDED.updated_at,
                resolved_at=EXCLUDED.resolved_at, record=EXCLUDED.record, evidence_reloaded=false""",
                (
                    i.id,
                    i.node_id,
                    i.resource,
                    i.rule,
                    i.status,
                    i.severity,
                    i.opened_at,
                    i.observed_at,
                    i.updated_at,
                    i.resolved_at,
                    Jsonb(i.model_dump(mode="json")),
                ),
            )

    def _write_checkpoint(self, conn: "Connection[Any]", checkpoint: Checkpoint) -> None:
        from psycopg.types.json import Jsonb

        conn.execute(
            """INSERT INTO ingestion_checkpoints(node_id,revision,updated_at,record)
            VALUES (%s,%s,%s,%s)
            ON CONFLICT(node_id) DO UPDATE SET revision=EXCLUDED.revision,
            updated_at=EXCLUDED.updated_at, record=EXCLUDED.record""",
            (
                checkpoint.node_id,
                checkpoint.revision,
                checkpoint.latest.observed_at,
                Jsonb(checkpoint.model_dump(mode="json")),
            ),
        )

    def commit(self, changes: list[Incident], checkpoint: Checkpoint) -> None:
        import psycopg

        if not self.slots.acquire(timeout=2):
            raise StoreError("incident storage busy")
        try:
            with self.connect() as conn:
                conn.execute("SET LOCAL synchronous_commit = on")
                self._write_incidents(conn, changes)
                self._write_checkpoint(conn, checkpoint)
        except psycopg.Error as exc:
            raise StoreError("ingestion storage write unavailable") from exc
        finally:
            self.slots.release()

    def snapshot(self, nodes: set[str]) -> StoreSnapshot:
        import psycopg

        if not self.slots.acquire(timeout=2):
            raise StoreError("incident storage busy")
        try:
            with self.connect() as conn:
                conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                active = [
                    Incident.model_validate(row[0])
                    for row in conn.execute(
                        "SELECT record FROM incidents WHERE status='active' AND node_id = ANY(%s)",
                        (sorted(nodes),),
                    )
                ]
                checkpoints = {}
                for node, revision, record in conn.execute(
                    "SELECT node_id,revision,record FROM ingestion_checkpoints WHERE node_id = ANY(%s)",
                    (sorted(nodes),),
                ):
                    checkpoint = Checkpoint.model_validate(record)
                    if checkpoint.node_id != node or checkpoint.revision != int(revision):
                        raise ValueError("checkpoint columns disagree with record")
                    checkpoints[node] = checkpoint
                return StoreSnapshot(active=active, checkpoints=checkpoints)
        except (psycopg.Error, ValidationError, ValueError) as exc:
            raise StoreError("ingestion storage snapshot unavailable") from exc
        finally:
            self.slots.release()

    def health(self) -> bool:
        import psycopg

        if not self.slots.acquire(timeout=2):
            return False
        try:
            with self.connect() as conn:
                conn.execute("SELECT id FROM incidents LIMIT 0")
                conn.execute("SELECT node_id FROM ingestion_checkpoints LIMIT 0")
            return True
        except psycopg.Error:
            return False
        finally:
            self.slots.release()

    def active(self) -> list[Incident]:
        return self._read("SELECT record FROM incidents WHERE status='active'", ())

    def _read(self, statement: str, params: tuple[object, ...]) -> list[Incident]:
        import psycopg

        if not self.slots.acquire(timeout=2):
            raise StoreError("incident storage busy")
        try:
            with self.connect() as conn:
                return [Incident.model_validate(row[0]) for row in conn.execute(statement, params)]
        except psycopg.Error as exc:
            raise StoreError("incident storage read unavailable") from exc
        finally:
            self.slots.release()

    def get(self, identifier: UUID) -> Incident | None:
        rows = self._read("SELECT record FROM incidents WHERE id=%s", (identifier,))
        return rows[0] if rows else None

    def query(
        self,
        node: str | None,
        rule: str | None,
        status: str | None,
        start: datetime | None,
        end: datetime | None,
        limit: int,
        offset: int,
    ) -> tuple[list[Incident], int]:
        import psycopg

        clauses, values = [], []
        for column, value, operator in (
            ("node_id", node, "="),
            ("rule", rule, "="),
            ("status", status, "="),
            ("opened_at", start, ">="),
            ("opened_at", end, "<="),
        ):
            if value is not None:
                clauses.append(f"{column} {operator} %s")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        if not self.slots.acquire(timeout=2):
            raise StoreError("incident storage busy")
        try:
            with self.connect() as conn:
                # One snapshot for total and page, including concurrent ingest.
                conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                count = conn.execute("SELECT count(*) FROM incidents" + where, values).fetchone()
                assert count is not None
                total = count[0]
                rows = conn.execute(
                    "SELECT record FROM incidents"
                    + where
                    + " ORDER BY opened_at DESC,id DESC LIMIT %s OFFSET %s",
                    [*values, limit, offset],
                )
                return [Incident.model_validate(row[0]) for row in rows], int(total)
        except psycopg.Error as exc:
            raise StoreError("incident storage query unavailable") from exc
        finally:
            self.slots.release()
