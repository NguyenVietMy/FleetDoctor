"""Bounded durable ordering metadata for collector ingestion."""

import hashlib
import json
from datetime import UTC
from typing import Annotated, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fleetdoctor.schema import Count, Sample

MAX_FINGERPRINTS = 60
MAX_RETIRED_SESSIONS = 8
# The checkpoint contains the complete bounded request plus retention metadata.
# 128 KiB covers a 64 KiB request, 60 fingerprints, 8 retired sessions and
# JSON escaping overhead while retaining a simple hard storage bound.
MAX_CHECKPOINT_BYTES = 131_072
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def canonical_sample_bytes(sample: Sample) -> bytes:
    """Serialize typed sample data independently of JSON/JSONB object key order."""
    normalized = sample.model_copy(update={"observed_at": sample.observed_at.astimezone(UTC)})
    return json.dumps(
        normalized.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sample_fingerprint(sample: Sample) -> str:
    return hashlib.sha256(canonical_sample_bytes(sample)).hexdigest()


class IdentityFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    boot_id: UUID
    agent_session_id: UUID
    sequence: Count
    fingerprint: Sha256

    @property
    def key(self) -> tuple[str, str, int]:
        return str(self.boot_id), str(self.agent_session_id), self.sequence


class RetiredSession(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    boot_id: UUID
    agent_session_id: UUID

    @property
    def key(self) -> tuple[str, str]:
        return str(self.boot_id), str(self.agent_session_id)


class Checkpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    revision: Count
    latest: Sample
    fingerprints: list[IdentityFingerprint] = Field(max_length=MAX_FINGERPRINTS)
    retired_sessions: list[RetiredSession] = Field(max_length=MAX_RETIRED_SESSIONS)

    @model_validator(mode="after")
    def consistent_and_bounded(self) -> Self:
        if self.latest.node_id != self.node_id:
            raise ValueError("checkpoint node does not match latest sample")
        fingerprint_keys = [item.key for item in self.fingerprints]
        if len(set(fingerprint_keys)) != len(fingerprint_keys):
            raise ValueError("checkpoint contains duplicate fingerprint identities")
        if self.revision < 1 or self.revision < len(self.fingerprints):
            raise ValueError("checkpoint revision is inconsistent with retained identities")
        latest_key = (
            str(self.latest.boot_id),
            str(self.latest.agent_session_id),
            self.latest.sequence,
        )
        if not self.fingerprints or self.fingerprints[-1].key != latest_key:
            raise ValueError("checkpoint latest identity is not the retained high-water mark")
        if self.fingerprints[-1].fingerprint != sample_fingerprint(self.latest):
            raise ValueError("checkpoint latest fingerprint does not match latest sample")
        retired_keys = [item.key for item in self.retired_sessions]
        if len(set(retired_keys)) != len(retired_keys):
            raise ValueError("checkpoint contains duplicate retired sessions")
        if latest_key[:2] in retired_keys:
            raise ValueError("checkpoint latest session is retired")
        if len(self.model_dump_json().encode("utf-8")) > MAX_CHECKPOINT_BYTES:
            raise ValueError("checkpoint exceeds storage bound")
        return self
