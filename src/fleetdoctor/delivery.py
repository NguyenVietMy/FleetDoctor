"""Process-local bounded delivery. Queue operations contain no awaits."""

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

import httpx
from pydantic import SecretStr

from fleetdoctor.schema import Delivery, Sample

LOG = logging.getLogger(__name__)
Outcome = Literal["accepted", "duplicate", "superseded", "ineligible", "rejected", "retry"]
MAX_COUNT = 60
MAX_BYTES = 2_000_000
MAX_BODY = 65_536
MAX_RESPONSE = 16_384
MAX_TOTAL = 2**64 - 1
BACKOFF = (1, 2, 4, 5)


@dataclass(frozen=True)
class Batch:
    ordinal: int
    body: bytes
    observed_at: datetime


class DeliveryQueue:
    def __init__(self, max_count: int = MAX_COUNT, max_bytes: int = MAX_BYTES) -> None:
        if max_count < 1 or max_bytes < 1:
            raise ValueError("positive queue bounds required")
        self.max_count, self.max_bytes = max_count, max_bytes
        self.entries: list[Batch] = []
        self.inflight: Batch | None = None
        self.discard_total = 0
        self.reasons: dict[str, int] = {}
        self.ordinal = 0
        self.changed = asyncio.Event()

    @property
    def size(self) -> int:
        return sum(len(entry.body) for entry in self.entries)

    def drop(self, entry: Batch | None, reason: str) -> None:
        if entry is not None:
            self.entries.remove(entry)
        self.discard_total = min(MAX_TOTAL, self.discard_total + 1)
        self.reasons[reason] = min(MAX_TOTAL, self.reasons.get(reason, 0) + 1)

    def prune(self, now: datetime) -> None:
        for entry in self.entries[:]:
            if entry is not self.inflight and (now - entry.observed_at).total_seconds() > 10:
                self.drop(entry, "expired")

    def enqueue(self, sample: Sample, now: datetime) -> Batch | None:
        self.prune(now)
        snapshot = sample.model_copy(
            update={"delivery": Delivery(discard_total=self.discard_total)}
        )
        body = snapshot.model_dump_json().encode("utf-8")
        if len(body) > MAX_BODY or len(body) > self.max_bytes:
            self.drop(None, "oversize")
            return None
        while len(self.entries) >= self.max_count or self.size + len(body) > self.max_bytes:
            victim = next((e for e in self.entries if e is not self.inflight), None)
            if victim is None:
                self.drop(None, "capacity")
                return None
            self.drop(victim, "capacity")
        entry = Batch(self.ordinal, body, sample.observed_at)
        self.ordinal += 1
        self.entries.append(entry)
        self.changed.set()
        return entry

    def select(self, now: datetime) -> Batch | None:
        self.prune(now)
        if self.inflight is not None:
            raise RuntimeError("one upload already in flight")
        self.inflight = self.entries[-1] if self.entries else None
        return self.inflight

    def complete(self, entry: Batch, outcome: Outcome, now: datetime) -> None:
        if self.inflight is not entry:
            raise RuntimeError("completion must match attempted batch")
        self.inflight = None
        if outcome in ("accepted", "duplicate"):
            self.entries.remove(entry)
            for older in self.entries[:]:
                if older.ordinal < entry.ordinal:
                    self.drop(older, "superseded")
        elif outcome != "retry":
            self.drop(entry, outcome)
        self.prune(now)


def acknowledgement(body: bytes, sent: bytes) -> Outcome:
    try:
        value = json.loads(body)
    except RecursionError as exc:
        raise ValueError("ingest acknowledgement nesting exceeds parser limit") from exc
    if not isinstance(value, dict) or set(value) - {
        "status",
        "durable",
        "incidents_durable",
        "identity",
    }:
        raise ValueError("invalid acknowledgement shape")
    status = value.get("status")
    if status not in ("accepted", "duplicate", "superseded", "ineligible"):
        raise ValueError("unknown acknowledgement status")
    if value.get("durable") is not False or value.get("incidents_durable") is not True:
        raise ValueError("invalid durability acknowledgement")
    if "identity" in value:
        sample = json.loads(sent)
        expected = {
            k: sample[k]
            for k in ("node_id", "boot_id", "agent_session_id", "sequence", "observed_at")
        }
        identity = value["identity"]
        if (
            not isinstance(identity, dict)
            or identity != expected
            or type(identity.get("sequence")) is not int
        ):
            raise ValueError("acknowledgement identity mismatch")
    return status  # type: ignore[no-any-return]


async def send(
    client: httpx.AsyncClient, url: str, token: SecretStr, body: bytes, deadline: float = 2
) -> Outcome:
    async def request() -> Outcome:
        async with client.stream(
            "POST",
            url + "/ingest",
            content=body,
            headers={
                "Authorization": "Bearer " + token.get_secret_value(),
                "Content-Type": "application/json",
            },
        ) as response:
            if response.status_code in (408, 429) or response.status_code >= 500:
                return "retry"
            if 400 <= response.status_code < 500:
                LOG.warning("terminal ingest HTTP rejection: %d", response.status_code)
                return "rejected"
            if not 200 <= response.status_code < 300:
                raise ValueError("unexpected ingest HTTP status")
            content = bytearray()
            async for chunk in response.aiter_bytes():
                if len(content) + len(chunk) > MAX_RESPONSE:
                    raise ValueError("ingest response too large")
                content.extend(chunk)
            return acknowledgement(bytes(content), body)

    return await asyncio.wait_for(request(), timeout=deadline)


async def uploader(
    queue: DeliveryQueue, client: httpx.AsyncClient, url: str, token: SecretStr
) -> None:
    failures = 0
    retry_at = 0.0
    minimum_wait = max(0.02, 2 * time.get_clock_info("monotonic").resolution)
    while True:
        # Enqueue can wake an idle uploader, never shorten a transport retry deadline.
        # Timers may wake early. Recheck the deadline and yield beyond clock
        # resolution rather than repeatedly scheduling near-zero waits.
        while (delay := retry_at - time.monotonic()) > 0:
            await asyncio.sleep(max(delay, minimum_wait))
        queue.changed.clear()
        entry = queue.select(datetime.now(UTC))
        if entry is None:
            await queue.changed.wait()
            continue
        try:
            result = await send(client, url, token, entry.body)
        except (httpx.HTTPError, TimeoutError, ValueError) as exc:
            LOG.warning("upload failed: %s", type(exc).__name__)
            result = "retry"
        except asyncio.CancelledError:
            queue.complete(entry, "retry", datetime.now(UTC))
            raise
        queue.complete(entry, result, datetime.now(UTC))
        if result == "retry":
            retry_at = time.monotonic() + BACKOFF[min(failures, len(BACKOFF) - 1)]
            failures = min(failures + 1, len(BACKOFF))
        else:
            failures = 0
            retry_at = 0
