import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from fleetdoctor import agent, delivery
from fleetdoctor.agent import make_sample
from fleetdoctor.delivery import DeliveryQueue, acknowledgement, send, uploader
from fleetdoctor.schema import Delivery, Filesystem, Sample

NOW = datetime.now(UTC)
TOKEN = SecretStr("a" * 40)


def sample(sequence: int = 0, now: datetime = NOW) -> Sample:
    return make_sample(
        "node-a", uuid4(), uuid4(), sequence, [Filesystem(mountpoint="/", errors=["fixture"])], now
    )


def ack(status: str = "accepted") -> bytes:
    return json.dumps({"status": status, "durable": False, "incidents_durable": True}).encode()


def test_queue_count_bytes_pinned_and_snapshot_lag() -> None:
    q = DeliveryQueue(max_count=2)
    first = q.enqueue(sample(0), NOW)
    assert first is not None and q.select(NOW) is first
    q.enqueue(sample(1), NOW)
    newest = q.enqueue(sample(2), NOW)
    assert len(q.entries) == 2 and q.inflight is first and q.discard_total == 1
    assert newest and json.loads(newest.body)["delivery"]["discard_total"] == 0
    q.complete(first, "accepted", NOW)
    assert q.entries == [newest]
    # Exact bytes include pinned entries, even while a newer collection arrives.
    assert newest
    bounded = DeliveryQueue(max_bytes=len(newest.body))
    pinned = bounded.enqueue(sample(), NOW)
    assert pinned and bounded.select(NOW) is pinned
    assert bounded.enqueue(sample(1), NOW) is None
    assert bounded.size <= bounded.max_bytes and bounded.discard_total == 1
    bounded.complete(pinned, "retry", NOW)
    assert bounded.enqueue(sample(2), NOW) is not None
    assert bounded.discard_total == 2


@pytest.mark.parametrize(
    "outcome,drops",
    [("accepted", 0), ("duplicate", 0), ("superseded", 1), ("ineligible", 1), ("rejected", 1)],
)
def test_completion_and_expiry(outcome: delivery.Outcome, drops: int) -> None:
    q = DeliveryQueue()
    entry = q.enqueue(sample(), NOW)
    assert entry and q.select(NOW) is entry
    body = entry.body
    q.complete(entry, "retry", NOW)
    assert q.select(NOW) is entry and entry.body is body
    q.complete(entry, outcome, NOW)
    assert q.discard_total == drops and not q.entries
    q.enqueue(sample(), NOW)
    q.prune(NOW + timedelta(seconds=10))
    assert q.entries
    q.prune(NOW + timedelta(seconds=10, microseconds=1))
    assert not q.entries and q.discard_total == drops + 1


def test_newest_success_discards_backlog_and_inflight_expiry_is_safe() -> None:
    q = DeliveryQueue()
    q.enqueue(sample(), NOW)
    latest = q.enqueue(sample(1), NOW)
    assert latest and q.select(NOW) is latest
    q.complete(latest, "duplicate", NOW)
    assert not q.entries and q.discard_total == 1
    pinned = q.enqueue(sample(), NOW)
    assert pinned and q.select(NOW) is pinned
    q.prune(NOW + timedelta(seconds=11))
    assert pinned in q.entries
    q.complete(pinned, "retry", NOW + timedelta(seconds=11))
    assert not q.entries and q.discard_total == 2
    small = DeliveryQueue(max_bytes=1)
    assert small.enqueue(sample(), NOW) is None and small.reasons == {"oversize": 1}
    q.discard_total = delivery.MAX_TOTAL
    q.drop(None, "capacity")
    assert q.discard_total == delivery.MAX_TOTAL


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"<html>",
        b"[]",
        b"{}",
        b'{"status":"ok"}',
        b'{"status":"accepted","durable":0,"incidents_durable":true}',
    ],
)
def test_ack_refuses_generic_success(body: bytes) -> None:
    with pytest.raises(ValueError):
        acknowledgement(body, sample().model_dump_json().encode())


def test_ack_old_collector_and_optional_identity() -> None:
    body = sample().model_dump_json().encode()
    assert acknowledgement(ack(), body) == "accepted"
    value = json.loads(ack())
    data = json.loads(body)
    value["identity"] = {
        k: data[k] for k in ("node_id", "boot_id", "agent_session_id", "sequence", "observed_at")
    }
    assert acknowledgement(json.dumps(value).encode(), body) == "accepted"
    value["identity"]["sequence"] = True
    with pytest.raises(ValueError):
        acknowledgement(json.dumps(value).encode(), body)


@pytest.mark.parametrize(
    "status,result",
    [
        (408, "retry"),
        (429, "retry"),
        (503, "retry"),
        (422, "rejected"),
        (403, "rejected"),
        (409, "rejected"),
        (200, "accepted"),
    ],
)
def test_http_outcomes(status: int, result: str) -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(status, content=ack()))
        ) as client:
            assert await send(client, "http://fixture", TOKEN, b"{}") == result

    asyncio.run(scenario())


def test_response_size_limit() -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 16385))
        ) as client:
            with pytest.raises(ValueError, match="too large"):
                await send(client, "http://fixture", TOKEN, b"{}")

    asyncio.run(scenario())


def deeply_nested_ack() -> bytes:
    body = (
        b'{"status":'
        + b"[" * 7000
        + b"0"
        + b"]" * 7000
        + b',"durable":false,"incidents_durable":true}'
    )
    assert len(body) == 14053 and len(body) <= delivery.MAX_RESPONSE
    return body


def test_deep_ack_keeps_actual_uploader_alive_and_retries_same_batch() -> None:
    async def scenario() -> None:
        q = DeliveryQueue()
        now = datetime.now(UTC)
        entry = q.enqueue(sample(now=now), now)
        assert entry is not None
        original = entry.body
        attempts: list[bytes] = []
        times: list[float] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(request.content)
            times.append(time.monotonic())
            assert q.entries == [entry] and q.inflight is entry and q.discard_total == 0
            assert request.content == original and entry.body is original
            return httpx.Response(200, content=deeply_nested_ack() if len(attempts) == 1 else ack())

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            task = asyncio.create_task(uploader(q, client, "http://fixture", TOKEN))
            try:

                async def recovered() -> None:
                    while q.entries:
                        if task.done():
                            await task
                            raise AssertionError("uploader terminated before acknowledgement")
                        await asyncio.sleep(0.01)

                await asyncio.wait_for(recovered(), timeout=4)
                assert not task.done()
                assert attempts == [original, original]
                assert times[1] - times[0] >= delivery.BACKOFF[0]
                assert q.inflight is None and q.discard_total == 0 and q.size == 0
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    asyncio.run(scenario())


def test_once_deep_ack_returns_after_one_actual_request(monkeypatch: pytest.MonkeyPatch) -> None:
    original_client = httpx.AsyncClient
    attempts: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.content)
        return httpx.Response(200, content=deeply_nested_ack())

    def client_factory(**kwargs: object) -> httpx.AsyncClient:
        return original_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    worker = Mock(collect=Mock(return_value=[Filesystem(mountpoint="/", errors=["fixture"])]))

    async def scenario() -> None:
        await asyncio.wait_for(
            agent.collect_loop(
                "node-a",
                uuid4(),
                uuid4(),
                worker,
                "http://fixture",
                TOKEN,
                ("/",),
                True,
                asyncio.Event(),
            ),
            timeout=3,
        )

    asyncio.run(scenario())
    assert len(attempts) == 1 and worker.collect.call_count == 1
    sent = Sample.model_validate_json(attempts[0])
    assert sent.sequence == 0 and sent.delivery is not None and sent.delivery.discard_total == 0


def test_backoff_immutable_retry_and_newest_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(delivery, "BACKOFF", (0.08, 0.12, 0.16, 0.2))

    async def scenario() -> None:
        q = DeliveryQueue()
        q.enqueue(sample(now=datetime.now(UTC)), datetime.now(UTC))
        times: list[float] = []
        bodies: list[bytes] = []
        complete = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            times.append(time.monotonic())
            bodies.append(request.content)
            if len(times) == 2:
                q.enqueue(sample(1, datetime.now(UTC)), datetime.now(UTC))
            if len(times) == 5:
                complete.set()
                return httpx.Response(200, content=ack())
            return httpx.Response(503)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            task = asyncio.create_task(uploader(q, client, "http://fixture", TOKEN))
            try:
                await asyncio.wait_for(complete.wait(), 2)
                await asyncio.sleep(0.01)
                assert bodies[0] == bodies[1] and bodies[2] == bodies[3] == bodies[4]
                assert all(
                    b - a >= expected
                    for a, b, expected in zip(
                        times, times[1:], (0.08, 0.12, 0.16, 0.2), strict=False
                    )
                )
                assert q.discard_total == 1 and not q.entries
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    asyncio.run(scenario())


def test_early_timer_wakeup_cannot_bypass_retry_deadline_or_newest_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        q = DeliveryQueue()
        now = datetime.now(UTC)
        first = q.enqueue(sample(now=now), now)
        assert first is not None
        clock = 10.0
        waits: list[float] = []
        attempts: list[tuple[float, bytes]] = []
        active = 0
        maximum = 0

        async def early_sleep(delay: float) -> None:
            nonlocal clock
            waits.append(delay)
            if len(waits) == 1:
                clock += delay - 0.015  # Reproduce an early Windows timer wakeup.
                created = datetime.now(UTC)
                q.enqueue(sample(1, created), created)
            else:
                clock += delay
            await asyncio.sleep(0)

        monkeypatch.setattr(
            delivery,
            "time",
            SimpleNamespace(
                monotonic=lambda: clock,
                get_clock_info=time.get_clock_info,
            ),
        )
        monkeypatch.setattr(
            delivery,
            "asyncio",
            SimpleNamespace(
                sleep=early_sleep,
                wait_for=asyncio.wait_for,
                CancelledError=asyncio.CancelledError,
            ),
        )

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            attempts.append((clock, request.content))
            try:
                assert q.inflight is not None and q.inflight.body == request.content
                await asyncio.sleep(0)
                if len(attempts) == 1:
                    return httpx.Response(503)
                assert clock >= 11.0, "retry sent before its original monotonic deadline"
                assert json.loads(request.content)["sequence"] == 1
                return httpx.Response(200, content=ack())
            finally:
                active -= 1

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            task = asyncio.create_task(uploader(q, client, "http://fixture", TOKEN))
            try:

                async def recovered() -> None:
                    while q.entries:
                        if task.done():
                            await task
                            raise AssertionError("uploader terminated before recovery")
                        await asyncio.sleep(0)

                await asyncio.wait_for(recovered(), timeout=2)
                assert not task.done() and len(attempts) == 2
                assert attempts[0] == (10.0, first.body) and attempts[1][0] >= 11.0
                assert len(waits) == 2 and all(delay >= 0.02 for delay in waits)
                assert q.inflight is None and q.discard_total == 1
                assert maximum == 1 and active == 0
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    asyncio.run(scenario())


def test_collection_independent_of_stalled_upload_and_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent, "next_tick", lambda scheduled, now: scheduled + 0.08)
    worker = Mock()
    ticks: list[float] = []

    def collect(paths: tuple[str, ...]) -> list[Filesystem]:
        ticks.append(time.monotonic())
        time.sleep(0.02)
        return [Filesystem(mountpoint="/", errors=["fixture"])]

    worker.collect.side_effect = collect
    active = 0
    maximum = 0
    upload_started = asyncio.Event()

    async def stalled(
        client: httpx.AsyncClient, url: str, token: SecretStr, body: bytes
    ) -> delivery.Outcome:
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        upload_started.set()
        try:
            await asyncio.sleep(10)
            return "retry"
        finally:
            active -= 1

    monkeypatch.setattr(delivery, "send", stalled)

    async def scenario() -> None:
        task = asyncio.create_task(
            agent.collect_loop(
                "node-a",
                uuid4(),
                uuid4(),
                worker,
                "http://fixture",
                TOKEN,
                ("/",),
                False,
                asyncio.Event(),
            )
        )
        try:
            await asyncio.wait_for(upload_started.wait(), timeout=2)
            assert ticks and active == 1
            collected_at_start = len(ticks)
            await asyncio.sleep(0.36)
            assert len(ticks) >= collected_at_start + 4
            assert not task.done() and active == 1 and maximum == 1
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert len(ticks) >= 4 and maximum == 1 and active == 0
        assert all(0.05 < b - a < 0.13 for a, b in zip(ticks, ticks[1:], strict=False))

    asyncio.run(scenario())


def test_once_is_one_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def fail(
        client: httpx.AsyncClient, url: str, token: SecretStr, body: bytes
    ) -> delivery.Outcome:
        nonlocal calls
        calls += 1
        return "retry"

    monkeypatch.setattr(agent, "send", fail)
    worker = Mock(collect=Mock(return_value=[Filesystem(mountpoint="/", errors=["fixture"])]))
    asyncio.run(
        agent.collect_loop(
            "node-a",
            uuid4(),
            uuid4(),
            worker,
            "http://fixture",
            TOKEN,
            ("/",),
            True,
            asyncio.Event(),
        )
    )
    assert calls == 1 and worker.collect.call_count == 1


@pytest.mark.parametrize("bad", [-1, True, "1", 2**64])
def test_delivery_strict_bounds(bad: object) -> None:
    with pytest.raises(ValidationError):
        Delivery.model_validate({"discard_total": bad})
