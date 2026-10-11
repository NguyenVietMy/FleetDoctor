import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from fleetdoctor.agent import make_sample, next_tick, upload
from fleetdoctor.collection import CollectionWorker, from_statvfs
from fleetdoctor.collector import create_app
from fleetdoctor.history import HistoryClient, validate_range
from fleetdoctor.schema import Filesystem, Sample

FIXTURES: dict[str, Any] = json.loads((Path(__file__).parent / "fixtures/statvfs.json").read_text())
NOW = datetime.now(UTC)
TOKENS = {"node-a": SecretStr("a" * 40), "node-b": SecretStr("b" * 40)}


def sample(node: str = "node-a") -> Sample:
    return make_sample(node, uuid4(), uuid4(), 0, [from_statvfs("/", FIXTURES["reserved"])], NOW)


def post(client: TestClient, value: Sample) -> httpx.Response:
    return cast(
        httpx.Response,
        client.post(
            "/ingest",
            content=value.model_dump_json(),
            headers={"Authorization": "Bearer " + TOKENS[value.node_id].get_secret_value()},
        ),
    )


def test_linux_reserved_blocks_and_units() -> None:
    fs = from_statvfs("/", FIXTURES["reserved"])
    assert fs.total_bytes == 4096000 and fs.used_bytes == 2457600
    assert fs.available_bytes == 1433600
    assert fs.block_usage_percent == pytest.approx(600 / 950 * 100)
    assert fs.inode_usage_percent == 30


@pytest.mark.parametrize("fixture", ["zero", "bad_blocks", "no_inodes"])
def test_invalid_capacity_is_unavailable(fixture: str) -> None:
    fs = from_statvfs("/bad", FIXTURES[fixture])
    assert fs.errors
    assert (
        fs.block_usage_percent is None
        if fixture in ("zero", "bad_blocks")
        else fs.inode_usage_percent is None
    )
    if fixture == "no_inodes":
        assert fs.used_bytes == 2457600


def test_bad_filesystem_preserves_good_sibling() -> None:
    s = make_sample(
        "node-a",
        uuid4(),
        uuid4(),
        0,
        [
            from_statvfs("/", FIXTURES["reserved"]),
            Filesystem(mountpoint="/bad", errors=["statvfs_PermissionError"]),
        ],
        NOW,
    )
    app = create_app(TOKENS, ("/", "/bad"), clock=lambda: NOW)
    with TestClient(app) as client:
        assert post(client, s).json()["status"] == "accepted"
        view = client.get("/nodes/node-a/metrics").json()
        assert view["fresh"] and not view["stale"]
        assert view["filesystems"][0]["used_bytes"] == 2457600
        assert view["filesystems"][1]["used_bytes"] is None


@pytest.mark.parametrize(
    "edit",
    [
        {"units": {"space": "kB"}},
        {"schema_version": 2},
        {"sequence": True},
        {"sequence": -1},
        {"observed_at": "2026-10-11T01:00:00"},
    ],
)
def test_wire_rejects_invalid_structure(edit: dict[str, Any]) -> None:
    data = sample().model_dump(mode="json") | edit
    with pytest.raises(ValidationError):
        Sample.model_validate(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("used_bytes", -1),
        ("available_bytes", 9000000),
        ("block_usage_percent", float("nan")),
        ("used_bytes", "123"),
        ("total_bytes", 10**400),
    ],
)
def test_bad_counters_rejected(field: str, value: Any) -> None:
    data = sample().model_dump(mode="json")
    data["filesystems"][0][field] = value
    with pytest.raises(ValidationError):
        Sample.model_validate(data)


def test_identity_authentication_and_payload_caps() -> None:
    with TestClient(create_app(TOKENS, clock=lambda: NOW)) as client:
        value = sample("node-b")
        assert (
            client.post(
                "/ingest",
                content=value.model_dump_json(),
                headers={"Authorization": "Bearer " + "a" * 40},
            ).status_code
            == 403
        )
        assert client.get("/nodes/node-b/metrics").json()["observed_at"] is None
        assert client.post("/ingest", content=value.model_dump_json()).status_code == 403
        assert client.post("/ingest", content="x" * 65537).status_code == 413
        assert client.post("/ingest", content=iter([b"x" * 40000, b"x" * 40000])).status_code == 413
        assert (
            client.post("/ingest", json={"secret": "should_not_be_echoed"}).text.find(
                "should_not_be_echoed"
            )
            < 0
        )
        assert post(client, value).status_code == 200
        assert post(client, sample()).status_code == 200
        assert len(client.get("/nodes").json()["nodes"]) == 2
        assert "a" * 40 not in repr(TOKENS) and "b" * 40 not in client.get("/nodes").text


def test_extreme_counter_cannot_break_prometheus_export() -> None:
    with TestClient(create_app(TOKENS, clock=lambda: NOW)) as client:
        assert post(client, sample()).status_code == 200
        malicious = sample().model_dump(mode="json")
        malicious["filesystems"][0]["total_bytes"] = 10**400
        response = client.post(
            "/ingest", json=malicious, headers={"Authorization": "Bearer " + "a" * 40}
        )
        assert response.status_code == 422
        assert client.get("/metrics").status_code == 200


@pytest.mark.parametrize(
    "age,accepted,fresh,stale",
    [
        (10, True, True, False),
        (10.01, False, False, True),
        (-2, True, True, False),
        (-2.01, False, False, True),
    ],
)
def test_ingestion_freshness_boundaries(
    age: float, accepted: bool, fresh: bool, stale: bool
) -> None:
    value = sample().model_copy(update={"observed_at": NOW - timedelta(seconds=age)})
    with TestClient(create_app(TOKENS, clock=lambda: NOW)) as client:
        assert (post(client, value).json()["status"] == "accepted") is accepted
        view = client.get("/nodes/node-a/metrics").json()
        assert view["fresh"] is fresh and view["stale"] is stale


def test_export_and_latest_expire_before_stale() -> None:
    current = [NOW]
    with TestClient(create_app(TOKENS, clock=lambda: current[0])) as client:
        post(client, sample())
        assert (
            'fleetdoctor_filesystem_available_bytes{filesystem="/",node="node-a"} 1.4336e+06'
            in client.get("/metrics").text
        )
        current[0] += timedelta(seconds=11)
        text = client.get("/metrics").text
        assert 'fleetdoctor_filesystem_available_bytes{filesystem="/",node="node-a"}' not in text
        assert 'fleetdoctor_node_stale{node="node-a"} 0.0' in text
        expired = client.get("/nodes/node-a/metrics").json()
        assert expired["filesystems"] is None
        assert "filesystems" not in expired["sample"]
        assert all(item["available_fields"] == [] for item in expired["coverage"].values())
        assert "1433600" not in client.get("/nodes").text
        current[0] += timedelta(seconds=5)
        assert client.get("/nodes/node-a/metrics").json()["stale"]


def test_duplicate_superseded_and_session_restart() -> None:
    current = [NOW]
    with TestClient(create_app(TOKENS, clock=lambda: current[0])) as client:
        value = sample()
        assert post(client, value).json()["status"] == "accepted"
        assert post(client, value).json()["status"] == "duplicate"
        current[0] += timedelta(seconds=5)
        newer = value.model_copy(update={"sequence": 1, "observed_at": current[0]})
        assert post(client, newer).json()["status"] == "accepted"
        assert post(client, value).json()["status"] == "superseded"
        current[0] += timedelta(seconds=5)
        restart = newer.model_copy(
            update={"sequence": 0, "agent_session_id": uuid4(), "observed_at": current[0]}
        )
        assert post(client, restart).json()["status"] == "accepted"
        old_session = newer.model_copy(
            update={"sequence": 9, "observed_at": current[0] + timedelta(seconds=1)}
        )
        assert post(client, old_session).json()["status"] == "superseded"
    with TestClient(create_app(TOKENS, clock=lambda: current[0])) as restarted:
        assert restarted.get("/nodes/node-a/metrics").json()["stale"]


def test_history_bounds_and_unavailable_upstream() -> None:
    start = NOW - timedelta(minutes=1)
    validate_range(start, NOW, 5, NOW)
    for begin, end, step in [
        (NOW, start, 5),
        (start, NOW, 1),
        (NOW - timedelta(days=8), NOW, 500),
        (start, NOW + timedelta(seconds=1), 5),
        (NOW - timedelta(days=1), NOW, 5),
    ]:
        with pytest.raises(ValueError):
            validate_range(begin, end, step, NOW)

    def handler(request: httpx.Request) -> httpx.Response:
        assert (
            request.url.params["query"] == 'fleetdoctor_filesystem_available_bytes{node="node-a"}'
        )
        return httpx.Response(503)

    with TestClient(
        create_app(
            TOKENS,
            clock=lambda: NOW,
            history=HistoryClient("http://test", httpx.MockTransport(handler)),
        )
    ) as client:
        assert (
            client.get(
                "/nodes/node-a/metrics", params={"start": start.isoformat(), "end": NOW.isoformat()}
            ).status_code
            == 503
        )
        assert (
            client.get("/nodes/node-a/metrics", params={"start": start.isoformat()}).status_code
            == 422
        )
        assert client.get("/nodes/other/metrics").status_code == 404


def test_monotonic_scheduler_skips_missed_ticks() -> None:
    assert next_tick(10, 12) == 15
    assert next_tick(10, 17) == 22


class Drip(httpx.AsyncByteStream):
    async def __aiter__(self) -> Any:
        for _ in range(100):
            await asyncio.sleep(0.02)
            yield b"."


def test_upload_total_deadline_includes_drip_body() -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=Drip()))
        ) as client:
            before = time.monotonic()
            with pytest.raises(TimeoutError):
                await upload(client, "http://test", SecretStr("a" * 40), sample(), deadline=0.1)
            assert time.monotonic() - before < 0.5

    asyncio.run(scenario())


def delayed_worker(conn: Connection) -> None:
    time.sleep(0.5)
    conn.send("ready")
    while True:
        path = conn.recv()
        conn.send(from_statvfs(path, FIXTURES["reserved"]))


def hanging_worker(conn: Connection) -> None:
    conn.send("ready")
    conn.recv()
    time.sleep(30)


def test_slow_worker_startup_eventually_collects() -> None:
    worker = CollectionWorker(target=delayed_worker)
    try:
        value = worker.collect(("/",), budget=0.001)[0]
        assert value.total_bytes is None and value.errors == ["collection_worker_starting"]
        assert worker.process is not None
        pid = worker.process.pid
        assert worker.wait_ready(5)
        assert worker.collect(("/",))[0].available_bytes == 1433600
        assert worker.process is not None and worker.process.pid == pid
    finally:
        worker.close()


def test_hung_collection_deadline_and_recovery() -> None:
    worker = CollectionWorker(target=hanging_worker)
    try:
        assert worker.wait_ready(5)
        before = time.monotonic()
        value = worker.collect(("/",), budget=0.05)[0]
        assert value.total_bytes is None and value.errors == ["collection_timeout"]
        assert time.monotonic() - before < 0.5
        assert worker.process is None
        worker.target = delayed_worker
        assert worker.wait_ready(5)
        assert worker.collect(("/",))[0].available_bytes == 1433600
    finally:
        worker.close()


def test_unkillable_worker_never_spawns_replacement() -> None:
    worker = CollectionWorker()
    process = Mock()
    process.is_alive.return_value = True
    worker.process = process
    worker.conn = None
    value = worker.collect(("/",))[0]
    assert value.errors == ["collection_worker_stuck"]
    process.start.assert_not_called()
