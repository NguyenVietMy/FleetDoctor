"""Production collection scheduler/transport through a node-a-only fault proxy.

Called by integration.py inside its uniquely owned real service stack. Collection
is synthetic; transport, clocks, PostgreSQL, Prometheus and Grafana are real.
"""

import asyncio
import hashlib
import json
import socket
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from integration_disk import PATH
from pydantic import SecretStr

from fleetdoctor.agent import collect_loop
from fleetdoctor.collection import CollectionWorker, from_statvfs
from fleetdoctor.schema import Filesystem


class SyntheticWorker(CollectionWorker):
    def __init__(self, node: str) -> None:
        self.node = node
        self.usage = 10
        self.ticks: list[dict[str, Any]] = []

    def collect(self, paths: tuple[str, ...], budget: float = 1) -> list[Filesystem]:
        self.ticks.append(
            {"sequence": len(self.ticks), "monotonic": time.monotonic(), "usage": self.usage}
        )
        return [
            from_statvfs(
                path,
                {
                    "f_blocks": 10000,
                    "f_bfree": 10000 - usage * 100,
                    "f_bavail": 10000 - usage * 100,
                    "f_frsize": 4096,
                    "f_files": 1000,
                    "f_ffree": 900,
                },
            )
            for path in paths
            for usage in [self.usage if path == PATH else 10]
        ]

    def close(self) -> None:
        pass


def recovery_response_cut(
    current: dict[str, Any],
    opening: dict[str, Any],
    attempts: list[dict[str, Any]],
    ticks: list[dict[str, Any]],
    restored: float,
) -> dict[str, Any]:
    """Bind recovery counts to the exact evidence returned by one detail response."""
    configuration = opening["configuration"]
    threshold = float(configuration["recovery_percent"])
    required = int(configuration["consecutive_samples"])
    opening_evidence = opening["opening_evidence"]
    latest = current["latest_evidence"]
    boot_id = str(opening_evidence["boot_id"])
    session_id = str(opening_evidence["agent_session_id"])
    if latest.get("boot_id") != boot_id or latest.get("agent_session_id") != session_id:
        raise AssertionError("recovery detail changed producer identity")
    latest_sequence = int(latest["sequence"])
    healthy_ticks = {
        int(tick["sequence"])
        for tick in ticks
        if tick["monotonic"] > restored and float(tick["usage"]) < threshold
    }
    matching_attempts = [
        row
        for row in attempts
        if row.get("boot_id") == boot_id
        and row.get("agent_session_id") == session_id
        and row.get("sequence") in healthy_ticks
    ]
    committed = {
        int(row["sequence"])
        for row in matching_attempts
        if row.get("status") == "accepted" and int(row["sequence"]) <= latest_sequence
    }
    latest_filesystem = latest.get("filesystem") or {}
    latest_is_healthy = (
        latest_sequence in healthy_ticks
        and latest.get("block_available") is True
        and latest_filesystem.get("mountpoint") == PATH
        and float(latest_filesystem.get("block_usage_percent", threshold)) < threshold
    )
    response_proven_sequence: int | None = None
    if latest_is_healthy and any(
        int(row["sequence"]) == latest_sequence for row in matching_attempts
    ):
        # The returned evidence is a commit boundary even if the proxy coroutine has
        # not resumed to annotate that same POST response as accepted yet.
        committed.add(latest_sequence)
        response_proven_sequence = latest_sequence
    committed_sequences = sorted(committed)
    return {
        "returned_status": current.get("status"),
        "latest_identity": {
            "boot_id": latest.get("boot_id"),
            "agent_session_id": latest.get("agent_session_id"),
            "sequence": latest_sequence,
        },
        "healthy_tick_sequences": sorted(healthy_ticks),
        "accepted_at_response_sequences": sorted(
            {
                int(row["sequence"])
                for row in matching_attempts
                if row.get("status") == "accepted" and int(row["sequence"]) <= latest_sequence
            }
        ),
        "response_proven_sequence": response_proven_sequence,
        "eligible_committed_sequences": committed_sequences,
        "eligible_committed_count": len(committed_sequences),
        "required_count": required,
        "expected_status": "resolved" if len(committed_sequences) >= required else "active",
    }


async def observe_recovery_response_cut(
    detail_request: Callable[[], Awaitable[dict[str, Any]]],
    opening: dict[str, Any],
    attempts: list[dict[str, Any]],
    ticks: list[dict[str, Any]],
    restored: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Take the count only after the awaited response fixes its evidence boundary."""
    current = await detail_request()
    return current, recovery_response_cut(current, opening, attempts, ticks, restored)


def assert_recovery_response_cut(current: dict[str, Any], cut: dict[str, Any]) -> None:
    if current.get("status") != cut["expected_status"]:
        raise AssertionError(
            "recovery response/count cut mismatch: " + json.dumps(cut, sort_keys=True)
        )


async def prove_outage(
    api: str, prom: str, grafana: str, values: dict[str, str], proof: dict[str, Any]
) -> None:
    tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
    workers = {node: SyntheticWorker(node) for node in tokens}
    stopped = asyncio.Event()
    blocked = False
    attempts: list[dict[str, Any]] = []
    proof.update(
        environment="isolated-real-services-production-agent-synthetic-filesystems",
        aws_execution=False,
        visual_proof=False,
    )
    proof["attempts"] = attempts
    proof["collection_ticks"] = {node: worker.ticks for node, worker in workers.items()}
    proxy = FastAPI()
    async with httpx.AsyncClient(timeout=3, trust_env=False) as client:

        @proxy.post("/ingest")
        async def forward(request: Request) -> Response:
            body = await request.body()
            value = json.loads(body)
            assert value["node_id"] == "node-a"
            row = {
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "boot_id": value["boot_id"],
                "agent_session_id": value["agent_session_id"],
                "sequence": value["sequence"],
                "observed_at": value["observed_at"],
                "discard_total": value["delivery"]["discard_total"],
                "monotonic": time.monotonic(),
                "blocked": blocked,
            }
            attempts.append(row)
            if blocked:
                row["http_status"] = 503
                return Response(status_code=503)
            result = await client.post(
                api + "/ingest",
                content=body,
                headers={
                    "Authorization": request.headers["authorization"],
                    "Content-Type": "application/json",
                },
            )
            row["http_status"] = result.status_code
            row["status"] = result.json().get("status")
            return Response(
                result.content, status_code=result.status_code, media_type="application/json"
            )

        async def get(path: str) -> dict[str, Any]:
            result = await client.get(api + path)
            result.raise_for_status()
            data: dict[str, Any] = result.json()
            return data

        async def wait_for(predicate: Any, timeout: float = 25) -> Any:
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                value = await predicate()
                if value:
                    return value
                await asyncio.sleep(0.2)
            raise TimeoutError("outage scenario condition deadline")

        async def active() -> list[dict[str, Any]]:
            return list((await get("/diagnoses?node=node-a&status=active"))["diagnoses"])

        async def cleared() -> bool:
            return not await active()

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            address = "http://127.0.0.1:" + str(sock.getsockname()[1])
            server = uvicorn.Server(uvicorn.Config(proxy, log_config=None, access_log=False))
            server_task = asyncio.create_task(server.serve(sockets=[sock]))
            tasks: list[asyncio.Task[None]] = []
            try:
                while not server.started:
                    if server_task.done():
                        await server_task
                        raise RuntimeError("proxy startup failed")
                    await asyncio.sleep(0.01)
                tasks = [
                    asyncio.create_task(
                        collect_loop(
                            node,
                            uuid4(),
                            uuid4(),
                            worker,
                            address if node == "node-a" else api,
                            SecretStr(tokens[node]),
                            ("/", PATH),
                            False,
                            stopped,
                        )
                    )
                    for node, worker in workers.items()
                ]
                await wait_for(cleared)

                # Wait for this producer's healthy sample even if no incident existed.
                async def received() -> bool:
                    return any(row.get("status") == "accepted" for row in attempts)

                await wait_for(received)
                workers["node-a"].usage = 98
                rows = await wait_for(active)
                incident = await get("/diagnoses/" + rows[0]["id"])
                proof["opening"] = incident
                last = next(row for row in reversed(attempts) if row.get("status") == "accepted")
                blocked = True
                outage_begin = time.monotonic()
                outage_wall = datetime.now(UTC).timestamp()
                proof["outage_begin_monotonic"] = outage_begin
                await asyncio.sleep(max(0, last["monotonic"] + 11.2 - time.monotonic()))
                nodes = {v["node_id"]: v for v in (await get("/nodes"))["nodes"]}
                assert not nodes["node-a"]["fresh"] and not nodes["node-a"]["stale"]
                assert nodes["node-a"]["filesystems"] is None and nodes["node-b"]["fresh"]
                proof["expired_before_stale"] = nodes
                await asyncio.sleep(max(0, last["monotonic"] + 16.2 - time.monotonic()))
                nodes = {v["node_id"]: v for v in (await get("/nodes"))["nodes"]}
                assert nodes["node-a"]["stale"] and nodes["node-b"]["fresh"]
                during = await get("/diagnoses/" + incident["id"])
                assert (
                    during["status"] == "active"
                    and during["opening_evidence"] == incident["opening_evidence"]
                )
                assert during["latest_evidence"] == incident["latest_evidence"]
                proof["stale_during_outage"] = nodes
                await asyncio.sleep(max(0, outage_begin + 25 - time.monotonic()))
                # Independent reads and node-b remain available throughout the fault.
                assert not (await get("/diagnoses?node=node-b&status=active"))["diagnoses"]
                blocked = False
                end_wall = datetime.now(UTC).timestamp()
                restored = time.monotonic()
                proof["outage_end_monotonic"] = restored
                assert restored - outage_begin >= 20

                async def reconnected() -> dict[str, Any] | None:
                    return next(
                        (
                            row
                            for row in attempts
                            if row["monotonic"] >= restored and row.get("status") == "accepted"
                        ),
                        None,
                    )

                reconnect = await wait_for(reconnected, 12)
                newest = max(
                    tick["sequence"]
                    for tick in workers["node-a"].ticks
                    if tick["monotonic"] <= reconnect["monotonic"]
                )
                assert reconnect["sequence"] == newest and reconnect["discard_total"] > 0
                proof["reconnect"] = reconnect
                retry_hashes: dict[int, set[str]] = {}
                for attempt in attempts:
                    retry_hashes.setdefault(attempt["sequence"], set()).add(attempt["body_sha256"])
                assert all(len(hashes) == 1 for hashes in retry_hashes.values())
                assert len([row for row in attempts if row["blocked"]]) >= 4
                proof["immutable_retry_bytes"] = True
                after = await get("/diagnoses/" + incident["id"])
                assert (
                    after["status"] == "active"
                    and after["opening_evidence"] == incident["opening_evidence"]
                )
                # Old healthy and high samples cannot repair/backfill history/windows.
                for usage in (10, 98):
                    from fleetdoctor.agent import make_sample

                    old = make_sample(
                        "node-a",
                        uuid4(),
                        uuid4(),
                        0,
                        [
                            from_statvfs(
                                path,
                                {
                                    "f_blocks": 100,
                                    "f_bfree": 100 - usage,
                                    "f_bavail": 100 - usage,
                                    "f_frsize": 4096,
                                    "f_files": 1000,
                                    "f_ffree": 900,
                                },
                            )
                            for path in ("/", PATH)
                        ],
                        datetime.fromtimestamp(outage_wall - 15, UTC),
                    )
                    result = await client.post(
                        api + "/ingest",
                        content=old.model_dump_json(),
                        headers={"Authorization": "Bearer " + tokens["node-a"]},
                    )
                    assert result.json()["status"] == "ineligible"
                workers["node-a"].usage = 10
                healthy_seen = 0
                proof["recovery_response_trace"] = []
                while healthy_seen < 3:
                    await asyncio.sleep(0.2)
                    current, cut = await observe_recovery_response_cut(
                        lambda: get("/diagnoses/" + incident["id"]),
                        incident,
                        attempts,
                        workers["node-a"].ticks,
                        restored,
                    )
                    proof["recovery_response_trace"].append(cut)
                    healthy_seen = int(cut["eligible_committed_count"])
                    assert current["opening_evidence"] == incident["opening_evidence"]
                    assert_recovery_response_cut(current, cut)
                    if time.monotonic() - restored > 25:
                        raise TimeoutError("three fresh recovery observations deadline")
                proof["resolved"] = current
                for worker in workers.values():
                    intervals = [
                        b["monotonic"] - a["monotonic"]
                        for a, b in zip(worker.ticks, worker.ticks[1:], strict=False)
                    ]
                    assert len(intervals) >= 7 and all(
                        4.5 <= delta <= 5.5 for delta in intervals
                    ), intervals
                # Prometheus range gaps allow one 5s scrape boundary after expiry.
                range_start = outage_wall + 17
                range_end = end_wall - 1
                histories = {}
                for node in tokens:
                    response = await client.get(
                        prom + "/api/v1/query_range",
                        params={
                            "query": f'fleetdoctor_filesystem_available_bytes{{node="{node}"}}',
                            "start": range_start,
                            "end": range_end,
                            "step": 1,
                        },
                    )
                    response.raise_for_status()
                    histories[node] = response.json()["data"]["result"]
                assert not histories["node-a"] and histories["node-b"]
                proof["prometheus_outage_range"] = {
                    "start": range_start,
                    "end": range_end,
                    "results": histories,
                }
                query = await client.get(
                    grafana + "/api/datasources/proxy/uid/prometheus/api/v1/query",
                    params={"query": "fleetdoctor_delivery_discard_total"},
                    auth=("admin", values["GRAFANA_PASSWORD"]),
                )
                query.raise_for_status()
                assert query.json()["data"]["result"]
                proof["grafana_delivery_query"] = query.json()
                proof["reader_acl"] = "separately asserted by integration_disk in same invocation"
                proof["status"] = "passed"
            except BaseException as exc:
                proof["status"] = "failed"
                proof["failure"] = type(exc).__name__ + ": " + str(exc)
                raise
            finally:
                stopped.set()
                for task in tasks:
                    task.cancel()
                for task in tasks:
                    with suppress(asyncio.CancelledError):
                        await task
                server.should_exit = True
                await asyncio.wait_for(server_task, 5)
