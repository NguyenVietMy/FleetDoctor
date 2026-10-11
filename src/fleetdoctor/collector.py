"""Single-worker, in-memory collection; durable checkpoints arrive in task 04."""

import asyncio
import hmac
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from threading import Lock
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response
from prometheus_client import CollectorRegistry, Gauge, generate_latest
from pydantic import SecretStr, ValidationError

from fleetdoctor.history import HISTORY_METRICS, HistoryClient, validate_range
from fleetdoctor.schema import FIELDS, Sample

MAX_BODY = 65536
METRICS = {
    "total_bytes": "size_bytes",
    "free_bytes": "free_bytes",
    "available_bytes": "available_bytes",
    "used_bytes": "used_bytes",
    "block_usage_percent": "block_usage_ratio",
    "inodes_total": "inodes_total",
    "inodes_free": "inodes_free",
    "inode_usage_percent": "inode_usage_ratio",
}


class State:
    def __init__(
        self, nodes: dict[str, SecretStr], paths: tuple[str, ...], clock: Callable[[], datetime]
    ) -> None:
        self.nodes, self.paths, self.clock = nodes, paths, clock
        self.latest: dict[str, Sample] = {}
        self.rejected: dict[str, str] = {}
        self.retired: dict[str, list[tuple[str, str]]] = {node: [] for node in nodes}
        self.lock = Lock()

    def accept(self, sample: Sample) -> str:
        with self.lock:
            age = (self.clock() - sample.observed_at).total_seconds()
            if age < -2 or age > 10:
                self.rejected[sample.node_id] = "clock_skew" if age < -2 else "late_observation"
                return "ineligible"
            previous = self.latest.get(sample.node_id)
            identity = (str(sample.boot_id), str(sample.agent_session_id))
            if identity in self.retired[sample.node_id]:
                return "superseded"
            if previous:
                prev_identity = (str(previous.boot_id), str(previous.agent_session_id))
                if identity == prev_identity and sample.sequence <= previous.sequence:
                    return "duplicate" if sample.sequence == previous.sequence else "superseded"
                if sample.observed_at <= previous.observed_at:
                    return "superseded"
                if identity != prev_identity:
                    self.retired[sample.node_id].append(prev_identity)
                    self.retired[sample.node_id] = self.retired[sample.node_id][-8:]
            self.latest[sample.node_id] = sample
            self.rejected.pop(sample.node_id, None)
            return "accepted"

    def view(self, node: str) -> dict[str, Any]:
        with self.lock:
            sample = self.latest.get(node)
            age = (self.clock() - sample.observed_at).total_seconds() if sample else None
            fresh = age is not None and -2 <= age <= 10
            return {
                "node_id": node,
                "observed_at": sample.observed_at if sample else None,
                "age_seconds": max(0, age) if age is not None else None,
                "stale": age is None or age > 15 or age < -2,
                "fresh": fresh,
                "active_incident_count": None,
                "diagnosis_coverage": "not_implemented_task01",
                "delivery_error": self.rejected.get(node),
                "coverage": {
                    fs.mountpoint: {
                        "available_fields": [f for f in FIELDS if getattr(fs, f) is not None]
                        if fresh
                        else [],
                        "errors": fs.errors if fresh else ["observation_not_fresh"],
                    }
                    for fs in sample.filesystems
                }
                if sample
                else {},
                "sample": sample.model_dump(
                    mode="json", exclude=set() if fresh else {"filesystems"}
                )
                if sample
                else None,
                "filesystems": [fs.model_dump() for fs in sample.filesystems]
                if sample and fresh
                else None,
            }


def create_app(
    nodes: dict[str, SecretStr],
    paths: tuple[str, ...] = ("/",),
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    history: HistoryClient | None = None,
) -> FastAPI:
    if not nodes or len(nodes) > 16 or any(len(v.get_secret_value()) < 32 for v in nodes.values()):
        raise ValueError("configure 1..16 node tokens of at least 32 characters")
    if not paths or len(paths) > 8 or len(set(paths)) != len(paths):
        raise ValueError("configure 1..8 unique filesystems")
    state = State(nodes, paths, clock)
    app = FastAPI(title="FleetDoctor", version="0.1.0")
    app.state.fleet = state
    upstream = history or HistoryClient(os.getenv("PROMETHEUS_URL", "http://prometheus:9090"))

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "storage": "latest_memory_only", "slice": "01"}

    @app.post("/ingest")
    async def ingest(request: Request) -> dict[str, Any]:
        length = request.headers.get("content-length")
        if length and (not length.isdigit() or int(length) > MAX_BODY):
            raise HTTPException(413, "sample exceeds 64KiB")

        async def read_body() -> bytes:
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_BODY:
                    raise HTTPException(413, "sample exceeds 64KiB")
                body.extend(chunk)
            return bytes(body)

        try:
            body = await asyncio.wait_for(read_body(), timeout=2)
            sample = Sample.model_validate_json(body)
        except TimeoutError as exc:
            raise HTTPException(408, "sample upload deadline exceeded") from exc
        except ValidationError as exc:
            raise HTTPException(422, "invalid sample schema or units") from exc
        token = nodes.get(sample.node_id)
        auth = request.headers.get("authorization", "")
        expected = "Bearer " + token.get_secret_value() if token else ""
        if not token or not hmac.compare_digest(auth.encode(), expected.encode()):
            raise HTTPException(403, "node identity not authorized")
        if {fs.mountpoint for fs in sample.filesystems} != set(paths):
            raise HTTPException(422, "sample must cover exactly the configured filesystems")
        return {"status": state.accept(sample), "durable": False}

    @app.get("/nodes")
    def list_nodes() -> dict[str, Any]:
        return {"nodes": [state.view(node) for node in nodes]}

    @app.get("/nodes/{node}/metrics")
    async def node_metrics(
        node: str,
        start: datetime | None = None,
        end: datetime | None = None,
        step: int = 5,
        field: str = Query(default="available_bytes", enum=list(HISTORY_METRICS)),
    ) -> dict[str, Any]:
        if node not in nodes:
            raise HTTPException(404, "unknown node")
        if start is None and end is None:
            return state.view(node)
        if start is None or end is None or field not in HISTORY_METRICS:
            raise HTTPException(422, "supply valid field, start and end together")
        try:
            validate_range(start, end, step, clock())
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        try:
            data = await upstream.query(node, start, end, step, field)
        except (httpx.HTTPError, TimeoutError, ValueError, KeyError) as exc:
            raise HTTPException(503, "metric history unavailable") from exc
        return {"node_id": node, "field": field, "step_seconds": step, "history": data}

    @app.get("/metrics")
    def metrics() -> Response:
        registry = CollectorRegistry()
        health_g = Gauge(
            "fleetdoctor_collector_up", "Collector is serving requests", registry=registry
        )
        health_g.set(1)
        stale = Gauge(
            "fleetdoctor_node_stale",
            "Last eligible observation older than 15s or absent",
            ["node"],
            registry=registry,
        )
        age_g = Gauge(
            "fleetdoctor_sample_age_seconds",
            "Age of last eligible observation",
            ["node"],
            registry=registry,
        )
        coverage = Gauge(
            "fleetdoctor_filesystem_coverage_ratio",
            "Fraction of available filesystem fields; zero if not fresh",
            ["node", "filesystem"],
            registry=registry,
        )
        gauges = {
            field: Gauge(
                "fleetdoctor_filesystem_" + suffix,
                "Filesystem " + suffix,
                ["node", "filesystem"],
                registry=registry,
            )
            for field, suffix in METRICS.items()
        }
        for node in nodes:
            view = state.view(node)
            stale.labels(node).set(int(view["stale"]))
            if view["age_seconds"] is not None:
                age_g.labels(node).set(view["age_seconds"])
            for path in paths:
                available = view["coverage"].get(path, {}).get("available_fields", [])
                coverage.labels(node, path).set(
                    len(available) / len(FIELDS) if view["fresh"] else 0
                )
            for fs in view["filesystems"] or []:
                for field, gauge in gauges.items():
                    value = fs[field]
                    if value is not None:
                        gauge.labels(node, fs["mountpoint"]).set(
                            value / 100 if field.endswith("percent") else value
                        )
        return Response(
            generate_latest(registry), media_type="text/plain; version=0.0.4; charset=utf-8"
        )

    return app


def app_factory() -> FastAPI:
    raw: dict[str, str] = json.loads(os.environ["FLEETDOCTOR_NODE_TOKENS"])
    return create_app(
        {node: SecretStr(token) for node, token in raw.items()},
        tuple(os.getenv("FLEETDOCTOR_FILESYSTEMS", "/").split(",")),
    )
