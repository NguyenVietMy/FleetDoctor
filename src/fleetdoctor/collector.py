"""Single-worker collection with transactional incidents; sample checkpoints are task 04."""

import asyncio
import hashlib
import hmac
import json
import os
from collections import OrderedDict
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from threading import Lock
from typing import Any
from uuid import UUID

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CollectorRegistry, Gauge, generate_latest
from pydantic import SecretStr, ValidationError

from fleetdoctor.history import HISTORY_METRICS, HistoryClient, validate_range
from fleetdoctor.incidents import DiskConfig
from fleetdoctor.rules import DiskEvaluator
from fleetdoctor.schema import FIELDS, Sample
from fleetdoctor.store import IncidentStore, PostgresStore, StoreError

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
        self,
        nodes: dict[str, SecretStr],
        paths: tuple[str, ...],
        clock: Callable[[], datetime],
        store: IncidentStore,
        config: DiskConfig,
    ) -> None:
        self.nodes, self.paths, self.clock = nodes, paths, clock
        self.latest: dict[str, Sample] = {}
        self.rejected: dict[str, str] = {}
        self.retired: dict[str, list[tuple[str, str]]] = {node: [] for node in nodes}
        self.identities: dict[str, OrderedDict[tuple[str, str, int], bytes]] = {
            node: OrderedDict() for node in nodes
        }
        self.lock = Lock()
        self.store, self.config = store, config
        self.evaluator = DiskEvaluator(store.active())

    def accept(self, sample: Sample) -> str:
        with self.lock:
            now = self.clock()
            age = (now - sample.observed_at).total_seconds()
            if age < -2 or age > 10:
                self.rejected[sample.node_id] = "clock_skew" if age < -2 else "late_observation"
                return "ineligible"
            key = (str(sample.boot_id), str(sample.agent_session_id), sample.sequence)
            fingerprint = hashlib.sha256(sample.model_dump_json().encode()).digest()
            known = self.identities[sample.node_id].get(key)
            if known is not None:
                if known != fingerprint:
                    raise HTTPException(409, "conflicting sample identity")
            previous = self.latest.get(sample.node_id)
            identity = (str(sample.boot_id), str(sample.agent_session_id))
            if identity in self.retired[sample.node_id]:
                return "superseded"
            if previous:
                prev_identity = (str(previous.boot_id), str(previous.agent_session_id))
                if identity == prev_identity and sample.sequence <= previous.sequence:
                    if sample.sequence == previous.sequence:
                        if sample != previous:
                            raise HTTPException(409, "conflicting sample identity")
                        return "duplicate"
                    return "superseded"
                if sample.observed_at <= previous.observed_at:
                    return "superseded"
            staged = deepcopy(self.evaluator)
            # A failed COMMIT response may still have durably changed incidents.
            # Reconcile that outcome before this observation, without advancing windows,
            # latest samples or deduplication until its own transaction succeeds.
            active = self.store.active()
            staged.active = {(i.node_id, i.resource): i for i in active}
            staged.reloaded.intersection_update(i.id for i in active)
            changes = staged.evaluate(sample, previous, now, self.config)
            self.store.apply(changes)
            # Every eligible batch passes storage before latest, dedup, identity or windows advance.
            if previous and identity != prev_identity:
                self.retired[sample.node_id].append(prev_identity)
                self.retired[sample.node_id] = self.retired[sample.node_id][-8:]
            self.evaluator = staged
            self.latest[sample.node_id] = sample
            identities = self.identities[sample.node_id]
            identities[key] = fingerprint
            if len(identities) > 60:
                identities.popitem(last=False)
            self.rejected.pop(sample.node_id, None)
            return "accepted"

    def view(self, node: str, *, include_counts: bool = True) -> dict[str, Any]:
        with self.lock:
            # Counts describe committed rows, including a lost write acknowledgement.
            # Metrics can still expose collection/storage status when storage is down.
            active = self.store.active() if include_counts else None
            sample = self.latest.get(node)
            age = (self.clock() - sample.observed_at).total_seconds() if sample else None
            fresh = age is not None and -2 <= age <= 10
            return {
                "node_id": node,
                "observed_at": sample.observed_at if sample else None,
                "age_seconds": max(0, age) if age is not None else None,
                "stale": age is None or age > 15 or age < -2,
                "fresh": fresh,
                "active_incident_count": sum(i.node_id == node for i in active)
                if active is not None
                else None,
                "diagnosis_coverage": {
                    path: "available"
                    if fresh
                    and sample
                    and any(
                        fs.mountpoint == path and fs.block_usage_percent is not None
                        for fs in sample.filesystems
                    )
                    else "unavailable"
                    for path in self.paths
                },
                "delivery_error": self.rejected.get(node),
                "delivery": {
                    "available": bool(sample and sample.delivery is not None),
                    "scope": "agent_session",
                    "discard_total": sample.delivery.discard_total
                    if sample and sample.delivery
                    else None,
                    "age_seconds": max(0, age) if age is not None else None,
                    "fresh": fresh,
                },
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
    store: IncidentStore | None = None,
    config: DiskConfig | None = None,
) -> FastAPI:
    if not nodes or len(nodes) > 16 or any(len(v.get_secret_value()) < 32 for v in nodes.values()):
        raise ValueError("configure 1..16 node tokens of at least 32 characters")
    if not paths or len(paths) > 8 or len(set(paths)) != len(paths):
        raise ValueError("configure 1..8 unique filesystems")
    storage = store if store is not None else PostgresStore.environment()
    state = State(nodes, paths, clock, storage, config or DiskConfig())
    app = FastAPI(title="FleetDoctor", version="0.1.0")
    app.state.fleet = state
    upstream = history or HistoryClient(os.getenv("PROMETHEUS_URL", "http://prometheus:9090"))

    @app.exception_handler(StoreError)
    async def storage_error(request: Request, exc: StoreError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": "incident storage unavailable"})

    def require_storage() -> None:
        if not storage.health():
            raise StoreError("incident storage unavailable")

    @app.get("/configuration")
    def configuration() -> dict[str, Any]:
        require_storage()
        return {
            "disk_rule": state.config.model_dump(),
            "filesystems": list(paths),
            "cadence_seconds": 5,
        }

    @app.get("/health")
    def health() -> dict[str, str]:
        require_storage()
        return {"status": "ok", "storage": "incidents_durable_samples_memory", "slice": "03"}

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
        return {
            "status": await asyncio.to_thread(state.accept, sample),
            "durable": False,
            "incidents_durable": True,
        }

    @app.get("/nodes")
    def list_nodes() -> dict[str, Any]:
        require_storage()
        return {"nodes": [state.view(node) for node in nodes]}

    @app.get("/diagnoses")
    def diagnoses(
        node: str | None = None,
        rule: str | None = None,
        status: str | None = Query(None, pattern="^(active|resolved)$"),
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = Query(25, ge=1, le=100),
        offset: int = Query(0, ge=0, le=10000),
    ) -> dict[str, Any]:
        if any(t is not None and (t.tzinfo is None or t.utcoffset() is None) for t in (start, end)):
            raise HTTPException(422, "opening time filters must include timezone")
        if start and end and start > end:
            raise HTTPException(422, "start must not exceed end")
        rows, total = storage.query(node, rule, status, start, end, limit, offset)
        with state.lock:
            records = [
                i.view(clock(), detail=False, reloaded=i.id in state.evaluator.reloaded)
                for i in rows
            ]
        return {
            "diagnoses": records,
            "total": total,
            "limit": limit,
            "offset": offset,
            "next_offset": offset + limit if offset + limit < total else None,
            "time_filter": "opened_at",
        }

    @app.get("/diagnoses/{identifier}")
    def diagnosis(identifier: UUID) -> dict[str, Any]:
        record = storage.get(identifier)
        if record is None:
            raise HTTPException(404, "unknown incident")
        with state.lock:
            return record.view(clock(), detail=True, reloaded=record.id in state.evaluator.reloaded)

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
            require_storage()
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
        storage_ok = storage.health()
        storage_g = Gauge(
            "fleetdoctor_incident_storage_up", "Required storage readiness", registry=registry
        )
        storage_g.set(int(storage_ok))
        active_g = Gauge(
            "fleetdoctor_active_incidents",
            "Active disk incidents",
            ["node", "rule"],
            registry=registry,
        )
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
        reporting = Gauge(
            "fleetdoctor_delivery_reporting_available",
            "Last sample contains session delivery reporting",
            ["node"],
            registry=registry,
        )
        discards = Gauge(
            "fleetdoctor_delivery_discard_total",
            "Last observed session cumulative local discards (gauge)",
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
        try:
            views = {node: state.view(node, include_counts=storage_ok) for node in nodes}
        except StoreError:
            storage_ok = False
            views = {node: state.view(node, include_counts=False) for node in nodes}
        storage_g.set(int(storage_ok))
        for node, view in views.items():
            if storage_ok:
                active_g.labels(node, "disk_block_exhaustion").set(view["active_incident_count"])
            reporting.labels(node).set(int(view["delivery"]["available"]))
            if view["delivery"]["available"]:
                discards.labels(node).set(view["delivery"]["discard_total"])
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
        config=DiskConfig.model_validate_json(os.getenv("FLEETDOCTOR_DISK_RULE", "{}")),
    )
