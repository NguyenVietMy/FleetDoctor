"""Single-worker collection with atomic incident and ingestion checkpoints."""

import asyncio
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

from fleetdoctor.checkpoint import (
    MAX_CHECKPOINT_BYTES,
    Checkpoint,
    IdentityFingerprint,
    RetiredSession,
    sample_fingerprint,
)
from fleetdoctor.fd import (
    MAX_ACTIVE_WATCHES,
    MAX_WATCH_RESPONSE,
    WatchIdentity,
    WatchResponse,
    parse_resource,
)
from fleetdoctor.history import HISTORY_METRICS, HistoryClient, validate_range
from fleetdoctor.incidents import (
    CpuConfig,
    DiskConfig,
    FdConfig,
    InodeConfig,
    NetworkConfig,
    OomConfig,
)
from fleetdoctor.memory import validate_cgroup_paths
from fleetdoctor.rules import MAX_ACTIVE_NETWORK_RESOURCES, CompositeEvaluator
from fleetdoctor.schema import FIELDS, Sample, WorkloadMemoryObservation
from fleetdoctor.store import IncidentStore, PostgresStore, StoreError, StoreSnapshot

MAX_BODY = 65536
ACKNOWLEDGEMENT_HEADER = "X-FleetDoctor-Acknowledgement"
ACKNOWLEDGEMENT_VERSION = "checkpoints-v1"
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


def usable_workload_memory(value: WorkloadMemoryObservation) -> bool:
    return (
        value.snapshot_stable
        and value.current_bytes is not None
        and value.events_before is not None
        and value.events is not None
        and (value.max_bytes is not None or value.max_unlimited)
    )


class State:
    def __init__(
        self,
        nodes: dict[str, SecretStr],
        paths: tuple[str, ...],
        clock: Callable[[], datetime],
        store: IncidentStore,
        config: DiskConfig,
        inode_config: InodeConfig | None = None,
        cpu_config: CpuConfig | None = None,
        oom_config: OomConfig | None = None,
        fd_config: FdConfig | None = None,
        network_config: NetworkConfig | None = None,
        cgroup_paths: tuple[str, ...] = (),
    ) -> None:
        self.nodes, self.paths, self.clock = nodes, paths, clock
        self.latest: dict[str, Sample] = {}
        self.rejected: dict[str, str] = {}
        self.live: set[str] = set()
        self.retired: dict[str, list[tuple[str, str]]] = {node: [] for node in nodes}
        self.identities: dict[str, OrderedDict[tuple[str, str, int], str]] = {
            node: OrderedDict() for node in nodes
        }
        self.published_checkpoints: dict[str, Checkpoint] = {}
        self.lock = Lock()
        self.store, self.config = store, config
        self.inode_config, self.cpu_config = (
            inode_config or InodeConfig(),
            cpu_config or CpuConfig(),
        )
        self.oom_config, self.fd_config = oom_config or OomConfig(), fd_config or FdConfig()
        self.network_config = network_config or NetworkConfig()
        self.cgroup_paths = cgroup_paths
        snapshot = store.snapshot(set(nodes))
        self.evaluator = CompositeEvaluator(snapshot.active)
        for checkpoint in snapshot.checkpoints.values():
            self._publish_checkpoint(checkpoint, live=False)

    def _publish_checkpoint(self, checkpoint: Checkpoint, *, live: bool) -> None:
        node = checkpoint.node_id
        self.latest[node] = checkpoint.latest.model_copy(deep=True)
        self.identities[node] = OrderedDict(
            (item.key, item.fingerprint) for item in checkpoint.fingerprints
        )
        self.retired[node] = [item.key for item in checkpoint.retired_sessions]
        self.published_checkpoints[node] = checkpoint.model_copy(deep=True)
        if live:
            self.live.add(node)
        else:
            self.live.discard(node)

    def _reconcile(self, snapshot: StoreSnapshot) -> None:
        if self.published_checkpoints.keys() - snapshot.checkpoints.keys():
            raise StoreError("published ingestion checkpoint is missing")
        changed_nodes = {
            node
            for node, checkpoint in snapshot.checkpoints.items()
            if self.published_checkpoints.get(node) != checkpoint
        }
        for node in changed_nodes:
            self._publish_checkpoint(snapshot.checkpoints[node], live=False)
            self.evaluator.reset_node(node)
        canonical = {(i.node_id, i.rule, i.resource): i for i in snapshot.active}
        if canonical != self.evaluator.active:
            affected = {
                node
                for node in self.nodes
                if {key: value for key, value in canonical.items() if key[0] == node}
                != {key: value for key, value in self.evaluator.active.items() if key[0] == node}
            }
            for node in affected:
                self.live.discard(node)
            self.evaluator.replace_active(snapshot.active, affected)

    def accept(self, sample: Sample) -> str:
        with self.lock:
            now = self.clock()
            snapshot = self.store.snapshot(set(self.nodes))
            self._reconcile(snapshot)
            key = (str(sample.boot_id), str(sample.agent_session_id), sample.sequence)
            fingerprint = sample_fingerprint(sample)
            known = self.identities[sample.node_id].get(key)
            if known is not None:
                if known != fingerprint:
                    raise HTTPException(409, "conflicting sample identity")
                return "duplicate"
            age = (now - sample.observed_at).total_seconds()
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
                    if sample.sequence == previous.sequence:
                        if sample != previous:
                            raise HTTPException(409, "conflicting sample identity")
                        return "duplicate"
                    return "superseded"
                if sample.observed_at <= previous.observed_at:
                    return "superseded"
            staged = deepcopy(self.evaluator)
            changes = staged.evaluate(
                sample,
                previous,
                now,
                self.config,
                self.inode_config,
                self.cpu_config,
                self.oom_config,
                self.fd_config,
                self.network_config,
            )
            retired = list(self.retired[sample.node_id])
            if previous and identity != prev_identity:
                retired.append(prev_identity)
                retired = retired[-8:]
            identities = OrderedDict(self.identities[sample.node_id])
            identities[key] = fingerprint
            if len(identities) > 60:
                identities.popitem(last=False)
            current = self.published_checkpoints.get(sample.node_id)
            checkpoint = Checkpoint(
                node_id=sample.node_id,
                revision=(current.revision + 1) if current else 1,
                latest=sample,
                fingerprints=[
                    IdentityFingerprint(
                        boot_id=UUID(boot),
                        agent_session_id=UUID(session),
                        sequence=sequence,
                        fingerprint=value,
                    )
                    for (boot, session, sequence), value in identities.items()
                ],
                retired_sessions=[
                    RetiredSession(boot_id=UUID(boot), agent_session_id=UUID(session))
                    for boot, session in retired
                ],
            )
            self.store.commit(changes, checkpoint)
            # Publication follows the successful connection-context COMMIT.
            self.evaluator = staged
            self._publish_checkpoint(checkpoint, live=True)
            self.rejected.pop(sample.node_id, None)
            return "accepted"

    def view(self, node: str, *, include_counts: bool = True) -> dict[str, Any]:
        with self.lock:
            # Counts describe committed rows, including a lost write acknowledgement.
            # Metrics can still expose collection/storage status when storage is down.
            active = self.store.active() if include_counts else None
            sample = self.latest.get(node)
            age = (self.clock() - sample.observed_at).total_seconds() if sample else None
            fresh = node in self.live and age is not None and -2 <= age <= 10
            by_rule = (
                {
                    rule: sum(i.node_id == node and i.rule == rule for i in active)
                    for rule in (
                        "disk_block_exhaustion",
                        "inode_exhaustion",
                        "cpu_saturation",
                        "workload_oom",
                        "fd_pressure",
                        "network_path_degradation",
                    )
                }
                if active is not None
                else None
            )
            cpu = sample.cpu if sample else None
            memory = sample.memory if sample else None
            fd = sample.fd if sample else None
            network = sample.network if sample else None
            fd_active_count = (
                sum(i.node_id == node and i.rule == "fd_pressure" for i in active)
                if active is not None
                else None
            )
            network_active_count = (
                sum(i.node_id == node and i.rule == "network_path_degradation" for i in active)
                if active is not None
                else None
            )
            cpu_coverage = {
                "host_rates": "available"
                if fresh and cpu is not None and cpu.busy_percent is not None
                else "unavailable",
                "runnable": "available"
                if fresh and cpu is not None and cpu.runnable_processes is not None
                else "unavailable",
                "logical_cores": "available"
                if fresh and cpu is not None and cpu.logical_cores is not None
                else "unavailable",
                "process_inventory": cpu.process_inventory
                if fresh and cpu is not None
                else "unavailable",
                "errors": cpu.errors
                if fresh and cpu is not None
                else ["observation_not_fresh" if sample else "observation_unavailable"],
            }
            return {
                "node_id": node,
                "observed_at": sample.observed_at if sample else None,
                "age_seconds": max(0, age) if age is not None else None,
                "stale": age is None or age > 15 or age < -2,
                "fresh": fresh,
                "active_incident_count": sum(i.node_id == node for i in active)
                if active is not None
                else None,
                "active_incident_counts": by_rule,
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
                "inode_diagnosis_coverage": {
                    path: "available"
                    if fresh
                    and sample
                    and any(
                        fs.mountpoint == path
                        and fs.inode_usage_percent is not None
                        and fs.block_usage_percent is not None
                        and fs.available_bytes is not None
                        for fs in sample.filesystems
                    )
                    else "unavailable"
                    for path in self.paths
                },
                "delivery_error": self.rejected.get(node),
                "delivery": {
                    "available": bool(fresh and sample and sample.delivery is not None),
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
                "cpu_coverage": cpu_coverage,
                "memory_coverage": {
                    "host": "available"
                    if fresh and memory is not None and memory.host.total_bytes is not None
                    else "unavailable",
                    "kernel_logs": memory.kernel_log_coverage
                    if fresh and memory is not None
                    else "unavailable",
                    "workloads": {
                        path: (
                            "available"
                            if fresh
                            and memory is not None
                            and any(
                                item.cgroup_path == path and usable_workload_memory(item)
                                for item in memory.workloads
                            )
                            else "unavailable"
                        )
                        for path in self.cgroup_paths
                    },
                },
                "fd_coverage": {
                    "watch": fd.watch_coverage if fresh and fd is not None else "unavailable",
                    "watch_revision": fd.watch_revision if fresh and fd is not None else None,
                    "admission_capacity": (
                        "unavailable"
                        if fd_active_count is None or fd_active_count >= MAX_ACTIVE_WATCHES
                        else (
                            "overflow"
                            if node in self.evaluator.fd.admission_overflow_nodes
                            else "available"
                        )
                    ),
                    "candidate_overflow": node in self.evaluator.fd.admission_overflow_nodes,
                    "observed": sum(
                        item.status == "present"
                        and item.descriptor_count is not None
                        and item.soft_limit is not None
                        for item in fd.observations
                    )
                    if fresh and fd is not None
                    else 0,
                    "total": len(fd.observations) if fresh and fd is not None else 0,
                    "errors": fd.errors
                    if fresh and fd is not None
                    else ["observation_not_fresh" if sample else "observation_unavailable"],
                },
                "network_coverage": {
                    "probe": network.probe.status
                    if fresh and network is not None
                    else "unavailable",
                    "route": network.probe.route_status
                    if fresh and network is not None
                    else "unavailable",
                    "route_error": network.probe.route_error
                    if fresh and network is not None
                    else "observation_not_fresh",
                    "interface_context": network.interface_coverage
                    if fresh and network is not None
                    else "unavailable",
                    "admission_capacity": (
                        "unavailable"
                        if network_active_count is None
                        or network_active_count >= MAX_ACTIVE_NETWORK_RESOURCES
                        else "available"
                    ),
                    "candidate_overflow": (node in self.evaluator.network.admission_overflow_nodes),
                    "host_counter_scope": "host_not_target_or_interface_attributed",
                    "interface_counter_scope": "interface_context_not_path_causation",
                    "errors": network.errors
                    if fresh and network is not None
                    else ["observation_not_fresh" if sample else "observation_unavailable"],
                },
                "sample": sample.model_dump(
                    mode="json",
                    exclude=set() if fresh else {"filesystems", "cpu", "memory", "fd", "network"},
                )
                if sample
                else None,
                "filesystems": [fs.model_dump() for fs in sample.filesystems]
                if sample and fresh
                else None,
                "cpu": cpu.model_dump(mode="json") if cpu is not None and fresh else None,
                "memory": memory.model_dump(mode="json") if memory is not None and fresh else None,
                "fd": fd.model_dump(mode="json") if fd is not None and fresh else None,
                "network": network.model_dump(mode="json")
                if network is not None and fresh
                else None,
            }

    def fd_watch(self, node: str) -> WatchResponse:
        with self.lock:
            snapshot = self.store.snapshot(set(self.nodes))
            self._reconcile(snapshot)
            checkpoint = snapshot.checkpoints.get(node)
            records = sorted(
                (
                    incident
                    for incident in snapshot.active
                    if incident.node_id == node and incident.rule == "fd_pressure"
                ),
                key=lambda incident: incident.resource,
            )
            if len(records) > MAX_ACTIVE_WATCHES:
                raise StoreError("durable FD watch capacity exceeded")
            watches = []
            for incident in records:
                identity = parse_resource(incident.resource)
                watches.append(
                    WatchIdentity(
                        **identity.model_dump(),
                        resource=incident.resource,
                    )
                )
            response = WatchResponse(
                node_id=node,
                revision=checkpoint.revision if checkpoint is not None else 0,
                complete=True,
                watches=watches,
            )
            if len(response.model_dump_json().encode("utf-8")) > MAX_WATCH_RESPONSE:
                raise StoreError("durable FD watch response exceeds 16KiB")
            return response


def create_app(
    nodes: dict[str, SecretStr],
    paths: tuple[str, ...] = ("/",),
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    history: HistoryClient | None = None,
    store: IncidentStore | None = None,
    config: DiskConfig | None = None,
    inode_config: InodeConfig | None = None,
    cpu_config: CpuConfig | None = None,
    oom_config: OomConfig | None = None,
    fd_config: FdConfig | None = None,
    network_config: NetworkConfig | None = None,
    cgroup_paths: tuple[str, ...] = (),
) -> FastAPI:
    if not nodes or len(nodes) > 16 or any(len(v.get_secret_value()) < 32 for v in nodes.values()):
        raise ValueError("configure 1..16 node tokens of at least 32 characters")
    if not paths or len(paths) > 8 or len(set(paths)) != len(paths):
        raise ValueError("configure 1..8 unique filesystems")
    validate_cgroup_paths(",".join(cgroup_paths))
    storage = store if store is not None else PostgresStore.environment()
    state = State(
        nodes,
        paths,
        clock,
        storage,
        config or DiskConfig(),
        inode_config or InodeConfig(),
        cpu_config or CpuConfig(),
        oom_config or OomConfig(),
        fd_config or FdConfig(),
        network_config or NetworkConfig(),
        cgroup_paths,
    )
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
            "inode_rule": state.inode_config.model_copy(
                update={
                    "block_guard_percent": min(
                        state.inode_config.block_guard_percent, state.config.trigger_percent
                    )
                }
            ).model_dump(),
            "inode_rule_requested_block_guard_percent": state.inode_config.block_guard_percent,
            "effective_inode_block_guard_percent": min(
                state.inode_config.block_guard_percent, state.config.trigger_percent
            ),
            "cpu_rule": state.cpu_config.model_dump(),
            "oom_rule": state.oom_config.model_dump(),
            "fd_rule": state.fd_config.model_dump(),
            "network_rule": state.network_config.model_dump(),
            "filesystems": list(paths),
            "cgroups": list(cgroup_paths),
            "cadence_seconds": 5,
            "ingestion_checkpoint": {
                "durable": True,
                "max_record_bytes": MAX_CHECKPOINT_BYTES,
                "fingerprints_per_node": 60,
                "retired_sessions_per_node": 8,
            },
        }

    @app.get("/health")
    def health() -> dict[str, str]:
        require_storage()
        return {
            "status": "ok",
            "storage": "incidents_and_ingestion_checkpoints_durable",
            "sample_history": "not_persisted",
            "slice": "09",
        }

    @app.get("/nodes/{node}/fd-watch")
    def fd_watch(node: str, request: Request) -> dict[str, Any]:
        token = nodes.get(node)
        auth = request.headers.get("authorization", "")
        expected = "Bearer " + token.get_secret_value() if token else ""
        if not token or not hmac.compare_digest(auth.encode(), expected.encode()):
            raise HTTPException(403, "node identity not authorized")
        return state.fd_watch(node).model_dump(mode="json")

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
        if sample.memory is not None:
            reported_cgroups = {workload.cgroup_path for workload in sample.memory.workloads} | set(
                sample.memory.workload_errors
            )
            if reported_cgroups != set(cgroup_paths):
                raise HTTPException(
                    422, "memory sample must cover exactly the configured workload cgroups"
                )
        acknowledgement = request.headers.get(ACKNOWLEDGEMENT_HEADER)
        if acknowledgement is not None and acknowledgement != ACKNOWLEDGEMENT_VERSION:
            raise HTTPException(422, "unsupported acknowledgement version")
        status = await asyncio.to_thread(state.accept, sample)
        result: dict[str, Any] = {
            "status": status,
            "durable": False,
            "incidents_durable": True,
        }
        if acknowledgement == ACKNOWLEDGEMENT_VERSION:
            result.update(
                checkpoint_durable=status in ("accepted", "duplicate"),
                identity={
                    key: value
                    for key, value in sample.model_dump(mode="json").items()
                    if key in ("node_id", "boot_id", "agent_session_id", "sequence", "observed_at")
                },
            )
        return result

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
            "Active incidents by fixed rule",
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
        inode_coverage = Gauge(
            "fleetdoctor_inode_diagnosis_coverage_ratio",
            "Required inode diagnosis sources available",
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
        cpu_gauges = {
            "busy_percent": Gauge(
                "fleetdoctor_cpu_busy_ratio",
                "Executed host CPU fraction",
                ["node"],
                registry=registry,
            ),
            "iowait_percent": Gauge(
                "fleetdoctor_cpu_iowait_ratio",
                "Host CPU iowait fraction",
                ["node"],
                registry=registry,
            ),
            "steal_percent": Gauge(
                "fleetdoctor_cpu_steal_ratio",
                "Host CPU steal fraction",
                ["node"],
                registry=registry,
            ),
            "logical_cores": Gauge(
                "fleetdoctor_cpu_logical_cores",
                "Online logical CPU count",
                ["node"],
                registry=registry,
            ),
            "runnable_processes": Gauge(
                "fleetdoctor_cpu_runnable_processes",
                "Instantaneous runnable process count",
                ["node"],
                registry=registry,
            ),
            "load_1m": Gauge(
                "fleetdoctor_cpu_load_1m", "One-minute host load", ["node"], registry=registry
            ),
            "load_5m": Gauge(
                "fleetdoctor_cpu_load_5m", "Five-minute host load", ["node"], registry=registry
            ),
            "load_15m": Gauge(
                "fleetdoctor_cpu_load_15m", "Fifteen-minute host load", ["node"], registry=registry
            ),
        }
        cpu_coverage = Gauge(
            "fleetdoctor_cpu_coverage_ratio",
            "Fraction of required CPU saturation sources available",
            ["node"],
            registry=registry,
        )
        process_coverage = Gauge(
            "fleetdoctor_cpu_process_inventory_available",
            "Bounded process inventory is available, possibly partial",
            ["node"],
            registry=registry,
        )
        host_memory_gauges = {
            "total_bytes": Gauge(
                "fleetdoctor_host_memory_total_bytes",
                "Host memory total",
                ["node"],
                registry=registry,
            ),
            "available_bytes": Gauge(
                "fleetdoctor_host_memory_available_bytes",
                "Host memory available",
                ["node"],
                registry=registry,
            ),
            "swap_total_bytes": Gauge(
                "fleetdoctor_host_swap_total_bytes", "Host swap total", ["node"], registry=registry
            ),
            "swap_free_bytes": Gauge(
                "fleetdoctor_host_swap_free_bytes", "Host swap free", ["node"], registry=registry
            ),
            "pgfault_per_second": Gauge(
                "fleetdoctor_host_pgfault_per_second",
                "Host page faults per second",
                ["node"],
                registry=registry,
            ),
            "pgmajfault_per_second": Gauge(
                "fleetdoctor_host_pgmajfault_per_second",
                "Host major page faults per second",
                ["node"],
                registry=registry,
            ),
            "swap_in_bytes_per_second": Gauge(
                "fleetdoctor_host_swap_in_bytes_per_second",
                "Host swap-in byte rate",
                ["node"],
                registry=registry,
            ),
            "swap_out_bytes_per_second": Gauge(
                "fleetdoctor_host_swap_out_bytes_per_second",
                "Host swap-out byte rate",
                ["node"],
                registry=registry,
            ),
        }
        workload_memory_gauges = {
            "current_bytes": Gauge(
                "fleetdoctor_workload_memory_current_bytes",
                "Configured cgroup memory usage",
                ["node", "cgroup"],
                registry=registry,
            ),
            "max_bytes": Gauge(
                "fleetdoctor_workload_memory_max_bytes",
                "Configured cgroup finite memory limit",
                ["node", "cgroup"],
                registry=registry,
            ),
            "usage_ratio": Gauge(
                "fleetdoctor_workload_memory_usage_ratio",
                "Configured cgroup memory usage ratio",
                ["node", "cgroup"],
                registry=registry,
            ),
            "swap_current_bytes": Gauge(
                "fleetdoctor_workload_swap_current_bytes",
                "Configured cgroup swap usage",
                ["node", "cgroup"],
                registry=registry,
            ),
            "swap_max_bytes": Gauge(
                "fleetdoctor_workload_swap_max_bytes",
                "Configured cgroup finite swap limit",
                ["node", "cgroup"],
                registry=registry,
            ),
            "oom": Gauge(
                "fleetdoctor_workload_memory_oom_total",
                "Cgroup-local cumulative OOM attempts",
                ["node", "cgroup"],
                registry=registry,
            ),
            "oom_kill": Gauge(
                "fleetdoctor_workload_memory_oom_kill_total",
                "Cgroup-local cumulative OOM kills",
                ["node", "cgroup"],
                registry=registry,
            ),
        }
        memory_coverage_g = Gauge(
            "fleetdoctor_memory_coverage_ratio",
            "Configured memory sources available",
            ["node", "scope"],
            registry=registry,
        )
        fd_pressure_g = Gauge(
            "fleetdoctor_fd_pressure_ratio",
            "Highest observed finite process FD pressure on the node",
            ["node"],
            registry=registry,
        )
        fd_count_g = Gauge(
            "fleetdoctor_fd_count",
            "Descriptor count for the node's highest-pressure observed process",
            ["node"],
            registry=registry,
        )
        fd_limit_g = Gauge(
            "fleetdoctor_fd_soft_limit",
            "Actual finite soft limit for the node's highest-pressure observed process",
            ["node"],
            registry=registry,
        )
        fd_growth_g = Gauge(
            "fleetdoctor_fd_growth_per_second",
            "Measured descriptor growth for the node's highest-pressure observed process",
            ["node"],
            registry=registry,
        )
        fd_coverage_g = Gauge(
            "fleetdoctor_fd_coverage_ratio",
            "Fraction of bounded FD identities with exact count and finite limit",
            ["node"],
            registry=registry,
        )
        fd_admission_g = Gauge(
            "fleetdoctor_fd_admission_capacity_available",
            "FD incident admission capacity is available",
            ["node"],
            registry=registry,
        )
        fd_overflow_g = Gauge(
            "fleetdoctor_fd_admission_candidate_overflow",
            "A qualifying FD candidate was rejected by the active incident cap",
            ["node"],
            registry=registry,
        )
        network_probe_coverage_g = Gauge(
            "fleetdoctor_network_probe_coverage_ratio",
            "Fresh measured three-packet probe is available",
            ["node"],
            registry=registry,
        )
        network_route_coverage_g = Gauge(
            "fleetdoctor_network_route_attribution_available",
            "Stable outgoing interface context is available",
            ["node"],
            registry=registry,
        )
        network_admission_g = Gauge(
            "fleetdoctor_network_admission_capacity_available",
            "Network incident admission capacity is available",
            ["node"],
            registry=registry,
        )
        network_overflow_g = Gauge(
            "fleetdoctor_network_admission_candidate_overflow",
            "A qualifying network candidate was rejected by the active incident cap",
            ["node"],
            registry=registry,
        )
        network_probe_gauges = {
            "loss_ratio": Gauge(
                "fleetdoctor_network_probe_loss_ratio",
                "Measured loss fraction from the current three-packet probe",
                ["node"],
                registry=registry,
            ),
            "lost": Gauge(
                "fleetdoctor_network_probe_loss_packets",
                "Measured lost packets from the current three-packet probe",
                ["node"],
                registry=registry,
            ),
            "median_rtt_ms": Gauge(
                "fleetdoctor_network_probe_median_rtt_seconds",
                "Median RTT of successful replies; absent when no reply",
                ["node"],
                registry=registry,
            ),
        }
        network_tcp_gauges = {
            "retrans_segs": Gauge(
                "fleetdoctor_network_tcp_retransmits_total",
                "Host-wide cumulative TCP retransmitted segments",
                ["node"],
                registry=registry,
            ),
            "retrans_per_second": Gauge(
                "fleetdoctor_network_tcp_retransmits_per_second",
                "Host-wide TCP retransmitted segments per second",
                ["node"],
                registry=registry,
            ),
            "curr_estab": Gauge(
                "fleetdoctor_network_tcp_curr_estab",
                "Instantaneous host TCP established connection count",
                ["node"],
                registry=registry,
            ),
        }
        network_tcp_states_g = Gauge(
            "fleetdoctor_network_tcp_state_connections",
            "Instantaneous bounded host TCP connection inventory",
            ["node", "state"],
            registry=registry,
        )
        interface_fields = ("rx_errors", "rx_dropped", "tx_errors", "tx_dropped")
        network_interface_totals = {
            field: Gauge(
                f"fleetdoctor_network_interface_{field}_total",
                f"Interface-scoped cumulative {field.replace('_', ' ')}",
                ["node", "interface"],
                registry=registry,
            )
            for field in interface_fields
        }
        network_interface_rates = {
            field: Gauge(
                f"fleetdoctor_network_interface_{field}_per_second",
                f"Interface-scoped {field.replace('_', ' ')} per second",
                ["node", "interface"],
                registry=registry,
            )
            for field in interface_fields
        }
        try:
            views = {node: state.view(node, include_counts=storage_ok) for node in nodes}
        except StoreError:
            storage_ok = False
            views = {node: state.view(node, include_counts=False) for node in nodes}
        storage_g.set(int(storage_ok))
        for node, view in views.items():
            if storage_ok:
                for rule, count in view["active_incident_counts"].items():
                    active_g.labels(node, rule).set(count)
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
                inode_coverage.labels(node, path).set(
                    int(view["inode_diagnosis_coverage"].get(path) == "available")
                )
            for fs in view["filesystems"] or []:
                for field, gauge in gauges.items():
                    value = fs[field]
                    if value is not None:
                        gauge.labels(node, fs["mountpoint"]).set(
                            value / 100 if field.endswith("percent") else value
                        )
            available_sources = sum(
                view["cpu_coverage"][name] == "available"
                for name in ("host_rates", "runnable", "logical_cores")
            )
            cpu_coverage.labels(node).set(available_sources / 3 if view["fresh"] else 0)
            process_coverage.labels(node).set(
                int(view["cpu_coverage"]["process_inventory"] in ("complete", "partial"))
            )
            if view["cpu"] is not None:
                for field, gauge in cpu_gauges.items():
                    value = view["cpu"][field]
                    if value is not None:
                        gauge.labels(node).set(value / 100 if field.endswith("percent") else value)
            memory = view["memory"]
            memory_coverage_g.labels(node, "host").set(
                int(view["memory_coverage"]["host"] == "available")
            )
            memory_coverage_g.labels(node, "kernel_logs").set(
                int(view["memory_coverage"]["kernel_logs"] in ("available", "baseline"))
            )
            for cgroup in cgroup_paths:
                memory_coverage_g.labels(node, cgroup).set(
                    int(view["memory_coverage"]["workloads"].get(cgroup) == "available")
                )
            if memory is not None:
                for field, gauge in host_memory_gauges.items():
                    value = memory["host"][field]
                    if value is not None:
                        gauge.labels(node).set(value)
                for workload in memory["workloads"]:
                    cgroup = workload["cgroup_path"]
                    if view["memory_coverage"]["workloads"].get(cgroup) != "available":
                        continue
                    for field, gauge in workload_memory_gauges.items():
                        value = (
                            workload["events"].get(field)
                            if field in ("oom", "oom_kill") and workload["events"] is not None
                            else workload.get(field)
                        )
                        if value is not None:
                            gauge.labels(node, cgroup).set(value)
            fd_coverage = view["fd_coverage"]
            fd_coverage_g.labels(node).set(
                fd_coverage["observed"] / fd_coverage["total"]
                if view["fresh"] and fd_coverage["total"]
                else 0
            )
            fd_admission_g.labels(node).set(int(fd_coverage["admission_capacity"] == "available"))
            fd_overflow_g.labels(node).set(int(fd_coverage["candidate_overflow"]))
            if view["fd"] is not None:
                exact = [
                    item
                    for item in view["fd"]["observations"]
                    if item["pressure_ratio"] is not None
                    and item["descriptor_count"] is not None
                    and item["soft_limit"] is not None
                ]
                if exact:
                    highest = max(exact, key=lambda item: item["pressure_ratio"])
                    fd_pressure_g.labels(node).set(highest["pressure_ratio"])
                    fd_count_g.labels(node).set(highest["descriptor_count"])
                    fd_limit_g.labels(node).set(highest["soft_limit"])
                    if highest["growth_per_second"] is not None:
                        fd_growth_g.labels(node).set(highest["growth_per_second"])
            network_coverage = view["network_coverage"]
            network_probe_coverage_g.labels(node).set(
                int(view["fresh"] and network_coverage["probe"] == "available")
            )
            network_route_coverage_g.labels(node).set(
                int(view["fresh"] and network_coverage["route"] == "available")
            )
            network_admission_g.labels(node).set(
                int(network_coverage["admission_capacity"] == "available")
            )
            network_overflow_g.labels(node).set(int(network_coverage["candidate_overflow"]))
            network = view["network"]
            if network is not None:
                probe = network["probe"]
                if probe["status"] == "available":
                    for field in ("loss_ratio", "lost"):
                        network_probe_gauges[field].labels(node).set(probe[field])
                    if probe["median_rtt_ms"] is not None:
                        network_probe_gauges["median_rtt_ms"].labels(node).set(
                            probe["median_rtt_ms"] / 1000
                        )
                tcp = network["tcp"]
                for field, gauge in network_tcp_gauges.items():
                    if tcp[field] is not None:
                        gauge.labels(node).set(tcp[field])
                for state_name, count in tcp["state_counts"].items():
                    network_tcp_states_g.labels(node, state_name).set(count)
                for interface in network["interfaces"]:
                    name = interface["name"]
                    for field in interface_fields:
                        network_interface_totals[field].labels(node, name).set(interface[field])
                        rate = interface[field + "_per_second"]
                        if rate is not None:
                            network_interface_rates[field].labels(node, name).set(rate)
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
        inode_config=InodeConfig.model_validate_json(os.getenv("FLEETDOCTOR_INODE_RULE", "{}")),
        cpu_config=CpuConfig.model_validate_json(os.getenv("FLEETDOCTOR_CPU_RULE", "{}")),
        oom_config=OomConfig.model_validate_json(os.getenv("FLEETDOCTOR_OOM_RULE", "{}")),
        fd_config=FdConfig.model_validate_json(os.getenv("FLEETDOCTOR_FD_RULE", "{}")),
        network_config=NetworkConfig.model_validate_json(
            os.getenv("FLEETDOCTOR_NETWORK_RULE", "{}")
        ),
        cgroup_paths=validate_cgroup_paths(os.getenv("FLEETDOCTOR_CGROUPS", "")),
    )
