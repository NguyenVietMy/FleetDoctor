"""Bounded direct-PID file-descriptor collection and durable watch contracts."""

import multiprocessing as mp
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from fleetdoctor.cpu import MAX_READ, parse_process_stat
from fleetdoctor.schema import (
    CpuObservation,
    FdObservation,
    FdProcessIdentity,
    FdProcessObservation,
    ProcessObservation,
)

MAX_CONFIGURED_PIDS = 16
MAX_SELECTED_IDENTITIES = 36
MAX_ACTIVE_WATCHES = 32
MAX_FD_IDENTITIES = 68
MAX_FD_ENTRIES = 4096
FD_COLLECTION_BUDGET = 0.65
FD_WORKER_BUDGET = 0.75
MAX_WATCH_RESPONSE = 16_384
RESOURCE_PATTERN = re.compile(r"^boot:([0-9a-f-]{36})/pid:([1-9][0-9]{0,9})/start:([0-9]{1,20})$")


class WatchIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    boot_id: UUID
    pid: int = Field(ge=1, le=2**31 - 1, strict=True)
    starttime_ticks: int = Field(ge=0, le=2**64 - 1, strict=True)
    resource: str = Field(min_length=1, max_length=128)

    def as_identity(self) -> FdProcessIdentity:
        return FdProcessIdentity(
            boot_id=self.boot_id, pid=self.pid, starttime_ticks=self.starttime_ticks
        )

    @model_validator(mode="after")
    def consistent_resource(self) -> "WatchIdentity":
        if self.as_identity().resource != self.resource:
            raise ValueError("watch resource and identity disagree")
        return self


class WatchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    revision: int = Field(ge=0, le=2**64 - 1, strict=True)
    complete: Literal[True] = True
    watches: list[WatchIdentity] = Field(max_length=MAX_ACTIVE_WATCHES)


def parse_resource(resource: str) -> FdProcessIdentity:
    match = RESOURCE_PATTERN.fullmatch(resource)
    if not match:
        raise ValueError("invalid FD resource identity")
    identity = FdProcessIdentity(
        boot_id=UUID(match.group(1)),
        pid=int(match.group(2)),
        starttime_ticks=int(match.group(3)),
    )
    if identity.resource != resource:
        raise ValueError("noncanonical FD resource identity")
    return identity


def parse_soft_limit(text: str) -> tuple[int | None, bool]:
    for line in text.splitlines():
        if not line.startswith("Max open files"):
            continue
        fields = line[len("Max open files") :].split()
        if len(fields) < 2:
            break
        if fields[0] == "unlimited":
            return None, True
        value = int(fields[0])
        if value <= 0 or value > 2**64 - 1:
            raise ValueError("invalid open-file soft limit")
        return value, False
    raise ValueError("missing open-file soft limit")


@dataclass(frozen=True)
class Candidate:
    identity: FdProcessIdentity
    configured: bool
    watched: bool
    cpu: ProcessObservation | None = None


class FdCollector:
    def __init__(
        self,
        proc: Path = Path("/proc"),
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.proc = proc
        self.clock = clock
        self.baselines: dict[str, tuple[int, float]] = {}

    def _read(self, path: Path) -> str:
        with path.open("rb") as stream:
            body = stream.read(MAX_READ + 1)
        if len(body) > MAX_READ:
            raise ValueError("proc source exceeds read bound")
        return body.decode("utf-8", errors="strict")

    def _current_identity(self, boot: UUID, pid: int) -> tuple[FdProcessIdentity, str, str]:
        text = self._read(self.proc / str(pid) / "stat")
        stat = parse_process_stat(text)
        closing = text.rfind(")")
        state = text[closing + 2 :].split()[0]
        return (
            FdProcessIdentity(boot_id=boot, pid=pid, starttime_ticks=stat.starttime),
            stat.comm,
            state,
        )

    def _configured_candidate(
        self, boot: UUID, pid: int, cpu_by_pid: dict[int, ProcessObservation]
    ) -> Candidate | None:
        cpu = cpu_by_pid.get(pid)
        if cpu is not None:
            return Candidate(
                FdProcessIdentity(
                    boot_id=boot,
                    pid=cpu.identity.pid,
                    starttime_ticks=cpu.identity.starttime_ticks,
                ),
                configured=True,
                watched=False,
                cpu=cpu,
            )
        try:
            identity, _, state = self._current_identity(boot, pid)
        except (OSError, UnicodeError, ValueError, ValidationError):
            return None
        return Candidate(identity, configured=True, watched=False) if state != "Z" else None

    def _count_fds(self, path: Path, deadline: float) -> int:
        count = 0
        with os.scandir(path) as entries:
            for entry in entries:
                if self.clock() > deadline:
                    raise TimeoutError("FD enumeration deadline")
                if entry.name.isdigit():
                    count += 1
                if count > MAX_FD_ENTRIES:
                    raise OverflowError("FD enumeration cap")
        return count

    def _probe(
        self, candidate: Candidate, current_boot: UUID, deadline: float
    ) -> FdProcessObservation | None:
        identity = candidate.identity
        if identity.boot_id != current_boot:
            self.baselines.pop(identity.resource, None)
            return FdProcessObservation(identity=identity, status="replaced", watched=True)
        try:
            before, comm, state = self._current_identity(current_boot, identity.pid)
        except FileNotFoundError:
            self.baselines.pop(identity.resource, None)
            return (
                FdProcessObservation(identity=identity, status="exited", watched=True)
                if candidate.watched
                else None
            )
        except (PermissionError, OSError, UnicodeError, ValueError, ValidationError) as exc:
            self.baselines.pop(identity.resource, None)
            if not candidate.watched:
                return None
            return FdProcessObservation(
                identity=identity,
                status="unknown",
                watched=candidate.watched,
                errors=[f"stat_{type(exc).__name__}"],
            )
        if before != identity:
            self.baselines.pop(identity.resource, None)
            if not candidate.watched:
                return None
            return FdProcessObservation(
                identity=identity, status="replaced", watched=candidate.watched
            )
        if state == "Z":
            self.baselines.pop(identity.resource, None)
            if not candidate.watched:
                return None
            return FdProcessObservation(
                identity=identity,
                status="exited",
                watched=candidate.watched,
                errors=["process_zombie_terminated"],
            )
        errors: list[str] = []
        count = limit = None
        unlimited = False
        try:
            limit, unlimited = parse_soft_limit(
                self._read(self.proc / str(identity.pid) / "limits")
            )
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append(f"limit_{type(exc).__name__}")
        try:
            count = self._count_fds(self.proc / str(identity.pid) / "fd", deadline)
        except (OSError, TimeoutError, OverflowError) as exc:
            errors.append(f"count_{type(exc).__name__}")
        try:
            after, _, after_state = self._current_identity(current_boot, identity.pid)
            if after != identity:
                raise RuntimeError("identity changed during FD collection")
            if after_state == "Z":
                self.baselines.pop(identity.resource, None)
                if not candidate.watched:
                    return None
                return FdProcessObservation(
                    identity=identity,
                    status="exited",
                    watched=True,
                    configured=candidate.configured,
                    errors=["process_zombie_terminated"],
                )
        except (OSError, UnicodeError, ValueError, ValidationError, RuntimeError) as exc:
            self.baselines.pop(identity.resource, None)
            if not candidate.watched:
                return None
            return FdProcessObservation(
                identity=identity,
                status="unknown",
                watched=candidate.watched,
                errors=[f"identity_recheck_{type(exc).__name__}"],
            )
        now = self.clock()
        delta = None
        growth = interval = None
        previous = self.baselines.get(identity.resource)
        if count is not None:
            if previous is not None and 0 < (now - previous[1]) <= 10:
                interval = now - previous[1]
                delta = count - previous[0]
                growth = delta / interval
            self.baselines[identity.resource] = (count, now)
        else:
            self.baselines.pop(identity.resource, None)
        pressure = count / limit if count is not None and limit is not None and limit > 0 else None
        return FdProcessObservation(
            identity=identity,
            status="present",
            watched=candidate.watched,
            configured=candidate.configured,
            comm=comm,
            descriptor_count=count,
            soft_limit=limit,
            limit_unlimited=unlimited,
            pressure_ratio=pressure,
            count_delta=delta,
            growth_per_second=growth,
            growth_interval_seconds=interval,
            cpu_percent=candidate.cpu.cpu_percent if candidate.cpu else None,
            rss_bytes=candidate.cpu.rss_bytes if candidate.cpu else None,
            errors=errors,
        )

    def collect(
        self,
        boot: UUID,
        cpu: CpuObservation,
        configured_pids: tuple[int, ...],
        watches: tuple[WatchIdentity, ...],
        watch_coverage: Literal["available", "degraded", "unavailable"],
        watch_revision: int | None,
        watch_error: str | None,
    ) -> FdObservation:
        if len(configured_pids) > MAX_CONFIGURED_PIDS or len(set(configured_pids)) != len(
            configured_pids
        ):
            raise ValueError("configure at most 16 unique process IDs")
        if len(watches) > MAX_ACTIVE_WATCHES:
            raise ValueError("FD watch response exceeds capacity")
        started = self.clock()
        cpu_by_resource = {
            FdProcessIdentity(
                boot_id=boot,
                pid=item.identity.pid,
                starttime_ticks=item.identity.starttime_ticks,
            ).resource: item
            for item in cpu.processes
        }
        cpu_by_pid = {item.identity.pid: item for item in cpu.processes}
        candidates: dict[str, Candidate] = {}
        for watch in watches:
            identity = watch.as_identity()
            candidates[identity.resource] = Candidate(
                identity,
                configured=identity.pid in configured_pids,
                watched=True,
                cpu=cpu_by_resource.get(identity.resource),
            )
        for pid in sorted(configured_pids):
            candidate = self._configured_candidate(boot, pid, cpu_by_pid)
            if candidate is not None:
                existing = candidates.get(candidate.identity.resource)
                candidates[candidate.identity.resource] = Candidate(
                    candidate.identity,
                    configured=True,
                    watched=bool(existing and existing.watched),
                    cpu=candidate.cpu or (existing.cpu if existing else None),
                )
        for item in cpu.processes[:MAX_SELECTED_IDENTITIES]:
            identity = FdProcessIdentity(
                boot_id=boot,
                pid=item.identity.pid,
                starttime_ticks=item.identity.starttime_ticks,
            )
            existing = candidates.get(identity.resource)
            candidates[identity.resource] = Candidate(
                identity,
                configured=item.configured or bool(existing and existing.configured),
                watched=bool(existing and existing.watched),
                cpu=item,
            )
        ordered = sorted(
            candidates.values(),
            key=lambda item: (
                not item.watched,
                not item.configured,
                str(item.identity.boot_id),
                item.identity.pid,
                item.identity.starttime_ticks,
            ),
        )[:MAX_FD_IDENTITIES]
        observations: list[FdProcessObservation] = []
        deadline = started + FD_COLLECTION_BUDGET
        for candidate in ordered:
            if self.clock() > deadline:
                if candidate.watched:
                    observations.append(
                        FdProcessObservation(
                            identity=candidate.identity,
                            status="unknown",
                            watched=True,
                            configured=candidate.configured,
                            errors=["collection_budget"],
                        )
                    )
                continue
            result = self._probe(candidate, boot, deadline)
            if result is not None:
                observations.append(result)
        retained = {item.identity.resource for item in observations if item.status == "present"}
        self.baselines = {
            resource: value for resource, value in self.baselines.items() if resource in retained
        }
        errors = [watch_error] if watch_error else []
        values: dict[str, Any] = {
            "observations": observations,
            "watch_coverage": watch_coverage,
            "watch_revision": watch_revision,
            "selected_identities": min(len(cpu.processes), MAX_SELECTED_IDENTITIES),
            "configured_pids": len(configured_pids),
            "errors": errors,
        }
        try:
            return FdObservation(**values)
        except ValidationError as exc:
            if "24KiB" not in str(exc):
                raise
        compact = [
            FdProcessObservation(
                identity=item.identity,
                status=item.status,
                watched=item.watched,
                configured=item.configured,
                descriptor_count=item.descriptor_count,
                soft_limit=item.soft_limit,
                limit_unlimited=item.limit_unlimited,
                pressure_ratio=item.pressure_ratio,
                errors=item.errors,
            )
            for item in observations
        ]
        compact_errors = [*errors, "payload_budget"][:8]
        while True:
            try:
                return FdObservation(
                    observations=compact,
                    watch_coverage=watch_coverage,
                    watch_revision=watch_revision,
                    selected_identities=min(len(cpu.processes), MAX_SELECTED_IDENTITIES),
                    configured_pids=len(configured_pids),
                    context_trimmed=True,
                    errors=compact_errors,
                )
            except ValidationError as exc:
                if "24KiB" not in str(exc):
                    raise
                removable = next(
                    (
                        index
                        for index in range(len(compact) - 1, -1, -1)
                        if not compact[index].watched
                    ),
                    None,
                )
                if removable is None:
                    raise ValueError("required watched FD statuses exceed 24KiB") from exc
                compact.pop(removable)


def _worker(conn: Connection) -> None:
    collector = FdCollector()
    try:
        conn.send("ready")
        while True:
            payload = conn.recv()
            result = collector.collect(
                UUID(payload["boot"]),
                CpuObservation.model_validate(payload["cpu"]),
                tuple(payload["configured_pids"]),
                tuple(WatchIdentity.model_validate(value) for value in payload["watches"]),
                payload["watch_coverage"],
                payload["watch_revision"],
                payload["watch_error"],
            )
            conn.send(result.model_dump())
    except (EOFError, BrokenPipeError):
        pass
    finally:
        conn.close()


class FdCollectionWorker:
    def __init__(self, target: Callable[[Connection], None] = _worker) -> None:
        self.process: Any = None
        self.conn: Connection | None = None
        self.ready = False
        self.target = target

    def start(self) -> None:
        if self.process is not None:
            return
        context = mp.get_context("spawn")
        self.conn, child = context.Pipe()
        self.process = context.Process(target=self.target, args=(child,), daemon=True)
        self.process.start()
        child.close()

    def wait_ready(self, timeout: float = 0) -> bool:
        self.start()
        if not self.ready and self.conn is not None and self.conn.poll(timeout):
            try:
                self.ready = self.conn.recv() == "ready"
            except (OSError, EOFError):
                self.close()
        return self.ready

    def close(self) -> None:
        self.ready = False
        if self.process is not None:
            self.process.terminate()
            self.process.join(timeout=0.05)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(timeout=0.05)
            if not self.process.is_alive():
                self.process.close()
                self.process = None
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    @staticmethod
    def unavailable(
        watches: tuple[WatchIdentity, ...],
        configured_pids: tuple[int, ...],
        watch_revision: int | None,
        watch_error: str | None,
        worker_error: str,
    ) -> FdObservation:
        errors = [worker_error]
        if watch_error is not None and watch_error not in errors:
            errors.append(watch_error)
        return FdObservation(
            observations=[
                FdProcessObservation(
                    identity=item.as_identity(),
                    status="unknown",
                    watched=True,
                    configured=item.pid in configured_pids,
                    errors=[worker_error],
                )
                for item in watches
            ],
            watch_coverage="degraded" if watches else "unavailable",
            watch_revision=watch_revision,
            configured_pids=len(configured_pids),
            errors=errors,
        )

    def collect(
        self,
        boot: UUID,
        cpu: CpuObservation,
        configured_pids: tuple[int, ...],
        watches: tuple[WatchIdentity, ...],
        watch_coverage: Literal["available", "degraded", "unavailable"],
        watch_revision: int | None,
        watch_error: str | None,
        budget: float = FD_WORKER_BUDGET,
    ) -> FdObservation:
        if self.process is not None and self.conn is None:
            if self.process.is_alive():
                return self.unavailable(
                    watches,
                    configured_pids,
                    watch_revision,
                    watch_error,
                    "fd_collection_worker_stuck",
                )
            self.process.close()
            self.process = None
        if not self.wait_ready():
            return self.unavailable(
                watches,
                configured_pids,
                watch_revision,
                watch_error,
                "fd_collection_worker_starting",
            )
        try:
            if self.conn is None:
                raise TimeoutError
            self.conn.send(
                {
                    "boot": str(boot),
                    "cpu": cpu.model_dump(),
                    "configured_pids": configured_pids,
                    "watches": [item.model_dump(mode="json") for item in watches],
                    "watch_coverage": watch_coverage,
                    "watch_revision": watch_revision,
                    "watch_error": watch_error,
                }
            )
            if not self.conn.poll(budget):
                raise TimeoutError
            return FdObservation.model_validate(self.conn.recv())
        except (TimeoutError, OSError, EOFError, ValidationError):
            self.close()
            return self.unavailable(
                watches,
                configured_pids,
                watch_revision,
                watch_error,
                "fd_collection_timeout",
            )
