"""One spawned process supervising all production collectors."""

from __future__ import annotations

import json
import os
import signal
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any, Literal
from uuid import UUID

from pydantic import ValidationError

from fleetdoctor.collection import collect_filesystem
from fleetdoctor.cpu import CpuCollector
from fleetdoctor.fd import FdCollectionWorker, FdCollector, WatchIdentity
from fleetdoctor.memory import MemoryCollector
from fleetdoctor.network import (
    NetworkCollectionWorker,
    NetworkCollector,
    _FrameTimeout,
    _group_members,
    _proc_identity,
    _receive_bytes_deadline,
)
from fleetdoctor.schema import (
    CpuObservation,
    FdObservation,
    Filesystem,
    HostMemoryObservation,
    MemoryObservation,
    NetworkObservation,
)

RESULT_LIMIT = 65536
FRAME_LIMIT = 70000
TEARDOWN_RESERVE = 0.5
TERM_GRACE = 0.15


@dataclass(frozen=True)
class SupervisorResult:
    filesystems: list[Filesystem]
    cpu: CpuObservation
    memory: MemoryObservation
    fd: FdObservation
    network: NetworkObservation


def _stop(_signum: int, _frame: object) -> None:
    raise SystemExit


def _dump(value: Any) -> Any:
    if isinstance(value, list):
        return [item.model_dump(mode="json") for item in value]
    return value.model_dump(mode="json")


def _send_frame(conn: Connection, message: dict[str, Any]) -> None:
    encoded = json.dumps(message, separators=(",", ":")).encode()
    if len(encoded) > FRAME_LIMIT:
        raise ValueError("collection_supervisor_frame_oversize")
    conn.send_bytes(encoded)


def _receive_frame(conn: Connection, deadline: float | None = None) -> dict[str, Any]:
    encoded = (
        conn.recv_bytes(FRAME_LIMIT)
        if deadline is None
        else _receive_bytes_deadline(conn, FRAME_LIMIT, deadline)
    )
    decoded = json.loads(encoded)
    if not isinstance(decoded, dict):
        raise ValueError("collection_supervisor_frame_not_object")
    return decoded


def _collect_filesystems(paths: tuple[str, ...]) -> list[Filesystem]:
    return [collect_filesystem(path) for path in paths]


def _supervisor_worker(conn: Connection) -> None:
    os.setsid()
    signal.signal(signal.SIGTERM, _stop)
    cpu_collector = CpuCollector()
    memory_collector = MemoryCollector()
    fd_collector = FdCollector()
    network_collector = NetworkCollector()
    identity = _proc_identity(os.getpid())
    _send_frame(
        conn,
        {
            "ready": True,
            "pid": os.getpid(),
            "pgid": os.getpgrp(),
            "starttime": identity[2] if identity else None,
        },
    )
    try:
        while True:
            request = _receive_frame(conn)
            if not isinstance(request.get("token"), dict):
                raise ValueError("collection_supervisor_request_identity")
            token = request["token"]
            executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fleetdoctor")
            paths = tuple(request["paths"])
            futures: dict[Future[Any], str] = {
                executor.submit(_collect_filesystems, paths): "filesystem",
                executor.submit(cpu_collector.collect, tuple(request["configured_pids"])): "cpu",
                executor.submit(memory_collector.collect, tuple(request["cgroups"])): "memory",
                executor.submit(network_collector.collect, request["network_target"]): "network",
            }
            completed: set[str] = set()
            fd_submitted = False
            try:
                while len(completed) < 5:
                    done, _ = wait(futures, timeout=0.05, return_when=FIRST_COMPLETED)
                    for future in done:
                        result_kind = futures.pop(future)
                        try:
                            value = future.result()
                            payload = _dump(value)
                            if (
                                len(json.dumps(payload, separators=(",", ":")).encode())
                                > RESULT_LIMIT
                            ):
                                raise ValueError("supervisor_result_oversize")
                            _send_frame(
                                conn,
                                {
                                    "kind": "result",
                                    "token": token,
                                    "result_kind": result_kind,
                                    "payload": payload,
                                },
                            )
                            if result_kind == "cpu" and not fd_submitted:
                                futures[
                                    executor.submit(
                                        fd_collector.collect,
                                        UUID(request["boot"]),
                                        value,
                                        tuple(request["configured_pids"]),
                                        tuple(
                                            WatchIdentity.model_validate(item)
                                            for item in request["watches"]
                                        ),
                                        request["watch_coverage"],
                                        request["watch_revision"],
                                        request["watch_error"],
                                    )
                                ] = "fd"
                                fd_submitted = True
                        except (OSError, ValueError, ValidationError) as exc:
                            _send_frame(
                                conn,
                                {
                                    "kind": "error",
                                    "token": token,
                                    "result_kind": result_kind,
                                    "error": type(exc).__name__,
                                },
                            )
                        completed.add(result_kind)
                    if "cpu" in completed and not fd_submitted:
                        _send_frame(
                            conn,
                            {
                                "kind": "error",
                                "token": token,
                                "result_kind": "fd",
                                "error": "cpu_dependency_unavailable",
                            },
                        )
                        completed.add("fd")
                        fd_submitted = True
                executor.shutdown(wait=True)
                _send_frame(conn, {"kind": "complete", "token": token})
            except BaseException:
                executor.shutdown(wait=False, cancel_futures=True)
                raise
    except (EOFError, BrokenPipeError, json.JSONDecodeError, ValueError):
        pass
    finally:
        conn.close()


class CollectionSupervisor(NetworkCollectionWorker):
    """Streams independently completed typed facts from one owned process group."""

    def __init__(self, target: Any = _supervisor_worker) -> None:
        super().__init__(target)

    def wait_ready(self, timeout: float = 0) -> bool:
        self.start()
        if not self.ready and self.conn is not None:
            deadline = time.monotonic() + max(0.0, timeout)
            try:
                response = _receive_frame(self.conn, deadline)
                pid = self.process.pid if self.process is not None else None
                identity = _proc_identity(pid) if pid is not None else None
                self.ready = bool(
                    response.get("ready") is True
                    and response.get("pid") == pid == response.get("pgid")
                    and identity == (pid, pid, response.get("starttime"))
                )
                if self.ready and identity is not None:
                    self.pgid = pid
                    self.starttime = identity[2]
                else:
                    self.close()
            except _FrameTimeout as exc:
                if exc.partial:
                    self.close()
            except (EOFError, OSError, ValueError, json.JSONDecodeError):
                self.close()
        return self.ready

    def close(self, deadline: float | None = None) -> None:
        was_stuck = self.stuck
        self.ready = False
        process = self.process
        if process is None:
            return
        deadline = deadline or (time.monotonic() + TEARDOWN_RESERVE)
        pid = process.pid
        identity = _proc_identity(pid) if pid is not None else None
        observed_pgid = self.pgid
        if (
            pid is not None
            and observed_pgid is None
            and self.starttime is not None
            and identity == (pid, pid, self.starttime)
        ):
            observed_pgid = pid
        authorized = bool(
            pid is not None
            and observed_pgid == pid
            and self.starttime is not None
            and identity == (pid, pid, self.starttime)
        )
        if authorized:
            members = _group_members(pid)
            authorized = members is not None and members.get(pid) == self.starttime
        owned_members = members or {} if authorized else {}
        if authorized:
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            process.join(max(0.0, min(TERM_GRACE, deadline - time.monotonic())))
            survivors = _group_members(pid)
            if survivors and time.monotonic() < deadline:
                if any(owned_members.get(member) != start for member, start in survivors.items()):
                    self.stuck = True
                else:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.join(max(0.0, deadline - time.monotonic()))
            remaining = _group_members(pid)
            self.stuck = process.is_alive() or remaining != {}
        else:
            pid_owned = bool(
                pid is not None
                and self.pgid is None
                and self.starttime is not None
                and identity is not None
                and identity[2] == self.starttime
            )
            if process.is_alive() and pid_owned and time.monotonic() < deadline:
                process.terminate()
                process.join(max(0.0, min(TERM_GRACE, deadline - time.monotonic())))
                if process.is_alive() and time.monotonic() < deadline:
                    process.kill()
                    process.join(max(0.0, deadline - time.monotonic()))
            self.stuck = process.is_alive() or (was_stuck and not pid_owned)
        if not self.stuck and not process.is_alive():
            process.close()
            self.process = None
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        if not self.stuck:
            self.pgid = None
            self.starttime = None

    @staticmethod
    def _validate(result_kind: str, payload: Any) -> Any:
        if result_kind == "filesystem":
            if not isinstance(payload, list) or len(payload) > 16:
                raise ValueError("invalid filesystem result")
            return [Filesystem.model_validate(item) for item in payload]
        if result_kind == "cpu":
            return CpuObservation.model_validate(payload)
        if result_kind == "memory":
            return MemoryObservation.model_validate(payload)
        if result_kind == "fd":
            return FdObservation.model_validate(payload)
        if result_kind == "network":
            return NetworkObservation.model_validate(payload)
        raise ValueError("unknown result kind")

    @staticmethod
    def _fallback(
        paths: tuple[str, ...],
        cgroups: tuple[str, ...],
        watches: tuple[WatchIdentity, ...],
        configured: tuple[int, ...],
        revision: int | None,
        watch_error: str | None,
        target: str | None,
        error: str,
    ) -> SupervisorResult:
        return SupervisorResult(
            [Filesystem(mountpoint=path, errors=[error]) for path in paths],
            CpuObservation(errors=[error]),
            MemoryObservation(
                host=HostMemoryObservation(errors=[error]),
                workload_errors={path: [error] for path in cgroups},
            ),
            FdCollectionWorker.unavailable(watches, configured, revision, watch_error, error),
            NetworkObservation.unavailable(target, error),
        )

    def collect_all(
        self,
        boot: UUID,
        session: UUID,
        sequence: int,
        paths: tuple[str, ...],
        configured: tuple[int, ...],
        cgroups: tuple[str, ...],
        watches: tuple[WatchIdentity, ...],
        watch_coverage: Literal["available", "degraded", "unavailable"],
        revision: int | None,
        watch_error: str | None,
        target: str | None,
        budget: float = 3.0,
    ) -> SupervisorResult:
        started = time.monotonic()
        deadline = started + budget
        error = "collection_supervisor_stuck" if self.stuck else "collection_supervisor_starting"
        if self.stuck or not self.wait_ready(min(0.2, budget)):
            if self.conn is None and self.process is not None:
                self.close(deadline)
            return self._fallback(
                paths, cgroups, watches, configured, revision, watch_error, target, error
            )
        token = {"boot": str(boot), "session": str(session), "sequence": sequence}
        results: dict[str, Any] = {}
        complete = False
        try:
            if self.conn is None:
                raise OSError
            _send_frame(
                self.conn,
                {
                    "token": token,
                    "boot": str(boot),
                    "paths": paths,
                    "configured_pids": configured,
                    "cgroups": cgroups,
                    "watches": [item.model_dump(mode="json") for item in watches],
                    "watch_coverage": watch_coverage,
                    "watch_revision": revision,
                    "watch_error": watch_error,
                    "network_target": target,
                },
            )
            response_deadline = deadline - TEARDOWN_RESERVE
            while time.monotonic() < response_deadline and not complete:
                message = _receive_frame(self.conn, response_deadline)
                if message.get("token") != token:
                    raise ValueError("collection_supervisor_identity_mismatch")
                kind = message.get("kind")
                result_kind = message.get("result_kind")
                if kind == "complete":
                    complete = True
                elif (
                    not isinstance(result_kind, str)
                    or result_kind in results
                    or result_kind not in {"filesystem", "cpu", "memory", "fd", "network"}
                ):
                    raise ValueError("collection_supervisor_duplicate_or_unknown_result")
                elif kind == "result":
                    try:
                        results[result_kind] = self._validate(result_kind, message.get("payload"))
                    except (TypeError, ValueError, ValidationError):
                        results[result_kind] = None
                elif kind == "error":
                    results[result_kind] = None
                else:
                    raise ValueError("collection_supervisor_invalid_message")
        except (ValueError, json.JSONDecodeError):
            results.clear()
        except (EOFError, OSError):
            pass
        if not complete or set(results) != {"filesystem", "cpu", "memory", "fd", "network"}:
            self.close(deadline)
        fallback = self._fallback(
            paths,
            cgroups,
            watches,
            configured,
            revision,
            watch_error,
            target,
            "collection_supervisor_timeout",
        )
        try:
            cpu = results.get("cpu") or fallback.cpu
            return SupervisorResult(
                results.get("filesystem") or fallback.filesystems,
                cpu,
                results.get("memory") or fallback.memory,
                results["fd"]
                if results.get("fd") is not None and results.get("cpu") is not None
                else FdCollectionWorker.unavailable(
                    watches,
                    configured,
                    revision,
                    watch_error,
                    "fd_cpu_dependency_unavailable"
                    if results.get("cpu") is None
                    else "collection_supervisor_timeout",
                ),
                results.get("network") or fallback.network,
            )
        except (KeyError, TypeError, ValidationError):
            self.close()
            return fallback
