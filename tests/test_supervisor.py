from __future__ import annotations

import json
import os
import struct
import time
from collections.abc import Callable
from typing import Any
from uuid import uuid4

import pytest

import fleetdoctor.supervisor as supervisor_module
from fleetdoctor.network import _group_members, _proc_identity
from fleetdoctor.schema import (
    CpuObservation,
    FdObservation,
    Filesystem,
    HostMemoryObservation,
    MemoryObservation,
    NetworkObservation,
)
from fleetdoctor.supervisor import CollectionSupervisor, _receive_frame, _send_frame


class FakeConnection:
    def __init__(self, build: Callable[[dict[str, Any]], list[Any]]) -> None:
        self.build = build
        self.messages: list[Any] = []
        self.request: dict[str, Any] | None = None

    def send_bytes(self, encoded: bytes) -> None:
        request = json.loads(encoded)
        self.request = request
        self.messages = self.build(request)

    def poll(self, _timeout: float = 0) -> bool:
        return bool(self.messages)

    def recv_bytes(self, maxlength: int) -> bytes:
        encoded = json.dumps(self.messages.pop(0), separators=(",", ":")).encode()
        if len(encoded) > maxlength:
            raise OSError("frame too large")
        return encoded


def payloads() -> dict[str, Any]:
    return {
        "filesystem": [Filesystem(mountpoint="/", errors=["diagnostic"]).model_dump(mode="json")],
        "cpu": CpuObservation(errors=["diagnostic"]).model_dump(mode="json"),
        "memory": MemoryObservation(host=HostMemoryObservation(errors=["diagnostic"])).model_dump(
            mode="json"
        ),
        "fd": FdObservation(errors=["diagnostic"]).model_dump(mode="json"),
        "network": NetworkObservation.unavailable("10.0.0.10", "diagnostic").model_dump(
            mode="json"
        ),
    }


def _partial_frame(kind: str) -> bytes:
    header = struct.pack("!i", 4096)
    return header[:2] if kind == "header" else header + b"{"


def _partial_ready(conn: Any, kind: str) -> None:
    os.setsid()
    os.write(conn.fileno(), _partial_frame(kind))
    time.sleep(30)


def partial_ready_header(conn: Any) -> None:
    _partial_ready(conn, "header")


def partial_ready_body(conn: Any) -> None:
    _partial_ready(conn, "body")


def _partial_result(conn: Any, kind: str) -> None:
    os.setsid()
    identity = _proc_identity(os.getpid())
    assert identity is not None
    _send_frame(
        conn,
        {
            "ready": True,
            "pid": os.getpid(),
            "pgid": os.getpgrp(),
            "starttime": identity[2],
        },
    )
    request = _receive_frame(conn)
    _send_frame(
        conn,
        {
            "kind": "result",
            "token": request["token"],
            "result_kind": "cpu",
            "payload": CpuObservation(errors=["partial_frame_preserved"]).model_dump(mode="json"),
        },
    )
    os.write(conn.fileno(), _partial_frame(kind))
    time.sleep(30)


def partial_result_header(conn: Any) -> None:
    _partial_result(conn, "header")


def partial_result_body(conn: Any) -> None:
    _partial_result(conn, "body")


class DiagnosticCpuCollector:
    def collect(self, _configured: tuple[int, ...]) -> CpuObservation:
        return CpuObservation(errors=["production_peer"])


class DiagnosticMemoryCollector:
    def collect(self, _cgroups: tuple[str, ...]) -> MemoryObservation:
        return MemoryObservation(host=HostMemoryObservation(errors=["production_peer"]))


class DiagnosticNetworkCollector:
    def collect(self, target: str | None) -> NetworkObservation:
        return NetworkObservation.unavailable(target, "production_peer")


class DiagnosticFdCollector:
    def collect(self, *args: Any, **kwargs: Any) -> FdObservation:
        return FdObservation(errors=["production_peer"])


class StalledDnsCollector:
    def collect(self, _hostname: str, _target: str) -> Any:
        time.sleep(30)


class OversizeDnsValue:
    def model_dump(self, *, mode: str) -> dict[str, str]:
        assert mode == "json"
        return {"oversize": "x" * 65537}


class OversizeDnsCollector:
    def collect(self, _hostname: str, _target: str) -> OversizeDnsValue:
        return OversizeDnsValue()


def _production_target(conn: Any, dns_collector: type[Any]) -> None:
    supervisor_module._collect_filesystems = lambda paths: [
        Filesystem(mountpoint=path, errors=["production_peer"]) for path in paths
    ]
    supervisor_module.__dict__["CpuCollector"] = DiagnosticCpuCollector
    supervisor_module.__dict__["MemoryCollector"] = DiagnosticMemoryCollector
    supervisor_module.__dict__["NetworkCollector"] = DiagnosticNetworkCollector
    supervisor_module.__dict__["FdCollector"] = DiagnosticFdCollector
    supervisor_module.__dict__["DnsCollector"] = dns_collector
    supervisor_module._supervisor_worker(conn)


def production_dns_stall_worker(conn: Any) -> None:
    _production_target(conn, StalledDnsCollector)


def production_dns_oversize_worker(conn: Any) -> None:
    _production_target(conn, OversizeDnsCollector)


def partial_dns_result_worker(conn: Any) -> None:
    os.setsid()
    identity = _proc_identity(os.getpid())
    assert identity is not None
    _send_frame(
        conn,
        {
            "ready": True,
            "pid": os.getpid(),
            "pgid": os.getpgrp(),
            "starttime": identity[2],
        },
    )
    request = _receive_frame(conn)
    for kind, value in payloads().items():
        _send_frame(
            conn,
            {
                "kind": "result",
                "token": request["token"],
                "result_kind": kind,
                "payload": value,
            },
        )
    os.write(conn.fileno(), struct.pack("!i", 4096) + b"{")
    time.sleep(30)


def run_with(build: Callable[[dict[str, Any]], list[Any]]) -> tuple[Any, bool]:
    supervisor = CollectionSupervisor()
    supervisor.conn = FakeConnection(build)  # type: ignore[assignment]
    supervisor.wait_ready = lambda timeout=0: True  # type: ignore[method-assign]
    closed = False

    def close(_deadline: float | None = None) -> None:
        nonlocal closed
        closed = True

    supervisor.close = close  # type: ignore[assignment]
    result = supervisor.collect_all(
        uuid4(),
        uuid4(),
        7,
        ("/",),
        (),
        (),
        (),
        "unavailable",
        None,
        "watch_unavailable",
        "10.0.0.10",
    )
    return result, closed


def test_supervisor_accepts_one_identity_bound_typed_result_per_kind() -> None:
    values = payloads()

    def messages(request: dict[str, Any]) -> list[dict[str, Any]]:
        token = request["token"]
        return [
            {"kind": "result", "token": token, "result_kind": kind, "payload": value}
            for kind, value in values.items()
        ] + [{"kind": "complete", "token": token}]

    result, closed = run_with(messages)
    assert not closed
    assert result.filesystems[0].errors == ["diagnostic"]
    assert result.cpu.errors == ["diagnostic"]
    assert result.memory.host.errors == ["diagnostic"]
    assert result.fd.errors == ["diagnostic"]
    assert result.network.probe.errors == ["diagnostic"]


def test_supervisor_preserves_completed_results_when_network_never_finishes() -> None:
    values = payloads()

    def messages(request: dict[str, Any]) -> list[dict[str, Any]]:
        token = request["token"]
        return [
            {"kind": "result", "token": token, "result_kind": kind, "payload": values[kind]}
            for kind in ("filesystem", "cpu", "memory", "fd")
        ]

    result, closed = run_with(messages)
    assert closed
    assert result.filesystems[0].errors == ["diagnostic"]
    assert result.cpu.errors == ["diagnostic"]
    assert result.memory.host.errors == ["diagnostic"]
    assert result.fd.errors == ["diagnostic"]
    assert result.network.probe.status == "unavailable"
    assert result.network.probe.sent is None
    assert result.network.probe.received is None
    assert "collection_supervisor_timeout" in result.network.probe.errors


def test_supervisor_rejects_mismatched_or_duplicate_responses() -> None:
    values = payloads()

    def mismatched(_request: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {
                "kind": "result",
                "token": {"boot": "wrong", "session": "wrong", "sequence": 7},
                "result_kind": "cpu",
                "payload": values["cpu"],
            }
        ]

    result, closed = run_with(mismatched)
    assert closed
    assert result.cpu.errors == ["collection_supervisor_timeout"]

    def duplicate(request: dict[str, Any]) -> list[dict[str, Any]]:
        message = {
            "kind": "result",
            "token": request["token"],
            "result_kind": "cpu",
            "payload": values["cpu"],
        }
        return [message, message]

    result, closed = run_with(duplicate)
    assert closed
    assert result.cpu.errors == ["collection_supervisor_timeout"]


def test_supervisor_fd_never_consumes_a_failed_cpu_result() -> None:
    values = payloads()

    def messages(request: dict[str, Any]) -> list[dict[str, Any]]:
        token = request["token"]
        return [
            {"kind": "error", "token": token, "result_kind": "cpu", "error": "blocked"},
            {
                "kind": "result",
                "token": token,
                "result_kind": "filesystem",
                "payload": values["filesystem"],
            },
            {
                "kind": "result",
                "token": token,
                "result_kind": "memory",
                "payload": values["memory"],
            },
            {"kind": "result", "token": token, "result_kind": "fd", "payload": values["fd"]},
            {
                "kind": "result",
                "token": token,
                "result_kind": "network",
                "payload": values["network"],
            },
            {"kind": "complete", "token": token},
        ]

    result, closed = run_with(messages)
    assert not closed
    assert result.cpu.errors == ["collection_supervisor_timeout"]
    assert "fd_cpu_dependency_unavailable" in result.fd.errors


def test_one_malformed_result_does_not_erase_valid_peers() -> None:
    values = payloads()

    def messages(request: dict[str, Any]) -> list[dict[str, Any]]:
        token = request["token"]
        return [
            {
                "kind": "result",
                "token": token,
                "result_kind": kind,
                "payload": {"not": "memory"} if kind == "memory" else value,
            }
            for kind, value in values.items()
        ] + [{"kind": "complete", "token": token}]

    result, closed = run_with(messages)
    assert not closed
    assert result.filesystems[0].errors == ["diagnostic"]
    assert result.cpu.errors == ["diagnostic"]
    assert result.memory.host.errors == ["collection_supervisor_timeout"]
    assert result.fd.errors == ["diagnostic"]
    assert result.network.probe.errors == ["diagnostic"]


def test_non_object_frame_is_bounded_protocol_failure() -> None:
    result, closed = run_with(lambda _request: [["not", "an", "object"]])
    assert closed
    assert result.cpu.errors == ["collection_supervisor_timeout"]
    assert result.network.probe.status == "unavailable"


def test_unhashable_result_kind_is_bounded_protocol_failure() -> None:
    values = payloads()

    def messages_for(malformed_kind: Any) -> Callable[[dict[str, Any]], list[dict[str, Any]]]:
        def messages(request: dict[str, Any]) -> list[dict[str, Any]]:
            token = request["token"]
            return [
                {
                    "kind": "result",
                    "token": token,
                    "result_kind": "cpu",
                    "payload": values["cpu"],
                },
                {
                    "kind": "result",
                    "token": token,
                    "result_kind": malformed_kind,
                    "payload": values["cpu"],
                },
            ]

        return messages

    for malformed_kind in (["cpu"], {"kind": "cpu"}):
        result, closed = run_with(messages_for(malformed_kind))
        assert closed
        assert result.cpu.errors == ["collection_supervisor_timeout"]
        assert result.network.probe.status == "unavailable"
        assert result.network.probe.sent is None
        assert result.network.probe.received is None


def test_timeout_and_teardown_share_one_parent_deadline() -> None:
    supervisor = CollectionSupervisor()
    supervisor.conn = FakeConnection(lambda _request: [])  # type: ignore[assignment]
    supervisor.wait_ready = lambda timeout=0: True  # type: ignore[method-assign]
    observed_deadlines: list[float] = []
    supervisor.close = lambda deadline=None: observed_deadlines.append(deadline or 0.0)  # type: ignore[method-assign]
    started = time.monotonic()
    supervisor.collect_all(
        uuid4(),
        uuid4(),
        7,
        ("/",),
        (),
        (),
        (),
        "unavailable",
        None,
        "watch_unavailable",
        "10.0.0.10",
        budget=0.1,
    )
    elapsed = time.monotonic() - started
    assert len(observed_deadlines) == 1
    assert started + 0.09 <= observed_deadlines[0] <= started + 0.12
    assert elapsed < 0.2


def test_close_does_not_clear_unresolved_ownership_after_leader_disappears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DeadProcess:
        pid = 424242
        closed = False

        @staticmethod
        def is_alive() -> bool:
            return False

        def close(self) -> None:
            self.closed = True

    process = DeadProcess()
    supervisor = CollectionSupervisor()
    supervisor.process = process
    supervisor.pgid = process.pid
    supervisor.starttime = 123
    supervisor.stuck = True
    monkeypatch.setattr(supervisor_module, "_proc_identity", lambda _pid: None)
    supervisor.close()
    assert supervisor.stuck
    assert supervisor.process is process
    assert not process.closed
    assert supervisor.pgid == process.pid
    assert supervisor.starttime == 123


@pytest.mark.skipif(os.name != "posix", reason="real multiprocessing pipe fd semantics")
@pytest.mark.parametrize("target", [partial_ready_header, partial_ready_body])
def test_partial_startup_frame_honors_parent_deadline_and_reaps_owned_process(target: Any) -> None:
    supervisor = CollectionSupervisor(target=target)
    supervisor.start()
    process = supervisor.process
    assert process is not None and process.pid is not None
    pid = process.pid
    assert supervisor.conn is not None and supervisor.conn.poll(2.0)
    started = time.monotonic()
    result = supervisor.collect_all(
        uuid4(),
        uuid4(),
        7,
        ("/",),
        (),
        (),
        (),
        "unavailable",
        None,
        "watch_unavailable",
        "10.0.0.10",
        budget=3.0,
    )
    elapsed = time.monotonic() - started
    assert elapsed < 3.2
    assert result.cpu.errors == ["collection_supervisor_starting"]
    assert supervisor.process is None and not supervisor.stuck
    assert _proc_identity(pid) is None


@pytest.mark.skipif(os.name != "posix", reason="real multiprocessing pipe fd semantics")
@pytest.mark.parametrize("target", [partial_result_header, partial_result_body])
def test_partial_result_frame_preserves_valid_fact_and_reaps_owned_group(target: Any) -> None:
    supervisor = CollectionSupervisor(target=target)
    assert supervisor.wait_ready(2.0)
    pgid = supervisor.pgid
    assert pgid is not None
    started = time.monotonic()
    result = supervisor.collect_all(
        uuid4(),
        uuid4(),
        7,
        ("/",),
        (),
        (),
        (),
        "unavailable",
        None,
        "watch_unavailable",
        "10.0.0.10",
        budget=3.0,
    )
    elapsed = time.monotonic() - started
    assert elapsed < 3.2
    assert result.cpu.errors == ["partial_frame_preserved"]
    assert result.network.probe.errors == ["collection_supervisor_timeout"]
    assert supervisor.process is None and not supervisor.stuck
    assert _group_members(pgid) == {}


def _assert_production_peers_survive_dns_failure(result: Any) -> None:
    assert result.filesystems[0].errors == ["production_peer"]
    assert result.cpu.errors == ["production_peer"]
    assert result.memory.host.errors == ["production_peer"]
    assert result.fd.errors == ["production_peer"]
    assert result.network.probe.errors == ["production_peer"]
    assert result.dns is not None
    assert result.dns.query.status == "unavailable"


@pytest.mark.skipif(os.name != "posix", reason="real production process-group semantics")
def test_production_six_future_dns_stall_preserves_peers_and_reaps_group() -> None:
    supervisor = CollectionSupervisor(target=production_dns_stall_worker)
    assert supervisor.wait_ready(2.0)
    pgid = supervisor.pgid
    assert pgid is not None
    started = time.monotonic()
    result = supervisor.collect_all(
        uuid4(),
        uuid4(),
        7,
        ("/",),
        (),
        (),
        (),
        "unavailable",
        None,
        "watch_unavailable",
        "10.0.0.10",
        "baseline.fleetdoctor.test.",
        budget=1.0,
    )
    assert time.monotonic() - started < 1.2
    _assert_production_peers_survive_dns_failure(result)
    assert supervisor.process is None and not supervisor.stuck
    assert _group_members(pgid) == {}


@pytest.mark.skipif(os.name != "posix", reason="real production process-group semantics")
def test_production_dns_oversize_isolated_from_five_peer_results() -> None:
    supervisor = CollectionSupervisor(target=production_dns_oversize_worker)
    assert supervisor.wait_ready(2.0)
    pgid = supervisor.pgid
    assert pgid is not None
    started = time.monotonic()
    result = supervisor.collect_all(
        uuid4(),
        uuid4(),
        7,
        ("/",),
        (),
        (),
        (),
        "unavailable",
        None,
        "watch_unavailable",
        "10.0.0.10",
        "baseline.fleetdoctor.test.",
        budget=2.0,
    )
    assert time.monotonic() - started < 2.0
    _assert_production_peers_survive_dns_failure(result)
    assert supervisor.process is not None and not supervisor.stuck
    supervisor.close()
    assert supervisor.process is None and not supervisor.stuck
    assert _group_members(pgid) == {}


@pytest.mark.skipif(os.name != "posix", reason="real production process-group semantics")
def test_partial_dns_frame_preserves_all_five_peers_and_reaps_group() -> None:
    supervisor = CollectionSupervisor(target=partial_dns_result_worker)
    assert supervisor.wait_ready(2.0)
    pgid = supervisor.pgid
    assert pgid is not None
    started = time.monotonic()
    result = supervisor.collect_all(
        uuid4(),
        uuid4(),
        7,
        ("/",),
        (),
        (),
        (),
        "unavailable",
        None,
        "watch_unavailable",
        "10.0.0.10",
        "baseline.fleetdoctor.test.",
        budget=3.0,
    )
    assert time.monotonic() - started < 3.2
    assert result.filesystems[0].errors == ["diagnostic"]
    assert result.cpu.errors == ["diagnostic"]
    assert result.memory.host.errors == ["diagnostic"]
    assert result.fd.errors == ["diagnostic"]
    assert result.network.probe.errors == ["diagnostic"]
    assert result.dns is not None and result.dns.query.status == "unavailable"
    assert supervisor.process is None and not supervisor.stuck
    assert _group_members(pgid) == {}
