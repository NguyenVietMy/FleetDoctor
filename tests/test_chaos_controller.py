from __future__ import annotations

import hashlib
import io
import json
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.request import ProxyHandler, Request, build_opener

import chaos_controller
import pytest
from chaos_controller import (
    HELPERS,
    MAX_REQUESTS,
    MAX_RESPONSE_BYTES,
    NodeLease,
    _requests_fd,
    _run,
    request_argv,
    serve,
    validate_protected_path,
    validate_source,
)


def request(scenario: str, action: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    selected = dict(arguments or {})
    if scenario == "config" and action == "begin":
        selected.setdefault(
            "expected_before",
            {
                "env_sha256": "0" * 64,
                "selectors": {"FLEETDOCTOR_CGROUPS": [], "FLEETDOCTOR_CPU_PIDS": []},
                "missing_keys": ["FLEETDOCTOR_CGROUPS", "FLEETDOCTOR_CPU_PIDS"],
            },
        )
    return {
        "id": scenario + "-request",
        "scenario": scenario,
        "action": action,
        "token": "a" * 32,
        "arguments": selected,
    }


@pytest.mark.parametrize("state", ["completed", "fault", "configuration", "malformed", "oversized"])
def test_prior_journal_ownership_blocks_new_session_and_releases_failed_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    directory = tmp_path / "journals"
    directory.mkdir()
    prior = directory / "session-prior.json"
    record: dict[str, Any] = {
        "schema_version": 1,
        "pid": 999999,
        "started_at": "2026-11-12T00:00:00+00:00",
        "active": None,
        "events": [],
        "status": "completed",
    }
    if state == "fault":
        record["active"] = {"fault": {"scenario": "cpu", "token": "a" * 32}, "configurations": []}
        record["status"] = "cleanup_failed"
    elif state == "configuration":
        record["active"] = {
            "fault": None,
            "configurations": [{"scenario": "config", "token": "b" * 32, "scope": "agent"}],
        }
        record["status"] = "failed"
    elif state == "malformed":
        del record["active"]
    prior.write_text(json.dumps(record), encoding="utf-8")
    original = prior.read_bytes()
    leases: list[Any] = []

    class FixtureLease:
        def __init__(self, path: Path) -> None:
            assert path == directory
            self.closed = False
            leases.append(self)

        def close(self) -> None:
            self.closed = True

    def validate_fixture_path(path: Path, *, directory: bool) -> None:
        assert path == tmp_path / "journals" or path.parent == tmp_path / "journals"
        assert path.is_dir() if directory else path.is_file()

    def write_fixture_receipt(path: Path, value: dict[str, Any]) -> None:
        assert path.parent == directory
        path.write_text(json.dumps(value), encoding="utf-8")

    monkeypatch.setattr(chaos_controller, "NodeLease", FixtureLease)
    monkeypatch.setattr(chaos_controller, "validate_protected_path", validate_fixture_path)
    monkeypatch.setattr(chaos_controller, "_atomic_receipt", write_fixture_receipt)
    if state == "oversized":
        monkeypatch.setattr(chaos_controller, "MAX_JOURNAL_BYTES", len(original) - 1)
    if state == "completed":
        journal = chaos_controller.ControllerJournal(directory)
        journal.finish("completed")
        assert journal.value["active"] is None
    else:
        with pytest.raises((RuntimeError, ValueError), match="ownership|malformed|size bound"):
            chaos_controller.ControllerJournal(directory)
        assert list(directory.iterdir()) == [prior]
    assert leases[-1].closed is True
    assert prior.read_bytes() == original


@pytest.mark.skipif(os.name != "posix", reason="root controller entrypoint requires POSIX")
def test_main_reports_unconfirmed_cleanup_as_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class PendingJournal:
        value: dict[str, Any] = {"active": {"fault": {"scenario": "cpu", "token": "a" * 32}}}
        status = ""

        def finish(self, status: str) -> None:
            self.status = status

    journal = PendingJournal()
    monkeypatch.setattr(sys, "argv", ["chaos_controller.py"])
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        chaos_controller,
        "validate_source",
        lambda *args: {"batch_id": "batch", "controller_bundle_sha256": "a" * 64},
    )
    monkeypatch.setattr(chaos_controller, "attest_runtime_identity", lambda *args: {})
    monkeypatch.setattr(chaos_controller, "_sha256", lambda *args: "b" * 64)
    monkeypatch.setattr(chaos_controller, "_set_parent_death_signal", lambda: None)
    monkeypatch.setattr(chaos_controller, "ControllerJournal", lambda **kwargs: journal)
    monkeypatch.setattr(chaos_controller, "serve", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError, match="cleanup is unconfirmed"):
        chaos_controller.main()
    assert journal.status == "cleanup_failed" and journal.value["active"] is not None


@pytest.mark.parametrize(
    ("scenario", "arguments"),
    [
        ("disk", {"duration": 180}),
        ("inode", {"duration": 180}),
        ("fd", {"limit": 128, "seconds": 180}),
        (
            "oom",
            {"allocation_bytes": 96 * 1024 * 1024, "limit_bytes": 48 * 1024 * 1024},
        ),
        ("cpu", {"workers": 4, "seconds": 180}),
        ("network", {"target": "10.0.0.10", "profile": "latency", "duration": 180}),
        ("dns", {"invalid_resolver": "203.0.113.254", "duration": 180}),
        ("io", {"duration": 120}),
    ],
)
def test_all_eight_start_adapters_are_strictly_allowlisted(
    tmp_path: Path, scenario: str, arguments: dict[str, Any]
) -> None:
    argv, activates = request_argv(tmp_path, request(scenario, "start", arguments))
    assert activates is True
    assert argv[1].startswith(str(tmp_path))
    assert "--token" in argv or scenario == "io"


def test_nonallowlisted_action_argument_and_token_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        request_argv(tmp_path, request("cpu", "shell"))
    with pytest.raises(ValueError, match="non-allowlisted"):
        request_argv(tmp_path, request("cpu", "start", {"workers": 2, "command": "id"}))
    malformed = request("cpu", "start", {"workers": 2}) | {"token": "../../root"}
    with pytest.raises(ValueError, match="token"):
        request_argv(tmp_path, malformed)


class Journal:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def record(self, event: str, **facts: Any) -> None:
        self.events.append((event, facts))


def stream(*items: dict[str, Any]) -> io.BytesIO:
    return io.BytesIO(b"".join(json.dumps(item).encode() + b"\n" for item in items))


def authenticated_session(role: str = "node-a") -> dict[str, Any]:
    return {
        "batch_id": "batch-identity",
        "session_id": "1" * 64,
        "protected_manifest_sha256": "2" * 64,
        "controller_bundle_sha256": "3" * 64,
        "identity": {
            "role": role,
            "account_id": "123456789012",
            "region": "us-east-1",
            "availability_zone": "us-east-1a",
            "instance_id": "i-aaaaaaaa",
            "private_ip": "10.0.0.20",
            "boot_id": "00000000-0000-0000-0000-000000000020",
            "host_public_key": "ssh-ed25519 AAAA",
            "host_key_fingerprint": "SHA256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU".replace(
                "-", "+"
            ).replace("_", "/"),
        },
    }


def auth_request(value: dict[str, Any], session: dict[str, Any]) -> dict[str, Any]:
    return {**value, "batch_id": session["batch_id"], "session_id": session["session_id"]}


def test_authenticated_hello_role_and_session_fail_before_mutation(tmp_path: Path) -> None:
    session = authenticated_session()
    hello = {"type": "hello", "batch_id": session["batch_id"], "nonce": "a" * 64}
    good = auth_request(request("cpu", "start", {"workers": 2, "seconds": 30}), session)
    wrong_session = {**good, "session_id": "9" * 64, "id": "wrong-session"}
    calls: list[list[str]] = []

    def record(argv: list[str]) -> dict[str, Any]:
        calls.append(argv)
        return {"owned": True}

    output = io.BytesIO()
    serve(
        tmp_path,
        stream(hello, wrong_session, good),
        output,
        runner=record,
        session=session,
    )
    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert responses[0]["type"] == "hello" and responses[0]["nonce"] == "a" * 64
    assert responses[1]["ok"] is False and "batch/session" in responses[1]["error"]
    assert responses[2]["ok"] is True and len(calls) == 2  # start plus EOF cleanup

    monitor = authenticated_session("monitor")
    monitor_hello = {"type": "hello", "batch_id": monitor["batch_id"], "nonce": "b" * 64}
    output = io.BytesIO()
    calls.clear()
    serve(
        tmp_path,
        stream(monitor_hello, auth_request(request("cpu", "start", {"workers": 2}), monitor)),
        output,
        runner=record,
        session=monitor,
    )
    assert not calls and json.loads(output.getvalue().splitlines()[1])["ok"] is False


def test_authenticated_monitor_api_relay_is_role_restricted_and_bounded(tmp_path: Path) -> None:
    monitor = authenticated_session("monitor")
    hello = {"type": "hello", "batch_id": monitor["batch_id"], "nonce": "c" * 64}
    api_request = auth_request(
        request(
            "api",
            "get",
            {"path": "/nodes/node-a/metrics", "params": {}},
        ),
        monitor,
    )
    api_request["token"] = "0" * 32
    output = io.BytesIO()
    serve(
        tmp_path,
        stream(hello, api_request),
        output,
        session=monitor,
        api_reader=lambda path, params: {
            "status_code": 200,
            "body": {"path": path, "params": params},
        },
    )
    response = json.loads(output.getvalue().splitlines()[1])
    assert response["ok"] is True
    assert response["result"]["body"]["path"] == "/nodes/node-a/metrics"

    node = authenticated_session("node-a")
    node_hello = {"type": "hello", "batch_id": node["batch_id"], "nonce": "d" * 64}
    output = io.BytesIO()
    serve(
        tmp_path,
        stream(node_hello, auth_request(api_request | {"session_id": node["session_id"]}, node)),
        output,
        session=node,
        api_reader=lambda path, params: {"status_code": 200, "body": {}},
    )
    assert json.loads(output.getvalue().splitlines()[1])["ok"] is False


@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="controller deadline uses POSIX timer")
def test_total_http_deadline_stops_actual_drip_without_reader_thread_accumulation() -> None:
    class Drip(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return None

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "1000")
            self.end_headers()
            try:
                for _ in range(1000):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.02)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Drip)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        opener = build_opener(ProxyHandler({}))
        request_value = Request(f"http://127.0.0.1:{server.server_port}/drip")
        for _ in range(3):
            started = time.monotonic()
            with pytest.raises(TimeoutError, match="total wall-clock"):
                chaos_controller._bounded_http_read(
                    opener,
                    request_value,
                    socket_timeout=1,
                    operation_timeout=0.15,
                    limit=2048,
                )
            assert time.monotonic() - started < 0.8
        assert not [
            item for item in threading.enumerate() if item.name == "fleetdoctor-bounded-http"
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_runtime_attestation_is_read_only_and_compares_every_stable_identity(
    tmp_path: Path,
) -> None:
    boot = tmp_path / "boot_id"
    boot.write_text("00000000-0000-0000-0000-000000000020\n", encoding="ascii")
    manifest = {
        "role": "node-a",
        "account_id": "123456789012",
        "region": "us-east-1",
        "availability_zone": "us-east-1a",
        "instance_id": "i-aaaaaaaa",
        "private_ip": "10.0.0.20",
    }
    document = {
        "accountId": manifest["account_id"],
        "region": manifest["region"],
        "availabilityZone": manifest["availability_zone"],
        "instanceId": manifest["instance_id"],
        "privateIp": manifest["private_ip"],
    }
    result = chaos_controller.attest_runtime_identity(
        manifest,
        metadata_provider=lambda: dict(document),
        boot_path=boot,
        host_key_provider=lambda: {
            "host_public_key": "ssh-ed25519 AAAA",
            "host_key_fingerprint": "SHA256:fixture",
        },
    )
    assert result["instance_id"] == "i-aaaaaaaa" and result["boot_id"].endswith("0020")
    wrong = dict(document, instanceId="i-bbbbbbbb")
    with pytest.raises(ValueError, match="actual instance identity"):
        chaos_controller.attest_runtime_identity(
            manifest,
            metadata_provider=lambda: wrong,
            boot_path=boot,
            host_key_provider=lambda: {
                "host_public_key": "ssh-ed25519 AAAA",
                "host_key_fingerprint": "SHA256:fixture",
            },
        )


def test_metadata_token_and_document_use_fixed_total_deadlines_and_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Request, dict[str, Any]]] = []
    document = {
        "accountId": "123456789012",
        "region": "us-east-1",
        "availabilityZone": "us-east-1a",
        "instanceId": "i-aaaaaaaa",
        "privateIp": "10.0.0.20",
    }

    def bounded(opener: Any, request: Request, **bounds: Any) -> tuple[int, str, bytes]:
        calls.append((request, bounds))
        if len(calls) == 1:
            return 200, "text/plain", b"synthetic-token"
        return 200, "application/json", json.dumps(document).encode()

    monkeypatch.setattr(chaos_controller, "_bounded_http_read", bounded)
    assert chaos_controller._metadata_identity() == document
    assert [request.get_method() for request, _ in calls] == ["PUT", "GET"]
    assert [bounds for _, bounds in calls] == [
        {"socket_timeout": 2, "operation_timeout": 3, "limit": 4096},
        {"socket_timeout": 2, "operation_timeout": 3, "limit": 16384},
    ]
    assert calls[0][0].full_url == "http://169.254.169.254/latest/api/token"
    assert calls[1][0].get_header("X-aws-ec2-metadata-token") == "synthetic-token"


def test_api_relay_uses_private_collector_origin_and_fixed_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Request, dict[str, Any]]] = []

    def bounded(opener: Any, request: Request, **bounds: Any) -> tuple[int, str, bytes]:
        calls.append((request, bounds))
        return 200, "application/json", b'{"fresh":true}'

    monkeypatch.setattr(chaos_controller, "_bounded_http_read", bounded)
    result = chaos_controller.api_get(
        {"role": "monitor", "private_ip": "10.0.0.10"},
        "/nodes/node-a/metrics",
        {},
    )
    assert result == {"status_code": 200, "body": {"fresh": True}}
    assert calls[0][0].full_url == "http://10.0.0.10:8000/nodes/node-a/metrics"
    assert calls[0][1] == {
        "socket_timeout": 3,
        "operation_timeout": 4,
        "limit": chaos_controller.MAX_API_RESPONSE_BYTES,
    }


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("http://example/health", {}),
        ("/ingest", {}),
        ("/health?redirect=http://evil", {}),
        ("/diagnoses", {"unknown": "value"}),
        ("/diagnoses", {"limit": 101}),
    ],
)
def test_api_relay_rejects_arbitrary_or_mutating_routes(path: str, params: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="API relay"):
        chaos_controller._validate_api_request(path, params)


def test_partial_start_is_owned_before_reply_and_cleaned_on_eof(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    journal = Journal()

    def runner(argv: list[str]) -> dict[str, Any]:
        calls.append(argv)
        if "start" in argv:
            raise RuntimeError("reply lost after possible start")
        return {"cleaned": True}

    output = io.BytesIO()
    serve(
        tmp_path,
        stream(request("cpu", "start", {"workers": 2, "seconds": 30})),
        output,
        runner=runner,
        journal=journal,  # type: ignore[arg-type]
    )
    assert len(calls) == 2
    assert "cleanup" in calls[-1]
    assert [event for event, _ in journal.events] == [
        "mutation_intent",
        "request_failed",
        "terminal_fault_cleanup_complete",
    ]
    assert json.loads(output.getvalue())["ok"] is False


def test_explicit_cleanup_failure_retains_ownership_and_blocks_next_start(tmp_path: Path) -> None:
    journal = Journal()
    calls = 0

    def runner(argv: list[str]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if "start" in argv:
            return {"owned": True}
        raise RuntimeError("forced cleanup failure")

    output = io.BytesIO()
    serve(
        tmp_path,
        stream(
            request("cpu", "start", {"workers": 2, "seconds": 30}),
            request("cpu", "cleanup"),
            request("dns", "start", {"duration": 30}),
        ),
        output,
        runner=runner,
        journal=journal,  # type: ignore[arg-type]
    )
    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert responses[0]["ok"] is True
    assert responses[1]["ok"] is False
    assert responses[2]["ok"] is False
    assert any(event == "terminal_fault_cleanup_failed" for event, _ in journal.events)
    assert calls == 3


def protocol_result(argv: list[str]) -> dict[str, Any]:
    scenario = next(
        name for name, relative in HELPERS.items() if Path(argv[1]).name == Path(relative).name
    )
    action = argv[2]
    if scenario == "config":
        return {"phase": "restored" if action == "restore" else "active"}
    if scenario == "io" and action == "cleanup":
        return {"phase": "stopped", "workload_cleanup_complete": True}
    if scenario == "io" and action == "destroy":
        return {"phase": "destroyed", "cleanup_complete": True}
    if scenario == "oom" and action == "release":
        return {"released": True, "owned": False}
    if action == "cleanup":
        return {"cleaned": True, "cleanup_complete": True, "owned": False}
    if scenario == "fd" and action == "release":
        return {"released": True, "owned": True, "phase": "released"}
    return {"owned": True, "phase": action, "stopped": action == "stop"}


def identified(item: dict[str, Any], index: int, token: str | None = None) -> dict[str, Any]:
    return item | {"id": f"protocol-{index}", "token": token or f"{index:032x}"}


def test_real_serve_state_machine_composes_config_and_all_eight_resources(
    tmp_path: Path,
) -> None:
    outer = "1" * 32
    child = "2" * 32
    items = [
        identified(
            request(
                "config",
                "begin",
                {"scope": "agent", "changes": {"FLEETDOCTOR_CGROUPS": "/owned"}},
            ),
            1,
            outer,
        )
    ]
    index = 2
    for scenario in ("disk", "inode"):
        token = f"{index:032x}"
        items += [
            identified(request(scenario, "start", {"duration": 30}), index, token),
            identified(request(scenario, "cleanup"), index + 1, token),
        ]
        index += 2
    fd_token = f"{index:032x}"
    items += [
        identified(request("fd", "start", {"limit": 128, "seconds": 30}), index, fd_token),
        identified(
            request(
                "config",
                "begin",
                {
                    "scope": "agent",
                    "changes": {"FLEETDOCTOR_CPU_PIDS": "123"},
                    "parent_token": outer,
                },
            ),
            index + 1,
            child,
        ),
        identified(request("fd", "pressure"), index + 2, fd_token),
        identified(request("fd", "release"), index + 3, fd_token),
        identified(request("dns", "start", {"duration": 30}), index + 4, "9" * 32),
        identified(request("fd", "cleanup"), index + 5, fd_token),
        identified(request("config", "restore", {"scope": "agent"}), index + 6, child),
    ]
    index += 7
    for scenario, start_actions, terminal_actions in (
        ("oom", (("prepare", {"lease_seconds": 360}), ("start", {})), ("stop", "release")),
        ("cpu", (("start", {"workers": 2, "seconds": 30}),), ("cleanup",)),
        ("network", (("start", {"target": "10.0.0.1", "duration": 30}),), ("cleanup",)),
        ("dns", (("start", {"duration": 30}),), ("cleanup",)),
        ("io", (("prepare", {}), ("start", {"duration": 30})), ("cleanup", "destroy")),
    ):
        token = f"{index:032x}"
        for action, arguments in start_actions:
            items.append(identified(request(scenario, action, arguments), index, token))
            index += 1
        for action in terminal_actions:
            items.append(identified(request(scenario, action), index, token))
            index += 1
    items.append(identified(request("config", "restore", {"scope": "agent"}), index, outer))
    journal = Journal()
    output = io.BytesIO()
    serve(tmp_path, stream(*items), output, runner=protocol_result, journal=journal)  # type: ignore[arg-type]
    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert sum(response["ok"] is False for response in responses) == 1
    assert "physical fault/resource" in responses[9]["error"]
    assert journal.events[-1][1]["active"] is None


def test_fd_release_and_io_workload_cleanup_remain_owned_until_terminal_cleanup(
    tmp_path: Path,
) -> None:
    for scenario, actions, expected_cleanup in (
        ("fd", ("start", "release"), ("cleanup",)),
        ("io", ("prepare", "start", "cleanup"), ("cleanup", "destroy")),
    ):
        token = "a" * 32
        calls: list[list[str]] = []

        def runner(argv: list[str], call_log: list[list[str]] = calls) -> dict[str, Any]:
            call_log.append(argv)
            return protocol_result(argv)

        requests = []
        for index, action in enumerate(actions):
            arguments = (
                {"limit": 128, "seconds": 30}
                if action == "start" and scenario == "fd"
                else {"duration": 30}
                if action == "start"
                else {}
            )
            requests.append(identified(request(scenario, action, arguments), index + 1, token))
        serve(tmp_path, stream(*requests), io.BytesIO(), runner=runner)
        assert tuple(argv[2] for argv in calls[-len(expected_cleanup) :]) == expected_cleanup


def test_eof_cleans_fault_then_restores_exact_config_scopes_in_reverse(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> dict[str, Any]:
        calls.append(argv)
        return protocol_result(argv)

    serve(
        tmp_path,
        stream(
            identified(
                request(
                    "config",
                    "begin",
                    {"scope": "monitor", "changes": {"FLEETDOCTOR_CGROUPS": "/monitor"}},
                ),
                1,
                "1" * 32,
            ),
            identified(
                request(
                    "config",
                    "begin",
                    {"scope": "agent", "changes": {"FLEETDOCTOR_CGROUPS": "/agent"}},
                ),
                2,
                "2" * 32,
            ),
            identified(request("fd", "start", {"limit": 128, "seconds": 30}), 3, "3" * 32),
            identified(request("fd", "release"), 4, "3" * 32),
        ),
        io.BytesIO(),
        runner=runner,
    )
    assert calls[-3][2] == "cleanup"
    assert calls[-2][2:] == ["restore", "--token", "2" * 32, "--scope", "agent"]
    assert calls[-1][2:] == ["restore", "--token", "1" * 32, "--scope", "monitor"]


def test_complete_40_attempt_45_phase_virtual_session_exceeds_old_caps(tmp_path: Path) -> None:
    items: list[dict[str, Any]] = []
    phases = ["network"] * 10 + ["cpu"] * 35
    index = 0
    for phase in phases:
        token = f"{index + 1:032x}"
        arguments = (
            {"target": "10.0.0.1", "duration": 30}
            if phase == "network"
            else {"workers": 2, "seconds": 30}
        )
        items.append(identified(request(phase, "start", arguments), index, token))
        index += 1
        for _ in range(12):
            items.append(identified(request(phase, "status"), index, token))
            index += 1
        items.append(identified(request(phase, "cleanup"), index, token))
        index += 1

    class VirtualClock:
        now = 0.0

        def __call__(self) -> float:
            self.now += 2.0
            return self.now

    clock = VirtualClock()
    output = io.BytesIO()
    serve(tmp_path, stream(*items), output, runner=protocol_result, monotonic=clock)
    assert len(items) > 512
    assert clock.now > 900
    assert len(output.getvalue().splitlines()) == len(items)


def test_system_exit_from_inflight_helper_is_not_converted_to_response(tmp_path: Path) -> None:
    calls = 0

    def runner(argv: list[str]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        raise SystemExit(143)

    with pytest.raises(SystemExit, match="143"):
        serve(
            tmp_path,
            stream(request("cpu", "start", {"workers": 2, "seconds": 30})),
            io.BytesIO(),
            runner=runner,
        )
    assert calls == 2


def test_user_writable_runtime_is_refused_even_with_matching_files(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    with pytest.raises(ValueError, match="unprotected"):
        validate_protected_path(
            root, directory=True, uid=os.getuid() if hasattr(os, "getuid") else 0
        )


def test_protected_manifest_binds_running_controller_and_every_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    deploy = source / "deploy"
    deploy.mkdir(parents=True)
    controller = deploy / "chaos_controller.py"
    controller.write_bytes(Path(chaos_controller.__file__).read_bytes())
    wrapper = deploy / "fleetdoctor-chaos-controller.sh"
    wrapper.write_text(
        "#!/bin/sh\nset -eu\nexec /usr/bin/python3.11 "
        '/opt/fleetdoctor/current/deploy/chaos_controller.py "$@"\n'
    )
    helper_hashes: dict[str, str] = {}
    for scenario, relative in HELPERS.items():
        helper = source / relative
        helper.parent.mkdir(parents=True, exist_ok=True)
        if helper != controller:
            helper.write_bytes((scenario + "\n").encode())
        helper_hashes[scenario] = hashlib.sha256(helper.read_bytes()).hexdigest()
    manifest = tmp_path / "controller.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "batch_id": "batch-identity",
                "role": "node-a",
                "plan_sha256": "a" * 64,
                "original_plan_sha256": "b" * 64,
                "account_id": "123456789012",
                "region": "us-east-1",
                "availability_zone": "us-east-1a",
                "instance_id": "i-aaaaaaaa",
                "private_ip": "10.0.0.20",
                "source_root": str(source),
                "controller_sha256": hashlib.sha256(controller.read_bytes()).hexdigest(),
                "wrapper_sha256": hashlib.sha256(wrapper.read_bytes()).hexdigest(),
                "controller_bundle_sha256": chaos_controller._digest(
                    {
                        "controller": hashlib.sha256(controller.read_bytes()).hexdigest(),
                        "wrapper": hashlib.sha256(wrapper.read_bytes()).hexdigest(),
                        "helpers": {key: helper_hashes[key] for key in sorted(helper_hashes)},
                    }
                ),
                "helpers": helper_hashes,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(chaos_controller, "validate_protected_path", lambda *args, **kwargs: None)
    monkeypatch.setattr(chaos_controller, "__file__", str(controller))
    assert validate_source(source, manifest)["batch_id"] == "batch-identity"
    (source / HELPERS["cpu"]).write_bytes(b"replaced\n")
    with pytest.raises(ValueError, match="frozen helper mismatch: cpu"):
        validate_source(source, manifest)


def test_writable_and_symlinked_protected_files_are_rejected(tmp_path: Path) -> None:
    owner = os.getuid() if hasattr(os, "getuid") else 0
    protected = tmp_path / "helper.py"
    protected.write_text("pass\n")
    protected.chmod(0o666)
    with pytest.raises(ValueError, match="unprotected"):
        validate_protected_path(protected, directory=False, uid=owner)
    protected.unlink()
    target = tmp_path / "target.py"
    target.write_text("pass\n")
    try:
        protected.symlink_to(target)
    except OSError:
        pytest.skip("test account cannot create symlinks")
    with pytest.raises(ValueError, match="unprotected"):
        validate_protected_path(protected, directory=False, uid=owner)


def test_fixed_wrapper_and_installer_use_only_protected_runtime_paths() -> None:
    wrapper = Path("deploy/fleetdoctor-chaos-controller.sh").read_bytes()
    installer = Path("deploy/install-chaos-controller.sh").read_bytes()
    assert wrapper == (
        b"#!/bin/sh\nset -eu\nexec /usr/bin/python3.11 "
        b'/opt/fleetdoctor/current/deploy/chaos_controller.py "$@"\n'
    )
    assert b"verify_file" in installer
    assert b"/etc/fleetdoctor/chaos-controller.json" in installer
    assert b"python3.11 -c" in installer
    assert b"$PATH" not in wrapper + installer


def test_maximum_request_count_and_oversized_response_fail_closed(tmp_path: Path) -> None:
    calls = 0

    def probe_runner(argv: list[str]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {"status": "ok"}

    requests = [
        request("disk", "probe") | {"id": f"request-{index}"} for index in range(MAX_REQUESTS + 1)
    ]
    with pytest.raises(TimeoutError, match="request/session bound"):
        serve(tmp_path, stream(*requests), io.BytesIO(), runner=probe_runner)
    assert calls == MAX_REQUESTS

    cleanup_calls: list[list[str]] = []

    def oversized_runner(argv: list[str]) -> dict[str, Any]:
        cleanup_calls.append(argv)
        if "start" in argv:
            return {"blob": "x" * (MAX_RESPONSE_BYTES + 1)}
        return {"cleaned": True}

    output = io.BytesIO()
    serve(
        tmp_path,
        stream(request("cpu", "start", {"workers": 2, "seconds": 30})),
        output,
        runner=oversized_runner,
    )
    response = json.loads(output.getvalue())
    assert response == {
        "error": "response exceeds bound",
        "id": "cpu-request",
        "ok": False,
    }
    assert len(cleanup_calls) == 2 and "cleanup" in cleanup_calls[-1]


@pytest.mark.skipif(sys.platform != "linux", reason="controller pipe selector requires Linux")
@pytest.mark.parametrize("partial", [b"", b'{"id":'])
def test_session_expiry_while_stdin_is_absent_or_partial(partial: bytes) -> None:
    read_fd, write_fd = os.pipe()
    reader = os.fdopen(read_fd, "rb", buffering=0)
    try:
        if partial:
            os.write(write_fd, partial)
        source = _requests_fd(reader, time.monotonic() + 0.05)
        with pytest.raises(TimeoutError, match="session expired"):
            next(source)
    finally:
        os.close(write_fd)
        reader.close()


@pytest.mark.skipif(sys.platform != "linux", reason="helper pipe selector requires Linux")
def test_helper_output_and_stall_are_bounded() -> None:
    with pytest.raises(ValueError, match="stdout exceeds controller bound"):
        _run(
            [sys.executable, "-c", f"import sys;sys.stdout.write('x'*{MAX_RESPONSE_BYTES + 1})"],
            timeout_seconds=5,
        )
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="helper exceeded"):
        _run([sys.executable, "-c", "import time;time.sleep(10)"], timeout_seconds=0.1)
    assert time.monotonic() - started < 5


def test_invalid_helper_timeout_has_no_subprocess_or_selector_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects: list[str] = []

    def forbidden_popen(*args: Any, **kwargs: Any) -> Any:
        effects.append("popen")
        raise AssertionError("Popen must not run for an invalid timeout")

    def forbidden_selector(*args: Any, **kwargs: Any) -> Any:
        effects.append("selector")
        raise AssertionError("selector must not be allocated for an invalid timeout")

    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)
    monkeypatch.setattr(selectors, "DefaultSelector", forbidden_selector)
    with pytest.raises(ValueError, match="timeout must be"):
        _run(["unreachable"], timeout_seconds=0)
    assert effects == []


@pytest.mark.skipif(sys.platform != "linux", reason="node lease uses Linux flock")
def test_node_wide_lease_blocks_overlapping_controllers_and_recovers_on_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(chaos_controller, "validate_protected_path", lambda *args, **kwargs: None)
    tmp_path.chmod(0o700)
    first = NodeLease(tmp_path, uid=os.getuid())
    try:
        with pytest.raises(BlockingIOError):
            NodeLease(tmp_path, uid=os.getuid())
    finally:
        first.close()
    recovered = NodeLease(tmp_path, uid=os.getuid())
    recovered.close()


@pytest.mark.skipif(sys.platform != "linux", reason="real POSIX signal proof requires Linux")
def test_real_sigterm_during_inflight_helper_cleans_and_exits_without_response(
    tmp_path: Path,
) -> None:
    started = tmp_path / "started"
    cleaned = tmp_path / "cleaned"
    code = r"""
import sys
import time
from pathlib import Path
from chaos_controller import serve

root, started, cleaned = map(Path, sys.argv[1:])

def runner(argv):
    if "start" in argv:
        started.write_text("started")
        while True:
            time.sleep(1)
    cleaned.write_text("cleaned")
    return {"cleaned": True}

serve(root, sys.stdin.buffer, sys.stdout.buffer, runner=runner)
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [os.fspath(Path.cwd() / "deploy"), environment.get("PYTHONPATH", "")]
    )
    process = subprocess.Popen(
        [sys.executable, "-c", code, os.fspath(tmp_path), os.fspath(started), os.fspath(cleaned)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    assert process.stdin is not None
    process.stdin.write(
        json.dumps(request("cpu", "start", {"workers": 2, "seconds": 30})).encode() + b"\n"
    )
    process.stdin.flush()
    deadline = time.monotonic() + 10
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert started.exists()
    process.send_signal(15)
    assert process.wait(timeout=10) == 143
    assert cleaned.read_text() == "cleaned"
    assert process.stdout is not None and process.stdout.read() == b""
