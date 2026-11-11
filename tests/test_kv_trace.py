from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import kv_trace
import pytest
from kv_trace import (
    CommandResult,
    HarnessError,
    ListenerIdentity,
    ProcessIdentity,
    RunConfig,
    UserIdentity,
)


def identity(pid: int = 101, starttime: int = 202, *, kind: str = "dkv-node-1") -> ProcessIdentity:
    return ProcessIdentity(kind=kind, pid=pid, starttime=starttime, pgid=pid, uid=1000)


def result(*, code: int = 0, stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult(["fake-client"], code, stdout, stderr, 0.01)


def current_user() -> UserIdentity:
    uid = os.geteuid()
    return UserIdentity("root" if uid == 0 else "fixture", uid, os.getegid(), str(Path.home()))


def three_free_ports() -> tuple[int, int, int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(3):
            value = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            value.bind(("127.0.0.1", 0))
            sockets.append(value)
        return tuple(int(value.getsockname()[1]) for value in sockets)  # type: ignore[return-value]
    finally:
        for value in sockets:
            value.close()


def wait_for_path(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path}")


def linux_fixture_python() -> str:
    if os.geteuid() != 0:
        return sys.executable
    python = shutil.which("python3", path="/usr/bin:/usr/local/bin:/bin")
    assert python is not None, "root Linux fixtures require a system Python interpreter"
    return str(Path(python).resolve())


def linux_fixture_user(tmp_path: Path) -> tuple[UserIdentity, Path, str]:
    pwd = __import__("pwd")
    if os.geteuid() == 0:
        record = pwd.getpwnam("nobody")
    else:
        record = pwd.getpwuid(os.geteuid())
    python = linux_fixture_python()
    owned = (
        Path(tempfile.mkdtemp(prefix="kv-trace-run-user-"))
        if os.geteuid() == 0
        else tmp_path / "run-user"
    )
    if os.geteuid() != 0:
        owned.mkdir()
    if os.geteuid() == 0:
        os.chown(owned, record.pw_uid, record.pw_gid)
    os.chmod(owned, 0o700)
    return UserIdentity(record.pw_name, record.pw_uid, record.pw_gid, record.pw_dir), owned, python


def test_port_validation_requires_three_distinct_unprivileged_ports() -> None:
    assert kv_trace.validate_ports([9101, 9102, 9103]) == (9101, 9102, 9103)
    for values in ([9101, 9102], [9101, 9101, 9103], [80, 9102, 9103], [9101, 9102, 70000]):
        with pytest.raises(HarnessError):
            kv_trace.validate_ports(values)


def test_output_refusal_does_not_modify_existing_path(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "keep"
    marker.write_text("owned by caller", encoding="utf-8")
    with pytest.raises(HarnessError, match="already exists"):
        kv_trace.refuse_existing_output(output)
    assert marker.read_text(encoding="utf-8") == "owned by caller"


def test_output_requires_absolute_path() -> None:
    with pytest.raises(HarnessError, match="absolute"):
        kv_trace.refuse_existing_output(Path("relative-output"))


def test_occupied_port_is_rejected_without_killing_listener() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = int(listener.getsockname()[1])
    try:
        with pytest.raises(HarnessError, match="occupied"):
            kv_trace.ports_available((port, port + 1, port + 2))
        assert listener.fileno() >= 0
    finally:
        listener.close()


def test_put_requires_exit_zero_committed_text_and_saved_id() -> None:
    request_id = "a" * 32
    kv_trace.validate_put(
        result(stdout="committed term 4 index 9\n", stderr=f"request id {request_id}\n"),
        request_id,
    )
    with pytest.raises(HarnessError, match="did not report committed"):
        kv_trace.validate_put(
            result(stdout="outcome unknown\n", stderr=f"request id {request_id}\n"), request_id
        )
    with pytest.raises(HarnessError, match="exit code 4"):
        kv_trace.validate_put(result(code=4, stdout="committed term 4 index 9\n"), request_id)


def test_get_requires_exact_semantic_value() -> None:
    kv_trace.validate_get(result(stdout="expected\n"), "expected")
    with pytest.raises(HarnessError, match="different value"):
        kv_trace.validate_get(result(stdout="other\n"), "expected")
    with pytest.raises(HarnessError, match="exit code"):
        kv_trace.validate_get(result(code=3, stdout="expected\n"), "expected")


def test_status_is_diagnostic_but_must_be_three_valid_snapshots() -> None:
    stdout = (
        "\n".join(
            [
                "node 1 role leader term 2 leader 1 log 3 commit 3 applied 3",
                "node 2 role follower term 2 leader 1 log 3 commit 3 applied 3",
                "node 3 role follower term 2 leader 1 log 3 commit 3 applied 3",
            ]
        )
        + "\n"
    )
    kv_trace.validate_status(result(stdout=stdout))
    with pytest.raises(HarnessError, match="three valid"):
        kv_trace.validate_status(result(stdout=stdout.splitlines()[0] + "\n"))


def test_parse_listener_inventory_keeps_only_ipv4_loopback_listeners(tmp_path: Path) -> None:
    source = tmp_path / "tcp"
    source.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:238D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 456 1 0\n"
        "   1: 00000000:238E 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 999 1 0\n"
        "   2: 0100007F:238F 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000 0 777 1 0\n",
        encoding="ascii",
    )
    assert kv_trace.parse_listeners(source) == {9101: ("127.0.0.1", 456)}


def test_post_launch_listener_check_binds_port_inode_to_exact_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nodes = [
        identity(101, 1),
        identity(102, 2, kind="dkv-node-2"),
        identity(103, 3, kind="dkv-node-3"),
    ]
    monkeypatch.setattr(
        kv_trace,
        "parse_listeners",
        lambda: {9101: ("127.0.0.1", 11), 9102: ("127.0.0.1", 12), 9103: ("127.0.0.1", 13)},
    )
    monkeypatch.setattr(kv_trace, "identity_matches", lambda _value: True)
    monkeypatch.setattr(kv_trace, "socket_inodes", lambda pid: {pid - 90})
    values = kv_trace.verify_listener_ownership(nodes, (9101, 9102, 9103))
    assert values == [
        ListenerIdentity("127.0.0.1", 9101, 11, 101, 1),
        ListenerIdentity("127.0.0.1", 9102, 12, 102, 2),
        ListenerIdentity("127.0.0.1", 9103, 13, 103, 3),
    ]
    monkeypatch.setattr(kv_trace, "socket_inodes", lambda _pid: set())
    with pytest.raises(HarnessError, match="not owned"):
        kv_trace.verify_listener_ownership(nodes, (9101, 9102, 9103))


def test_mount_resolution_selects_longest_containing_mount(tmp_path: Path) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "1 0 8:1 / / rw - ext4 /dev/root rw\n"
        "2 1 8:2 / /srv rw - ext4 /dev/data rw\n"
        "3 2 8:3 / /srv/task rw - ext4 /dev/task rw\n",
        encoding="utf-8",
    )
    assert (
        kv_trace.select_containing_mount(
            "/srv/task/run/data", mountinfo.read_text(encoding="utf-8")
        )
        == "/srv/task"
    )


def test_capture_classifies_empty_truncated_partial_and_usable(tmp_path: Path) -> None:
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"")
    assert kv_trace.classify_pcap(pcap, "", "", (9101, 9102, 9103))["classification"] == "empty"
    pcap.write_bytes(b"x" * 12)
    assert kv_trace.classify_pcap(pcap, "", "", (9101, 9102, 9103))["classification"] == "truncated"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
    assert (
        kv_trace.classify_pcap(pcap, "", "", (9101, 9102, 9103))["classification"] == "header_only"
    )
    pcap.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 2, 8, 8)
        + b"short"
    )
    assert (
        kv_trace.classify_pcap(pcap, "", "", (9101, 9102, 9103))["classification"]
        == "truncated_packet_data"
    )
    pcap.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 2, 4, 4)
        + b"data"
    )
    partial = kv_trace.classify_pcap(
        pcap, "", "0 packets captured\n0 packets dropped by kernel\n", (9101, 9102, 9103)
    )
    assert partial["classification"] == "partial" and not partial["usable"]
    usable = kv_trace.classify_pcap(
        pcap,
        "2026-11-09 13:00:00.123456 IP 127.0.0.1.50000 > 127.0.0.1.9101: Flags [P.], length 12\n",
        "4 packets captured\n4 packets received by filter\n0 packets dropped by kernel\n",
        (9101, 9102, 9103),
    )
    assert usable["classification"] == "usable" and usable["kernel_drops"] == 0


def test_capture_capacity_fits_worst_case_records_inside_artifact_bound() -> None:
    assert kv_trace.TCPDUMP_SNAPLEN == 512
    assert kv_trace.TCPDUMP_PACKET_LIMIT == 30_000
    assert kv_trace.TCPDUMP_CAPACITY_BYTES == 15_840_024
    assert kv_trace.TCPDUMP_CAPACITY_BYTES <= kv_trace.MAX_PCAP_BYTES


def test_capture_rejects_and_reports_snapshot_payload_truncation(tmp_path: Path) -> None:
    pcap = tmp_path / "truncated-payload.pcap"
    pcap.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, kv_trace.TCPDUMP_SNAPLEN, 1)
        + struct.pack("<IIII", 1, 2, 4, 8)
        + b"data"
    )
    classified = kv_trace.classify_pcap(
        pcap,
        "2026-11-09 13:00:00.123456 IP 127.0.0.1.50000 > 127.0.0.1.9101: Flags [P.], length 8\n",
        "1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n",
        (9101, 9102, 9103),
    )
    assert classified["classification"] == "partial"
    assert classified["usable"] is False
    assert classified["payload_truncations"] == 1
    assert classified["structure"]["valid"] is True
    assert classified["structure"]["payload_truncations"] == 1


def test_capture_reports_unreadable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "denied.pcap"

    def denied(_self: Path) -> os.stat_result:
        raise PermissionError

    monkeypatch.setattr(Path, "stat", denied)
    assert (
        kv_trace.classify_pcap(path, "", "", (9101, 9102, 9103))["classification"] == "unreadable"
    )


def test_trace_classification_requires_storage_and_tcp_evidence(tmp_path: Path) -> None:
    assert kv_trace.classify_traces(tmp_path)["classification"] == "empty"
    (tmp_path / "node.1").write_text(
        '1.0 pwrite64(3</run/raft.log>, "x", 1, 0) = 1 <0.001>\n'
        "1.1 fdatasync(3</run/raft.log>) = 0 <0.002>\n"
        '1.2 sendto(4<TCP:[127.0.0.1:9101->127.0.0.1:9102]>, "x", 1, 0, NULL, 0) = 1\n',
        encoding="utf-8",
    )
    assert kv_trace.classify_traces(tmp_path)["usable"] is True
    (tmp_path / "node.1").write_text(
        "1.0 fdatasync(3</run/raft.log>) = -1 EIO (Input/output error)\n"
        "1.2 connect(4<TCP:[127.0.0.1:9101]>, NULL, 0) = -1 ECONNREFUSED\n",
        encoding="utf-8",
    )
    assert kv_trace.classify_traces(tmp_path)["usable"] is False


def test_workload_uses_exact_phase_boundaries_and_retains_semantic_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = fake_config(tmp_path)
    config = replace(config, pairs=1, pace_seconds=15.0)
    (config.output / "logs").mkdir(parents=True)
    (config.output / "traces").mkdir()
    current = 10.0

    def monotonic() -> float:
        return current

    def sleep(seconds: float) -> None:
        nonlocal current
        current += seconds

    def client(
        _config: RunConfig,
        operation: list[str],
        **_kwargs: Any,
    ) -> CommandResult:
        if operation[0] == "put":
            return result(
                stdout="committed term 1 index 2\n", stderr=f"request id {operation[-1]}\n"
            )
        return result(stdout="fleetdoctor-untraced-value-00\n")

    timestamps = iter(["start-utc", "end-utc"])
    monkeypatch.setattr("kv_trace.time.monotonic", monotonic)
    monkeypatch.setattr("kv_trace.time.sleep", sleep)
    monkeypatch.setattr(kv_trace, "run_client", client)
    monkeypatch.setattr(kv_trace, "utc_now", lambda: next(timestamps))
    phase = kv_trace.run_workload(
        config, "untraced", strace=None, trace_dir=config.output / "traces"
    )
    assert phase["started_utc"] == "start-utc"
    assert phase["ended_utc"] == "end-utc"
    assert phase["started_monotonic"] == 10.0
    assert phase["ended_monotonic"] == 25.0
    assert phase["elapsed_seconds"] == 15.0

    def failed_client(
        _config: RunConfig,
        _operation: list[str],
        **_kwargs: Any,
    ) -> CommandResult:
        return result(code=4, stdout="outcome unknown\n", stderr="request id " + "0" * 32)

    monkeypatch.setattr(kv_trace, "run_client", failed_client)
    monkeypatch.setattr(kv_trace, "utc_now", lambda: "failed-start")
    with pytest.raises(HarnessError, match="exit code 4"):
        kv_trace.run_workload(config, "failed", strace=None, trace_dir=config.output / "traces")
    retained = (config.output / "logs" / "workload-failed.jsonl").read_text(encoding="utf-8")
    assert "outcome unknown" in retained
    assert "semantic_failure" in retained


def test_sample_assessment_preserves_baseline_missing_and_identity_facts() -> None:
    nodes = [
        identity(11, 21),
        identity(12, 22, kind="dkv-node-2"),
        identity(13, 23, kind="dkv-node-3"),
    ]
    baseline: dict[str, Any] = {
        "result": {
            "cpu": {
                "processes": [
                    {
                        "identity": {"pid": node.pid, "starttime_ticks": node.starttime},
                        "configured": True,
                        "rss_bytes": 4096,
                        "cpu_percent": None,
                    }
                    for node in nodes
                ],
                "errors": ["cpu_rate_baseline_unavailable"],
            },
            "memory": {"errors": []},
            "fd": {
                "observations": [
                    {
                        "identity": {"pid": node.pid, "starttime_ticks": node.starttime},
                        "status": "present",
                        "configured": True,
                        "descriptor_count": 4,
                    }
                    for node in nodes
                ],
                "errors": [],
            },
            "network": {"errors": ["target_unconfigured"]},
            "io": {
                "processes": [
                    {
                        "pid": node.pid,
                        "starttime": node.starttime,
                        "status": "available",
                        "rate_status": "baseline",
                    }
                    for node in nodes
                ],
                "errors": [],
            },
        }
    }
    available = json.loads(json.dumps(baseline))
    for process in available["result"]["cpu"]["processes"]:
        process["cpu_percent"] = 0.1
    for process in available["result"]["io"]["processes"]:
        process["rate_status"] = "available"
    baseline["monotonic"] = 101.0
    available["monotonic"] = 106.0
    third = json.loads(json.dumps(available))
    third["monotonic"] = 111.0
    phases = [{"phase": "untraced", "started_monotonic": 100.0, "ended_monotonic": 115.0}]
    assessment = kv_trace.sample_assessment([baseline, available, third], nodes, phases)
    assert assessment["identity_stable"] is True
    assert assessment["coverage"] == "available"
    assert "cpu_rate_baseline_unavailable" in assessment["errors"]
    assert "target_unconfigured" in assessment["errors"]
    assert assessment["phase_sample_counts"] == {"untraced": 3}
    mismatch = json.loads(json.dumps(available))
    mismatch["result"]["cpu"]["processes"][0]["identity"]["starttime_ticks"] = 999
    assert kv_trace.sample_assessment([mismatch], nodes)["identity_stable"] is False
    unconfigured_fd = json.loads(json.dumps(available))
    unconfigured_fd["result"]["fd"]["observations"][0]["configured"] = False
    partial = kv_trace.sample_assessment([unconfigured_fd], nodes)
    assert partial["coverage"] == "partial"
    assert (nodes[0].pid, nodes[0].starttime) in partial["missing"]["fd_present_count"]


def test_sample_schema_rejects_wrong_shapes_malformed_and_nonfinite_values() -> None:
    valid = {
        "monotonic": 1.0,
        "result": {
            "cpu": {
                "processes": [
                    {
                        "identity": {"pid": 1, "starttime_ticks": 2},
                        "configured": True,
                        "rss_bytes": 1,
                        "cpu_percent": 0.1,
                    }
                ],
                "errors": [],
            },
            "memory": {},
            "fd": {
                "observations": [
                    {
                        "identity": {"pid": 1, "starttime_ticks": 2},
                        "status": "present",
                        "configured": True,
                        "descriptor_count": 3,
                    }
                ],
                "errors": [],
            },
            "network": {"errors": []},
            "io": {
                "processes": [
                    {
                        "pid": 1,
                        "starttime": 2,
                        "status": "available",
                        "rate_status": "available",
                    }
                ],
                "errors": [],
            },
        },
    }
    assert kv_trace.parse_sample_records(json.dumps(valid))[0]["monotonic"] == 1.0
    unavailable = json.loads(json.dumps(valid))
    unavailable["result"]["io"]["processes"] = [
        {
            "pid": 9,
            "starttime": None,
            "status": "unavailable",
            "rate_status": "unavailable",
            "errors": ["proc_unavailable"],
        }
    ]
    parsed_unavailable = kv_trace.parse_sample_records(json.dumps(unavailable))
    unavailable_assessment = kv_trace.sample_assessment(parsed_unavailable, [identity(9, 99)])
    assert unavailable_assessment["io_nonbaseline_identities"] == []
    for invalid_starttime in (False, 1.5, "2"):
        invalid_io = json.loads(json.dumps(valid))
        invalid_io["result"]["io"]["processes"][0]["starttime"] = invalid_starttime
        with pytest.raises(HarnessError, match="starttime is invalid"):
            kv_trace.parse_sample_records(json.dumps(invalid_io))
    unavailable_with_identity = json.loads(json.dumps(unavailable))
    unavailable_with_identity["result"]["io"]["processes"][0]["starttime"] = 99
    with pytest.raises(HarnessError, match="starttime is invalid"):
        kv_trace.parse_sample_records(json.dumps(unavailable_with_identity))
    invalid_lines = [
        "[]",
        '{"monotonic":1,"result":[]}',
        '{"monotonic":1,"result":{"cpu":{"processes":["x"]}}}',
        "{not-json}",
    ]
    nonfinite = json.loads(json.dumps(valid))
    nonfinite["result"]["cpu"]["processes"][0]["cpu_percent"] = float("nan")
    invalid_lines.append(json.dumps(nonfinite))
    for value in invalid_lines:
        with pytest.raises(HarnessError, match="direct sample"):
            kv_trace.parse_sample_records(value)


def test_gate_refuses_stale_and_requires_readiness_hash(tmp_path: Path) -> None:
    gate = tmp_path / "gate.json"
    gate.write_text("{}", encoding="utf-8")
    with pytest.raises(HarnessError, match="stale"):
        kv_trace.wait_for_gate(gate, "a" * 64, 1)
    gate.unlink()

    def release() -> None:
        time.sleep(0.05)
        gate.write_text(
            json.dumps({"release": True, "readiness_sha256": "a" * 64}), encoding="utf-8"
        )

    thread = threading.Thread(target=release)
    thread.start()
    assert (
        kv_trace.wait_for_gate(gate, "a" * 64, 1, expected_uid=getattr(os, "geteuid", lambda: 0)())[
            "release"
        ]
        is True
    )
    thread.join()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux atomic no-replace publication contract")
def test_atomic_gate_publication_hides_partial_temp_and_refuses_stale_final(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    gate = tmp_path / "gate.json"
    payload = {"release": True, "readiness_sha256": "a" * 64}
    observed: list[str] = []
    real_link = os.link

    def inspected_link(source: Path, target: Path, *, follow_symlinks: bool = True) -> None:
        assert target == gate
        assert not gate.exists()
        assert json.loads(source.read_text(encoding="utf-8")) == payload
        observed.append(source.name)
        real_link(source, target, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "link", inspected_link)
    kv_trace.publish_json_no_replace(
        gate,
        payload,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
    )
    assert json.loads(gate.read_text(encoding="utf-8")) == payload
    assert len(observed) == 1
    assert not list(tmp_path.glob(".gate.json.*.tmp"))

    monkeypatch.setattr(os, "link", real_link)
    stale = gate.read_bytes()
    with pytest.raises(HarnessError, match="already exists"):
        kv_trace.publish_json_no_replace(
            gate,
            {"release": False},
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
    assert gate.read_bytes() == stale
    assert not list(tmp_path.glob(".gate.json.*.tmp"))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux TCP TIME_WAIT cleanup contract")
def test_port_release_accepts_time_wait_without_accepting_a_listener() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    port = int(server.getsockname()[1])
    server.listen(1)
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    accepted, _ = server.accept()
    accepted.shutdown(socket.SHUT_WR)
    assert client.recv(1) == b""
    accepted.close()
    client.close()
    server.close()

    extra_ports: list[int] = []
    while len(extra_ports) < 2:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        candidate = int(probe.getsockname()[1])
        probe.close()
        if candidate != port and candidate not in extra_ports:
            extra_ports.append(candidate)
    ports = (port, extra_ports[0], extra_ports[1])
    with pytest.raises(HarnessError, match="occupied"):
        kv_trace.ports_available(ports)
    assert kv_trace.ports_released(ports) is True


def test_early_capture_exit_is_rejected_after_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExitedProcess:
        def poll(self) -> int:
            return 7

    monkeypatch.setattr(kv_trace, "identity_matches", lambda _identity: True)
    process: Any = ExitedProcess()
    states = kv_trace.capture_process_states([(process, identity(101, 202, kind="tcpdump"))])
    assert states[0]["running"] is False
    assert states[0]["returncode"] == 7
    with pytest.raises(HarnessError, match="before shutdown"):
        kv_trace.validate_capture_process_states(states)
    assert kv_trace.expected_capture_stop(7) is False


def test_watchdog_expiry_is_monotonic_despite_wall_clock_shift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cleaned: list[Path] = []
    monkeypatch.setattr(kv_trace, "watchdog_cleanup", lambda state, *_args: cleaned.append(state))
    monkeypatch.setattr(time, "monotonic", lambda: 50.0)
    monkeypatch.setattr(time, "time", lambda: -(10**12))
    state = tmp_path / "state.json"
    learned = tmp_path / "learned.json"
    assert kv_trace.watchdog_main(state, learned, 49.0) == 2
    assert cleaned == [state]


@pytest.mark.skipif(os.name != "posix", reason="POSIX process ownership contract")
def test_owned_cleanup_refuses_changed_identity_then_stops_exact_process() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
    )
    actual = kv_trace.capture_identity("fixture", process.pid)
    replaced = ProcessIdentity(
        actual.kind, actual.pid, actual.starttime + 1, actual.pgid, actual.uid
    )
    try:
        assert kv_trace.signal_owned(replaced, signal.SIGTERM) is False
        assert process.poll() is None
        assert kv_trace.terminate_popen(process, actual, signal.SIGTERM)
        assert process.returncode is not None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


@pytest.mark.skipif(os.name != "posix", reason="POSIX timeout contract")
def test_bounded_command_timeout_reaps_owned_process() -> None:
    with pytest.raises(HarnessError, match="timed out"):
        kv_trace.run_bounded_command(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            user=current_user(),
            timeout=0.05,
            kind="timeout-fixture",
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX bounded pipe and registry contract")
def test_bounded_command_streams_limits_and_registers_short_child(tmp_path: Path) -> None:
    registered: list[ProcessIdentity] = []
    unregistered: list[ProcessIdentity] = []
    failure = tmp_path / "failure.json"
    with pytest.raises(HarnessError, match="stdout exceeded bound"):
        kv_trace.run_bounded_command(
            [sys.executable, "-c", "print('x' * 100000)"],
            user=current_user(),
            timeout=3,
            kind="bounded-fixture",
            stdout_limit=1024,
            register=lambda _process, child: registered.append(child),
            unregister=unregistered.append,
            failure_output=failure,
        )
    assert len(registered) == 1
    assert unregistered == registered
    retained = json.loads(failure.read_text(encoding="utf-8"))
    assert "stdout exceeded bound" in retained["error"]
    assert retained["stdout_prefix"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX watchdog contract")
def test_controller_death_watchdog_expires_owned_process(tmp_path: Path) -> None:
    owned = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
    )
    owned_identity = kv_trace.capture_identity("owned-fixture", owned.pid)
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps(
            {
                "processes": [asdict(owned_identity)],
                "run_uid": os.geteuid(),
                "sampler": None,
            }
        ),
        encoding="utf-8",
    )
    learned = tmp_path / "learned.json"
    watchdog = subprocess.Popen(
        [
            sys.executable,
            str(Path(kv_trace.__file__).resolve()),
            "--_watchdog-state",
            str(state),
            "--_watchdog-learned",
            str(learned),
            "--_watchdog-deadline",
            str(time.monotonic() + 10),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        assert watchdog.stdin is not None
        watchdog.stdin.close()
        watchdog.wait(timeout=5)
        owned.wait(timeout=5)
        assert watchdog.returncode == 1
        assert owned.returncode is not None
    finally:
        if watchdog.poll() is None:
            watchdog.kill()
            watchdog.wait()
        if owned.poll() is None:
            owned.kill()
            owned.wait()


def fake_config(tmp_path: Path) -> RunConfig:
    executable = Path(sys.executable)
    archive = tmp_path / "source.tar"
    archive.write_bytes(b"source")
    current = UserIdentity(
        "fixture",
        getattr(os, "geteuid", lambda: 1000)(),
        getattr(os, "getegid", lambda: 1000)(),
        str(tmp_path),
    )
    return RunConfig(
        executable,
        executable,
        archive,
        kv_trace.sha256_file(archive),
        "a" * 40,
        tmp_path / "run",
        (9101, 9102, 9103),
        current,
        8,
        2.0,
        60,
        None,
        30,
        kv_trace.MAX_OUTPUT_BYTES,
    )


def prepare_fake_controller_output(
    controller: kv_trace.Controller, sample: str | None = None
) -> None:
    controller.config.output.mkdir()
    (controller.config.output / "control").mkdir()
    (controller.config.output / "samples").mkdir()
    if sample is not None:
        (controller.config.output / "samples" / "direct-samples.jsonl").write_text(
            sample, encoding="utf-8"
        )
    controller.save()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux protected sample finalization contract")
def test_wrong_shape_sample_forces_failed_terminal_manifest_after_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    controller = kv_trace.Controller(fake_config(tmp_path))
    observed: list[str] = []
    monkeypatch.setattr(
        controller,
        "execute",
        lambda _tools: prepare_fake_controller_output(controller, "[]\n"),
    )

    def cleanup() -> bool:
        observed.append(json.loads(controller.manifest_path.read_text(encoding="utf-8"))["status"])
        controller.manifest["port_release_verified"] = True
        return True

    monkeypatch.setattr(controller, "cleanup", cleanup)
    assert controller.run({}) == 1
    retained = json.loads(controller.manifest_path.read_text(encoding="utf-8"))
    assert observed == ["finalizing"]
    assert retained["status"] == "failed"
    assert "direct sample line 1 is not an object" in retained["sample_finalization_exception"]
    assert retained["port_release_verified"] is True
    assert "finished_utc" in retained


def test_assessment_exception_is_failed_and_signal_handlers_are_restored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    controller = kv_trace.Controller(fake_config(tmp_path))
    previous = {item: signal.getsignal(item) for item in (signal.SIGINT, signal.SIGTERM)}
    monkeypatch.setattr(
        controller,
        "execute",
        lambda _tools: prepare_fake_controller_output(controller),
    )

    def cleanup() -> bool:
        assert (
            json.loads(controller.manifest_path.read_text(encoding="utf-8"))["status"]
            == "finalizing"
        )
        controller.manifest["port_release_verified"] = True
        return True

    def broken_assessment(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("assessment fixture failure")

    monkeypatch.setattr(controller, "cleanup", cleanup)
    monkeypatch.setattr(kv_trace, "sample_assessment", broken_assessment)
    assert controller.run({}) == 1
    retained = json.loads(controller.manifest_path.read_text(encoding="utf-8"))
    assert retained["status"] == "failed"
    assert "assessment fixture failure" in retained["sample_finalization_exception"]
    assert all(signal.getsignal(item) == handler for item, handler in previous.items())


@pytest.mark.skipif(sys.platform != "linux", reason="Linux finalization interruption contract")
def test_signal_during_finalization_saves_failure_and_restores_handler(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    controller = kv_trace.Controller(fake_config(tmp_path))
    previous = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(
        controller,
        "execute",
        lambda _tools: prepare_fake_controller_output(controller),
    )

    def interrupted_cleanup() -> bool:
        assert (
            json.loads(controller.manifest_path.read_text(encoding="utf-8"))["status"]
            == "finalizing"
        )
        os.kill(os.getpid(), signal.SIGTERM)
        raise AssertionError("SIGTERM handler did not interrupt cleanup")

    monkeypatch.setattr(controller, "cleanup", interrupted_cleanup)
    assert controller.run({}) == 1
    retained = json.loads(controller.manifest_path.read_text(encoding="utf-8"))
    assert retained["status"] == "failed"
    assert "KeyboardInterrupt" in retained["cleanup_exception"]
    assert signal.getsignal(signal.SIGTERM) == previous


def test_partial_launch_retains_failed_terminal_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    controller = kv_trace.Controller(fake_config(tmp_path))

    def prepare() -> None:
        controller.config.output.mkdir()
        for name in ("control", "samples"):
            (controller.config.output / name).mkdir()
        controller.manifest["environment"] = {"tools": {}}
        controller.save()

    def partial() -> list[ListenerIdentity]:
        raise HarnessError("partial node launch")

    def cleanup() -> bool:
        controller.manifest["port_release_verified"] = True
        return True

    monkeypatch.setattr(controller, "prepare_output", prepare)
    monkeypatch.setattr(controller, "start_watchdog", lambda: None)
    monkeypatch.setattr(controller, "start_nodes", partial)
    monkeypatch.setattr(controller, "cleanup", cleanup)
    assert controller.run({}) == 1
    retained = json.loads(controller.manifest_path.read_text(encoding="utf-8"))
    assert retained["status"] == "failed"
    assert "partial node launch" in retained["error"]
    assert retained["port_release_verified"] is True


def test_decoder_nonzero_is_a_hard_failure_with_diagnostics_available() -> None:
    failed = result(code=1, stderr="pcap: truncated dump file\n")
    with pytest.raises(HarnessError, match="decoder failed with exit code 1"):
        kv_trace.validate_decoder_result(failed)
    assert "truncated" in failed.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Linux protected process authority contract")
def test_watchdog_ignores_forged_auxiliary_foreign_and_non_descendant_processes(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state.json"
    auxiliary = tmp_path / "sampler.json"
    learned = tmp_path / "learned.json"
    foreign = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    non_descendant = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    foreign_identity = kv_trace.capture_identity("forged-foreign", foreign.pid)
    foreign_identity = replace(foreign_identity, uid=foreign_identity.uid + 1)
    non_descendant_identity = kv_trace.capture_identity("forged-peer", non_descendant.pid)
    auxiliary.write_text(
        json.dumps({"processes": [asdict(foreign_identity), asdict(non_descendant_identity)]}),
        encoding="utf-8",
    )
    state.write_text(
        json.dumps(
            {
                "processes": [],
                "run_uid": os.geteuid(),
                "sampler": None,
                "aux_state_files": [str(auxiliary)],
            }
        ),
        encoding="utf-8",
    )
    try:
        assert kv_trace.watchdog_targets(state, learned) == []
        kv_trace.watchdog_cleanup(state, learned)
        assert foreign.poll() is None
        assert non_descendant.poll() is None
    finally:
        for process in (foreign, non_descendant):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux no-follow file contract")
def test_protected_reads_and_exclusive_write_refuse_symlink_fifo_and_oversize(
    tmp_path: Path,
) -> None:
    trap = tmp_path / "trap"
    trap.write_bytes(b"trap-bytes")
    trap_before = trap.stat()
    planted = tmp_path / "planted.json"
    planted.symlink_to(trap)
    with pytest.raises(HarnessError, match="protected read"):
        kv_trace.bounded_owned_text(planted, expected_uid=os.geteuid())
    with pytest.raises(HarnessError, match="protected JSON path"):
        kv_trace.write_json_exclusive(
            planted,
            {"changed": True},
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            mode=0o600,
        )
    assert trap.read_bytes() == b"trap-bytes"
    assert (trap.stat().st_uid, trap.stat().st_gid) == (trap_before.st_uid, trap_before.st_gid)
    with pytest.raises(HarnessError, match="unexpected owner"):
        kv_trace.bounded_owned_text(trap, expected_uid=os.geteuid() + 1)

    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)
    started = time.monotonic()
    with pytest.raises(HarnessError, match="not a regular file"):
        kv_trace.bounded_owned_text(fifo, expected_uid=os.geteuid())
    assert time.monotonic() - started < 1.0

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * 33)
    with pytest.raises(HarnessError, match="exceeds 32 bytes"):
        kv_trace.bounded_owned_text(oversized, expected_uid=os.geteuid(), maximum=32)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux listener ownership contract")
def test_post_gate_listener_replacement_aborts_before_client_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ports = three_free_ports()
    child_code = """
import socket, sys, time
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(('127.0.0.1', int(sys.argv[1])))
listener.listen(1)
print('ready', flush=True)
for command in sys.stdin:
    if command.strip() == 'close' and listener is not None:
        listener.close()
        listener = None
        print('closed', flush=True)
time.sleep(30)
"""

    def start_listener(port: int) -> subprocess.Popen[str]:
        process = subprocess.Popen(
            [sys.executable, "-c", child_code, str(port)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "ready"
        return process

    originals = [start_listener(port) for port in ports]
    replacement: subprocess.Popen[str] | None = None
    try:
        identities = [
            kv_trace.capture_identity(f"dkv-node-{index}", process.pid)
            for index, process in enumerate(originals, start=1)
        ]
        assert originals[0].stdin is not None
        assert originals[0].stdout is not None
        originals[0].stdin.write("close\n")
        originals[0].stdin.flush()
        assert originals[0].stdout.readline().strip() == "closed"
        replacement = start_listener(ports[0])

        controller = kv_trace.Controller(replace(fake_config(tmp_path), ports=ports))
        controller.node_processes = list(zip(originals, identities, strict=True))
        client_called = False

        def forbidden_workload(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            nonlocal client_called
            client_called = True
            raise AssertionError("client workload must not start after listener replacement")

        monkeypatch.setattr(kv_trace, "run_workload", forbidden_workload)
        with pytest.raises(HarnessError, match="listener is not owned"):
            controller.run_untraced_after_gate()
        assert client_called is False
        assert controller.manifest.get("listener_checks") is None
    finally:
        for process in [*originals, *([replacement] if replacement is not None else [])]:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux protected runtime audit contract")
def test_recursive_prelaunch_audit_requires_root_and_rejects_unsafe_entries(tmp_path: Path) -> None:
    if os.geteuid() != 0:
        runtime = tmp_path / "runtime"
        runtime.mkdir()
        with pytest.raises(HarnessError, match="requires Linux root"):
            kv_trace.audit_protected_runtime(runtime, runtime / "venv/bin/python", os.geteuid())
        return

    runtime = Path(tempfile.mkdtemp(prefix="kv-trace-audit-", dir="/var/lib"))
    unsafe_descriptor, unsafe_name = tempfile.mkstemp(prefix="kv-trace-unsafe-", dir="/tmp")
    os.close(unsafe_descriptor)
    unsafe_target = Path(unsafe_name)
    try:
        for relative in ("venv/bin", "scripts", "src"):
            (runtime / relative).mkdir(parents=True, exist_ok=True)
        for path in (runtime, *runtime.rglob("*")):
            if path.is_dir():
                path.chmod(0o755)
        venv_python = runtime / "venv" / "bin" / "python"
        venv_python.symlink_to(linux_fixture_python())
        result_value = kv_trace.audit_protected_runtime(runtime, venv_python, 65534)
        assert result_value["passed"] is True
        assert result_value["resolved_python"].startswith("/usr/")

        writable = runtime / "src" / "writable.py"
        writable.write_text("pass\n", encoding="utf-8")
        writable.chmod(0o666)
        with pytest.raises(HarnessError, match="group/world writable"):
            kv_trace.audit_protected_runtime(runtime, venv_python, 65534)
        writable.unlink()

        escape = runtime / "src" / "escape.py"
        escape.symlink_to(unsafe_target)
        with pytest.raises(HarnessError, match="not root-owned and protected"):
            kv_trace.audit_protected_runtime(runtime, venv_python, 65534)
    finally:
        shutil.rmtree(runtime)
        unsafe_target.unlink(missing_ok=True)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux protected ancestor contract")
def test_unsafe_runtime_and_output_parent_are_rejected_without_touching_trap(
    tmp_path: Path,
) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    runtime = unsafe / "kv_trace.py"
    runtime.write_bytes(b"unchanged")
    before = runtime.stat()
    with pytest.raises(HarnessError, match="root-owned and protected"):
        kv_trace.require_protected_directory(unsafe, "output parent")
    with pytest.raises(HarnessError, match="root-owned and protected"):
        kv_trace.require_protected_file(runtime, "controller runtime file")
    assert runtime.read_bytes() == b"unchanged"
    assert (runtime.stat().st_uid, runtime.stat().st_gid) == (before.st_uid, before.st_gid)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descendant cleanup contract")
def test_watchdog_discovers_and_cleans_setsid_sampler_descendant(tmp_path: Path) -> None:
    run_user, owned, child_python = linux_fixture_user(tmp_path)
    child_pid_path = owned / "child.pid"
    sampler_code = (
        "import pathlib,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],"
        "start_new_session=True); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(30)"
    )
    devnull = open(os.devnull, "w", encoding="utf-8")
    sampler, sampler_identity = kv_trace.spawn_owned(
        [child_python, "-c", sampler_code, str(child_pid_path)],
        kind="direct-sampler",
        user=run_user,
        stdin=subprocess.DEVNULL,
        stdout=devnull,
        stderr=devnull,
    )
    state = tmp_path / "state.json"
    learned = tmp_path / "learned.json"
    state.write_text(
        json.dumps(
            {
                "processes": [asdict(sampler_identity)],
                "run_uid": run_user.uid,
                "sampler": asdict(sampler_identity),
            }
        ),
        encoding="utf-8",
    )
    watchdog = subprocess.Popen(
        [
            sys.executable,
            str(Path(kv_trace.__file__).resolve()),
            "--_watchdog-state",
            str(state),
            "--_watchdog-learned",
            str(learned),
            "--_watchdog-deadline",
            str(time.monotonic() + 15),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    child_identity: ProcessIdentity | None = None
    try:
        wait_for_path(child_pid_path)
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        child_identity = kv_trace.capture_identity("sampler-descendant", child_pid)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if learned.exists():
                values = json.loads(learned.read_text(encoding="utf-8")).get("processes", [])
                if any(item.get("pid") == child_pid for item in values):
                    break
            time.sleep(0.05)
        else:
            raise AssertionError("watchdog did not learn setsid sampler descendant")
        assert watchdog.stdin is not None
        watchdog.stdin.close()
        watchdog.wait(timeout=6)
        sampler.wait(timeout=6)
        assert watchdog.returncode == 1
        assert kv_trace.wait_identity_exit(child_identity, 5)
    finally:
        devnull.close()
        if watchdog.poll() is None:
            watchdog.kill()
            watchdog.wait()
        if sampler.poll() is None:
            kv_trace.terminate_popen(sampler, sampler_identity, signal.SIGKILL)
        if child_identity is not None and kv_trace.identity_matches(child_identity):
            kv_trace.terminate_owned(child_identity, signal.SIGKILL)
        shutil.rmtree(owned, ignore_errors=True)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux parent-death signal contract")
def test_abrupt_parent_death_during_registration_reaps_child(tmp_path: Path) -> None:
    marker = tmp_path / "registered.json"
    script_dir = str(Path(kv_trace.__file__).resolve().parent)
    code = """
import json, os, pathlib, subprocess, sys, time
sys.path.insert(0, sys.argv[1])
import kv_trace
pwd = __import__('pwd')
rec = pwd.getpwnam('nobody') if os.geteuid() == 0 else pwd.getpwuid(os.geteuid())
user = kv_trace.UserIdentity(rec.pw_name, rec.pw_uid, rec.pw_gid, rec.pw_dir)
child_python = sys.argv[3]
def register(process, identity):
    pathlib.Path(sys.argv[2]).write_text(json.dumps(kv_trace.asdict(identity)))
    time.sleep(30)
kv_trace.spawn_owned([child_python, '-c', 'import time; time.sleep(30)'],
    kind='registration-child', user=user, stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, register=register)
"""
    parent = subprocess.Popen(
        [sys.executable, "-c", code, script_dir, str(marker), linux_fixture_python()]
    )
    child_identity: ProcessIdentity | None = None
    try:
        wait_for_path(marker)
        child_identity = ProcessIdentity(**json.loads(marker.read_text(encoding="utf-8")))
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait(timeout=5)
        assert kv_trace.wait_identity_exit(child_identity, 5)
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait()
        if child_identity is not None and kv_trace.identity_matches(child_identity):
            kv_trace.terminate_owned(child_identity, signal.SIGKILL)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux exec timer contract")
def test_idle_capture_child_has_independent_exec_expiry_and_unblocks_sigalrm(
    tmp_path: Path,
) -> None:
    run_user, owned, child_python = linux_fixture_user(tmp_path)
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    devnull = open(os.devnull, "w", encoding="utf-8")
    process: subprocess.Popen[str] | None = None
    identity_value: ProcessIdentity | None = None
    try:
        process, identity_value = kv_trace.spawn_owned(
            [child_python, "-c", "import time; time.sleep(30)"],
            kind="idle-capture-fixture",
            user=run_user,
            stdin=subprocess.DEVNULL,
            stdout=devnull,
            stderr=devnull,
            parent_death_signal=None,
            exec_expiry_seconds=0.2,
        )
        process.wait(timeout=5)
        assert process.returncode == -signal.SIGALRM
        current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        assert signal.SIGALRM in current_mask
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        devnull.close()
        if process is not None and process.poll() is None and identity_value is not None:
            kv_trace.terminate_popen(process, identity_value, signal.SIGKILL)
        shutil.rmtree(owned, ignore_errors=True)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux controller signal contract")
@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_controller_signal_during_registration_is_terminal_and_cleans_child(
    tmp_path: Path, signum: signal.Signals
) -> None:
    output = tmp_path / f"run-{signum.name.lower()}"
    marker = tmp_path / f"register-{signum.name.lower()}.json"
    archive = tmp_path / "source.tar"
    archive.write_bytes(b"source")
    ports = three_free_ports()
    script_dir = str(Path(kv_trace.__file__).resolve().parent)
    code = """
import json, os, pathlib, signal, subprocess, sys, time
sys.path.insert(0, sys.argv[1])
import kv_trace
pwd = __import__('pwd')
rec = pwd.getpwnam('nobody') if os.geteuid() == 0 else pwd.getpwuid(os.geteuid())
user = kv_trace.UserIdentity(rec.pw_name, rec.pw_uid, rec.pw_gid, rec.pw_dir)
child_python = sys.argv[8]
output = pathlib.Path(sys.argv[2])
marker = pathlib.Path(sys.argv[3])
archive = pathlib.Path(sys.argv[4])
ports = tuple(int(value) for value in sys.argv[5:8])
config = kv_trace.RunConfig(pathlib.Path(sys.executable), pathlib.Path(sys.executable), archive,
    kv_trace.sha256_file(archive), 'a' * 40, output, ports, user, 8, 2.0, 60, None, 30,
    kv_trace.MAX_OUTPUT_BYTES)
controller = kv_trace.Controller(config)
def prepare():
    output.mkdir()
    (output / 'control').mkdir()
    (output / 'samples').mkdir()
    controller.manifest['environment'] = {'tools': {}}
    controller.save()
def start_nodes():
    def register(process, identity):
        controller.add_process(process, identity)
        marker.write_text(json.dumps(kv_trace.asdict(identity)))
        time.sleep(1.0)
    kv_trace.spawn_owned([child_python, '-c', 'import time; time.sleep(30)'],
        kind='registration-child', user=user, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, register=register)
    raise AssertionError('signal was not delivered')
controller.prepare_output = prepare
controller.start_watchdog = lambda: None
controller.start_nodes = start_nodes
raise SystemExit(controller.run({}))
"""
    parent = subprocess.Popen(
        [
            sys.executable,
            "-c",
            code,
            script_dir,
            str(output),
            str(marker),
            str(archive),
            *(str(port) for port in ports),
            linux_fixture_python(),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    child_identity: ProcessIdentity | None = None
    try:
        wait_for_path(marker)
        child_identity = ProcessIdentity(**json.loads(marker.read_text(encoding="utf-8")))
        os.kill(parent.pid, signum)
        stdout, stderr = parent.communicate(timeout=8)
        assert parent.returncode == 1, (stdout, stderr)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["status"] == "failed"
        assert "KeyboardInterrupt" in manifest["error"]
        assert any(
            item["kind"] == "registration-child" and item["clean"] is True
            for item in manifest["cleanup"]
        )
        assert manifest["cleanup_survivors"] == []
        assert kv_trace.wait_identity_exit(child_identity, 5)
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait()
        if child_identity is not None and kv_trace.identity_matches(child_identity):
            kv_trace.terminate_owned(child_identity, signal.SIGKILL)


def test_cli_help_is_cross_platform_and_does_not_start_capture() -> None:
    completed = subprocess.run(
        [sys.executable, str(Path(kv_trace.__file__).resolve()), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert completed.returncode == 0
    assert "exclusive new absolute output directory" in completed.stdout
    assert "root controller" in completed.stdout
