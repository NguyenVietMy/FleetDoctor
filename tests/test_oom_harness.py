import io
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import chaos_oom
import oom_helper_integration
import oom_smoke
import psycopg
import pytest


@pytest.mark.parametrize("pending_suffix", [".json", ".gate"])
def test_helper_expiry_waits_for_automatic_cleanup_before_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pending_suffix: str
) -> None:
    token = "a" * 32
    pending = tmp_path / (token + pending_suffix)
    pending.write_text("pending cleanup")
    clock = [0.0]
    calls: list[str] = []

    def status(*args: object) -> dict[str, Any]:
        assert not pending.exists(), "status polled a cgroup during automatic teardown"
        calls.append("status")
        return {"state": "absent"}

    def sleep(seconds: float) -> None:
        clock[0] += seconds
        pending.unlink()

    monkeypatch.setattr(oom_helper_integration, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(oom_helper_integration, "helper", status)
    monkeypatch.setattr("oom_helper_integration.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("oom_helper_integration.time.sleep", sleep)

    assert oom_helper_integration.wait_expired(Path("helper"), token, 1.0) == {"state": "absent"}
    assert calls == ["status"]


def test_helper_expiry_still_times_out_when_automatic_cleanup_stalls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "b" * 32
    pending = tmp_path / (token + ".json")
    pending.write_text("cleanup stalled")
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    monkeypatch.setattr(oom_helper_integration, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(
        oom_helper_integration, "helper", lambda *args: pytest.fail("pending state must not pass")
    )
    monkeypatch.setattr("oom_helper_integration.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("oom_helper_integration.time.sleep", sleep)

    with pytest.raises(TimeoutError, match="controller-independent limit"):
        oom_helper_integration.wait_expired(Path("helper"), token, 0.25)
    assert pending.exists()


def test_native_smoke_waits_for_tcp_and_authenticated_dsn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    connect_attempts = 0

    def command(argv: list[str], timeout: float = 30) -> subprocess.CompletedProcess[str]:
        commands.append(argv)
        return subprocess.CompletedProcess(argv, 0, "accepting connections", "")

    class Connection:
        def __enter__(self) -> "Connection":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str) -> "Connection":
            assert query == "SELECT 1"
            return self

        def fetchone(self) -> tuple[int]:
            return (1,)

    def connect(dsn: str, *, connect_timeout: int) -> Connection:
        nonlocal connect_attempts
        assert dsn == "host=127.0.0.1 port=54321"
        assert connect_timeout == 2
        connect_attempts += 1
        if connect_attempts == 1:
            raise psycopg.OperationalError("final TCP server not ready")
        return Connection()

    ticks = iter((0.0, 0.1, 0.2))
    monkeypatch.setattr(oom_smoke, "command", command)
    monkeypatch.setattr("oom_smoke.time.monotonic", lambda: next(ticks))
    monkeypatch.setattr("oom_smoke.time.sleep", lambda seconds: None)
    monkeypatch.setattr(psycopg, "connect", connect)

    oom_smoke.wait_postgres("proof-postgres", "host=127.0.0.1 port=54321")

    assert connect_attempts == 2
    assert len(commands) == 2
    assert all(command[4:8] == ["-h", "127.0.0.1", "-p", "5432"] for command in commands)


def test_api_and_helper_enforce_after_call_deadlines(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr("chaos_oom.time.monotonic", lambda: next(ticks))
    monkeypatch.setattr(chaos_oom, "urlopen", lambda request, timeout: io.BytesIO(b"{}"))
    with pytest.raises(TimeoutError, match="after-call"):
        chaos_oom.api("http://fixture", "token", 1.0)

    ticks = iter((0.0, 2.0))
    monkeypatch.setattr("chaos_oom.time.monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        "chaos_oom.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="{}", stderr=""),
    )
    with pytest.raises(TimeoutError, match="after-call"):
        chaos_oom.helper(Path("helper"), "status", "a" * 16, 1.0)


def test_reference_allows_baseline_old_generations_but_rejects_new_incidents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows: list[dict[str, Any]] = [{"id": "old-generation"}]

    def api(url: str, token: str, deadline: float) -> dict[str, Any]:
        if "/metrics" in url:
            return {"fresh": True, "memory_coverage": {"host": "available"}}
        return {"diagnoses": rows}

    monkeypatch.setattr(chaos_oom, "api", api)
    chaos_oom.assert_reference("http://fixture", "token", "node-b", {"old-generation"}, 10)
    rows.append({"id": "new-generation"})
    with pytest.raises(RuntimeError, match="opened a new"):
        chaos_oom.assert_reference("http://fixture", "token", "node-b", {"old-generation"}, 10)


def test_recovery_counts_only_three_distinct_post_stop_eligible_samples() -> None:
    identities: set[tuple[str, str, int, str]] = set()
    before = ("boot", "session", 1, "before")
    observed = {
        "events_stable": True,
        "max_bytes": 100,
        "usage_ratio": 0.79,
    }
    assert not chaos_oom.add_recovery_sample(
        identities, before, before, observed, (1, 1), (1, 1), 80
    )
    for sequence in range(2, 5):
        identity = ("boot", "session", sequence, str(sequence))
        assert chaos_oom.add_recovery_sample(
            identities, identity, before, observed, (1, 1), (1, 1), 80
        )
        assert not chaos_oom.add_recovery_sample(
            identities, identity, before, observed, (1, 1), (1, 1), 80
        )
    assert len(identities) == 3
    assert not chaos_oom.add_recovery_sample(
        identities,
        ("boot", "session", 5, "5"),
        before,
        observed,
        (2, 1),
        (1, 1),
        80,
    )
