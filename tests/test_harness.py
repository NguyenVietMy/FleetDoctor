import errno
import json
import os
from pathlib import Path
from typing import Any

import pytest
from chaos_harness import DISK_PATH, DiskHarness, write_report

from fleetdoctor.incidents import DiskConfig


@pytest.fixture(autouse=True)
def fixture_source_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "chaos_harness.source_manifest",
        lambda: {"revision": "fixture", "dirty": False, "sha256": {}},
    )


class WindowsSharingError(PermissionError):
    winerror: int


def windows_sharing_error(code: int = 5) -> PermissionError:
    error = WindowsSharingError(errno.EACCES, "reader holds destination")
    error.winerror = code
    return error


@pytest.mark.parametrize("code", [5, 32])
def test_report_transient_sharing_failure_retries_atomic_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    path = tmp_path / "run.json"
    previous, report = {"status": "running"}, {"status": "passed", "events": {"finished": 1}}
    path.write_text(json.dumps(previous))
    replace = os.replace
    attempts: list[Path] = []
    waits: list[float] = []

    def transient(source: Path, destination: Path) -> None:
        assert source == path.with_suffix(".tmp") and destination == path
        assert json.loads(source.read_text()) == report
        assert json.loads(destination.read_text()) == previous
        attempts.append(source)
        if len(attempts) <= 2:
            raise windows_sharing_error(code)
        replace(source, destination)

    monkeypatch.setattr("chaos_harness.os.replace", transient)
    monkeypatch.setattr("chaos_harness.time.sleep", waits.append)
    write_report(path, report)
    assert len(attempts) == 3 and waits == [0.05, 0.05]
    assert json.loads(path.read_text()) == report
    assert not path.with_suffix(".tmp").exists()


@pytest.mark.parametrize("code", [5, 32])
def test_report_permanent_sharing_failure_is_bounded_and_preserves_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    path = tmp_path / "run.json"
    previous = b'{"status":"running"}\n'
    path.write_bytes(previous)
    report = {"status": "failed", "errors": ["permanent sharing failure"]}
    error = windows_sharing_error(code)
    attempts: list[Path] = []
    waits: list[float] = []

    def fail(source: Path, destination: Path) -> None:
        attempts.append(source)
        assert destination.read_bytes() == previous
        raise error

    monkeypatch.setattr("chaos_harness.os.replace", fail)
    monkeypatch.setattr("chaos_harness.time.sleep", waits.append)
    with pytest.raises(PermissionError) as caught:
        write_report(path, report)
    assert caught.value is error
    assert len(attempts) == 5 and waits == [0.05] * 4
    assert path.read_bytes() == previous
    assert json.loads(path.with_suffix(".tmp").read_text()) == report


@pytest.mark.parametrize(
    "error",
    [
        PermissionError(errno.EACCES, "non-Windows"),
        OSError(errno.ENOSPC, "full"),
        InterruptedError("interrupted"),
        KeyboardInterrupt(),
    ],
)
def test_report_other_replace_errors_are_not_retried_or_hidden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    path = tmp_path / "run.json"
    previous = b'{"status":"running"}'
    path.write_bytes(previous)
    attempts: list[Path] = []
    waits: list[float] = []

    def fail(source: Path, destination: Path) -> None:
        attempts.append(source)
        raise error

    monkeypatch.setattr("chaos_harness.os.replace", fail)
    monkeypatch.setattr("chaos_harness.time.sleep", waits.append)
    with pytest.raises(type(error)) as caught:
        write_report(path, {"status": "failed"})
    assert caught.value is error and len(attempts) == 1 and not waits
    assert path.read_bytes() == previous


def test_report_retry_wait_interruption_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "run.json"
    previous = b'{"status":"running"}'
    path.write_bytes(previous)
    attempts = []

    def fail(source: Path, destination: Path) -> None:
        attempts.append(source)
        raise windows_sharing_error()

    def interrupt(seconds: float) -> None:
        raise KeyboardInterrupt()

    monkeypatch.setattr("chaos_harness.os.replace", fail)
    monkeypatch.setattr("chaos_harness.time.sleep", interrupt)
    with pytest.raises(KeyboardInterrupt):
        write_report(path, {"status": "failed"})
    assert len(attempts) == 1 and path.read_bytes() == previous


def test_report_temporary_write_error_is_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "run.json"
    previous = b'{"status":"running"}'
    path.write_bytes(previous)
    attempts: list[Path] = []

    def fail(temp: Path, *args: Any, **kwargs: Any) -> None:
        attempts.append(temp)
        raise windows_sharing_error()

    def unexpected(*args: Any) -> None:
        pytest.fail("only replacement failures may be retried")

    monkeypatch.setattr(Path, "write_text", fail)
    monkeypatch.setattr("chaos_harness.os.replace", unexpected)
    monkeypatch.setattr("chaos_harness.time.sleep", unexpected)
    with pytest.raises(PermissionError):
        write_report(path, {"status": "failed"})
    assert attempts == [path.with_suffix(".tmp")] and path.read_bytes() == previous


class Clock:
    now = 0.0

    def read(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class Backend:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.phase = "prepare"
        self.diagnosis_delay = self.recovery_delay = 0.0
        self.bad_reference = self.bad_preparation = False
        self.missing = self.no_incident = False
        self.config = DiskConfig().model_dump()

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/configuration":
            if self.bad_preparation:
                raise ValueError("preparation refused")
            return {"disk_rule": self.config, "filesystems": ["/", DISK_PATH], "cadence_seconds": 5}
        if path == "/nodes":
            return {
                "nodes": [
                    {
                        "node_id": node,
                        "fresh": not (node == "node-b" and self.bad_reference),
                        "stale": False,
                        "active_incident_count": 0,
                        "diagnosis_coverage": {"/": "available", DISK_PATH: "available"},
                        "sample": {
                            "observed_at": "2026-10-11T00:00:00Z"
                            if self.phase == "prepare"
                            else "2026-10-11T00:00:05Z"
                        },
                        "filesystems": [
                            {
                                "mountpoint": DISK_PATH,
                                "total_bytes": 384 * 1024**2,
                                "block_usage_percent": None
                                if self.missing
                                else 97
                                if node == "node-a" and self.phase == "inject"
                                else 10,
                            }
                        ],
                    }
                    for node in ("node-a", "node-b")
                ]
            }
        record = {
            "id": "incident-1",
            "resource": DISK_PATH,
            "rule": "disk_block_exhaustion",
            "configuration": self.config,
            "status": "resolved" if self.phase == "recover" else "active",
            "evidence_fresh": True,
            "evidence_available": True,
        }
        if path == "/diagnoses":
            if self.phase == "inject":
                self.clock.now += self.diagnosis_delay
            return {
                "diagnoses": [record] if self.phase == "inject" and not self.no_incident else []
            }
        if path.startswith("/diagnoses/"):
            if self.phase == "recover":
                self.clock.now += self.recovery_delay
            return record
        raise AssertionError(path)


class Injector:
    def __init__(self, backend: Backend) -> None:
        self.backend = backend
        self.started = self.cleaned = 0
        self.cleanup_failures = 0
        self.interrupt = False

    def probe(self) -> dict[str, Any]:
        return {"mapping": {"target": DISK_PATH}}

    def start(self, token: str, duration: int) -> dict[str, Any]:
        self.started += 1
        self.backend.phase = "inject"
        if self.interrupt:
            raise InterruptedError("lost controller")
        return {"token": token, "duration": duration}

    def cleanup(self, token: str) -> dict[str, Any]:
        self.cleaned += 1
        if self.cleaned <= self.cleanup_failures:
            raise ConnectionError("unreachable")
        self.backend.phase = "recover"
        return {"cleanup_complete": True}


def rig(tmp_path: Path) -> tuple[DiskHarness, Backend, Injector, Clock]:
    clock = Clock()
    api = Backend(clock)
    injector = Injector(api)
    harness = DiskHarness(
        api,
        injector,
        "node-a",
        "node-b",
        tmp_path / "run.json",
        {"kind": "fixture"},
        monotonic=clock.read,
        sleep=clock.sleep,
        lease_directory=tmp_path,
    )
    return harness, api, injector, clock


def test_report_retry_wait_remains_in_monotonic_event_accounting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness, _, _, clock = rig(tmp_path)
    replace = os.replace
    attempts = 0

    def transient(source: Path, destination: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts <= 2:
            raise windows_sharing_error()
        replace(source, destination)

    monkeypatch.setattr("chaos_harness.os.replace", transient)
    monkeypatch.setattr("chaos_harness.time.sleep", clock.sleep)
    harness.event("injection_start")
    harness.event("threshold_observed")
    assert harness.report["events"]["injection_start"]["monotonic_seconds"] == 0
    assert harness.report["events"]["threshold_observed"]["monotonic_seconds"] == 0.1
    assert clock.now == 0.1


def test_query_delay_counts_even_in_same_poll(tmp_path: Path) -> None:
    harness, api, injector, _ = rig(tmp_path)
    api.diagnosis_delay = 2.5
    result = harness.run()
    assert result["trigger_to_diagnosis_seconds"] == 2.5
    assert result["events"]["threshold_observed"]["monotonic_seconds"] == 0
    assert result["events"]["api_diagnosis"]["monotonic_seconds"] == 2.5
    assert injector.cleaned == 1 and not (tmp_path / "disk-node-a.lease").exists()
    assert json.loads((tmp_path / "run.json").read_text())["status"] == "passed"


@pytest.mark.parametrize("phase", ["diagnosis", "recovery"])
def test_late_success_response_is_failure(tmp_path: Path, phase: str) -> None:
    harness, api, injector, _ = rig(tmp_path)
    if phase == "diagnosis":
        api.diagnosis_delay = 61
    else:
        api.recovery_delay = 61
    with pytest.raises((TimeoutError, RuntimeError)):
        harness.run()
    assert harness.report["status"] == "failed" and injector.cleaned == 1
    assert any("timeout" in error for error in harness.report["errors"])
    assert (
        "api_" + ("diagnosis" if phase == "diagnosis" else "resolution")
        not in harness.report["events"]
    )


def test_pre_injection_failure_releases_owned_lease_then_retry(tmp_path: Path) -> None:
    harness, api, injector, _ = rig(tmp_path)
    api.bad_preparation = True
    with pytest.raises(ValueError):
        harness.run()
    assert injector.started == injector.cleaned == 0
    assert not (tmp_path / "disk-node-a.lease").exists()
    retained = json.loads((tmp_path / "run.json").read_text())
    assert retained["status"] == "failed"
    second, _, _, _ = rig(tmp_path)
    second.output = tmp_path / "retry.json"
    assert second.run()["status"] == "passed"
    assert json.loads((tmp_path / "run.json").read_text()) == retained


def test_interrupt_and_bounded_cleanup_reconnects(tmp_path: Path) -> None:
    harness, _, injector, _ = rig(tmp_path)
    injector.interrupt = True
    injector.cleanup_failures = 2
    with pytest.raises(InterruptedError):
        harness.run()
    assert injector.cleaned == 3 and "cleanup_complete" in harness.report["events"]
    assert harness.report["status"] == "failed"


def test_cleanup_failure_and_healthy_reference_are_enforced(tmp_path: Path) -> None:
    harness, _, injector, _ = rig(tmp_path)
    injector.cleanup_failures = 10
    with pytest.raises(RuntimeError):
        harness.run()
    assert injector.cleaned == 3 and (tmp_path / "disk-node-a.lease").exists()
    (tmp_path / "disk-node-a.lease").unlink()
    second, api, injector, _ = rig(tmp_path)
    api.bad_reference = True
    with pytest.raises(ValueError, match="reference"):
        second.run()
    assert injector.started == 0


def test_no_incident_times_out_and_keeps_failure_report(tmp_path: Path) -> None:
    harness, api, injector, clock = rig(tmp_path)
    api.no_incident = True
    with pytest.raises(TimeoutError):
        harness.run()
    assert clock.now > 60 and injector.cleaned == 1
    assert "threshold_observed" in harness.report["events"]
    assert "api_diagnosis" not in harness.report["events"]
