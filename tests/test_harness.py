import errno
import json
import os
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from chaos_harness import DISK_PATH, DiskHarness, InodeHarness, write_report
from fastapi.testclient import TestClient
from pydantic import SecretStr

from fleetdoctor.agent import make_sample
from fleetdoctor.collection import from_statvfs
from fleetdoctor.collector import create_app
from fleetdoctor.incidents import DiskConfig, InodeConfig
from fleetdoctor.store import FixtureStore


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
        self.expire_after_callback = False
        self.status_failure_call: int | None = None
        self.status_calls = 0
        self.status_delays: dict[int, float] = {}
        self.token = ""

    def probe(self) -> dict[str, Any]:
        return {"mapping": {"target": DISK_PATH}}

    def start(self, token: str, duration: int) -> dict[str, Any]:
        self.started += 1
        self.token = token
        self.backend.phase = "inject"
        if self.interrupt:
            raise InterruptedError("lost controller")
        return {"token": token, "duration": duration}

    def status(self, token: str) -> dict[str, Any]:
        self.status_calls += 1
        self.backend.clock.sleep(self.status_delays.get(self.status_calls, 0))
        if self.status_calls == self.status_failure_call:
            raise RuntimeError("live disk status invalid")
        return {
            "token": token,
            "mapping": {"target": DISK_PATH},
            "filler_inode": 10,
            "cleanup_complete": self.expire_after_callback and self.status_calls > 1,
        }

    def cleanup(self, token: str) -> dict[str, Any]:
        self.cleaned += 1
        if self.cleaned <= self.cleanup_failures:
            raise ConnectionError("unreachable")
        self.backend.phase = "recover"
        return {"cleanup_complete": True}


class InodeBackend(Backend):
    def __init__(self, clock: Clock) -> None:
        super().__init__(clock)
        self.inode_config = InodeConfig().model_dump()
        self.opening_detail_delay = 0.0
        self.active_summary_overrides: dict[str, Any] = {}
        self.opening_detail_overrides: dict[str, Any] = {}
        self.resolved_detail_overrides: dict[str, Any] = {}
        self.resolved_detail_response: Any = None
        self.replace_resolved_detail = False

    def inode_evidence(self, inode_usage: float) -> dict[str, Any]:
        return {
            "node_id": "node-a",
            "inode_available": True,
            "block_available": True,
            "effective_block_guard_percent": 95,
            "filesystem": {
                "mountpoint": DISK_PATH,
                "inodes_total": 1024,
                "inode_usage_percent": inode_usage,
                "block_usage_percent": 10,
                "available_bytes": 300 * 1024**2,
            },
        }

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/configuration":
            return {
                "disk_rule": DiskConfig().model_dump(),
                "inode_rule": self.inode_config,
                "effective_inode_block_guard_percent": 95,
                "filesystems": ["/", DISK_PATH],
                "cadence_seconds": 5,
            }
        if path == "/nodes":
            return {
                "nodes": [
                    {
                        "node_id": node,
                        "fresh": not (node == "node-b" and self.bad_reference),
                        "stale": False,
                        "active_incident_count": 0,
                        "inode_diagnosis_coverage": {"/": "available", DISK_PATH: "available"},
                        "sample": {
                            "observed_at": "2026-10-18T00:00:00Z"
                            if self.phase == "prepare"
                            else "2026-10-18T00:00:05Z"
                        },
                        "filesystems": [
                            {
                                "mountpoint": DISK_PATH,
                                "inodes_total": 1024,
                                "inode_usage_percent": 97
                                if node == "node-a" and self.phase == "inject"
                                else 10,
                                "block_usage_percent": 10,
                                "available_bytes": 300 * 1024**2,
                            }
                        ],
                    }
                    for node in ("node-a", "node-b")
                ]
            }
        opening_evidence = self.inode_evidence(97)
        record: dict[str, Any] = {
            "id": "inode-incident-1",
            "node_id": "node-a",
            "resource": DISK_PATH,
            "rule": "inode_exhaustion",
            "configuration": self.inode_config,
            "severity": self.inode_config["severity"],
            "status": "resolved" if self.phase == "recover" else "active",
            "evidence_fresh": True,
            "evidence_available": True,
            "opening_evidence": opening_evidence,
            "latest_evidence": (
                self.inode_evidence(10) if self.phase == "recover" else opening_evidence
            ),
        }
        if path == "/diagnoses":
            if self.phase == "inject":
                self.clock.now += self.diagnosis_delay
            summary = deepcopy(record)
            summary.pop("opening_evidence")
            summary.pop("latest_evidence")
            summary.update(deepcopy(self.active_summary_overrides))
            return {
                "diagnoses": [summary] if self.phase == "inject" and not self.no_incident else []
            }
        if path.startswith("/diagnoses/"):
            if self.phase == "recover":
                self.clock.now += self.recovery_delay
                if self.replace_resolved_detail:
                    return cast(dict[str, Any], self.resolved_detail_response)
                record.update(deepcopy(self.resolved_detail_overrides))
            else:
                self.clock.now += self.opening_detail_delay
                record.update(deepcopy(self.opening_detail_overrides))
            return record
        raise AssertionError(path)


class InodeInjector(Injector):
    def status(self, token: str) -> dict[str, Any]:
        self.status_calls += 1
        if self.status_calls == self.status_failure_call:
            raise RuntimeError("live inode status invalid")
        return {
            "token": token,
            "mapping": {"target": DISK_PATH},
            "directory_inode": 10,
            "directory_dev": 20,
            "files": [{"name": "f-0000", "state": "created"}],
            "cleanup_complete": False,
        }


class ProductionInodeBackend:
    """HTTP adapter backed by the production FastAPI routes and FixtureStore."""

    def __init__(self) -> None:
        self.now = datetime(2026, 10, 19, tzinfo=UTC)
        self.tokens = {node: node[-1] * 40 for node in ("node-a", "node-b")}
        self.sequences = {node: 0 for node in self.tokens}
        self.boots = {node: uuid4() for node in self.tokens}
        self.sessions = {node: uuid4() for node in self.tokens}
        self.list_responses: list[dict[str, Any]] = []
        app = create_app(
            {node: SecretStr(token) for node, token in self.tokens.items()},
            ("/", DISK_PATH),
            clock=lambda: self.now,
            store=FixtureStore(),
        )
        self.client = TestClient(app)
        self.send("node-a", 10)
        self.send("node-b", 10)

    @staticmethod
    def filesystem(path: str, inode_usage: int) -> Any:
        return from_statvfs(
            path,
            {
                "f_blocks": 10000,
                "f_bfree": 9000,
                "f_bavail": 9000,
                "f_frsize": 4096,
                "f_files": 1000,
                "f_ffree": 1000 - inode_usage * 10,
            },
        )

    def send(self, node: str, inode_usage: int) -> None:
        self.now += timedelta(seconds=1)
        self.sequences[node] += 1
        sample = make_sample(
            node,
            self.boots[node],
            self.sessions[node],
            self.sequences[node],
            [self.filesystem("/", 10), self.filesystem(DISK_PATH, inode_usage)],
            self.now,
        )
        response = self.client.post(
            "/ingest",
            content=sample.model_dump_json(),
            headers={"Authorization": "Bearer " + self.tokens[node]},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self.client.get(path, params=params)
        assert response.status_code == 200
        result: dict[str, Any] = response.json()
        if path == "/diagnoses":
            self.list_responses.append(deepcopy(result))
        return result


class ProductionInodeInjector:
    def __init__(self, backend: ProductionInodeBackend) -> None:
        self.backend = backend
        self.started = self.cleaned = 0

    def probe(self) -> dict[str, Any]:
        return {"mapping": {"target": DISK_PATH}}

    def start(self, token: str, duration: int) -> dict[str, Any]:
        self.started += 1
        for _ in range(3):
            self.backend.send("node-a", 97)
        return {"token": token, "duration": duration}

    def status(self, token: str) -> dict[str, Any]:
        return {
            "token": token,
            "mapping": {"target": DISK_PATH},
            "directory_inode": 10,
            "directory_dev": 20,
            "files": [{"name": "f-0000", "state": "created"}],
            "cleanup_complete": False,
        }

    def cleanup(self, token: str) -> dict[str, Any]:
        self.cleaned += 1
        for _ in range(3):
            self.backend.send("node-a", 10)
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


def inode_rig(tmp_path: Path) -> tuple[InodeHarness, InodeBackend, InodeInjector, Clock]:
    clock = Clock()
    api = InodeBackend(clock)
    injector = InodeInjector(api)
    harness = InodeHarness(
        api,
        injector,
        "node-a",
        "node-b",
        tmp_path / "inode-run.json",
        {"kind": "fixture-only-no-native-or-PostgreSQL-proof"},
        monotonic=clock.read,
        sleep=clock.sleep,
        lease_directory=tmp_path,
    )
    return harness, api, injector, clock


def test_inode_harness_measures_threshold_incident_cleanup_and_recovery(tmp_path: Path) -> None:
    harness, _, injector, _ = inode_rig(tmp_path)
    result = harness.run()
    assert result["status"] == "passed"
    assert result["trigger_to_diagnosis_seconds"] == 0
    assert result["opening_detail"]["rule"] == "inode_exhaustion"
    assert result["resolved_detail"]["status"] == "resolved"
    assert result["owned_status_at_diagnosis"]["directory_inode"] == 10
    assert injector.cleaned == 1
    assert not (tmp_path / "filesystem-node-a.lease").exists()
    serialized_samples = json.dumps([poll["nodes"] for poll in result["polls"]])
    assert result["token"] not in serialized_samples and "scenario" not in serialized_samples


def test_inode_harness_accepts_production_api_summary_then_validates_detail(
    tmp_path: Path,
) -> None:
    clock = Clock()
    api = ProductionInodeBackend()
    injector = ProductionInodeInjector(api)
    harness = InodeHarness(
        api,
        injector,
        "node-a",
        "node-b",
        tmp_path / "production-api-inode-run.json",
        {"kind": "FixtureStore production FastAPI contract; no native or PostgreSQL proof"},
        monotonic=clock.read,
        sleep=clock.sleep,
        lease_directory=tmp_path,
    )

    result = harness.run()

    nonempty_summaries = [
        diagnosis for response in api.list_responses for diagnosis in response["diagnoses"]
    ]
    assert nonempty_summaries
    assert all("opening_evidence" not in item for item in nonempty_summaries)
    assert all("latest_evidence" not in item for item in nonempty_summaries)
    assert result["opening_detail"]["opening_evidence"]["inode_available"] is True
    assert result["resolved_detail"]["latest_evidence"]["inode_available"] is True
    assert result["status"] == "passed"
    assert injector.started == injector.cleaned == 1


def test_inode_query_delay_counts_even_in_same_poll(tmp_path: Path) -> None:
    harness, api, injector, _ = inode_rig(tmp_path)
    api.diagnosis_delay = 2.5
    result = harness.run()
    assert result["trigger_to_diagnosis_seconds"] == 2.5
    assert result["events"]["threshold_observed"]["monotonic_seconds"] == 0
    assert result["events"]["api_diagnosis"]["monotonic_seconds"] == 2.5
    assert result["polls"][1]["resource_observed_monotonic_seconds"] == 0
    assert result["polls"][1]["incident_response_completed_monotonic_seconds"] == 2.5
    assert injector.cleaned == 1 and not (tmp_path / "filesystem-node-a.lease").exists()


def test_inode_opening_detail_delay_uses_final_required_response_time(tmp_path: Path) -> None:
    harness, api, injector, clock = inode_rig(tmp_path)
    api.opening_detail_delay = 2.5
    result = harness.run()
    assert clock.now == 2.5
    assert result["trigger_to_diagnosis_seconds"] == 2.5
    assert result["events"]["threshold_observed"]["monotonic_seconds"] == 0
    assert result["events"]["api_diagnosis"]["monotonic_seconds"] == 2.5
    assert result["polls"][1]["incident_response_completed_monotonic_seconds"] == 0
    assert injector.cleaned == 1 and not (tmp_path / "filesystem-node-a.lease").exists()


@pytest.mark.parametrize("delay", [7.0, 60.0])
def test_inode_timely_recovery_detail_uses_actual_completion_time(
    tmp_path: Path, delay: float
) -> None:
    harness, api, injector, clock = inode_rig(tmp_path)
    api.recovery_delay = delay
    result = harness.run()
    assert result["status"] == "passed"
    assert clock.now == delay
    assert result["events"]["api_resolution"]["monotonic_seconds"] == delay
    assert result["resolved_detail"]["status"] == "resolved"
    assert result["recovery_observation"]["filesystem"]["inode_usage_percent"] == 10
    assert injector.cleaned == 1 and not (tmp_path / "filesystem-node-a.lease").exists()


def test_inode_late_recovery_detail_fails_without_success_publication(tmp_path: Path) -> None:
    harness, api, injector, clock = inode_rig(tmp_path)
    api.recovery_delay = 61
    with pytest.raises(RuntimeError, match="inode run failed"):
        harness.run()
    assert clock.now == 61
    assert harness.report["status"] == "failed"
    assert any("recovery timeout" in error for error in harness.report["errors"])
    assert "api_resolution" not in harness.report["events"]
    assert "recovery_observation" not in harness.report
    assert "resolved_detail" not in harness.report
    assert injector.cleaned == 1
    assert (tmp_path / "filesystem-node-a.lease").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("node_id", "node-b"),
        ("resource", "/wrong"),
        ("rule", "disk_block_exhaustion"),
        ("configuration", {"wrong": True}),
        ("severity", "warning"),
        ("status", "resolved"),
        ("evidence_fresh", False),
        ("evidence_available", False),
    ],
)
def test_inode_rejects_mismatched_active_summary(tmp_path: Path, field: str, value: Any) -> None:
    harness, api, injector, _ = inode_rig(tmp_path)
    api.active_summary_overrides[field] = value
    with pytest.raises(ValueError, match="inode incident"):
        harness.run()
    assert harness.report["status"] == "failed"
    assert "api_diagnosis" not in harness.report["events"]
    assert injector.cleaned == 1 and (tmp_path / "filesystem-node-a.lease").exists()


@pytest.mark.parametrize(
    "mismatch",
    [
        "id",
        "node",
        "resource",
        "rule",
        "configuration",
        "severity",
        "status",
        "freshness",
        "availability",
        "inode_evidence",
        "block_evidence",
        "effective_guard",
        "inode_threshold",
        "available_bytes",
        "block_guard",
        "missing_evidence",
    ],
)
def test_inode_rejects_mismatched_opening_detail(tmp_path: Path, mismatch: str) -> None:
    harness, api, injector, _ = inode_rig(tmp_path)
    direct = {
        "id": ("id", "other-incident"),
        "node": ("node_id", "node-b"),
        "resource": ("resource", "/wrong"),
        "rule": ("rule", "disk_block_exhaustion"),
        "configuration": ("configuration", {"wrong": True}),
        "severity": ("severity", "warning"),
        "status": ("status", "resolved"),
        "freshness": ("evidence_fresh", False),
        "availability": ("evidence_available", False),
    }
    if mismatch in direct:
        field, value = direct[mismatch]
        api.opening_detail_overrides[field] = value
    else:
        evidence: Any = api.inode_evidence(97)
        if mismatch == "inode_evidence":
            evidence["inode_available"] = False
        elif mismatch == "block_evidence":
            evidence["block_available"] = False
        elif mismatch == "effective_guard":
            evidence["effective_block_guard_percent"] = 94
        elif mismatch == "inode_threshold":
            evidence["filesystem"]["inode_usage_percent"] = 94
        elif mismatch == "available_bytes":
            evidence["filesystem"]["available_bytes"] = 0
        elif mismatch == "missing_evidence":
            evidence = None
        else:
            evidence["filesystem"]["block_usage_percent"] = 95
        api.opening_detail_overrides["opening_evidence"] = evidence
    with pytest.raises(ValueError, match="inode incident"):
        harness.run()
    assert harness.report["status"] == "failed"
    assert "api_diagnosis" not in harness.report["events"]
    assert "opening_detail" not in harness.report
    assert injector.cleaned == 1 and (tmp_path / "filesystem-node-a.lease").exists()


@pytest.mark.parametrize(
    "mismatch",
    [
        "id",
        "node",
        "resource",
        "rule",
        "configuration",
        "severity",
        "status",
        "freshness",
        "availability",
        "opening_evidence",
        "latest_node",
        "latest_availability",
        "latest_threshold",
    ],
)
def test_inode_rejects_mismatched_resolved_detail(tmp_path: Path, mismatch: str) -> None:
    harness, api, injector, _ = inode_rig(tmp_path)
    direct = {
        "id": ("id", "different-incident"),
        "node": ("node_id", "node-b"),
        "resource": ("resource", "/wrong"),
        "rule": ("rule", "disk_block_exhaustion"),
        "configuration": ("configuration", {"wrong": True}),
        "severity": ("severity", "warning"),
        "status": ("status", "active"),
        "freshness": ("evidence_fresh", False),
        "availability": ("evidence_available", False),
    }
    if mismatch in direct:
        field, value = direct[mismatch]
        api.resolved_detail_overrides[field] = value
    elif mismatch == "opening_evidence":
        evidence = api.inode_evidence(97)
        evidence["sequence"] = 2
        api.resolved_detail_overrides["opening_evidence"] = evidence
    else:
        evidence = api.inode_evidence(10)
        if mismatch == "latest_node":
            evidence["node_id"] = "node-b"
        elif mismatch == "latest_availability":
            evidence["inode_available"] = False
        else:
            evidence["filesystem"]["inode_usage_percent"] = 90
        api.resolved_detail_overrides["latest_evidence"] = evidence
    with pytest.raises(RuntimeError, match="inode run failed"):
        harness.run()
    assert harness.report["status"] == "failed"
    assert any(
        word in error
        for error in harness.report["errors"]
        for word in ("mismatch", "stale", "unavailable", "changed")
    )
    assert "api_resolution" not in harness.report["events"]
    assert "resolved_detail" not in harness.report
    assert "recovery_observation" not in harness.report
    assert injector.cleaned == 1 and (tmp_path / "filesystem-node-a.lease").exists()


@pytest.mark.parametrize("response", [None, {}, []])
def test_inode_rejects_missing_or_malformed_resolved_detail(tmp_path: Path, response: Any) -> None:
    harness, api, injector, _ = inode_rig(tmp_path)
    api.replace_resolved_detail = True
    api.resolved_detail_response = response

    with pytest.raises(RuntimeError, match="inode run failed"):
        harness.run()

    assert harness.report["status"] == "failed"
    assert any("inode incident" in error for error in harness.report["errors"])
    assert "api_resolution" not in harness.report["events"]
    assert "resolved_detail" not in harness.report
    assert "recovery_observation" not in harness.report
    assert injector.cleaned == 1 and (tmp_path / "filesystem-node-a.lease").exists()


def test_inode_recovery_condition_uses_configured_sample_count(tmp_path: Path) -> None:
    harness, api, _, _ = inode_rig(tmp_path)
    api.inode_config = InodeConfig(consecutive_samples=7).model_dump()
    result = harness.run()
    assert result["recovery_condition"] == "7 fresh inode readings < 90.0% and resolved incident"


def test_inode_harness_uses_shared_filesystem_lease_and_retains_failures(tmp_path: Path) -> None:
    lease = tmp_path / "filesystem-node-a.lease"
    lease.write_text("other-controller")
    harness, _, injector, _ = inode_rig(tmp_path)
    with pytest.raises(FileExistsError):
        harness.run()
    assert injector.started == 0 and lease.read_text() == "other-controller"
    assert harness.report["status"] == "failed"


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
    assert injector.cleaned == 1 and not (tmp_path / "filesystem-node-a.lease").exists()
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
    assert not (tmp_path / "filesystem-node-a.lease").exists()
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
    assert injector.cleaned == 3 and (tmp_path / "filesystem-node-a.lease").exists()
    (tmp_path / "filesystem-node-a.lease").unlink()
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


def test_task04_callback_runs_inside_owned_injection_and_shared_deadline(tmp_path: Path) -> None:
    harness, _, injector, clock = rig(tmp_path)
    seen: list[float] = []

    def callback(report: dict[str, Any], deadline: float) -> dict[str, Any]:
        assert report["incident_id"] == "incident-1"
        assert deadline == pytest.approx(clock.now + 70)
        seen.append(deadline)
        clock.sleep(10)
        return {"collector_restarted": True}

    harness.after_diagnosis = callback
    harness.max_injection_seconds = 240
    result = harness.run()
    assert seen and result["after_diagnosis"] == {"collector_restarted": True}
    assert result["owned_status_before_callback"]["token"] == result["token"]
    assert result["owned_status_after_callback"]["token"] == result["token"]
    assert injector.cleaned == 1


@pytest.mark.parametrize("status_failure_call", [1, 2])
def test_task04_callback_live_status_failure_blocks_pre_and_post_restart_gates(
    tmp_path: Path, status_failure_call: int
) -> None:
    harness, _, injector, _ = rig(tmp_path)
    callback_calls = 0

    def callback(report: dict[str, Any], deadline: float) -> dict[str, Any]:
        nonlocal callback_calls
        callback_calls += 1
        return {"collector_restarted": True}

    injector.status_failure_call = status_failure_call
    harness.after_diagnosis = callback
    harness.max_injection_seconds = 240
    with pytest.raises(RuntimeError, match="live disk status invalid"):
        harness.run()
    assert callback_calls == (0 if status_failure_call == 1 else 1)
    assert injector.cleaned == 1
    assert harness.report["status"] == "failed"


def test_task04_callback_refuses_without_eighty_second_reserve(tmp_path: Path) -> None:
    harness, _, injector, _ = rig(tmp_path)
    harness.after_diagnosis = lambda report, deadline: {"late": False}
    harness.max_injection_seconds = 79
    with pytest.raises(RuntimeError):
        harness.run()
    assert injector.cleaned == 1
    assert any("80" in error for error in harness.report["errors"])


def test_task04_callback_rechecks_reserve_after_slow_pre_status(tmp_path: Path) -> None:
    harness, _, injector, _ = rig(tmp_path)
    callback_calls = 0

    def callback(report: dict[str, Any], deadline: float) -> dict[str, Any]:
        nonlocal callback_calls
        callback_calls += 1
        return {"collector_restarted": True}

    injector.status_delays[1] = 11
    harness.after_diagnosis = callback
    harness.max_injection_seconds = 100
    with pytest.raises(RuntimeError, match="at least 80 seconds"):
        harness.run()
    assert callback_calls == 0
    assert injector.cleaned == 1
    assert harness.report["status"] == "failed"
    assert "after_diagnosis" not in harness.report
    assert "after_diagnosis_complete" not in harness.report["events"]
    assert harness.report["errors"] == [
        "RuntimeError: at least 80 seconds must remain before collector restart"
    ]


def test_task04_callback_rejects_late_post_status_without_success_publication(
    tmp_path: Path,
) -> None:
    harness, _, injector, clock = rig(tmp_path)

    def callback(report: dict[str, Any], deadline: float) -> dict[str, Any]:
        clock.sleep(70)
        return {"collector_restarted": True}

    injector.status_delays[2] = 21
    harness.after_diagnosis = callback
    harness.max_injection_seconds = 100
    with pytest.raises(RuntimeError, match="acceptance returned after deadline"):
        harness.run()
    assert injector.cleaned == 1
    assert harness.report["status"] == "failed"
    assert "owned_status_after_callback" not in harness.report
    assert "after_diagnosis" not in harness.report
    assert "after_diagnosis_complete" not in harness.report["events"]
    assert harness.report["errors"] == [
        "RuntimeError: collector restart acceptance returned after deadline"
    ]


def test_task04_callback_accepts_exact_admission_and_action_boundaries(tmp_path: Path) -> None:
    harness, _, injector, clock = rig(tmp_path)
    callback_calls = 0

    def callback(report: dict[str, Any], deadline: float) -> dict[str, Any]:
        nonlocal callback_calls
        callback_calls += 1
        assert deadline == 80
        clock.sleep(60)
        return {"collector_restarted": True}

    injector.status_delays = {1: 10, 2: 10}
    harness.after_diagnosis = callback
    harness.max_injection_seconds = 100
    result = harness.run()
    assert callback_calls == 1
    assert result["status"] == "passed"
    assert result["events"]["after_diagnosis_complete"]["monotonic_seconds"] == 80
    assert result["after_diagnosis"] == {"collector_restarted": True}
    assert injector.cleaned == 1


def test_task04_callback_records_timely_post_status_completion(tmp_path: Path) -> None:
    harness, _, injector, clock = rig(tmp_path)

    def callback(report: dict[str, Any], deadline: float) -> dict[str, Any]:
        clock.sleep(10)
        return {"collector_restarted": True}

    injector.status_delays = {1: 5, 2: 7}
    harness.after_diagnosis = callback
    harness.max_injection_seconds = 240
    result = harness.run()
    assert result["status"] == "passed"
    assert result["events"]["after_diagnosis_complete"]["monotonic_seconds"] == 22
    assert result["after_diagnosis"] == {"collector_restarted": True}
    assert injector.cleaned == 1


@pytest.mark.parametrize("failure", ["late", "expired"])
def test_task04_callback_rejects_late_result_or_expired_filler(
    tmp_path: Path, failure: str
) -> None:
    harness, _, injector, clock = rig(tmp_path)
    harness.max_injection_seconds = 240

    def callback(report: dict[str, Any], deadline: float) -> dict[str, Any]:
        if failure == "late":
            clock.sleep(71)
        else:
            injector.expire_after_callback = True
        return {"collector_restarted": True}

    harness.after_diagnosis = callback
    with pytest.raises(RuntimeError):
        harness.run()
    assert injector.cleaned == 1
    assert harness.report["status"] == "failed"
