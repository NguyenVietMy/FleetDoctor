from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from fleetdoctor.agent import make_sample
from fleetdoctor.checkpoint import Checkpoint
from fleetdoctor.collection import from_statvfs
from fleetdoctor.collector import create_app
from fleetdoctor.incidents import DiskConfig, Incident
from fleetdoctor.schema import Filesystem, Sample
from fleetdoctor.store import FixtureStore, StoreError, StoreSnapshot

TOKENS = {"node-a": SecretStr("a" * 40), "node-b": SecretStr("b" * 40)}
PATH = "/var/lib/fleetdoctor/chaos/disk"


def blocks(usage: int, path: str = PATH) -> Filesystem:
    return from_statvfs(
        path,
        {
            "f_blocks": 10000,
            "f_bfree": 10000 - usage * 100,
            "f_bavail": 10000 - usage * 100,
            "f_frsize": 4096,
            "f_files": 1000,
            "f_ffree": 900,
        },
    )


class Rig:
    def __init__(self, store: FixtureStore | None = None) -> None:
        self.now = datetime(2026, 10, 11, tzinfo=UTC)
        self.store = FixtureStore() if store is None else store
        self.app = create_app(TOKENS, ("/", PATH), clock=lambda: self.now, store=self.store)
        self.client = TestClient(self.app)
        self.boot, self.session = uuid4(), uuid4()
        self.sequence = 0

    def sample(self, usage: int | None, *, node: str = "node-a", gap: int = 5) -> Sample:
        self.now += timedelta(seconds=gap)
        self.sequence += 1
        fs = (
            blocks(usage)
            if usage is not None
            else Filesystem(mountpoint=PATH, errors=["permission_denied"])
        )
        return make_sample(
            node, self.boot, self.session, self.sequence, [blocks(10, "/"), fs], self.now
        )

    def post(self, value: Sample) -> Any:
        return self.client.post(
            "/ingest",
            content=value.model_dump_json(),
            headers={"Authorization": "Bearer " + TOKENS[value.node_id].get_secret_value()},
        )

    def send(self, usage: int | None, **kwargs: Any) -> None:
        assert self.post(self.sample(usage, **kwargs)).json()["status"] == "accepted"

    def records(self, status: str | None = None) -> list[dict[str, Any]]:
        response = self.client.get("/diagnoses", params={"status": status} if status else {})
        assert response.status_code == 200
        return list(response.json()["diagnoses"])


class LostAcknowledgementStore(FixtureStore):
    """Commit rows, enforce the actual active-key constraint, then lose one reply."""

    lose_next_commit = False

    def commit(self, changes: list[Incident], checkpoint: Checkpoint) -> None:
        for change in changes:
            if change.status == "active" and any(
                old.status == "active"
                and (old.node_id, old.rule, old.resource)
                == (change.node_id, change.rule, change.resource)
                and old.id != change.id
                for old in self.records.values()
            ):
                raise StoreError("incident_one_active")
        super().commit(changes, checkpoint)
        if self.lose_next_commit:
            self.lose_next_commit = False
            raise StoreError("COMMIT succeeded; acknowledgement lost")


@pytest.mark.parametrize("next_observation", ["same", "newer_high", "newer_low", "new_config"])
def test_committed_opening_survives_lost_acknowledgement(next_observation: str) -> None:
    store = LostAcknowledgementStore()
    rig = Rig(store)
    rig.send(98)
    rig.send(98)
    previous = rig.app.state.fleet.latest["node-a"]
    failed = rig.sample(98)
    store.lose_next_commit = True
    assert rig.post(failed).status_code == 503
    assert rig.app.state.fleet.latest["node-a"] == previous
    assert not rig.app.state.fleet.evaluator.active
    persisted = rig.records("active")[0]
    opening = rig.client.get("/diagnoses/" + persisted["id"]).json()
    assert rig.client.get("/nodes/node-a/metrics").json()["active_incident_count"] == 1
    assert (
        'fleetdoctor_active_incidents{node="node-a",rule="disk_block_exhaustion"} 1.0'
        in rig.client.get("/metrics").text
    )
    if next_observation == "new_config":
        rig.app.state.fleet.config = DiskConfig(trigger_percent=99, severity="warning")
    if next_observation in ("same", "new_config"):
        rig.now += timedelta(seconds=1)
        assert rig.post(failed).json()["status"] == "duplicate"
    elif next_observation == "newer_high":
        rig.send(98)
        assert rig.post(failed).json()["status"] == "duplicate"
    healthy_count = 0
    if next_observation == "newer_low":
        rig.send(80)
        healthy_count = 1
    active = rig.records("active")
    assert len(active) == 1 and active[0]["id"] == persisted["id"]
    detail = rig.client.get("/diagnoses/" + persisted["id"]).json()
    assert detail["opening_evidence"] == opening["opening_evidence"]
    assert detail["opened_at"] == opening["opened_at"]
    assert detail["configuration"] == opening["configuration"]
    for _ in range(3 - healthy_count):
        rig.send(80)
    resolved = rig.client.get("/diagnoses/" + persisted["id"]).json()
    assert resolved["status"] == "resolved"
    assert resolved["opening_evidence"] == opening["opening_evidence"]
    assert rig.client.get("/nodes").json()["nodes"][0]["active_incident_count"] == 0
    assert len(rig.records()) == 1


@pytest.mark.parametrize("next_observation", ["same", "newer_high"])
def test_committed_resolution_retry_preserves_original_resolution_and_recurrence(
    next_observation: str,
) -> None:
    store = LostAcknowledgementStore()
    rig = Rig(store)
    for _ in range(3):
        rig.send(98)
    opening = rig.records("active")[0]
    rig.send(80)
    rig.send(80)
    previous = rig.app.state.fleet.latest["node-a"]
    failed = rig.sample(80)
    store.lose_next_commit = True
    assert rig.post(failed).status_code == 503
    assert rig.app.state.fleet.latest["node-a"] == previous
    committed = rig.client.get("/diagnoses/" + opening["id"]).json()
    assert committed["status"] == "resolved"
    assert rig.client.get("/nodes").json()["nodes"][0]["active_incident_count"] == 0
    high_count = 0
    rig.now += timedelta(seconds=1)
    if next_observation == "same":
        assert rig.post(failed).json()["status"] == "duplicate"
    else:
        rig.send(98)
        high_count = 1
        assert rig.post(failed).json()["status"] == "duplicate"
    retried = rig.client.get("/diagnoses/" + opening["id"]).json()
    assert retried["resolved_at"] == committed["resolved_at"]
    assert retried["opening_evidence"] == committed["opening_evidence"]
    assert not rig.app.state.fleet.evaluator.active
    for _ in range(3 - high_count):
        rig.send(98)
    recurrence = rig.records("active")[0]
    assert recurrence["id"] != opening["id"] and len(rig.records()) == 2


def test_count_read_failure_omits_all_counts_without_hiding_storage_failure() -> None:
    class UnavailableReadStore(FixtureStore):
        unavailable = False

        def active(self) -> list[Incident]:
            if self.unavailable:
                raise StoreError("read failed after health probe")
            return super().active()

        def snapshot(self, nodes: set[str]) -> StoreSnapshot:
            if self.unavailable:
                raise StoreError("read failed after health probe")
            return super().snapshot(nodes)

    store = UnavailableReadStore()
    rig = Rig(store)
    for _ in range(3):
        rig.send(98)
    previous = rig.app.state.fleet.latest["node-a"]
    store.unavailable = True
    assert rig.client.get("/nodes").status_code == 503
    response = rig.client.get("/metrics")
    assert response.status_code == 200
    assert "fleetdoctor_incident_storage_up 0.0" in response.text
    assert "fleetdoctor_active_incidents{node=" not in response.text
    assert rig.post(rig.sample(80)).status_code == 503
    assert rig.app.state.fleet.latest["node-a"] == previous


def test_unknown_resolution_keeps_reload_marker_on_identical_retry() -> None:
    store = LostAcknowledgementStore()
    rig = Rig(store)
    rig.app.state.fleet.config = DiskConfig(consecutive_samples=1)
    rig.send(98)
    identifier = rig.records("active")[0]["id"]
    rig.app = create_app(TOKENS, ("/", PATH), clock=lambda: rig.now, store=store)
    rig.client = TestClient(rig.app)
    assert rig.client.get("/diagnoses/" + identifier).json()["evidence_stale"]
    failed = rig.sample(80)
    store.lose_next_commit = True
    assert rig.post(failed).status_code == 503
    assert rig.client.get("/nodes").json()["nodes"][0]["active_incident_count"] == 0
    assert rig.post(failed).json()["status"] == "duplicate"
    detail = rig.client.get("/diagnoses/" + identifier).json()
    assert detail["status"] == "resolved" and detail["evidence_stale"]


def test_lifecycle_evidence_hysteresis_recurrence_and_independent_nodes() -> None:
    rig = Rig()
    for usage in (95, 95, 94, 95, 95):
        rig.send(usage)
    assert not rig.records()
    rig.send(95, node="node-b")
    assert not rig.records()
    rig.send(95)
    opened = rig.records()[0]
    assert opened["severity"] == "critical" and opened["resource"] == PATH
    detail = rig.client.get("/diagnoses/" + opened["id"]).json()
    assert detail["opening_evidence"]["filesystem"]["block_usage_percent"] == 95
    assert detail["investigation_steps"] and detail["configuration"]["consecutive_samples"] == 3
    rig.send(99)
    rig.send(89)
    rig.send(89)
    rig.send(90)  # strict recovery and hysteresis reset
    rig.send(None)  # fresh delivery alone cannot recover
    missing = rig.client.get("/diagnoses/" + opened["id"]).json()
    assert missing["evidence_fresh"] and not missing["evidence_available"]
    node = rig.client.get("/nodes/node-a/metrics").json()
    assert node["fresh"] and node["diagnosis_coverage"][PATH] == "unavailable"
    assert node["diagnosis_coverage"]["/"] == "available"
    for _ in range(3):
        rig.send(89)
    resolved = rig.client.get("/diagnoses/" + opened["id"]).json()
    assert resolved["status"] == "resolved" and resolved["resolved_at"]
    assert resolved["opening_evidence"] == detail["opening_evidence"]
    assert resolved["latest_evidence"]["filesystem"]["block_usage_percent"] == 89
    assert rig.client.get("/nodes/node-a/metrics").json()["active_incident_count"] == 0
    for _ in range(3):
        rig.send(98)
    assert rig.records("active")[0]["id"] != opened["id"]
    assert len(rig.records()) == 2


@pytest.mark.parametrize("phase", ["opening", "recovery"])
@pytest.mark.parametrize("reset", ["missing", "gap", "session", "boot", "band"])
def test_both_windows_reset(phase: str, reset: str) -> None:
    rig = Rig()
    if phase == "recovery":
        for _ in range(3):
            rig.send(96)
    usage = 96 if phase == "opening" else 80
    rig.send(usage)
    rig.send(usage)
    if reset == "missing":
        rig.send(None)
    elif reset == "band":
        rig.send(92)
    else:
        if reset == "session":
            rig.session = uuid4()
        if reset == "boot":
            rig.boot = uuid4()
        rig.send(usage, gap=11 if reset == "gap" else 5)
        # Reset sample is eligible as the first observation of the new window.
    rig.send(usage)
    assert bool(rig.records("active")) is (phase == "recovery")
    rig.send(usage)
    if reset in ("missing", "band"):
        assert bool(rig.records("active")) is (phase == "recovery")
        rig.send(usage)
    assert bool(rig.records("active")) is (phase == "opening")


def test_replay_and_failed_transaction_cannot_advance_or_retire_identity() -> None:
    rig = Rig()
    value = rig.sample(96)
    rig.post(value)
    assert rig.post(value).json()["status"] == "duplicate"
    rig.send(96)
    previous = rig.app.state.fleet.latest["node-a"]
    failing = rig.sample(98)
    rig.store.fail = True
    assert rig.post(failing).status_code == 503
    assert rig.app.state.fleet.latest["node-a"] == previous
    assert not rig.store.records
    assert rig.client.get("/health").status_code == 503
    assert rig.client.get("/nodes").status_code == 503
    assert rig.client.get("/diagnoses").status_code == 503
    metrics = rig.client.get("/metrics").text
    assert "fleetdoctor_incident_storage_up 0.0" in metrics
    assert 'fleetdoctor_active_incidents{node="node-a"' not in metrics
    rig.store.fail = False
    assert rig.post(failing).json() == {
        "status": "accepted",
        "durable": False,
        "incidents_durable": True,
    }
    assert len(rig.records("active")) == 1
    assert rig.post(failing).json()["status"] == "duplicate"
    old_retired = rig.app.state.fleet.retired["node-a"].copy()
    rig.session = uuid4()
    change = rig.sample(80)
    rig.store.fail = True
    assert rig.post(change).status_code == 503
    assert rig.app.state.fleet.retired["node-a"] == old_retired
    rig.store.fail = False
    assert rig.post(change).json()["status"] == "accepted"
    late = change.model_copy(
        update={"sequence": change.sequence + 1, "observed_at": rig.now - timedelta(seconds=11)}
    )
    assert rig.post(late).json()["status"] == "ineligible"
    assert len(rig.records("active")) == 1


def test_config_severity_freeze_reload_staleness_and_api_bounds() -> None:
    rig = Rig()
    rig.send(96)
    rig.send(96)
    rig.app.state.fleet.config = DiskConfig(severity="warning", trigger_percent=97)
    rig.send(98)
    assert not rig.records()
    rig.send(98)
    rig.send(98)
    record = rig.records()[0]
    assert record["severity"] == "warning" and record["configuration"]["trigger_percent"] == 97
    rig.app.state.fleet.config = DiskConfig(recovery_percent=70, severity="info")
    rig.send(85)
    restarted = create_app(TOKENS, ("/", PATH), clock=lambda: rig.now, store=rig.store)
    rig.client = TestClient(restarted)
    rig.app = restarted
    detail = rig.client.get("/diagnoses/" + record["id"]).json()
    assert detail["evidence_stale"] and not detail["evidence_fresh"]
    assert detail["severity"] == "warning"
    rig.send(85)
    rig.send(85)
    assert rig.records("active")  # pending recovery wasn't retained
    rig.send(85)
    assert rig.records("resolved")
    detail = rig.client.get("/diagnoses/" + record["id"]).json()
    rig.now += timedelta(seconds=16)
    stale = rig.client.get("/diagnoses/" + record["id"]).json()
    assert stale["evidence_stale"] and stale["observed_at"] == detail["observed_at"]
    for params in (
        {"limit": 0},
        {"limit": 101},
        {"offset": 10001},
        {"offset": -1},
        {"status": "x"},
        {"rule": "cpu"},
        {"start": "2026-10-11T00:00:00"},
        {"start": "2026-10-12T00:00:00Z", "end": "2026-10-11T00:00:00Z"},
    ):
        assert rig.client.get("/diagnoses", params=params).status_code == 422
    for params in (
        {"node": "node-b"},
        {"node": "node-a' OR 1=1 --"},
        {"start": "2026-10-12T00:00:00Z"},
    ):
        assert rig.client.get("/diagnoses", params=params).json()["total"] == 0
    page = rig.client.get("/diagnoses", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 1 and page["diagnoses"] == [] and page["next_offset"] is None
    assert rig.client.get("/diagnoses/" + str(uuid4())).status_code == 404


@pytest.mark.parametrize(
    "data",
    [
        {"severity": "fatal"},
        {"trigger_percent": 90, "recovery_percent": 95},
        {"consecutive_samples": True},
        {"trigger_percent": float("nan")},
        {"max_gap_seconds": 11},
    ],
)
def test_invalid_configuration(data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        DiskConfig.model_validate(data)


def test_no_production_memory_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)
    with pytest.raises(KeyError):
        create_app(TOKENS)
