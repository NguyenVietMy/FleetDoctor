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
from fleetdoctor.history import HISTORY_METRICS
from fleetdoctor.incidents import DiskConfig, Incident, InodeConfig
from fleetdoctor.schema import Filesystem, Sample
from fleetdoctor.store import FixtureStore, StoreError

TOKEN = "i" * 40
PATH = "/var/lib/fleetdoctor/chaos/disk"


def filesystem(
    inode_usage: int,
    *,
    block_usage: int = 10,
    path: str = PATH,
    total_inodes: int = 1000,
) -> Filesystem:
    return from_statvfs(
        path,
        {
            "f_blocks": 10000,
            "f_bfree": 10000 - block_usage * 100,
            "f_bavail": 10000 - block_usage * 100,
            "f_frsize": 4096,
            "f_files": total_inodes,
            "f_ffree": total_inodes - inode_usage * total_inodes // 100,
        },
    )


class Rig:
    def __init__(self, store: FixtureStore | None = None) -> None:
        self.now = datetime(2026, 10, 18, tzinfo=UTC)
        self.store = store or FixtureStore()
        self.boot, self.session = uuid4(), uuid4()
        self.sequence = 0
        self.app = create_app(
            {"node-a": SecretStr(TOKEN)},
            ("/", PATH),
            clock=lambda: self.now,
            store=self.store,
        )
        self.client = TestClient(self.app)

    def sample(
        self,
        inode_usage: int | None,
        *,
        block_usage: int | None = 10,
        root_block_usage: int = 10,
        gap: int = 5,
    ) -> Sample:
        self.now += timedelta(seconds=gap)
        self.sequence += 1
        if inode_usage is None:
            target = Filesystem(mountpoint=PATH, errors=["inode_unavailable"])
        elif block_usage is None:
            value = filesystem(inode_usage)
            target = Filesystem(
                mountpoint=PATH,
                inodes_total=value.inodes_total,
                inodes_free=value.inodes_free,
                inode_usage_percent=value.inode_usage_percent,
                errors=["block_unavailable"],
            )
        else:
            target = filesystem(inode_usage, block_usage=block_usage)
        return make_sample(
            "node-a",
            self.boot,
            self.session,
            self.sequence,
            [filesystem(10, block_usage=root_block_usage, path="/"), target],
            self.now,
        )

    def send(self, inode_usage: int | None, **kwargs: Any) -> None:
        sample = self.sample(inode_usage, **kwargs)
        response = self.client.post(
            "/ingest",
            content=sample.model_dump_json(),
            headers={"Authorization": "Bearer " + TOKEN},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"

    def records(
        self, rule: str = "inode_exhaustion", status: str | None = None
    ) -> list[dict[str, Any]]:
        params = {"rule": rule}
        if status is not None:
            params["status"] = status
        response = self.client.get("/diagnoses", params=params)
        assert response.status_code == 200
        return list(response.json()["diagnoses"])


def test_inode_lifecycle_block_disambiguation_coverage_metrics_and_history() -> None:
    rig = Rig()
    for inode, block in ((95, 95), (95, 96), (95, None), (0, 10)):
        rig.send(inode, block_usage=block)
    assert not rig.records()
    for value in (95, 94, 95, 95, 95):
        rig.send(value)
    opened = rig.records(status="active")[0]
    assert opened["severity"] == "critical" and opened["resource"] == PATH
    detail = rig.client.get("/diagnoses/" + opened["id"]).json()
    assert detail["configuration"] == InodeConfig().model_dump()
    assert detail["opening_evidence"]["inode_available"]
    assert detail["opening_evidence"]["block_available"]
    assert detail["opening_evidence"]["filesystem"]["available_bytes"] > 0
    assert "causal directory" in detail["investigation_steps"][2]

    node = rig.client.get("/nodes/node-a/metrics").json()
    assert node["diagnosis_coverage"][PATH] == "available"
    assert node["inode_diagnosis_coverage"][PATH] == "available"
    assert node["active_incident_counts"]["inode_exhaustion"] == 1
    metrics = rig.client.get("/metrics").text
    assert 'fleetdoctor_active_incidents{node="node-a",rule="inode_exhaustion"} 1.0' in metrics
    assert (
        f'fleetdoctor_inode_diagnosis_coverage_ratio{{filesystem="{PATH}",node="node-a"}} 1.0'
        in metrics
    )
    configuration = rig.client.get("/configuration").json()
    assert configuration["inode_rule"] == InodeConfig().model_dump()
    assert {
        "inodes_total",
        "inodes_free",
        "inode_usage_ratio",
        "inode_diagnosis_coverage_ratio",
    }.issubset(HISTORY_METRICS)

    rig.send(89, block_usage=None)
    rig.send(89, block_usage=None)
    rig.send(None)
    assert rig.records(status="active")
    for _ in range(3):
        rig.send(89, block_usage=None)
    resolved = rig.client.get("/diagnoses/" + opened["id"]).json()
    assert resolved["status"] == "resolved"
    assert resolved["opening_evidence"] == detail["opening_evidence"]
    assert resolved["latest_evidence"]["inode_available"]
    assert not resolved["latest_evidence"]["block_available"]


@pytest.mark.parametrize("phase", ["opening", "recovery"])
@pytest.mark.parametrize("reset", ["missing", "gap", "session", "boot", "band"])
def test_inode_windows_reset_on_ineligible_continuity(phase: str, reset: str) -> None:
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
    rig.send(usage)
    assert bool(rig.records(status="active")) is (phase == "recovery")
    rig.send(usage)
    if reset in ("missing", "band"):
        assert bool(rig.records(status="active")) is (phase == "recovery")
        rig.send(usage)
    assert bool(rig.records(status="active")) is (phase == "opening")


def test_inode_config_is_frozen_and_persisted_json_is_rule_directed() -> None:
    rig = Rig()
    rig.app.state.fleet.inode_config = InodeConfig(trigger_percent=97, severity="warning")
    for _ in range(3):
        rig.send(98)
    record = rig.records(status="active")[0]
    assert record["configuration"]["trigger_percent"] == 97
    assert record["severity"] == "warning"
    rig.app.state.fleet.inode_config = InodeConfig(recovery_percent=70)
    rig.send(80)

    restarted = create_app(
        {"node-a": SecretStr(TOKEN)},
        ("/", PATH),
        clock=lambda: rig.now,
        store=rig.store,
    )
    rig.app, rig.client = restarted, TestClient(restarted)
    reloaded = rig.store.active()[0]
    assert type(reloaded.configuration) is InodeConfig
    assert reloaded.configuration.trigger_percent == 97
    for _ in range(3):
        rig.send(80)
    assert rig.records(status="resolved")

    payload = reloaded.model_dump(mode="json")
    inode_shape = InodeConfig().model_dump()
    payload["configuration"] = inode_shape
    decoded = Incident.model_validate_json(Incident.model_validate(payload).model_dump_json())
    assert type(decoded.configuration) is InodeConfig
    payload["rule"] = "disk_block_exhaustion"
    payload["configuration"] = DiskConfig().model_dump()
    payload["opening_evidence"]["block_available"] = True
    payload["latest_evidence"]["block_available"] = True
    assert type(Incident.model_validate(payload).configuration) is DiskConfig


class LostAcknowledgementStore(FixtureStore):
    lose_next_commit = False

    def commit(self, changes: list[Incident], checkpoint: Checkpoint) -> None:
        super().commit(changes, checkpoint)
        if self.lose_next_commit:
            self.lose_next_commit = False
            raise StoreError("COMMIT succeeded; acknowledgement lost")


def test_mixed_disk_inode_lost_ack_reconciles_and_inode_recurs() -> None:
    store = LostAcknowledgementStore()
    rig = Rig(store)
    rig.send(96, root_block_usage=98)
    rig.send(96, root_block_usage=98)
    final = rig.sample(96, root_block_usage=98)
    store.lose_next_commit = True
    failed = rig.client.post(
        "/ingest",
        content=final.model_dump_json(),
        headers={"Authorization": "Bearer " + TOKEN},
    )
    assert failed.status_code == 503
    assert {incident.rule for incident in store.active()} == {
        "disk_block_exhaustion",
        "inode_exhaustion",
    }
    retry = rig.client.post(
        "/ingest",
        content=final.model_dump_json(),
        headers={"Authorization": "Bearer " + TOKEN},
    )
    assert retry.json()["status"] == "duplicate"
    counts = rig.client.get("/nodes/node-a/metrics").json()["active_incident_counts"]
    assert counts["disk_block_exhaustion"] == counts["inode_exhaustion"] == 1

    for _ in range(3):
        rig.send(80)
    assert not store.active()
    first_inode = rig.records()[0]
    for _ in range(3):
        rig.send(96)
    inode_records = rig.records()
    assert len(inode_records) == 2
    assert len([record for record in inode_records if record["status"] == "active"]) == 1
    assert (
        next(record for record in inode_records if record["id"] == first_inode["id"])["status"]
        == "resolved"
    )


def test_collector_restart_rebuilds_inode_opening_and_recovery_windows() -> None:
    rig = Rig()
    rig.send(96)
    rig.send(96)
    restarted = create_app(
        {"node-a": SecretStr(TOKEN)},
        ("/", PATH),
        clock=lambda: rig.now,
        store=rig.store,
    )
    rig.app, rig.client = restarted, TestClient(restarted)
    rig.send(96)
    rig.send(96)
    assert not rig.records(status="active")
    rig.send(96)
    opened = rig.records(status="active")[0]

    rig.send(80)
    rig.send(80)
    restarted = create_app(
        {"node-a": SecretStr(TOKEN)},
        ("/", PATH),
        clock=lambda: rig.now,
        store=rig.store,
    )
    rig.app, rig.client = restarted, TestClient(restarted)
    rig.send(80)
    rig.send(80)
    assert rig.records(status="active")[0]["id"] == opened["id"]
    rig.send(80)
    assert rig.client.get("/diagnoses/" + opened["id"]).json()["status"] == "resolved"


def test_inode_guard_cannot_exceed_lowered_disk_trigger() -> None:
    rig = Rig()
    rig.app.state.fleet.config = DiskConfig(trigger_percent=92, recovery_percent=85)
    rig.app.state.fleet.inode_config = InodeConfig(block_guard_percent=95)
    for _ in range(3):
        rig.send(96, block_usage=93)
    assert not rig.records()
    disk = rig.records(rule="disk_block_exhaustion", status="active")
    assert len(disk) == 1
    assert rig.client.get("/configuration").json()["effective_inode_block_guard_percent"] == 92
    assert rig.client.get("/configuration").json()["inode_rule"]["block_guard_percent"] == 92
    assert rig.client.get("/configuration").json()["inode_rule_requested_block_guard_percent"] == 95

    lower = Rig()
    lower.app.state.fleet.config = DiskConfig(trigger_percent=92, recovery_percent=85)
    for _ in range(3):
        lower.send(96, block_usage=91)
    lowered_incident = lower.records(status="active")[0]
    assert lowered_incident["configuration"]["block_guard_percent"] == 92
    assert (
        lower.client.get("/diagnoses/" + lowered_incident["id"]).json()["opening_evidence"][
            "effective_block_guard_percent"
        ]
        == 92
    )

    other = Rig()
    other.app.state.fleet.config = DiskConfig(trigger_percent=99)
    other.app.state.fleet.inode_config = InodeConfig(block_guard_percent=90)
    for _ in range(3):
        other.send(96, block_usage=89)
    inode = other.records(status="active")[0]
    detail = other.client.get("/diagnoses/" + inode["id"]).json()
    assert detail["configuration"]["block_guard_percent"] == 90
    assert detail["opening_evidence"]["effective_block_guard_percent"] == 90


@pytest.mark.parametrize(
    "data",
    [
        {"trigger_percent": 90, "recovery_percent": 95},
        {"block_guard_percent": 0},
        {"consecutive_samples": True},
        {"max_gap_seconds": 11},
        {"severity": "fatal"},
    ],
)
def test_invalid_inode_configuration(data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        InodeConfig.model_validate(data)
