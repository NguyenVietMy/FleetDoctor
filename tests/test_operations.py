import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import lab
import pytest
from deploy_lab import filesystem_paths, load_env
from healthy_demo import delivery_report, journal_bounds
from lab import current_addresses, inventory
from prepare_aws_plan import check_instance_deletions
from upgrade_env import DISK_PATH, upgrade


@pytest.fixture
def inventory_values() -> dict[str, dict[str, str]]:
    return {
        "monitor": {"id": "i-0123456789abcdef0", "private_ip": "10.0.1.10"},
        "node-a": {"id": "i-0123456789abcdef1", "private_ip": "10.0.1.11"},
        "node-b": {"id": "i-0123456789abcdef2", "private_ip": "10.0.1.12"},
    }


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig"])
def test_inventory_accepts_utf8_with_or_without_bom(
    tmp_path: Path, inventory_values: dict[str, dict[str, str]], encoding: str
) -> None:
    path = tmp_path / "instances.json"
    encoded = json.dumps(inventory_values).encode(encoding)
    assert encoded.startswith(b"\xef\xbb\xbf") == (encoding == "utf-8-sig")
    path.write_bytes(encoded)
    assert inventory(path) == inventory_values


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig"])
@pytest.mark.parametrize("invalid", ["missing-role", "extra-role", "invalid-id"])
def test_inventory_encoding_does_not_bypass_safety_validation(
    tmp_path: Path,
    inventory_values: dict[str, dict[str, str]],
    encoding: str,
    invalid: str,
) -> None:
    if invalid == "missing-role":
        inventory_values.pop("node-b")
    elif invalid == "extra-role":
        inventory_values["unrelated"] = {"id": "i-0123456789abcdef3"}
    else:
        inventory_values["node-a"]["id"] = "not-an-instance"
    path = tmp_path / "instances.json"
    path.write_bytes(json.dumps(inventory_values).encode(encoding))
    with pytest.raises(ValueError, match="expected exactly|invalid instance ID"):
        inventory(path)


def test_public_addresses_come_from_current_aws_response() -> None:
    response: dict[str, Any] = {
        "Reservations": [
            {
                "Instances": [
                    {"InstanceId": "i-abc", "PublicIpAddress": "203.0.113.22"},
                    {"InstanceId": "i-def", "PublicIpAddress": "203.0.113.23"},
                ]
            }
        ]
    }
    assert current_addresses(response, {"i-abc", "i-def"}) == {
        "i-abc": "203.0.113.22",
        "i-def": "203.0.113.23",
    }
    with pytest.raises(ValueError):
        current_addresses(response, {"i-other"})
    response["Reservations"][0]["Instances"][0].pop("PublicIpAddress")
    with pytest.raises(ValueError):
        current_addresses(response, {"i-abc", "i-def"})


def configure_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inventory_values: dict[str, dict[str, str]],
    script: bytes,
) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    (root / "deploy").mkdir(parents=True)
    (root / "deploy/export-monitor.sh").write_bytes(script)
    output = tmp_path / "backup"
    monkeypatch.setattr(lab, "ROOT", root)
    monkeypatch.setattr(lab, "inventory", lambda path: inventory_values)
    monkeypatch.setattr(
        lab,
        "addresses",
        lambda profile, values: {
            "monitor": "203.0.113.1",
            "node-a": "203.0.113.2",
            "node-b": "203.0.113.3",
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lab.py",
            "export",
            "--inventory",
            str(tmp_path / "instances.json"),
            "--key",
            str(tmp_path / "key"),
            "--output",
            str(output),
        ],
    )
    return root, output


def test_export_rejects_crlf_local_script_before_any_export_side_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inventory_values: dict[str, dict[str, str]],
) -> None:
    _, output = configure_export(
        tmp_path,
        monkeypatch,
        inventory_values,
        b"#!/bin/bash\r\nset -euo pipefail\r\n",
    )

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("export side effect reached before local script validation")

    monkeypatch.setattr(lab, "addresses", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(ValueError, match="LF line endings"):
        lab.main()
    assert not output.exists()


def test_export_streams_exact_local_script_and_deletes_remote_only_after_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inventory_values: dict[str, dict[str, str]],
) -> None:
    script = b"#!/bin/bash\nset -euo pipefail\ncd /opt/fleetdoctor/current\n"
    _, output = configure_export(tmp_path, monkeypatch, inventory_values, script)
    actions: list[str] = []

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        remote = argv[-1]
        if "pg_dump" in remote:
            actions.append("pg_dump")
            assert kwargs["timeout"] == 90
            return SimpleNamespace(returncode=0, stdout=b"private sql\n", stderr=b"")
        if remote == "sudo bash -s":
            actions.append("local_script_stdin")
            assert kwargs["input"] == script
            assert kwargs["timeout"] == 180
            assert kwargs["capture_output"] is True
            assert kwargs["text"] is False
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        if argv[0] == "scp":
            actions.append("local_archive_copy")
            Path(argv[-1]).write_bytes(b"private stores\n")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if remote == "rm -f /tmp/fleetdoctor-stores.tgz":
            assert (output / "stores.tgz").read_bytes() == b"private stores\n"
            actions.append("remote_archive_delete")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected subprocess: {argv}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    lab.main()
    assert actions == [
        "pg_dump",
        "local_script_stdin",
        "local_archive_copy",
        "remote_archive_delete",
    ]
    assert (output / "postgres.sql").read_bytes() == b"private sql\n"
    assert (output / "stores.tgz").read_bytes() == b"private stores\n"
    assert json.loads((output / "instances.json").read_text(encoding="utf-8")) == inventory_values


@pytest.mark.parametrize("failure", ["exit", "timeout"])
def test_export_script_failure_is_bounded_redacted_and_preserves_remote_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inventory_values: dict[str, dict[str, str]],
    failure: str,
) -> None:
    script = b"#!/bin/bash\nset -euo pipefail\n"
    _, output = configure_export(tmp_path, monkeypatch, inventory_values, script)
    actions: list[str] = []

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        remote = argv[-1]
        if "pg_dump" in remote:
            actions.append("pg_dump")
            return SimpleNamespace(returncode=0, stdout=b"private sql\n", stderr=b"")
        if remote == "sudo bash -s":
            actions.append("local_script_stdin")
            assert kwargs["input"] == script
            assert kwargs["timeout"] == 180
            if failure == "timeout":
                raise subprocess.TimeoutExpired(
                    argv, kwargs["timeout"], output=b"PRIVATE STDOUT", stderr=b"PRIVATE STDERR"
                )
            return SimpleNamespace(
                returncode=23, stdout=b"PRIVATE STDOUT", stderr=b"PRIVATE STDERR"
            )
        actions.append("unexpected_after_failure")
        raise AssertionError("copy or deletion ran after export script failure")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises((RuntimeError, TimeoutError)) as failure_info:
        lab.main()
    assert "PRIVATE" not in str(failure_info.value)
    assert actions == ["pg_dump", "local_script_stdin"]
    assert (output / "postgres.sql").read_bytes() == b"private sql\n"
    assert not (output / "stores.tgz").exists()


def delivery_samples(sequences: list[int], interval: int = 5) -> list[dict[str, Any]]:
    start = datetime(2026, 10, 11, tzinfo=UTC)
    return [
        {
            "node_id": "node-b",
            "boot_id": "boot",
            "agent_session_id": "session",
            "sequence": sequence,
            "observed_at": (start + timedelta(seconds=sequence * interval)).isoformat(),
        }
        for sequence in sequences
    ]


def test_delivery_report_allows_repeated_polls_of_consecutive_samples() -> None:
    report = delivery_report(delivery_samples([11, 11, 12, 12, 13, 14]))
    assert report["sequences"] == [11, 12, 13, 14]
    assert report["raw_intervals_seconds"] == [5, 5, 5]


def test_delivery_report_rejects_gap_hidden_by_old_normalization() -> None:
    with pytest.raises(ValueError, match="nonconsecutive"):
        delivery_report(delivery_samples([11, 11, 13, 14]))


def test_delivery_report_rejects_slow_raw_delivery() -> None:
    with pytest.raises(ValueError, match="raw observation interval"):
        delivery_report(delivery_samples([0, 1, 2, 3], interval=10))


def test_journal_window_uses_sample_clock() -> None:
    samples = delivery_samples([0, 1, 2, 3])
    start, end = journal_bounds(samples)
    assert start == datetime(2026, 10, 11, tzinfo=UTC) - timedelta(seconds=1)
    assert end == datetime(2026, 10, 11, tzinfo=UTC) + timedelta(seconds=17)


def test_retained_env_private_upgrade_is_idempotent_and_preserves_secrets(tmp_path: Path) -> None:
    path = tmp_path / "lab.env"
    original = "POSTGRES_PASSWORD='retained'\nGRAFANA_PASSWORD='retained-ui'\nFLEETDOCTOR_NODE_TOKENS='{}'\nCOLLECTOR_PORT='8000'\n"
    path.write_text(original)
    assert upgrade(path, disk=True)
    upgraded = path.read_text()
    assert upgraded.startswith(original)
    settings = load_env(path)
    assert len(settings["GRAFANA_DB_PASSWORD"]) >= 32
    assert filesystem_paths(settings) == ("/", DISK_PATH)
    assert not upgrade(path, disk=True) and path.read_text() == upgraded
    with pytest.raises(ValueError):
        filesystem_paths({"FLEETDOCTOR_FILESYSTEMS": "/,/tmp/unverified"})


@pytest.mark.parametrize("actions", [["delete"], ["delete", "create"], ["create", "delete"]])
def test_terraform_plan_rejects_instance_loss(actions: list[str]) -> None:
    plan = {
        "resource_changes": [
            {
                "address": 'aws_instance.lab["monitor"]',
                "type": "aws_instance",
                "mode": "managed",
                "change": {"actions": actions},
            }
        ]
    }
    with pytest.raises(ValueError, match="instance deletion/replacement rejected"):
        check_instance_deletions(plan)
    assert check_instance_deletions(plan, allow_instance_deletion=True) == [
        'aws_instance.lab["monitor"]'
    ]


def test_terraform_plan_allows_creation_and_in_place_maintenance() -> None:
    for actions in (["create"], ["update"], ["no-op"]):
        assert not check_instance_deletions(
            {
                "resource_changes": [
                    {
                        "address": 'aws_instance.lab["monitor"]',
                        "type": "aws_instance",
                        "change": {"actions": actions},
                    }
                ]
            }
        )
