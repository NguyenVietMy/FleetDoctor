import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import chaos_disk
import pytest


def setup_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    output, preflight = tmp_path / "run.json", tmp_path / "healthy.json"
    monkeypatch.setattr(chaos_disk, "ROOT", tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chaos_disk",
            "--output",
            str(output),
            "--preflight",
            str(preflight),
            "--inventory",
            str(tmp_path / "inventory.json"),
        ],
    )
    preflight.write_text(
        json.dumps(
            {"status": "passed", "source_sha256": {}, "finished_at": datetime.now(UTC).isoformat()}
        )
    )
    return output, preflight


@pytest.mark.parametrize("failure", ["stale", "malformed", "lookup"])
def test_cli_preparation_failure_is_retained_without_injection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    output, preflight = setup_cli(tmp_path, monkeypatch)
    if failure == "stale":
        value = json.loads(preflight.read_text())
        value["finished_at"] = "2020-01-01T00:00:00Z"
        preflight.write_text(json.dumps(value))
    elif failure == "malformed":
        preflight.write_text("{")
    monkeypatch.setattr(chaos_disk, "inventory", Mock(return_value={}))
    addresses = Mock(side_effect=OSError("lookup failed"))
    monkeypatch.setattr(chaos_disk, "addresses", addresses)
    injector = Mock()
    monkeypatch.setattr(chaos_disk, "RemoteInjector", injector)
    with pytest.raises((ValueError, OSError)):
        chaos_disk.main()
    report = json.loads(output.read_text())
    assert report["status"] == "failed" and report["phase"] == "preparation"
    assert report["injection_attempted"] is False and report["errors"]
    injector.assert_not_called()
    if failure != "lookup":
        addresses.assert_not_called()


def test_cli_pre_run_probe_failure_marks_harness_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, _ = setup_cli(tmp_path, monkeypatch)
    monkeypatch.setattr(chaos_disk, "inventory", Mock(return_value={}))
    monkeypatch.setattr(
        chaos_disk,
        "addresses",
        Mock(return_value={"node-a": "fixture-a", "node-b": "fixture-b", "monitor": "fixture-m"}),
    )
    monkeypatch.setattr("chaos_harness.source_manifest", lambda: {"revision": "fixture"})
    injector = Mock()
    injector.probe.side_effect = OSError("resource probe failed")
    injector.commands = []
    monkeypatch.setattr(chaos_disk, "RemoteInjector", lambda _: injector)
    with pytest.raises(OSError):
        chaos_disk.main()
    report = json.loads(output.read_text())
    assert report["status"] == "failed" and report["injection_attempted"] is False
    assert "resource probe failed" in report["errors"][0]
    assert "injection_start" not in report["events"]
    injector.start.assert_not_called()


def test_cli_existing_output_is_refused_before_any_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, preflight = setup_cli(tmp_path, monkeypatch)
    output.write_text("retained original")
    preflight.write_text("malformed")
    with pytest.raises(ValueError, match="new report"):
        chaos_disk.main()
    assert output.read_text() == "retained original"
