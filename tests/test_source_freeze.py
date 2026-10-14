import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import source_freeze
from lab import ROOT
from source_freeze import aggregate_digest, validate_source_freeze

PLAN_HASH = "3" * 64


def write(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def inventory() -> dict[str, Any]:
    value: dict[str, Any] = {
        "repo": str(ROOT),
        "base": "f91267d5be2db914088f3f3c34375346621eafc4",
        "head": "f91267d5be2db914088f3f3c34375346621eafc4",
        "tree": "70216499b0ae8c809025234de37911eefa2fe1be",
        "files": [{"path": "README.md", "kind": "file", "sha256": "1" * 64}],
        "changed_files": ["README.md"],
        "diff_sha256": "2" * 64,
        "plan_sha256": PLAN_HASH,
    }
    value["sha256"] = aggregate_digest(value)
    return value


def test_full_checkout_freeze_matches_every_inventoried_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frozen = inventory()
    monkeypatch.setattr(source_freeze, "current_inventory", lambda plan: deepcopy(frozen))
    path = tmp_path / "freeze.json"
    write(path, frozen)
    validated = validate_source_freeze(path, PLAN_HASH)
    assert validated["sha256"] == frozen["sha256"]
    assert {item["kind"] for item in validated["files"]} <= {"file", "deleted"}


def test_freeze_rejects_reviewed_file_drift_and_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual = inventory()
    monkeypatch.setattr(source_freeze, "current_inventory", lambda plan: deepcopy(actual))
    frozen = deepcopy(actual)
    first = next(item for item in frozen["files"] if item["kind"] == "file")
    first["sha256"] = "0" * 64
    frozen["sha256"] = aggregate_digest(frozen)
    path = tmp_path / "drift.json"
    write(path, frozen)
    with pytest.raises(ValueError, match="differs"):
        validate_source_freeze(path, PLAN_HASH)

    frozen = deepcopy(actual)
    frozen["files"].append({"path": "../secret", "kind": "file", "sha256": "0" * 64})
    frozen["sha256"] = aggregate_digest(frozen)
    write(tmp_path / "traversal.json", frozen)
    with pytest.raises(ValueError, match="path"):
        validate_source_freeze(tmp_path / "traversal.json", PLAN_HASH)
