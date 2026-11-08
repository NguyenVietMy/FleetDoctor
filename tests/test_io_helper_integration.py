from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from chaos_harness import source_manifest
from io_helper_integration import (
    BASE_REVISION,
    common_repository_preflight,
    manifests_match,
    materialize_source,
    windows_source_archive,
)

ROOT = Path(__file__).resolve().parents[1]
GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(
    GIT is None or not (ROOT / ".git").exists(),
    reason="real-Git source materialization requires a Git-capable checkout",
)


def git(*argv: str, cwd: Path = ROOT, check: bool = True) -> subprocess.CompletedProcess[str]:
    assert GIT is not None
    return subprocess.run([GIT, *argv], cwd=cwd, check=check, capture_output=True, text=True)


def existing_non_base_revision() -> str:
    revisions = git("rev-list", "--all").stdout.splitlines()
    candidate = next((revision for revision in revisions if revision != BASE_REVISION), None)
    if candidate is None:
        pytest.skip("real-Git regression requires an existing non-base revision")
    return candidate


def shallow_repo(tmp_path: Path, name: str, revision: str) -> Path:
    repository = tmp_path / name
    git("init", "--bare", str(repository))
    git(
        "-C",
        str(repository),
        "fetch",
        "--depth=1",
        ROOT.resolve().as_uri(),
        revision,
    )
    git("-C", str(repository), "update-ref", "refs/heads/candidate", "FETCH_HEAD")
    return repository


def test_manifest_revision_materializes_shallow_raw_and_committed_identity(
    tmp_path: Path,
) -> None:
    target = existing_non_base_revision()
    common = shallow_repo(tmp_path, "common.git", target)
    candidate = tmp_path / "candidate"
    git("clone", "--no-hardlinks", "--branch", "candidate", str(common), str(candidate))

    readme = candidate / "README.md"
    readme.write_bytes(readme.read_bytes() + b"\nfix1 raw overlay\n")
    deleted = candidate / "TASKS.md"
    deleted.unlink()
    untracked = candidate / "fix1-untracked.txt"
    untracked.write_text("untracked raw bytes\n", encoding="utf-8")
    expected = source_manifest(candidate)

    archive = tmp_path / "source.zip"
    windows_source_archive(archive, expected, candidate)
    deleted_paths = [item["path"] for item in expected["files"] if item["kind"] == "deleted"]
    preflight = common_repository_preflight(common, expected)
    materialized = materialize_source(
        common, tmp_path / "materialized", archive, deleted_paths, expected
    )

    assert target != BASE_REVISION
    assert preflight["target_revision"] == target
    assert preflight["target_exists"] is True
    assert preflight["review_base"] == BASE_REVISION
    assert preflight["review_base_exists"] is False
    assert manifests_match(expected, materialized)
    inventory = {item["path"]: item for item in materialized["files"]}
    assert inventory["README.md"]["tracked_at_head"] is True
    assert (
        inventory["README.md"]["working_tree_sha256"]
        != inventory["README.md"]["git_committed_sha256"]
    )
    assert inventory["TASKS.md"]["kind"] == "deleted"
    assert inventory["TASKS.md"]["tracked_at_head"] is True
    assert inventory["fix1-untracked.txt"]["tracked_at_head"] is False
    assert inventory["fix1-untracked.txt"]["git_committed_sha256"] is None


def test_preflight_rejects_common_repository_without_manifest_revision(
    tmp_path: Path,
) -> None:
    target = existing_non_base_revision()
    candidate_common = shallow_repo(tmp_path, "candidate.git", target)
    candidate = tmp_path / "candidate"
    git(
        "clone",
        "--no-hardlinks",
        "--branch",
        "candidate",
        str(candidate_common),
        str(candidate),
    )
    manifest = source_manifest(candidate)

    wrong_common = tmp_path / "wrong.git"
    git("init", "--bare", str(wrong_common))
    with pytest.raises(
        RuntimeError, match="selected common repository lacks source manifest revision"
    ):
        common_repository_preflight(wrong_common, manifest)

    assert manifest["revision"] == target


def test_manifest_match_ignores_platform_metadata_but_not_source_identity() -> None:
    entry: dict[str, Any] = {
        "path": "tracked.txt",
        "kind": "file",
        "working_tree_sha256": "1" * 64,
        "git_committed_sha256": "2" * 64,
        "tracked_at_head": True,
    }
    expected: dict[str, Any] = {
        "revision": "3" * 40,
        "dirty": False,
        "working_tree_platform": "nt",
        "sha256": {"tracked.txt": "1" * 64},
        "files": [dict(entry)],
    }
    platform_variant: dict[str, Any] = {
        **expected,
        "dirty": True,
        "working_tree_platform": "posix",
        "files": [dict(entry)],
    }

    assert manifests_match(expected, platform_variant)
    platform_variant["files"][0]["tracked_at_head"] = False
    assert not manifests_match(expected, platform_variant)
