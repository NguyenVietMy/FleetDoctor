"""Validate the coordinator's full-checkout source freeze before live effects."""

import hashlib
import json
import os
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from lab import ROOT


def _git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def aggregate_digest(record: dict[str, Any]) -> str:
    value = {key: item for key, item in record.items() if key != "sha256"}
    return _digest(json.dumps(value, sort_keys=True).encode())


def current_inventory(plan_sha256: str) -> dict[str, Any]:
    paths = sorted(
        {
            value.decode("utf-8")
            for value in _git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(
                b"\0"
            )
            if value
        }
    )
    files = []
    for name in paths:
        path = ROOT / name
        files.append(
            {
                "path": name,
                "kind": "file" if path.is_file() else "deleted",
                "sha256": _digest(path.read_bytes()) if path.is_file() else None,
            }
        )
    changes = sorted(
        {
            value.decode("utf-8")
            for value in (
                _git("diff", "--name-only", "-z", "f91267d5be2db914088f3f3c34375346621eafc4")
                + _git("ls-files", "--others", "--exclude-standard", "-z")
            ).split(b"\0")
            if value
        }
    )
    value: dict[str, Any] = {
        "repo": str(ROOT),
        "base": "f91267d5be2db914088f3f3c34375346621eafc4",
        "head": _git("rev-parse", "HEAD").decode().strip(),
        "tree": _git("rev-parse", "HEAD^{tree}").decode().strip(),
        "files": files,
        "changed_files": changes,
        "diff_sha256": _digest(
            _git(
                "diff",
                "--binary",
                "--no-ext-diff",
                "f91267d5be2db914088f3f3c34375346621eafc4",
            )
        ),
        "plan_sha256": plan_sha256,
    }
    value["sha256"] = aggregate_digest(value)
    return value


def validate_source_freeze(path: Path, approved_plan_sha256: str | None = None) -> dict[str, Any]:
    try:
        expected: dict[str, Any] = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid source freeze") from exc
    required = {
        "repo",
        "base",
        "head",
        "tree",
        "files",
        "changed_files",
        "diff_sha256",
        "plan_sha256",
        "sha256",
    }
    if set(expected) != required:
        raise ValueError("invalid source freeze shape")
    if not isinstance(expected["files"], list) or not isinstance(expected["changed_files"], list):
        raise ValueError("invalid source freeze inventory")
    seen: set[str] = set()
    for item in expected["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "kind", "sha256"}:
            raise ValueError("invalid source freeze file entry")
        name = item["path"]
        candidate = PurePosixPath(name) if isinstance(name, str) else None
        if (
            candidate is None
            or candidate.is_absolute()
            or ".." in candidate.parts
            or "\\" in name
            or name in seen
        ):
            raise ValueError("invalid source freeze path")
        seen.add(name)
        if item["kind"] not in ("file", "deleted"):
            raise ValueError("invalid source freeze file kind")
        digest = item["sha256"]
        if item["kind"] == "file" and (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            raise ValueError("invalid source freeze file digest")
        if item["kind"] == "deleted" and digest is not None:
            raise ValueError("deleted source freeze entry has a digest")
    if expected["sha256"] != aggregate_digest(expected):
        raise ValueError("source freeze aggregate mismatch")
    if approved_plan_sha256 is not None and expected["plan_sha256"] != approved_plan_sha256:
        raise ValueError("source freeze plan approval mismatch")
    if os.path.normcase(str(Path(expected["repo"]).resolve())) != os.path.normcase(
        str(ROOT.resolve())
    ):
        raise ValueError("source freeze repository mismatch")
    actual = current_inventory(expected["plan_sha256"])
    if expected != actual:
        raise ValueError("current checkout differs from approved source freeze")
    return expected
