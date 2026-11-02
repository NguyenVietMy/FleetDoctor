"""Validate the coordinator's full-checkout source freeze before live effects."""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from lab import ROOT

BASE = "5042e86ebc8caac113fc66984ad2cf0f0034f86a"


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
        committed = subprocess.run(["git", "show", f"HEAD:{name}"], cwd=ROOT, capture_output=True)
        files.append(
            {
                "path": name,
                "kind": "file" if path.is_file() else "deleted",
                "sha256": _digest(path.read_bytes()) if path.is_file() else None,
                "git_committed_sha256": _digest(committed.stdout)
                if committed.returncode == 0
                else None,
            }
        )
    changes = sorted(
        {
            value.decode("utf-8")
            for value in (
                _git("diff", "--name-only", "-z", BASE)
                + _git("ls-files", "--others", "--exclude-standard", "-z")
            ).split(b"\0")
            if value
        }
    )
    value: dict[str, Any] = {
        "repo": str(ROOT),
        "base": BASE,
        "head": _git("rev-parse", "HEAD").decode().strip(),
        "tree": _git("rev-parse", "HEAD^{tree}").decode().strip(),
        "files": files,
        "working_tree_platform": os.name,
        "changed_files": changes,
        "diff_sha256": _digest(
            _git(
                "diff",
                "--binary",
                "--no-ext-diff",
                BASE,
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
        "working_tree_platform",
        "changed_files",
        "diff_sha256",
        "plan_sha256",
        "sha256",
    }
    legacy_required = required - {"working_tree_platform"}
    current_shape = set(expected) == required
    if not current_shape and set(expected) != legacy_required:
        raise ValueError("invalid source freeze shape")
    if not isinstance(expected["files"], list) or not isinstance(expected["changed_files"], list):
        raise ValueError("invalid source freeze inventory")
    seen: set[str] = set()
    for item in expected["files"]:
        current_entry = {"path", "kind", "sha256", "git_committed_sha256"}
        legacy_entry = {"path", "kind", "sha256"}
        if not isinstance(item, dict) or set(item) not in (current_entry, legacy_entry):
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
        committed_digest = item.get("git_committed_sha256")
        if committed_digest is not None and (
            not isinstance(committed_digest, str)
            or len(committed_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in committed_digest)
        ):
            raise ValueError("invalid committed source digest")
    if current_shape and expected["working_tree_platform"] not in ("nt", "posix"):
        raise ValueError("invalid working tree platform")
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


def write_current_inventory(path: Path, plan_sha256: str) -> dict[str, Any]:
    """Atomically write a complete tracked and nonignored-untracked source inventory."""
    value = current_inventory(plan_sha256)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.plan_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in args.plan_sha256
    ):
        parser.error("--plan-sha256 must be a lowercase SHA-256 digest")
    value = write_current_inventory(args.output, args.plan_sha256)
    print(json.dumps({"output": str(args.output), "sha256": value["sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
