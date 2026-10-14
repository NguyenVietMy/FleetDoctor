import argparse
import hashlib
import json
import sys
import tarfile
from copy import deepcopy
from pathlib import Path
from typing import Any

import deploy_lab
import pytest
import source_freeze
from lab import ROOT
from source_freeze import aggregate_digest
from upgrade_env import DISK_PATH


def inventory_values() -> dict[str, dict[str, str]]:
    return {
        role: {"id": identifier, "private_ip": private_ip}
        for role, (identifier, private_ip) in deploy_lab.EXPECTED_INSTANCES.items()
    }


class ArchiveObserved(RuntimeError):
    pass


def write_release_fixture(root: Path, install_script: bytes) -> None:
    (root / "deploy").mkdir(parents=True)
    (root / "deploy/install-agent.sh").write_bytes(install_script)
    (root / "src/fleetdoctor").mkdir(parents=True)
    (root / "monitoring").mkdir()
    for name in ("pyproject.toml", "uv.lock", "compose.yaml", "Dockerfile", ".dockerignore"):
        (root / name).write_text(name + "\n", encoding="utf-8", newline="\n")


def run_release_packaging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    install_script: bytes,
    remote_deploy: Any,
) -> Path:
    root = tmp_path / "repo"
    write_release_fixture(root, install_script)
    env = tmp_path / "lab.env"
    env.write_text(
        "GRAFANA_DB_PASSWORD='" + "g" * 32 + "'\n"
        "COLLECTOR_BIND_IP='10.42.1.242'\n"
        "FLEETDOCTOR_NODE_TOKENS='" + json.dumps({"node-a": "a" * 40, "node-b": "b" * 40}) + "'\n"
        "FLEETDOCTOR_FILESYSTEMS='/'\n",
        encoding="utf-8",
        newline="\n",
    )
    output = tmp_path / "deploy.json"
    monkeypatch.setattr(deploy_lab, "ROOT", root)
    monkeypatch.setattr(deploy_lab, "inventory", lambda path: inventory_values())
    monkeypatch.setattr(
        deploy_lab,
        "addresses",
        lambda profile, values: {
            role: f"203.0.113.{index + 1}" for index, role in enumerate(values)
        },
    )
    monkeypatch.setattr(deploy_lab, "validate_live_scope", lambda profile, values: None)
    monkeypatch.setattr(
        deploy_lab,
        "validate_source_freeze",
        lambda path, plan: {
            "sha256": "a" * 64,
            "plan_sha256": plan,
            "files": [{"path": "deploy/install-agent.sh"}],
        },
    )

    def local_build(argv: list[str], *, timeout: int = 180, data: str | None = None) -> str:
        if argv[:2] == ["uv", "build"]:
            stage = Path(argv[argv.index("--out-dir") + 1])
            (stage / "fleetdoctor-0-py3-none-any.whl").write_bytes(b"wheel")
            return ""
        if argv[:2] == ["uv", "export"]:
            Path(argv[argv.index("--output-file") + 1]).write_text(
                "dependency==1 --hash=sha256:" + "0" * 64 + "\n",
                encoding="utf-8",
                newline="\n",
            )
            return ""
        raise AssertionError(f"unexpected command before remote staging: {argv[0]}")

    monkeypatch.setattr(deploy_lab, "command", local_build)
    monkeypatch.setattr(deploy_lab, "remote_deploy", remote_deploy)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "deploy_lab.py",
            "--env",
            str(env),
            "--source-freeze",
            str(tmp_path / "freeze.json"),
            "--approved-plan-sha256",
            "3" * 64,
            "--output",
            str(output),
        ],
    )
    return output


def test_crlf_release_script_is_rejected_before_remote_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden_remote_stage(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("remote staging reached with an invalid release shell")

    output = run_release_packaging(
        tmp_path,
        monkeypatch,
        b"#!/bin/bash\r\nset -euo pipefail\r\n",
        forbidden_remote_stage,
    )
    with pytest.raises(ValueError, match="LF line endings"):
        deploy_lab.main()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "failed"
    assert report["remote_stage_cleanup"] == {}


def test_release_archive_contains_exact_validated_lf_shell_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = b"#!/bin/bash\nset -euo pipefail\n"

    def observe_archive(
        args: argparse.Namespace,
        values: dict[str, dict[str, str]],
        public: dict[str, str],
        paths: tuple[str, ...],
        archive: Path,
        local_stage: Path,
        report: dict[str, Any],
    ) -> None:
        assert (
            hashlib.sha256(archive.read_bytes()).hexdigest() == report["release"]["archive_sha256"]
        )
        with tarfile.open(archive, "r:gz") as release:
            member = release.extractfile("deploy/install-agent.sh")
            assert member is not None
            assert member.read() == expected
        raise ArchiveObserved("archive captured before remote staging")

    run_release_packaging(tmp_path, monkeypatch, expected, observe_archive)
    with pytest.raises(ArchiveObserved, match="captured"):
        deploy_lab.main()


def test_source_drift_aborts_before_inventory_or_remote_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual: dict[str, Any] = {
        "repo": str(ROOT),
        "base": "f91267d5be2db914088f3f3c34375346621eafc4",
        "head": "f91267d5be2db914088f3f3c34375346621eafc4",
        "tree": "70216499b0ae8c809025234de37911eefa2fe1be",
        "files": [{"path": "README.md", "kind": "file", "sha256": "1" * 64}],
        "changed_files": ["README.md"],
        "diff_sha256": "2" * 64,
        "plan_sha256": "3" * 64,
    }
    actual["sha256"] = aggregate_digest(actual)
    monkeypatch.setattr(source_freeze, "current_inventory", lambda plan: deepcopy(actual))
    frozen = deepcopy(actual)
    frozen["files"][0]["sha256"] = "0" * 64
    frozen["sha256"] = aggregate_digest(frozen)
    source = tmp_path / "freeze.json"
    source.write_text(json.dumps(frozen), encoding="utf-8")
    output = tmp_path / "deploy.json"

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("live boundary reached after invalid source")

    monkeypatch.setattr(deploy_lab, "inventory", forbidden)
    monkeypatch.setattr(deploy_lab, "addresses", forbidden)
    monkeypatch.setattr(deploy_lab, "command", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "deploy_lab.py",
            "--env",
            str(tmp_path / "unused.env"),
            "--source-freeze",
            str(source),
            "--approved-plan-sha256",
            "3" * 64,
            "--output",
            str(output),
        ],
    )
    with pytest.raises(ValueError, match="differs"):
        deploy_lab.main()
    report = json.loads(output.read_text())
    assert report["status"] == "failed" and report["remote_stage_cleanup"] == {}


def test_exact_account_and_inventory_are_required(monkeypatch: pytest.MonkeyPatch) -> None:
    values = inventory_values()
    monkeypatch.setattr(
        deploy_lab,
        "aws",
        lambda *args, **kwargs: json.dumps({"Account": deploy_lab.EXPECTED_ACCOUNT}),
    )
    deploy_lab.validate_live_scope("fleetdoctor", values)
    values["node-a"]["id"] = "i-wrong"
    with pytest.raises(ValueError, match="inventory"):
        deploy_lab.validate_live_scope("fleetdoctor", values)
    values = inventory_values()
    monkeypatch.setattr(
        deploy_lab, "aws", lambda *args, **kwargs: json.dumps({"Account": "000000000000"})
    )
    with pytest.raises(ValueError, match="account"):
        deploy_lab.validate_live_scope("fleetdoctor", values)


@pytest.mark.parametrize("failure_step", range(1, 19))
def test_every_remote_copy_and_activation_failure_cleans_only_owned_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_step: int
) -> None:
    env = tmp_path / "lab.env"
    env.write_text(
        "FLEETDOCTOR_NODE_TOKENS='" + json.dumps({"node-a": "a" * 40, "node-b": "b" * 40}) + "'\n",
        encoding="utf-8",
    )
    archive = tmp_path / "release.tgz"
    archive.write_bytes(b"release")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    args = argparse.Namespace(env=env, key=tmp_path / "key")
    values = inventory_values()
    public = {role: f"203.0.113.{index + 1}" for index, role in enumerate(values)}
    report: dict[str, Any] = {"release": {"archive_sha256": digest}}
    mutation_count = 0
    prepared: list[str] = []
    cleanup_commands: list[str] = []

    def fake_command(argv: list[str], *, timeout: int = 180, data: str | None = None) -> str:
        nonlocal mutation_count
        text = argv[-1]
        if "mktemp -d" in text:
            stage = f"/tmp/fleetdoctor.{len(prepared):010d}"
            prepared.append(stage)
            return stage + "\n"
        if "rm -f --" in text:
            cleanup_commands.append(text)
            return ""
        if "sha256sum" in text:
            return digest + "\n"
        mutating = argv[0] == "scp" or any(
            marker in text
            for marker in (
                "tar -xzf",
                "disk_resource.py prepare",
                "install-agent.sh",
                "systemctl is-active --quiet",
            )
        )
        if mutating:
            mutation_count += 1
            if mutation_count == failure_step:
                raise InterruptedError("injected deployment interruption")
        return ""

    monkeypatch.setattr(deploy_lab, "command", fake_command)
    with pytest.raises(InterruptedError):
        deploy_lab.remote_deploy(
            args,
            values,
            public,
            ("/", DISK_PATH),
            archive,
            tmp_path,
            report,
        )
    assert len(cleanup_commands) == len(prepared)
    assert all("rm -rf" not in command and "*" not in command for command in cleanup_commands)
    assert set(report["remote_stage_cleanup"]) == set(list(values)[: len(prepared)])
