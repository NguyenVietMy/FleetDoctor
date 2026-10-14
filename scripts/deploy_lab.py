"""Deploy a hash-verified local wheel and source archive to existing lab instances."""

import argparse
import hashlib
import json
import re
import shlex
import shutil
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chaos_harness import write_report
from lab import ROOT, addresses, aws, command, inventory, validated_lf_shell
from source_freeze import validate_source_freeze
from upgrade_env import DISK_PATH

EXPECTED_ACCOUNT = "520622116399"
EXPECTED_INSTANCES = {
    "monitor": ("i-0d038b65ed59c5dfd", "10.42.1.242"),
    "node-a": ("i-01a322f2d65025cde", "10.42.1.101"),
    "node-b": ("i-0a734cc76af61c027", "10.42.1.169"),
}


@dataclass
class RemoteStage:
    role: str
    target: str
    prefix: list[str]
    path: str
    files: set[str] = field(default_factory=lambda: {"release.tgz"})


def filesystem_paths(settings: dict[str, str]) -> tuple[str, ...]:
    paths = tuple(settings.get("FLEETDOCTOR_FILESYSTEMS", "/").split(","))
    if paths not in (("/",), ("/", DISK_PATH)):
        raise ValueError("lab deployment supports root plus the verified dedicated disk only")
    return paths


def load_env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip("'")
    return values


def validate_live_scope(profile: str, values: dict[str, dict[str, str]]) -> None:
    actual = {role: (item.get("id"), item.get("private_ip")) for role, item in values.items()}
    if actual != EXPECTED_INSTANCES:
        raise ValueError("inventory does not match the exact retained Task04 lab")
    identity = json.loads(aws(profile, "sts", "get-caller-identity", "--output", "json"))
    if identity.get("Account") != EXPECTED_ACCOUNT:
        raise ValueError("AWS account does not match the approved Task04 lab")


def cleanup_stages(stages: list[RemoteStage], report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    results: dict[str, Any] = report.setdefault("remote_stage_cleanup", {})
    for stage in stages:
        exact_files = " ".join(shlex.quote(stage.path + "/" + name) for name in sorted(stage.files))
        cleanup = f"rm -f -- {exact_files}; rmdir -- {shlex.quote(stage.path)}"
        attempts = []
        for attempt in range(1, 4):
            try:
                command(stage.prefix + [cleanup], timeout=20)
                attempts.append({"attempt": attempt, "status": "removed"})
                results[stage.role] = {
                    "stage": stage.path,
                    "files": sorted(stage.files),
                    "attempts": attempts,
                    "status": "removed",
                }
                break
            except Exception as exc:
                attempts.append({"attempt": attempt, "error_type": type(exc).__name__})
        else:
            results[stage.role] = {
                "stage": stage.path,
                "files": sorted(stage.files),
                "attempts": attempts,
                "status": "unconfirmed",
            }
            failures.append(stage.role)
    return failures


def source_hashes() -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((ROOT / "src/fleetdoctor").glob("*.py"))
    }


def validate_release_shells(archive: Path) -> dict[str, str]:
    source_shells = {
        path.relative_to(ROOT).as_posix(): path for path in sorted((ROOT / "deploy").rglob("*.sh"))
    }
    with tarfile.open(archive, "r:gz") as release:
        archived_shells = {
            member.name: member
            for member in release.getmembers()
            if member.isfile() and member.name.startswith("deploy/") and member.name.endswith(".sh")
        }
        if set(archived_shells) != set(source_shells):
            raise ValueError("release shell inventory differs from the approved deploy source")
        digests: dict[str, str] = {}
        for name, source in source_shells.items():
            source_bytes = validated_lf_shell(source)
            extracted = release.extractfile(archived_shells[name])
            if extracted is None or extracted.read() != source_bytes:
                raise ValueError(f"release shell bytes differ from approved source: {name}")
            digests[name] = hashlib.sha256(source_bytes).hexdigest()
    return digests


def remote_deploy(
    args: argparse.Namespace,
    values: dict[str, dict[str, str]],
    public: dict[str, str],
    paths: tuple[str, ...],
    archive: Path,
    local_stage: Path,
    report: dict[str, Any],
) -> None:
    settings = load_env(args.env)
    tokens: dict[str, str] = json.loads(settings["FLEETDOCTOR_NODE_TOKENS"])
    stages: list[RemoteStage] = []
    failure: BaseException | None = None
    try:
        for role, host in public.items():
            target = f"ec2-user@{host}"
            prefix = [
                "ssh",
                "-i",
                str(args.key),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=accept-new",
                target,
            ]
            command(prefix + ["sudo cloud-init status --wait"], timeout=240)
            remote_stage = command(
                prefix + ["umask 077; mktemp -d /tmp/fleetdoctor.XXXXXXXXXX"]
            ).strip()
            if not re.fullmatch(r"/tmp/fleetdoctor\.[A-Za-z0-9]{10}", remote_stage):
                raise ValueError("unexpected private staging directory")
            stage = RemoteStage(role, target, prefix, remote_stage)
            stages.append(stage)
            report.setdefault("remote_stages", {})[role] = {
                "path": remote_stage,
                "owned_files": sorted(stage.files),
            }
            command(
                [
                    "scp",
                    "-i",
                    str(args.key),
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    str(archive),
                    target + ":" + remote_stage + "/release.tgz",
                ]
            )
            remote_digest = command(
                prefix + [f"sha256sum {shlex.quote(remote_stage + '/release.tgz')} | cut -d' ' -f1"]
            ).strip()
            if remote_digest != report["release"]["archive_sha256"]:
                raise ValueError("remote release archive digest mismatch")
            command(
                prefix
                + [
                    f"sudo mkdir -p /opt/fleetdoctor/current && sudo tar -xzf {shlex.quote(remote_stage + '/release.tgz')} -C /opt/fleetdoctor/current"
                ]
            )
            if role != "monitor" and DISK_PATH in paths:
                command(
                    prefix
                    + [
                        "sudo python3.11 /opt/fleetdoctor/current/deploy/disk_resource.py prepare >/dev/null"
                    ],
                    timeout=60,
                )
        for stage in stages:
            role, target, prefix, remote_stage = (
                stage.role,
                stage.target,
                stage.prefix,
                stage.path,
            )
            if role == "monitor":
                secret = local_stage / "monitor.env"
                shutil.copyfile(args.env, secret)
                stage.files.add("monitor.env")
                report["remote_stages"][role]["owned_files"] = sorted(stage.files)
                command(
                    [
                        "scp",
                        "-i",
                        str(args.key),
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "StrictHostKeyChecking=accept-new",
                        str(secret),
                        target + ":" + remote_stage + "/monitor.env",
                    ]
                )
                command(
                    prefix
                    + [
                        f"sudo mkdir -p /opt/fleetdoctor/current && sudo tar -xzf {shlex.quote(remote_stage + '/release.tgz')} -C /opt/fleetdoctor/current && sudo install -m 0600 {shlex.quote(remote_stage + '/monitor.env')} /opt/fleetdoctor/current/.env && rm -- {shlex.quote(remote_stage + '/monitor.env')} && cd /opt/fleetdoctor/current && sudo docker compose up -d --build --wait --wait-timeout 90"
                    ],
                    timeout=600,
                )
            else:
                node_env = local_stage / f"{role}.env"
                node_env.write_text(
                    f"FLEETDOCTOR_NODE_ID={role}\nFLEETDOCTOR_COLLECTOR_URL=http://{values['monitor']['private_ip']}:8000\nFLEETDOCTOR_FILESYSTEMS={','.join(paths)}\n",
                    encoding="utf-8",
                    newline="\n",
                )
                credential = local_stage / f"{role}.token"
                credential.write_text(tokens[role], encoding="utf-8")
                stage.files.update({"agent.env", "token"})
                report["remote_stages"][role]["owned_files"] = sorted(stage.files)
                for file, name in ((node_env, "agent.env"), (credential, "token")):
                    command(
                        [
                            "scp",
                            "-i",
                            str(args.key),
                            "-o",
                            "BatchMode=yes",
                            "-o",
                            "StrictHostKeyChecking=accept-new",
                            str(file),
                            target + ":" + remote_stage + "/" + name,
                        ]
                    )
                command(
                    prefix
                    + [
                        f"sudo mkdir -p /opt/fleetdoctor/current && sudo tar -xzf {shlex.quote(remote_stage + '/release.tgz')} -C /opt/fleetdoctor/current && "
                        + (
                            "sudo python3.11 /opt/fleetdoctor/current/deploy/disk_resource.py prepare >/dev/null && "
                            if DISK_PATH in paths
                            else ""
                        )
                        + f"sudo bash /opt/fleetdoctor/current/deploy/install-agent.sh {shlex.quote(remote_stage + '/agent.env')} {shlex.quote(remote_stage + '/token')}"
                    ],
                    timeout=240,
                )
                command(
                    prefix
                    + [
                        f"sudo grep -Fx {shlex.quote('FLEETDOCTOR_FILESYSTEMS=' + ','.join(paths))} /etc/fleetdoctor/agent.env >/dev/null && systemctl is-active --quiet fleetdoctor-agent"
                    ]
                )
            report.setdefault("activation", {})[role] = "verified"
    except BaseException as exc:
        failure = exc
    finally:
        cleanup_failures = cleanup_stages(stages, report)
    if failure is not None or cleanup_failures:
        if failure is not None:
            report["deployment_error"] = {
                "type": type(failure).__name__,
                "message": "deployment failed; sensitive command output omitted",
            }
        if cleanup_failures:
            report["cleanup_error"] = {"roles": cleanup_failures}
        if failure is not None:
            raise failure
        raise RuntimeError("remote private staging cleanup was not confirmed")


def legacy_main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="fleetdoctor")
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--key", type=Path, default=Path.home() / ".ssh/fleetdoctor")
    parser.add_argument("--env", type=Path, required=True)
    args = parser.parse_args()
    values = inventory(args.inventory)
    public = addresses(args.profile, values)
    settings = load_env(args.env)
    paths = filesystem_paths(settings)
    if len(settings.get("GRAFANA_DB_PASSWORD", "")) < 32:
        raise ValueError("run scripts/upgrade_env.py privately before deployment")
    if settings.get("COLLECTOR_BIND_IP") != values["monitor"]["private_ip"]:
        raise ValueError("env COLLECTOR_BIND_IP must equal monitor private IP")
    tokens: dict[str, str] = json.loads(settings["FLEETDOCTOR_NODE_TOKENS"])
    if set(tokens) != {"node-a", "node-b"}:
        raise ValueError("configure exactly two node tokens")
    with tempfile.TemporaryDirectory(prefix="fleetdoctor-release-") as temp:
        stage = Path(temp)
        command(["uv", "build", "--wheel", "--out-dir", str(stage)])
        wheel = next(stage.glob("*.whl"))
        command(
            [
                "uv",
                "export",
                "--locked",
                "--no-dev",
                "--no-emit-project",
                "--format",
                "requirements-txt",
                "--output-file",
                str(stage / "requirements.txt"),
            ]
        )
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        (stage / "wheel.sha256").write_text(
            f"{digest}  {wheel.name}\n", encoding="utf-8", newline="\n"
        )
        archive = stage / "release.tgz"
        with tarfile.open(archive, "w:gz") as tar:
            for name in (
                "src",
                "deploy",
                "monitoring",
                "pyproject.toml",
                "uv.lock",
                "compose.yaml",
                "Dockerfile",
                ".dockerignore",
            ):
                tar.add(
                    ROOT / name,
                    arcname=name,
                    filter=lambda info: None if "__pycache__" in info.name else info,
                )
            for name in (wheel.name, "wheel.sha256", "requirements.txt"):
                tar.add(stage / name, arcname=name)
        prepared: dict[str, tuple[str, list[str], str]] = {}
        for role, host in public.items():
            target = f"ec2-user@{host}"
            prefix = [
                "ssh",
                "-i",
                str(args.key),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                target,
            ]
            command(prefix + ["sudo cloud-init status --wait"], timeout=240)
            remote_stage = command(
                prefix + ["umask 077; mktemp -d /tmp/fleetdoctor.XXXXXXXXXX"]
            ).strip()
            if not re.fullmatch(r"/tmp/fleetdoctor\.[A-Za-z0-9]{10}", remote_stage):
                raise ValueError("unexpected private staging directory")
            command(
                [
                    "scp",
                    "-i",
                    str(args.key),
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    str(archive),
                    target + ":" + remote_stage + "/release.tgz",
                ]
            )
            prepared[role] = target, prefix, remote_stage
            command(
                prefix
                + [
                    f"sudo mkdir -p /opt/fleetdoctor/current && sudo tar -xzf {remote_stage}/release.tgz -C /opt/fleetdoctor/current"
                ]
            )
            if role != "monitor" and DISK_PATH in paths:
                command(
                    prefix
                    + [
                        "sudo python3.11 /opt/fleetdoctor/current/deploy/disk_resource.py prepare >/dev/null"
                    ],
                    timeout=60,
                )
        for role, (target, prefix, remote_stage) in prepared.items():
            if role == "monitor":
                secret = stage / "monitor.env"
                shutil.copyfile(args.env, secret)
                command(
                    [
                        "scp",
                        "-i",
                        str(args.key),
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "StrictHostKeyChecking=accept-new",
                        str(secret),
                        target + ":" + remote_stage + "/monitor.env",
                    ]
                )
                command(
                    prefix
                    + [
                        f"sudo mkdir -p /opt/fleetdoctor/current && sudo tar -xzf {remote_stage}/release.tgz -C /opt/fleetdoctor/current && sudo install -m 0600 {remote_stage}/monitor.env /opt/fleetdoctor/current/.env && rm {remote_stage}/monitor.env && cd /opt/fleetdoctor/current && sudo docker compose up -d --build --wait --wait-timeout 90"
                    ],
                    timeout=600,
                )
            else:
                node_env = stage / f"{role}.env"
                node_env.write_text(
                    f"FLEETDOCTOR_NODE_ID={role}\nFLEETDOCTOR_COLLECTOR_URL=http://{values['monitor']['private_ip']}:8000\nFLEETDOCTOR_FILESYSTEMS={','.join(paths)}\n",
                    encoding="utf-8",
                    newline="\n",
                )
                credential = stage / f"{role}.token"
                credential.write_text(tokens[role], encoding="utf-8")
                for file, dest in (
                    (node_env, remote_stage + "/agent.env"),
                    (credential, remote_stage + "/token"),
                ):
                    command(
                        [
                            "scp",
                            "-i",
                            str(args.key),
                            "-o",
                            "BatchMode=yes",
                            "-o",
                            "StrictHostKeyChecking=accept-new",
                            str(file),
                            target + ":" + dest,
                        ]
                    )
                command(
                    prefix
                    + [
                        f"sudo mkdir -p /opt/fleetdoctor/current && sudo tar -xzf {remote_stage}/release.tgz -C /opt/fleetdoctor/current && "
                        + (
                            "sudo python3.11 /opt/fleetdoctor/current/deploy/disk_resource.py prepare >/dev/null && "
                            if DISK_PATH in paths
                            else ""
                        )
                        + f"sudo bash /opt/fleetdoctor/current/deploy/install-agent.sh {remote_stage}/agent.env {remote_stage}/token"
                    ],
                    timeout=240,
                )
                command(
                    prefix
                    + [
                        f"sudo grep -Fx {shlex.quote('FLEETDOCTOR_FILESYSTEMS=' + ','.join(paths))} /etc/fleetdoctor/agent.env >/dev/null && systemctl is-active --quiet fleetdoctor-agent"
                    ]
                )
            command(prefix + [f"rm {remote_stage}/release.tgz && rmdir {remote_stage}"])
            print(f"Deployed {role} (secrets redacted).")
        print("Deployment finished. Run the healthy demonstration via SSH tunnels.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="fleetdoctor")
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--key", type=Path, default=Path.home() / ".ssh/fleetdoctor")
    parser.add_argument("--env", type=Path, required=True)
    parser.add_argument("--source-freeze", type=Path)
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    task04 = args.source_freeze is not None or args.approved_plan_sha256 is not None
    if (args.source_freeze is None) != (args.approved_plan_sha256 is None):
        parser.error("--source-freeze and --approved-plan-sha256 must be supplied together")
    if task04 and args.output is None:
        parser.error("Task04 deployment requires --output")
    if args.output is not None and args.output.exists():
        raise ValueError("use a new deployment report path; failed reports are retained")
    report: dict[str, Any] = {
        "schema_version": 1,
        "operation": "fleetdoctor_deploy",
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "task04_source_gate": task04,
        "remote_stage_cleanup": {},
    }
    try:
        if task04:
            assert args.source_freeze is not None and args.approved_plan_sha256 is not None
            freeze = validate_source_freeze(args.source_freeze, args.approved_plan_sha256)
            report["source_validation_initial"] = {
                "status": "matched",
                "aggregate_sha256": freeze["sha256"],
                "plan_sha256": freeze["plan_sha256"],
                "files": len(freeze["files"]),
            }
        values = inventory(args.inventory)
        if task04:
            validate_live_scope(args.profile, values)
        public = addresses(args.profile, values)
        settings = load_env(args.env)
        paths = filesystem_paths(settings)
        if len(settings.get("GRAFANA_DB_PASSWORD", "")) < 32:
            raise ValueError("run scripts/upgrade_env.py privately before deployment")
        if settings.get("COLLECTOR_BIND_IP") != values["monitor"]["private_ip"]:
            raise ValueError("env COLLECTOR_BIND_IP must equal monitor private IP")
        tokens: dict[str, str] = json.loads(settings["FLEETDOCTOR_NODE_TOKENS"])
        if set(tokens) != {"node-a", "node-b"}:
            raise ValueError("configure exactly two node tokens")
        with tempfile.TemporaryDirectory(prefix="fleetdoctor-release-") as temp:
            stage = Path(temp)
            command(["uv", "build", "--wheel", "--out-dir", str(stage)])
            wheel = next(stage.glob("*.whl"))
            command(
                [
                    "uv",
                    "export",
                    "--locked",
                    "--no-dev",
                    "--no-emit-project",
                    "--format",
                    "requirements-txt",
                    "--output-file",
                    str(stage / "requirements.txt"),
                ]
            )
            wheel_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            (stage / "wheel.sha256").write_text(
                f"{wheel_digest}  {wheel.name}\n", encoding="utf-8", newline="\n"
            )
            archive = stage / "release.tgz"
            with tarfile.open(archive, "w:gz") as tar:
                for name in (
                    "src",
                    "deploy",
                    "monitoring",
                    "pyproject.toml",
                    "uv.lock",
                    "compose.yaml",
                    "Dockerfile",
                    ".dockerignore",
                ):
                    tar.add(
                        ROOT / name,
                        arcname=name,
                        filter=lambda info: None if "__pycache__" in info.name else info,
                    )
                for name in (wheel.name, "wheel.sha256", "requirements.txt"):
                    tar.add(stage / name, arcname=name)
            report["release"] = {
                "wheel": wheel.name,
                "wheel_sha256": wheel_digest,
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "source_sha256": source_hashes(),
            }
            report["release"]["shell_sha256"] = validate_release_shells(archive)
            if task04:
                freeze = validate_source_freeze(args.source_freeze, args.approved_plan_sha256)
                report["source_validation_pre_stage"] = {
                    "status": "matched",
                    "aggregate_sha256": freeze["sha256"],
                }
            remote_deploy(args, values, public, paths, archive, stage, report)
            from healthy_demo import installed_source_probe

            expected = source_hashes()
            for role, host in public.items():
                ssh = [
                    "ssh",
                    "-i",
                    str(args.key),
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=5",
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    f"ec2-user@{host}",
                ]
                installed = installed_source_probe(ssh, role)
                if installed["source_sha256"] != expected:
                    raise ValueError(f"{role} imported package differs from approved source")
                report.setdefault("installed_source", {})[role] = installed
        if task04:
            freeze = validate_source_freeze(args.source_freeze, args.approved_plan_sha256)
            report["source_validation_final"] = {
                "status": "matched",
                "aggregate_sha256": freeze["sha256"],
            }
        report["status"] = "passed"
    except BaseException as exc:
        report["status"] = "failed"
        report.setdefault(
            "deployment_error",
            {
                "type": type(exc).__name__,
                "message": "deployment failed; sensitive command output omitted",
            },
        )
        raise
    finally:
        report["finished_at"] = datetime.now(UTC).isoformat()
        if args.output is not None:
            write_report(args.output, report)
    print("Deployment finished; secrets redacted.")


if __name__ == "__main__":
    main()
