"""Deploy a hash-verified local wheel and source archive to existing lab instances."""

import argparse
import hashlib
import json
import re
import shlex
import shutil
import tarfile
import tempfile
from pathlib import Path

from lab import ROOT, addresses, command, inventory
from upgrade_env import DISK_PATH


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


def main() -> None:
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


if __name__ == "__main__":
    main()
