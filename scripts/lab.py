"""Operate only Terraform's exact lab instance IDs; refresh ephemeral IPs every time."""

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def command(argv: list[str], *, timeout: int = 180, data: str | None = None) -> str:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        input=data,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout


def inventory(path: Path | None) -> dict[str, dict[str, str]]:
    raw = (
        path.read_text(encoding="utf-8-sig")
        if path
        else command(["terraform", "-chdir=infra/aws", "output", "-json", "instances"])
    )
    values: dict[str, dict[str, str]] = json.loads(raw)
    if set(values) != {"monitor", "node-a", "node-b"}:
        raise ValueError("expected exactly this lab's three roles")
    if any(not item["id"].startswith("i-") for item in values.values()):
        raise ValueError("invalid instance ID")
    return values


def current_addresses(response: dict[str, Any], expected: set[str]) -> dict[str, str]:
    found = {
        instance["InstanceId"]: instance.get("PublicIpAddress", "")
        for group in response["Reservations"]
        for instance in group["Instances"]
    }
    if set(found) != expected or any(not address for address in found.values()):
        raise ValueError("all lab instances must have current public addresses")
    return found


def aws(profile: str, *args: str, timeout: int = 180) -> str:
    return command(["aws", "--profile", profile, "--region", "us-east-1", *args], timeout=timeout)


def addresses(profile: str, values: dict[str, dict[str, str]]) -> dict[str, str]:
    ids = {item["id"] for item in values.values()}
    result = json.loads(
        aws(
            profile, "ec2", "describe-instances", "--instance-ids", *sorted(ids), "--output", "json"
        )
    )
    by_id = current_addresses(result, ids)
    return {role: by_id[item["id"]] for role, item in values.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("show", "start", "stop", "export"))
    parser.add_argument("--profile", default="fleetdoctor")
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--key", type=Path, default=Path.home() / ".ssh/fleetdoctor")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    values = inventory(args.inventory)
    ids = sorted(item["id"] for item in values.values())
    if args.action == "stop":
        aws(args.profile, "ec2", "stop-instances", "--instance-ids", *ids)
        aws(args.profile, "ec2", "wait", "instance-stopped", "--instance-ids", *ids, timeout=600)
        print("Stopped exact lab instances; EBS storage still bills.")
        return
    if args.action == "start":
        aws(args.profile, "ec2", "start-instances", "--instance-ids", *ids)
        aws(args.profile, "ec2", "wait", "instance-status-ok", "--instance-ids", *ids, timeout=600)
    public = addresses(args.profile, values)
    if args.action == "export":
        if args.output is None:
            parser.error("export requires --output <new local directory>")
        args.output.mkdir(parents=True, exist_ok=False)
        target = f"ec2-user@{public['monitor']}"
        ssh = ["ssh", "-i", str(args.key), "-o", "StrictHostKeyChecking=accept-new", target]
        # SQL and volume archives may contain private data; export to local storage only.
        dump = subprocess.run(
            ssh
            + [
                "cd /opt/fleetdoctor/current && sudo docker compose exec -T postgres pg_dump -U fleetdoctor fleetdoctor"
            ],
            capture_output=True,
            timeout=90,
        )
        if dump.returncode:
            raise RuntimeError("PostgreSQL export failed")
        (args.output / "postgres.sql").write_bytes(dump.stdout)
        export_cmd = "cd /opt/fleetdoctor/current && sudo bash deploy/export-monitor.sh"
        command(ssh + [export_cmd], timeout=180)
        command(
            [
                "scp",
                "-i",
                str(args.key),
                "-o",
                "StrictHostKeyChecking=accept-new",
                target + ":/tmp/fleetdoctor-stores.tgz",
                str(args.output / "stores.tgz"),
            ]
        )
        # Keep the remote private-data copy only until the local download succeeds.
        command(ssh + ["rm -f /tmp/fleetdoctor-stores.tgz"])
        (args.output / "instances.json").write_text(json.dumps(values, indent=2), encoding="utf-8")
        print(f"Exported local backups to {args.output}; contains private data.")
        return
    print(
        json.dumps(
            {role: item | {"public_ip": public[role]} for role, item in values.items()}, indent=2
        )
    )
    print(
        f"ssh -i {args.key} -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 -L 8000:{values['monitor']['private_ip']}:8000 ec2-user@{public['monitor']}"
    )


if __name__ == "__main__":
    main()
