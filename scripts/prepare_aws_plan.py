"""Prepare reviewable Terraform inputs and saved plan without creating cloud resources."""

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Any

import httpx
from lab import command


def check_instance_deletions(
    plan: dict[str, Any], *, allow_instance_deletion: bool = False
) -> list[str]:
    targets = [
        change["address"]
        for change in plan.get("resource_changes", [])
        if change.get("mode", "managed") == "managed"
        and change.get("type") == "aws_instance"
        and "delete" in change["change"]["actions"]
    ]
    if targets and not allow_instance_deletion:
        raise ValueError("instance deletion/replacement rejected: " + ", ".join(targets))
    return targets


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--profile", default="fleetdoctor")
    parser.add_argument("--public-key", type=Path, default=Path.home() / ".ssh/fleetdoctor.pub")
    parser.add_argument("--owner-ip")
    parser.add_argument(
        "--allow-instance-deletion",
        action="store_true",
        help="explicitly permit planning instance deletion/replacement; does not authorize apply",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    if args.owner_ip:
        address = ipaddress.IPv4Address(args.owner_ip)
    else:
        response = httpx.get("https://checkip.amazonaws.com", timeout=5, trust_env=False)
        response.raise_for_status()
        address = ipaddress.IPv4Address(response.text.strip())
    public_key = args.public_key.read_text(encoding="utf-8").strip()
    inputs = args.output_dir / "lab.tfvars.json"
    inputs.write_text(
        json.dumps(
            {
                "aws_profile": args.profile,
                "owner_cidr": f"{address}/32",
                "ssh_public_key": public_key,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    plan = args.output_dir / "lab.tfplan"
    result = command(
        [
            "terraform",
            "-chdir=infra/aws",
            "plan",
            "-input=false",
            "-no-color",
            "-var-file=" + str(inputs.resolve()),
            "-out=" + str(plan.resolve()),
        ]
    )
    (args.output_dir / "terraform-plan.txt").write_text(result, encoding="utf-8")
    plan_json = command(["terraform", "-chdir=infra/aws", "show", "-json", str(plan.resolve())])
    (args.output_dir / "terraform-plan.json").write_text(plan_json, encoding="utf-8")
    try:
        deletions = check_instance_deletions(
            json.loads(plan_json), allow_instance_deletion=args.allow_instance_deletion
        )
    except ValueError:
        # Retain rejected diagnostics while removing the normal apply path.
        plan.rename(args.output_dir / "rejected.tfplan")
        raise
    if deletions:
        print("Explicitly opted-in instance deletion/replacement: " + ", ".join(deletions))
    print(f"Review plan text and JSON in: {args.output_dir}")
    print(f"Saved concrete AWS plan: {plan}; no cloud resources created.")


if __name__ == "__main__":
    main()
