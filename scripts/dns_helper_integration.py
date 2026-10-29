#!/usr/bin/env python3
"""Aggregate the complete disposable native DNS gate with exact owned cleanup."""

from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from chaos_harness import source_manifest, write_report

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def absent(argv: list[str], expected: tuple[str, ...]) -> dict[str, Any]:
    result = run(argv, timeout=30)
    diagnostic = (result.stderr or "") + "\n" + (result.stdout or "")
    status = (
        "present"
        if result.returncode == 0
        else "absent"
        if any(item in diagnostic for item in expected)
        else "unknown"
    )
    return {"status": status, "returncode": result.returncode, "diagnostic": diagnostic[-1000:]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    nested = {
        "helper_cases": args.output.with_name(args.output.stem + "-helper-cases.json"),
        "agent": args.output.with_name(args.output.stem + "-agent.json"),
        "resolved": args.output.with_name(args.output.stem + "-resolved.json"),
        "adapter": args.output.with_name(args.output.stem + "-adapter.json"),
        "history_resource": args.output.with_name(args.output.stem + "-history-resource.json"),
    }
    conflicts = [path for path in (args.output, *nested.values()) if path.exists()]
    if conflicts:
        raise FileExistsError(f"DNS native output already exists: {conflicts}")
    token = uuid4().hex[:12]
    image = f"fleetdoctor-dns-native-{token}"
    resolved_image = f"fleetdoctor-dns-resolved-{token}"
    names = {
        "resolved": f"fleetdoctor-dns-resolved-run-{token}",
        "server": f"fleetdoctor-dns-server-{token}",
        "adapter": f"fleetdoctor-dns-adapter-{token}",
        "helper_cases": f"fleetdoctor-dns-helper-{token}",
        "history_resource": f"fleetdoctor-dns-history-{token}",
    }
    network = f"fleetdoctor-dns-{token}"
    commands: list[dict[str, Any]] = []
    cleanup_commands: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "token": token,
        "platform": platform.platform(),
        "aws_execution": False,
        "required_gates": [
            "real_direct_adapter_and_fixed_regular_bind",
            "fixed_path_helper_regular_symlink_interruption_foreign_cleanup",
            "systemd_resolved_product_cache_bypass",
            "ordinary_hardened_agent_api_harness",
            "maximum_721_history_resource_envelope",
        ],
        "source_before": source_manifest(),
        "owned": {
            "images": [image, resolved_image],
            "containers": list(names.values()),
            "network": network,
        },
        "nested_receipts": {key: str(value) for key, value in nested.items()},
        "commands": commands,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_report(args.output, evidence)

    def save(stage: str, **values: Any) -> None:
        evidence["current_stage"] = stage
        evidence.update(values)
        write_report(args.output, evidence)

    def command(
        stage: str,
        argv: list[str],
        *,
        timeout: int = 180,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        save(stage)
        started = time.monotonic()
        result = run(argv, timeout=timeout)
        receipt = {
            "stage": stage,
            "argv": argv,
            "returncode": result.returncode,
            "elapsed_seconds": time.monotonic() - started,
            "stdout_tail": result.stdout[-8000:],
            "stderr_tail": result.stderr[-8000:],
        }
        commands.append(receipt)
        save(stage, commands=commands)
        if check and result.returncode:
            raise RuntimeError(
                f"{stage} failed rc={result.returncode}: "
                f"stdout={result.stdout[-2000:]} stderr={result.stderr[-2000:]}"
            )
        return result

    try:
        command(
            "build_test_image",
            ["docker", "build", "--target", "test", "-t", image, "."],
            timeout=600,
        )
        command("create_network", ["docker", "network", "create", "--internal", network])
        network_value = json.loads(
            command(
                "inspect_network_for_unused_resolver", ["docker", "network", "inspect", network]
            ).stdout
        )[0]
        subnet = next(
            ipaddress.ip_network(item["Subnet"])
            for item in network_value["IPAM"]["Config"]
            if ":" not in item["Subnet"]
        )
        invalid_resolver = str(subnet.broadcast_address - 2)
        save(
            "select_unused_on_link_invalid_resolver",
            invalid_resolver=invalid_resolver,
            invalid_resolver_subnet=str(subnet),
        )
        command(
            "start_authority",
            [
                "docker",
                "run",
                "-d",
                "--name",
                names["server"],
                "--network",
                network,
                image,
                "/app/.venv/bin/python",
                "scripts/dns_authoritative.py",
                "--answer",
                "10.77.0.80",
            ],
        )
        authority_ip = command(
            "inspect_authority",
            [
                "docker",
                "inspect",
                "-f",
                f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}',
                names["server"],
            ],
        ).stdout.strip()
        adapter = command(
            "real_adapter_regular_bind",
            [
                "docker",
                "run",
                "--name",
                names["adapter"],
                "--init",
                "--network",
                network,
                "--dns",
                authority_ip,
                "--user",
                "root",
                "--cap-drop",
                "ALL",
                "--memory",
                "100m",
                "--pids-limit",
                "16",
                "-e",
                f"DNS_PROOF_TARGET={authority_ip}",
                "-e",
                f"DNS_INVALID_RESOLVER={invalid_resolver}",
                image,
                "/app/.venv/bin/python",
                "scripts/dns_native_probe.py",
            ],
            timeout=180,
            check=False,
        )
        try:
            adapter_value: dict[str, Any] = json.loads(adapter.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            write_report(
                nested["adapter"],
                {
                    "status": "failed",
                    "returncode": adapter.returncode,
                    "stdout": adapter.stdout[-8000:],
                    "stderr": adapter.stderr[-8000:],
                    "parse_error": f"{type(exc).__name__}:{exc}",
                },
            )
            raise RuntimeError("real adapter did not produce a valid nested receipt") from exc
        write_report(nested["adapter"], adapter_value)
        if adapter.returncode or adapter_value.get("status") != "passed":
            raise RuntimeError("real adapter nested receipt did not pass")
        save("real_adapter_regular_bind_complete", adapter=adapter_value)

        command(
            "create_helper_cases_container",
            [
                "docker",
                "create",
                "--name",
                names["helper_cases"],
                "--init",
                "--privileged",
                "--network",
                network,
                "--memory",
                "100m",
                "--pids-limit",
                "16",
                "-e",
                f"DNS_INVALID_RESOLVER={invalid_resolver}",
                image,
                "/bin/sh",
                "-c",
                "while [ ! -e /tmp/fleetdoctor-proof-start ]; do sleep 0.05; done; "
                "exec /app/.venv/bin/python scripts/dns_helper_native_cases.py",
            ],
        )
        command(
            "start_helper_cases_container_paused",
            ["docker", "start", names["helper_cases"]],
        )
        helper_inspect = json.loads(
            command(
                "inspect_helper_fixed_resolver_backing",
                ["docker", "inspect", names["helper_cases"]],
            ).stdout
        )[0]
        backing = {
            "resolv_conf_path": helper_inspect["ResolvConfPath"],
            "host_config_init": helper_inspect["HostConfig"].get("Init"),
            "privileged": helper_inspect["HostConfig"]["Privileged"],
            "memory": helper_inspect["HostConfig"]["Memory"],
            "pids_limit": helper_inspect["HostConfig"]["PidsLimit"],
            "mounts": helper_inspect["Mounts"],
        }
        if not backing["resolv_conf_path"] or backing["host_config_init"] is not True:
            raise RuntimeError("helper proof lacks Docker resolver backing or init/subreaper")
        command(
            "release_helper_cases_after_backing_inspection",
            ["docker", "exec", names["helper_cases"], "touch", "/tmp/fleetdoctor-proof-start"],
        )
        helper_exit = command(
            "fixed_path_helper_native_matrix",
            ["docker", "wait", names["helper_cases"]],
            timeout=300,
            check=False,
        )
        helper_cases = command(
            "fixed_path_helper_native_matrix_logs",
            ["docker", "logs", names["helper_cases"]],
            check=False,
        )
        try:
            helper_value: dict[str, Any] = json.loads(helper_cases.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            helper_value = {
                "status": "failed",
                "returncode": int(helper_exit.stdout.strip() or "-1"),
                "stdout": helper_cases.stdout[-8000:],
                "stderr": helper_cases.stderr[-8000:],
                "parse_error": f"{type(exc).__name__}:{exc}",
            }
        helper_value["docker_inspect_before_mutation"] = backing
        write_report(nested["helper_cases"], helper_value)
        if (
            helper_exit.returncode
            or int(helper_exit.stdout.strip() or "-1") != 0
            or helper_cases.returncode
            or helper_value.get("status") != "passed"
        ):
            raise RuntimeError("fixed-path helper nested receipt did not pass")
        save("fixed_path_helper_native_matrix_complete", helper_cases=helper_value)

        command(
            "build_resolved_image",
            ["docker", "build", "--target", "dns-resolved-test", "-t", resolved_image, "."],
            timeout=600,
        )
        resolved = command(
            "systemd_resolved_product_cache_bypass",
            [
                "docker",
                "run",
                "--name",
                names["resolved"],
                "--init",
                "--network",
                network,
                "--memory",
                "256m",
                "--pids-limit",
                "32",
                resolved_image,
            ],
            timeout=180,
            check=False,
        )
        try:
            resolved_value: dict[str, Any] = json.loads(resolved.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            resolved_value = {
                "status": "failed",
                "returncode": resolved.returncode,
                "stdout": resolved.stdout[-8000:],
                "stderr": resolved.stderr[-8000:],
                "parse_error": f"{type(exc).__name__}:{exc}",
            }
        write_report(nested["resolved"], resolved_value)
        if resolved.returncode or resolved_value.get("status") != "passed":
            raise RuntimeError("systemd-resolved nested receipt did not pass")
        save("systemd_resolved_product_cache_bypass_complete", systemd_resolved=resolved_value)

        agent = command(
            "ordinary_hardened_agent_api_harness",
            [
                sys.executable,
                str(ROOT / "scripts/dns_agent_integration.py"),
                "--output",
                str(nested["agent"]),
            ],
            timeout=900,
            check=False,
        )
        if nested["agent"].exists():
            agent_value: dict[str, Any] = json.loads(nested["agent"].read_text(encoding="utf-8"))
        else:
            agent_value = {
                "status": "failed",
                "returncode": agent.returncode,
                "stdout": agent.stdout[-8000:],
                "stderr": agent.stderr[-8000:],
                "error": "nested agent receipt missing",
            }
            write_report(nested["agent"], agent_value)
        save(
            "ordinary_hardened_agent_api_harness_complete",
            agent=agent_value,
            agent_controller_stdout=agent.stdout[-2000:],
        )
        if agent.returncode or agent_value.get("status") != "passed":
            raise RuntimeError("ordinary hardened agent nested receipt did not pass")

        history_resource = command(
            "maximum_721_history_resource_envelope",
            [
                "docker",
                "run",
                "--name",
                names["history_resource"],
                "--memory",
                "100m",
                "--pids-limit",
                "16",
                image,
                "/app/.venv/bin/python",
                "scripts/dns_history_resource_probe.py",
            ],
            timeout=180,
            check=False,
        )
        try:
            history_value: dict[str, Any] = json.loads(history_resource.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            history_value = {
                "status": "failed",
                "returncode": history_resource.returncode,
                "stdout": history_resource.stdout[-8000:],
                "stderr": history_resource.stderr[-8000:],
                "parse_error": f"{type(exc).__name__}:{exc}",
            }
        write_report(nested["history_resource"], history_value)
        save("maximum_721_history_resource_envelope_complete", history_resource=history_value)
        if history_resource.returncode or history_value.get("status") != "passed":
            raise RuntimeError("maximum-history resource nested receipt did not pass")

        versions = command(
            "installed_versions",
            [
                "docker",
                "run",
                "--rm",
                image,
                "/app/.venv/bin/python",
                "-c",
                "import dns,json,platform;print(json.dumps({'python':platform.python_version(),'dnspython':dns.__version__}))",
            ],
        )
        image_inspect = json.loads(
            command("image_digest", ["docker", "image", "inspect", image]).stdout
        )[0]
        evidence.update(
            status="passed",
            completed_at=datetime.now(UTC).isoformat(),
            installed_versions=json.loads(versions.stdout),
            image_digest=image_inspect.get("Id"),
        )
    except BaseException as exc:
        evidence.update(
            status="failed",
            failed_at=datetime.now(UTC).isoformat(),
            error=f"{type(exc).__name__}:{exc}",
        )
    finally:
        save("cleanup")
        for name in names.values():
            result = run(["docker", "rm", "-f", name], timeout=30)
            cleanup_commands.append(
                {
                    "argv": ["docker", "rm", "-f", name],
                    "returncode": result.returncode,
                    "stderr": result.stderr[-1000:],
                }
            )
        result = run(["docker", "network", "rm", network], timeout=30)
        cleanup_commands.append(
            {
                "argv": ["docker", "network", "rm", network],
                "returncode": result.returncode,
                "stderr": result.stderr[-1000:],
            }
        )
        for owned_image in (image, resolved_image):
            result = run(["docker", "image", "rm", "-f", owned_image], timeout=60)
            cleanup_commands.append(
                {
                    "argv": ["docker", "image", "rm", "-f", owned_image],
                    "returncode": result.returncode,
                    "stderr": result.stderr[-1000:],
                }
            )
        verification = {
            name: absent(
                ["docker", "container", "inspect", container],
                (f"No such container: {container}", f"No such object: {container}"),
            )
            for name, container in names.items()
        }
        verification["network"] = absent(
            ["docker", "network", "inspect", network],
            (f"network {network} not found",),
        )
        verification["image"] = absent(
            ["docker", "image", "inspect", image],
            (f"No such image: {image}", f"No such object: {image}"),
        )
        verification["resolved_image"] = absent(
            ["docker", "image", "inspect", resolved_image],
            (f"No such image: {resolved_image}", f"No such object: {resolved_image}"),
        )
        cleanup_status = (
            "passed"
            if all(value["status"] == "absent" for value in verification.values())
            else "failed"
        )
        evidence["cleanup"] = {
            "status": cleanup_status,
            "commands": cleanup_commands,
            "verification": verification,
        }
        evidence["source_after"] = source_manifest()
        evidence["source_unchanged"] = evidence["source_after"] == evidence["source_before"]
        if cleanup_status != "passed" or not evidence["source_unchanged"]:
            evidence["status"] = "failed"
        evidence["finished_at"] = datetime.now(UTC).isoformat()
        evidence.pop("current_stage", None)
        write_report(args.output, evidence)
    if evidence["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
