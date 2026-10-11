"""Capture real lab observations through tunnels; requires fresh data for both nodes."""

import argparse
import hashlib
import json
import socket
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from deploy_lab import load_env
from lab import ROOT, addresses, aws, command, inventory


def installed_source_probe(ssh: list[str], role: str) -> dict[str, Any]:
    """Inspect the package imported by the deployed interpreter, outside archive cwd."""
    program = """
import hashlib, json, pathlib, sys
import fleetdoctor
base = pathlib.Path(fleetdoctor.__file__).resolve().parent
result = {
    "python": sys.executable,
    "prefix": sys.prefix,
    "package_directory": str(base),
    "source_sha256": {
        "src/fleetdoctor/" + path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(base.glob("*.py"))
    },
}
"""
    if role == "monitor":
        remote = (
            "cd /opt/fleetdoctor/current && "
            "sudo docker compose exec -T collector /app/.venv/bin/python -"
        )
    else:
        remote = "cd / && /opt/fleetdoctor/venv/bin/python -"
        program += """
import subprocess
properties = subprocess.check_output([
    "systemctl", "show", "fleetdoctor-agent", "-p", "MainPID",
    "-p", "ExecMainStartTimestamp", "-p", "ExecStart",
], text=True)
service = dict(line.split("=", 1) for line in properties.splitlines())
pid = int(service["MainPID"])
assert pid > 0 and service["ExecMainStartTimestamp"]
cmdline = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().decode().strip("\\0").split("\\0")
assert "/opt/fleetdoctor/venv/bin/fleetdoctor-agent" in cmdline
assert sys.prefix == "/opt/fleetdoctor/venv"
assert base.is_relative_to(pathlib.Path(sys.prefix))
assert subprocess.check_output([
    "systemctl", "show", "fleetdoctor-agent", "-p", "MainPID", "--value"
], text=True).strip() == str(pid)
result["service"] = service
result["process_cmdline"] = cmdline
"""
    program += "\nprint(json.dumps(result))\n"
    result: dict[str, Any] = json.loads(command(ssh + [remote], data=program))
    return result


def delivery_report(samples: list[dict[str, Any]]) -> dict[str, Any]:
    """Require consecutive delivery across at least three raw five-second intervals."""
    if not samples:
        raise ValueError("no observations")
    unique: list[dict[str, Any]] = []
    for sample in samples:
        if any(
            sample[key] != samples[0][key] for key in ("agent_session_id", "boot_id", "node_id")
        ):
            raise ValueError("agent identity changed during delivery window")
        if unique and sample["sequence"] == unique[-1]["sequence"]:
            if sample != unique[-1]:
                raise ValueError("same sequence changed contents")
            continue
        if unique and sample["sequence"] != unique[-1]["sequence"] + 1:
            raise ValueError("nonconsecutive accepted sequences")
        unique.append(sample)
    if len(unique) < 4:
        raise ValueError("need at least four consecutive samples")
    intervals = [
        (
            datetime.fromisoformat(b["observed_at"]) - datetime.fromisoformat(a["observed_at"])
        ).total_seconds()
        for a, b in zip(unique, unique[1:], strict=False)
    ]
    if not all(4.5 <= interval <= 5.5 for interval in intervals):
        raise ValueError("raw observation interval outside five-second cadence")
    return {
        "agent_session_id": unique[0]["agent_session_id"],
        "sequences": [sample["sequence"] for sample in unique],
        "raw_intervals_seconds": intervals,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env", type=Path, required=True)
    parser.add_argument("--profile", default="fleetdoctor")
    parser.add_argument("--key", type=Path, default=Path.home() / ".ssh/fleetdoctor")
    parser.add_argument("--inventory", type=Path)
    args = parser.parse_args()
    values = inventory(args.inventory)
    public = addresses(args.profile, values)
    settings = load_env(args.env)
    evidence: dict[str, Any] = {
        "environment": "AWS EC2 us-east-1",
        "started_at": datetime.now(UTC).isoformat(),
        "aws_execution": True,
        "revision": command(["git", "rev-parse", "HEAD"]).strip(),
        "uncommitted_changes": command(["git", "status", "--porcelain"]).splitlines(),
        "hosts": {},
        "observations": [],
        "cost_status": "actual_billing_pending_export; estimate_in_docs_costs",
        "source_sha256": {
            path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((ROOT / "src/fleetdoctor").glob("*.py"))
        },
    }
    try:
        ids = sorted(item["id"] for item in values.values())
        evidence["instances"] = json.loads(
            aws(args.profile, "ec2", "describe-instances", "--instance-ids", *ids)
        )
        evidence["cpu_credits"] = json.loads(
            aws(
                args.profile,
                "ec2",
                "describe-instance-credit-specifications",
                "--instance-ids",
                *ids,
            )
        )
        for role, host in public.items():
            ssh = [
                "ssh",
                "-i",
                str(args.key),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                f"ec2-user@{host}",
            ]
            probe = "set -e; uname -a; cat /proc/sys/kernel/random/boot_id; test -f /sys/fs/cgroup/cgroup.controllers; timedatectl show -p NTPSynchronized; test $(timedatectl show -p NTPSynchronized --value) = yes"
            if role == "monitor":
                probe += "; sudo docker compose version"
            else:
                probe += "; systemctl is-active fleetdoctor-agent; systemctl show fleetdoctor-agent -p MainPID"
            evidence["hosts"][role] = command(ssh + [probe])
            source_check = command(
                ssh
                + [
                    "cd /opt/fleetdoctor/current && sha256sum src/fleetdoctor/*.py && sha256sum --check --strict wheel.sha256"
                ]
            )
            actual = {
                line.split()[1]: line.split()[0]
                for line in source_check.splitlines()
                if line.startswith(tuple("0123456789abcdef")) and len(line.split()[0]) == 64
            }
            assert actual == evidence["source_sha256"], f"{role} source differs from local tree"
            evidence.setdefault("remote_source_checks", {})[role] = source_check
            installed = installed_source_probe(ssh, role)
            assert installed["source_sha256"] == evidence["source_sha256"], (
                f"{role} imported installed package differs from local tree"
            )
            evidence.setdefault("installed_source_checks", {})[role] = installed
        # Five-second probes can meet Uvicorn's idle connection expiry through SSH.
        # Give each evidence request its own connection instead of reusing an idle socket.
        with httpx.Client(
            timeout=4, trust_env=False, limits=httpx.Limits(max_keepalive_connections=0)
        ) as client:
            datasource = client.get(
                "http://127.0.0.1:3000/api/datasources/uid/prometheus/health",
                auth=("admin", settings["GRAFANA_PASSWORD"]),
            )
            datasource.raise_for_status()
            assert datasource.json()["status"] == "OK"
            grafana_query = client.get(
                "http://127.0.0.1:3000/api/datasources/proxy/uid/prometheus/api/v1/query",
                params={"query": "fleetdoctor_filesystem_available_bytes"},
                auth=("admin", settings["GRAFANA_PASSWORD"]),
            )
            grafana_query.raise_for_status()
            assert {item["metric"]["node"] for item in grafana_query.json()["data"]["result"]} == {
                "node-a",
                "node-b",
            }
            evidence["grafana_datasource"] = datasource.json()
            evidence["grafana_live_query"] = grafana_query.json()
            window_start = datetime.now(UTC)
            deadline = time.monotonic() + 22
            while time.monotonic() < deadline:
                response = client.get("http://127.0.0.1:8000/nodes")
                response.raise_for_status()
                nodes = response.json()["nodes"]
                assert {node["node_id"] for node in nodes} == {"node-a", "node-b"}
                assert all(
                    node["fresh"]
                    and not node["stale"]
                    and node["filesystems"]
                    and node["filesystems"][0]["total_bytes"] is not None
                    for node in nodes
                )
                evidence["observations"].append(nodes)
                time.sleep(1)
            window_end = datetime.now(UTC)
            evidence["delivery_window"] = {
                "start": window_start.isoformat(),
                "end": window_end.isoformat(),
                "poll_interval_seconds": 1,
            }
            for node in ("node-a", "node-b"):
                samples = [
                    next(item for item in batch if item["node_id"] == node)["sample"]
                    for batch in evidence["observations"]
                ]
                evidence.setdefault("delivery", {})[node] = delivery_report(samples)
                ssh = [
                    "ssh",
                    "-i",
                    str(args.key),
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    f"ec2-user@{public[node]}",
                ]
                journal = command(
                    ssh
                    + [
                        "sudo journalctl -u fleetdoctor-agent --no-pager -o cat "
                        f"--since '{window_start.strftime('%Y-%m-%d %H:%M:%S UTC')}' "
                        f"--until '{(window_end + timedelta(seconds=1)).strftime('%Y-%m-%d %H:%M:%S UTC')}'"
                    ]
                )
                failures = [line for line in journal.splitlines() if "upload failed" in line]
                evidence.setdefault("agent_upload_failures", {})[node] = failures
                assert not failures, f"{node} upload failures during delivery window"
                # Anchor history in an already observed sample, safely in the past.
                # A workstation clock slightly ahead of EC2 must not request future data.
                end = datetime.fromisoformat(samples[-1]["observed_at"]) - timedelta(seconds=5)
                history = client.get(
                    f"http://127.0.0.1:8000/nodes/{node}/metrics",
                    params={
                        "start": (end - timedelta(minutes=2)).isoformat(),
                        "end": end.isoformat(),
                        "step": 5,
                    },
                )
                history.raise_for_status()
                assert any(
                    len(series["values"]) >= 2 for series in history.json()["history"]["result"]
                )
                evidence.setdefault("history", {})[node] = history.json()
            for name in ("fleet", "node"):
                dashboard = client.get(
                    f"http://127.0.0.1:3000/api/dashboards/uid/fleetdoctor-{name}",
                    auth=("admin", settings["GRAFANA_PASSWORD"]),
                )
                dashboard.raise_for_status()
                assert dashboard.json()["dashboard"]["refresh"] == "5s"
                node_queries = set()
                for panel in dashboard.json()["dashboard"]["panels"]:
                    unit = panel.get("fieldConfig", {}).get("defaults", {}).get("unit")
                    for target in panel.get("targets", []):
                        expression = target.get("expr", "")
                        if "_bytes" in expression:
                            assert unit == "bytes"
                        if "_ratio" in expression:
                            assert unit == "percentunit"
                        if "_stale" in expression:
                            assert unit == "short"
                        node_queries.add(expression)
                if name == "node":
                    assert {
                        'fleetdoctor_node_stale{node="$node"}',
                        'fleetdoctor_filesystem_coverage_ratio{node="$node"}',
                    } <= node_queries
                    evidence["node_dashboard_queries"] = sorted(node_queries)
            evidence["grafana"] = "both_dashboards_provisioned_units_verified"
        evidence["public_port_checks"] = {}
        for port in (8000, 9090, 3000, 5432):
            with socket.socket() as port_probe:
                port_probe.settimeout(2)
                result = port_probe.connect_ex((public["monitor"], port))
                assert result != 0, f"public monitor port {port} must be closed"
                evidence["public_port_checks"][str(port)] = "connection_refused_or_filtered"
        evidence["status"] = "passed"
    except BaseException as exc:
        evidence["status"] = "failed"
        evidence["failure"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        evidence["finished_at"] = datetime.now(UTC).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"Real AWS healthy demonstration passed: {args.output}")


if __name__ == "__main__":
    main()
