"""Run isolated services with two fixture producers; never claim AWS host evidence."""

import argparse
import asyncio
import json
import socket
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from chaos_harness import source_manifest
from create_env import create
from integration_cpu import prove as prove_cpu
from integration_disk import PATH as DISK_PATH
from integration_disk import prove
from integration_fd import prove as prove_fd
from integration_inode import prove as prove_inode
from integration_oom import CGROUP as OOM_CGROUP
from integration_oom import MISSING_CGROUP as OOM_MISSING_CGROUP
from integration_oom import prove as prove_oom
from integration_outage import prove_outage

from fleetdoctor.agent import make_sample
from fleetdoctor.collection import from_statvfs

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    project = "fd08-" + uuid4().hex[:10]
    ports = (free_port(), free_port(), free_port())
    started = datetime.now(UTC)
    evidence: dict[str, Any] = {
        "environment": "isolated-docker-synthetic-two-node",
        "project": project,
        "started_at": started.isoformat(),
        "aws_execution": False,
        "revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
    }
    evidence["source_before"] = source_manifest()
    stop = threading.Event()
    pause = threading.Event()
    producer_errors: list[str] = []
    thread: threading.Thread | None = None
    with tempfile.TemporaryDirectory(prefix="fleetdoctor-integration-") as temp:
        env_file = Path(temp) / "test.env"
        values = create(
            env_file,
            ports=ports,
            disk=True,
            cgroups=(OOM_CGROUP, OOM_MISSING_CGROUP),
        )
        tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
        base = [
            "docker",
            "compose",
            "--project-name",
            project,
            "--env-file",
            str(env_file),
            "-f",
            str(ROOT / "compose.yaml"),
        ]

        def compose(*command: str) -> str:
            result = subprocess.run(
                base + list(command),
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=240,
            )
            if result.returncode:
                raise RuntimeError(f"Compose {' '.join(command)} failed: {result.stderr[-3000:]}")
            return result.stdout

        def poll(
            url: str, auth: tuple[str, str] | None = None, deadline: float = 60
        ) -> dict[str, Any]:
            limit = time.monotonic() + deadline
            while time.monotonic() < limit:
                try:
                    response = httpx.get(url, auth=auth, timeout=2, trust_env=False)
                    if response.is_success:
                        result: dict[str, Any] = response.json()
                        return result
                except (httpx.HTTPError, ValueError):
                    pass
                time.sleep(1)
            raise TimeoutError("service readiness deadline")

        api, prom, grafana = (f"http://127.0.0.1:{port}" for port in ports)
        try:
            migration_id = str(uuid4())
            migration_time = datetime.now(UTC).isoformat()
            migration_record = {
                "id": migration_id,
                "node_id": "migration-fixture",
                "resource": "/",
                "rule": "disk_block_exhaustion",
                "status": "resolved",
                "severity": "critical",
                "diagnosis": "pre-Task04 migration fixture",
                "configuration": {
                    "trigger_percent": 95,
                    "recovery_percent": 90,
                    "consecutive_samples": 3,
                    "max_gap_seconds": 10,
                    "severity": "critical",
                },
                "opening_evidence": {"block_available": True},
                "latest_evidence": {"block_available": True},
                "opened_at": migration_time,
                "observed_at": migration_time,
                "evaluated_at": migration_time,
                "updated_at": migration_time,
                "resolved_at": migration_time,
                "investigation_steps": ["migration fixture"],
            }
            record_json = json.dumps(migration_record, separators=(",", ":")).replace("'", "''")
            compose("up", "-d", "--wait", "--wait-timeout", "90", "postgres")
            compose(
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "fleetdoctor",
                "-d",
                "fleetdoctor",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "CREATE TABLE incidents (id uuid PRIMARY KEY,node_id text NOT NULL,resource text NOT NULL,rule text NOT NULL,status text NOT NULL CHECK (status IN ('active','resolved')),severity text NOT NULL,opened_at timestamptz NOT NULL,observed_at timestamptz NOT NULL,updated_at timestamptz NOT NULL,resolved_at timestamptz,record jsonb NOT NULL);"
                + f"INSERT INTO incidents VALUES ('{migration_id}','migration-fixture','/','disk_block_exhaustion','resolved','critical','{migration_time}','{migration_time}','{migration_time}','{migration_time}','{record_json}'::jsonb);",
            )
            compose("up", "-d", "--build", "--wait", "--wait-timeout", "90")
            poll(api + "/health")
            migration = compose(
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "fleetdoctor",
                "-d",
                "fleetdoctor",
                "-Atc",
                f"SELECT id::text FROM incidents WHERE id='{migration_id}' AND to_regclass('public.ingestion_checkpoints') IS NOT NULL;",
            ).strip()
            assert migration == migration_id
            evidence["pre_task04_schema_migration"] = {
                "incident_id_preserved": migration_id,
                "checkpoint_table_created": True,
            }
            stat: dict[str, int] = json.loads((ROOT / "tests/fixtures/statvfs.json").read_text())[
                "reserved"
            ]

            def produce() -> None:
                sessions = {node: uuid4() for node in tokens}
                boots = {node: uuid4() for node in tokens}
                sequence = 0
                with httpx.Client(
                    timeout=2, trust_env=False, limits=httpx.Limits(max_keepalive_connections=0)
                ) as client:
                    while not stop.is_set():
                        if pause.is_set():
                            stop.wait(0.1)
                            continue
                        for index, node in enumerate(tokens):
                            counters = stat | {"f_bavail": stat["f_bavail"] - index * 50}
                            value = make_sample(
                                node,
                                boots[node],
                                sessions[node],
                                sequence,
                                [from_statvfs("/", counters), from_statvfs(DISK_PATH, counters)],
                            )
                            try:
                                response = client.post(
                                    api + "/ingest",
                                    content=value.model_dump_json(),
                                    headers={"Authorization": "Bearer " + tokens[node]},
                                )
                                response.raise_for_status()
                            except httpx.HTTPError as exc:
                                producer_errors.append(type(exc).__name__)
                        sequence += 1
                        stop.wait(5)

            thread = threading.Thread(target=produce, daemon=True)
            thread.start()
            time.sleep(1)
            nodes = poll(api + "/nodes")["nodes"]
            assert len(nodes) == 2 and all(node["fresh"] and not node["stale"] for node in nodes)
            assert (
                nodes[0]["filesystems"][0]["available_bytes"]
                != nodes[1]["filesystems"][0]["available_bytes"]
            )
            evidence["nodes"] = nodes
            history_deadline = time.monotonic() + 40
            while True:
                end = datetime.now(UTC)
                params: dict[str, str | int] = {
                    "start": started.isoformat(),
                    "end": end.isoformat(),
                    "step": 5,
                }
                histories = {
                    node: httpx.get(
                        api + f"/nodes/{node}/metrics", params=params, timeout=4, trust_env=False
                    ).json()
                    for node in tokens
                }
                if all(
                    any(
                        len(series["values"]) >= 2
                        for series in value.get("history", {}).get("result", [])
                    )
                    for value in histories.values()
                ):
                    break
                if time.monotonic() > history_deadline:
                    raise TimeoutError("two-node Prometheus history not present")
                time.sleep(2)
            evidence["history"] = histories
            evidence["prometheus"] = poll(prom + "/api/v1/query?query=fleetdoctor_collector_up")
            dashboards = {
                name: poll(
                    grafana + f"/api/dashboards/uid/fleetdoctor-{name}",
                    ("admin", values["GRAFANA_PASSWORD"]),
                )
                for name in ("fleet", "node")
            }
            for dashboard in dashboards.values():
                assert dashboard["dashboard"]["refresh"] == "5s"
                for panel in dashboard["dashboard"]["panels"]:
                    if panel["datasource"]["uid"] != "prometheus":
                        continue
                    expr = panel["targets"][0]["expr"]
                    unit = panel["fieldConfig"]["defaults"]["unit"]
                    assert unit == (
                        "bytes"
                        if "bytes" in expr
                        else "percentunit"
                        if "ratio" in expr
                        else "s"
                        if "seconds" in expr
                        else "short"
                    )
            evidence["dashboard_uids"] = [
                value["dashboard"]["uid"] for value in dashboards.values()
            ]
            node_queries = {
                target["expr"]
                for panel in dashboards["node"]["dashboard"]["panels"]
                for target in panel["targets"]
                if "expr" in target
            }
            assert {
                'fleetdoctor_node_stale{node="$node"}',
                'fleetdoctor_filesystem_coverage_ratio{node="$node"}',
            } <= node_queries
            evidence["node_dashboard_queries"] = sorted(node_queries)
            # Exercise Linux statvfs and spawned worker in the actual collector container.
            evidence["linux_collection"] = compose(
                "exec",
                "-T",
                "collector",
                "/app/.venv/bin/python",
                "-c",
                "from fleetdoctor.collection import CollectionWorker; w=CollectionWorker(); assert w.wait_ready(5); f=w.collect(('/',))[0]; assert f.total_bytes is not None; print(f.model_dump_json()); w.close()",
            )
            compose(
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "fleetdoctor",
                "-d",
                "fleetdoctor",
                "-c",
                "CREATE TABLE task01_persistence (value text); INSERT INTO task01_persistence VALUES ('retained');",
            )
            pause.set()
            time.sleep(2)
            compose("down")
            compose("up", "-d", "--wait", "--wait-timeout", "90")
            pause.clear()
            time.sleep(5)
            retained = compose(
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "fleetdoctor",
                "-d",
                "fleetdoctor",
                "-Atc",
                "SELECT value FROM task01_persistence;",
            )
            assert retained.strip() == "retained"
            evidence["postgres_persistence"] = True
            old_history = httpx.get(
                prom + "/api/v1/query_range",
                params={
                    "query": "fleetdoctor_filesystem_available_bytes",
                    "start": started.timestamp(),
                    "end": end.timestamp(),
                    "step": 5,
                },
                timeout=4,
                trust_env=False,
            ).json()
            assert len(old_history["data"]["result"]) == 4
            evidence["prometheus_persistence"] = True
            assert not producer_errors, producer_errors
            pause.set()
            time.sleep(2)
            evidence["disk_incidents"] = {}
            prove(api, grafana, values, compose, evidence["disk_incidents"])
            evidence["inode_incidents"] = {}
            prove_inode(api, prom, grafana, values, compose, evidence["inode_incidents"])
            evidence["cpu_incidents"] = {}
            prove_cpu(api, prom, grafana, values, compose, evidence["cpu_incidents"])
            evidence["oom_incidents"] = {}
            prove_oom(api, prom, grafana, values, compose, evidence["oom_incidents"])
            evidence["fd_incidents"] = {}
            prove_fd(api, prom, grafana, values, compose, evidence["fd_incidents"], stat)
            evidence["outage_and_replay"] = {}
            asyncio.run(prove_outage(api, prom, grafana, values, evidence["outage_and_replay"]))
            evidence["source_after"] = source_manifest()
            assert evidence["source_before"] == evidence["source_after"], (
                "source changed during service proof"
            )
            evidence["status"] = "passed"
        except BaseException as exc:
            evidence["status"] = "failed"
            evidence["failure"] = type(exc).__name__ + ": " + str(exc)
            raise
        finally:
            stop.set()
            if thread:
                thread.join(timeout=3)
            try:
                compose("down", "--volumes", "--remove-orphans")
                evidence["cleanup"] = "removed_only_unique_test_project"
            finally:
                evidence["finished_at"] = datetime.now(UTC).isoformat()
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"Integration passed; evidence: {args.output}")


if __name__ == "__main__":
    main()
