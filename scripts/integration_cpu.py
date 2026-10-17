"""Synthetic CPU lifecycle proof against the real isolated service stack."""

import json
import time
from collections.abc import Callable
from typing import Any
from uuid import uuid4

import httpx

from fleetdoctor.agent import make_sample
from fleetdoctor.collection import from_statvfs
from fleetdoctor.schema import CpuCounters, CpuObservation, Filesystem

DISK_PATH = "/var/lib/fleetdoctor/chaos/disk"


def prove(
    api: str,
    prom: str,
    grafana: str,
    values: dict[str, str],
    compose: Callable[..., str],
    proof: dict[str, Any],
) -> None:
    tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
    boot, session = uuid4(), uuid4()
    sequence = 0
    proof["environment"] = "real-isolated-services-synthetic-cpu-and-disk-observations"

    def filesystem(usage: int, path: str) -> Filesystem:
        return from_statvfs(
            path,
            {
                "f_blocks": 100_000,
                "f_bfree": 100_000 - usage * 1_000,
                "f_bavail": 100_000 - usage * 1_000,
                "f_frsize": 4096,
                "f_files": 1_000,
                "f_ffree": 900,
            },
        )

    def observation(busy: float, runnable: int = 3) -> CpuObservation:
        return CpuObservation(
            interval_seconds=5,
            busy_percent=busy,
            iowait_percent=2,
            steal_percent=1,
            logical_cores=2,
            online_cpu_ids=[0, 1],
            runnable_processes=runnable,
            load_1m=3,
            load_5m=2,
            load_15m=1,
            ticks_per_second=100,
            counters=CpuCounters(
                user=sequence * 100 + 1,
                nice=0,
                system=sequence * 10 + 1,
                idle=sequence * 5 + 1,
                iowait=sequence + 1,
                irq=0,
                softirq=sequence + 1,
                steal=sequence + 1,
            ),
            process_inventory="partial",
            scanned_processes=0,
            errors=["integration_synthetic_process_inventory"],
        )

    with httpx.Client(timeout=8, trust_env=False) as client:

        def send(busy: float, disk: int) -> None:
            nonlocal sequence
            sequence += 1
            value = make_sample(
                "node-a",
                boot,
                session,
                sequence,
                [filesystem(10, "/"), filesystem(disk, DISK_PATH)],
                cpu=observation(busy),
            )
            response = client.post(
                api + "/ingest",
                content=value.model_dump_json(),
                headers={"Authorization": "Bearer " + tokens["node-a"]},
            )
            response.raise_for_status()
            assert response.json()["status"] == "accepted"

        for _ in range(3):
            send(95, 98)
        active = client.get(
            api + "/diagnoses", params={"node": "node-a", "status": "active"}
        ).json()["diagnoses"]
        rules = {(record["rule"], record["resource"]) for record in active}
        assert ("cpu_saturation", "cpu") in rules
        assert ("disk_block_exhaustion", DISK_PATH) in rules
        cpu_record = next(record for record in active if record["rule"] == "cpu_saturation")
        detail = client.get(api + "/diagnoses/" + cpu_record["id"]).json()
        assert detail["opening_evidence"]["cpu"]["busy_percent"] == 95
        assert detail["opening_evidence"]["cpu"]["runnable_processes"] == 3
        proof["opened"] = {"rules": sorted([list(item) for item in rules]), "cpu": detail}
        compose("restart", "collector")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if client.get(api + "/health").is_success:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        else:
            raise TimeoutError("collector restart readiness")
        restored = client.get(api + "/diagnoses/" + cpu_record["id"]).json()
        assert restored["status"] == "active" and restored["evidence_stale"]
        for _ in range(2):
            send(79, 80)
            assert client.get(api + "/diagnoses/" + cpu_record["id"]).json()["status"] == "active"
        send(79, 80)
        resolved = client.get(api + "/diagnoses/" + cpu_record["id"]).json()
        assert resolved["status"] == "resolved"
        proof["restart_and_three_sample_recovery"] = resolved
        sql = compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "fleetdoctor",
            "-d",
            "fleetdoctor",
            "-Atc",
            "SELECT rule||':'||status FROM incidents WHERE id='" + cpu_record["id"] + "';",
        ).strip()
        assert sql == "cpu_saturation:resolved"
        proof["postgres_record"] = sql
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            metric = client.get(
                prom + "/api/v1/query",
                params={"query": 'fleetdoctor_cpu_busy_ratio{node="node-a"}'},
            ).json()
            if metric.get("data", {}).get("result"):
                proof["prometheus_cpu"] = metric
                break
            time.sleep(1)
        else:
            raise TimeoutError("CPU Prometheus series unavailable")
        for dashboard in ("fleet", "node"):
            body = client.get(
                grafana + "/api/dashboards/uid/fleetdoctor-" + dashboard,
                auth=("admin", values["GRAFANA_PASSWORD"]),
            ).json()["dashboard"]
            titles = {panel["title"] for panel in body["panels"]}
            assert "Host CPU busy" in titles and "CPU source coverage" in titles
        proof["grafana_cpu_panels"] = True
