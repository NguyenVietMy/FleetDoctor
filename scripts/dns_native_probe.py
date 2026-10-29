#!/usr/bin/env python3
"""Inside-container real resolver/helper proof with exact restoration."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fleetdoctor.dns import DnsBaselineHistory, DnsCollector
from fleetdoctor.network import NetworkCollector

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy/dns_resource.py"
HOSTNAME = "baseline.fleetdoctor.test."


def call_helper(action: str, token: str, *extra: str) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, str(HELPER), action, "--token", token, *extra],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr[-1000:])
    value: dict[str, object] = json.loads(result.stdout)
    return value


def main() -> None:
    target = os.environ["DNS_PROOF_TARGET"]
    invalid_resolver = os.environ["DNS_INVALID_RESOLVER"]
    resolver_path = Path("/etc/resolv.conf")
    docker_original = resolver_path.read_bytes()
    resolver_path.write_bytes(f"nameserver {target}\n".encode("ascii"))
    before = resolver_path.read_bytes()
    before_hash = hashlib.sha256(before).hexdigest()
    collector = DnsCollector()
    baseline = collector.collect(HOSTNAME, target)
    network = NetworkCollector().collect(target)
    if baseline.query.status != "success":
        raise RuntimeError(f"baseline query unavailable: {baseline.model_dump_json()}")
    if network.probe.status != "available" or network.probe.lost != 0:
        raise RuntimeError("direct-IP proof is not healthy")
    history = DnsBaselineHistory()
    attached = history.attach(
        baseline,
        node_id="node-a",
        boot_id=uuid4(),
        agent_session_id=uuid4(),
        sequence=0,
        observed_at=datetime.now(UTC),
        direct_ip_probe=network.probe,
    )
    if attached.baseline is None:
        raise RuntimeError("genuine native baseline was not retained")
    token = uuid4().hex
    started: dict[str, object] | None = None
    cleaned: dict[str, object] | None = None
    failed = None
    try:
        started = call_helper(
            "start", token, "--invalid-resolver", invalid_resolver, "--duration", "20"
        )
        failed = collector.collect(HOSTNAME, target)
        if failed.query.status != "failure":
            raise RuntimeError(
                f"injected query was not a measured failure: {failed.model_dump_json()}"
            )
    finally:
        cleaned = call_helper("cleanup", token)
    recovered = collector.collect(HOSTNAME, target)
    after = resolver_path.read_bytes()
    if recovered.query.status != "success" or after != before:
        raise RuntimeError("resolver did not recover exactly")
    resolver_path.write_bytes(docker_original)
    print(
        json.dumps(
            {
                "status": "passed",
                "uid": os.getuid(),
                "gid": os.getgid(),
                "hostname": HOSTNAME,
                "target": target,
                "invalid_resolver": invalid_resolver,
                "before_sha256": before_hash,
                "after_sha256": hashlib.sha256(after).hexdigest(),
                "docker_original_restored": resolver_path.read_bytes() == docker_original,
                "baseline": attached.model_dump(mode="json"),
                "injected": failed.model_dump(mode="json") if failed is not None else None,
                "recovered": recovered.model_dump(mode="json"),
                "start": started,
                "cleanup": cleaned,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
