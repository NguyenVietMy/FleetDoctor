#!/usr/bin/env python3
"""Measure maximum production DNS history inside the service resource envelope."""

from __future__ import annotations

import json
import os
import resource
import sys
import time
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import median
from uuid import uuid4

from fleetdoctor.dns import MAX_BASELINES, MAX_HISTORY_BYTES, DnsBaselineHistory
from fleetdoctor.schema import (
    DnsObservation,
    DnsQueryObservation,
    NetworkProbeObservation,
    ResolverSnapshot,
)


def cgroup_value(name: str) -> int | str | None:
    path = Path("/sys/fs/cgroup") / name
    if not path.exists():
        return None
    raw = path.read_text(encoding="ascii").strip()
    return int(raw) if raw.isdigit() else raw


def main() -> None:
    started = time.monotonic()
    boot_id, session_id = uuid4(), uuid4()
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    resolver = ResolverSnapshot(
        status="available",
        nameservers=["192.0.2.53"],
        fingerprint="a" * 64,
        entry_type="regular",
    )
    query = DnsQueryObservation(
        status="success",
        hostname="baseline.fleetdoctor.test.",
        answers=["192.0.2.80"],
        duration_seconds=0.01,
        selected_server="192.0.2.53",
        adapter="dnspython",
    )
    observation = DnsObservation(
        hostname="baseline.fleetdoctor.test.",
        direct_ip_target="192.0.2.80",
        resolver=resolver,
        query=query,
        retention_coverage="complete",
    )
    probe = NetworkProbeObservation(
        status="available",
        target="192.0.2.80",
        sent=3,
        received=3,
        lost=0,
        loss_ratio=0,
        successful_sequences=[1, 2, 3],
        successful_rtts_ms=[19.0, 20.0, 21.0],
        median_rtt_ms=20.0,
        route_status="available",
        interface="eth0",
        interface_ifindex=1,
    )
    history = DnsBaselineHistory()
    timings: list[float] = []
    tracemalloc.start()
    before_current, before_peak = tracemalloc.get_traced_memory()
    for sequence in range(MAX_BASELINES):
        attach_started = time.monotonic()
        history.attach(
            observation,
            node_id="node-a",
            boot_id=boot_id,
            agent_session_id=session_id,
            sequence=sequence,
            observed_at=observed + timedelta(seconds=sequence * 5),
            direct_ip_probe=probe,
            monotonic_now=float(sequence * 5),
        )
        timings.append(time.monotonic() - attach_started)
    selection_started = time.monotonic()
    selected = history.attach(
        observation,
        node_id="node-a",
        boot_id=boot_id,
        agent_session_id=session_id,
        sequence=MAX_BASELINES - 1,
        observed_at=observed + timedelta(seconds=(MAX_BASELINES - 1) * 5),
        direct_ip_probe=probe,
        monotonic_now=float((MAX_BASELINES - 1) * 5),
    )
    selection_seconds = time.monotonic() - selection_started
    after_current, after_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    index_bytes = sys.getsizeof(history._items) + sum(
        sys.getsizeof(key) + sys.getsizeof(value) for key, value in history._items.items()
    )
    memory_limit = cgroup_value("memory.max")
    memory_current = cgroup_value("memory.current")
    memory_peak = cgroup_value("memory.peak")
    pids_limit = cgroup_value("pids.max")
    pids_current = cgroup_value("pids.current")
    threads = len(list(Path("/proc/self/task").iterdir()))
    passed = bool(
        history.count == MAX_BASELINES
        and history.serialized_bytes <= MAX_HISTORY_BYTES
        and history.coverage_complete
        and selected.baseline is not None
        and max(timings) < 3
        and selection_seconds < 3
        and memory_limit == 100 * 1024 * 1024
        and isinstance(memory_current, int)
        and memory_current < memory_limit
        and isinstance(memory_peak, int)
        and memory_peak <= memory_limit
        and pids_limit == 16
        and isinstance(pids_current, int)
        and pids_current <= pids_limit
        and threads <= pids_limit
    )
    print(
        json.dumps(
            {
                "status": "passed" if passed else "failed",
                "attribution": "controlled_maximum_history_resource_check_not_native_baseline",
                "production_class": "fleetdoctor.dns.DnsBaselineHistory",
                "history": {
                    "count": history.count,
                    "maximum": MAX_BASELINES,
                    "serialized_bytes": history.serialized_bytes,
                    "serialized_limit_bytes": MAX_HISTORY_BYTES,
                    "index_bytes": index_bytes,
                    "coverage_complete": history.coverage_complete,
                    "selected_baseline": selected.baseline.model_dump(mode="json")
                    if selected.baseline is not None
                    else None,
                },
                "timing": {
                    "total_fill_seconds": time.monotonic() - started,
                    "maximum_attach_seconds": max(timings),
                    "median_attach_seconds": median(timings),
                    "selection_seconds": selection_seconds,
                    "parent_operation_limit_seconds": 3,
                    "production_cadence_seconds": 5,
                },
                "python_allocation": {
                    "tracemalloc_before_current_bytes": before_current,
                    "tracemalloc_before_peak_bytes": before_peak,
                    "tracemalloc_after_current_bytes": after_current,
                    "tracemalloc_after_peak_bytes": after_peak,
                    "ru_maxrss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                },
                "cgroup": {
                    "memory_limit_bytes": memory_limit,
                    "memory_current_bytes": memory_current,
                    "memory_peak_bytes": memory_peak,
                    "pids_limit": pids_limit,
                    "pids_current": pids_current,
                    "process_threads": threads,
                },
                "pid": os.getpid(),
            },
            sort_keys=True,
        )
    )
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
