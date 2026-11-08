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

from io_payload_fixture import maximum_sample

from fleetdoctor.agent import enqueue_bounded_sample, payload_bounded_sample
from fleetdoctor.delivery import MAX_BODY, MAX_BYTES, MAX_COUNT, DeliveryQueue
from fleetdoctor.dns import MAX_BASELINES, MAX_HISTORY_BYTES, DnsBaselineHistory
from fleetdoctor.network import _proc_identity
from fleetdoctor.schema import (
    DnsObservation,
    DnsQueryObservation,
    NetworkProbeObservation,
    ResolverSnapshot,
)
from fleetdoctor.supervisor import CollectionSupervisor


def cgroup_directory() -> Path:
    for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
        hierarchy, controllers, relative = line.split(":", 2)
        if hierarchy == "0" and not controllers:
            path = Path("/sys/fs/cgroup") / relative.removeprefix("/")
            if path.is_dir():
                return path
    raise RuntimeError("unified service cgroup path is unavailable")


def cgroup_value(name: str) -> int | str | None:
    path = cgroup_directory() / name
    if not path.exists():
        return None
    raw = path.read_text(encoding="ascii").strip()
    return int(raw) if raw.isdigit() else raw


def cgroup_events(name: str) -> dict[str, int]:
    path = cgroup_directory() / name
    if not path.exists():
        return {}
    values: dict[str, int] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        key, raw = line.split()
        values[key] = int(raw)
    return values


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
    maximum = maximum_sample(
        selected,
        boot=boot_id,
        session=session_id,
        observed_at=observed + timedelta(seconds=MAX_BASELINES * 5),
    )
    assert maximum.fd is not None and maximum.io is not None
    raw_payload_bytes = len(maximum.model_dump_json().encode())
    bounded = payload_bounded_sample(maximum)
    bounded_payload_bytes = len(bounded.model_dump_json().encode())
    queue = DeliveryQueue()
    queue_now = maximum.observed_at
    for sequence in range(MAX_COUNT + 1):
        enqueue_bounded_sample(
            queue,
            bounded.model_copy(update={"sequence": sequence}),
            queue_now,
        )
    memory_events_before = cgroup_events("memory.events")
    pids_events_before = cgroup_events("pids.events")
    supervisor = CollectionSupervisor()
    worker_pid: int | None = None
    worker_start: int | None = None
    collection_seconds: float | None = None
    cleanup_seconds: float | None = None
    collection_summary: dict[str, object] = {}
    combined_samples: dict[str, dict[str, int | str | None]] = {}
    worker_live_before_cleanup = False
    worker_orphaned = True
    try:
        if not supervisor.wait_ready(5.0):
            raise RuntimeError("production collection supervisor did not become ready")
        if supervisor.process is None or supervisor.starttime is None:
            raise RuntimeError("production collection supervisor identity unavailable")
        worker_pid = supervisor.process.pid
        worker_start = supervisor.starttime
        combined_samples["ready"] = {
            "memory_current_bytes": cgroup_value("memory.current"),
            "memory_peak_bytes": cgroup_value("memory.peak"),
            "pids_current": cgroup_value("pids.current"),
            "pids_peak": cgroup_value("pids.peak"),
        }
        collect_started = time.monotonic()
        collection = supervisor.collect_all(
            boot_id,
            session_id,
            MAX_BASELINES,
            ("/",),
            (),
            (),
            (),
            "unavailable",
            None,
            "watch_unavailable",
            "192.0.2.80",
            "baseline.fleetdoctor.test.",
            budget=3.0,
        )
        collection_seconds = time.monotonic() - collect_started
        worker_identity = _proc_identity(worker_pid)
        worker_live_before_cleanup = bool(
            worker_identity is not None and worker_identity[2] == worker_start
        )
        combined_samples["after_collection"] = {
            "memory_current_bytes": cgroup_value("memory.current"),
            "memory_peak_bytes": cgroup_value("memory.peak"),
            "pids_current": cgroup_value("pids.current"),
            "pids_peak": cgroup_value("pids.peak"),
        }
        collection_summary = {
            "filesystem_count": len(collection.filesystems),
            "cpu_errors": collection.cpu.errors,
            "memory_errors": collection.memory.host.errors,
            "fd_errors": collection.fd.errors,
            "network_status": collection.network.probe.status,
            "dns_status": collection.dns.query.status if collection.dns else None,
            "dns_error": collection.dns.query.error if collection.dns else None,
            "io_status": collection.io.status,
        }
    finally:
        cleanup_started = time.monotonic()
        supervisor.close()
        cleanup_seconds = time.monotonic() - cleanup_started
        if worker_pid is not None and worker_start is not None:
            identity_after = _proc_identity(worker_pid)
            worker_orphaned = bool(identity_after is not None and identity_after[2] == worker_start)
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
    pids_peak = cgroup_value("pids.peak")
    memory_events_after = cgroup_events("memory.events")
    pids_events_after = cgroup_events("pids.events")
    memory_event_delta = {
        key: value - memory_events_before.get(key, 0) for key, value in memory_events_after.items()
    }
    pids_event_delta = {
        key: value - pids_events_before.get(key, 0) for key, value in pids_events_after.items()
    }
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
        and (pids_peak is None or isinstance(pids_peak, int) and pids_peak <= pids_limit)
        and threads <= pids_limit
        and collection_seconds is not None
        and collection_seconds < 3
        and worker_live_before_cleanup
        and not worker_orphaned
        and not any(memory_event_delta.get(key, 0) for key in ("oom", "oom_kill", "oom_group_kill"))
        and memory_event_delta.get("max", 0) == 0
        and pids_event_delta.get("max", 0) == 0
        and raw_payload_bytes > MAX_BODY
        and bounded_payload_bytes <= MAX_BODY
        and bounded.io is not None
        and bounded.io.context_trimmed
        and len(bounded.io.devices) == 4
        and bounded.fd is not None
        and {item.identity.resource for item in bounded.fd.observations}
        == {item.identity.resource for item in maximum.fd.observations if item.watched}
        and bounded.dns == selected
        and len(queue.entries) <= MAX_COUNT
        and queue.size <= MAX_BYTES
        and all(len(item.body) <= MAX_BODY for item in queue.entries)
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
                "combined_delivery": {
                    "raw_payload_bytes": raw_payload_bytes,
                    "bounded_payload_bytes": bounded_payload_bytes,
                    "maximum_payload_bytes": MAX_BODY,
                    "io_devices_preserved": len(bounded.io.devices) if bounded.io else None,
                    "io_process_coverage": bounded.io.process_coverage if bounded.io else None,
                    "io_pressure_coverage": bounded.io.pressure_coverage if bounded.io else None,
                    "fd_watched_preserved": len(bounded.fd.observations) if bounded.fd else None,
                    "dns_selected_baseline_preserved": bounded.dns == selected,
                    "queue_entries": len(queue.entries),
                    "queue_bytes": queue.size,
                    "queue_count_limit": MAX_COUNT,
                    "queue_bytes_limit": MAX_BYTES,
                    "queue_discard_total": queue.discard_total,
                    "queue_reasons": queue.reasons,
                },
                "live_production_supervisor": {
                    "worker_pid": worker_pid,
                    "worker_starttime": worker_start,
                    "worker_live_before_cleanup": worker_live_before_cleanup,
                    "worker_orphaned_after_cleanup": worker_orphaned,
                    "collect_all_seconds": collection_seconds,
                    "cleanup_seconds": cleanup_seconds,
                    "collection": collection_summary,
                    "combined_samples": combined_samples,
                },
                "cgroup": {
                    "path": str(cgroup_directory()),
                    "memory_limit_bytes": memory_limit,
                    "memory_current_bytes": memory_current,
                    "memory_peak_bytes": memory_peak,
                    "pids_limit": pids_limit,
                    "pids_current": pids_current,
                    "pids_peak": pids_peak,
                    "process_threads": threads,
                    "memory_events_before": memory_events_before,
                    "memory_events_after": memory_events_after,
                    "memory_event_delta": memory_event_delta,
                    "pids_events_before": pids_events_before,
                    "pids_events_after": pids_events_after,
                    "pids_event_delta": pids_event_delta,
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
