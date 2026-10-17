"""Bounded Linux host CPU and process collection with explicit reset semantics."""

import multiprocessing as mp
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from itertools import chain
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from fleetdoctor.schema import CpuCounters, CpuObservation, ProcessIdentity, ProcessObservation

MAX_PROCESSES = 4096
MAX_READ = 4096
PROCESS_BUDGET = 0.5


@dataclass(frozen=True)
class ProcessStat:
    pid: int
    comm: str
    utime: int
    stime: int
    starttime: int
    rss_pages: int

    @property
    def ticks(self) -> int:
        return self.utime + self.stime


def parse_proc_stat(text: str) -> tuple[CpuCounters, tuple[int, ...], int]:
    aggregate: list[str] | None = None
    online: list[int] = []
    runnable: int | None = None
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "cpu":
            aggregate = fields[1:9]
        elif fields[0].startswith("cpu") and fields[0][3:].isdigit():
            online.append(int(fields[0][3:]))
        elif fields[0] == "procs_running" and len(fields) == 2:
            runnable = int(fields[1])
    if aggregate is None or len(aggregate) != 8 or runnable is None or not online:
        raise ValueError("missing required /proc/stat fields")
    values = [int(value) for value in aggregate]
    if any(value < 0 for value in values) or runnable < 0:
        raise ValueError("negative /proc/stat counter")
    return (
        CpuCounters(**dict(zip(CpuCounters.model_fields, values, strict=True))),
        tuple(online),
        runnable,
    )


def parse_loadavg(text: str) -> tuple[float, float, float]:
    fields = text.split()
    if len(fields) < 3:
        raise ValueError("malformed /proc/loadavg")
    values = tuple(float(value) for value in fields[:3])
    if any(value < 0 or not value < float("inf") for value in values):
        raise ValueError("invalid load average")
    return values  # type: ignore[return-value]


def parse_process_stat(text: str) -> ProcessStat:
    opening, closing = text.find("("), text.rfind(")")
    if opening <= 0 or closing <= opening or closing + 2 > len(text):
        raise ValueError("malformed process stat")
    pid = int(text[:opening].strip())
    comm = text[opening + 1 : closing]
    rest = text[closing + 2 :].split()
    # Rest starts at field 3 (state); utime=14, stime=15, starttime=22, rss=24.
    if len(rest) < 22 or not comm or "\n" in comm or "\r" in comm:
        raise ValueError("malformed process stat")
    values = ProcessStat(
        pid, comm[:128], int(rest[11]), int(rest[12]), int(rest[19]), int(rest[21])
    )
    if min(values.pid, values.utime, values.stime, values.starttime, values.rss_pages) < 0:
        raise ValueError("negative process stat value")
    return values


def cpu_rates(previous: CpuCounters, current: CpuCounters) -> tuple[float, float, float]:
    old = [getattr(previous, field) for field in CpuCounters.model_fields]
    new = [getattr(current, field) for field in CpuCounters.model_fields]
    deltas = [right - left for left, right in zip(old, new, strict=True)]
    if any(delta < 0 for delta in deltas) or not (total := sum(deltas)):
        raise ValueError("CPU counters reset or did not advance")
    busy = deltas[0] + deltas[1] + deltas[2] + deltas[5] + deltas[6]
    return 100 * busy / total, 100 * deltas[4] / total, 100 * deltas[7] / total


class CpuCollector:
    def __init__(
        self,
        proc: Path = Path("/proc"),
        clock: Callable[[], float] = time.monotonic,
        ticks_per_second: int | None = None,
        page_size: int | None = None,
    ) -> None:
        self.proc, self.clock = proc, clock
        self.ticks = ticks_per_second or int(os.sysconf("SC_CLK_TCK"))
        self.page_size = page_size or int(os.sysconf("SC_PAGE_SIZE"))
        self.previous_counters: CpuCounters | None = None
        self.previous_time: float | None = None
        self.previous_cores: tuple[int, ...] | None = None
        self.previous_processes: dict[tuple[int, int], int] = {}

    def _read(self, path: Path) -> str:
        with path.open("rb") as stream:
            body = stream.read(MAX_READ + 1)
        if len(body) > MAX_READ:
            raise ValueError("proc source exceeds read bound")
        return body.decode("utf-8", errors="strict")

    def _processes(
        self, started: float, configured: frozenset[int]
    ) -> tuple[
        list[ProcessObservation],
        dict[tuple[int, int], int],
        int,
        Literal["complete", "partial", "unavailable"],
        list[str],
    ]:
        observations: list[tuple[ProcessStat, float | None, bool]] = []
        baseline: dict[tuple[int, int], int] = {}
        errors: list[str] = []
        scanned = 0
        try:
            entries: Iterable[Path] = chain(
                (self.proc / str(pid) for pid in sorted(configured)), self.proc.iterdir()
            )
        except OSError as exc:
            return [], {}, 0, "unavailable", [f"process_list_{type(exc).__name__}"]
        partial = False
        seen_pids: set[int] = set()
        for entry in entries:
            if scanned >= MAX_PROCESSES or self.clock() - started > PROCESS_BUDGET:
                partial = True
                break
            if not entry.name.isdigit():
                continue
            if int(entry.name) in seen_pids:
                continue
            seen_pids.add(int(entry.name))
            scanned += 1
            try:
                stat = parse_process_stat(self._read(entry / "stat"))
            except (OSError, UnicodeError, ValueError):
                partial = True
                continue
            key = stat.pid, stat.starttime
            baseline[key] = stat.ticks
            rate = None
            if (
                self.previous_time is not None
                and (elapsed := self.clock() - self.previous_time) > 0
                and elapsed <= 10
                and key in self.previous_processes
                and stat.ticks >= self.previous_processes[key]
            ):
                rate = 100 * (stat.ticks - self.previous_processes[key]) / self.ticks / elapsed
            observations.append((stat, rate, stat.pid in configured))
        by_cpu = sorted(
            observations, key=lambda item: item[1] if item[1] is not None else -1, reverse=True
        )[:10]
        by_rss = sorted(observations, key=lambda item: item[0].rss_pages, reverse=True)[:10]
        selected: dict[tuple[int, int], tuple[ProcessStat, float | None, bool]] = {
            (item[0].pid, item[0].starttime): item for item in [*by_cpu, *by_rss]
        }
        for item in observations:
            if item[2]:
                selected[(item[0].pid, item[0].starttime)] = item
        processes = [
            ProcessObservation(
                identity=ProcessIdentity(pid=stat.pid, starttime_ticks=stat.starttime),
                comm=stat.comm,
                cpu_percent=rate,
                rss_bytes=stat.rss_pages * self.page_size,
                configured=is_configured,
            )
            for stat, rate, is_configured in list(selected.values())[:36]
        ]
        if partial:
            errors.append("process_inventory_partial")
        return processes, baseline, scanned, "partial" if partial else "complete", errors

    def collect(self, configured_pids: tuple[int, ...] = ()) -> CpuObservation:
        if len(configured_pids) > 16 or len(set(configured_pids)) != len(configured_pids):
            raise ValueError("configure at most 16 unique process IDs")
        if any(type(pid) is not int or pid < 1 or pid > 2**31 - 1 for pid in configured_pids):
            raise ValueError("configured process IDs must be positive integers")
        started = self.clock()
        errors: list[str] = []
        try:
            counters, cores, runnable = parse_proc_stat(self._read(self.proc / "stat"))
        except (OSError, UnicodeError, ValueError, ValidationError) as exc:
            return CpuObservation(errors=[f"proc_stat_{type(exc).__name__}"])
        try:
            loads: tuple[float | None, float | None, float | None] = parse_loadavg(
                self._read(self.proc / "loadavg")
            )
        except (OSError, UnicodeError, ValueError) as exc:
            loads = (None, None, None)
            errors.append(f"loadavg_{type(exc).__name__}")
        processes, baseline, scanned, inventory, process_errors = self._processes(
            started, frozenset(configured_pids)
        )
        errors.extend(process_errors)
        elapsed = started - self.previous_time if self.previous_time is not None else None
        busy = iowait = steal = interval = None
        if (
            self.previous_counters is not None
            and self.previous_cores == cores
            and elapsed is not None
            and 0 < elapsed <= 10
        ):
            try:
                busy, iowait, steal = cpu_rates(self.previous_counters, counters)
                interval = elapsed
            except ValueError:
                errors.append("cpu_counter_reset")
        else:
            errors.append("cpu_rate_baseline_unavailable")
        self.previous_counters, self.previous_time, self.previous_cores = counters, started, cores
        self.previous_processes = baseline
        return CpuObservation(
            interval_seconds=interval,
            busy_percent=busy,
            iowait_percent=iowait,
            steal_percent=steal,
            logical_cores=len(cores),
            online_cpu_ids=list(cores),
            runnable_processes=runnable,
            load_1m=loads[0],
            load_5m=loads[1],
            load_15m=loads[2],
            ticks_per_second=self.ticks,
            counters=counters,
            processes=processes,
            process_inventory=inventory,
            scanned_processes=scanned,
            errors=errors,
        )


def _worker(conn: Connection) -> None:
    collector = CpuCollector()
    try:
        conn.send("ready")
        while True:
            configured = tuple(conn.recv())
            conn.send(collector.collect(configured).model_dump())
    except (EOFError, BrokenPipeError):
        pass
    finally:
        conn.close()


class CpuCollectionWorker:
    def __init__(self, target: Callable[[Connection], None] = _worker) -> None:
        self.process: Any = None
        self.conn: Connection | None = None
        self.ready = False
        self.target = target

    def start(self) -> None:
        if self.process is not None:
            return
        ctx = mp.get_context("spawn")
        self.conn, child = ctx.Pipe()
        self.process = ctx.Process(target=self.target, args=(child,), daemon=True)
        self.process.start()
        child.close()

    def wait_ready(self, timeout: float = 0) -> bool:
        self.start()
        if not self.ready and self.conn is not None and self.conn.poll(timeout):
            try:
                self.ready = self.conn.recv() == "ready"
            except (OSError, EOFError):
                self.close()
        return self.ready

    def close(self) -> None:
        self.ready = False
        if self.process is not None:
            self.process.terminate()
            self.process.join(timeout=0.05)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(timeout=0.05)
            if not self.process.is_alive():
                self.process.close()
                self.process = None
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def collect(
        self, configured_pids: tuple[int, ...] = (), budget: float = 0.75
    ) -> CpuObservation:
        if self.process is not None and self.conn is None:
            if self.process.is_alive():
                return CpuObservation(errors=["cpu_collection_worker_stuck"])
            self.process.close()
            self.process = None
        if not self.wait_ready():
            return CpuObservation(errors=["cpu_collection_worker_starting"])
        try:
            if self.conn is None:
                raise TimeoutError
            self.conn.send(configured_pids)
            if not self.conn.poll(budget):
                raise TimeoutError
            return CpuObservation.model_validate(self.conn.recv())
        except (TimeoutError, OSError, EOFError, ValidationError):
            self.close()
            return CpuObservation(errors=["cpu_collection_timeout"])
