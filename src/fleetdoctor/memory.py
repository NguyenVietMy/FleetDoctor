"""Bounded Linux memory, cgroup-v2, RSS, and incremental kernel-log collection."""

import json
import multiprocessing as mp
import os
import re
import selectors
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from pydantic import ValidationError

from fleetdoctor.cpu import parse_process_stat
from fleetdoctor.schema import (
    HostMemoryObservation,
    KernelOomLog,
    MemoryCounters,
    MemoryEvents,
    MemoryObservation,
    ProcessIdentity,
    ProcessObservation,
    WorkloadMemoryObservation,
)

MAX_HOST_READ = 64 * 1024
MAX_CGROUP_READ = 8 * 1024
MAX_CGROUPS = 4
MAX_PATH = 256
MAX_RSS_PROCESSES = 10
MAX_JOURNAL_RECORDS = 64
MAX_LOG_MESSAGE_BYTES = 512
MAX_LOG_TOTAL_BYTES = 8 * 1024
CGROUP_PATH = re.compile(r"^/[a-zA-Z0-9_.@/-]+$")
JournalCoverage = Literal["available", "permission_denied", "cursor_lost", "unavailable"]
LogCoverage = Literal["baseline", "available", "permission_denied", "cursor_lost", "unavailable"]


def parse_meminfo(text: str) -> tuple[int, int, int, int]:
    wanted = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
    values: dict[str, int] = {}
    for line in text.splitlines():
        name, separator, rest = line.partition(":")
        if separator and name in wanted:
            fields = rest.split()
            if len(fields) != 2 or fields[1] != "kB":
                raise ValueError("unsupported meminfo unit")
            value = int(fields[0])
            if value < 0:
                raise ValueError("negative meminfo value")
            values[name] = value * 1024
    if set(values) != wanted:
        raise ValueError("missing required meminfo field")
    return tuple(values[name] for name in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"))  # type: ignore[return-value]


def parse_vmstat(text: str) -> MemoryCounters:
    wanted = {"pgfault", "pgmajfault", "pswpin", "pswpout"}
    values: dict[str, int] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in wanted:
            value = int(fields[1])
            if value < 0:
                raise ValueError("negative vmstat counter")
            values[fields[0]] = value
    if set(values) != wanted:
        raise ValueError("missing required vmstat field")
    return MemoryCounters(**values)


def parse_memory_events(text: str) -> MemoryEvents:
    values: dict[str, int] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise ValueError("malformed memory.events.local")
        value = int(fields[1])
        if value < 0:
            raise ValueError("negative memory event counter")
        values[fields[0]] = value
    if "oom" not in values or "oom_kill" not in values:
        raise ValueError("missing local OOM counters")
    return MemoryEvents(
        **{key: values[key] for key in ("oom", "oom_kill", "high", "max") if key in values}
    )


def parse_limit(text: str) -> tuple[int | None, bool]:
    value = text.strip()
    if value == "max":
        return None, True
    parsed = int(value)
    if parsed < 0 or parsed > 2**64 - 1:
        raise ValueError("invalid cgroup limit")
    return parsed, False


def validate_cgroup_paths(raw: str) -> tuple[str, ...]:
    if not raw:
        return ()
    paths = tuple(raw.split(","))
    if len(paths) > MAX_CGROUPS or len(set(paths)) != len(paths):
        raise ValueError("configure at most four unique cgroup paths")
    if any(
        len(path) > MAX_PATH
        or path == "/"
        or not CGROUP_PATH.fullmatch(path)
        or "//" in path
        or any(part in ("", ".", "..") for part in path.split("/")[1:])
        for path in paths
    ):
        raise ValueError("cgroup paths must be canonical absolute non-root paths")
    return paths


def utf8_prefix(value: str, maximum: int) -> str:
    if maximum <= 0:
        return ""
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value
    return encoded[:maximum].decode("utf-8", errors="ignore")


class MemoryCollector:
    def __init__(
        self,
        proc: Path = Path("/proc"),
        cgroup_root: Path = Path("/sys/fs/cgroup"),
        clock: Callable[[], float] = time.monotonic,
        boot_id: UUID | None = None,
        page_size: int | None = None,
        journal: Callable[[str | None], tuple[list[dict[str, Any]], str | None, JournalCoverage]]
        | None = None,
    ) -> None:
        self.proc = proc
        self.cgroup_root = cgroup_root
        self.clock = clock
        self.boot_id = boot_id or UUID(
            self._read(proc / "sys/kernel/random/boot_id", MAX_CGROUP_READ).strip()
        )
        self.page_size = page_size or int(os.sysconf("SC_PAGE_SIZE"))
        self.previous_counters: MemoryCounters | None = None
        self.previous_time: float | None = None
        self.journal_cursor: str | None = None
        self.journal_initialized = False
        self.journal_since_realtime = time.time()
        self.journal = journal or self._journal

    def _read(self, path: Path, maximum: int) -> str:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            body = stream.read(maximum + 1)
        if len(body) > maximum:
            raise ValueError("source exceeds read bound")
        return body.decode("utf-8", errors="strict")

    def _journal(
        self, cursor: str | None
    ) -> tuple[
        list[dict[str, Any]],
        str | None,
        JournalCoverage,
    ]:
        command = [
            "journalctl",
            "--dmesg",
            "--boot=" + str(self.boot_id),
            "--output=json",
            "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,MESSAGE",
            "--show-cursor",
            "--no-pager",
            "--quiet",
            "--lines=" + str(MAX_JOURNAL_RECORDS + 1),
        ]
        if cursor:
            command.extend(["--after-cursor", cursor])
        else:
            command.append("--since=@" + str(self.journal_since_realtime))
        stdout, stderr, returncode = self._bounded_journal_command(command)
        message = stderr.decode("utf-8", errors="replace").lower()
        if (
            "permission" in message
            or "not seeing messages" in message
            or "insufficient permissions" in message
        ):
            return [], cursor, "permission_denied"
        if returncode:
            coverage: JournalCoverage
            if "cursor" in message:
                coverage = "cursor_lost"
            else:
                coverage = "unavailable"
            return [], cursor, coverage
        text = stdout.decode("utf-8", errors="strict")
        records: list[dict[str, Any]] = []
        for line in text.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                records.append(value)
        if len(records) > MAX_JOURNAL_RECORDS:
            return [], cursor, "cursor_lost"
        for record in records:
            try:
                if UUID(str(record.get("_BOOT_ID"))) != self.boot_id:
                    return [], cursor, "cursor_lost"
            except (TypeError, ValueError, AttributeError):
                return [], cursor, "cursor_lost"
        latest = next(
            (str(item["__CURSOR"]) for item in reversed(records) if "__CURSOR" in item), cursor
        )
        shown = re.search(r"^-- cursor: (\S+)$", text, flags=re.MULTILINE)
        if shown:
            latest = shown.group(1)
        if records and latest == cursor:
            return [], cursor, "cursor_lost"
        return records, latest, "available"

    def _bounded_journal_command(self, command: list[str]) -> tuple[bytes, bytes, int]:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.stdout is None or process.stderr is None:
            process.kill()
            raise RuntimeError("journal pipes unavailable")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, ("stdout", MAX_HOST_READ))
        selector.register(process.stderr, selectors.EVENT_READ, ("stderr", MAX_CGROUP_READ))
        chunks: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + 0.25
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, 0.25)
                events = selector.select(remaining)
                if not events and process.poll() is not None:
                    events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
                for key, _ in events:
                    name, maximum = key.data
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    chunks[name].extend(chunk)
                    if len(chunks[name]) > maximum:
                        raise ValueError("journal output exceeds bounded capture")
            returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            return bytes(chunks["stdout"]), bytes(chunks["stderr"]), returncode
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=0.1)

    @staticmethod
    def _exact_memcg(message: str, paths: tuple[str, ...]) -> str | None:
        candidates = re.findall(r"\b(?:oom_memcg|memcg)=(/[^,\s\"']+)", message)
        return next((candidate for candidate in candidates if candidate in paths), None)

    def _logs(
        self, paths: tuple[str, ...]
    ) -> tuple[
        list[KernelOomLog],
        LogCoverage,
        list[str],
    ]:
        try:
            records, cursor, coverage = self.journal(self.journal_cursor)
        except (OSError, UnicodeError, subprocess.SubprocessError, ValueError) as exc:
            self.journal_cursor = None
            self.journal_initialized = False
            self.journal_since_realtime = time.time()
            return [], "unavailable", [f"kernel_log_{type(exc).__name__}"]
        if coverage != "available":
            self.journal_cursor = None
            self.journal_initialized = False
            self.journal_since_realtime = time.time()
            return [], coverage, ["kernel_log_" + coverage]
        self.journal_cursor = cursor
        if not self.journal_initialized:
            self.journal_initialized = True
            self.journal_since_realtime = time.time()
            return [], "baseline", []
        logs: list[KernelOomLog] = []
        retained_bytes = 0
        for record in records:
            raw_message = str(record.get("MESSAGE", ""))
            lowered = raw_message.lower()
            if "oom" not in lowered and "killed process" not in lowered:
                continue
            path = self._exact_memcg(raw_message, paths)
            if path is None:
                continue
            message = utf8_prefix(
                raw_message,
                min(MAX_LOG_MESSAGE_BYTES, MAX_LOG_TOTAL_BYTES - retained_bytes),
            )
            if not message:
                break
            cursor_value = str(record.get("__CURSOR", ""))[:256]
            timestamp = record.get("__REALTIME_TIMESTAMP")
            if not cursor_value or timestamp is None:
                continue
            try:
                observed = datetime.fromtimestamp(int(timestamp) / 1_000_000, UTC)
            except (ValueError, TypeError, OSError):
                continue
            pid_match = re.search(r"Killed process\s+(\d+)\s+\(([^)\r\n]{1,128})\)", raw_message)
            logs.append(
                KernelOomLog(
                    boot_id=self.boot_id,
                    cursor=cursor_value,
                    realtime_timestamp=observed,
                    message=message,
                    cgroup_path=path,
                    victim_pid=int(pid_match.group(1)) if pid_match else None,
                    victim_comm=pid_match.group(2) if pid_match else None,
                )
            )
            retained_bytes += len(message.encode("utf-8"))
            if len(logs) == 16:
                break
        return logs, coverage, []

    def _host(self, started: float) -> HostMemoryObservation:
        errors: list[str] = []
        total: int | None
        available: int | None
        swap_total: int | None
        swap_free: int | None
        try:
            total, available, swap_total, swap_free = parse_meminfo(
                self._read(self.proc / "meminfo", MAX_HOST_READ)
            )
        except (OSError, UnicodeError, ValueError) as exc:
            total = available = swap_total = swap_free = None
            errors.append(f"meminfo_{type(exc).__name__}")
        try:
            counters = parse_vmstat(self._read(self.proc / "vmstat", MAX_HOST_READ))
        except (OSError, UnicodeError, ValueError, ValidationError) as exc:
            counters = None
            errors.append(f"vmstat_{type(exc).__name__}")
        elapsed = started - self.previous_time if self.previous_time is not None else None
        rates: tuple[float | None, float | None, float | None, float | None] = (
            None,
            None,
            None,
            None,
        )
        interval = None
        if (
            counters is not None
            and self.previous_counters is not None
            and elapsed is not None
            and 0 < elapsed <= 10
        ):
            deltas = tuple(
                getattr(counters, field) - getattr(self.previous_counters, field)
                for field in MemoryCounters.model_fields
            )
            if min(deltas) >= 0:
                rates = (
                    deltas[0] / elapsed,
                    deltas[1] / elapsed,
                    deltas[2] * self.page_size / elapsed,
                    deltas[3] * self.page_size / elapsed,
                )
                interval = elapsed
            else:
                errors.append("memory_counter_reset")
        else:
            errors.append("memory_rate_baseline_unavailable")
        self.previous_counters, self.previous_time = counters, started
        return HostMemoryObservation(
            total_bytes=total,
            available_bytes=available,
            swap_total_bytes=swap_total,
            swap_free_bytes=swap_free,
            page_size_bytes=self.page_size,
            interval_seconds=interval,
            counters=counters,
            pgfault_per_second=rates[0],
            pgmajfault_per_second=rates[1],
            swap_in_bytes_per_second=rates[2],
            swap_out_bytes_per_second=rates[3],
            errors=errors,
        )

    def _rss(
        self, directory: Path
    ) -> tuple[list[ProcessObservation], Literal["complete", "partial", "unavailable"], list[str]]:
        try:
            pids = [
                int(value)
                for value in self._read(directory / "cgroup.procs", MAX_CGROUP_READ).split()
            ]
        except (OSError, ValueError, UnicodeError) as exc:
            return [], "unavailable", [f"cgroup_processes_{type(exc).__name__}"]
        partial = len(pids) > MAX_RSS_PROCESSES
        observations: list[ProcessObservation] = []
        for pid in sorted(pids)[:MAX_RSS_PROCESSES]:
            try:
                stat = parse_process_stat(
                    self._read(self.proc / str(pid) / "stat", MAX_CGROUP_READ)
                )
            except (OSError, ValueError, UnicodeError):
                partial = True
                continue
            observations.append(
                ProcessObservation(
                    identity=ProcessIdentity(pid=stat.pid, starttime_ticks=stat.starttime),
                    comm=stat.comm,
                    rss_bytes=stat.rss_pages * self.page_size,
                    configured=True,
                )
            )
        return (
            observations,
            "partial" if partial else "complete",
            ["process_inventory_partial"] if partial else [],
        )

    def _workload_once(self, path: str) -> WorkloadMemoryObservation:
        relative = path.lstrip("/")
        directory = self.cgroup_root / relative
        resolved_root = self.cgroup_root.resolve(strict=True)
        resolved = directory.resolve(strict=True)
        if resolved.parent != resolved_root and resolved_root not in resolved.parents:
            raise ValueError("cgroup escaped configured root")
        if resolved == resolved_root or resolved != directory.absolute():
            raise ValueError("cgroup path is not an exact non-root leaf")
        before_stat = os.stat(resolved, follow_symlinks=False)
        events_before = parse_memory_events(
            self._read(resolved / "memory.events.local", MAX_CGROUP_READ)
        )
        current = int(self._read(resolved / "memory.current", MAX_CGROUP_READ).strip())
        maximum, max_unlimited = parse_limit(self._read(resolved / "memory.max", MAX_CGROUP_READ))
        swap_current = int(self._read(resolved / "memory.swap.current", MAX_CGROUP_READ).strip())
        swap_max, swap_unlimited = parse_limit(
            self._read(resolved / "memory.swap.max", MAX_CGROUP_READ)
        )
        processes, inventory, process_errors = self._rss(resolved)
        events = parse_memory_events(self._read(resolved / "memory.events.local", MAX_CGROUP_READ))
        after_stat = os.stat(resolved, follow_symlinks=False)
        if (before_stat.st_dev, before_stat.st_ino) != (after_stat.st_dev, after_stat.st_ino):
            raise FileNotFoundError("cgroup generation changed during collection")
        if min(current, swap_current) < 0:
            raise ValueError("negative cgroup usage")
        stable = events_before == events
        return WorkloadMemoryObservation(
            cgroup_path=path,
            boot_id=self.boot_id,
            st_dev=after_stat.st_dev,
            st_ino=after_stat.st_ino,
            current_bytes=current,
            max_bytes=maximum,
            max_unlimited=max_unlimited,
            usage_ratio=current / maximum if maximum else None,
            swap_current_bytes=swap_current,
            swap_max_bytes=swap_max,
            swap_max_unlimited=swap_unlimited,
            events_before=events_before,
            events=events,
            events_stable=stable,
            processes=processes,
            process_inventory=inventory,
            errors=process_errors + ([] if stable else ["unstable_snapshot"]),
        )

    def _workload(self, path: str) -> WorkloadMemoryObservation:
        last: Exception | None = None
        for _ in range(2):
            try:
                observation = self._workload_once(path)
                if observation.events_stable:
                    return observation
                return observation
            except (OSError, UnicodeError, ValueError, ValidationError) as exc:
                last = exc
        assert last is not None
        # A missing resource has no defensible generation identity, so it is absent rather than zero-filled.
        raise last

    def collect(self, paths: tuple[str, ...] = ()) -> MemoryObservation:
        validate_cgroup_paths(",".join(paths))
        started = self.clock()
        host = self._host(started)
        workloads: list[WorkloadMemoryObservation] = []
        workload_errors: dict[str, list[str]] = {}
        for path in paths:
            try:
                workloads.append(self._workload(path))
            except FileNotFoundError:
                workload_errors[path] = ["cgroup_missing"]
            except PermissionError:
                workload_errors[path] = ["cgroup_permission_denied"]
            except (OSError, UnicodeError, ValueError, ValidationError) as exc:
                workload_errors[path] = ["cgroup_collection_" + type(exc).__name__]
        logs, coverage, log_errors = self._logs(paths)
        return MemoryObservation(
            host=host,
            workloads=workloads,
            kernel_logs=logs,
            kernel_log_coverage=coverage,
            kernel_log_errors=log_errors,
            workload_errors=workload_errors,
        )


def _worker(conn: Connection) -> None:
    collector = MemoryCollector()
    try:
        conn.send("ready")
        while True:
            configured = tuple(conn.recv())
            conn.send(collector.collect(configured).model_dump())
    except (EOFError, BrokenPipeError):
        pass
    finally:
        conn.close()


class MemoryCollectionWorker:
    def __init__(self, target: Callable[[Connection], None] = _worker) -> None:
        self.process: Any = None
        self.conn: Connection | None = None
        self.ready = False
        self.target = target

    def start(self) -> None:
        if self.process is not None:
            return
        context = mp.get_context("spawn")
        self.conn, child = context.Pipe()
        self.process = context.Process(target=self.target, args=(child,), daemon=True)
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

    @staticmethod
    def _failed(paths: tuple[str, ...], error: str) -> MemoryObservation:
        return MemoryObservation(
            host=HostMemoryObservation(errors=[error]),
            workload_errors={path: [error] for path in paths},
        )

    def collect(self, paths: tuple[str, ...] = (), budget: float = 0.75) -> MemoryObservation:
        if self.process is not None and self.conn is None:
            if self.process.is_alive():
                return self._failed(paths, "memory_collection_worker_stuck")
            self.process.close()
            self.process = None
        if not self.wait_ready():
            return self._failed(paths, "memory_collection_worker_starting")
        try:
            if self.conn is None:
                raise TimeoutError
            self.conn.send(paths)
            if not self.conn.poll(budget):
                raise TimeoutError
            return MemoryObservation.model_validate(self.conn.recv())
        except (TimeoutError, OSError, EOFError, ValidationError):
            self.close()
            return self._failed(paths, "memory_collection_timeout")
