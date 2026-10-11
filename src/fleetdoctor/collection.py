"""A single long-lived spawned worker bounds potentially blocking statvfs calls."""

import multiprocessing as mp
import os
import time
from collections.abc import Callable
from multiprocessing.connection import Connection
from typing import Any

from pydantic import ValidationError

from fleetdoctor.schema import Filesystem


def from_statvfs(path: str, values: dict[str, int]) -> Filesystem:
    errors: list[str] = []
    blocks: dict[str, Any] = {}
    inodes: dict[str, Any] = {}
    try:
        total, free, available = (
            values[key] * values["f_frsize"] for key in ("f_blocks", "f_bfree", "f_bavail")
        )
        if values["f_frsize"] <= 0 or not 0 <= available <= free <= total:
            raise ValueError
        used = total - free
        blocks = dict(
            total_bytes=total,
            free_bytes=free,
            available_bytes=available,
            used_bytes=used,
            block_usage_percent=100 * used / (used + available) if used + available else None,
        )
        if used + available == 0:
            errors.append("block_capacity_unavailable")
    except (KeyError, ValueError):
        errors.append("invalid_block_counters")
    try:
        total_i, free_i = values["f_files"], values["f_ffree"]
        if not 0 <= free_i <= total_i:
            raise ValueError
        inodes = dict(
            inodes_total=total_i,
            inodes_free=free_i,
            inode_usage_percent=100 * (total_i - free_i) / total_i if total_i else None,
        )
        if not total_i:
            errors.append("inode_capacity_unavailable")
    except (KeyError, ValueError):
        errors.append("invalid_inode_counters")
    return Filesystem(mountpoint=path, errors=errors, **blocks, **inodes)


def _worker(conn: Connection) -> None:
    try:
        conn.send("ready")
        while True:
            path = conn.recv()
            try:
                stat = os.statvfs(path)
                values = {
                    key: int(getattr(stat, key))
                    for key in ("f_frsize", "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree")
                }
                fs = from_statvfs(path, values)
            except (OSError, ValueError, ValidationError) as exc:
                fs = Filesystem(mountpoint=path, errors=[f"statvfs_{type(exc).__name__}"])
            conn.send(fs.model_dump())
    except (EOFError, BrokenPipeError):
        pass
    finally:
        conn.close()


class CollectionWorker:
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

    def collect(self, paths: tuple[str, ...], budget: float = 1.0) -> list[Filesystem]:
        deadline = time.monotonic() + budget
        if self.process is not None and self.conn is None:
            if self.process.is_alive():
                return [Filesystem(mountpoint=p, errors=["collection_worker_stuck"]) for p in paths]
            self.process.close()
            self.process = None
        if not self.wait_ready():
            return [Filesystem(mountpoint=p, errors=["collection_worker_starting"]) for p in paths]
        result: list[Filesystem] = []
        for path in paths:
            try:
                if self.conn is None:
                    raise TimeoutError
                self.conn.send(path)
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self.conn.poll(
                    remaining / max(1, len(paths) - len(result))
                ):
                    raise TimeoutError
                result.append(Filesystem.model_validate(self.conn.recv()))
            except (TimeoutError, OSError, EOFError):
                result.append(Filesystem(mountpoint=path, errors=["collection_timeout"]))
                self.close()
        return result
