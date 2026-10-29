#!/usr/bin/env python3
"""Test-only stopped-parent barriers for the native DNS helper proof."""

from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
import dns_resource as helper  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token", required=True)
    parser.add_argument(
        "--barrier",
        required=True,
        choices=(
            "before_identity",
            "after_armed",
            "before_publication",
            "after_publication",
            "regular_partial",
            "symlink_unlinked",
        ),
    )
    args = parser.parse_args()
    barrier_path = helper.RUNS / f"{args.token}.{args.barrier}.barrier.json"
    original_process_identity = helper.process_identity
    original_wait_line = helper._wait_line
    helper_os: Any = helper.__dict__["os"]
    original_link = helper_os.link
    original_write = helper._write_regular
    stopped = False

    def stop(extra: dict[str, Any] | None = None) -> None:
        nonlocal stopped
        if stopped:
            return
        stopped = True
        record = helper.load(helper.run_path(args.token))
        parent = original_process_identity(os.getpid())
        if parent is None:
            raise RuntimeError("driver identity unavailable at interruption barrier")
        value: dict[str, Any] = {
            "barrier": args.barrier,
            "token": args.token,
            "driver": parent,
            "record_phase": record.get("phase"),
            "watchdog": record.get("watchdog"),
        }
        if extra:
            value.update(extra)
        helper.save(barrier_path, value)
        os.kill(os.getpid(), signal.SIGSTOP)

    def identity(pid: int) -> dict[str, int | str] | None:
        value = original_process_identity(pid)
        if args.barrier == "before_identity" and pid != os.getpid() and value is not None:
            stop({"watchdog": value})
        return value

    def wait_line(fd: int, expected: bytes, deadline: float) -> None:
        original_wait_line(fd, expected, deadline)
        if args.barrier == "after_armed" and expected == b"ARMED\n":
            stop()

    def link(source: str | bytes | Path, destination: str | bytes | Path, *values: Any) -> None:
        destination_path = Path(os.fsdecode(destination))
        if args.barrier == "before_publication" and destination_path == helper.LEASE:
            stop()
        original_link(source, destination, *values)
        if args.barrier == "after_publication" and destination_path == helper.LEASE:
            stop()

    def write_regular(content: bytes, metadata: dict[str, Any]) -> None:
        if args.barrier == "regular_partial":
            fd = os.open(
                helper.RESOLV_CONF,
                os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW,
            )
            try:
                if os.write(fd, content[:7]) != 7:
                    raise OSError("short test-only resolver prefix write")
                os.fsync(fd)
            finally:
                os.close(fd)
            stop({"partial_bytes": 7})
        elif args.barrier == "symlink_unlinked":
            if not helper.RESOLV_CONF.is_symlink():
                raise RuntimeError("symlink interruption requires symlink layout")
            helper.RESOLV_CONF.unlink()
            helper._fsync_directory(helper.RESOLV_CONF.parent)
            stop({"entry_missing": not helper.RESOLV_CONF.exists()})
        original_write(content, metadata)

    helper.process_identity = identity
    helper._wait_line = wait_line
    helper_os.link = link
    helper._write_regular = write_regular
    helper.start(args.token, os.environ["DNS_INVALID_RESOLVER"], 30)
    raise RuntimeError("test driver passed its required interruption barrier")


if __name__ == "__main__":
    main()
