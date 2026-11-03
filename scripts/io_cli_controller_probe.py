#!/usr/bin/env python3
"""Keep the normal one-shot I/O helper caller alive for interruption proof."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def write_ready(path: Path, value: dict[str, object]) -> None:
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                raise OSError("short CLI controller readiness write")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    args = parser.parse_args()
    result = subprocess.run(
        [
            sys.executable,
            os.fspath(args.helper),
            "start",
            args.token,
            "--duration",
            str(args.duration),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError(result.stderr[-2000:])
    record: dict[str, object] = json.loads(result.stdout)
    write_ready(args.ready, {"pid": os.getpid(), "record": record})
    signal.signal(signal.SIGTERM, lambda _signal, _frame: raise_exit())
    while True:
        time.sleep(1)


def raise_exit() -> None:
    raise SystemExit(0)


if __name__ == "__main__":
    main()
