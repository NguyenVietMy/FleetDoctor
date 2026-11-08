"""Run the bounded I/O harness against the fixed local helper and real FleetDoctor API."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
from io_harness import IoHarness

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "io_resource.py"


class HttpAPI:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = httpx.get(self.url + path, params=params, timeout=3, trust_env=False)
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        return result


class LocalInjector:
    def call(self, action: str, token: str, duration: int | None = None) -> dict[str, Any]:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise PermissionError("run chaos_io under an already authorized root execution context")
        command = [os.fspath(Path(sys.executable)), os.fspath(HELPER), action, token]
        if duration is not None:
            command.extend(("--duration", str(duration)))
        result = subprocess.run(command, capture_output=True, text=True, timeout=150)
        if result.returncode:
            raise RuntimeError(result.stderr[-2000:])
        value: dict[str, Any] = json.loads(result.stdout)
        return value

    def start(self, token: str, duration: int) -> dict[str, Any]:
        return self.call("start", token, duration)

    def status(self, token: str) -> dict[str, Any]:
        return self.call("status", token)

    def cleanup(self, token: str) -> dict[str, Any]:
        return self.call("cleanup", token)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = IoHarness(HttpAPI(args.api), LocalInjector(), args.token, args.output).run()
    raise SystemExit(0 if result["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
