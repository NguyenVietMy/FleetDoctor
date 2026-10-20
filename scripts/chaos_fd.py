#!/usr/bin/env python3
"""Bounded FD-pressure harness using the owned helper and ordinary FleetDoctor APIs."""

import argparse
import json
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from fd_harness import FdHarness

INSTALLED_HELPER = Path("/usr/local/sbin/fleetdoctor-fd-resource")


class HttpBackend:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url, self.token = base_url.rstrip("/"), token

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.base_url + path + (("?" + urlencode(params)) if params else "")
        request = Request(url, headers={"Authorization": "Bearer " + self.token})
        with urlopen(request, timeout=2) as response:
            return cast(dict[str, Any], json.load(response))


class Helper:
    def __init__(
        self,
        path: Path,
        *,
        prepared: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.path, self.prepared, self.monotonic = path, prepared, monotonic

    def call(self, action: str, token: str, *extra: str) -> dict[str, Any]:
        command = (
            ["sudo", str(self.path)]
            if self.path == INSTALLED_HELPER
            else ["sudo", sys.executable, str(self.path)]
        )
        result = subprocess.run(
            [*command, action, "--token", token, *extra],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("FD helper " + action + " failed")
        return cast(dict[str, Any], json.loads(result.stdout))

    def start(self, token: str, limit: int, seconds: int) -> dict[str, Any]:
        if self.prepared:
            value = self.status(token)
            remaining = float(value.get("seconds", 0)) - (
                self.monotonic() - float(value.get("started_monotonic", 0))
            )
            if (
                value.get("state") != "active"
                or value.get("phase") != "prepared"
                or int(value.get("limit", 0)) != limit
                or remaining < 90
            ):
                raise RuntimeError(
                    "prepared FD worker must be the same low-count identity with at least 90 seconds left"
                )
            return value
        return self.call("start", token, "--limit", str(limit), "--seconds", str(seconds))

    def status(self, token: str) -> dict[str, Any]:
        return self.call("status", token)

    def pressure(self, token: str) -> dict[str, Any]:
        return self.call("pressure", token)

    def release(self, token: str) -> dict[str, Any]:
        return self.call("release", token)

    def cleanup(self, token: str) -> dict[str, Any]:
        return self.call("cleanup", token)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url")
    parser.add_argument("--api-token")
    parser.add_argument("--node")
    parser.add_argument("--reference-node")
    parser.add_argument("--mode", choices=("release", "exit"))
    parser.add_argument("--limit", type=int, default=128)
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--helper", type=Path, default=INSTALLED_HELPER)
    parser.add_argument("--prepared-token", required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("refusing to overwrite FD CLI report")
    if args.prepare_only:
        prepared = Helper(args.helper).start(
            args.prepared_token,
            args.limit,
            args.seconds,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")
        return
    if not all((args.base_url, args.api_token, args.node, args.reference_node, args.mode)):
        parser.error(
            "run mode requires --base-url, --api-token, --node, --reference-node, and --mode"
        )
    FdHarness(
        HttpBackend(cast(str, args.base_url), cast(str, args.api_token)),
        Helper(args.helper, prepared=True),
        cast(str, args.node),
        cast(str, args.reference_node),
        args.output,
        environment={
            "scope": "operator-supplied target/reference nodes",
            "reference_isolation": "must be established by operator",
            "prepared_identity": "ordinary FLEETDOCTOR_CPU_PIDS configuration required",
        },
        token=args.prepared_token,
    ).run(cast(Literal["release", "exit"], args.mode), args.limit)


if __name__ == "__main__":
    main()
