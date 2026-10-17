#!/usr/bin/env python3
"""Root-owned controller for one bounded transient CPU workload unit."""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

STATE_ROOT = Path("/run/fleetdoctor-cpu")
TOKEN = re.compile(r"^[a-f0-9]{16,64}$")
USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
MAX_WORKERS = 64
MAX_SECONDS = 180
STATE_OWNER_UID = 0


def unit_name(token: str) -> str:
    if not TOKEN.fullmatch(token):
        raise ValueError("token must be 16..64 lowercase hexadecimal characters")
    return "fleetdoctor-cpu-" + token[:32] + ".service"


def state_path(token: str) -> Path:
    return STATE_ROOT / (token + ".json")


def command(argv: list[str], timeout: float = 8) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)


def trusted_state(token: str) -> dict[str, Any] | None:
    path = state_path(token)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, encoding="utf-8") as stream:
        stat = os.fstat(stream.fileno())
        if os.name == "posix" and (stat.st_uid != STATE_OWNER_UID or stat.st_mode & 0o077):
            raise ValueError("untrusted CPU helper state")
        record: dict[str, Any] = json.load(stream)
    if record.get("token") != token or record.get("unit") != unit_name(token):
        raise ValueError("CPU helper state identity mismatch")
    return record


def show(unit: str) -> dict[str, str]:
    result = command(
        [
            "systemctl",
            "show",
            unit,
            "--property=Id,LoadState,ActiveState,SubState,InvocationID,ControlGroup,User",
        ]
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("systemctl status unavailable")
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def validate_live(record: dict[str, Any], status: dict[str, str]) -> None:
    if status.get("Id") != record["unit"]:
        raise ValueError("transient unit identity mismatch")
    invocation = status.get("InvocationID")
    if invocation and invocation != record["invocation_id"]:
        raise ValueError("transient unit was replaced")
    control_group = status.get("ControlGroup", "")
    if control_group and control_group != record["control_group"]:
        raise ValueError("transient cgroup was replaced")
    if status.get("User") and status["User"] != record["worker_user"]:
        raise ValueError("transient worker identity was replaced")


def write_state(path: Path, record: dict[str, Any]) -> None:
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def start(
    token: str, workers: int, seconds: int, worker_user: str = "fleetdoctor"
) -> dict[str, Any]:
    unit = unit_name(token)
    if not 1 <= workers <= MAX_WORKERS or not 1 <= seconds <= MAX_SECONDS:
        raise ValueError("workers must be 1..64 and seconds 1..180")
    if not USER.fullmatch(worker_user) or worker_user == "root":
        raise ValueError("worker user must be a bounded unprivileged account name")
    if trusted_state(token) is not None or show(unit).get("LoadState") not in (None, "not-found"):
        raise ValueError("owned CPU workload already exists")
    script_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result = command(
        [
            "systemd-run",
            "--unit=" + unit.removesuffix(".service"),
            "--collect",
            "--uid=" + worker_user,
            "--nice=10",
            "--property=RuntimeMaxSec=" + str(seconds),
            "--property=KillMode=control-group",
            "--property=TasksMax=" + str(workers + 4),
            "--property=MemoryMax=256M",
            "--property=NoNewPrivileges=yes",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=yes",
            sys.executable,
            str(Path(__file__).resolve()),
            "worker",
            "--workers",
            str(workers),
            "--seconds",
            str(seconds),
        ],
        timeout=10,
    )
    if result.returncode:
        raise RuntimeError("failed to create transient CPU unit")
    status = show(unit)
    if not status.get("InvocationID") or not status.get("ControlGroup"):
        command(["systemctl", "stop", unit])
        raise RuntimeError("transient CPU unit lacks ownership identity")
    record = {
        "token": token,
        "unit": unit,
        "invocation_id": status["InvocationID"],
        "control_group": status["ControlGroup"],
        "workers": workers,
        "seconds": seconds,
        "worker_user": worker_user,
        "script_sha256": script_hash,
        "started_monotonic": time.monotonic(),
    }
    try:
        write_state(state_path(token), record)
    except BaseException:
        command(["systemctl", "stop", unit], timeout=15)
        raise
    return record | {"status": status}


def status(token: str) -> dict[str, Any]:
    record = trusted_state(token)
    if record is None:
        return {"token": token, "state": "absent", "owned": False}
    current = show(record["unit"])
    validate_live(record, current)
    return record | {
        "state": current.get("ActiveState", "unknown"),
        "status": current,
        "owned": True,
    }


def cleanup(token: str) -> dict[str, Any]:
    record = trusted_state(token)
    if record is None:
        return {"token": token, "state": "absent", "owned": False, "cleaned": True}
    current = show(record["unit"])
    validate_live(record, current)
    if current.get("LoadState") != "not-found":
        result = command(["systemctl", "stop", record["unit"]], timeout=15)
        if result.returncode:
            raise RuntimeError("owned transient CPU unit did not stop")
    state_path(token).unlink()
    return {"token": token, "unit": record["unit"], "owned": True, "cleaned": True}


def burn(seconds: int) -> None:
    deadline = time.monotonic() + seconds
    value = 1
    while time.monotonic() < deadline:
        value = (value * 48271) % 2_147_483_647


def worker(workers: int, seconds: int) -> None:
    children: list[subprocess.Popen[bytes]] = []
    stopped = False

    def stop(signum: int, frame: object) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for _ in range(workers - 1):
            children.append(subprocess.Popen(["/bin/sh", "-c", "while :; do :; done"]))
        deadline = time.monotonic() + seconds
        value = 1
        while not stopped and time.monotonic() < deadline:
            value = (value * 48271) % 2_147_483_647
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("start", "status", "cleanup"):
        item = sub.add_parser(action)
        item.add_argument("--token", required=True)
        if action == "start":
            item.add_argument("--workers", type=int, required=True)
            item.add_argument("--seconds", type=int, required=True)
            item.add_argument("--worker-user", default="fleetdoctor")
    worker_parser = sub.add_parser("worker")
    worker_parser.add_argument("--workers", type=int, required=True)
    worker_parser.add_argument("--seconds", type=int, required=True)
    burn_parser = sub.add_parser("burn")
    burn_parser.add_argument("--seconds", type=int, required=True)
    args = parser.parse_args()
    if args.action == "worker":
        worker(args.workers, args.seconds)
        return
    if args.action == "burn":
        burn(args.seconds)
        return
    if os.geteuid() != 0:
        raise PermissionError("CPU controller must run as root")
    if args.action == "start":
        result = start(args.token, args.workers, args.seconds, args.worker_user)
    elif args.action == "status":
        result = status(args.token)
    else:
        result = cleanup(args.token)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
