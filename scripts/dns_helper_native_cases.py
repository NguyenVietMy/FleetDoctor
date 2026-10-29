#!/usr/bin/env python3
"""Inside-container fixed-path DNS helper lifecycle and interruption proof."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy/dns_resource.py"
DRIVER = ROOT / "scripts/dns_helper_interruption_driver.py"
HOSTNAME = "baseline.fleetdoctor.test."
INVALID_RESOLVER = os.environ["DNS_INVALID_RESOLVER"]


def identity(pid: int) -> dict[str, Any] | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()
        return {
            "pid": pid,
            "starttime": int(fields[19]),
            "proc_state": fields[0],
            "argv_sha256": hashlib.sha256(Path(f"/proc/{pid}/cmdline").read_bytes()).hexdigest(),
        }
    except (FileNotFoundError, IndexError, OSError, ValueError):
        return None


def retained_state(expected: dict[str, Any]) -> dict[str, Any]:
    current = identity(int(expected["pid"]))
    exact = bool(
        current is not None
        and current.get("pid") == expected.get("pid")
        and current.get("starttime") == expected.get("starttime")
    )
    return {"exact_identity_present": exact, "current": current}


def wait_absent(expected: dict[str, Any], timeout: float = 8) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout
    while True:
        state = retained_state(expected)
        observations.append(state)
        if not state["exact_identity_present"]:
            return observations
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"retained PID/start was not reaped (zombie is not absence): {observations[-1]}"
            )
        time.sleep(0.05)


def helper(action: str, token: str, duration: int = 30) -> dict[str, Any]:
    argv = [sys.executable, str(HELPER), action, "--token", token]
    if action == "start":
        argv += ["--invalid-resolver", INVALID_RESOLVER, "--duration", str(duration)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError(
            f"helper {action} failed rc={result.returncode}: {result.stderr[-1000:]}"
        )
    value: dict[str, Any] = json.loads(result.stdout)
    return value


def exact_entry() -> dict[str, Any]:
    entry = Path("/etc/resolv.conf").lstat()
    content = Path("/etc/resolv.conf").read_bytes()
    return {
        "type": "symlink" if stat.S_ISLNK(entry.st_mode) else "regular",
        "link_target": os.readlink("/etc/resolv.conf") if stat.S_ISLNK(entry.st_mode) else None,
        "uid": entry.st_uid,
        "gid": entry.st_gid,
        "mode": stat.S_IMODE(entry.st_mode),
        "device": entry.st_dev,
        "inode": entry.st_ino,
        "links": entry.st_nlink,
        "sha256": hashlib.sha256(content).hexdigest(),
        "bytes": content.decode("ascii"),
    }


def restored(before: dict[str, Any], after: dict[str, Any]) -> bool:
    ignored = {"device", "inode"} if before.get("type") == "symlink" else set()
    return {key: value for key, value in before.items() if key not in ignored} == {
        key: value for key, value in after.items() if key not in ignored
    }


def wait_record(token: str, timeout: float = 8) -> dict[str, Any]:
    path = Path(f"/run/fleetdoctor/dns/runs/{token}.json")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict) and value.get("cleanup_complete"):
                return value
        time.sleep(0.05)
    raise TimeoutError(f"helper cleanup record did not complete for {token}")


def ordinary_query() -> dict[str, Any]:
    account = pwd.getpwnam("fleetdoctor")

    def demote() -> None:
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)

    code = (
        "from fleetdoctor.dns import DnsCollector;"
        f"print(DnsCollector().collect({HOSTNAME!r},'127.0.0.1').model_dump_json())"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        preexec_fn=demote,
    )
    if result.returncode:
        raise RuntimeError(result.stderr[-1000:])
    value: dict[str, Any] = json.loads(result.stdout)
    value["uid"] = account.pw_uid
    value["gid"] = account.pw_gid
    return value


def normal_case(label: str, *, duration: int = 30) -> dict[str, Any]:
    token = uuid4().hex
    before = exact_entry()
    started = helper("start", token, duration)
    watchdog = started["watchdog"]
    live = retained_state(watchdog)
    if not live["exact_identity_present"] or live["current"].get("proc_state") == "Z":
        raise RuntimeError("normal active helper did not retain its live watchdog")
    active = exact_entry()
    query = ordinary_query()
    if query["resolver"]["status"] != "available" or query["query"]["status"] != "failure":
        raise RuntimeError("ordinary UID10001 did not observe a measured DNS failure")
    cleaned = helper("cleanup", token)
    after = exact_entry()
    reaping = wait_absent(watchdog)
    if not restored(before, after) or not cleaned.get("cleanup_complete"):
        raise RuntimeError("normal helper case did not restore the exact fixed entry")
    return {
        "label": label,
        "token": token,
        "before": before,
        "active": active,
        "ordinary_uid10001": query,
        "watchdog_live_until_cleanup": live,
        "cleanup": cleaned,
        "watchdog_reaping": reaping,
        "after": after,
        "exactly_restored": True,
    }


def interrupted_case(barrier: str, termination_signal: int = signal.SIGKILL) -> dict[str, Any]:
    token = uuid4().hex
    before = exact_entry()
    driver = subprocess.Popen(
        [sys.executable, str(DRIVER), "--token", token, "--barrier", barrier],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    barrier_path = Path(f"/run/fleetdoctor/dns/runs/{token}.{barrier}.barrier.json")
    reached: dict[str, Any] | None = None
    try:
        deadline = time.monotonic() + 8
        while not barrier_path.exists() and time.monotonic() < deadline:
            if driver.poll() is not None:
                stdout, stderr = driver.communicate()
                raise RuntimeError(
                    f"interruption driver exited before {barrier}: {stdout[-500:]} {stderr[-1000:]}"
                )
            time.sleep(0.05)
        if not barrier_path.exists():
            raise TimeoutError(f"interruption driver did not reach {barrier}")
        reached = json.loads(barrier_path.read_text(encoding="utf-8"))
        expected_driver = reached["driver"]
        stop_deadline = time.monotonic() + 2
        while True:
            observed_driver = retained_state(expected_driver)
            if observed_driver["exact_identity_present"] and observed_driver["current"].get(
                "proc_state"
            ) in {"T", "t"}:
                break
            if time.monotonic() >= stop_deadline:
                raise RuntimeError("interruption driver exact stopped identity was not proved")
            time.sleep(0.01)
        os.kill(driver.pid, termination_signal)
        if termination_signal == signal.SIGTERM:
            os.kill(driver.pid, signal.SIGCONT)
        driver.wait(timeout=3)
        driver_reaping = wait_absent(expected_driver)
        completed = wait_record(token)
        watchdog = reached.get("watchdog") or completed.get("watchdog")
        if not isinstance(watchdog, dict):
            raise RuntimeError("interruption did not retain exact watchdog identity")
        watchdog_reaping = wait_absent(watchdog)
        after = exact_entry()
        if not restored(before, after) or Path("/run/fleetdoctor/dns/lease.json").exists():
            raise RuntimeError("interrupted helper did not converge to the exact prestate")
        retry = normal_case("distinct-token-retry-after-" + barrier)
        return {
            "barrier": reached,
            "termination_signal": signal.Signals(termination_signal).name,
            "driver_identity_before_kill": observed_driver,
            "driver_reaping": driver_reaping,
            "watchdog_reaping": watchdog_reaping,
            "completed": completed,
            "before": before,
            "after": after,
            "exactly_restored": True,
            "distinct_token_retry": retry,
        }
    finally:
        if driver.poll() is None:
            driver.kill()
            driver.wait(timeout=3)
        if reached is not None:
            try:
                wait_record(token)
            except (OSError, TimeoutError, ValueError):
                pass


def lock_contention_case() -> dict[str, Any]:
    token = uuid4().hex
    before = exact_entry()
    code = (
        "import sys,time\n"
        f"sys.path.insert(0,{str(HELPER.parent)!r})\n"
        "import dns_resource as helper\n"
        "helper.safe_base()\n"
        "with helper.locked():\n"
        " print('LOCKED',flush=True)\n"
        " time.sleep(10)\n"
    )
    holder = subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    expected = identity(holder.pid)
    if expected is None or holder.stdout is None or holder.stdout.readline().strip() != "LOCKED":
        stdout, stderr = holder.communicate(timeout=3)
        raise RuntimeError(f"lock holder failed: {stdout[-500:]} {stderr[-1000:]}")
    started = time.monotonic()
    attempted = subprocess.run(
        [
            sys.executable,
            str(HELPER),
            "start",
            "--token",
            token,
            "--invalid-resolver",
            INVALID_RESOLVER,
            "--duration",
            "30",
        ],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    elapsed = time.monotonic() - started
    holder.terminate()
    holder.wait(timeout=3)
    reaping = wait_absent(expected)
    after = exact_entry()
    if (
        attempted.returncode == 0
        or "lock deadline exceeded" not in attempted.stderr
        or not 1.8 <= elapsed <= 3.0
        or not restored(before, after)
        or Path("/run/fleetdoctor/dns/lease.json").exists()
        or Path(f"/run/fleetdoctor/dns/runs/{token}.json").exists()
    ):
        raise RuntimeError("bounded lock contention proof failed")
    return {
        "token": token,
        "holder": expected,
        "holder_reaping": reaping,
        "attempt_returncode": attempted.returncode,
        "attempt_stderr": attempted.stderr[-1000:],
        "elapsed_seconds": elapsed,
        "before": before,
        "after": after,
        "resolver_unchanged": True,
        "lease_absent": True,
        "run_record_absent": True,
    }


def foreign_cases() -> dict[str, Any]:
    resolver = Path("/etc/resolv.conf")
    token = uuid4().hex
    before = exact_entry()
    started = helper("start", token)
    injected = resolver.read_bytes()
    resolver.write_bytes(b"nameserver 198.51.100.9\n")
    refused = subprocess.run(
        [sys.executable, str(HELPER), "cleanup", "--token", token],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if refused.returncode == 0 or resolver.read_bytes() != b"nameserver 198.51.100.9\n":
        raise RuntimeError("foreign resolver state was not refused before mutation")
    resolver.write_bytes(injected)
    cleaned = helper("cleanup", token)
    wait_absent(started["watchdog"])

    token2 = uuid4().hex
    started2 = helper("start", token2)
    lease = Path("/run/fleetdoctor/dns/lease.json")
    owned_lease = lease.read_bytes()
    lease.write_text('{"complete":true,"token":"' + ("f" * 32) + '"}', encoding="utf-8")
    active_before_refusal = resolver.read_bytes()
    refused_lease = subprocess.run(
        [sys.executable, str(HELPER), "cleanup", "--token", token2],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if refused_lease.returncode == 0 or resolver.read_bytes() != active_before_refusal:
        raise RuntimeError("foreign lease was not refused before resolver mutation")
    lease.write_bytes(owned_lease)
    cleaned2 = helper("cleanup", token2)
    wait_absent(started2["watchdog"])
    if not restored(before, exact_entry()):
        raise RuntimeError("foreign-state cases did not restore the original resolver")
    return {
        "resolver_change": {
            "returncode": refused.returncode,
            "stderr": refused.stderr[-1000:],
            "cleanup": cleaned,
        },
        "lease_change": {
            "returncode": refused_lease.returncode,
            "stderr": refused_lease.stderr[-1000:],
            "cleanup": cleaned2,
        },
        "exactly_restored": True,
    }


def deadline_case() -> dict[str, Any]:
    token = uuid4().hex
    before = exact_entry()
    started = helper("start", token, 2)
    completed = wait_record(token, 8)
    reaping = wait_absent(started["watchdog"])
    if not restored(before, exact_entry()) or completed.get("cleanup_reason") != "deadline":
        raise RuntimeError("deadline watchdog did not restore exact resolver state")
    return {"start": started, "completed": completed, "watchdog_reaping": reaping}


def use_symlink_layout() -> dict[str, Any]:
    mount_before = subprocess.run(
        ["findmnt", "-J", "-T", "/etc/resolv.conf"],
        capture_output=True,
        text=True,
        check=False,
    )
    unmounted = subprocess.run(
        ["umount", "/etc/resolv.conf"], capture_output=True, text=True, check=False
    )
    if unmounted.returncode:
        raise RuntimeError(f"owned resolver bind unmount failed: {unmounted.stderr[-500:]}")
    resolver = Path("/etc/resolv.conf")
    if resolver.exists() or resolver.is_symlink():
        resolver.unlink()
    target = Path("/run/fleetdoctor-native-symlink-target.conf")
    target.write_text("nameserver 127.0.0.11\noptions edns0\n", encoding="ascii")
    target.chmod(0o644)
    target_before = {
        "identity": identity_for_path(target),
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    }
    resolver.symlink_to(target)
    return {
        "findmnt_before": json.loads(mount_before.stdout) if mount_before.returncode == 0 else None,
        "unmount_returncode": unmounted.returncode,
        "target": str(target),
        "target_before": target_before,
    }


def identity_for_path(path: Path) -> dict[str, Any]:
    value = path.stat(follow_symlinks=False)
    return {
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode),
        "device": value.st_dev,
        "inode": value.st_ino,
        "links": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def main() -> None:
    report: dict[str, Any] = {
        "status": "failed",
        "uid": os.getuid(),
        "gid": os.getgid(),
        "pid1": Path("/proc/1/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace"),
        "docker_resolv_conf_path": os.environ.get("DNS_DOCKER_RESOLV_PATH"),
        "cases": {},
    }
    try:
        report["initial_regular_bind"] = exact_entry()
        report["cases"]["normal_regular_bind"] = normal_case("normal-regular-bind")
        report["cases"]["foreign_state"] = foreign_cases()
        report["cases"]["deadline"] = deadline_case()
        report["cases"]["bounded_lock_contention"] = lock_contention_case()
        for barrier in (
            "before_identity",
            "after_armed",
            "before_publication",
            "after_publication",
            "regular_partial",
        ):
            report["cases"][barrier] = interrupted_case(barrier)
        report["cases"]["sigterm_regular_partial"] = interrupted_case(
            "regular_partial", signal.SIGTERM
        )
        report["symlink_layout"] = use_symlink_layout()
        report["cases"]["normal_symlink"] = normal_case("normal-symlink")
        report["cases"]["symlink_unlinked"] = interrupted_case("symlink_unlinked")
        target = Path(report["symlink_layout"]["target"])
        target_after = {
            "identity": identity_for_path(target),
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        }
        report["symlink_layout"]["target_after"] = target_after
        report["symlink_layout"]["target_unchanged"] = (
            target_after == report["symlink_layout"]["target_before"]
        )
        if not report["symlink_layout"]["target_unchanged"]:
            raise RuntimeError("helper changed original symlink target")
        report["status"] = "passed"
    except BaseException as exc:
        report["error"] = f"{type(exc).__name__}:{exc}"
    finally:
        lease = Path("/run/fleetdoctor/dns/lease.json")
        if lease.exists():
            try:
                lease_value = json.loads(lease.read_text(encoding="utf-8"))
                cleanup_token = lease_value.get("token")
                if isinstance(cleanup_token, str):
                    report["failure_cleanup"] = helper("cleanup", cleanup_token)
            except BaseException as cleanup_exc:
                report["failure_cleanup_error"] = f"{type(cleanup_exc).__name__}:{cleanup_exc}"
        report["final_cleanup"] = {
            "lease_absent": not lease.exists(),
            "resolver": exact_entry() if Path("/etc/resolv.conf").exists() else None,
        }
        if not report["final_cleanup"]["lease_absent"]:
            report["status"] = "failed"
        print(json.dumps(report, sort_keys=True), flush=True)
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
