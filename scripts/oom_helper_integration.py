#!/usr/bin/env python3
"""Native systemd proof for OOM helper expiry, interruption, and idempotent cleanup."""

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def command(argv: list[str], timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)


def helper(script: Path, action: str, token: str, *extra: str) -> dict[str, Any]:
    result = command([sys.executable, str(script), action, "--token", token, *extra])
    if result.returncode:
        raise RuntimeError(f"helper {action} failed: {(result.stderr or result.stdout)[-1000:]}")
    value: dict[str, Any] = json.loads(result.stdout)
    return value


def helper_failure(script: Path, action: str, token: str, *extra: str) -> str:
    result = command([sys.executable, str(script), action, "--token", token, *extra])
    if result.returncode == 0:
        raise RuntimeError(f"helper {action} unexpectedly succeeded")
    return (result.stderr or result.stdout)[-2000:]


def signal_prelaunch(script: Path, token: str) -> str:
    process = subprocess.Popen(
        [
            sys.executable,
            str(script),
            "prepare",
            "--token",
            token,
            "--lease-seconds",
            "15",
            "--expiry-probe",
            "--proof-fault",
            "prelaunch_signal_wait",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    state = Path("/run/fleetdoctor-oom") / (token + ".json")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not state.exists() and process.poll() is None:
        time.sleep(0.02)
    if not state.exists() or process.poll() is not None:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
        raise RuntimeError(
            "signal proof did not reach protected starting state: " + (stderr or stdout)[-1000:]
        )
    process.terminate()
    stdout, stderr = process.communicate(timeout=10)
    if process.returncode == 0 or "SIGTERM" not in stderr:
        raise RuntimeError("SIGTERM prepare proof did not report a protected interruption")
    return (stderr or stdout)[-2000:]


def wait_expired(script: Path, token: str, deadline: float) -> dict[str, Any]:
    while time.monotonic() < deadline:
        value = helper(script, "status", token)
        if value.get("state") == "absent":
            return value
        time.sleep(0.1)
    raise TimeoutError("owned transient resource did not expire after controller-independent limit")


def assert_identity_and_headroom(value: dict[str, Any], script_sha256: str, boot_id: str) -> None:
    if value.get("script_sha256") != script_sha256 or value.get("boot_id") != boot_id:
        raise RuntimeError("prepared resource did not bind source and boot identity")
    if int(value.get("available_memory_before", 0)) < 512 * 1024 * 1024:
        raise RuntimeError("prepared resource did not prove required host headroom")


def assert_removed(token: str, leaf_path: str) -> dict[str, Any]:
    state_root = Path("/run/fleetdoctor-oom")
    state = state_root / (token + ".json")
    gate = state_root / (token + ".gate")
    leaf = Path("/sys/fs/cgroup") / leaf_path.lstrip("/")
    if state.exists() or gate.exists() or leaf.exists():
        raise RuntimeError("automatic cleanup retained state, gate, or workload cgroup")
    return {"state_removed": True, "gate_removed": True, "leaf_removed": True}


def wait_partial_removed(token: str, control_group: str | None = None) -> dict[str, Any]:
    state_root = Path("/run/fleetdoctor-oom")
    state = state_root / (token + ".json")
    gate = state_root / (token + ".gate")
    cgroup = Path("/sys/fs/cgroup") / control_group.lstrip("/") if control_group else None
    unit = "fleetdoctor-oom-" + token[:32] + ".service"
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        shown = command(
            ["systemctl", "show", unit, "--property=LoadState,ActiveState,ControlGroup"],
            timeout=5,
        )
        fields = dict(line.split("=", 1) for line in shown.stdout.splitlines() if "=" in line)
        inactive = fields.get("LoadState") == "not-found" or fields.get("ActiveState") in (
            "inactive",
            "failed",
        )
        if (
            not state.exists()
            and not gate.exists()
            and (cgroup is None or not cgroup.exists())
            and inactive
        ):
            return {
                "state_removed": True,
                "gate_removed": True,
                "cgroup_removed": cgroup is None or not cgroup.exists(),
                "unit_inactive": True,
            }
        time.sleep(0.1)
    raise RuntimeError("partial preparation cleanup retained unit, cgroup, state, or gate")


def retry_same_token(script: Path, token: str) -> dict[str, Any]:
    prepared = helper(script, "prepare", token, "--lease-seconds", "2", "--expiry-probe")
    expired = wait_expired(script, token, time.monotonic() + 10)
    removed = assert_removed(token, str(prepared["leaf_path"]))
    return {"prepared": prepared, "expired": expired, "removed": removed}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("refusing to overwrite helper proof report")
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("OOM helper integration requires root Linux systemd")
    script = Path(__file__).resolve().parents[1] / "deploy/memory_resource.py"
    tokens = {
        name: secrets.token_hex(16)
        for name in (
            "expiry",
            "interrupt",
            "repeat",
            "prelaunch",
            "prelaunch_signal",
            "early_exit",
            "not_ready",
            "cleanup_retry",
        )
    }
    report: dict[str, Any] = {
        "status": "failed",
        "script": str(script),
        "script_sha256": __import__("hashlib").sha256(script.read_bytes()).hexdigest(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "proofs": {},
        "cleanup": {},
    }
    failure: BaseException | None = None
    try:
        expiry = helper(
            script, "prepare", tokens["expiry"], "--lease-seconds", "3", "--expiry-probe"
        )
        assert_identity_and_headroom(expiry, report["script_sha256"], report["boot_id"])
        state = Path("/run/fleetdoctor-oom") / (tokens["expiry"] + ".json")
        stat = state.stat()
        if stat.st_uid != 0 or stat.st_mode & 0o077:
            raise RuntimeError("expiry state is not root-owned mode 0600")
        expired = wait_expired(script, tokens["expiry"], time.monotonic() + 12)
        automatic_cleanup = assert_removed(tokens["expiry"], str(expiry["leaf_path"]))
        first_release = helper(script, "release", tokens["expiry"])
        second_release = helper(script, "release", tokens["expiry"])
        if state.exists() or (state.parent / (tokens["expiry"] + ".gate")).exists():
            raise RuntimeError("expiry release retained state or gate")
        report["proofs"]["independent_expiry"] = {
            "prepared": expiry,
            "expired": expired,
            "release": first_release,
            "repeated_release": second_release,
            "automatic_cleanup": automatic_cleanup,
        }

        interrupted = helper(script, "prepare", tokens["interrupt"])
        assert_identity_and_headroom(interrupted, report["script_sha256"], report["boot_id"])
        killed = command(
            ["systemctl", "kill", "--signal=TERM", str(interrupted["unit"])], timeout=10
        )
        if killed.returncode:
            raise RuntimeError("failed to interrupt owned supervisor")
        interrupted_status = wait_expired(script, tokens["interrupt"], time.monotonic() + 12)
        interrupted_cleanup = assert_removed(tokens["interrupt"], str(interrupted["leaf_path"]))
        report["proofs"]["interruption"] = {
            "prepared": interrupted,
            "expired": interrupted_status,
            "release": helper(script, "release", tokens["interrupt"]),
            "unit_signal": "TERM",
            "automatic_cleanup": interrupted_cleanup,
        }

        repeated = helper(script, "prepare", tokens["repeat"])
        assert_identity_and_headroom(repeated, report["script_sha256"], report["boot_id"])
        first_stop = helper(script, "stop", tokens["repeat"])
        second_stop = helper(script, "stop", tokens["repeat"])
        first_release = helper(script, "release", tokens["repeat"])
        second_release = helper(script, "release", tokens["repeat"])
        explicit_cleanup = assert_removed(tokens["repeat"], str(repeated["leaf_path"]))
        report["proofs"]["repeated_cleanup"] = {
            "prepared": repeated,
            "first_stop": first_stop,
            "second_stop": second_stop,
            "first_release": first_release,
            "second_release": second_release,
            "explicit_cleanup": explicit_cleanup,
        }

        prelaunch_error = helper_failure(
            script,
            "prepare",
            tokens["prelaunch"],
            "--lease-seconds",
            "15",
            "--expiry-probe",
            "--proof-fault",
            "prelaunch_interrupt",
        )
        prelaunch_cleanup = wait_partial_removed(tokens["prelaunch"])
        report["proofs"]["partial_prelaunch_interruption"] = {
            "failure": prelaunch_error,
            "cleanup": prelaunch_cleanup,
            "retry": retry_same_token(script, tokens["prelaunch"]),
        }

        signal_error = signal_prelaunch(script, tokens["prelaunch_signal"])
        signal_cleanup = wait_partial_removed(tokens["prelaunch_signal"])
        report["proofs"]["partial_prelaunch_sigterm"] = {
            "failure": signal_error,
            "cleanup": signal_cleanup,
            "retry": retry_same_token(script, tokens["prelaunch_signal"]),
        }

        early_error = helper_failure(
            script,
            "prepare",
            tokens["early_exit"],
            "--lease-seconds",
            "15",
            "--expiry-probe",
            "--proof-fault",
            "supervisor_early_exit",
        )
        early_cleanup = wait_partial_removed(tokens["early_exit"])
        report["proofs"]["partial_supervisor_early_exit"] = {
            "failure": early_error,
            "cleanup": early_cleanup,
            "retry": retry_same_token(script, tokens["early_exit"]),
        }

        timeout_error = helper_failure(
            script,
            "prepare",
            tokens["not_ready"],
            "--lease-seconds",
            "15",
            "--expiry-probe",
            "--proof-fault",
            "supervisor_not_ready",
        )
        timeout_cleanup = wait_partial_removed(tokens["not_ready"])
        report["proofs"]["partial_readiness_timeout"] = {
            "failure": timeout_error,
            "cleanup": timeout_cleanup,
            "retry": retry_same_token(script, tokens["not_ready"]),
        }

        cleanup_error = helper_failure(
            script,
            "prepare",
            tokens["cleanup_retry"],
            "--lease-seconds",
            "15",
            "--expiry-probe",
            "--proof-fault",
            "cleanup_failure",
        )
        retained_path = Path("/run/fleetdoctor-oom") / (tokens["cleanup_retry"] + ".json")
        retained = json.loads(retained_path.read_text())
        if (
            retained.get("phase") != "starting"
            or not retained.get("invocation_id")
            or not retained.get("control_group")
            or "injected bounded cleanup failure" not in retained.get("cleanup_error", "")
        ):
            raise RuntimeError("cleanup failure did not retain verifiable retry evidence")
        release_retry = helper(script, "release", tokens["cleanup_retry"])
        cleanup_retry_removed = wait_partial_removed(
            tokens["cleanup_retry"], str(retained["control_group"])
        )
        report["proofs"]["partial_cleanup_failure_retry"] = {
            "failure": cleanup_error,
            "retained": retained,
            "release_retry": release_retry,
            "cleanup": cleanup_retry_removed,
            "retry": retry_same_token(script, tokens["cleanup_retry"]),
        }
        report["status"] = "passed"
    except BaseException as exc:
        failure = exc
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for name, token in tokens.items():
            try:
                report["cleanup"][name] = helper(script, "release", token)
                state_root = Path("/run/fleetdoctor-oom")
                if (state_root / (token + ".json")).exists() or (
                    state_root / (token + ".gate")
                ).exists():
                    raise RuntimeError("final cleanup retained trusted helper files")
            except BaseException as exc:
                report["cleanup"][name] = {"error": f"{type(exc).__name__}: {exc}"}
                if failure is None:
                    failure = exc
        if failure is not None:
            report["status"] = "failed"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if failure is not None:
        raise RuntimeError(
            "OOM helper proof failed; retained report: " + str(args.output)
        ) from failure


if __name__ == "__main__":
    main()
