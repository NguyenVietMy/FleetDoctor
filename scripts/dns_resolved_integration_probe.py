#!/usr/bin/env python3
"""Real systemd-resolved cache-bypass proof through the product DNS adapter."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HOSTNAME = "baseline.fleetdoctor.test."
state: dict[str, Any] = {"mode": "success", "queries": 0}
stop = threading.Event()


def server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 1053))
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, address = sock.recvfrom(4096)
        except TimeoutError:
            continue
        state["queries"] += 1
        flags = 0x8180 if state["mode"] == "success" else 0x8182
        qend = 12
        while data[qend]:
            qend += data[qend] + 1
        qend += 5
        reply = (
            data[:2]
            + struct.pack("!HHHHH", flags, 1, int(state["mode"] == "success"), 0, 0)
            + data[12:qend]
        )
        if state["mode"] == "success":
            reply += (
                b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 3600, 4) + socket.inet_aton("10.77.0.9")
            )
        sock.sendto(reply, address)
    sock.close()


def command(argv: list[str], timeout: float = 5) -> dict[str, Any]:
    started = time.monotonic()
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return {
        "argv": argv,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "elapsed_seconds": time.monotonic() - started,
        "upstream_queries": state["queries"],
    }


def product_collect_as_agent(resolver_file: Path) -> dict[str, Any]:
    identity = pwd.getpwnam("fleetdoctor")

    def demote() -> None:
        os.setgid(identity.pw_gid)
        os.setuid(identity.pw_uid)

    code = (
        "import json;from pathlib import Path;from fleetdoctor.dns import DnsCollector;"
        f"print(DnsCollector(Path({str(resolver_file)!r})).collect({HOSTNAME!r},'127.0.0.1').model_dump_json())"
    )
    result = subprocess.run(
        ["/app/.venv/bin/python", "-c", code],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        preexec_fn=demote,
    )
    if result.returncode:
        raise RuntimeError(result.stderr[-1000:])
    value: dict[str, Any] = json.loads(result.stdout)
    value["executed_uid"] = identity.pw_uid
    value["executed_gid"] = identity.pw_gid
    value["upstream_queries"] = state["queries"]
    return value


def main() -> None:
    result: dict[str, Any] = {
        "status": "failed",
        "product_code_executed": True,
        "adapter_source_sha256": hashlib.sha256(
            (ROOT / "src/fleetdoctor/dns.py").read_bytes()
        ).hexdigest(),
        "commands": [],
    }
    resolved: subprocess.Popen[bytes] | None = None
    worker = threading.Thread(target=server)
    try:
        Path("/run/dbus").mkdir(parents=True, exist_ok=True)
        result["commands"].append(command(["dbus-daemon", "--system", "--fork", "--nopidfile"]))
        Path("/etc/systemd/resolved.conf").write_text(
            "[Resolve]\nDNS=127.0.0.1:1053\nFallbackDNS=\nDNSSEC=no\nDNSOverTLS=no\n"
            "LLMNR=no\nMulticastDNS=no\nCache=yes\nCacheFromLocalhost=yes\n",
            encoding="ascii",
        )
        identity = pwd.getpwnam("systemd-resolve")
        Path("/run/systemd/resolve").mkdir(parents=True, exist_ok=True)
        os.chown("/run/systemd/resolve", identity.pw_uid, identity.pw_gid)
        resolver_file = Path("/tmp/fleetdoctor-product-resolv.conf")
        resolver_file.write_text("nameserver 127.0.0.53\n", encoding="ascii")
        resolver_file.chmod(0o644)
        worker.start()
        log = Path("/tmp/resolved.log").open("wb")
        resolved = subprocess.Popen(["/lib/systemd/systemd-resolved"], stdout=log, stderr=log)
        ordinary = [
            "resolvectl",
            "--protocol=dns",
            "--type=A",
            "--legend=no",
            "query",
            HOSTNAME,
        ]
        for _ in range(30):
            warm = command(ordinary)
            result["commands"].append(warm)
            if warm["returncode"] == 0:
                break
            time.sleep(0.1)
        if warm["returncode"] != 0 or "10.77.0.9" not in warm["stdout"]:
            raise RuntimeError("systemd-resolved cache warm failed")
        product_baseline = product_collect_as_agent(resolver_file)
        if product_baseline["query"]["status"] != "success":
            raise RuntimeError("product adapter baseline failed")
        state["mode"] = "servfail"
        cached = command(ordinary)
        result["commands"].append(cached)
        count_before = state["queries"]
        product_failure = product_collect_as_agent(resolver_file)
        if cached["returncode"] != 0 or "10.77.0.9" not in cached["stdout"]:
            raise RuntimeError("ordinary lookup did not use warmed cache")
        if product_failure["query"]["status"] != "failure" or state["queries"] <= count_before:
            raise RuntimeError("product no-cache adapter did not observe live upstream failure")
        state["mode"] = "success"
        product_recovery = product_collect_as_agent(resolver_file)
        if product_recovery["query"]["status"] != "success":
            raise RuntimeError("product adapter did not recover")
        result.update(
            status="passed",
            warm_cached_success=True,
            uncached_failure_reached_upstream=True,
            uncached_recovery=True,
            product_baseline=product_baseline,
            product_failure=product_failure,
            product_recovery=product_recovery,
            resolved_version=command(["resolvectl", "--version"]),
            supported_flags=command(["resolvectl", "--help"]),
            service_state={"pid": resolved.pid, "running": resolved.poll() is None},
            effective_config=Path("/etc/systemd/resolved.conf").read_text(encoding="ascii"),
        )
    except BaseException as exc:
        result["error"] = f"{type(exc).__name__}:{exc}"
    finally:
        if resolved is not None:
            resolved.terminate()
            try:
                resolved.wait(timeout=3)
            except subprocess.TimeoutExpired:
                resolved.kill()
                resolved.wait(timeout=3)
        stop.set()
        if worker.ident:
            worker.join(timeout=2)
        log_path = Path("/tmp/resolved.log")
        result["resolved_log"] = (
            log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else None
        )
        print(json.dumps(result, sort_keys=True), flush=True)
        os._exit(0 if result["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
