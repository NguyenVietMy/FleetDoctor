"""Prepared node-a-only delivery fault primitive; never invoked by local proofs.

The authorized lab controller must supply the retained node-a identity and monitor
private address from its allowlist, then wrap this context in the existing lab
parent-finally stop/export discipline. This module does not connect to any host.
"""

import ipaddress
import shlex
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class Rule:
    monitor: str
    agent_uid: int
    owner: UUID
    seconds: int

    def command(self, operation: str) -> list[str]:
        if not isinstance(self.owner, UUID):
            raise ValueError("unique UUID ownership required")
        address = ipaddress.IPv4Address(self.monitor)
        private = any(
            address in ipaddress.IPv4Network(net)
            for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
        if not private or type(self.agent_uid) is not int or self.agent_uid <= 0:
            raise ValueError("exact RFC1918 monitor and non-root agent uid required")
        if type(self.seconds) is not int or not 20 <= self.seconds <= 60:
            raise ValueError("outage watchdog must be 20..60 seconds")
        if operation not in ("-C", "-A", "-D"):
            raise ValueError("only exact check/add/delete is allowed")
        return [
            "iptables",
            "-w",
            "2",
            operation,
            "OUTPUT",
            "-p",
            "tcp",
            "-d",
            str(address),
            "--dport",
            "8000",
            "-m",
            "owner",
            "--uid-owner",
            str(self.agent_uid),
            "-m",
            "comment",
            "--comment",
            "fleetdoctor-outage-" + str(self.owner),
            "-j",
            "REJECT",
        ]


def execute(command: list[str]) -> int:
    return subprocess.run(command, check=False, capture_output=True, timeout=4).returncode


def watchdog(rule: Rule) -> subprocess.Popen[bytes]:
    # A separate process survives controller cancellation/disconnection. No shell,
    # broad chain cleanup, credential output, or inherited controller pipe.
    code = (
        "import subprocess,time; time.sleep("
        + str(rule.seconds)
        + "); subprocess.run("
        + repr(rule.command("-D"))
        + ", timeout=4, capture_output=True)"
    )
    return subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def inspect_rules() -> str:
    result = subprocess.run(
        ["iptables", "-w", "2", "-S", "OUTPUT"],
        check=True,
        capture_output=True,
        text=True,
        timeout=4,
    )
    if len(result.stdout) > 65_536:
        raise ValueError("OUTPUT rule inspection exceeds bound")
    return result.stdout


def refuse_existing(rule: Rule, listing: str) -> None:
    for line in listing.splitlines():
        tokens = shlex.split(line)
        if any("fleetdoctor-outage-" in token for token in tokens):
            raise ValueError("another delivery interruption is present")
        # Reject an unrelated rule that can already interrupt this endpoint/uid.
        # Broad DROP/REJECT rules are also refused, never changed or removed.
        if "-j" not in tokens or tokens[tokens.index("-j") + 1] not in ("DROP", "REJECT"):
            continue
        constraints = {
            flag: tokens[tokens.index(flag) + 1] if flag in tokens else None
            for flag in ("-d", "--dport", "--uid-owner", "-p")
        }
        if (
            constraints["-d"] in (None, rule.monitor, rule.monitor + "/32")
            and constraints["--dport"] in (None, "8000")
            and constraints["--uid-owner"] in (None, str(rule.agent_uid))
            and constraints["-p"] in (None, "tcp", "all")
        ):
            raise ValueError("unrelated existing rule may interrupt delivery")


@contextmanager
def interrupt(
    rule: Rule,
    node: str,
    expected_monitor: str,
    expected_uid: int,
    run: Callable[[list[str]], int] = execute,
    arm: Callable[[Rule], subprocess.Popen[bytes]] = watchdog,
    inspect: Callable[[], str] = inspect_rules,
) -> Iterator[None]:
    if node != "node-a" or rule.monitor != expected_monitor or rule.agent_uid != expected_uid:
        raise ValueError("retained node-a monitor/uid allowlist mismatch")
    check, add, delete = (rule.command(op) for op in ("-C", "-A", "-D"))
    refuse_existing(rule, inspect())
    result = run(check)
    if result != 1:  # iptables exit 1 means exact rule absent; errors are refusals.
        raise RuntimeError("owned rule exists or check failed")
    timer = arm(rule)
    if timer.poll() is not None:
        raise RuntimeError("independent watchdog failed to arm")
    try:
        if run(add) != 0:
            raise RuntimeError("delivery rule insertion failed")
        yield
    finally:
        # Leave watchdog armed even after successful early cleanup. It can only
        # delete this exact unique rule; it cannot affect another owner or SSH.
        present = run(check)
        if present not in (0, 1) or (present == 0 and run(delete) != 0):
            raise RuntimeError("owned rule cleanup failed; watchdog remains armed")
