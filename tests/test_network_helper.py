import os
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fcntl")
helper = pytest.importorskip("network_resource")


def owned_tree(profile: str = "latency") -> dict[str, Any]:
    netem_options = (
        {"limit": 1000, "delay": 250000}
        if profile == "latency"
        else {
            "limit": 1000,
            "loss-random": {"probability": 4294967295, "correlation": 0},
        }
    )
    return {
        "qdisc": [
            {
                "kind": "prio",
                "handle": "1:",
                "root": True,
                "options": {"bands": 3, "priomap": [1] * 16},
            },
            {"kind": "netem", "handle": "30:", "parent": "1:3", "options": netem_options},
        ],
        "class": [
            {"kind": "prio", "handle": "1:1", "parent": "1:"},
            {"kind": "prio", "handle": "1:2", "parent": "1:"},
            {"kind": "prio", "handle": "1:3", "parent": "1:"},
        ],
        "filter_root": [
            {
                "kind": "flower",
                "protocol": "ip",
                "pref": 49152,
                "handle": "0xfd09",
                "options": {
                    "keys": {
                        "dst_ip": "192.0.2.10",
                        "ip_proto": "icmp",
                        "icmp_type": 8,
                        "icmp_code": 0,
                    },
                    "classid": "1:3",
                },
            }
        ],
        "filter_ingress": [],
    }


def captured_kernel_tree() -> dict[str, Any]:
    value = owned_tree()
    value["class"] = [
        {"class": "prio", "handle": "1:1", "parent": "1:"},
        {"class": "prio", "handle": "1:2", "parent": "1:"},
        {"class": "prio", "handle": "1:3", "leaf": "0x30", "parent": "1:"},
    ]
    value["qdisc"][0].update(refcnt=17)
    value["qdisc"][1]["options"] = {
        "delay": {"correlation": 0, "delay": 0.25, "jitter": 0},
        "ecn": False,
        "gap": 0,
        "limit": 1000,
        "seed": 11128420526396280945,
    }
    value["filter_root"] = [
        {"protocol": "ip", "pref": 49152, "kind": "flower", "chain": 0},
        {
            "protocol": "ip",
            "pref": 49152,
            "kind": "flower",
            "chain": 0,
            "options": {
                "handle": 64777,
                "classid": "1:3",
                "keys": {
                    "eth_type": "ipv4",
                    "ip_proto": "icmp",
                    "dst_ip": "192.0.2.10",
                    "icmp_type": "8",
                    "icmp_code": "0",
                },
                "not_in_hw": True,
            },
        },
    ]
    return value


@pytest.mark.parametrize("profile", ["latency", "loss"])
def test_exact_owned_tree(profile: str) -> None:
    assert helper.owned_prefix(owned_tree(profile), 3, "192.0.2.10", profile)


def test_captured_kernel_class_and_nested_delay_format_is_owned() -> None:
    assert helper.owned_prefix(captured_kernel_tree(), 3, "192.0.2.10", "latency")


def test_captured_kernel_loss_format_is_owned() -> None:
    value = captured_kernel_tree()
    value["qdisc"][1]["options"] = {
        "limit": 1000,
        "loss-random": {"loss": 1, "correlation": 0},
        "seed": 8937913761336023156,
        "ecn": False,
        "gap": 0,
    }
    assert helper.owned_prefix(value, 3, "192.0.2.10", "loss")


@pytest.mark.parametrize(
    ("field", "amount"),
    [("loss", 0.01), ("probability", 1)],
)
def test_loss_units_are_representation_specific(field: str, amount: float) -> None:
    value = captured_kernel_tree()
    value["qdisc"][1]["options"] = {
        "limit": 1000,
        "loss-random": {field: amount, "correlation": 0},
    }
    assert not helper.owned_prefix(value, 3, "192.0.2.10", "loss")


def test_partial_cleanup_authority_refuses_foreign_flower_action() -> None:
    value = captured_kernel_tree()
    value["qdisc"][1]["options"] = {
        "limit": 1000,
        "loss-random": {"loss": 1, "correlation": 0},
        "seed": 8937913761336023156,
        "ecn": False,
        "gap": 0,
    }
    value["filter_root"][1]["options"]["actions"] = [
        {"order": 1, "kind": "gact", "control_action": {"type": "drop"}}
    ]
    assert not helper.owned_prefix(value, 3, "192.0.2.10", "loss")


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("qdisc", 0, "handle"), "2:"),
        (("qdisc", 0, "options", "priomap"), [0] * 16),
        (("qdisc", 1, "parent"), "1:2"),
        (("filter_root", 0, "handle"), "0xbeef"),
        (("filter_root", 0, "options", "keys", "dst_ip"), "192.0.2.11"),
        (("filter_root", 0, "options", "keys", "ip_proto"), "tcp"),
        (("filter_root", 0, "options", "keys", "icmp_type"), 0),
        (("filter_root", 0, "options", "classid"), "1:2"),
    ],
)
def test_changed_authority_is_refused(path: tuple[object, ...], replacement: object) -> None:
    value = deepcopy(owned_tree())
    cursor: Any = value
    for item in path[:-1]:
        cursor = cursor[item]
    cursor[path[-1]] = replacement
    assert not helper.owned_prefix(value, 3, "192.0.2.10", "latency")


def test_additional_foreign_object_is_refused() -> None:
    value = owned_tree()
    value["qdisc"].append({"kind": "clsact", "handle": "ffff:"})
    assert not helper.owned_prefix(value, 3, "192.0.2.10", "latency")


def test_normalization_discards_only_runtime_statistics() -> None:
    value = owned_tree()
    changed = deepcopy(value)
    changed["qdisc"][0]["bytes"] = 999
    assert helper.normalized_state(value) == helper.normalized_state(changed)
    changed["qdisc"][0]["handle"] = "2:"
    assert helper.normalized_state(value) != helper.normalized_state(changed)


def test_flower_argv_matches_only_numeric_echo_request_to_exact_target() -> None:
    commands = helper.setup_commands("/sbin/tc", "eth0", "192.0.2.10", "latency")
    flower = commands[1]
    assert flower[flower.index("ip_proto") + 1] == "icmp"
    assert flower[flower.index("dst_ip") + 1] == "192.0.2.10"
    assert flower[flower.index("type") + 1] == "8"
    assert flower[flower.index("code") + 1] == "0"
    assert flower[flower.index("flowid") + 1] == "1:3"
    assert commands[2][-2:] == ["delay", "250ms"]


def test_tc_inventory_queries_filters_at_the_discovered_root_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def command(argv: list[str], *, timeout: float = 2) -> dict[str, Any]:
        calls.append(argv)
        if "qdisc" in argv:
            value = [{"kind": "prio", "handle": "1:", "root": True}]
        elif "class" in argv:
            value = []
        elif argv[-1] == "ingress":
            value = []
        else:
            value = [{"kind": "flower", "handle": "fd09::1"}]
        return {"returncode": 0, "stdout": __import__("json").dumps(value), "stderr": ""}

    monkeypatch.setattr(helper, "command", command)
    state = helper.tc_state("eth0", "/sbin/tc")
    assert state["filter_root"] == [{"kind": "flower", "handle": "fd09::1"}]
    assert ["parent", "1:"] == calls[2][-2:]


def test_cleanup_retry_finishes_after_lease_was_already_unlinked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    baseline: dict[str, Any] = {"qdisc": [], "class": [], "filter_root": [], "filter_ingress": []}
    record = {
        "token": "a" * 32,
        "cleanup_complete": False,
        "cleanup_phase": "lease_removal_pending",
        "tools": {"tc": "/sbin/tc", "ip": "/sbin/ip"},
        "target": "192.0.2.10",
        "route_before": {"interface": "eth0"},
        "namespace": {"net": "fixture"},
        "interface": "eth0",
        "prestate": baseline,
        "restored_state": baseline,
    }
    saved: list[dict[str, Any]] = []
    monkeypatch.setattr(helper, "load_record", lambda token: deepcopy(record))
    monkeypatch.setattr(helper, "validate_lease", lambda token, **kwargs: False)
    monkeypatch.setattr(helper, "route_identity", lambda target, ip: record["route_before"])
    monkeypatch.setattr(helper, "namespace_identity", lambda: record["namespace"])
    monkeypatch.setattr(helper, "tc_state", lambda interface, tc: baseline)
    monkeypatch.setattr(helper, "run_path", lambda token: tmp_path / "record.json")
    monkeypatch.setattr(helper, "save", lambda path, value: saved.append(deepcopy(value)))
    monkeypatch.setattr(helper, "LEASE", tmp_path / "absent-lease")
    result = helper.cleanup_locked("a" * 32, reason="requested")
    assert result["cleanup_complete"] is True
    assert result["cleanup_phase"] == "complete"
    assert all(item.get("cleanup_phase") != "restored" for item in saved)


@pytest.mark.parametrize("failed_step", [0, 1, 2])
def test_each_setup_command_failure_attempts_owned_rollback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failed_step: int
) -> None:
    token = f"{failed_step + 1:032x}"
    baseline = {
        "qdisc": [{"kind": "noqueue", "root": True}],
        "class": [],
        "filter_root": [],
        "filter_ingress": [],
    }
    route = {
        "target": "192.0.2.10",
        "interface": "eth0",
        "ifindex": 2,
        "source": "192.0.2.2",
        "namespace": {"device": 1, "inode": 2},
    }
    monkeypatch.setattr(helper, "LEASE", tmp_path / "lease.json")
    monkeypatch.setattr(helper, "run_path", lambda value: tmp_path / f"{value}.json")
    monkeypatch.setattr(helper, "locked", lambda: nullcontext())
    monkeypatch.setattr(helper, "_tool", lambda name: f"/sbin/{name}")
    monkeypatch.setattr(helper, "route_identity", lambda target, ip: route)
    monkeypatch.setattr(helper, "namespace_identity", lambda: route["namespace"])
    monkeypatch.setattr(helper, "tc_state", lambda interface, tc: baseline)
    monkeypatch.setattr(helper, "launch_watchdog", lambda value, duration: SimpleNamespace(pid=123))
    monkeypatch.setattr(helper, "process_start", lambda pid: "456")
    monkeypatch.setattr(helper, "owned_watchdog", lambda record: True)
    monkeypatch.setattr(
        helper,
        "setup_commands",
        lambda tc, interface, target, profile: [["tc", str(index)] for index in range(3)],
    )
    calls = 0

    def command(argv: list[str]) -> dict[str, Any]:
        nonlocal calls
        current = calls
        calls += 1
        if current == failed_step:
            return {
                "argv": argv,
                "returncode": 23,
                "stdout": "setup stdout",
                "stderr": "fixture setup failure",
            }
        return {"argv": argv, "returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(helper, "command", command)
    cleanup: list[str] = []

    def cleanup_locked(value: str, *, reason: str) -> dict[str, Any]:
        cleanup.append(reason)
        return {"cleanup_complete": True}

    monkeypatch.setattr(helper, "cleanup_locked", cleanup_locked)
    with pytest.raises(RuntimeError, match="command failed with exit 23"):
        helper.start(token, "192.0.2.10", "latency", 30)
    record = __import__("json").loads((tmp_path / f"{token}.json").read_text())
    assert record["pending_step"] == failed_step
    assert record["completed_steps"] == failed_step
    assert record["setup_failure"].startswith("RuntimeError")
    assert record["commands"][-1] == {
        "argv": ["tc", str(failed_step)],
        "returncode": 23,
        "stdout": "setup stdout",
        "stderr": "fixture setup failure",
    }
    assert cleanup == ["partial_setup_rollback"]


@pytest.mark.parametrize(
    ("route_result", "namespace_result", "expected"),
    [
        ({"interface": "eth1"}, {"net": "fixture"}, "route_or_namespace_identity_changed"),
        ({"interface": "eth0"}, {"net": "changed"}, "route_or_namespace_identity_changed"),
    ],
)
def test_cleanup_identity_refusal_is_retained_without_unlinking_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    route_result: dict[str, Any],
    namespace_result: dict[str, Any],
    expected: str,
) -> None:
    token = "a" * 32
    lease = tmp_path / "lease.json"
    lease.write_text('{"token":"' + token + '"}', encoding="utf-8")
    record = {
        "token": token,
        "cleanup_complete": False,
        "cleanup_phase": "active",
        "tools": {"tc": "/sbin/tc", "ip": "/sbin/ip"},
        "target": "192.0.2.10",
        "route_before": {"interface": "eth0"},
        "namespace": {"net": "fixture"},
    }
    saved: list[dict[str, Any]] = []
    monkeypatch.setattr(helper, "LEASE", lease)
    monkeypatch.setattr(helper, "load_record", lambda value: deepcopy(record))
    monkeypatch.setattr(helper, "validate_lease", lambda value, **kwargs: True)
    monkeypatch.setattr(helper, "route_identity", lambda target, ip: route_result)
    monkeypatch.setattr(helper, "namespace_identity", lambda: namespace_result)
    monkeypatch.setattr(helper, "run_path", lambda value: tmp_path / "record.json")
    monkeypatch.setattr(helper, "save", lambda path, value: saved.append(deepcopy(value)))
    with pytest.raises(ValueError, match="identity changed"):
        helper.cleanup_locked(token, reason="requested")
    assert saved[-1]["cleanup_failed"] == expected
    assert saved[-1]["cleanup_complete"] is False
    assert saved[-1]["cleanup_phase"] == "active"
    assert lease.exists()


def test_cleanup_route_probe_failure_is_retained_without_unlinking_lease(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token = "a" * 32
    lease = tmp_path / "lease.json"
    lease.write_text('{"token":"' + token + '"}', encoding="utf-8")
    record = {
        "token": token,
        "cleanup_complete": False,
        "cleanup_phase": "active",
        "tools": {"tc": "/sbin/tc", "ip": "/sbin/ip"},
        "target": "192.0.2.10",
        "route_before": {"interface": "eth0"},
        "namespace": {"net": "fixture"},
    }
    saved: list[dict[str, Any]] = []
    monkeypatch.setattr(helper, "LEASE", lease)
    monkeypatch.setattr(helper, "load_record", lambda value: deepcopy(record))
    monkeypatch.setattr(helper, "validate_lease", lambda value, **kwargs: True)
    monkeypatch.setattr(
        helper,
        "route_identity",
        lambda target, ip: (_ for _ in ()).throw(RuntimeError("route probe failed")),
    )
    monkeypatch.setattr(helper, "run_path", lambda value: tmp_path / "record.json")
    monkeypatch.setattr(helper, "save", lambda path, value: saved.append(deepcopy(value)))
    with pytest.raises(RuntimeError, match="route probe failed"):
        helper.cleanup_locked(token, reason="requested")
    assert saved[-1]["cleanup_failed"] == "route_or_namespace_identity_unavailable"
    assert saved[-1]["cleanup_failure"] == "RuntimeError: route probe failed"
    assert saved[-1]["cleanup_complete"] is False
    assert lease.exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned lease authority")
def test_root_owned_forged_lease_is_refused_by_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lease = tmp_path / "lease.json"
    lease.write_text('{"token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}', encoding="utf-8")
    os.chmod(lease, 0o600)
    monkeypatch.setattr(helper, "LEASE", lease)
    with pytest.raises(ValueError, match="does not authorize"):
        helper.validate_lease("a" * 32)


@pytest.mark.skipif(os.geteuid() == 0, reason="nonroot ownership refusal")
def test_nonroot_owned_lease_is_refused_before_token_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lease = tmp_path / "lease.json"
    lease.write_text('{"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}', encoding="utf-8")
    os.chmod(lease, 0o600)
    monkeypatch.setattr(helper, "LEASE", lease)
    with pytest.raises(ValueError, match="not trusted"):
        helper.validate_lease("a" * 32)


def test_cleanup_delete_failure_retains_actionable_record(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    baseline = {
        "qdisc": [{"kind": "noqueue", "root": True}],
        "class": [],
        "filter_root": [],
        "filter_ingress": [],
    }
    active = owned_tree()
    record = {
        "token": "a" * 32,
        "cleanup_complete": False,
        "cleanup_phase": "active",
        "completed_steps": 3,
        "tools": {"tc": "/sbin/tc", "ip": "/sbin/ip"},
        "target": "192.0.2.10",
        "profile": "latency",
        "route_before": {"interface": "eth0"},
        "namespace": {"net": "fixture"},
        "interface": "eth0",
        "prestate": baseline,
        "active_state": active,
    }
    saved: list[dict[str, Any]] = []
    monkeypatch.setattr(helper, "load_record", lambda token: deepcopy(record))
    monkeypatch.setattr(helper, "validate_lease", lambda token, **kwargs: True)
    monkeypatch.setattr(helper, "route_identity", lambda target, ip: record["route_before"])
    monkeypatch.setattr(helper, "namespace_identity", lambda: record["namespace"])
    monkeypatch.setattr(helper, "tc_state", lambda interface, tc: active)
    monkeypatch.setattr(helper, "command", lambda argv: {"returncode": 2, "argv": argv})
    monkeypatch.setattr(helper, "run_path", lambda token: tmp_path / "record.json")
    monkeypatch.setattr(helper, "save", lambda path, value: saved.append(deepcopy(value)))
    with pytest.raises(RuntimeError, match="cleanup failed"):
        helper.cleanup_locked("a" * 32, reason="requested")
    assert saved[-1]["cleanup_failed"] == "owned_root_delete_failed"
    assert saved[-1]["cleanup_complete"] is False


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("qdisc", 0, "options", "priomap"), [0] * 16),
        (("qdisc", 1, "options", "delay", "delay"), 0.5),
        (("filter_root", 1, "options", "keys", "dst_ip"), "192.0.2.11"),
    ],
)
def test_active_state_cleanup_refuses_same_handle_foreign_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    path: tuple[object, ...],
    replacement: object,
) -> None:
    token = "a" * 32
    active = captured_kernel_tree()
    live = deepcopy(active)
    cursor: Any = live
    for item in path[:-1]:
        cursor = cursor[item]
    cursor[path[-1]] = replacement
    record = {
        "token": token,
        "cleanup_complete": False,
        "cleanup_phase": "active",
        "completed_steps": 3,
        "tools": {"tc": "/sbin/tc", "ip": "/sbin/ip"},
        "target": "192.0.2.10",
        "profile": "latency",
        "route_before": {"interface": "eth0"},
        "namespace": {"net": "fixture"},
        "interface": "eth0",
        "prestate": {"qdisc": [], "class": [], "filter_root": [], "filter_ingress": []},
        "active_state": active,
    }
    saved: list[dict[str, Any]] = []
    monkeypatch.setattr(helper, "load_record", lambda value: deepcopy(record))
    monkeypatch.setattr(helper, "validate_lease", lambda value, **kwargs: True)
    monkeypatch.setattr(helper, "route_identity", lambda target, ip: record["route_before"])
    monkeypatch.setattr(helper, "namespace_identity", lambda: record["namespace"])
    monkeypatch.setattr(helper, "tc_state", lambda interface, tc: live)
    monkeypatch.setattr(helper, "run_path", lambda value: tmp_path / "record.json")
    monkeypatch.setattr(helper, "save", lambda path, value: saved.append(deepcopy(value)))
    monkeypatch.setattr(
        helper,
        "command",
        lambda argv: pytest.fail("changed active state must be refused before tc deletion"),
    )
    with pytest.raises(ValueError, match="not the owned tree"):
        helper.cleanup_locked(token, reason="requested")
    assert saved[-1]["cleanup_failed"] == "foreign_or_changed_tc_hierarchy"


def test_existing_lease_refuses_concurrent_start_before_tool_or_tc_access(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lease = tmp_path / "lease.json"
    lease.write_text('{"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}', encoding="utf-8")
    monkeypatch.setattr(helper, "LEASE", lease)
    monkeypatch.setattr(helper, "run_path", lambda token: tmp_path / f"{token}.json")
    monkeypatch.setattr(helper, "locked", lambda: nullcontext())
    monkeypatch.setattr(
        helper,
        "_tool",
        lambda name: pytest.fail("tool discovery must not run while a lease is active"),
    )
    with pytest.raises(ValueError, match="unresolved"):
        helper.start("b" * 32, "192.0.2.10", "latency", 30)
