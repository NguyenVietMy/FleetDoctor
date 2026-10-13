from unittest.mock import Mock
from uuid import uuid4

import pytest
from outage_rule import Rule, interrupt, refuse_existing


@pytest.mark.parametrize(
    "ip,uid,seconds",
    [
        ("127.0.0.1", 1000, 20),
        ("8.8.8.8", 1000, 20),
        ("10.0.0.2", 0, 20),
        ("10.0.0.2", 1000, 61),
        ("10.0.0.2", True, 20),
    ],
)
def test_refuse_broad_or_unbounded_fault(ip: str, uid: int, seconds: int) -> None:
    with pytest.raises(ValueError):
        Rule(ip, uid, uuid4(), seconds).command("-A")


def test_scope_watchdog_and_finally() -> None:
    rule = Rule("10.0.0.2", 1001, uuid4(), 25)
    run = Mock(side_effect=[1, 0, 0, 0])
    arm = Mock(return_value=Mock(poll=Mock(return_value=None)))
    with pytest.raises(TimeoutError):
        with interrupt(rule, "node-a", rule.monitor, rule.agent_uid, run, arm, lambda: ""):
            raise TimeoutError("controller deadline")
    commands = [call.args[0] for call in run.call_args_list]
    assert commands == [rule.command(op) for op in ("-C", "-A", "-C", "-D")]
    assert "8000" in commands[1] and "22" not in commands[1] and "--uid-owner" in commands[1]
    arm.assert_called_once_with(rule)
    with pytest.raises(ValueError):
        with interrupt(rule, "node-b", rule.monitor, rule.agent_uid, run, arm, lambda: ""):
            pass


@pytest.mark.parametrize("check", [0, 2])
def test_existing_or_error_refuses_without_mutation(check: int) -> None:
    rule = Rule("10.0.0.2", 1001, uuid4(), 25)
    run, arm = Mock(return_value=check), Mock()
    with pytest.raises(RuntimeError):
        with interrupt(rule, "node-a", rule.monitor, rule.agent_uid, run, arm, lambda: ""):
            pass
    run.assert_called_once_with(rule.command("-C"))
    arm.assert_not_called()


def test_failed_insertion_still_cleans_owned_rule() -> None:
    rule = Rule("10.0.0.2", 1001, uuid4(), 25)
    run = Mock(side_effect=[1, 2, 0, 0])
    arm = Mock(return_value=Mock(poll=Mock(return_value=None)))
    with pytest.raises(RuntimeError, match="insertion"):
        with interrupt(rule, "node-a", rule.monitor, rule.agent_uid, run, arm, lambda: ""):
            pass
    assert run.call_args.args[0] == rule.command("-D")


@pytest.mark.parametrize(
    "listing",
    [
        "-A OUTPUT -m comment --comment fleetdoctor-outage-other -j REJECT",
        "-A OUTPUT -j DROP",
        "-A OUTPUT -d 10.0.0.2/32 -p tcp --dport 8000 -m owner --uid-owner 1001 -j REJECT",
    ],
)
def test_unrelated_or_existing_fault_is_refused(listing: str) -> None:
    with pytest.raises(ValueError):
        refuse_existing(Rule("10.0.0.2", 1001, uuid4(), 25), listing)


def test_unrelated_ssh_or_other_uid_rules_are_not_changed() -> None:
    rule = Rule("10.0.0.2", 1001, uuid4(), 25)
    refuse_existing(rule, "-A OUTPUT -p tcp --dport 22 -j REJECT")
    refuse_existing(rule, "-A OUTPUT -m owner --uid-owner 0 -j REJECT")


def test_cleanup_check_error_fails_with_watchdog_armed() -> None:
    rule = Rule("10.0.0.2", 1001, uuid4(), 25)
    run = Mock(side_effect=[1, 0, 2])
    arm = Mock(return_value=Mock(poll=Mock(return_value=None)))
    with pytest.raises(RuntimeError, match="cleanup"):
        with interrupt(rule, "node-a", rule.monitor, rule.agent_uid, run, arm, lambda: ""):
            pass
