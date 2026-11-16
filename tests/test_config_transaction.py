from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import config_transaction as transaction
import pytest


def test_update_env_bytes_preserves_unrelated_bytes_crlf_order_and_encoding() -> None:
    raw = b"# keep\r\nFLEETDOCTOR_NODE_ID=node-a\r\nFLEETDOCTOR_CPU_PIDS=1,2\r\nUNRELATED=\xff\r\n"
    updated = transaction.update_env_bytes(
        raw,
        {"FLEETDOCTOR_CPU_PIDS": "1,2,99", "FLEETDOCTOR_CGROUPS": "/a,/b"},
    )
    assert updated == (
        b"# keep\r\nFLEETDOCTOR_NODE_ID=node-a\r\n"
        b"FLEETDOCTOR_CPU_PIDS=1,2,99\r\nUNRELATED=\xff\r\n"
        b"FLEETDOCTOR_CGROUPS=/a,/b\r\n"
    )


def test_inventory_and_rewrite_share_quoted_whitespace_parser_without_secret_disclosure(
    tmp_path: Path,
) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "state"
    raw = (
        b"SECRET=\xffnever-return\r\n"
        b"  FLEETDOCTOR_CGROUPS = '/monitor,/shared'  \r\n"
        b'FLEETDOCTOR_CPU_PIDS="7,9"\r\n'
    )
    env.write_bytes(raw)
    result = transaction.inventory(
        env_path=env,
        state_dir=state,
        service_state={"ActiveState": "active", "UnitFileState": "enabled"},
    )
    assert result["selectors"] == {
        "FLEETDOCTOR_CGROUPS": ["/monitor", "/shared"],
        "FLEETDOCTOR_CPU_PIDS": [7, 9],
    }
    assert result["missing_keys"] == [] and "SECRET" not in json.dumps(result)
    updated = transaction.update_env_bytes(
        raw,
        {
            "FLEETDOCTOR_CGROUPS": "/monitor,/shared,/owned",
            "FLEETDOCTOR_CPU_PIDS": "7,9,11",
        },
    )
    assert b"SECRET=\xffnever-return\r\n" in updated
    assert b"FLEETDOCTOR_CGROUPS=/monitor,/shared,/owned\r\n" in updated


def test_stale_or_omitting_selector_cas_refuses_before_write_and_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "state"
    original = b"FLEETDOCTOR_CGROUPS=/monitor,/shared\nFLEETDOCTOR_CPU_PIDS=7,9\n"
    env.write_bytes(original)
    restarts: list[str] = []
    monkeypatch.setattr(transaction, "_restart", lambda service: restarts.append(service))
    snapshot = transaction.inventory(
        env_path=env,
        state_dir=state,
        service_state={"ActiveState": "active", "UnitFileState": "enabled"},
    )
    expected = {key: snapshot[key] for key in ("env_sha256", "selectors", "missing_keys")}
    with pytest.raises(ValueError, match="drop existing"):
        transaction.begin(
            "1" * 32,
            {"FLEETDOCTOR_CGROUPS": "/shared,/new"},
            env_path=env,
            state_dir=state,
            service_state=snapshot["service_state"],
            expected_before=expected,
        )
    assert env.read_bytes() == original and not restarts and not list(state.glob("*.json"))
    stale = deepcopy(expected)
    stale["env_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="changed since inventory"):
        transaction.begin(
            "2" * 32,
            {"FLEETDOCTOR_CPU_PIDS": "7,9,11"},
            env_path=env,
            state_dir=state,
            service_state=snapshot["service_state"],
            expected_before=stale,
        )
    assert env.read_bytes() == original and not restarts


def test_lookup_reports_only_the_exact_active_or_absent_token_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "state"
    env.write_bytes(b"FLEETDOCTOR_CPU_PIDS=7,9\n")
    token = "1" * 32
    service_state = {"ActiveState": "active", "UnitFileState": "enabled"}
    monkeypatch.setattr(transaction, "_service_state", lambda service: service_state)
    transaction.begin(
        token,
        {"FLEETDOCTOR_CPU_PIDS": "7,9,11"},
        env_path=env,
        state_dir=state,
        service="test.service",
        service_state=service_state,
        restart=False,
    )
    prepared = env.read_bytes()

    active = transaction.lookup(
        token,
        state_dir=state,
        expected_env_path=env,
        expected_service="test.service",
    )
    absent = transaction.lookup(
        "2" * 32,
        state_dir=state,
        expected_env_path=env,
        expected_service="test.service",
    )

    assert active["state"] == "active" and active["token"] == token
    assert absent == {"token": "2" * 32, "state": "absent"}
    assert env.read_bytes() == prepared
    assert (state / f"agent-env-{token}.json").exists()


def test_multiline_unrelated_quote_cannot_create_a_false_selector_line(tmp_path: Path) -> None:
    raw = (
        b"PRIVATE_VALUE='first line\n"
        b"FLEETDOCTOR_CGROUPS=/inside-secret\n"
        b"last line'\n"
        b"FLEETDOCTOR_CGROUPS=/effective\n"
    )
    with pytest.raises(ValueError, match="multiline|ambiguous"):
        transaction.parse_selectors(raw)
    with pytest.raises(ValueError, match="multiline|ambiguous"):
        transaction.update_env_bytes(raw, {"FLEETDOCTOR_CGROUPS": "/effective,/new"})


def test_duplicate_selector_and_selector_bounds_fail_closed() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        transaction.update_env_bytes(
            b"FLEETDOCTOR_CPU_PIDS=1\nFLEETDOCTOR_CPU_PIDS=2\n",
            {"FLEETDOCTOR_CPU_PIDS": "3"},
        )
    with pytest.raises(ValueError, match="at most 16"):
        transaction.validate_cpu_pids(",".join(str(item) for item in range(1, 18)))
    with pytest.raises(ValueError, match="at most eight"):
        transaction.validate_cgroups(",".join(f"/scope/{item}" for item in range(9)))


def test_begin_restore_round_trip_is_exact_and_removes_receipt(tmp_path: Path) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "transactions"
    original = b"A=1\nFLEETDOCTOR_CPU_PIDS=7\nTAIL=no-newline"
    env.write_bytes(original)
    token = "a" * 32
    applied = transaction.begin(
        token,
        {"FLEETDOCTOR_CPU_PIDS": "7,99"},
        env_path=env,
        state_dir=state,
        service="test.service",
        service_state={"ActiveState": "inactive", "UnitFileState": "disabled"},
        restart=False,
    )
    assert applied["phase"] == "applied"
    assert env.read_bytes() != original
    restored = transaction.restore(
        token,
        state_dir=state,
        restart=False,
        expected_env_path=env,
        expected_service="test.service",
    )
    assert restored["original_sha256"] == restored["restored_sha256"]
    assert env.read_bytes() == original
    assert list(state.iterdir()) == []


def test_failed_restart_retains_durable_actionable_receipt_and_recover_restores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "transactions"
    original = b"FLEETDOCTOR_CPU_PIDS=1\n"
    env.write_bytes(original)
    token = "b" * 32

    def fail_restart(service: str) -> None:
        raise RuntimeError("forced restart failure")

    monkeypatch.setattr(transaction, "_restart", fail_restart)
    with pytest.raises(RuntimeError, match="forced restart"):
        transaction.begin(
            token,
            {"FLEETDOCTOR_CPU_PIDS": "1,2"},
            env_path=env,
            state_dir=state,
            service="test.service",
            service_state={"ActiveState": "active", "UnitFileState": "enabled"},
        )
    receipt = state / f"agent-env-{token}.json"
    assert receipt.exists() and json.loads(receipt.read_text())["phase"] == "applied"
    results = transaction.recover(
        state_dir=state,
        restart=False,
        expected_env_path=env,
        expected_service="test.service",
    )
    assert results[0]["phase"] == "restored"
    assert env.read_bytes() == original


def test_failed_restore_restart_remains_actionable_and_retries_when_bytes_are_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "transactions"
    original = b"FLEETDOCTOR_CPU_PIDS=1\n"
    env.write_bytes(original)
    token = "e" * 32
    service_state = {"ActiveState": "active", "UnitFileState": "enabled"}
    transaction.begin(
        token,
        {"FLEETDOCTOR_CPU_PIDS": "1,2"},
        env_path=env,
        state_dir=state,
        service="test.service",
        service_state=service_state,
        restart=False,
    )
    attempts = 0

    def restart(service: str) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("forced restore restart failure")

    monkeypatch.setattr(transaction, "_restart", restart)
    monkeypatch.setattr(transaction, "_service_state", lambda service: service_state)
    with pytest.raises(RuntimeError, match="forced restore"):
        transaction.restore(
            token,
            state_dir=state,
            expected_env_path=env,
            expected_service="test.service",
        )
    receipt = state / f"agent-env-{token}.json"
    assert json.loads(receipt.read_text())["phase"] == "restore_intent"
    assert env.read_bytes() == original
    result = transaction.recover(
        state_dir=state,
        expected_env_path=env,
        expected_service="test.service",
    )
    assert result[0]["phase"] == "restored"
    assert attempts == 2


def test_crash_staging_files_are_recovered_from_durable_receipt(tmp_path: Path) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "transactions"
    original = b"FLEETDOCTOR_CPU_PIDS=1\n"
    env.write_bytes(original)
    token = "c" * 32
    transaction.begin(
        token,
        {"FLEETDOCTOR_CPU_PIDS": "1,2"},
        env_path=env,
        state_dir=state,
        service="test.service",
        service_state={"ActiveState": "inactive", "UnitFileState": "disabled"},
        restart=False,
    )
    (state / f"agent-env-{token}.json.new").write_bytes(b'{"partial":')
    env.with_name(env.name + ".new").write_bytes(b"partial environment staging")
    result = transaction.recover(
        state_dir=state,
        restart=False,
        expected_env_path=env,
        expected_service="test.service",
    )
    assert result[0]["phase"] == "restored"
    assert env.read_bytes() == original
    assert not env.with_name(env.name + ".new").exists()


def test_short_writes_are_completed_for_journal_environment_and_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "transactions"
    original = b"A=1\nFLEETDOCTOR_CGROUPS=/old\n"
    env.write_bytes(original)
    real_write = os.write

    def short_write(descriptor: int, raw: bytes) -> int:
        return real_write(descriptor, raw[:3])

    monkeypatch.setattr(os, "write", short_write)
    token = "d" * 32
    transaction.begin(
        token,
        {"FLEETDOCTOR_CGROUPS": "/old,/new"},
        env_path=env,
        state_dir=state,
        service="test.service",
        service_state={"ActiveState": "inactive", "UnitFileState": "disabled"},
        restart=False,
    )
    transaction.restore(
        token,
        state_dir=state,
        restart=False,
        expected_env_path=env,
        expected_service="test.service",
    )
    assert env.read_bytes() == original


def test_outer_scope_is_exclusive_and_allows_only_exact_fd_child_in_reverse_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "transactions"
    env.write_bytes(b"BASE=1\n")
    monkeypatch.setattr(transaction, "ENV", env)

    def validate_fixture_path(path: Path, *, directory: bool) -> None:
        # Exercise selector nesting independently of production root-path ownership.
        assert path == env and not directory
        assert path.is_file() and not path.is_symlink()

    monkeypatch.setattr(transaction, "_validate_fixed_root_path", validate_fixture_path)
    service_state = {"ActiveState": "inactive", "UnitFileState": "disabled"}
    outer, child = "1" * 32, "2" * 32
    transaction.begin(
        outer,
        {"FLEETDOCTOR_CGROUPS": "/old,/owned"},
        env_path=env,
        state_dir=state,
        service="test.service",
        service_state=service_state,
        restart=False,
    )
    with pytest.raises(RuntimeError, match="exclusive outer"):
        transaction.begin(
            "3" * 32,
            {"FLEETDOCTOR_CGROUPS": "/replacement"},
            env_path=env,
            state_dir=state,
            service="test.service",
            service_state=service_state,
            restart=False,
        )
    transaction.begin(
        child,
        {"FLEETDOCTOR_CPU_PIDS": "123"},
        parent_token=outer,
        env_path=env,
        state_dir=state,
        service="test.service",
        service_state=service_state,
        restart=False,
    )
    with pytest.raises(RuntimeError, match="nested configuration"):
        transaction.restore(
            outer,
            state_dir=state,
            restart=False,
            expected_env_path=env,
            expected_service="test.service",
        )
    transaction.restore(
        child,
        state_dir=state,
        restart=False,
        expected_env_path=env,
        expected_service="test.service",
    )
    transaction.restore(
        outer,
        state_dir=state,
        restart=False,
        expected_env_path=env,
        expected_service="test.service",
    )
    assert env.read_bytes() == b"BASE=1\n"


@pytest.mark.skipif(os.name != "posix", reason="production root ownership requires POSIX")
def test_production_env_path_guard_rejects_untrusted_fixture_before_env_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "transactions"
    original = b"BASE=1\n"
    env.write_bytes(original)
    env.chmod(0o666)
    monkeypatch.setattr(transaction, "ENV", env)
    with pytest.raises(ValueError, match="untrusted configuration transaction path"):
        transaction.begin(
            "1" * 32,
            {"FLEETDOCTOR_CGROUPS": "/owned"},
            env_path=env,
            state_dir=state,
            service="test.service",
            service_state={"ActiveState": "inactive", "UnitFileState": "disabled"},
            restart=False,
        )
    assert env.read_bytes() == original
    assert not list(state.iterdir())


def test_completed_restore_crash_window_is_verified_and_idempotently_unlinked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / "agent.env"
    state = tmp_path / "transactions"
    original = b"FLEETDOCTOR_CPU_PIDS=1\n"
    env.write_bytes(original)
    token = "4" * 32
    service_state = {"ActiveState": "inactive", "UnitFileState": "disabled"}
    transaction.begin(
        token,
        {"FLEETDOCTOR_CPU_PIDS": "1,2"},
        env_path=env,
        state_dir=state,
        service="test.service",
        service_state=service_state,
        restart=False,
    )
    receipt = state / f"agent-env-{token}.json"
    original_unlink = Path.unlink
    failed = False

    def interrupt_unlink(path: Path, missing_ok: bool = False) -> None:
        nonlocal failed
        if path == receipt and not failed:
            failed = True
            raise OSError("simulated crash before receipt unlink")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", interrupt_unlink)
    with pytest.raises(OSError, match="simulated crash"):
        transaction.restore(
            token,
            state_dir=state,
            restart=False,
            expected_env_path=env,
            expected_service="test.service",
        )
    assert json.loads(receipt.read_text())["phase"] == "restored"
    recovered = transaction.restore(
        token,
        state_dir=state,
        restart=False,
        expected_env_path=env,
        expected_service="test.service",
    )
    assert recovered["completed_before_recovery"] is True
    assert env.read_bytes() == original and not receipt.exists()
