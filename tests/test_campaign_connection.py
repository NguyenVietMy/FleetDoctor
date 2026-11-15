from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import campaign_connection as connection
import pytest


def receipt_fixture(public_key: str) -> tuple[dict[str, Any], dict[str, Any]]:
    instances = {
        role: {"id": f"i-{index:08x}", "private_ip": f"10.0.0.{index}"}
        for index, role in enumerate(("monitor", "node-a", "node-b"), start=10)
    }
    manifest: dict[str, Any] = {
        "batch_id": "batch-connection",
        "lab": {
            "account_id": "123456789012",
            "region": "us-east-1",
            "availability_zone": "us-east-1a",
            "instances": instances,
        },
        "connection_receipt_sha256": "0" * 64,
    }
    fingerprint = connection._fingerprint(public_key)
    roles: dict[str, Any] = {}
    for index, role in enumerate(("monitor", "node-a", "node-b"), start=20):
        instance = instances[role]
        ssh_host = f"198.51.100.{index}"
        boot_id = f"00000000-0000-0000-0000-0000000000{index}"
        inventory = {
            "account_id": "123456789012",
            "region": "us-east-1",
            "availability_zone": "us-east-1a",
            "role": role,
            "instance_id": instance["id"],
            "private_ip": instance["private_ip"],
            "boot_id": boot_id,
            "ssh_host": ssh_host,
            "ssh_port": 22,
        }
        host_key = {
            "host": ssh_host,
            "port": 22,
            "algorithm": "ssh-ed25519",
            "public_key": public_key,
            "fingerprint": fingerprint,
        }
        roles[role] = {
            "instance_id": instance["id"],
            "private_ip": instance["private_ip"],
            "boot_id": boot_id,
            "ssh_host": ssh_host,
            "ssh_port": 22,
            "host_public_key": public_key,
            "host_key_fingerprint": fingerprint,
            "protected_manifest_sha256": hashlib.sha256(f"manifest-{role}".encode()).hexdigest(),
            "controller_bundle_sha256": hashlib.sha256(f"bundle-{role}".encode()).hexdigest(),
            "inventory": inventory,
            "inventory_sha256": connection.digest(inventory),
            "host_key_attestation": host_key,
            "host_key_attestation_sha256": connection.digest(host_key),
        }
    receipt = {
        "schema_version": 1,
        "batch_id": manifest["batch_id"],
        "checked_at": datetime.now(UTC).isoformat(),
        "plan_sha256": connection.PLAN_SHA256,
        "lab": manifest["lab"],
        "roles": roles,
    }
    manifest["connection_receipt_sha256"] = connection.digest(receipt)
    return manifest, receipt


def test_connection_receipt_binds_public_ssh_endpoint_separately_from_private_collector() -> None:
    manifest, receipt = receipt_fixture("ssh-ed25519 AAAA")
    assert connection.validate_connection_receipt(manifest, receipt) is receipt
    assert receipt["roles"]["monitor"]["ssh_host"] != receipt["roles"]["monitor"]["private_ip"]
    changed = deepcopy(receipt)
    changed["roles"]["node-a"]["ssh_host"] = "198.51.100.99"
    manifest["connection_receipt_sha256"] = connection.digest(changed)
    with pytest.raises(ValueError, match="inventory provenance"):
        connection.validate_connection_receipt(manifest, changed)


def test_connection_receipt_separates_new_work_freshness_from_cleanup_identity() -> None:
    manifest, receipt = receipt_fixture("ssh-ed25519 AAAA")
    now = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
    receipt["checked_at"] = (now - timedelta(seconds=601)).isoformat()
    manifest["connection_receipt_sha256"] = connection.digest(receipt)

    with pytest.raises(ValueError, match="stale for new work"):
        connection.validate_connection_receipt(manifest, receipt, now=now)
    assert (
        connection.validate_connection_receipt(manifest, receipt, now=now, purpose="cleanup")
        is receipt
    )
    with pytest.raises(ValueError, match="purpose is invalid"):
        connection.validate_connection_receipt(manifest, receipt, now=now, purpose="unknown")  # type: ignore[arg-type]


@pytest.mark.parametrize("purpose", ["new-work", "cleanup"])
def test_connection_receipt_future_bound_applies_to_every_purpose(purpose: str) -> None:
    manifest, receipt = receipt_fixture("ssh-ed25519 AAAA")
    now = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
    receipt["checked_at"] = (now + timedelta(seconds=61)).isoformat()
    manifest["connection_receipt_sha256"] = connection.digest(receipt)

    with pytest.raises(ValueError, match="future-dated"):
        connection.validate_connection_receipt(manifest, receipt, now=now, purpose=purpose)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "damage",
    [
        "digest",
        "timestamp",
        "batch",
        "account",
        "role",
        "instance",
        "region",
        "az",
        "private_ip",
        "boot",
        "host_key",
        "protected_manifest",
        "bundle",
    ],
)
def test_historical_cleanup_still_rejects_changed_identity_or_provenance(damage: str) -> None:
    source_manifest, source_receipt = receipt_fixture("ssh-ed25519 AAAA")
    manifest = deepcopy(source_manifest)
    receipt = deepcopy(source_receipt)
    manifest["installed"] = {
        name: {
            "protected_manifest": facts["protected_manifest_sha256"],
            "controller_bundle": facts["controller_bundle_sha256"],
        }
        for name, facts in source_receipt["roles"].items()
    }
    receipt["checked_at"] = "2020-01-01T00:00:00+00:00"
    role = receipt["roles"]["node-a"]
    if damage == "digest":
        role["boot_id"] = "11111111-1111-1111-1111-111111111111"
    elif damage == "timestamp":
        receipt["checked_at"] = "not-a-time"
    elif damage == "batch":
        receipt["batch_id"] = "different-batch"
    elif damage == "account":
        receipt["lab"]["account_id"] = "000000000000"
    elif damage == "role":
        role["inventory"]["role"] = "node-b"
    elif damage == "instance":
        role["instance_id"] = "i-ffffffff"
    elif damage == "region":
        role["inventory"]["region"] = "us-west-2"
    elif damage == "az":
        role["inventory"]["availability_zone"] = "us-east-1b"
    elif damage == "private_ip":
        role["private_ip"] = "10.0.0.250"
    elif damage == "boot":
        role["boot_id"] = "11111111-1111-1111-1111-111111111111"
    elif damage == "host_key":
        role["host_key_fingerprint"] = "SHA256:wrong"
    elif damage == "protected_manifest":
        role["protected_manifest_sha256"] = "0" * 64
    elif damage == "bundle":
        role["controller_bundle_sha256"] = "0" * 64
    if damage != "digest":
        manifest["connection_receipt_sha256"] = connection.digest(receipt)

    with pytest.raises((ValueError, TypeError)):
        connection.validate_connection_receipt(manifest, receipt, purpose="cleanup")


@pytest.mark.parametrize(
    ("scenario", "action", "token", "arguments"),
    [
        ("cpu", "begin", "1" * 32, {}),
        ("config", "begin", "1" * 32, {"scope": "agent"}),
        ("config", "restore", "2" * 32, {"scope": "agent"}),
        ("config", "restore", "1" * 32, {"scope": "monitor"}),
        ("config", "inventory", "1" * 32, {"scope": "agent"}),
    ],
)
def test_cleanup_transport_rejects_noncleanup_authority_before_io(
    scenario: str, action: str, token: str, arguments: dict[str, Any]
) -> None:
    transport = object.__new__(connection.PersistentSshTransport)
    transport.purpose = "cleanup"
    transport.cleanup_token = "1" * 32
    transport.cleanup_scope = "agent"

    with pytest.raises(PermissionError, match="exact owned authority"):
        transport.call(scenario, action, token, arguments)


@pytest.mark.parametrize(
    "damage",
    [
        "nonce",
        "batch",
        "role",
        "instance",
        "account",
        "region",
        "az",
        "private_ip",
        "boot",
        "manifest",
        "bundle",
        "host_key",
        "host_fingerprint",
    ],
)
def test_client_hello_rejects_every_stable_or_challenge_mismatch_before_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    manifest, receipt = receipt_fixture("ssh-ed25519 AAAA")
    role = receipt["roles"]["node-a"]
    nonce = "a" * 64
    identity = {
        "role": "node-a",
        "account_id": role["inventory"]["account_id"],
        "region": role["inventory"]["region"],
        "availability_zone": role["inventory"]["availability_zone"],
        "instance_id": role["instance_id"],
        "private_ip": role["private_ip"],
        "boot_id": role["boot_id"],
        "host_public_key": role["host_public_key"],
        "host_key_fingerprint": role["host_key_fingerprint"],
    }
    response = {
        "type": "hello",
        "ok": True,
        "batch_id": manifest["batch_id"],
        "nonce": nonce,
        "session_id": "b" * 64,
        "protected_manifest_sha256": role["protected_manifest_sha256"],
        "controller_bundle_sha256": role["controller_bundle_sha256"],
        "identity": identity,
    }
    target = {
        "nonce": (response, "nonce"),
        "batch": (response, "batch_id"),
        "role": (identity, "role"),
        "instance": (identity, "instance_id"),
        "account": (identity, "account_id"),
        "region": (identity, "region"),
        "az": (identity, "availability_zone"),
        "private_ip": (identity, "private_ip"),
        "boot": (identity, "boot_id"),
        "manifest": (response, "protected_manifest_sha256"),
        "bundle": (response, "controller_bundle_sha256"),
        "host_key": (identity, "host_public_key"),
        "host_fingerprint": (identity, "host_key_fingerprint"),
    }[damage]
    target[0][target[1]] = "wrong"

    class Process:
        def __init__(self) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(json.dumps(response).encode() + b"\n")
            self.stderr = io.BytesIO()
            self.code: int | None = None

        def poll(self) -> int | None:
            return self.code

        def wait(self, timeout: float) -> int:
            self.code = 0
            return 0

        def terminate(self) -> None:
            self.code = 0

        def kill(self) -> None:
            self.code = 1

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    key = tmp_path / "key"
    key.write_bytes(b"synthetic")
    with pytest.raises(ValueError, match="hello does not match"):
        connection.PersistentSshTransport("node-a", role, key, manifest["batch_id"], nonce=nonce)


@pytest.mark.skipif(
    shutil.which("ssh") is None or shutil.which("ssh-keygen") is None,
    reason="OpenSSH parser tools unavailable",
)
def test_port22_pin_uses_bare_host_and_openssh_parsers_without_connecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "synthetic-id"
    generated = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert generated.returncode == 0
    public_key = (tmp_path / "synthetic-id.pub").read_text(encoding="ascii").strip()
    public_key = " ".join(public_key.split()[:2])
    manifest, receipt = receipt_fixture(public_key)
    role = receipt["roles"]["monitor"]
    nonce = "a" * 64
    identity = {
        "role": "monitor",
        "account_id": role["inventory"]["account_id"],
        "region": role["inventory"]["region"],
        "availability_zone": role["inventory"]["availability_zone"],
        "instance_id": role["instance_id"],
        "private_ip": role["private_ip"],
        "boot_id": role["boot_id"],
        "host_public_key": role["host_public_key"],
        "host_key_fingerprint": role["host_key_fingerprint"],
    }
    hello = {
        "type": "hello",
        "ok": True,
        "batch_id": manifest["batch_id"],
        "nonce": nonce,
        "session_id": "b" * 64,
        "protected_manifest_sha256": role["protected_manifest_sha256"],
        "controller_bundle_sha256": role["controller_bundle_sha256"],
        "identity": identity,
    }
    launched: list[str] = []

    class Process:
        def __init__(self) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(json.dumps(hello).encode() + b"\n")
            self.stderr = io.BytesIO()
            self.code: int | None = None

        def poll(self) -> int | None:
            return self.code

        def wait(self, timeout: float) -> int:
            self.code = 0
            return 0

        def terminate(self) -> None:
            self.code = 0

        def kill(self) -> None:
            self.code = 1

    real_popen = subprocess.Popen

    def fake_popen(argv: list[str], **kwargs: Any) -> Process:
        launched.extend(argv)
        return Process()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    transport = connection.PersistentSshTransport(
        "monitor", role, key, manifest["batch_id"], nonce=nonce
    )
    known_hosts = transport.known_hosts
    assert known_hosts.read_text(encoding="ascii") == f"{role['ssh_host']} {public_key}\n"
    assert f"[{role['ssh_host']}]:22" not in known_hosts.read_text(encoding="ascii")
    assert ["-F", "none"] == launched[launched.index("-F") : launched.index("-F") + 2]
    monkeypatch.setattr(subprocess, "Popen", real_popen)
    lookup = subprocess.run(
        ["ssh-keygen", "-F", role["ssh_host"], "-f", str(known_hosts)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert lookup.returncode == 0 and role["ssh_host"] in lookup.stdout
    parsed = subprocess.run(
        [
            "ssh",
            "-G",
            "-F",
            "none",
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(known_hosts),
            f"ec2-user@{role['ssh_host']}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert parsed.returncode == 0
    transport.close()
    assert not known_hosts.exists()
