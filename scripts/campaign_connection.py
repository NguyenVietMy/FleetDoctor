"""Verified Ticket15 connection receipts, SSH sessions, and monitor API relay."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

MAX_PROTOCOL_BYTES = 64 * 1024
MAX_API_RESPONSE_BYTES = 512 * 1024
TEARDOWN_SECONDS = 30 * 60
PLAN_SHA256 = "ce914426774a3484bb76c290dcedcddb81d3a281da23fb67ada422930b59ffc0"
ConnectionPurpose = Literal["new-work", "cleanup"]


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _fingerprint(public_key: str) -> str:
    pieces = public_key.split()
    if len(pieces) != 2 or pieces[0] != "ssh-ed25519":
        raise ValueError("connection host key must be a plain ED25519 public key")
    raw = base64.b64decode(pieces[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def validate_connection_receipt(
    manifest: Mapping[str, Any],
    receipt: dict[str, Any],
    *,
    now: datetime | None = None,
    purpose: ConnectionPurpose = "new-work",
) -> dict[str, Any]:
    if purpose not in {"new-work", "cleanup"}:
        raise ValueError("connection receipt purpose is invalid")
    required = {"schema_version", "batch_id", "checked_at", "plan_sha256", "lab", "roles"}
    if set(receipt) != required or receipt.get("schema_version") != 1:
        raise ValueError("connection receipt schema is invalid")
    if (
        receipt.get("batch_id") != manifest.get("batch_id")
        or receipt.get("plan_sha256") != PLAN_SHA256
        or receipt.get("lab") != manifest.get("lab")
        or digest(receipt) != manifest.get("connection_receipt_sha256")
    ):
        raise ValueError("connection receipt does not bind the frozen manifest")
    checked_at = datetime.fromisoformat(str(receipt.get("checked_at")))
    if checked_at.tzinfo is None:
        raise ValueError("connection receipt timestamp lacks timezone")
    reference = now or datetime.now(UTC)
    if reference.tzinfo is None:
        raise ValueError("connection receipt validation time lacks timezone")
    age = reference - checked_at
    if age.total_seconds() < -60:
        raise ValueError("connection receipt is future-dated")
    if purpose == "new-work" and age.total_seconds() > 600:
        raise ValueError("connection receipt is stale for new work")
    roles = receipt.get("roles")
    instances = manifest.get("lab", {}).get("instances")
    installed = manifest.get("installed")
    if not isinstance(roles, dict) or set(roles) != {"monitor", "node-a", "node-b"}:
        raise ValueError("connection receipt roles are incomplete")
    if not isinstance(instances, dict):
        raise ValueError("manifest lab instances are unavailable")
    for role, facts in roles.items():
        required_role = {
            "instance_id",
            "private_ip",
            "boot_id",
            "ssh_host",
            "ssh_port",
            "host_public_key",
            "host_key_fingerprint",
            "protected_manifest_sha256",
            "controller_bundle_sha256",
            "inventory",
            "inventory_sha256",
            "host_key_attestation",
            "host_key_attestation_sha256",
        }
        if not isinstance(facts, dict) or set(facts) != required_role:
            raise ValueError(f"connection receipt role is malformed: {role}")
        instance = instances.get(role)
        if not isinstance(instance, dict):
            raise ValueError(f"manifest instance facts are missing: {role}")
        if (
            facts["instance_id"] != instance.get("id")
            or facts["private_ip"] != instance.get("private_ip")
            or facts["ssh_port"] != 22
        ):
            raise ValueError(f"connection endpoint does not match lab role: {role}")
        ipaddress.ip_address(str(facts["private_ip"]))
        ipaddress.ip_address(str(facts["ssh_host"]))
        if re.fullmatch(r"[0-9a-fA-F-]{36}", str(facts["boot_id"])) is None:
            raise ValueError(f"connection boot identity is invalid: {role}")
        if facts["host_key_fingerprint"] != _fingerprint(str(facts["host_public_key"])):
            raise ValueError(f"connection host key fingerprint is invalid: {role}")
        if any(
            re.fullmatch(r"[0-9a-f]{64}", str(facts[field])) is None
            for field in ("protected_manifest_sha256", "controller_bundle_sha256")
        ):
            raise ValueError(f"connection protected digest is invalid: {role}")
        if isinstance(installed, dict) and (
            not isinstance(installed.get(role), dict)
            or facts["protected_manifest_sha256"] != installed[role].get("protected_manifest")
            or facts["controller_bundle_sha256"] != installed[role].get("controller_bundle")
        ):
            raise ValueError(f"connection protected installation differs: {role}")
        inventory = facts["inventory"]
        expected_inventory = {
            "account_id": manifest["lab"]["account_id"],
            "region": manifest["lab"]["region"],
            "availability_zone": manifest["lab"]["availability_zone"],
            "role": role,
            "instance_id": instance["id"],
            "private_ip": instance["private_ip"],
            "boot_id": facts["boot_id"],
            "ssh_host": facts["ssh_host"],
            "ssh_port": 22,
        }
        if inventory != expected_inventory or facts["inventory_sha256"] != digest(inventory):
            raise ValueError(f"connection inventory provenance is invalid: {role}")
        attestation = facts["host_key_attestation"]
        expected_attestation = {
            "host": facts["ssh_host"],
            "port": 22,
            "algorithm": "ssh-ed25519",
            "public_key": facts["host_public_key"],
            "fingerprint": facts["host_key_fingerprint"],
        }
        if attestation != expected_attestation or facts["host_key_attestation_sha256"] != digest(
            attestation
        ):
            raise ValueError(f"connection host-key provenance is invalid: {role}")
    return receipt


class PersistentSshTransport:
    def __init__(
        self,
        role: str,
        role_receipt: Mapping[str, Any],
        key: Path,
        batch_id: str,
        *,
        user: str = "ec2-user",
        controller: str = "/usr/local/sbin/fleetdoctor-chaos-controller",
        call_timeout_seconds: float = 180,
        nonce: str | None = None,
        purpose: ConnectionPurpose = "new-work",
        cleanup_token: str | None = None,
    ) -> None:
        if role not in {"monitor", "node-a", "node-b"}:
            raise ValueError("SSH role is invalid")
        if user != "ec2-user" or controller != "/usr/local/sbin/fleetdoctor-chaos-controller":
            raise ValueError("SSH transport identity/controller is not allowlisted")
        if not 1 <= call_timeout_seconds <= 300:
            raise ValueError("SSH call timeout must be in 1..300 seconds")
        if purpose not in {"new-work", "cleanup"}:
            raise ValueError("SSH transport purpose is invalid")
        if purpose == "cleanup":
            if cleanup_token is None or re.fullmatch(r"[0-9a-f]{32}", cleanup_token) is None:
                raise ValueError("cleanup transport requires its exact owned token")
        elif cleanup_token is not None:
            raise ValueError("new-work transport cannot receive cleanup authority")
        info = key.lstat()
        if key.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ValueError("SSH identity file must be a regular non-symlink file")
        self.role = role
        self.role_receipt = dict(role_receipt)
        self.batch_id = batch_id
        self.call_timeout_seconds = call_timeout_seconds
        self.purpose = purpose
        self.cleanup_token = cleanup_token
        self.cleanup_scope = "monitor" if role == "monitor" else "agent"
        host = str(role_receipt["ssh_host"])
        ipaddress.ip_address(host)
        known = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            prefix=f"fleetdoctor-{role}-",
            suffix=".known_hosts",
            delete=False,
        )
        self.known_hosts = Path(known.name)
        try:
            known.write(f"{host} {role_receipt['host_public_key']}\n")
        finally:
            known.close()
        os.chmod(self.known_hosts, 0o600)
        try:
            self.process = subprocess.Popen(
                [
                    "ssh",
                    "-F",
                    "none",
                    "-T",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "ConnectionAttempts=1",
                    "-o",
                    "ServerAliveInterval=5",
                    "-o",
                    "ServerAliveCountMax=3",
                    "-o",
                    "StrictHostKeyChecking=yes",
                    "-o",
                    "HostKeyAlgorithms=ssh-ed25519",
                    "-o",
                    "UpdateHostKeys=no",
                    "-o",
                    "ControlMaster=no",
                    "-o",
                    "ProxyCommand=none",
                    "-o",
                    "ProxyJump=none",
                    "-o",
                    "UserKnownHostsFile=" + os.fspath(self.known_hosts),
                    "-o",
                    "GlobalKnownHostsFile=" + os.fspath(self.known_hosts),
                    "-i",
                    os.fspath(key),
                    f"{user}@{host}",
                    "sudo",
                    "--",
                    controller,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except BaseException:
            self.known_hosts.unlink(missing_ok=True)
            raise
        self.sequence = 0
        self.broken = False
        self.closed = False
        self._lock = threading.Lock()
        hello_nonce = nonce or secrets.token_hex(32)
        expected_identity = {
            "role": role,
            "account_id": role_receipt["inventory"]["account_id"],
            "region": role_receipt["inventory"]["region"],
            "availability_zone": role_receipt["inventory"]["availability_zone"],
            "instance_id": role_receipt["instance_id"],
            "private_ip": role_receipt["private_ip"],
            "boot_id": role_receipt["boot_id"],
            "host_public_key": role_receipt["host_public_key"],
            "host_key_fingerprint": role_receipt["host_key_fingerprint"],
        }
        try:
            line = self._exchange(
                canonical({"type": "hello", "batch_id": batch_id, "nonce": hello_nonce}) + b"\n",
                MAX_PROTOCOL_BYTES,
            )
            response = self._parse_line(line, MAX_PROTOCOL_BYTES)
            if (
                response.get("type") != "hello"
                or response.get("ok") is not True
                or response.get("batch_id") != batch_id
                or response.get("nonce") != hello_nonce
                or re.fullmatch(r"[0-9a-f]{64}", str(response.get("session_id", ""))) is None
                or response.get("protected_manifest_sha256")
                != role_receipt["protected_manifest_sha256"]
                or response.get("controller_bundle_sha256")
                != role_receipt["controller_bundle_sha256"]
                or response.get("identity") != expected_identity
            ):
                raise ValueError("authenticated controller hello does not match connection receipt")
        except BaseException:
            self._abort()
            self.known_hosts.unlink(missing_ok=True)
            raise
        self.session_id = cast(str, response["session_id"])
        self.hello_receipt = response

    def _abort(self) -> None:
        self.broken = True
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    pass

    def _exchange(self, encoded: bytes, limit: int) -> bytes:
        result: list[bytes] = []
        failure: list[BaseException] = []

        def worker() -> None:
            try:
                assert self.process.stdin is not None and self.process.stdout is not None
                self.process.stdin.write(encoded)
                self.process.stdin.flush()
                result.append(self.process.stdout.readline(limit + 1))
            except BaseException as exc:
                failure.append(exc)

        thread = threading.Thread(target=worker, name="fleetdoctor-ssh-exchange", daemon=True)
        thread.start()
        thread.join(self.call_timeout_seconds)
        if thread.is_alive():
            self._abort()
            thread.join(5)
            raise TimeoutError("persistent SSH controller call exceeded its finite deadline")
        if failure or not result:
            self._abort()
            raise RuntimeError("persistent SSH controller I/O failed") from (
                failure[0] if failure else None
            )
        return result[0]

    def _parse_line(self, line: bytes, limit: int) -> dict[str, Any]:
        if not line or len(line) > limit or not line.endswith(b"\n"):
            self._abort()
            raise RuntimeError("controller response is missing, truncated or oversized")
        try:
            response = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._abort()
            raise RuntimeError("controller response is malformed") from exc
        if not isinstance(response, dict):
            self._abort()
            raise RuntimeError("controller response must be an object")
        return cast(dict[str, Any], response)

    def call(
        self, scenario: str, action: str, token: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if self.purpose == "cleanup":
            supplied = arguments or {}
            allowed = (
                scenario == "config"
                and supplied == {"scope": self.cleanup_scope}
                and (
                    (action == "inventory" and token == "0" * 32)
                    or (
                        action in {"lookup", "status", "adopt", "restore"}
                        and token == self.cleanup_token
                    )
                )
            )
            if not allowed:
                raise PermissionError("cleanup transport request exceeds exact owned authority")
        with self._lock:
            if self.closed or self.broken or self.process.poll() is not None:
                raise RuntimeError("persistent SSH controller is not live")
            self.sequence += 1
            request_id = f"request-{self.sequence}"
            encoded = (
                canonical(
                    {
                        "id": request_id,
                        "scenario": scenario,
                        "action": action,
                        "token": token,
                        "arguments": arguments or {},
                        "batch_id": self.batch_id,
                        "session_id": self.session_id,
                    }
                )
                + b"\n"
            )
            if len(encoded) > MAX_PROTOCOL_BYTES:
                raise ValueError("controller request exceeds bound")
            limit = MAX_API_RESPONSE_BYTES if scenario == "api" else MAX_PROTOCOL_BYTES
            response = self._parse_line(self._exchange(encoded, limit), limit)
            if (
                response.get("id") != request_id
                or response.get("batch_id") != self.batch_id
                or response.get("session_id") != self.session_id
            ):
                self._abort()
                raise RuntimeError("controller response identity mismatch")
            if response.get("ok") is not True or not isinstance(response.get("result"), dict):
                raise RuntimeError(str(response.get("error", "controller request failed")))
            return cast(dict[str, Any], response["result"])

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            if not self.broken and self.process.stdin is not None:
                closer = threading.Thread(target=self.process.stdin.close, daemon=True)
                closer.start()
                closer.join(5)
                if closer.is_alive():
                    self._abort()
                    raise TimeoutError("persistent SSH stdin close exceeded its finite deadline")
            if not self.broken:
                try:
                    code = self.process.wait(timeout=TEARDOWN_SECONDS)
                except subprocess.TimeoutExpired as exc:
                    self._abort()
                    raise TimeoutError(
                        "persistent SSH cleanup exceeded its finite deadline"
                    ) from exc
                if code:
                    stderr = self.process.stderr.read()[-2000:] if self.process.stderr else b""
                    raise RuntimeError(
                        "persistent SSH controller failed: " + stderr.decode(errors="replace")
                    )
        finally:
            self.known_hosts.unlink(missing_ok=True)

    def __enter__(self) -> PersistentSshTransport:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class RelayResponse:
    def __init__(self, status_code: int, body: dict[str, Any]) -> None:
        self.status_code, self._body = status_code, body

    def raise_for_status(self) -> None:
        if not 200 <= self.status_code < 300:
            raise RuntimeError(f"verified monitor API returned HTTP {self.status_code}")

    def json(self) -> dict[str, Any]:
        return self._body


class MonitorBackend:
    def __init__(self, transport: Any) -> None:
        if transport.role != "monitor":
            raise ValueError("API backend requires the verified monitor session")
        self.transport = transport
        self.origin = f"http://{transport.role_receipt['private_ip']}:8000"

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        result = self.transport.call("api", "get", "0" * 32, {"path": path, "params": params or {}})
        if set(result) != {"status_code", "body"} or not isinstance(result["body"], dict):
            raise RuntimeError("verified monitor API envelope is malformed")
        response = RelayResponse(int(result["status_code"]), result["body"])
        response.raise_for_status()
        return response.json()

    def client_get(self, url: str, params: dict[str, Any] | None = None) -> RelayResponse:
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin != self.origin or parsed.query or parsed.fragment or not parsed.path:
            raise ValueError("client URL does not match the verified monitor collector origin")
        result = self.transport.call(
            "api", "get", "0" * 32, {"path": parsed.path, "params": params or {}}
        )
        return RelayResponse(int(result["status_code"]), cast(dict[str, Any], result["body"]))


class RelayHttpClient:
    def __init__(self, backend: MonitorBackend) -> None:
        self.backend = backend

    def get(self, url: str, params: dict[str, Any] | None = None) -> RelayResponse:
        return self.backend.client_get(url, params)
