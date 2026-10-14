"""Run the bounded Task04 disk lifecycle with a retained collector restart."""

import argparse
import json
import shlex
import signal
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
from chaos_disk import API, RemoteInjector
from chaos_harness import Backend, DiskHarness, write_report
from deploy_lab import load_env, source_hashes, validate_live_scope
from lab import addresses, command, inventory
from source_freeze import validate_source_freeze


def bounded_command(ssh: list[str], remote: str, deadline: float) -> str:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("collector restart callback deadline")
    return command(ssh + [remote], timeout=max(1, min(45, int(remaining))))


def collector_identity(ssh: list[str], deadline: float) -> dict[str, Any]:
    value = bounded_command(
        ssh,
        'cd /opt/fleetdoctor/current && id=$(sudo docker compose ps -q collector) && test -n "$id" && sudo docker inspect --format \'{{json .Id}} {{json .State.Pid}} {{json .State.StartedAt}}\' "$id"',
        deadline,
    ).strip()
    decoder = json.JSONDecoder()

    def next_value(offset: int) -> tuple[Any, int]:
        while offset < len(value) and value[offset].isspace():
            offset += 1
        return decoder.raw_decode(value, offset)

    identifier, offset = next_value(0)
    pid, offset = next_value(offset)
    started, offset = next_value(offset)
    if value[offset:].strip():
        raise ValueError("unexpected collector process identity fields")
    if (
        not isinstance(identifier, str)
        or type(pid) is not int
        or pid <= 0
        or not isinstance(started, str)
        or not started
    ):
        raise ValueError("invalid collector process identity")
    return {"container_id": identifier, "pid": pid, "started_at": started}


def database_snapshot(
    ssh: list[str], node: str, incident_id: str, deadline: float
) -> dict[str, Any]:
    identifier = str(UUID(incident_id))
    if node not in ("node-a", "node-b"):
        raise ValueError("invalid checkpoint node")
    statement = (
        "SELECT json_build_object("
        "'incident',(SELECT record FROM incidents WHERE id="
        + f"'{identifier}'::uuid),'checkpoint',(SELECT record FROM ingestion_checkpoints WHERE node_id="
        + f"'{node}'),'incident_count',(SELECT count(*) FROM incidents WHERE node_id="
        + f"'{node}'))::text"
    )
    remote = (
        "cd /opt/fleetdoctor/current && sudo docker compose exec -T postgres "
        "psql -U fleetdoctor -d fleetdoctor -v ON_ERROR_STOP=1 -Atc " + shlex.quote(statement)
    )
    result: dict[str, Any] = json.loads(bounded_command(ssh, remote, deadline))
    if result.get("incident") is None or result.get("checkpoint") is None:
        raise ValueError("canonical incident/checkpoint snapshot is incomplete")
    return result


def grafana_incident(settings: dict[str, str], incident_id: str) -> dict[str, Any]:
    response = httpx.post(
        "http://127.0.0.1:3000/api/ds/query",
        auth=("admin", settings["GRAFANA_PASSWORD"]),
        timeout=4,
        trust_env=False,
        json={
            "queries": [
                {
                    "refId": "A",
                    "datasource": {
                        "uid": "incidents",
                        "type": "grafana-postgresql-datasource",
                    },
                    "format": "table",
                    "rawSql": "SELECT id::text,node_id,resource,severity,status,opened_at,observed_at,updated_at,resolved_at FROM incidents WHERE id='"
                    + incident_id
                    + "'::uuid",
                }
            ],
            "from": "now-1h",
            "to": "now",
        },
    )
    response.raise_for_status()
    value: dict[str, Any] = response.json()
    if value["results"]["A"].get("error"):
        raise ValueError("Grafana incident datasource query failed")
    return value


def require_active_incident(record: dict[str, Any], incident_id: str, source: str) -> None:
    try:
        actual_id = str(UUID(record["id"]))
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError(f"{source} canonical incident identity is invalid") from None
    if actual_id != incident_id:
        raise ValueError(f"{source} canonical incident identity changed")
    if record.get("status") != "active":
        raise ValueError(f"{source} canonical incident is not active")


def restart_collector(
    ssh: list[str],
    api: Backend,
    settings: dict[str, str],
    report: dict[str, Any],
    deadline: float,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if monotonic() >= deadline:
        raise TimeoutError("collector restart callback deadline")
    incident_id = str(UUID(report["incident_id"]))
    before_detail = api.get("/diagnoses/" + incident_id)
    before_db = database_snapshot(ssh, report["target"], incident_id, deadline)
    require_active_incident(before_detail, incident_id, "pre-restart API")
    require_active_incident(before_db["incident"], incident_id, "pre-restart database")
    before_identity = collector_identity(ssh, deadline)
    attempted = False
    failure: BaseException | None = None
    result: dict[str, Any] = {
        "restart_started_at": datetime.now(UTC).isoformat(),
        "collector_before": before_identity,
        "database_before": before_db,
        "api_before": before_detail,
    }
    try:
        if monotonic() >= deadline:
            raise TimeoutError("collector restart callback deadline before stop")
        attempted = True
        bounded_command(
            ssh,
            "cd /opt/fleetdoctor/current && sudo docker compose stop collector",
            deadline,
        )
        bounded_command(
            ssh,
            "cd /opt/fleetdoctor/current && sudo docker compose up -d --force-recreate --no-deps collector",
            deadline,
        )
        readiness_deadline = min(deadline, monotonic() + 45)
        while True:
            if monotonic() > readiness_deadline:
                raise TimeoutError("collector readiness exceeded 45 seconds")
            try:
                health = api.get("/health")
                if monotonic() > readiness_deadline:
                    raise TimeoutError("collector readiness exceeded 45 seconds")
                if health.get("status") == "ok":
                    break
            except (httpx.HTTPError, ValueError, KeyError):
                pass
            sleep(0.2)
        if monotonic() > deadline:
            raise TimeoutError("collector restart callback deadline")
        after_identity = collector_identity(ssh, deadline)
        if after_identity["container_id"] == before_identity["container_id"]:
            raise ValueError("collector container was not recreated")
        after_db = database_snapshot(ssh, report["target"], incident_id, deadline)
        after_detail = api.get("/diagnoses/" + incident_id)
        require_active_incident(after_detail, incident_id, "post-restart API")
        require_active_incident(after_db["incident"], incident_id, "post-restart database")
        for field in ("id", "opening_evidence", "configuration", "severity", "opened_at"):
            if after_detail[field] != before_detail[field]:
                raise ValueError(f"canonical incident {field} changed across restart")
        before_checkpoint = before_db["checkpoint"]
        after_checkpoint = after_db["checkpoint"]
        if (
            after_checkpoint["node_id"] != before_checkpoint["node_id"]
            or after_checkpoint["revision"] < before_checkpoint["revision"]
            or after_checkpoint["latest"]["sequence"] < before_checkpoint["latest"]["sequence"]
        ):
            raise ValueError("durable checkpoint ordering regressed across restart")
        result.update(
            collector_after=after_identity,
            database_after=after_db,
            api_after=after_detail,
            grafana_incident=grafana_incident(settings, incident_id),
            node_b=api.get("/nodes/node-b/metrics"),
            restart_finished_at=datetime.now(UTC).isoformat(),
            collector_wide_interruption=True,
        )
        if result["node_b"]["active_incident_count"] != 0:
            raise ValueError("reference node acquired an incident")
    except BaseException as exc:
        failure = exc
    finally:
        if attempted:
            try:
                cleanup_deadline = monotonic() + 90.0
                bounded_command(
                    ssh,
                    "cd /opt/fleetdoctor/current && sudo docker compose up -d --no-deps --wait --wait-timeout 45 collector",
                    cleanup_deadline,
                )
                result["collector_restoration"] = "confirmed_active"
            except BaseException as restore_exc:
                result["collector_restoration"] = "failed"
                report.setdefault("errors", []).append(
                    "collector restoration: " + type(restore_exc).__name__
                )
                if failure is None:
                    failure = restore_exc
                else:
                    report.setdefault("secondary_errors", []).append(
                        "collector restoration: " + type(restore_exc).__name__
                    )
    if failure is not None:
        report["collector_restart_failure"] = {
            "type": type(failure).__name__,
            "restoration": result.get("collector_restoration", "not_attempted"),
        }
        raise failure
    return result


def execute(args: argparse.Namespace) -> None:
    freeze = validate_source_freeze(args.source_freeze)
    preflight: dict[str, Any] = json.loads(args.preflight.read_text(encoding="utf-8-sig"))
    if preflight.get("status") != "passed":
        raise ValueError("successful healthy preflight required")
    if preflight.get("source_sha256") != source_hashes():
        raise ValueError("preflight source differs from approved checkout")
    age = (datetime.now(UTC) - datetime.fromisoformat(preflight["finished_at"])).total_seconds()
    if not 0 <= age <= 300:
        raise ValueError("preflight must be completed within five minutes")
    values = inventory(args.inventory)
    validate_live_scope(args.profile, values)
    public = addresses(args.profile, values)
    settings = load_env(args.env)
    injectors = {
        role: RemoteInjector(
            [
                "ssh",
                "-i",
                str(args.key),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=accept-new",
                f"ec2-user@{host}",
            ]
        )
        for role, host in public.items()
        if role != "monitor"
    }
    monitor_ssh = [
        "ssh",
        "-i",
        str(args.key),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"ec2-user@{public['monitor']}",
    ]
    api = API(args.api)
    harness = DiskHarness(
        api,
        injectors["node-a"],
        "node-a",
        "node-b",
        args.output,
        {
            "kind": "AWS-existing-three-node-lab",
            "preflight": str(args.preflight),
            "source_freeze_sha256": freeze["sha256"],
            "plan_sha256": freeze["plan_sha256"],
            "visual_inspection": "unrun",
        },
    )
    harness.max_injection_seconds = 240
    harness.after_diagnosis = lambda report, deadline: restart_collector(
        monitor_ssh, api, settings, report, deadline
    )
    try:
        harness.report["resource_mappings"] = {
            node: injector.probe() for node, injector in injectors.items()
        }
        harness.run()
        try:
            final = validate_source_freeze(args.source_freeze)
        except BaseException as exc:
            harness.report["status"] = "failed"
            harness.report["source_validation_final"] = {
                "status": "failed",
                "matched": False,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
            harness.report.setdefault("errors", []).append(
                "final source validation: " + type(exc).__name__ + ": " + str(exc)
            )
            raise
        harness.report["source_validation_final"] = {
            "status": "matched",
            "aggregate_sha256": final["sha256"],
        }
    finally:
        harness.report["remote_commands"] = {
            node: injector.commands for node, injector in injectors.items()
        }
        write_report(args.output, harness.report)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--source-freeze", type=Path, required=True)
    parser.add_argument("--env", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--profile", default="fleetdoctor")
    parser.add_argument("--key", type=Path, default=Path.home() / ".ssh/fleetdoctor")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("use a new report path; failed runs are retained")
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def interrupted(signum: int, frame: object) -> None:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise InterruptedError("restart demonstration interrupted")

    old = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        execute(args)
    except BaseException as exc:
        if not args.output.exists():
            write_report(
                args.output,
                {
                    "schema_version": 1,
                    "scenario": "disk_fill_collector_restart",
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "finished_at": datetime.now(UTC).isoformat(),
                },
            )
        raise
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)
    print(f"Task04 restart demonstration passed: {args.output}")


if __name__ == "__main__":
    main()
