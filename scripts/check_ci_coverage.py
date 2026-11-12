"""Check the audited PRD cases against retained results, without claiming live proof."""

import argparse
import hashlib
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENTS = ("linux-host", "linux-root", "linux-nonroot")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def junit(path: Path) -> tuple[dict[str, str], list[str]]:
    """Return exact pytest node IDs; never let a passing sibling hide a bad case."""
    root = ET.parse(path).getroot()
    if root.tag not in ("testsuites", "testsuite"):
        raise ValueError("expected JUnit testsuite(s)")
    cases: dict[str, str] = {}
    errors: list[str] = []
    for case in root.iter("testcase"):
        module = case.get("classname", "")
        name = case.get("name", "")
        if not module or not name:
            # Pytest emits module-level skipped imports without a classname.
            if case.find("skipped") is not None and name:
                key = name
            else:
                raise ValueError("JUnit testcase has no identity")
        else:
            key = module.replace(".", "/") + ".py::" + name
        if key in cases:
            raise ValueError(f"duplicate JUnit identity: {key}")
        state = (
            "failed"
            if case.find("failure") is not None or case.find("error") is not None
            else "skipped"
            if case.find("skipped") is not None
            else "passed"
        )
        cases[key] = state
        if state == "failed":
            errors.append(f"failed/error case: {key}")
    if not cases:
        raise ValueError("empty JUnit report")
    # Collection/internal errors may be represented outside testcases.
    for suite in root.iter("testsuite"):
        for attr in ("errors", "failures"):
            if int(suite.get(attr, "0")):
                errors.append(f"JUnit suite declares {attr}")
    return cases, errors


def audit_fixtures(contract: dict[str, Any], reports: dict[str, Path]) -> dict[str, Any]:
    if contract.get("schema_version") != 1 or not contract.get("requirements"):
        raise ValueError("invalid or empty coverage contract")
    errors: list[str] = []
    results: dict[str, Any] = {}
    for environment in ENVIRONMENTS:
        try:
            path = reports[environment]
            cases, failures = junit(path)
            errors.extend(f"{environment}: {failure}" for failure in failures)
            required: set[str] = set()
            for requirement in contract["requirements"]:
                nodes = requirement["tests"]
                if not nodes or len(nodes) != len(set(nodes)):
                    raise ValueError("empty or duplicate requirement test identities")
                required.update(nodes)
            for node in sorted(required):
                state = cases.get(node, "missing")
                if state != "passed":
                    errors.append(f"{environment}: {state} required case: {node}")
            results[environment] = {
                "path": str(path),
                "sha256": digest(path),
                "required_cases": len(required),
                "passed": sum(state == "passed" for state in cases.values()),
                "skipped_not_required": sorted(
                    node
                    for node, state in cases.items()
                    if state == "skipped" and node not in required
                ),
            }
        except (KeyError, OSError, ValueError, ET.ParseError) as exc:
            errors.append(f"{environment}: {exc}")
    return {"errors": errors, "environments": results}


def audit_services(contract: dict[str, Any], path: Path, revision: str) -> list[str]:
    proof = json.loads(path.read_text(encoding="utf-8"))
    errors = []
    for key, expected in (
        ("status", "passed"),
        ("revision", revision),
        ("aws_execution", False),
        ("environment", "isolated-docker-synthetic-two-node"),
        ("cleanup", "removed_only_unique_test_project"),
    ):
        if key not in proof or proof[key] != expected:
            errors.append(f"service receipt: unexpected {key}")
    if not proof.get("source_before") or proof.get("source_before") != proof.get("source_after"):
        errors.append("service receipt: missing or changed source snapshot")
    snapshot = proof.get("source_before", {})
    if snapshot.get("revision") != revision or snapshot.get("dirty") is not False:
        errors.append("service receipt: snapshot is not the clean identified commit")
    for key in contract["service_sections"]:
        if not proof.get(key):
            errors.append(f"service receipt: missing {key}")
    return errors


def audit_steps(contract: dict[str, Any], steps: dict[str, Any]) -> list[str]:
    return [
        f"required CI step did not succeed: {name}"
        for name in contract["required_steps"]
        if steps.get(name, {}).get("outcome") != "success"
        or steps.get(name, {}).get("conclusion") != "success"
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=ROOT / "docs/ci-coverage.json")
    parser.add_argument("--report", action="append", default=[], metavar="ENVIRONMENT=PATH")
    parser.add_argument("--integration", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--fixtures-only", action="store_true", help="local fixture proof; never a full CI verdict"
    )
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "status": "failed",
        "scope": "local-fixtures" if args.fixtures_only else "hosted-ci",
        "revision": revision,
        "run_id": os.getenv("GITHUB_RUN_ID"),
        "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        "created_at": datetime.now(UTC).isoformat(),
        "live_aws_or_model_proof": False,
    }
    try:
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        receipt["contract_sha256"] = digest(args.contract)
        reports: dict[str, Path] = {}
        for item in args.report:
            environment, filename = item.split("=", 1)
            if environment not in ENVIRONMENTS or environment in reports:
                raise ValueError("unknown or duplicate report environment")
            reports[environment] = Path(filename)
        receipt.update(audit_fixtures(contract, reports))
        if not args.fixtures_only:
            if (
                os.getenv("GITHUB_ACTIONS") != "true"
                or os.getenv("GITHUB_SHA") != revision
                or not receipt["run_id"]
                or not receipt["run_attempt"]
            ):
                receipt["errors"].append("full verdict requires matching GitHub Actions context")
            if subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=ROOT, text=True
            ).strip():
                receipt["errors"].append("full verdict requires a clean current-commit checkout")
            steps = json.loads(os.getenv("FLEETDOCTOR_CI_STEPS", "{}"))
            receipt["steps"] = steps
            receipt["errors"].extend(audit_steps(contract, steps))
            if args.integration is None:
                receipt["errors"].append("service integration receipt required")
            else:
                receipt["errors"].extend(audit_services(contract, args.integration, revision))
                receipt["integration_sha256"] = digest(args.integration)
        if not receipt["errors"]:
            receipt["status"] = "fixture_coverage_passed" if args.fixtures_only else "passed"
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as exc:
        receipt.setdefault("errors", []).append(f"invalid or missing evidence: {exc}")
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"{receipt['status']}: {args.output}")
    if receipt["status"] == "failed":
        for error in receipt.get("errors", []):
            print(error)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
