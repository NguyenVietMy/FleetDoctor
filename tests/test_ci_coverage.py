import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest
from check_ci_coverage import ENVIRONMENTS, audit_fixtures, audit_services, audit_steps, junit

CASES = ["tests/test_rules.py::test_reset[boot]", "tests/test_rules.py::test_reset[session]"]
CONTRACT: dict[str, Any] = {
    "schema_version": 1,
    "requirements": [{"id": "reset", "tests": CASES}],
    "required_steps": ["install", "services"],
    "service_sections": ["api_contract", "disk_incidents"],
}


def report(path: Path, states: dict[str, str]) -> Path:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite", tests=str(len(states)), errors="0", failures="0")
    for node, state in states.items():
        filename, name = node.split("::", 1)
        case = ET.SubElement(
            suite, "testcase", classname=filename[:-3].replace("/", "."), name=name
        )
        if state != "passed":
            ET.SubElement(case, state)
    ET.ElementTree(root).write(path, encoding="utf-8")
    return path


def reports(tmp_path: Path) -> dict[str, Path]:
    return {
        name: report(tmp_path / f"{name}.xml", dict.fromkeys(CASES, "passed"))
        for name in ENVIRONMENTS
    }


def test_required_parameter_cases_pass_in_each_designated_environment(tmp_path: Path) -> None:
    files = reports(tmp_path)
    result = audit_fixtures(CONTRACT, files)
    assert result["errors"] == []
    assert set(result["environments"]) == set(ENVIRONMENTS)
    assert all(value["required_cases"] == 2 for value in result["environments"].values())


@pytest.mark.parametrize("state", ["missing", "skipped", "failure", "error"])
def test_passing_parameter_sibling_or_other_environment_cannot_hide_bad_case(
    tmp_path: Path, state: str
) -> None:
    files = reports(tmp_path)
    states = {CASES[0]: "passed"}
    if state != "missing":
        states[CASES[1]] = state
    report(files["linux-root"], states)
    errors = audit_fixtures(CONTRACT, files)["errors"]
    assert any("linux-root" in error and CASES[1] in error for error in errors)


@pytest.mark.parametrize("damage", ["missing_environment", "missing_file", "malformed", "empty"])
def test_missing_or_incomplete_reports_fail_closed(tmp_path: Path, damage: str) -> None:
    files = reports(tmp_path)
    if damage == "missing_environment":
        files.pop("linux-host")
    elif damage == "missing_file":
        files["linux-host"].unlink()
    elif damage == "malformed":
        files["linux-host"].write_text("<broken", encoding="utf-8")
    else:
        files["linux-host"].write_text("<testsuites />", encoding="utf-8")
    assert audit_fixtures(CONTRACT, files)["errors"]


def test_nonrequired_platform_skip_is_visible_but_any_failure_blocks(tmp_path: Path) -> None:
    files = reports(tmp_path)
    optional = "tests/test_platform.py::test_windows_job"
    states = dict.fromkeys(CASES, "passed") | {optional: "skipped"}
    report(files["linux-host"], states)
    result = audit_fixtures(CONTRACT, files)
    assert not result["errors"]
    assert result["environments"]["linux-host"]["skipped_not_required"] == [optional]
    states[optional] = "failure"
    report(files["linux-host"], states)
    assert audit_fixtures(CONTRACT, files)["errors"]


def test_duplicate_junit_identity_cannot_overwrite_a_failed_case(tmp_path: Path) -> None:
    path = report(tmp_path / "proof.xml", {CASES[0]: "failure"})
    root = ET.parse(path).getroot()
    suite = root[0]
    ET.SubElement(suite, "testcase", classname="tests.test_rules", name="test_reset[boot]")
    ET.ElementTree(root).write(path, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        junit(path)


def test_suite_error_blocks_even_without_a_failure_testcase(tmp_path: Path) -> None:
    path = report(tmp_path / "proof.xml", dict.fromkeys(CASES, "passed"))
    root = ET.parse(path).getroot()
    root[0].set("errors", "1")
    ET.ElementTree(root).write(path, encoding="utf-8")
    assert junit(path)[1]


@pytest.mark.parametrize("outcome", ["skipped", "failure", "cancelled"])
def test_required_steps_use_outcome_so_continue_on_error_cannot_mask_failure(outcome: str) -> None:
    steps = {
        "install": {"outcome": "success", "conclusion": "success"},
        "services": {"outcome": outcome, "conclusion": "success"},
    }
    assert audit_steps(CONTRACT, steps) == ["required CI step did not succeed: services"]
    assert len(audit_steps(CONTRACT, {})) == 2
    steps["services"] = {"outcome": "success", "conclusion": "success"}
    assert audit_steps(CONTRACT, steps) == []


@pytest.mark.parametrize("damage", [None, "revision", "status", "source_after", "disk_incidents"])
def test_service_proof_requires_current_revision_complete_sections_and_unchanged_source(
    tmp_path: Path, damage: str | None
) -> None:
    proof = {
        "status": "passed",
        "revision": "a" * 40,
        "aws_execution": False,
        "environment": "isolated-docker-synthetic-two-node",
        "cleanup": "removed_only_unique_test_project",
        "source_before": {"revision": "a" * 40, "dirty": False, "sha256": {"source.py": "digest"}},
        "source_after": {"revision": "a" * 40, "dirty": False, "sha256": {"source.py": "digest"}},
        "api_contract": {"rejected_ingest_did_not_publish": True},
        "disk_incidents": {"real_database_outage_same_sample_retry": True},
    }
    if damage:
        proof.pop(damage)
    path = tmp_path / "service.json"
    path.write_text(json.dumps(proof), encoding="utf-8")
    assert bool(audit_services(CONTRACT, path, "a" * 40)) is bool(damage)


def test_local_cli_receipt_cannot_claim_full_ci_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from check_ci_coverage import main

    files = reports(tmp_path)
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps(CONTRACT), encoding="utf-8")
    output = tmp_path / "receipt.json"
    argv = ["check_ci_coverage", "--contract", str(contract), "--output", str(output)]
    for environment, path in files.items():
        argv.extend(["--report", f"{environment}={path}"])
    monkeypatch.setattr(
        "check_ci_coverage.subprocess.check_output",
        lambda command, **kwargs: "a" * 40 + "\n" if command[1] == "rev-parse" else "",
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.setattr("sys.argv", argv + ["--fixtures-only"])
    main()
    result = json.loads(output.read_text())
    assert result["status"] == "fixture_coverage_passed" and result["scope"] == "local-fixtures"
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit, match="1"):
        main()
    result = json.loads(output.read_text())
    assert result["status"] == "failed"
    assert "full verdict requires matching GitHub Actions context" in result["errors"]


def test_committed_contract_maps_nonempty_unique_prd_cases_and_existing_ci_steps() -> None:
    root = Path(__file__).resolve().parents[1]
    contract = json.loads((root / "docs/ci-coverage.json").read_text())
    import yaml

    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    steps = {
        step["id"] for step in workflow["jobs"]["filesystem-and-services"]["steps"] if "id" in step
    }
    assert len(contract["requirements"]) >= 22
    assert len({requirement["id"] for requirement in contract["requirements"]}) == len(
        contract["requirements"]
    )
    assert set(contract["required_steps"]) <= steps
    for requirement in contract["requirements"]:
        assert requirement["clause"] and requirement["tests"]
        for node in requirement["tests"]:
            filename, name = node.split("::", 1)
            assert f"def {name.split('[', 1)[0]}(" in (root / filename).read_text(encoding="utf-8")
