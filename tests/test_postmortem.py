import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

import fleetdoctor.postmortem as postmortem_module
from fleetdoctor.agent import make_sample
from fleetdoctor.collection import from_statvfs
from fleetdoctor.collector import create_app
from fleetdoctor.postmortem import (
    DraftingError,
    _run_owned,
    generate_bundle,
    validate_portable_example,
)
from fleetdoctor.schema import Filesystem, Sample
from fleetdoctor.store import FixtureStore

FIXTURES = Path(__file__).parent / "fixtures"
SCENARIO = FIXTURES / "postmortem-scenario.json"
RESPONSE = FIXTURES / "postmortem-response.json"
INCIDENT_ID = "11111111-1111-4111-8111-111111111111"
MODEL = "claude-opus-5-5"
DISK_PATH = "/var/lib/fleetdoctor/chaos/disk"
TOKENS = {"node-a": SecretStr("a" * 40), "node-b": SecretStr("b" * 40)}


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def dump(path: Path, value: Any) -> Path:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def fixture_bundle(tmp_path: Path, *, response: Path = RESPONSE, name: str = "bundle") -> Path:
    return generate_bundle(
        incident_id=INCIDENT_ID,
        scenario_record=SCENARIO,
        output_dir=tmp_path / name,
        backend="fixture",
        fixture_response=response,
    )


def assert_pointer(document: Any, pointer: str) -> None:
    current = document
    for raw in pointer.removeprefix("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        current = current[int(token)] if isinstance(current, list) else current[token]


def test_fixture_bundle_is_complete_immutable_and_portable(tmp_path: Path) -> None:
    before = {path: path.read_bytes() for path in (SCENARIO, RESPONSE)}
    output = fixture_bundle(tmp_path)
    assert {path: path.read_bytes() for path in before} == before
    manifest = load(output / "manifest.json")
    metadata = load(output / "metadata.json")
    evidence = load(output / "evidence.json")
    assert manifest["status"] == metadata["status"] == "succeeded"
    assert metadata["backend_result"]["model_calls"] == 0
    assert load(output / "model-usage.json")["modelUsage"] == {"model_calls": 0}
    assert (output / "scenario-record.json").read_bytes() == SCENARIO.read_bytes()
    assert (output / "fixture-response.json").read_bytes() == RESPONSE.read_bytes()
    assert "polls" not in evidence["scenario"] and "polls" in evidence["omissions"]
    assert evidence["incident"]["status"] == "resolved"
    draft = (output / "draft.md").read_text(encoding="utf-8")
    assert draft.startswith("# DRAFT postmortem — author review required\n")
    assert "Model prose is untrusted" in draft
    assert "**MISSING:**" in draft and "writer PID" in draft
    assert "scenario/injector metadata" in draft.lower()
    for fragment in re.findall(r"evidence\.json#([^)]*)", draft):
        pointer = unquote(fragment)
        assert pointer in evidence["provenance"]
        assert_pointer(evidence, pointer)
    for artifact, digest in manifest["artifacts"].items():
        assert hashlib.sha256((output / artifact).read_bytes()).hexdigest() == digest


def test_portable_example_allowlist_links_labels_and_hashes(tmp_path: Path) -> None:
    bundle = fixture_bundle(tmp_path, name="private")
    published = tmp_path / "published"
    published.mkdir()
    for name in ("draft.md", "evidence.json", "model-usage.json"):
        shutil.copyfile(bundle / name, published / name)
    (published / "reviewed-final.md").write_text(
        "# Coordinator-reviewed final\n\n**Coordinator/agent review, pending owner (author) acceptance.**\n",
        encoding="utf-8",
        newline="\n",
    )
    dump(
        published / "review-receipt.json",
        {"reviewer": "coordinator/agent", "owner_author_acceptance": "pending"},
    )
    hashed = {
        name: hashlib.sha256((published / name).read_bytes()).hexdigest()
        for name in (
            "draft.md",
            "evidence.json",
            "model-usage.json",
            "reviewed-final.md",
            "review-receipt.json",
        )
    }
    dump(published / "hash-manifest.json", {"artifacts": hashed})
    validate_portable_example(published)
    (published / "raw-response.json").write_text("{}", encoding="utf-8")
    with pytest.raises(DraftingError, match="allowlist"):
        validate_portable_example(published)
    (published / "raw-response.json").unlink()
    (published / "private-artifacts").mkdir()
    with pytest.raises(DraftingError, match="allowlist"):
        validate_portable_example(published)


def test_renderer_escapes_model_markdown_html_and_preserves_non_ascii(tmp_path: Path) -> None:
    response = load(RESPONSE)
    response["sections"][0]["claims"][0]["text"] = (
        "<script>x</script> [link](https://bad) café\nnext"
    )
    response_path = dump(tmp_path / "response.json", response)
    draft = (fixture_bundle(tmp_path, response=response_path) / "draft.md").read_text("utf-8")
    assert "<script>" not in draft and "https://bad" not in draft
    assert "&lt;script&gt;" in draft and "café next" in draft


def test_renderer_preserves_readable_apostrophes_and_quotes(tmp_path: Path) -> None:
    response = load(RESPONSE)
    response["sections"][0]["claims"][0]["text"] = 'It\'s a "quoted" observation.'
    output = fixture_bundle(tmp_path, response=dump(tmp_path / "response.json", response))
    draft = (output / "draft.md").read_text(encoding="utf-8")
    assert 'It\'s a "quoted" observation' in draft
    assert "&\\#" not in draft and "&quot;" not in draft


def test_source_facts_include_recorded_investigation_guidance(tmp_path: Path) -> None:
    output = fixture_bundle(tmp_path)
    evidence = load(output / "evidence.json")
    facts = (output / "draft.md").read_text("utf-8").split("## Symptoms", 1)[0]
    assert "Recorded investigation guidance (not evidence of execution)" in facts
    for index, step in enumerate(evidence["incident"]["investigation_steps"]):
        citation = f"evidence.json#/incident/investigation_steps/{index}"
        line = next(line for line in facts.splitlines() if citation in line)
        assert step in re.sub(r"\\(.)", r"\1", html.unescape(line))


@pytest.mark.parametrize("text", [" ", "\n\t\r"])
def test_whitespace_only_claim_has_a_terminal_failure(tmp_path: Path, text: str) -> None:
    response = load(RESPONSE)
    response["sections"][0]["claims"][0]["text"] = text
    response_path = dump(tmp_path / "response.json", response)
    with pytest.raises(DraftingError) as failure:
        fixture_bundle(tmp_path, response=response_path)
    assert failure.value.stage == "response"
    assert load(tmp_path / "bundle/manifest.json")["status"] == "failed"
    assert not (tmp_path / "bundle/draft.md").exists()


def test_portable_example_validates_review_receipt_fragments(tmp_path: Path) -> None:
    original = Path(__file__).parents[1] / "docs/postmortems/disk-fill-20261011"
    published = tmp_path / "published"
    shutil.copytree(original, published)
    reviewed = published / "reviewed-final.md"
    reviewed.write_text(
        reviewed.read_text("utf-8") + "\n[broken receipt](review-receipt.json#/missing/field)\n",
        encoding="utf-8",
        newline="\n",
    )
    manifest = load(published / "hash-manifest.json")
    manifest["artifacts"]["reviewed-final.md"] = hashlib.sha256(reviewed.read_bytes()).hexdigest()
    dump(published / "hash-manifest.json", manifest)
    with pytest.raises(DraftingError, match="unresolvable JSON Pointer: /missing/field"):
        validate_portable_example(published)


def test_projection_accounts_for_every_scenario_field(tmp_path: Path) -> None:
    scenario = load(SCENARIO)
    scenario["configuration"]["cadence_seconds"] = 5
    scenario["trigger_condition"] = "three fresh observations at or above 95%"
    scenario["recovery_condition"] = "three fresh observations below 90%"
    scenario["future_context"] = {"value": "not projected"}
    output = generate_bundle(
        incident_id=INCIDENT_ID,
        scenario_record=dump(tmp_path / "scenario.json", scenario),
        output_dir=tmp_path / "bundle",
        backend="fixture",
        fixture_response=RESPONSE,
    )
    evidence = load(output / "evidence.json")
    projected = set(evidence["scenario"]) | set(evidence["relocated_scenario_fields"])
    omitted = set(evidence["omissions"])
    assert projected.isdisjoint(omitted)
    assert projected | omitted == set(scenario)
    assert evidence["omissions"] == sorted(omitted)
    assert "opening_detail" in omitted and "future_context" in omitted
    assert evidence["relocated_scenario_fields"] == {"resolved_detail": "/incident"}
    assert evidence["scenario"]["configuration"]["cadence_seconds"] == 5
    assert (
        evidence["provenance"]["/scenario/configuration/cadence_seconds"]["source_class"]
        == "harness_measurement"
    )
    assert evidence["scenario"]["trigger_condition"] == scenario["trigger_condition"]


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda value: value.update(incident_id=str(uuid4())), "identity mismatch"),
        (lambda value: value.update(status="running"), "status must be"),
        (lambda value: value["resolved_detail"].pop("diagnosis"), "missing authoritative"),
        (lambda value: value["resolved_detail"].pop("rule"), "missing authoritative"),
        (lambda value: value["resolved_detail"].pop("severity"), "missing authoritative"),
        (lambda value: value["resolved_detail"].pop("status"), "missing authoritative"),
        (lambda value: value.update(actual_diagnosis="cpu_saturation"), "actual_diagnosis"),
        (
            lambda value: value["configuration"]["disk_rule"].update(trigger_percent=True),
            "boolean numeric",
        ),
    ],
)
def test_invalid_saved_evidence_is_rejected_before_bundle(
    tmp_path: Path, mutation: Any, match: str
) -> None:
    value = load(SCENARIO)
    mutation(value)
    scenario = dump(tmp_path / "scenario.json", value)
    output = tmp_path / "not-created"
    with pytest.raises(DraftingError, match=match):
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=scenario,
            output_dir=output,
            backend="fixture",
            fixture_response=RESPONSE,
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "raw",
    [
        b'{"status":"passed","status":"failed"}',
        b'{"status":"passed","value":NaN}',
        b"[]",
        b"\xff",
    ],
)
def test_strict_scenario_json_failures_do_not_create_bundle(tmp_path: Path, raw: bytes) -> None:
    scenario = tmp_path / "bad.json"
    scenario.write_bytes(raw)
    output = tmp_path / "not-created"
    with pytest.raises(DraftingError, match="strict JSON|root must"):
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=scenario,
            output_dir=output,
            backend="fixture",
            fixture_response=RESPONSE,
        )
    assert not output.exists()


def test_raw_incident_boolean_numeric_is_rejected_without_scenario_config(tmp_path: Path) -> None:
    scenario = load(SCENARIO)
    scenario.pop("configuration")
    for name in ("opening_detail", "resolved_detail"):
        scenario[name]["configuration"]["max_gap_seconds"] = True
    scenario_path = dump(tmp_path / "scenario.json", scenario)
    with pytest.raises(DraftingError, match="boolean numeric"):
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=scenario_path,
            output_dir=tmp_path / "not-created",
            backend="fixture",
            fixture_response=RESPONSE,
        )


def inode_scenario(tmp_path: Path, *, mismatch: bool = False) -> tuple[Path, Path]:
    scenario = load(SCENARIO)
    inode_config = {
        "trigger_percent": 95,
        "recovery_percent": 90,
        "block_guard_percent": 95,
        "consecutive_samples": 3,
        "max_gap_seconds": 10,
        "severity": "critical",
    }
    scenario["expected_diagnosis"] = scenario["actual_diagnosis"] = "inode_exhaustion"
    scenario["configuration"] = {"inode_rule": inode_config | {}}
    if mismatch:
        scenario["configuration"]["inode_rule"]["trigger_percent"] = 96
    for name in ("opening_detail", "resolved_detail"):
        detail = scenario[name]
        detail["rule"] = "inode_exhaustion"
        detail["diagnosis"] = "Filesystem inode capacity is exhausted"
        detail["configuration"] = inode_config | {}
        detail["opening_evidence"] = {
            "inode_available": True,
            "inode_usage_percent": 97.0,
        }
        detail["latest_evidence"] = {
            "inode_available": True,
            "inode_usage_percent": 1.0 if name == "resolved_detail" else 97.0,
        }
    response = load(RESPONSE)
    response["sections"][3]["claims"][0]["citations"] = [
        "/incident/opening_evidence/inode_usage_percent"
    ]
    response["sections"][3]["claims"][1]["citations"] = [
        "/scenario/events/threshold_observed/utc",
        "/incident/opening_evidence/inode_usage_percent",
    ]
    return dump(tmp_path / "inode-scenario.json", scenario), dump(
        tmp_path / "inode-response.json", response
    )


def test_inode_configuration_semantic_match_and_mismatch(tmp_path: Path) -> None:
    scenario, response = inode_scenario(tmp_path)
    output = generate_bundle(
        incident_id=INCIDENT_ID,
        scenario_record=scenario,
        output_dir=tmp_path / "inode-bundle",
        backend="fixture",
        fixture_response=response,
    )
    assert load(output / "manifest.json")["status"] == "succeeded"
    mismatch_scenario, mismatch_response = inode_scenario(tmp_path, mismatch=True)
    with pytest.raises(DraftingError, match="configuration.inode_rule disagrees"):
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=mismatch_scenario,
            output_dir=tmp_path / "not-created",
            backend="fixture",
            fixture_response=mismatch_response,
        )


def test_existing_output_and_input_aliases_are_refused(tmp_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(DraftingError, match="already exists"):
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=SCENARIO,
            output_dir=existing,
            backend="fixture",
            fixture_response=RESPONSE,
        )
    alias = tmp_path / "alias.json"
    try:
        os.link(SCENARIO, alias)
    except OSError:
        pytest.skip("hard links unavailable")
    with pytest.raises(DraftingError, match="alias"):
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=SCENARIO,
            incident_file=alias,
            output_dir=tmp_path / "not-created",
            backend="fixture",
            fixture_response=RESPONSE,
        )


@pytest.mark.parametrize(
    "pointer",
    [
        "/unknown/value",
        "/incident",
        "/incident/opening_evidence",
        "",
        "/incident/investigation_steps/" + "9" * 5000,
    ],
)
def test_bad_citation_retains_terminal_failure_bundle(tmp_path: Path, pointer: str) -> None:
    response = load(RESPONSE)
    response["sections"][0]["claims"][0]["citations"] = [pointer]
    response_path = dump(tmp_path / "response.json", response)
    output = tmp_path / "failed"
    with pytest.raises(DraftingError) as failure:
        fixture_bundle(tmp_path, response=response_path, name="failed")
    assert failure.value.stage == "response" and failure.value.output_dir == output
    assert load(output / "manifest.json")["status"] == "failed"
    assert load(output / "error.json")["stage"] == "response"
    assert (output / "scenario-record.json").read_bytes() == SCENARIO.read_bytes()


def test_missing_claim_cannot_smuggle_citations(tmp_path: Path) -> None:
    response = load(RESPONSE)
    response["sections"][-1]["claims"][0]["citations"] = ["/incident/rule"]
    response_path = dump(tmp_path / "response.json", response)
    with pytest.raises(DraftingError, match="missing claims"):
        fixture_bundle(tmp_path, response=response_path)


def test_rfc6901_slash_escape_resolves_to_specific_provenance(tmp_path: Path) -> None:
    response = load(RESPONSE)
    response["sections"][1]["claims"][0]["citations"] = ["/scenario/events/cleanup~1complete/utc"]
    response_path = dump(tmp_path / "response.json", response)
    output = fixture_bundle(tmp_path, response=response_path)
    draft = (output / "draft.md").read_text(encoding="utf-8")
    assert "cleanup~1complete/utc" in draft


def test_failed_record_with_explicit_recovery_stays_failed_and_retains_context(
    tmp_path: Path,
) -> None:
    scenario = load(SCENARIO)
    scenario["status"] = "failed"
    scenario["explicit_cleanup"] = {"cleanup_complete": True}
    scenario["explicit_cleanup_utc"] = "2026-10-12T00:00:00+00:00"
    scenario["explicit_recovery"] = {"status": "observed_later"}
    scenario_path = dump(tmp_path / "failed-scenario.json", scenario)
    output = generate_bundle(
        incident_id=INCIDENT_ID,
        scenario_record=scenario_path,
        output_dir=tmp_path / "bundle",
        backend="fixture",
        fixture_response=RESPONSE,
    )
    evidence = load(output / "evidence.json")
    assert evidence["scenario"]["status"] == "failed"
    assert evidence["scenario"]["explicit_cleanup"]["cleanup_complete"] is True
    assert evidence["scenario"]["explicit_recovery"]["status"] == "observed_later"


def test_explicit_incident_file_and_record_pointer_support_generic_layout(tmp_path: Path) -> None:
    scenario = load(SCENARIO)
    incident = scenario.pop("resolved_detail")
    scenario.pop("opening_detail")
    scenario.pop("incident_id")
    scenario["incident"] = {"id": INCIDENT_ID}
    scenario["timing"] = {"diagnosis_seconds": 4.5}
    scenario["cleanup"] = {"cleanup_complete": True}
    scenario["recovery"] = {"status": "resolved"}
    scenario_path = dump(tmp_path / "generic.json", scenario)
    incident_path = dump(tmp_path / "incident.json", incident)
    output = generate_bundle(
        incident_id=INCIDENT_ID,
        scenario_record=scenario_path,
        incident_file=incident_path,
        record_incident_pointer="/incident/id",
        output_dir=tmp_path / "generic-bundle",
        backend="fixture",
        fixture_response=RESPONSE,
    )
    evidence = load(output / "evidence.json")
    provenance = evidence["provenance"]
    assert provenance["/incident/id"]["artifact"] == "incident-file.json"
    assert evidence["scenario"]["timing"]["diagnosis_seconds"] == 4.5
    assert provenance["/scenario/cleanup/cleanup_complete"]["source_class"] == "harness_injector"


def test_equivalent_uuid_formats_across_saved_details_are_accepted(tmp_path: Path) -> None:
    scenario = load(SCENARIO)
    scenario["opening_detail"]["id"] = "{" + INCIDENT_ID + "}"
    scenario_path = dump(tmp_path / "scenario.json", scenario)
    output = generate_bundle(
        incident_id=INCIDENT_ID,
        scenario_record=scenario_path,
        output_dir=tmp_path / "bundle",
        backend="fixture",
        fixture_response=RESPONSE,
    )
    assert load(output / "manifest.json")["status"] == "succeeded"


@pytest.mark.parametrize(
    "pointer", ["/incident/investigation_steps/²", "/incident/investigation_steps/01"]
)
def test_malformed_array_citation_is_a_retained_drafting_error(
    tmp_path: Path, pointer: str
) -> None:
    response = load(RESPONSE)
    response["sections"][0]["claims"][0]["citations"] = [pointer]
    response_path = dump(tmp_path / "response.json", response)
    with pytest.raises(DraftingError) as failure:
        fixture_bundle(tmp_path, response=response_path)
    assert failure.value.stage == "response"
    assert load(tmp_path / "bundle" / "manifest.json")["status"] == "failed"


def fake_cli(path: Path) -> Path:
    path.write_text(
        """
import json, os, subprocess, sys, time
args = sys.argv[1:]
mode = os.environ.get('FAKE_MODE', 'success')
if os.environ.get('FAKE_ARGV_LOG'):
    with open(os.environ['FAKE_ARGV_LOG'], 'a', encoding='utf-8') as stream:
        stream.write(json.dumps(args) + '\\n')
if '--version' in args:
    if mode == 'version-nonzero':
        raise SystemExit(3)
    print('2.1.296 (Fake Claude Code)')
    raise SystemExit(0)
if 'auth' in args and args[args.index('auth'):] == ['auth', 'status', '--json']:
    auth = {'loggedIn': True, 'authMethod': 'claude.ai', 'apiProvider': 'firstParty', 'subscriptionType': 'pro'}
    auth.update(email='private-account@example.invalid', orgId='private-org-identifier', orgName='private-organization-name')
    print('private-account@example.invalid private-org-identifier private-organization-name', file=sys.stderr)
    if mode == 'auth-malformed':
        print('{private-account@example.invalid private-org-identifier private-organization-name')
        raise SystemExit(0)
    if mode == 'logged-out':
        auth['loggedIn'] = False
    if mode == 'auth-method':
        auth['authMethod'] = 'apiKey'
    if mode == 'auth-provider':
        auth['apiProvider'] = 'bedrock'
    print(json.dumps(auth))
    if mode == 'auth-nonzero':
        raise SystemExit(4)
    raise SystemExit(0)
prompt = sys.stdin.buffer.read()
if os.environ.get('FAKE_OBSERVED'):
    with open(os.environ['FAKE_OBSERVED'], 'w', encoding='utf-8', newline='\\n') as stream:
        json.dump({'argv': args, 'cwd': os.getcwd(), 'prompt_has_evidence': b'EVIDENCE_JSON' in prompt}, stream)
if mode == 'nonzero':
    print('provider failed', file=sys.stderr)
    raise SystemExit(7)
if mode == 'malformed':
    sys.stdout.buffer.write(b'{')
    raise SystemExit(0)
if mode == 'overflow':
    sys.stdout.buffer.write(b'x' * (3 * 1024 * 1024))
    raise SystemExit(0)
if mode == 'timeout':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    if os.environ.get('FAKE_CHILD_PID'):
        open(os.environ['FAKE_CHILD_PID'], 'w', encoding='ascii').write(str(child.pid))
    time.sleep(60)
if mode == 'parent-exits':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    if os.environ.get('FAKE_CHILD_PID'):
        open(os.environ['FAKE_CHILD_PID'], 'w', encoding='ascii').write(str(child.pid))
    os._exit(0)
structured = json.load(open(os.environ['FAKE_RESPONSE'], encoding='utf-8'))
model = 'claude-opus-5-5'
envelope = {'type':'result','subtype':'success','is_error':False,'permission_denials':[],
            'structured_output':structured,'total_cost_usd':0.03,
            'modelUsage':{model:{'canonicalModel':model,'provider':'firstParty','costUSD':0.03}}}
if mode == 'envelope-error':
    envelope['is_error'] = True
if mode == 'permission':
    envelope['permission_denials'] = [{'tool':'Read'}]
if mode == 'wrong-model':
    envelope['modelUsage'] = {'claude-sonnet-4-5': {'provider':'firstParty'}}
if mode == 'absent-model':
    envelope['modelUsage'] = {}
if mode == 'extra-model':
    envelope['modelUsage']['claude-sonnet-4-5'] = {'provider':'firstParty'}
if mode == 'canonical-mismatch':
    envelope['modelUsage'][model]['canonicalModel'] = 'claude-sonnet-4-5'
if mode == 'provider-mismatch':
    envelope['modelUsage'][model]['provider'] = 'bedrock'
print(json.dumps(envelope))
""".lstrip(),
        encoding="utf-8",
        newline="\n",
    )
    return path


def clean_environment(tmp_path: Path, mode: str = "success") -> dict[str, str]:
    result = dict(os.environ)
    for name in list(result):
        if name.startswith("ANTHROPIC_") or name.startswith("CLAUDE_CODE_"):
            result.pop(name)
    result.update(FAKE_MODE=mode, FAKE_RESPONSE=str(RESPONSE))
    return result


def test_fake_claude_success_uses_exact_isolation_contract(tmp_path: Path) -> None:
    script = fake_cli(tmp_path / "fake_claude.py")
    observed = tmp_path / "observed.json"
    environment = clean_environment(tmp_path)
    environment["FAKE_OBSERVED"] = str(observed)
    argv_log = tmp_path / "argv.jsonl"
    environment["FAKE_ARGV_LOG"] = str(argv_log)
    output = generate_bundle(
        incident_id=INCIDENT_ID,
        scenario_record=SCENARIO,
        output_dir=tmp_path / "claude-bundle",
        backend="claude-cli",
        model=MODEL,
        claude_command=[sys.executable, str(script)],
        environ=environment,
    )
    recorded = load(observed)
    metadata = load(output / "metadata.json")["backend_result"]
    assert recorded["prompt_has_evidence"] is True
    assert recorded["cwd"] != str(Path.cwd())
    assert not Path(recorded["cwd"]).is_relative_to(output)
    assert metadata["runtime_cwd_isolated"] is True
    assert not Path(metadata["runtime_cwd"]).exists()
    required = {
        "-p",
        "--safe-mode",
        "--strict-mcp-config",
        "--tools",
        "--no-session-persistence",
        "--setting-sources",
        "--json-schema",
    }
    assert required <= set(recorded["argv"])
    calls = [json.loads(line) for line in argv_log.read_text("utf-8").splitlines()]
    assert len(calls) == 3
    for preliminary in calls[:2]:
        assert "--safe-mode" in preliminary
        assert preliminary[preliminary.index("--setting-sources") + 1] == ""
    assert metadata["actual_model"] == MODEL
    assert metadata["auth"] == {
        "loggedIn": True,
        "authMethod": "claude.ai",
        "apiProvider": "firstParty",
        "subscriptionType": "pro",
    }
    assert "session_id" not in json.dumps(metadata)


@pytest.mark.parametrize("mode", ["auth-nonzero", "auth-malformed", "nonzero"])
def test_authentication_profile_is_absent_from_every_failed_bundle_file(
    tmp_path: Path, mode: str
) -> None:
    script = fake_cli(tmp_path / "fake_claude.py")
    output = tmp_path / "failed"
    with pytest.raises(DraftingError):
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=SCENARIO,
            output_dir=output,
            backend="claude-cli",
            model=MODEL,
            claude_command=[sys.executable, str(script)],
            environ=clean_environment(tmp_path, mode),
        )
    assert load(output / "manifest.json")["status"] == "failed"
    for artifact in output.rglob("*"):
        if artifact.is_file():
            for private_value in (
                b"private-account@example.invalid",
                b"private-org-identifier",
                b"private-organization-name",
            ):
                assert private_value not in artifact.read_bytes(), artifact.name
    diagnostics = json.loads((output / "backend-diagnostics.json").read_bytes())
    auth = next(row for row in diagnostics if row["label"] == "auth")
    assert set(load(output / auth["stdout_file"])) == {
        "loggedIn",
        "authMethod",
        "apiProvider",
        "subscriptionType",
    }
    assert (output / auth["stderr_file"]).read_bytes() == b""


@pytest.mark.parametrize(
    "mode,stage",
    [
        ("nonzero", "provider"),
        ("malformed", "response"),
        ("envelope-error", "response"),
        ("permission", "response"),
        ("wrong-model", "response"),
        ("absent-model", "response"),
        ("extra-model", "response"),
        ("canonical-mismatch", "response"),
        ("provider-mismatch", "response"),
        ("overflow", "response"),
    ],
)
def test_fake_claude_failures_are_visible_and_terminal(
    tmp_path: Path, mode: str, stage: str
) -> None:
    script = fake_cli(tmp_path / "fake_claude.py")
    output = tmp_path / f"failed-{mode}"
    with pytest.raises(DraftingError) as failure:
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=SCENARIO,
            output_dir=output,
            backend="claude-cli",
            model=MODEL,
            claude_command=[sys.executable, str(script)],
            environ=clean_environment(tmp_path, mode),
        )
    assert failure.value.stage == stage
    manifest = load(output / "manifest.json")
    assert manifest["status"] == "failed" and manifest["error_stage"] == stage
    diagnostics = json.loads((output / "backend-diagnostics.json").read_text(encoding="utf-8"))
    assert isinstance(diagnostics, list)
    assert diagnostics[-1]["label"] == "generation"
    assert (output / diagnostics[-1]["stdout_file"]).exists()
    assert (output / diagnostics[-1]["stderr_file"]).exists()
    if mode == "nonzero":
        assert b"provider failed" in (output / diagnostics[-1]["stderr_file"]).read_bytes()


def test_alternative_auth_override_is_named_not_disclosed(tmp_path: Path) -> None:
    script = fake_cli(tmp_path / "fake_claude.py")
    environment = clean_environment(tmp_path)
    environment["ANTHROPIC_API_KEY"] = "do-not-print-me"
    with pytest.raises(DraftingError) as failure:
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=SCENARIO,
            output_dir=tmp_path / "failed",
            backend="claude-cli",
            model=MODEL,
            claude_command=[sys.executable, str(script)],
            environ=environment,
        )
    assert "ANTHROPIC_API_KEY" in str(failure.value)
    assert "do-not-print-me" not in str(failure.value)


@pytest.mark.parametrize(
    "mode,label",
    [
        ("version-nonzero", "version"),
        ("auth-nonzero", "auth"),
        ("logged-out", "auth"),
        ("auth-method", "auth"),
        ("auth-provider", "auth"),
    ],
)
def test_preliminary_backend_failures_have_terminal_manifests(
    tmp_path: Path, mode: str, label: str
) -> None:
    script = fake_cli(tmp_path / "fake.py")
    output = tmp_path / "failed"
    with pytest.raises(DraftingError) as failure:
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=SCENARIO,
            output_dir=output,
            backend="claude-cli",
            model=MODEL,
            claude_command=[sys.executable, str(script)],
            environ=clean_environment(tmp_path, mode),
        )
    assert failure.value.stage == "provider"
    assert load(output / "manifest.json")["status"] == "failed"
    diagnostics = json.loads((output / "backend-diagnostics.json").read_bytes())
    assert diagnostics[-1]["label"] == label


def test_missing_cli_has_a_terminal_spawn_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("fleetdoctor.postmortem.shutil.which", lambda name: None)
    output = tmp_path / "failed"
    with pytest.raises(DraftingError) as failure:
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=SCENARIO,
            output_dir=output,
            backend="claude-cli",
            model=MODEL,
            environ=clean_environment(tmp_path),
        )
    assert failure.value.stage == "spawn"
    assert load(output / "manifest.json")["error_stage"] == "spawn"


def test_generation_timeout_retains_failed_bundle_and_cleans_child(tmp_path: Path) -> None:
    script = fake_cli(tmp_path / "fake.py")
    environment = clean_environment(tmp_path, "timeout")
    child_pid_file = tmp_path / "child.pid"
    environment["FAKE_CHILD_PID"] = str(child_pid_file)
    output = tmp_path / "failed"
    with pytest.raises(DraftingError) as failure:
        generate_bundle(
            incident_id=INCIDENT_ID,
            scenario_record=SCENARIO,
            output_dir=output,
            backend="claude-cli",
            model=MODEL,
            timeout_seconds=10,
            claude_command=[sys.executable, str(script)],
            environ=environment,
        )
    assert failure.value.stage == "timeout"
    assert load(output / "manifest.json")["error_stage"] == "timeout"
    assert child_pid_file.exists() and not process_exists(int(child_pid_file.read_text()))


def process_exists(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x00100000 | 0x001000, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259
        finally:
            kernel32.CloseHandle(handle)
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists():
        try:
            return stat.read_text(encoding="ascii").split()[2] != "Z"
        except (OSError, IndexError):
            return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def test_owned_process_timeout_reaps_spawned_grandchild(tmp_path: Path) -> None:
    script = fake_cli(tmp_path / "fake_claude.py")
    pid_file = tmp_path / "child.pid"
    environment = clean_environment(tmp_path, "timeout")
    environment["FAKE_CHILD_PID"] = str(pid_file)
    result = _run_owned(
        [sys.executable, str(script)],
        b"prompt",
        cwd=tmp_path,
        timeout=0.5,
        env=environment,
    )
    assert result.timed_out
    deadline = time.monotonic() + 5
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert pid_file.exists()
    child_pid = int(pid_file.read_text(encoding="ascii"))
    deadline = time.monotonic() + 5
    while process_exists(child_pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not process_exists(child_pid)


def test_owned_process_parent_exit_still_enforces_deadline_and_reaps_grandchild(
    tmp_path: Path,
) -> None:
    script = fake_cli(tmp_path / "fake_claude.py")
    pid_file = tmp_path / "child.pid"
    environment = clean_environment(tmp_path, "parent-exits")
    environment["FAKE_CHILD_PID"] = str(pid_file)
    started = time.monotonic()
    result = _run_owned(
        [sys.executable, str(script)], b"prompt", cwd=tmp_path, timeout=0.5, env=environment
    )
    elapsed = time.monotonic() - started
    assert result.timed_out and elapsed < 3
    assert pid_file.exists()
    child_pid = int(pid_file.read_text(encoding="ascii"))
    deadline = time.monotonic() + 5
    while process_exists(child_pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not process_exists(child_pid)


def test_owned_process_combined_output_is_bounded(tmp_path: Path) -> None:
    script = tmp_path / "overflow.py"
    script.write_text(
        "import sys, time\nsys.stdout.buffer.write(b'x' * 200000)\nsys.stdout.flush()\ntime.sleep(30)\n",
        encoding="utf-8",
    )
    result = _run_owned(
        [sys.executable, str(script)], b"", cwd=tmp_path, timeout=5, output_limit=4096
    )
    assert result.output_overflow and len(result.stdout) + len(result.stderr) <= 4096


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object setup path")
@pytest.mark.parametrize("failure_kind", ["oserror", "argument", "interrupt"])
def test_job_assignment_failure_reaps_gated_launcher_before_target_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_kind: str
) -> None:
    import ctypes

    target = tmp_path / "target.py"
    marker = tmp_path / "target-ran"
    target.write_text(
        "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('ran')\n",
        encoding="utf-8",
    )
    launched: list[subprocess.Popen[bytes]] = []
    original_popen = subprocess.Popen

    def recording_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process = original_popen(*args, **kwargs)
        launched.append(process)
        return process

    monkeypatch.setattr("fleetdoctor.postmortem.subprocess.Popen", recording_popen)
    assignment_error: BaseException = (
        ctypes.ArgumentError("injected assignment failure")
        if failure_kind == "argument"
        else KeyboardInterrupt()
        if failure_kind == "interrupt"
        else OSError("injected assignment failure")
    )
    monkeypatch.setattr(
        postmortem_module._WindowsJob,
        "assign",
        lambda self, process: (_ for _ in ()).throw(assignment_error),
    )
    expected = KeyboardInterrupt if failure_kind == "interrupt" else DraftingError
    with pytest.raises(expected):
        _run_owned(
            [sys.executable, str(target), str(marker)],
            b"",
            cwd=tmp_path,
            timeout=1,
            env=dict(os.environ),
        )
    assert launched and launched[0].poll() is not None
    assert not marker.exists()


def test_unreleased_launcher_gate_has_a_deadline(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-run"
    spec = tmp_path / "command.json"
    dump(spec, [sys.executable, "-c", "from pathlib import Path; Path('must-not-run').touch()"])
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            postmortem_module._OWNED_LAUNCHER,
            str(spec),
            str(tmp_path / "missing-gate"),
            "0.1",
        ],
        cwd=tmp_path,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 125
    assert not marker.exists()


def disk_blocks(usage: int, path: str = DISK_PATH) -> Filesystem:
    return from_statvfs(
        path,
        {
            "f_blocks": 10000,
            "f_bfree": 10000 - usage * 100,
            "f_bavail": 10000 - usage * 100,
            "f_frsize": 4096,
            "f_files": 1000,
            "f_ffree": 900,
        },
    )


def test_drafting_error_does_not_interrupt_collector_diagnosis_or_recovery(
    tmp_path: Path,
) -> None:
    now = [datetime(2026, 10, 11, tzinfo=UTC)]
    store = FixtureStore()
    app = create_app(TOKENS, ("/", DISK_PATH), store=store, clock=lambda: now[0])
    boot, session = uuid4(), uuid4()
    sequence = 0

    def sample(usage: int) -> Sample:
        nonlocal sequence
        sequence += 1
        now[0] += timedelta(seconds=5)
        return make_sample(
            "node-a",
            boot,
            session,
            sequence,
            [disk_blocks(10, "/"), disk_blocks(usage)],
            now[0],
        )

    def post(client: TestClient, usage: int) -> None:
        response = client.post(
            "/ingest",
            content=sample(usage).model_dump_json(),
            headers={"Authorization": "Bearer " + "a" * 40},
        )
        assert response.status_code == 200 and response.json()["status"] == "accepted"

    with TestClient(app) as client:
        for _ in range(3):
            post(client, 98)
        first = client.get("/diagnoses", params={"status": "active"}).json()["diagnoses"][0]
        bad_response = load(RESPONSE)
        bad_response["sections"][0]["claims"][0]["citations"] = ["/unknown"]
        bad_path = dump(tmp_path / "bad-response.json", bad_response)
        with pytest.raises(DraftingError):
            fixture_bundle(tmp_path, response=bad_path, name="drafting-failure")
        for _ in range(3):
            post(client, 80)
        assert client.get("/diagnoses/" + first["id"]).json()["status"] == "resolved"
        assert "fleetdoctor_collector_up 1.0" in client.get("/metrics").text
        assert client.get("/nodes/node-a/metrics").json()["fresh"] is True
        for _ in range(3):
            post(client, 98)
        recurrence = client.get("/diagnoses", params={"status": "active"}).json()["diagnoses"]
        assert len(recurrence) == 1 and recurrence[0]["id"] != first["id"]
