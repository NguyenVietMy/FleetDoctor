# Evidence-linked postmortem drafting

The drafter runs after an incident and measurement record have been saved. It reads files only, never calls the FleetDoctor API/database, and never changes monitoring, incident rules, evidence, severity, or lifecycle state. Every output is a prominent **DRAFT** whose model prose still requires factual review.

## Supported inputs

The automatic disk/inode layout accepts a top-level `incident_id` and saved `opening_detail`/`resolved_detail`; matching resolved detail wins. Other layouts require `--incident-file` plus either top-level `incident_id` or an explicit `--record-incident-pointer` such as `/incident/id`. All available supported identities and immutable opening facts must agree. The record must be `passed`, `failed`, or `interrupted`; later cleanup does not turn a failed record into a passed record.

Inputs are strict UTF-8 JSON objects. Duplicate keys, non-finite numbers, missing authoritative incident fields, ambiguous identities, rule/node/resource/configuration disagreements, oversized evidence, and existing/aliased output paths fail before model invocation. Full raw sources remain byte-identical and are copied into the private bundle. The compact `evidence.json` omits bulk polls/manifests and maps each usable citation pointer back to a logical source artifact, original pointer, source class, and SHA-256.

Every top-level scenario field is accounted for as projected, explicitly relocated to the incident, or listed in sorted `omissions`. Omitted selected-incident view fields are named separately. Measurement configuration, cadence, trigger and recovery conditions are retained when recorded. Omissions describe original field locations and do not imply redaction of duplicate values in retained harness subtrees. The full original record stays private.

## Deterministic fixture command

Use a new external directory; its parent must already exist and the target must not exist:

```text
uv run python -m fleetdoctor.postmortem \
  --incident-id 11111111-1111-4111-8111-111111111111 \
  --scenario-record tests/fixtures/postmortem-scenario.json \
  --output-dir <external-existing-parent>/task12-fixture-unique \
  --backend fixture \
  --fixture-response tests/fixtures/postmortem-response.json
```

This command makes zero model calls. A successful bundle contains exact raw inputs, `selected-incident.json`, compact `evidence.json`, `prompt.txt`, raw fixture/backend output, sanitized metadata, deterministic `draft.md`, and a terminal `manifest.json` with hashes. A backend/response failure retains a uniquely named failed bundle and terminal failed manifest. Validation/path errors before exclusive bundle creation write stderr only.

## Claude subscription command

Run only after fixture/static proof, with alternative API/provider/model override environment variables unset. The output directory below must not already exist:

```powershell
$newDraftDirectory = Join-Path $env:TEMP ('fleetdoctor-postmortem-' + [guid]::NewGuid().ToString('N'))
uv run python -m fleetdoctor.postmortem `
  --incident-id ff8d91b8-69d7-4b12-a95f-98c5ab8e84fe `
  --scenario-record C:\Users\VietM\.fleetdoctor\task02-20261011-130055\aws-disk-host-p1-retry5-functional-1.json `
  --output-dir $newDraftDirectory `
  --backend claude-cli `
  --model claude-opus-5-5 `
  --timeout-seconds 300
```

The adapter verifies the installed version and the saved `claude.ai`/`firstParty` subscription immediately before generation. It uses stdin/argv without a shell, a private temporary cwd, bounded concurrent output capture, and owned process-tree cleanup. Tools, MCP, settings sources, Chrome, permission prompts, and session persistence are disabled. Authentication/cache/profile bookkeeping by the installed CLI is the documented exception to bundle-only writes; no global configuration is changed. Any API key/token/base URL, Bedrock/Vertex/Foundry, custom-header, config-dir, OAuth-token, or default-model override causes visible refusal without printing its value.

Version and authentication probes also use safe mode with settings sources disabled. Authentication diagnostics retain only `loggedIn`, `authMethod`, `apiProvider`, and `subscriptionType`, restricted to known status values (unknown values become null), plus process exit/deadline/overflow state. Raw authentication stdout and stderr are discarded on success and failure, so account and organization fields are not copied into failed bundles. The deterministic source-facts block includes the saved incident's investigation guidance with citations; guidance is not evidence that those steps were executed.

Expected success files are `scenario-record.json`, `selected-incident.json`, `evidence.json`, `prompt.txt`, `raw-response.json`, `backend-stderr.bin`, private `metadata.json`, sanitized `model-usage.json`, `draft.md`, and terminal `manifest.json`. Keep the actual bundle outside the checkout. Publication is a later allowlisted copy containing only the original `draft.md`, unchanged `evidence.json`, sanitized `model-usage.json`, coordinator-reviewed `reviewed-final.md`, `review-receipt.json`, and `hash-manifest.json`. `uv run python scripts/check_postmortem_examples.py` rejects missing/extra files, private metadata, broken evidence or review-receipt links, absent owner-pending labels, and hash mismatches. Raw prompt/scenario/response data and CLI session bookkeeping stay private.

The generated draft must be checked claim-by-claim against saved evidence. A coordinator/agent-reviewed final remains **pending owner (author) acceptance** and must not be called author-approved. One disk example does not claim all eight scenarios or Ticket17/final project acceptance.

The retained [disk example](postmortems/disk-fill-20261011/draft.md) was generated by an actual Claude call on 2026-11-08 from the saved 2026-10-11 functional drill. Its [separate reviewed result](postmortems/disk-fill-20261011/reviewed-final.md) corrects and qualifies model claims while preserving the original draft. The [review receipt](postmortems/disk-fill-20261011/review-receipt.json) records claim dispositions; owner acceptance remains pending.
