# Disk-fill functional drill: reviewed postmortem

**Review status:** Coordinator/agent review, pending owner (author) acceptance.

This document reviews the saved AWS functional drill of **2026-10-11**. The model draft was generated on **2026-11-08** using the existing Claude subscription. The original generated draft is retained unchanged as `draft.md`; the original measured record remains in the private generation bundle. This single historical drill does not establish a five-run median or current deployment status.

Incident [`ff8d91b8-69d7-4b12-a95f-98c5ab8e84fe`](evidence.json#/incident/id) affected [`node-a`](evidence.json#/incident/node_id), resource [`/var/lib/fleetdoctor/chaos/disk`](evidence.json#/incident/resource). The saved rule is [`disk_block_exhaustion`](evidence.json#/incident/rule), severity [`critical`](evidence.json#/incident/severity), and lifecycle [`resolved`](evidence.json#/incident/status). Those fields are source facts, unchanged by drafting or review.

## Symptoms

The opening observation recorded **97.149% block use**, above the configured **95%** trigger. It retained 352,336,896 used bytes, 10,338,304 available bytes, and a filesystem size of 366,869,504 bytes. The rule's exhaustion diagnosis is a threshold diagnosis; these counters do not say that available bytes reached zero. [Usage](evidence.json#/incident/opening_evidence/filesystem/block_usage_percent), [trigger](evidence.json#/incident/configuration/trigger_percent), [used](evidence.json#/incident/opening_evidence/filesystem/used_bytes), [available](evidence.json#/incident/opening_evidence/filesystem/available_bytes), [size](evidence.json#/incident/opening_evidence/filesystem/total_bytes).

Opening inode use was **0.0122%**. Block coverage was available and the selected opening filesystem reported no errors. Application write failures, ENOSPC, customer impact, and a responsible writer PID/path are not established by this compact example. [Inodes](evidence.json#/incident/opening_evidence/filesystem/inode_usage_percent), [coverage](evidence.json#/incident/opening_evidence/coverage/block), [errors](evidence.json#/incident/opening_evidence/filesystem/errors), [recorded attribution limit](evidence.json#/incident/investigation_steps/4).

## Timeline

All wall-clock times below are UTC on **2026-10-11**. Agent observation, collector lifecycle, helper receipts, and controller API visibility use different clock domains. Their timestamps provide correlation; cross-host wall-clock subtraction is not a calibrated latency measurement.

| UTC | Recorded milestone |
| --- | --- |
| 23:38:12.903035 | Baseline agent sample 13; 14,336 used bytes. [Baseline](evidence.json#/scenario/original_observation/observed_at), [bytes](evidence.json#/scenario/original_observation/filesystem/used_bytes). |
| 23:38:14.631799 | Controller injection-start event. [Event](evidence.json#/scenario/events/injection_start/utc). |
| 23:38:17.897974 | Retained trigger observation, sample 14, above the configured threshold. [Observation](evidence.json#/scenario/trigger_observation/observed_at), [usage](evidence.json#/scenario/trigger_observation/filesystem/block_usage_percent). |
| 23:38:19.550052 | Controller recorded the threshold observation. [Event](evidence.json#/scenario/events/threshold_observed/utc). |
| 23:38:27.921129 | Collector opened the incident; its opening sample is sequence 16. [Open](evidence.json#/incident/opened_at), [sequence](evidence.json#/incident/opening_evidence/sequence). |
| 23:38:29.738769 | Controller first recorded API diagnosis visibility. [Event](evidence.json#/scenario/events/api_diagnosis/utc). |
| 23:38:32.355640 | Owned helper cleanup receipt reported completion. [Receipt](evidence.json#/scenario/cleanup_attempts/0/result/cleanup_utc). |
| 23:38:33.401023 | Controller cleanup-complete event. [Event](evidence.json#/scenario/events/cleanup_complete/utc). |
| 23:38:42.921877 | Collector resolved the same incident; latest evidence is sample 19. [Resolution](evidence.json#/incident/resolved_at), [sequence](evidence.json#/incident/latest_evidence/sequence). |
| 23:38:44.886463 | Controller first recorded API resolution visibility. [Event](evidence.json#/scenario/events/api_resolution/utc). |

The recorded controller measurements are **10.188 seconds from threshold observation to API diagnosis** and **14.922 seconds from injection start to API diagnosis**. A separate derived interval is **11.484 seconds from controller cleanup completion to API resolution**, calculated from 84228.812 minus 84217.328 on the saved controller monotonic clock. Wall-clock subtraction is not substituted for these monotonic measurements. [Diagnosis measurement](evidence.json#/scenario/trigger_to_diagnosis_seconds), [injection measurement](evidence.json#/scenario/injection_to_diagnosis_seconds), [cleanup marker](evidence.json#/scenario/events/cleanup_complete/monotonic_seconds), [resolution marker](evidence.json#/scenario/events/api_resolution/monotonic_seconds).

## Observed diagnosis and evidence

The recorded diagnosis is: “Filesystem /var/lib/fleetdoctor/chaos/disk has exhausted workload block space.” High block use and low inode use support the recorded distinction between block and inode pressure. The configured rule requires **three consecutive qualifying samples** with a maximum gap of **10 seconds**. [Diagnosis](evidence.json#/incident/diagnosis), [block use](evidence.json#/incident/opening_evidence/filesystem/block_usage_percent), [inode use](evidence.json#/incident/opening_evidence/filesystem/inode_usage_percent), [count](evidence.json#/incident/configuration/consecutive_samples), [gap](evidence.json#/incident/configuration/max_gap_seconds).

The injector's worker/watchdog identities, loop device, and backing image describe the test setup. They do not establish culprit attribution by FleetDoctor telemetry. The incident itself records that writer PID and file path are unavailable from statvfs telemetry. The root filesystem's trigger sample was about 11.03% used; that supports a limited observation about the monitored root mount, rather than a claim about every filesystem or fleet-wide impact. [Setup mapping](evidence.json#/scenario/injector/mapping/source), [attribution limit](evidence.json#/incident/investigation_steps/4), [root mount](evidence.json#/scenario/trigger_observation/filesystems/0/mountpoint), [root usage](evidence.json#/scenario/trigger_observation/filesystems/0/block_usage_percent).

The captured model-facing projection predates complete omission tracking. Its four-entry `omissions` array is incomplete. Additional top-level source fields absent from that list are: `configuration`, `diagnosis_timeout_seconds`, `environment`, `incident_id`, `injection_attempted`, `local_lease`, `max_injection_seconds`, `opening_detail`, `original_resource`, `poll_interval_seconds`, `preparation_timeout_seconds`, `recovery_condition`, `recovery_timeout_seconds`, `resource_mappings`, `schema_version`, `trigger_condition`, `trigger_timeout_seconds`. The selected `resolved_detail` was relocated into `incident`; computed view fields omitted from that snapshot are listed in the [projection review](review-receipt.json#/historical_projection_review). The original draft also retains an apostrophe-escaping artifact from the earlier renderer. These original generated bytes are preserved; the current generator corrects omission tracking and quote rendering.

Omission from the compact projection does not mean absence from the retained private record. This compact example does not independently reconstruct intermediate qualifying samples or assess node-b's reference telemetry. A root field listed as omitted is not necessarily redacted: the ownership token remains in the nested [injector](evidence.json#/scenario/injector/token) and [cleanup receipt](evidence.json#/scenario/cleanup_attempts/0/result/token). No investigation command is claimed executed merely because it appears in the incident's suggested steps.

## Recorded recovery actions

Cleanup attempt 1 reports `cleanup_complete=true`. The initial injector snapshot still says false; it is an earlier setup snapshot, not the terminal cleanup receipt. These are harness facts. [Attempt](evidence.json#/scenario/cleanup_attempts/0/attempt), [completed receipt](evidence.json#/scenario/cleanup_attempts/0/result/cleanup_complete), [initial snapshot](evidence.json#/scenario/injector/cleanup_complete).

Latest usage returned to **14,336 bytes (0.00395%)**, below the configured **90% recovery threshold**, and the same incident is resolved. The total filesystem size remained 366,869,504 bytes. The sequence is consistent with the owned cleanup freeing space; telemetry alone does not establish a particular writer as the cause. The configured recovery window is three qualifying samples; the compact projection does not show every intermediate sample. [Recovered bytes](evidence.json#/incident/latest_evidence/filesystem/used_bytes), [usage](evidence.json#/incident/latest_evidence/filesystem/block_usage_percent), [threshold](evidence.json#/incident/configuration/recovery_percent), [status](evidence.json#/incident/status), [size](evidence.json#/incident/latest_evidence/filesystem/total_bytes), [window](evidence.json#/incident/configuration/consecutive_samples).

## Lessons and follow-ups

- **Configuration-derived explanation:** The original record explicitly configures a [five-second cadence](review-receipt.json#/historical_projection_review/cadence_seconds), retained as a direct-source review fact. At that configured cadence, three qualifying samples span about `(3 - 1) × 5 = 10` seconds from the first qualifying observation to the third. Fault phase, observation freshness, transport, and controller polling add separate delays. Use the retained controller measurements for this drill instead of presenting `sample count × cadence` as a universal latency bound. [Configured count](evidence.json#/incident/configuration/consecutive_samples), [first retained trigger time](evidence.json#/scenario/trigger_observation/observed_at), [opening sample time](evidence.json#/incident/opening_evidence/observed_at).
- **Proposed follow-up:** Preserve milestone and clock definitions alongside future comparable trials. This single functional drill is not a median or broad performance result.
- **Proposed follow-up:** If writer attribution is needed, perform and retain an appropriate investigation in the authorized lab. The recorded investigation steps are guidance, not evidence of execution. [Guidance](evidence.json#/incident/investigation_steps/2).
- **Open review gate:** Owner (author) acceptance of this agent-reviewed result remains pending.
