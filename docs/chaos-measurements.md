# Chaos measurement record v 1

`scripts/chaos_harness.py` owns reusable report/events/leases. `scripts/chaos_disk.py` and `scripts/chaos_inode.py` supply the API and owned remote injectors. Reports are written atomically outside the checkout after each milestone/poll. Failed runs and original outcomes remain available for explicit recovery.

| Field | Meaning |
| --- | --- |
| schema_version/scenario/token/target/reference/resource | Record version, scenario metadata, unique run ownership and measured node/mount. Scenario IDs are never diagnosis inputs. |
| expected_diagnosis/actual_diagnosis/incident_id | Declared rule versus actual API match and stable UUID. |
| configuration | Effective thresholds, severity, windows, max gap, filesystem paths and 5s cadence; frozen for the batch and persisted in the incident. |
| source | Git base/revision, dirty flag and source SHA256 mapping, excluding secret/ignored files. Strict real CLI collection needs the checkout/Git; timing unit fixtures explicitly inject a deterministic manifest. |
| environment/resource_mappings/original_resource | Preflight installed hashes/service identity, kernel/OS, AWS instance types/credit configuration, root reserve and exact mount/device/backing-file mapping on both nodes. |
| original_observation/trigger_observation/recovery_observation/polls | Raw ordinary observations, identities and resource counters, plus reference-node health and active incident snapshots. |
| events | UTC correlation and a single controller monotonic clock for preparation, injection start, threshold observation, first API diagnosis visibility, cleanup completion, resolution visibility and finish. |
| opening_detail/resolved_detail | Actual API snapshots containing frozen opening/latest evidence, investigation steps, rule configuration and lifecycle times. |
| trigger_to_diagnosis_seconds | API visibility monotonic time minus first validated resource-threshold observation time. The resource timestamp precedes the incident lookup; same-poll responses retain actual API request elapsed time. Polling delay is included. |
| injection_to_diagnosis_seconds | First API visibility minus controller injection command start, including helper startup/fault buildup. |
| remote_commands/injector/cleanup_attempts | Exact non-secret injection/cleanup commands, token, watchdog ownership, duration, bounded reconnect results. |
| timeouts/status/errors | Declared bounds and actual result, including preparation failures, interruptions, missing evidence/reference failures, late-success timeouts and unsuccessful cleanup. |
| explicit_cleanup/explicit_recovery | Later idempotent recovery evidence; original failed run status remains unchanged. |

The first trigger requires a new fresh observation of the exact prepared mount at or above the configured threshold. Starting the writer is not trigger evidence. Opening/latest observations come from the collector, and automated rules see only telemetry. API summaries are bounded to 100 and filtered by node/rule/status; detail snapshots retain all relevant evidence. The harness observes one target at a time while checking the other remains fresh, covered and incident-free throughout.

Resource receipt and incident receipt each have their own monotonic timestamp. A 2.5s diagnosis query within the same poll produces 2.5s latency. A matching response arriving after 60s is a timeout. Recovery is accepted only within 60s after owned cleanup, with fresh healthy mount evidence and a resolved matching incident. Absent incidents during a failed injection still require verified cleanup/healthy resource evidence; the run remains failed.

Disk and inode controllers share one filesystem lease per target, so their helpers cannot run simultaneously. Inode threshold timing records resource observation before the diagnosis query and response completion after it; trigger-to-diagnosis latency therefore includes the query delay. Its helper evidence also binds the exact owned directory, write-ahead file ledger, worker/watchdog process identity, and fixed mount mapping.

This schema supports a single disk or inode demonstration. It does not establish a median or five-run calibrated acceptance. Reports must state synthetic Docker versus actual AWS environments, the inspected source snapshot, and unrun visual/live gates explicitly.
