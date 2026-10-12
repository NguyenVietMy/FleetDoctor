# Task02 evidence

Task02 implementation, static checks, Windows/Linux tests, real PostgreSQL/Grafana integration and two fresh AWS disk lifecycles passed on 2026-10-11. Independent source acceptance is recorded in the [external final handoff](C:/Users/VietM/.fleetdoctor/task02-20261011-130055/final-handoff.json), bound to the complete frozen manifest. No commit, push or merge was performed.

Base: `a1888a967ee474051336a90d19fd2ca39caf2c25`. Approved plan SHA256: `7f697eea6972c1a7ec83c72e1874618fbd261c7e73a8d3874205a94feb3e02d9`, plan-review round2. Private proof artifacts reside under `C:/Users/VietM/.fleetdoctor/task02-20261011-130055/`.

The delegated builder authored the original implementation and two fixes. The coordinator authored verification drivers/docs and the later committed-acknowledgement fix in collector.py, test_disk.py, commit_ack_probe.py and integration_disk.py. Fresh Sol6.1 High/Fast inspectors are separate from both authors. This is same-provider independent review. Two plan reviews, two delegated fix rounds and two inspection rounds are the declared budget; the coordinator takeover is separately recorded.

## Current proofs

- Windows Python3.12: **99 passed, 13 Linux-only skipped**. Linux Python3.11.16: **112 passed, no skips**. One upstream Starlette/httpx warning remains. Locked sync, Ruff format/lint, mypy, imports and Terraform format/validation passed. Records: `static-checks-host-p1-final.json`, `windows-checks-host-p1.json`, `remote-verification-host-p1-retry4.json`.
- The current real isolated PostgreSQL/Grafana integration passed on the retained AWS monitor with synthetic observations, its own unique project/ports/secrets and verified packaged-source hashes. It built the default production image and removed only its test containers/volumes and current source copy. The nested runner's `aws_execution:false` means that script performs no AWS operations or real-node disk measurements; its hosting environment is explicitly recorded by the wrapper. Local Docker was unresponsive after the disk-space incident, and was not globally restarted.
- Integration covers required storage, SQL failure before publication, DB outage/retry, reload/age/unavailable evidence, opening immutability, recovery/recurrence, filters/pagination, reader write denial and every diagnosis panel query. New cases inject a client error **after a real PostgreSQL COMMIT**, then check identical/interposed-newer-low retries, original incident/resolution, committed counts and recurrence. This proves the committed boundary; no actual dropped network packet is claimed.
- The unchanged helper's earlier actual privileged Linux proof remains valid: ext4 fill, worker SIGKILL with independent watchdog cleanup, private namespace identity checks, retained-image remount, rollback and unrelated-mount refusal. Records: `disk_helper-checks-initial.json`, `disk-helper-initial.json`. Its own container/image were removed.

The 112-test Linux transcript is reused from retry2 with every production/unit-test hash unchanged; the only intervening source edit makes the service test explicitly wait for observation expiry. That service proof is rerun on the final bytes. Windows application/unit-test bytes likewise remain unchanged.

The first independent inspection returned **REVISE**, finding FD02-I1-001: a lost COMMIT acknowledgement could strand an incident because memory stayed behind the durable row. The coordinator accepted and fixed it by reconciling canonical active rows before evaluating eligible observations, publishing memory only after a successful transaction, and deriving counts from committed rows. Regression tests cover same/newer-high/newer-low/config changes, original UUID/opening/config/severity, original resolution time, recurrence, reload flags and failed count reads. The previous inspection does not cover these later edits; the final handoff contains the fresh round2 verdict.

## Fresh AWS functional demonstration

Profile `fleetdoctor`, region `us-east-1`; monitor `i-0d038b65ed59c5dfd`, node-a `i-01a322f2d65025cde`, node-b `i-0a734cc76af61c027`. Existing secrets were preserved. Current installed module, operation-file and systemd unit hashes matched source; preflight verified fresh consecutive 5s delivery, root plus dedicated resource coverage, zero active incidents, actual Grafana queries and closed public monitoring/database ports.

Both runs filled only `/var/lib/fleetdoctor/chaos/disk` on node-a. Node-b remained fresh, covered and incident-free in every recorded poll. Three fresh >=95% observations opened critical incidents; owned cleanup and three fresh <90% observations resolved them. Opening evidence stayed unchanged, history persisted, and recurrence used a different UUID.

| Run | Incident UUID | Threshold observation to API diagnosis | Injection start to API diagnosis | Cleanup to API resolution |
| --- | --- | ---: | ---: | ---: |
| 1 | `ff8d91b8-69d7-4b12-a95f-98c5ab8e84fe` | 10.188s | 14.922s | 11.484s |
| 2 | `70445a8f-ec93-4b3b-a21a-c5575f83aa37` | 10.093s | 13.843s | 11.531s |

These are **two functional demonstrations**, not a calibrated five-run batch or median claim. Timing uses one controller monotonic clock and includes requests/poll delay. Both 60s diagnosis/recovery bounds passed. Raw polls, configuration, source hashes, resource identities, incident details, cleanup and timestamps are retained in `aws-disk-host-p1-retry5-functional-1.json` and `aws-disk-host-p1-retry5-functional-2.json`.

`aws-acceptance-host-p1-retry5.json`, `aws-healthy-host-p1-retry5.json` and `acceptance-audit-host-p1-retry5.json` bind the current deployment and completed-record audit. All four actual Grafana diagnosis panels returned both new UUIDs. Reader SELECT was true; INSERT/UPDATE/DELETE false. Both nodes were fresh with zero active incidents before shutdown. SQL contains both UUIDs; SQL/store/inventory exports were nonempty, hash-verified and the store archive listed. **Restore remains unrun.**

Ordinary EC2 stop/start preserved the image path/inode/filesystem identity with a new boot ID and successful collection. Historical explicit owned recovery released the matching lease without relabeling its failed run. Abrupt reboot while filled remains unrun.

Final AWS readback at the end of `2026-10-11T23:40:06.847372+00:00` confirmed **all three exact instances stopped, no public IPs**. The coordinator closed its own tunnel, exported evidence and stopped the allowlisted IDs in a finally path. Retained EBS still bills.

## Failures and source binding

Original BOM, late-tunnel and Windows report-replace failures remain failed in separate artifacts. Two builder fixes accept UTF8/BOM inventories and bound retry of only Windows replacement errors5/32; permanent failures/interruption still surface and retry delay is measured. `aws-explicit-recovery-retry3.json` retains the original failed status while proving explicit owned cleanup/recovery. Earlier passing retry3 measurements precede the coordinator fix and are historical evidence, not acceptance of this newer code.

The first new `host-p1` attempt failed SSH/export before deployment/injection after the controller IP changed. The approved plan allowed a necessary SSH refresh after inspection: exactly two TCP22 owner rules changed to the current single /32 and readback matched. A broad Terraform plan was rejected for stopped-state public-IP replacements and never applied. The refreshed running plan has zero resource changes. `host-p1-retry1` passed all 112 Linux tests but service integration stopped before creating a stack because Git was absent; the wrapper added that explicit test prerequisite for the next attempt. The retry2 service test exposed an environment-dependent assumption that connection failures necessarily age the first observation beyond 10s; the coordinator made expiry explicit before constructing the fresh retry, without changing application code. Local failed transcripts and source hashes are retained. Retry4 passed the current service proof, then its physical run opened a critical incident and confirmed cleanup but failed on a recovery HTTP ReadTimeout; its failed report/lease were retained. The next attempt explicitly recovered that same token after reboot before the passing physical runs. Current service proof is reused under all84 matching source hashes, with no application or timeout changes. The retry2 temporary server result was cleared on reboot; a recovery-status record explicitly marks it unavailable. A subsequent retry stopped on that optional recovery dependency before testing; the wrapper corrected it and moved new artifacts to a private home directory that survives reboot.

ENOSPC left the original inspection-round1.json zero bytes; recovered independent output is in a new inspection-round1-recovered.json. Recorded cleanup removed only two superseded generated Task02 store archives and reproducible own bytecode, preserving SQL/inventory, the latest complete export and all original Task01 evidence. A later45GB free-space change is not attributed to that cleanup.

The audit verified all 65 measurement source hashes before documentation updates; the independent remote package verified 84 files. Later checkout edits are limited to README, TASKS, ticket02, disk-full.md and this page. `post-measurement-documentation-host-p1.json` records exact deltas. Production code, tests, CI and dashboards remain the measured bytes; the final frozen manifest includes the documentation.

## Remaining gates

Visual Grafana inspection is **unrun**: surface inventory was empty and the in-app browser returned `Browser is not available: iab`. Actual SQL/datasource responses are separate evidence. Remote CI, backup restore, owner billing/credits/$20 alert, Task04 durable sample checkpoints, Task15 calibrated measurements, Task16 healthy-hour/overhead and later diagnosis/postmortem/workload tickets are not claimed complete.

See the [disk runbook](disk-full.md) and [measurement format](chaos-measurements.md). The external handoff owns the exact inspected source, verdict and remaining findings; plan approval alone is not source acceptance.
