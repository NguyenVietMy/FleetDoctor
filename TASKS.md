# FleetDoctor tasks

Approved breakdown: 19 slices. Ticket numbers below are sequential; the discussion column preserves the original numbers, including split slices 3A/3B and validations 13A–13F.

The [PRD](<FleetDoctor PRD.md>) owns requirements, thresholds, windows, and measurement rules. Tickets 01 and 02 passed their AWS functional demonstrations on 2026-10-11; Task02's frozen independent verdict and remaining gates are recorded in [Task02 evidence](docs/task02-evidence.md). Task03 is implemented locally; its exact source acceptance, verification and remaining gates are tracked in [Task03 evidence](docs/task03-evidence.md). Task04 is implemented with builder-local verification; [Task04 evidence](docs/task04-evidence.md) records the measured proof and the still-unrun independent, remote, AWS and rendered-dashboard gates. Later tickets are unstarted. `ready-for-agent` means the ticket is specified. Work starts when its blockers are complete. See also [Task01 evidence](docs/task01-evidence.md). Project target: 2026-10-25.

| Ticket | Discussion | Outcome | Blocked by |
| --- | --- | --- | --- |
| 01 | 1 | [Healthy AWS fleet](.scratch/fleetdoctor/issues/01-healthy-aws-fleet.md) | None |
| 02 | 2 | [Disk-full diagnosis](.scratch/fleetdoctor/issues/02-disk-full-diagnosis.md) | 01 |
| 03 | 3A | [Outage and replay handling](.scratch/fleetdoctor/issues/03-outage-and-replay-handling.md) | 02 |
| 04 | 3B | [Durable ingestion and restart recovery](.scratch/fleetdoctor/issues/04-durable-ingestion-and-restart-recovery.md) | 03 |
| 05 | 4 | [CPU saturation](.scratch/fleetdoctor/issues/05-cpu-saturation.md) | 02 |
| 06 | 5 | [Workload OOM](.scratch/fleetdoctor/issues/06-workload-oom.md) | 02 |
| 07 | 6 | [Inode exhaustion](.scratch/fleetdoctor/issues/07-inode-exhaustion.md) | 02 |
| 08 | 7 | [FD pressure](.scratch/fleetdoctor/issues/08-fd-pressure.md) | 02 |
| 09 | 8 | [Network degradation](.scratch/fleetdoctor/issues/09-network-degradation.md) | 02 |
| 10 | 9 | [DNS failure](.scratch/fleetdoctor/issues/10-dns-failure.md) | 09 |
| 11 | 10 | [I/O bottleneck](.scratch/fleetdoctor/issues/11-io-bottleneck.md) | 02 |
| 12 | 11 | [Postmortem drafting](.scratch/fleetdoctor/issues/12-postmortem-drafting.md) | 02 |
| 13 | 12 | [DistributedKVStore investigation](.scratch/fleetdoctor/issues/13-distributedkvstore-investigation.md) | 05, 06, 08, 09, 11 |
| 14 | 13A | [Full CI validation](.scratch/fleetdoctor/issues/14-full-ci-validation.md) | 04, 05, 06, 07, 08, 10, 11, 12 |
| 15 | 13B | [Chaos measurement validation](.scratch/fleetdoctor/issues/15-chaos-measurement-validation.md) | 14 |
| 16 | 13C | [Healthy baseline and agent overhead](.scratch/fleetdoctor/issues/16-healthy-baseline-and-agent-overhead.md) | 14 |
| 17 | 13D | [Postmortem verification](.scratch/fleetdoctor/issues/17-postmortem-verification.md) | 15 |
| 18 | 13E | [KV tracing verification](.scratch/fleetdoctor/issues/18-kv-tracing-verification.md) | 13 |
| 19 | 13F | [Final delivery verification](.scratch/fleetdoctor/issues/19-final-delivery-verification.md) | 16, 17, 18 |

## Working rules

- Implementation slices deliver observable behavior through collection, diagnosis where applicable, API/Grafana, tests, and usage/runbook documentation. Extend CI with the delivered behavior; ticket 14 verifies the full required gate.
- Chaos scripts prepare fresh baselines, measure actual resource/probe triggers, enforce timeouts, restore state on completion/interruption, and retain incident-linked timing/evidence. The diagnosis engine receives ordinary telemetry.
- Chaos measurements and the healthy baseline use separate lab sessions. Successful fixture checks and live execution each require their own recorded evidence.
- All scope is core. Preserve the two-week target and $20 AWS target; record exact dates when implementation begins and use measured results for final claims.
