# FleetDoctor tasks

**Status updated 2026-11-11** against baseline `main` at [`f77201e`](https://github.com/NguyenVietMy/FleetDoctor/commit/f77201e9061290acf60831a61acd7bb8d22f87f9). Implementation Tickets 03–13 are merged. Ticket14's PRD coverage audit/enforcement is implemented locally with inspection and current-commit hosted CI pending; Tickets 15–19 retain their separate validation gates. Ticket12's model example still needs owner author acceptance.

The [delivery status](docs/delivery-status.md) links merged PRs, retained CI proof and pending live/acceptance work. Individual issue checklists distinguish delivered implementation from unverified live demonstrations. The [PRD](<FleetDoctor PRD.md>) owns requirements, thresholds, windows and measurement rules. Tickets 01/02 retain their 2026-10-11 AWS functional evidence; five-run calibration, the healthy-hour/overhead run and final delivery acceptance remain later gates.

Approved breakdown: 19 slices. Ticket numbers below are sequential; the discussion column preserves the original numbers, including split slices 3A/3B and validations 13A–13F. `ready-for-agent` means specified; a ticket starts only after its blockers are complete. The original project target remains 2026-10-25, not a claim that it was met.

| Ticket | Discussion | Outcome | Status | Blocked by |
| --- | --- | --- | --- | --- |
| 01 | 1 | [Healthy AWS fleet](.scratch/fleetdoctor/issues/01-healthy-aws-fleet.md) | Implemented; AWS functional evidence recorded | None |
| 02 | 2 | [Disk-full diagnosis](.scratch/fleetdoctor/issues/02-disk-full-diagnosis.md) | Implemented; AWS functional evidence recorded | 01 |
| 03 | 3A | [Outage and replay handling](.scratch/fleetdoctor/issues/03-outage-and-replay-handling.md) | [Merged PR #2](https://github.com/NguyenVietMy/FleetDoctor/pull/2) | 02 |
| 04 | 3B | [Durable ingestion and restart recovery](.scratch/fleetdoctor/issues/04-durable-ingestion-and-restart-recovery.md) | [Merged PR #3](https://github.com/NguyenVietMy/FleetDoctor/pull/3) | 03 |
| 05 | 4 | [CPU saturation](.scratch/fleetdoctor/issues/05-cpu-saturation.md) | [Merged PR #4](https://github.com/NguyenVietMy/FleetDoctor/pull/4) | 02 |
| 06 | 5 | [Workload OOM](.scratch/fleetdoctor/issues/06-workload-oom.md) | [Merged PR #5](https://github.com/NguyenVietMy/FleetDoctor/pull/5) | 02 |
| 07 | 6 | [Inode exhaustion](.scratch/fleetdoctor/issues/07-inode-exhaustion.md) | [Merged PR #6](https://github.com/NguyenVietMy/FleetDoctor/pull/6) | 02 |
| 08 | 7 | [FD pressure](.scratch/fleetdoctor/issues/08-fd-pressure.md) | [Merged PR #7](https://github.com/NguyenVietMy/FleetDoctor/pull/7) | 02 |
| 09 | 8 | [Network degradation](.scratch/fleetdoctor/issues/09-network-degradation.md) | [Merged PR #8](https://github.com/NguyenVietMy/FleetDoctor/pull/8) | 02 |
| 10 | 9 | [DNS failure](.scratch/fleetdoctor/issues/10-dns-failure.md) | [Merged PR #9](https://github.com/NguyenVietMy/FleetDoctor/pull/9) | 09 |
| 11 | 10 | [I/O bottleneck](.scratch/fleetdoctor/issues/11-io-bottleneck.md) | [Merged PR #10](https://github.com/NguyenVietMy/FleetDoctor/pull/10) | 02 |
| 12 | 11 | [Postmortem drafting](.scratch/fleetdoctor/issues/12-postmortem-drafting.md) | [Merged PR #11](https://github.com/NguyenVietMy/FleetDoctor/pull/11); author acceptance pending | 02 |
| 13 | 12 | [DistributedKVStore investigation](.scratch/fleetdoctor/issues/13-distributedkvstore-investigation.md) | Implemented; bounded AWS trace verified; Ticket18/owner verification separate | 05, 06, 08, 09, 11 |
| 14 | 13A | [Full CI validation](.scratch/fleetdoctor/issues/14-full-ci-validation.md) | [Coverage audit/enforcement](docs/ci-coverage.md) implemented locally; inspection and current-commit hosted CI pending | 04, 05, 06, 07, 08, 10, 11, 12 |
| 15 | 13B | [Chaos measurement validation](.scratch/fleetdoctor/issues/15-chaos-measurement-validation.md) | Not started; blocked | 14 |
| 16 | 13C | [Healthy baseline and agent overhead](.scratch/fleetdoctor/issues/16-healthy-baseline-and-agent-overhead.md) | Not started; blocked | 14 |
| 17 | 13D | [Postmortem verification](.scratch/fleetdoctor/issues/17-postmortem-verification.md) | Not started; blocked | 15 |
| 18 | 13E | [KV tracing verification](.scratch/fleetdoctor/issues/18-kv-tracing-verification.md) | Not started; blocked | 13 |
| 19 | 13F | [Final delivery verification](.scratch/fleetdoctor/issues/19-final-delivery-verification.md) | Not started; blocked | 16, 17, 18 |

## Working rules

- Implementation slices deliver observable behavior through collection, diagnosis where applicable, API/Grafana, tests, and usage/runbook documentation. Extend CI with the delivered behavior; ticket 14 verifies the full required gate.
- Chaos scripts prepare fresh baselines, measure actual resource/probe triggers, enforce timeouts, restore state on completion/interruption, and retain incident-linked timing/evidence. The diagnosis engine receives ordinary telemetry.
- Chaos measurements and the healthy baseline use separate lab sessions. Successful fixture checks and live execution each require their own recorded evidence.
- All scope is core. Preserve the two-week target and $20 AWS target; record exact dates when implementation begins and use measured results for final claims.
