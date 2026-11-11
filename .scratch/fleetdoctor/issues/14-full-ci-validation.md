# 14: Full CI validation

**What to build:** The completed implementation has recorded passing evidence for every required PR CI check on the identified commit.

**Blocked by:** 04: Durable ingestion and restart recovery; 05: CPU saturation; 06: Workload OOM; 07: Inode exhaustion; 08: FD pressure; 10: DNS failure; 11: I/O bottleneck; 12: Postmortem drafting

**Status:** case-by-case coverage audit and enforcing CI receipt implemented locally on 2026-11-11; independent source inspection and passing hosted CI for the changed commit remain pending. Baseline CI is retained separately. Acceptance is not yet granted.

- [x] Run installation/static checks, Linux collection fixtures, all eight diagnosis/lifecycle tests, collector/API/persistence integration checks, and postmortem fixtures.
- [x] Audit coverage of the PRD failure/reset/freshness/replay/restart cases and drafting failure isolation against the executed fixtures and isolated-service checks. See the [assertion audit and exact-case contract](../../../docs/ci-coverage.md); baseline execution does not cover new cases.
- [ ] Record fresh independent source inspection and all required current-commit hosted checks, including the enforced coverage receipt. Missing/failed/skipped required evidence blocks acceptance and release of Tickets15/16.
- [x] Retain commit identity, results, and failure logs; failed, missing, or skipped required checks block acceptance. Record live runs separately from fixture results.

**Evidence:** [Coverage audit, skip policy and proof commands](../../../docs/ci-coverage.md); [retained exact-commit CI proof and limits](../../../docs/delivery-status.md#retained-ci-proof). Baseline main [run 42960011517](https://github.com/NguyenVietMy/FleetDoctor/actions/runs/42960011517) passed `f77201e9061290acf60831a61acd7bb8d22f87f9`. It does not establish execution of the Ticket14 changes. Publication and latest-head hosted validation remain separate gates.
