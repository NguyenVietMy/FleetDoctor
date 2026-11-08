# 14: Full CI validation

**What to build:** The completed implementation has recorded passing evidence for every required PR CI check on the identified commit.

**Blocked by:** 04: Durable ingestion and restart recovery; 05: CPU saturation; 06: Workload OOM; 07: Inode exhaustion; 08: FD pressure; 10: DNS failure; 11: I/O bottleneck; 12: Postmortem drafting

**Status:** verification partial; passing CI execution and retained results are available. The PRD coverage audit remains pending.

- [x] Run installation/static checks, Linux collection fixtures, all eight diagnosis/lifecycle tests, collector/API/persistence integration checks, and postmortem fixtures.
- [ ] Audit coverage of the PRD failure/reset/freshness/replay/restart cases and drafting failure isolation against the executed fixtures and isolated-service checks.
- [x] Retain commit identity, results, and failure logs; failed, missing, or skipped required checks block acceptance. Record live runs separately from fixture results.

**Evidence:** [Retained exact-commit CI proof and limits](../../../docs/delivery-status.md#retained-ci-proof). Passing the workflow supplies execution evidence; the unchecked coverage audit still blocks this ticket's acceptance.
