# 14: Full CI validation

**What to build:** The completed implementation has recorded passing evidence for every required PR CI check on the identified commit.

**Blocked by:** 04: Durable ingestion and restart recovery; 05: CPU saturation; 06: Workload OOM; 07: Inode exhaustion; 08: FD pressure; 10: DNS failure; 11: I/O bottleneck; 12: Postmortem drafting

**Status:** released on merged main `1b34a5d1abb364431c12860c1253e2f3b51af479` by hosted run `43136058442`. Its retained coverage receipt reports all 166 required cases passed in each of Linux host, Linux root and Linux non-root. The earlier independent verdict did not inspect the final one-line CI artifact-path correction; that narrow correction was coordinator-validated separately and is not retroactively attributed to the old verdict.

- [x] Run installation/static checks, Linux collection fixtures, all eight diagnosis/lifecycle tests, collector/API/persistence integration checks, and postmortem fixtures.
- [x] Audit coverage of the PRD failure/reset/freshness/replay/restart cases and drafting failure isolation against the executed fixtures and isolated-service checks. See the [assertion audit and exact-case contract](../../../docs/ci-coverage.md); baseline execution does not cover new cases.
- [x] Record the disclosed source-inspection boundary and all required merged-main hosted checks, including the enforced coverage receipt. Missing/failed/skipped required evidence blocks acceptance and release of Tickets15/16.
- [x] Retain commit identity, results, and failure logs; failed, missing, or skipped required checks block acceptance. Record live runs separately from fixture results.

**Evidence:** [Coverage audit, skip policy and proof commands](../../../docs/ci-coverage.md); [retained exact-commit CI proof and limits](../../../docs/delivery-status.md#retained-ci-proof). Merged-main [run 43136058442](https://github.com/NguyenVietMy/FleetDoctor/actions/runs/43136058442) passed `1b34a5d1abb364431c12860c1253e2f3b51af479`: host 817 passed/100 not-required skips, root 910/7 and non-root 813/104. Each environment passed all 166 required cases. Retained coverage receipt SHA-256 is `cb3ea0b641341bc61e2daa54d7f52118b152b6807d88542f42db94d56260dad3`; contract SHA-256 is `c58f8c5c4608c4717fce4687a172be368f530d3d87c9b2bf80b9eee37004e91b`; hosted artifact digest is `sha256:783d1e2a32306d6c4f0f67b53f2808b4bf074c225ebab79c3ab37b8f0488000b`. The final one-line artifact-path correction was coordinator-validated outside the old independent inspection; the old verdict is not expanded.
