# 14: Full CI validation

**What to build:** The completed implementation has recorded passing evidence for every required PR CI check on the identified commit.

**Blocked by:** 04: Durable ingestion and restart recovery; 05: CPU saturation; 06: Workload OOM; 07: Inode exhaustion; 08: FD pressure; 10: DNS failure; 11: I/O bottleneck; 12: Postmortem drafting

**Status:** ready-for-agent

- [ ] Run installation/static checks, Linux collection fixtures, all eight diagnosis/lifecycle tests, collector/API/persistence integration checks, and postmortem fixtures.
- [ ] Cover the PRD failure/reset/freshness/replay/restart cases and drafting failure isolation using fixtures and isolated services.
- [ ] Retain commit identity, results, and failure logs; failed, missing, or skipped required checks block acceptance. Record live runs separately from fixture results.
