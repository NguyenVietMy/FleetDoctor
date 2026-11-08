# 03: Outage and replay handling

**What to build:** During interrupted delivery, operators see stale or unavailable evidence accurately; reconnection and retries preserve incident correctness.

**Blocked by:** 02: Disk-full diagnosis

**Status:** merged in [PR #2](https://github.com/NguyenVietMy/FleetDoctor/pull/2); implementation delivered. Remaining validation is recorded below.

- [x] Enforce the PRD queue bounds, latest-sample preference, upload/probe timeouts, and dropped-sample reporting while the collector is unavailable.
- [x] Validate sample identity and freshness; deduplicate retries and reject superseded samples from live windows. Handle boot/session changes, clock skew, gaps, and unavailable sources.
- [x] API/Grafana show stale nodes and coverage limitations; old resource gauges disappear at the declared age. Missing, inconclusive, or replayed evidence cannot resolve an incident or advance a rule window.
- [x] Fixture/API/service outage and replay checks verify ordering, freshness, bounded retries, and preserved opening evidence.
- [ ] Retain a combined actual AWS disk-fault/delivery-loss/reconnection demonstration; the isolated service and separate privileged disk-helper proofs do not establish that combined live run.

Implementation semantics and prepared lab procedure: [outage and replay](../../../docs/outage-and-replay.md). Actual builder proof paths and limitations: [Task03 evidence](../../../docs/task03-evidence.md).

**Verified scope:** Fixture/API/service outage and replay checks plus a separate privileged disk-helper proof; the combined AWS disk-and-delivery fault is still unverified.

**Evidence:** [Task03 handoff record](../../../docs/task03-evidence.md), [current delivery and CI status](../../../docs/delivery-status.md).
