# 03: Outage and replay handling

**What to build:** During interrupted delivery, operators see stale or unavailable evidence accurately; reconnection and retries preserve incident correctness.

**Blocked by:** 02: Disk-full diagnosis

**Status:** implemented-local; exact source acceptance and proof status are owned by the linked Task03 evidence/handoff. AWS/visual/publication gates unrun.

- [x] Enforce the PRD queue bounds, latest-sample preference, upload/probe timeouts, and dropped-sample reporting while the collector is unavailable.
- [x] Validate sample identity and freshness; deduplicate retries and reject superseded samples from live windows. Handle boot/session changes, clock skew, gaps, and unavailable sources.
- [x] API/Grafana show stale nodes and coverage limitations; old resource gauges disappear at the declared age. Missing, inconclusive, or replayed evidence cannot resolve an incident or advance a rule window.
- [x] Exercise the disk flow through delivery loss and reconnection. Fixture/API tests verify ordering, freshness, bounded retries, and preserved opening evidence.

Implementation semantics and prepared lab procedure: [outage and replay](../../../docs/outage-and-replay.md). Actual builder proof paths and limitations: [Task03 evidence](../../../docs/task03-evidence.md).
