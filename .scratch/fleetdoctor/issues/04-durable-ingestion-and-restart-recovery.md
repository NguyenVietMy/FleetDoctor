# 04: Durable ingestion and restart recovery

**What to build:** A storage failure or collector restart preserves recorded incidents and makes ingestion retryable without claiming unwritten diagnoses.

**Blocked by:** 03: Outage and replay handling

**Status:** merged in [PR #3](https://github.com/NguyenVietMy/FleetDoctor/pull/3); implementation delivered. Remaining validation is recorded below.

- [x] Commit incident changes and ingestion checkpoints atomically before acknowledging successful ingestion; failed persistence returns a retryable error.
- [x] Reload active incidents after restart with stable identities and saved opening/latest evidence. Rebuild pending windows and counter baselines from fresh observations.
- [x] Retries following a failed write or restart do not lose an incident, create duplicates, falsely resolve it, or count a sample twice.
- [x] Integration checks with the test database cover failed writes and restart during the disk lifecycle; record the resulting API and provisioned Grafana datasource evidence.

- [ ] Record the source-gated AWS collector restart/recovery demonstration and rendered-dashboard acceptance.

**Verified scope:** Atomic PostgreSQL/checkpoint, rollback, retry and restart checks, API evidence and provisioned Grafana datasource queries; AWS restart and rendered-dashboard acceptance remain separate.

**Evidence:** [Task04 handoff record](../../../docs/task04-evidence.md), [current delivery and CI status](../../../docs/delivery-status.md).
