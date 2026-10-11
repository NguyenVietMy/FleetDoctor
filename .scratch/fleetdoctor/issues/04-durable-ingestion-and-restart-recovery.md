# 04: Durable ingestion and restart recovery

**What to build:** A storage failure or collector restart preserves recorded incidents and makes ingestion retryable without claiming unwritten diagnoses.

**Blocked by:** 03: Outage and replay handling

**Status:** ready-for-agent

- [ ] Commit incident changes and ingestion checkpoints atomically before acknowledging successful ingestion; failed persistence returns a retryable error.
- [ ] Reload active incidents after restart with stable identities and saved opening/latest evidence. Rebuild pending windows and counter baselines from fresh observations.
- [ ] Retries following a failed write or restart do not lose an incident, create duplicates, falsely resolve it, or count a sample twice.
- [ ] Integration checks with the test database cover failed writes and restart during the disk lifecycle; record the resulting API/Grafana evidence.
