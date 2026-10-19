# Task07 evidence status

Task07 implements a distinct typed inode-exhaustion rule, effective block disambiguation, heterogeneous durable lifecycle/reload/reconciliation, API/history/Prometheus/Grafana surfaces, a bounded inode helper with shared disk exclusion and independent watchdog, a measured harness, operations documentation and CI gates.

Evidence is separated by role and environment:

- Builder fixture/static checks cover threshold/hysteresis, unavailable/partial data, block-vs-inode disambiguation, effective guard derivation, window resets, frozen typed JSON, restart, API counts/coverage/history mapping, helper ownership and partial-kill cleanup, and measured-harness behavior.
- The isolated service proof uses real PostgreSQL, Prometheus and Grafana with explicitly synthetic observations.
- The privileged native proof uses a private tmpfs-backed ext4 loop resource, production statvfs collection, real PostgreSQL/API persistence and recovery. It is not FixtureStore evidence.
- The existing disk-helper proof is rerun because new images now use an explicit small inode budget and disk/inode leases mutually exclude.
- Independent inspection, coordinator-run proof, rendered Grafana review, remote CI, AWS/SSH/deployment, five measured AWS runs, healthy-hour/overhead calibration, publication and owner acceptance remain unrun at builder handoff.

Builder proof commands and unique external artifact paths are recorded in the external `builder-result.json`. Plan approval is design-only; builder checks do not establish independent source approval or any unrun gate.
