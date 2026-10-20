# Task08 evidence status

Task08 implements strict schema-v4 file-descriptor collection, exact boot/PID/start-time identity, bounded configured/top/watch selection, monotonic growth evidence, durable typed `fd_pressure` lifecycle and watch recovery, API/history/Prometheus/Grafana surfaces, a pidfd-only bounded helper, production harness, operations documentation, and CI gates.

Evidence is separated by role and environment:

- Builder fixture/static checks cover finite/unlimited/missing/malformed limits, bounded/racy FD enumeration, selection priority/capacity, watch churn, growth resets, thresholds and equality, frozen gaps/configuration, release/exit/boot recovery, durable restart/lost acknowledgement, mixed typed rules, payload bounds, watch-fetch total deadline/cache behavior, helper authority/rollback, and harness late/contradictory/preparation cleanup behavior.
- The isolated service proof uses real PostgreSQL, Prometheus, Grafana datasource queries, collector restart, and explicitly synthetic schema-v4 observations. It is not native `/proc` pressure evidence or visual-render approval.
- The native proof uses actual Linux `/proc`, the bounded unprivileged helper, production agent/watch fetch/worker, production harness/collector, and real PostgreSQL. Its healthy reference is a separate Docker PID namespace on the same Docker host and network, not a separate AWS node. The main lifecycle does not filter production top lists; controlled fixtures separately prove configured inclusion outside both top sets.
- Native lifecycle evidence includes low configured baseline, staged actual threshold timing, exact summary/detail identity and incident ID, immutable opening evidence across collector restart, descriptor release, confirmed exit, node-wide concurrent-token exclusion, failed start, worker self-expiry, independent watchdog expiry, and owned cleanup.
- Independent inspection, coordinator-run stable-source proof, rendered Grafana inspection at 2000x900, remote CI, AWS/SSH/deployment, five measured AWS runs, healthy-hour/overhead calibration, publication, and owner acceptance remain unrun at builder handoff.

Builder commands, retained failures, unique external artifacts, source bindings, and cleanup results are recorded in the external `build-result.json`. Approved-plan status is design authorization only; builder checks do not establish independent source approval or any unrun gate.
