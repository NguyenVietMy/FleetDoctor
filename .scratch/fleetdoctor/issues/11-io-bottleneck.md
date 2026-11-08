# 11: I/O bottleneck

**What to build:** Sustained device latency and backlog produce an I/O incident with supported device/filesystem evidence and correct recovery after the workload stops.

**Blocked by:** 02: Disk-full diagnosis

**Status:** merged in [PR #10](https://github.com/NguyenVietMy/FleetDoctor/pull/10); implementation delivered. Remaining validation is recorded below.

- [x] Collect completed I/O counts/timing, inflight/weighted I/O, available PSI and configured-process counters. Derive interval throughput, latency, and outstanding I/O with an explicit device mapping.
- [x] Apply the PRD latency/backlog windows and fresh idle-device recovery; unavailable latency alone cannot clear an incident. Support process attribution only with evidence.
- [x] Use bounded concurrent I/O on preallocated files while block/inode usage remain below failure thresholds; restore workload state on interruption.
- [x] Demonstrate API/Grafana diagnosis and recovery; add rate/reset/device/idle-recovery tests and the I/O runbook and metric explanations.

**Verified scope:** Fixture/service, API/Grafana query wiring and actual-systemd I/O lifecycle CI; rendered-dashboard acceptance and AWS calibration remain separate.

**Evidence:** [Task11 handoff record](../../../docs/task11-evidence.md), [current delivery and CI status](../../../docs/delivery-status.md).
