# 11: I/O bottleneck

**What to build:** Sustained device latency and backlog produce an I/O incident with supported device/filesystem evidence and correct recovery after the workload stops.

**Blocked by:** 02: Disk-full diagnosis

**Status:** ready-for-agent

- [ ] Collect completed I/O counts/timing, inflight/weighted I/O, available PSI and configured-process counters. Derive interval throughput, latency, and outstanding I/O with an explicit device mapping.
- [ ] Apply the PRD latency/backlog windows and fresh idle-device recovery; unavailable latency alone cannot clear an incident. Support process attribution only with evidence.
- [ ] Use bounded concurrent I/O on preallocated files while block/inode usage remain below failure thresholds; restore workload state on interruption.
- [ ] Demonstrate API/Grafana diagnosis and recovery; add rate/reset/device/idle-recovery tests and the I/O runbook and metric explanations.
