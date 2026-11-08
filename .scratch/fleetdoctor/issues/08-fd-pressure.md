# 08: FD pressure

**What to build:** A configured leaking process produces an FD-pressure incident with its actual descriptor limit and identity, resolving after release or confirmed exit.

**Blocked by:** 02: Disk-full diagnosis

**Status:** merged in [PR #7](https://github.com/NguyenVietMy/FleetDoctor/pull/7); implementation delivered. Remaining validation is recorded below.

- [x] Collect FD count, finite soft limit, PID/start-time identity, growth, and supporting CPU/RSS for configured workloads and the bounded process set.
- [x] Expose evidence and investigation steps through the API/Grafana; distinguish observed pressure from suspected leakage and handle PID reuse and confirmed process exit.
- [x] Run a bounded small-limit FD workload through diagnosis and cleanup/recovery. Add parsing/rule/API checks for unavailable limits, reuse, growth, exit, and the FD runbook.

**Verified scope:** Fixture/service checks plus native process FD pressure and exact-identity cleanup/recovery CI; the healthy peer uses the same Docker host, not another AWS VM.

**Evidence:** [Task08 handoff record](../../../docs/task08-evidence.md), [current delivery and CI status](../../../docs/delivery-status.md).
