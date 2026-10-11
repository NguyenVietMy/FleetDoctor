# 08: FD pressure

**What to build:** A configured leaking process produces an FD-pressure incident with its actual descriptor limit and identity, resolving after release or confirmed exit.

**Blocked by:** 02: Disk-full diagnosis

**Status:** ready-for-agent

- [ ] Collect FD count, finite soft limit, PID/start-time identity, growth, and supporting CPU/RSS for configured workloads and the bounded process set.
- [ ] Expose evidence and investigation steps through the API/Grafana; distinguish observed pressure from suspected leakage and handle PID reuse and confirmed process exit.
- [ ] Run a bounded small-limit FD workload through diagnosis and cleanup/recovery. Add parsing/rule/API checks for unavailable limits, reuse, growth, exit, and the FD runbook.
