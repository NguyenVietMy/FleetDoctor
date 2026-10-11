# 05: CPU saturation

**What to build:** A bounded CPU workload produces a supported saturation diagnosis and visible recovery on the correct node.

**Blocked by:** 02: Disk-full diagnosis

**Status:** ready-for-agent

- [ ] Collect CPU deltas, runnable demand, logical cores, load, iowait, steal, and bounded top-process evidence with correct scopes, rates, and reset handling.
- [ ] Connect the PRD CPU trigger/recovery rule to incident evidence, API/Grafana views, and a bounded oversubscribed injector.
- [ ] Verify correct node/resource diagnosis, cleanup, and automatic recovery; add collection/rule/API checks and a CPU runbook with manual investigation commands.
