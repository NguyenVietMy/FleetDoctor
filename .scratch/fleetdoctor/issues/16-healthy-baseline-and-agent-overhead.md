# 16: Healthy baseline and agent overhead

**What to build:** Measured healthy operation demonstrates zero false incidents and bounded agent overhead on both monitored nodes.

**Blocked by:** 14: Full CI validation

**Status:** ready-for-agent

- [ ] Run a separate one-hour lab session with idle periods, ordinary light workloads, and brief healthy transients; both nodes must remain observable with zero false incidents.
- [ ] Average agent CPU must be below 2% of one logical core and peak RSS below 50 MB on each node. Measure workload memory separately.
- [ ] Retain the workload, measurement method, node observations, incident output, revision, and environment. Keep this session separate from chaos injections.
