# 05: CPU saturation

**What to build:** A bounded CPU workload produces a supported saturation diagnosis and visible recovery on the correct node.

**Blocked by:** 02: Disk-full diagnosis

**Status:** merged in [PR #4](https://github.com/NguyenVietMy/FleetDoctor/pull/4); implementation delivered. Remaining validation is recorded below.

- [x] Collect CPU deltas, runnable demand, logical cores, load, iowait, steal, and bounded top-process evidence with correct scopes, rates, and reset handling.
- [x] Connect the PRD CPU trigger/recovery rule to incident evidence, API/Grafana views, and a bounded oversubscribed injector.
- [x] Verify node/resource lifecycle behavior with fixture/service observations; add collection/rule/API checks and a CPU runbook with manual investigation commands.
- [ ] Demonstrate actual host CPU saturation through supported diagnosis, cleanup and automatic recovery in the target AWS lab. The limited native smoke is collection/cleanup evidence, not threshold or latency acceptance.

**Verified scope:** CPU collection/rule/API/service checks and a limited native collection/cleanup smoke; that smoke does not establish actual host saturation or its diagnosis latency.

**Evidence:** [Task05 handoff record](../../../docs/task05-evidence.md), [current delivery and CI status](../../../docs/delivery-status.md).
