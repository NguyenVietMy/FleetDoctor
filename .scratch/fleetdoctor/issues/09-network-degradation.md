# 09: Network degradation

**What to build:** Separate latency and packet-loss faults produce supported network-path incidents while ingestion and administration remain available.

**Blocked by:** 02: Disk-full diagnosis

**Status:** merged in [PR #8](https://github.com/NguyenVietMy/FleetDoctor/pull/8); implementation delivered. Remaining validation is recorded below.

- [x] Collect bounded three-packet direct-IP probes, TCP state/retransmit counters, and interface errors/drops. Keep host-wide and interface-specific evidence distinct.
- [x] Implement the PRD trigger/recovery behavior and display loss/RTT evidence; no replies yield unavailable RTT with loss evidence.
- [x] Scope tc/netem to probe traffic and restore the original state on completion or interruption. Exercise latency and loss profiles separately with recovery between them.
- [x] Record both phase timings and the slower phase as scenario latency. Add probe/rule/API checks, graphs, and the network runbook.

**Verified scope:** Fixture/service checks plus native isolated ping/tc latency and loss profiles, diagnosis/recovery and cleanup CI; five comparable AWS runs remain separate.

**Evidence:** [Task09 handoff record](../../../docs/task09-evidence.md), [current delivery and CI status](../../../docs/delivery-status.md).
