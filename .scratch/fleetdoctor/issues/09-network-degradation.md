# 09: Network degradation

**What to build:** Separate latency and packet-loss faults produce supported network-path incidents while ingestion and administration remain available.

**Blocked by:** 02: Disk-full diagnosis

**Status:** ready-for-agent

- [ ] Collect bounded three-packet direct-IP probes, TCP state/retransmit counters, and interface errors/drops. Keep host-wide and interface-specific evidence distinct.
- [ ] Implement the PRD trigger/recovery behavior and display loss/RTT evidence; no replies yield unavailable RTT with loss evidence.
- [ ] Scope tc/netem to probe traffic and restore the original state on completion or interruption. Exercise latency and loss profiles separately with recovery between them.
- [ ] Record both phase timings and the slower phase as scenario latency. Add probe/rule/API checks, graphs, and the network runbook.
