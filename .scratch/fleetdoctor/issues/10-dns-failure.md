# 10: DNS failure

**What to build:** A resolver failure produces a DNS incident when direct-IP reachability remains healthy and resolves after the original resolver is restored.

**Blocked by:** 09: Network degradation

**Status:** merged in [PR #9](https://github.com/NguyenVietMy/FleetDoctor/pull/9); implementation delivered. Remaining validation is recorded below.

- [x] Perform bounded uncached queries through the node's configured resolver for a baseline-confirmed hostname; retain nameservers, timing, and errors.
- [x] Implement the PRD DNS windows and evidence. Show inconclusive DNS evidence when direct-IP reachability also fails, and keep ingestion addressed by private IP.
- [x] Save and restore resolver state, including interrupted runs; demonstrate diagnosis and recovery through API/Grafana and add probe/rule/API checks plus a DNS runbook.

**Verified scope:** Fixture/service and native resolver/restoration CI, including direct-resolver and systemd-resolved coverage; AWS deployment and calibration remain separate.

**Evidence:** [Task10 handoff record](../../../docs/task10-evidence.md), [current delivery and CI status](../../../docs/delivery-status.md).
