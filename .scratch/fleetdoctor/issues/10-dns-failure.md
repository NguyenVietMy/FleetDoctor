# 10: DNS failure

**What to build:** A resolver failure produces a DNS incident when direct-IP reachability remains healthy and resolves after the original resolver is restored.

**Blocked by:** 09: Network degradation

**Status:** ready-for-agent

- [ ] Perform bounded uncached queries through the node's configured resolver for a baseline-confirmed hostname; retain nameservers, timing, and errors.
- [ ] Implement the PRD DNS windows and evidence. Show inconclusive DNS evidence when direct-IP reachability also fails, and keep ingestion addressed by private IP.
- [ ] Save and restore resolver state, including interrupted runs; demonstrate diagnosis and recovery through API/Grafana and add probe/rule/API checks plus a DNS runbook.
