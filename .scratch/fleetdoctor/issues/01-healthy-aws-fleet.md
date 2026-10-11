# 01: Healthy AWS fleet

**What to build:** An engineer can start the three-VM AWS lab and see fresh filesystem observations from both monitored nodes through the collector API, Prometheus history, and Grafana.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Select Linux/cgroup v2 images and instance sizes using a current estimate against the $20 AWS target before provisioning. Include retained storage, IPv4, CPU surplus, and documented start/stop/export/teardown procedures.
- [ ] Two host agents send identified, versioned filesystem samples every five seconds over private addresses. Latest/history APIs and fleet/per-node Grafana views show correct units, observation age, and coverage.
- [ ] Central services run through Docker Compose with persistent stores, configured retention/disk limits, restricted access, and SSH-tunnel instructions.
- [ ] Initial installation/static checks, Linux parsing fixtures, and isolated collector/service integration checks pass. Record a healthy end-to-end demonstration and setup instructions.
