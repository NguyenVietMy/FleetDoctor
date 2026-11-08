# Ticket11 evidence status

Ticket11 source adds schema-v7 I/O collection, same-generation diskstats arithmetic, stable device/filesystem resources, typed `io_bottleneck` incidents with explicit supersession, atomic PostgreSQL persistence, API/history/Prometheus, Grafana panels, an owned dm-delay helper, a measured harness, real-service integration, and an actual-systemd aggregate for WSL or a direct Linux host.

Builder results live only in the external `build1-artifacts` directory. This document does not turn an unrun gate into PASS. Required local gates include Windows locked/static/full tests, Linux root/nonroot images, real PostgreSQL/API integration, actual-systemd production-agent lifecycle with a healthy peer, every changed Prometheus/PostgreSQL dashboard query, exact cleanup, and a final source manifest. Coordinator reruns, visual review, and fresh independent inspection remain separate.

Not claimed here: hosted latest-head CI (publication is unauthorized), AWS/SSH execution, five comparable AWS trials, the healthy-hour false-positive baseline, production overhead, deployment, merge, or owner acceptance.
