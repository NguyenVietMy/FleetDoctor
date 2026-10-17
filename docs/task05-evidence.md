# Task05 evidence status

Task05 implements strict schema-v2 host CPU telemetry while preserving literal schema-v1 serialization/fingerprints; bounded `/proc` host/process collection; CPU trigger/recovery with heterogeneous atomic incident/checkpoint persistence; fresh API, fixed Prometheus history, and Grafana surfaces; and bounded helper, smoke, and harness entry points.

Evidence is deliberately separated:

| Gate | Status in source handoff |
| --- | --- |
| Builder format/lint/type/Windows tests | Recorded in the external builder result after execution |
| Limited native-Linux `/proc` workload smoke | Command prepared; only claim if an actual report is retained |
| Isolated PostgreSQL/Prometheus/Grafana lifecycle | Command prepared; only claim if the unique external report passes |
| Fresh independent source inspection and rendered dashboard screenshots | Coordinator gate, unexecuted by this document |
| CI on a pushed latest commit | Not authorized or executed in the builder assignment |
| AWS host saturation, five-run measurement, Task15 calibration | Not authorized or executed |
| One-hour baseline and agent overhead, Task16 | Not executed |
| Commit, push, PR, merge, deployment, tracker update | Not authorized or executed |

Synthetic service observations prove transaction/API/query behavior, not physical host saturation. The two-worker/five-second Linux smoke proves real collection and owned cleanup, not the CPU incident threshold. Final acceptance requires the later AWS measurement gate described in the PRD and runbook.
