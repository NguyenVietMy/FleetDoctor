# Task06 evidence status

Task06 implements explicit schema-v3 host/workload memory telemetry while preserving literal v1/v2 serialization and fingerprints; bounded `/proc`, cgroup-v2, RSS and incremental kernel-log collection; immediate generation-scoped workload-OOM detection and three-sample recovery; heterogeneous atomic incident/checkpoint persistence; API, fixed history, Prometheus and Grafana surfaces; and bounded delegated-systemd helper, native smoke and measured-harness entry points.

Evidence remains separated by role and environment:

- Builder fixture/static checks establish parser, schema, rule, reset, recovery, generation, persistence-rollback, helper-safety and compatibility behavior.
- The isolated Docker proof uses PostgreSQL, Prometheus, Grafana and synthetic v3 observations; it is not native kernel OOM evidence.
- `scripts/oom_smoke.py` is the local native gate: a real bounded kernel kill observed by production `MemoryCollector`, persisted in PostgreSQL through the API, and resolved before release.
- `scripts/oom_helper_integration.py` is the native lifecycle gate for controller-independent expiry, interruption, repeated stop/release, source/boot/headroom binding, and trusted state/gate/cgroup cleanup.
- Corrective-round helper evidence additionally covers interruption before launch, supervisor early exit, readiness timeout, retained cleanup failure followed by identity-checked retry, exact allocator placement before gate opening, non-root UID resolution, and cleared supplementary groups. The prepare controller installs catchable SIGINT/SIGTERM handlers before creating owned state, finishes identity-safe cleanup before restoring the prior handlers, and the native proof sends a real SIGTERM while preparation is paused in a bounded prelaunch state.
- Journal evidence accepts at most 64 records per interval by requesting an observable 65th sentinel. Overflow discards attribution, reports `cursor_lost`, and forces a new no-replay baseline. Retained messages are bounded by UTF-8 encoded bytes to 512 bytes each and 8KiB total.
- Prometheus publishes binary coverage for every configured cgroup every scrape. Missing, permission-denied, partial unusable, and stale workload sources emit coverage zero without misleading usage, limit, or event gauges.
- Independent source inspection, rendered dashboard inspection, remote CI, AWS/SSH/deployment, five measured AWS runs, healthy-hour/overhead calibration, publication and owner acceptance remain separate gates unless an external result records them.

Stale active incidents for removed generations are intentional: FleetDoctor will not invent recovery from a replacement or missing resource. Operators must investigate and retain that historical failure; Task06 adds no manual state-changing API or SQL lifecycle state.

The diagnosis filter retains inherited compatibility for unknown parameterized rule strings: they return an empty HTTP 200 page. `workload_oom` is a supported positive filter and is covered directly. This narrow exception preserves the pre-Task06 Disk/CPU contract asserted by `tests/test_disk.py`; it does not change fixed per-rule counts or incident detail support.
