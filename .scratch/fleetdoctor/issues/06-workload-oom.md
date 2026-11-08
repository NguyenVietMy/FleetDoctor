# 06: Workload OOM

**What to build:** A real OOM kill in a configured workload cgroup opens an immediate incident while monitoring stays operational, followed by observable recovery.

**Blocked by:** 02: Disk-full diagnosis

**Status:** merged in [PR #5](https://github.com/NguyenVietMy/FleetDoctor/pull/5); implementation delivered. Remaining validation is recorded below.

- [x] Collect host memory/swap, workload usage/limits/local OOM counters, bounded RSS evidence, and incremental kernel logs. Expose permission limits and initialize event baselines.
- [x] Use new scoped event evidence for immediate diagnosis; retain victim details only when supported. Recover using fresh usage and no-new-event observations rather than the cumulative counter becoming zero.
- [x] Keep the leaking process within bounded memory/swap, separate from the agent; retain the cgroup through recovery and restore the test resource on interruption.
- [x] Demonstrate the real scoped OOM and resolved incident; add event/reset/missing-log/recovery tests, graphs, and the workload-OOM runbook.

**Verified scope:** Fixture/service checks plus native Linux bounded kernel OOM, persisted API diagnosis/recovery and helper lifecycle CI; this is not an AWS measurement batch.

**Evidence:** [Task06 handoff record](../../../docs/task06-evidence.md), [current delivery and CI status](../../../docs/delivery-status.md).
