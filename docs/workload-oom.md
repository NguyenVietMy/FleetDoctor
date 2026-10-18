# Workload OOM runbook

## What the diagnosis means

`workload_oom` opens on a positive delta in the exact configured cgroup's `memory.events.local:oom_kill` counter. This proves that a process in that cgroup generation was killed by an OOM killer. It does not, alone, prove that `memory.max` caused the kill or identify a victim. Bounded current-boot kernel logs and PID/start-time/RSS rows add context only when their scope and timing support it. A log is scoped only by an explicit `oom_memcg=` or `memcg=` field exactly equal to the configured path; substring, ancestor, descendant and bare-victim messages remain unscoped.

The display path and generation-qualified persistence key are separate. If a cgroup disappears or is replaced, the old incident stays active and stale for investigation. A replacement generation establishes its own baseline and can open a new incident without being blocked by the old row.

## Configuration and collector-first rollout

Deploy the v3-capable collector before the agent. Configure at most four canonical absolute non-root cgroup paths:

```text
FLEETDOCTOR_CGROUPS=/system.slice/fleetdoctor-oom-TOKEN.service/workload
FLEETDOCTOR_OOM_RULE={"recovery_percent":80,"consecutive_samples":3,"max_gap_seconds":10,"severity":"critical"}
```

The default empty list still collects host memory. Missing configured leaves are reported in `memory.workload_errors` rather than zero-filled or silently omitted. Do not grant the agent write access to cgroups. Optional membership in a journal-reading group has broader host-log visibility and is not installed automatically; missing journal permission is reported, forces a fresh no-replay journal baseline if access later returns, and does not suppress valid local-counter detection.

## Bounded local/native proof

The all-in-one smoke requires root Linux with systemd, cgroup v2 memory/pids controllers, Docker, at least 512MiB available memory, and an existing unprivileged account such as `nobody`. It creates a unique delegated transient unit and a unique PostgreSQL container, constrains the workload leaf to 48MiB memory, zero swap, and four tasks, touches 96MiB, requires a real local `oom_kill` increment, persists and resolves the incident through the API, then releases the unit and container.

```text
sudo $(command -v uv) run python scripts/oom_smoke.py \
  --worker-user nobody \
  --output /tmp/task06-oom-smoke-UNIQUE.json
```

The output must not already exist. Ordinary `MemoryError`, a controller SIGKILL, timeout, or an unrelated cgroup event is failure, not OOM proof.

## Measured harness lifecycle

Prepare first so the empty leaf can be added to `FLEETDOCTOR_CGROUPS` and observed by the agent before injection:

```text
TOKEN=$(openssl rand -hex 16)
sudo /usr/local/sbin/fleetdoctor-memory-resource prepare --token "$TOKEN"
# Record leaf_path and generation from JSON, add the exact leaf_path to the agent env,
# restart the agent, and wait for fresh initialized local counters.
```

Then run the harness with the same token/path. It verifies the empty prepared generation, fresh target/reference, baseline and absence of an active matching incident before allocation. It stops allocation while retaining the leaf, waits up to 60 seconds for three fresh recovery observations, then releases it.

```text
uv run python scripts/chaos_oom.py \
  --base-url http://MONITOR:8000 --api-token TOKEN \
  --node node-a --reference-node node-b \
  --token HELPER_TOKEN --cgroup EXACT_PREPARED_PATH \
  --output /tmp/task06-oom-run-UNIQUE.json
```

The supervisor lease is at most 360 seconds. The child lifetime is at most 180 seconds. Start refuses insufficient reserve for child, stop, recovery, and release. `OOMPolicy=continue`, `Delegate=yes`, a supervisor subgroup, `KillMode=control-group`, `RuntimeMaxSec`, `MemoryMax=256M`, and `TasksMax=16` keep monitoring outside the leaf and make controller disappearance bounded. Repeated `stop`/`release` applies only to the recorded token, unit invocation, cgroup path, and generation; replacement identity is refused.

## Manual diagnosis

```text
cat /sys/fs/cgroup/EXACT/memory.current
cat /sys/fs/cgroup/EXACT/memory.max
cat /sys/fs/cgroup/EXACT/memory.swap.current
cat /sys/fs/cgroup/EXACT/memory.swap.max
cat /sys/fs/cgroup/EXACT/memory.events.local
systemctl show UNIT -p Delegate -p OOMPolicy -p KillMode -p RuntimeMaxUSec -p ControlGroup
journalctl --dmesg --boot --since '-5 minutes' --no-pager
```

Do not remove the leaf until the incident resolves. Recovery requires a finite positive limit, usage below 80%, stable bracketed counters, zero new local `oom` and `oom_kill` deltas, and three newly accepted observations. Missing/unlimited/reset/replaced/removed telemetry cannot resolve the incident.
