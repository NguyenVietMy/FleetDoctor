# CPU saturation runbook

FleetDoctor opens `cpu_saturation` for resource `cpu` after three fresh eligible observations where executed host busy CPU is at least 90% **and** instantaneous runnable processes exceed online logical cores. It resolves only after three fresh observations below 80% busy. Load averages, iowait, and steal are supporting context, not alternate triggers.

## Investigate

Confirm all values refer to the same host and interval:

```text
grep -E '^(cpu |cpu[0-9]+ |procs_running )' /proc/stat
cat /proc/loadavg
nproc --all
top -H -b -n 1
ps -e -o pid,lstart,psr,pcpu,rss,comm --sort=-pcpu | head -20
pidstat -u -p ALL 1 5
systemctl show fleetdoctor-agent -p CPUUsageNSec -p MemoryCurrent -p TasksCurrent
```

Busy excludes idle, iowait, and steal. High load without runnable demand can reflect uninterruptible I/O rather than CPU saturation. Check CPU affinity, cgroup quotas/throttling, steal, instance type, credit mode/balance, and evidence coverage before naming a cause. A listed process is an observed contributor only; PID plus start-time ticks prevent reuse from merging identities.

## Bounded local smoke

On a native Linux checkout (or a native Linux copy inside WSL), run:

```text
uv sync --locked --all-extras
uv run python scripts/cpu_smoke.py --workers 2 --seconds 5 --output /tmp/fleetdoctor-task05-cpu-smoke-UNIQUE.json
```

This exercises actual `/proc` deltas and an owned process group with at most two workers for at most five seconds. It intentionally does not seek 90% host utilization and is not saturation acceptance. The output path must not already exist.

## Saturation harness

The host-mode harness requires exactly `min(64, 2 * online logical cores)` workers and rejects other scope claims. It uses a unique token-derived transient systemd unit. The unit runs as the unprivileged `fleetdoctor` user, nice 10, with `RuntimeMaxSec`, `KillMode=control-group`, `TasksMax`, `MemoryMax`, `NoNewPrivileges`, and a read-only system. The root controller records and revalidates the systemd invocation ID and cgroup before status/stop; it never kills by process name or an unverified PID.

Run only in an authorized disposable lab after a fresh source/config/environment capture:

```text
uv run python scripts/chaos_cpu.py --base-url http://MONITOR:8000 --api-token TOKEN --node node-a --reference-node node-b --workers WORKERS --seconds 60 --timeout 180 --output /tmp/task05-cpu-UNIQUE.json
```

Keep 30 seconds reserved for cleanup. Repeating helper cleanup for the same token is harmless. If the controller is interrupted, run `sudo deploy/cpu_resource.py cleanup --token TOKEN` from the same trusted source tree. A copied helper on native Linux is required for systemd lifecycle proof; a Windows path cannot execute under Linux systemd. The deployment default is the unprivileged `fleetdoctor` account; an isolated proof host without that deployed account may explicitly select another existing unprivileged account with `start --worker-user nobody` and must record the deviation.

## Recovery and limits

Remove only the token-owned transient unit, then verify three unique fresh observations and the same incident ID moving to `resolved`. Confirm the reference node remained free of CPU incidents. Retain failures, cleanup results, kernel/version, logical cores, cgroup/affinity scope, cloud CPU credit mode, configuration, source hashes, and incident-linked timestamps.

Local fixtures and the limited smoke do not prove AWS saturation. The later authorized AWS gate must retain five measured runs, correct node/resource diagnosis, cleanup/recovery every run, and the PRD latency/environment record. Task15 calibration and Task16 one-hour healthy/overhead measurements remain separate.
