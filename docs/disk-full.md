# Disk block exhaustion

Task02 implements the disk rule, with local checks and two AWS functional lifecycles recorded on 2026-10-11. The [evidence page](task02-evidence.md) links the frozen independent inspection verdict and remaining gates. This runbook operates the existing three-instance lab; it does not create infrastructure.

The symptom is declining space available to workloads. `statvfs` reports total/free/available/used bytes and usage `used/(used+available)*100`. Defaults are three consecutive eligible observations at usage >=95% to open, three below 90% to resolve, critical severity. `FLEETDOCTOR_DISK_RULE` accepts validated JSON for `trigger_percent`, `recovery_percent`, `consecutive_samples`, `max_gap_seconds` (at most 10), and `severity` (`info`, `warning`, `critical`). `/configuration` exposes the effective values. New configuration resets opening windows; active incidents retain their frozen configuration and severity for recovery. The measured batch must keep configuration fixed.

Observation age must be in[-2,10] seconds. Increasing observation times, source boot/session and gaps matter; identity changes, gaps over the frozen limit, missing block evidence and hysteresis values reset the affected consecutive windows. Duplicate/superseded/late observations cannot advance them. Each node/mount has independent state. Evidence preserves the opening observation, latest observation, identity, counter coverage, timestamps and manual investigation steps. No writer PID or file path is inferred from `statvfs`.

Use `df -B1 -- /var/lib/fleetdoctor/chaos/disk`, `df -i`, `findmnt`, known-workload `du`, and `lsof +L1` for investigation. Verify device identity before deleting expendable data or expanding capacity. In this scenario remove only the helper-owned filler through its cleanup command. Three new healthy observations resolve the incident automatically; recurrence receives a new UUID.

## Retained lab deployment

Use the exact IDs in `C:/Users/VietM/.fleetdoctor/task01-20261011-010631/instances.json`, AWS profile `fleetdoctor`, and the verified SSH key. All existing secrets remain private. Upgrade the retained env once, before deployment:

```text
uv run python scripts/upgrade_env.py <retained-lab.env> --disk
uv run python scripts/lab.py start --profile fleetdoctor --inventory C:/Users/VietM/.fleetdoctor/task01-20261011-010631/instances.json
uv run python scripts/deploy_lab.py --profile fleetdoctor --inventory C:/Users/VietM/.fleetdoctor/task01-20261011-010631/instances.json --env <retained-lab.env> --key C:/Users/VietM/.ssh/fleetdoctor
```

The upgrade preserves every existing secret/setting, adds a private random Grafana reader password and the two filesystem paths if absent, writes atomically with private permissions, and is idempotent. If a filesystem setting already exists it is preserved; explicitly configure `FLEETDOCTOR_FILESYSTEMS='/,/var/lib/fleetdoctor/chaos/disk'` for this scenario. Do not regenerate the retained env. On Windows keep this file in the existing private user directory (POSIX modes alone do not establish Windows ACLs).

Deployment stages the source and prepares **both** nodes' resources before activating the new configuration. Collector and agents receive identical paths. The installer verifies the wheel, installs the agent without collector extras, and EXIT-traps staged credentials even on failure. `healthy_demo` compares installed module hashes/service process identity, verifies both paths' fresh coverage, requires no active incidents, checks datasource queries and consecutive 5s delivery, and anchors journal windows to observed sample timestamps.

PostgreSQL schema and reader role setup run idempotently during every collector startup, including retained pre-Task04 volumes. Grafana uses a distinct SELECT-only incidents role and has no checkpoint access; disabling its read-only default still cannot bypass table ACLs. PostgreSQL has no public host port. Failed startup storage prevents the API from starting. Runtime health probes both required tables; a missing incident or checkpoint table returns 503, and `/metrics` exposes storage failure while omitting active counts. Eligible incident changes and the bounded node checkpoint commit atomically before latest/dedup/window publication. A lost COMMIT result is reconciled through one consistent checkpoint/active-incident snapshot. Same-body retained observations are duplicate even when old, opening/configuration and original resolution remain stable, and recurrence uses a new UUID.

## Prepare, measure, recover

Refresh current public addresses with `scripts/lab.py show`. Open SSH tunnels to monitor private-IP port 8000 and loopback ports 3000/9090, using refreshed addresses. Example tunnel arguments are `-L8000:<monitor-private-ip>:8000 -L3000:127.0.0.1:3000 -L9090:127.0.0.1:9090 -N ec2-user@<monitor-public-ip>`. A background Windows helper should use `Start-Process -WindowStyle Hidden`; retain its process ID and close that process after the run.

```text
uv run python scripts/healthy_demo.py --profile fleetdoctor --inventory C:/Users/VietM/.fleetdoctor/task01-20261011-010631/instances.json --env <retained-lab.env> --key C:/Users/VietM/.ssh/fleetdoctor --output <new-external-directory>/healthy-task02.json
uv run python scripts/chaos_disk.py --profile fleetdoctor --inventory C:/Users/VietM/.fleetdoctor/task01-20261011-010631/instances.json --key C:/Users/VietM/.ssh/fleetdoctor --preflight <new-external-directory>/healthy-task02.json --target node-a --output <new-external-directory>/disk-run.json
uv run python scripts/lab.py export --profile fleetdoctor --inventory C:/Users/VietM/.fleetdoctor/task01-20261011-010631/instances.json --key C:/Users/VietM/.ssh/fleetdoctor --output <new-external-export-directory>
uv run python scripts/lab.py stop --profile fleetdoctor --inventory C:/Users/VietM/.fleetdoctor/task01-20261011-010631/instances.json
```

Place the stop command in the parent's `finally` block regardless of deployment/run/export success. Successful fixtures do not establish AWS acceptance. Preserve real incident detail and actual Grafana SQL responses; visual inspection is a separate unrun gate when browser control is unavailable.

The helper allocates a 384MiB image under `/var/lib/fleetdoctor/chaos`, formats its newly owned loop device as ext4 and mounts only the fixed test path. It checks root reserve, ownership, exact device/backing-file/inode/mount ID and 256..512MiB telemetry capacity. Filling `/` or an unverified mount is impossible through its interface. Agents remain read-only. A public, root-owned read-only identity record lets collection reject a disappeared or replaced mount; it never labels underlying-root counters as the test filesystem.

Preparation is bounded and requires fresh healthy observations on both nodes, initialized target block counters, zero active target incident and fixed rule configuration. The live helper holds at least 95% workload usage (up to 97%); harness preparation rejects higher configured trigger thresholds. The writer and an independent watchdog detach from the controller. Per-target remote and local leases prevent concurrent runs. Injector maximum duration is 180s (helper permits 2..240); trigger timeout 45s, diagnosis 60s after the first telemetry threshold observation, recovery 60s after confirmed cleanup. Polls target 1s spacing; requests and any excess actual poll duration remain in the measured interval. Deadlines are checked before accepting successful responses. Interruption/lost SSH triggers bounded cleanup retries; the independent watchdog removes the owned filler even after worker SIGKILL. Failed cleanup makes the run fail.

For an interrupted run use its retained report, not a new token:

```text
uv run python scripts/chaos_disk.py --inventory C:/Users/VietM/.fleetdoctor/task01-20261011-010631/instances.json --preflight <healthy-task02.json> --target node-a --cleanup-report <disk-run.json> --output <recovery-report.json>
```

This explicitly removes only the matching owned filler, waits boundedly for fresh recovery and releases the matching local lease. The original failed status remains recorded. Pre-injection preparation failures release their lease without invoking remote cleanup and can be retried with a new report path.

## Stop/start and orphan recovery

Loop mounts disappear on reboot while the image and manifests remain. `fleetdoctor-disk-prepare.service` runs as root before the read-only agent, remounts the verified image without formatting it, and publishes its new mount identity. Agent startup requires the mount; ongoing collection checks source, major/minor and stable filesystem identity before and after `statvfs` in its own mount namespace. Root injector mount IDs remain strict; agent hardening stays enabled. Unrelated mounts/images are refused. Allocation, manifest-save, launch and remount failures roll back only resources created by that invocation; pre-existing loop mappings/images survive failures.

Abrupt reboot can leave a filler and lease. Preparation preserves them and their evidence. Explicitly recover the old run after preparation with the cleanup command above plus `--after-reboot`; the helper requires a prior boot identity and the same owned backing file/filler inode. Alternatively on the target use `sudo python3.11 /opt/fleetdoctor/current/deploy/disk_resource.py cleanup-reboot --token <32-hex-token>`, then retain fresh API recovery evidence. Do not erase leases or manually delete unknown files. Ordinary remount/prepare does not silently clean an interrupted measurement.

API reload marks active evidence stale until an eligible fresh update. PostgreSQL's `evidence_reloaded` flag gives direct Grafana SQL the same behavior, including a fast restart while observation age is under 15s. This flag never changes opening evidence or observation time. Block availability is separate from staleness and delivery freshness.

## Local proofs

```text
uv run pytest
uv run python scripts/integration.py --output <external-directory>/integration-task02.json
uv run python scripts/disk_helper_integration.py --output <external-directory>/disk-helper.json
docker build --target test -t <unique-test-image> .
docker run --rm --name <unique-test-container> <unique-test-image>
docker image rm <unique-test-image>
```

The service proof uses ordinary synthetic telemetry against real isolated PostgreSQL/Grafana. It checks opening/latest immutability, SQL failure before publication, identical-body retry, a client fault after an actual PostgreSQL COMMIT (not a network packet-drop claim), real DB stop/start, active reload before updates, missing blocks, recovery, recurrence, bounded filters/pagination, reader ACL denial and actual dashboard queries. The privileged proof creates its own disposable container/tmpfs image, reaches the threshold, kills the writer to test watchdog cleanup, remounts the retained image and tests unrelated-mount refusal. It detaches only its owned loop device. Unsupported privileged environments must be recorded as unrun/failed and proven on the lab by the parent; they are never relabeled passed.

See [measurement records](chaos-measurements.md) and [Task02 evidence status](task02-evidence.md). Five calibrated disk runs/all-scenario medians, healthy-hour/overhead, model postmortems and workload tracing remain their later tickets.
