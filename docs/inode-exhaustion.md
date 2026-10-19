# Inode exhaustion

FleetDoctor opens `inode_exhaustion` for each node/filesystem after three fresh eligible observations at inode usage >=95%, positive workload-available bytes, and block usage below the effective guard. The guard is `min(FLEETDOCTOR_INODE_RULE.block_guard_percent, FLEETDOCTOR_DISK_RULE.trigger_percent)`; an inode guard can be stricter, never looser, than disk diagnosis. Three fresh inode readings below 90% resolve the incident even when unrelated block counters are unavailable. Active incidents retain their effective opening configuration.

`FLEETDOCTOR_INODE_RULE` accepts JSON fields `trigger_percent`, `recovery_percent`, `block_guard_percent`, `consecutive_samples`, `max_gap_seconds` (at most 10), and `severity`. `/configuration` exposes the effective `inode_rule`, `inode_rule_requested_block_guard_percent`, and `effective_inode_block_guard_percent`. Missing/zero inode capacity, missing opening block data, zero workload-available bytes, gaps, boot/session changes, stale/replayed observations, and simultaneous block exhaustion cannot open the rule.

Evidence includes node/mount, boot/session/sequence/time, inode total/free/use, block total/available/use, source errors and the effective guard. Statvfs does not identify a causal directory. Use bounded `find`, file-count summaries, `df -i`, `df -B1`, and `findmnt` only after verifying the mount; never report the injector directory as a proven production cause.

## Bounded helper

The helper reuses the protected 384MiB ext4 loop resource at `/var/lib/fleetdoctor/chaos/disk`. Only a newly created image is formatted with an explicit small budget (`mkfs.ext4 -N 256`); ext4 may round the actual total, and the helper validates that measured total is at most 4096. A retained image is never reformatted. Replacing an old large-budget image is a separate destructive lab action and is not authorized by this runbook.

`deploy/inode_resource.py` accepts only `probe`, `start`, `status`, and `cleanup` plus internal worker/watchdog modes, fixed paths, a 32-hex token and duration 2..240 seconds. Start requires a healthy baseline, exact owned mount/device/backing identity, no disk lease, and creates one root-only token directory with at most 4096 empty regular files. Disk and inode starts share `control.lock` and mutually exclude their leases. The file ledger records write-ahead pending names and markers; each file is marked while still an unnamed inode and then atomically linked into the owned directory before device/inode identity is recorded. A kill before marking leaves no visible name, while any visible pending file must have the persisted marker. Watchdog cleanup therefore handles interruption at every creation boundary, but still refuses unknown names, unmarked or replaced pending names, symlinks, links, nonempty/replaced files, changed ownership/mode/device/inode, mapping changes or ambiguous process identity. Worker/watchdog ownership includes boot, PID/start time, mode, token and the exact inode helper path.

Cleanup removes only the validated manifest files, token directory and matching lease. It is idempotent and leaves the ext4 mount present for the three recovery observations. Do not manually delete helper metadata or files. If status races automatic teardown, retry the read boundedly; production authority is not relaxed.

## Local proof

```text
uv run pytest
uv run python scripts/integration.py --output <new-external-directory>/task07-services.json
uv run python scripts/inode_helper_integration.py --output <new-external-directory>/task07-inode-native.json
uv run python scripts/disk_helper_integration.py --output <new-external-directory>/task07-disk-regression.json
```

The service proof uses synthetic observations but real isolated PostgreSQL, Prometheus and Grafana. The inode native proof uses an owned Docker network, real PostgreSQL, a privileged container, private tmpfs-backed ext4, production statvfs collection and API/rule/store code. It persists and reloads one typed incident, removes owned files, observes three fresh recovery samples, and verifies scoped container/network/anonymous-volume/image cleanup. It also kills a worker during partial creation and waits for the independent watchdog. Neither proof is AWS calibration or rendered-dashboard approval.

For an authorized retained-lab measurement, first run the existing fresh healthy preflight, then:

```text
uv run python scripts/chaos_inode.py --profile fleetdoctor --inventory <instances.json> --key <key> --preflight <fresh-healthy.json> --target node-a --output <new-external-directory>/inode-run.json
```

The harness uses a shared per-target filesystem lease, a single monotonic clock, UTC correlation, actual telemetry threshold time, fresh target/reference coverage, incident identity/detail, source/config/environment manifests, bounded deadlines, cleanup attempts and fresh resolution. For an interrupted run, pass its retained report through `--cleanup-report` and a new output path. Five AWS runs, calibrated medians, healthy-hour/overhead, rendered visual review, deployment and publication remain later gates.
