# I/O bottleneck runbook

FleetDoctor schema 7 monitors only explicit `FLEETDOCTOR_IO_MOUNTS` entries (maximum four). Configuration is canonicalized to unique sorted mount scopes before collection and wire encoding. Empty configuration is disabled coverage, never a fabricated zero. Each mount must agree across `/proc/self/mountinfo`, `stat().st_dev`, `/sys/dev/block/<major>:<minor>`, a stable device binding (`diskseq` or dm UUID), filesystem `f_fsid`, and a full `/proc/diskstats` row. Multiple mounts on one stable device/filesystem become one resource with mutable sorted scopes. Parent/partition, device-mapper slave, and shared-backing selections are rejected to prevent double counting.

The durable fingerprint contains major:minor, canonical sysfs path, stable device binding, and filesystem binding. It excludes mount namespace, mount ID, and mount membership. Collection brackets the diskstats/monotonic sample with namespace, mount inventory, device binding, and filesystem binding snapshots. Any start/end mismatch makes that resource unavailable for the interval and resets its baseline; it cannot produce a rate, trigger, recovery, or supersession decision. A service restart likewise preserves incident identity but needs a new baseline. A complete stable replacement at an old scope terminates the old incident as `superseded`, never healthy `resolved`; missing or ambiguous mappings cannot supersede anything.

## Kernel arithmetic

Diskstats sectors are fixed 512-byte accounting units. For one valid monotonic interval:

- read/write bytes per second = sector delta × 512 / elapsed seconds;
- completions per second = read-plus-write completion delta / elapsed seconds;
- completion latency = read-plus-write time delta / completion delta, and is null with zero completions;
- average outstanding = weighted-I/O-millisecond delta / interval milliseconds.

`inflight` is an endpoint gauge. Counter decrease/wrap, attachment change, worker/session restart, elapsed time outside `(0,10]`, missing counters, or partial input resets the baseline. Confirmed idle is stricter than null latency: all completion, sector, timing, I/O-time, and weighted-time deltas are zero; inflight is zero at both endpoints; and supported discard/flush groups are present and unchanged. Legacy rows without optional groups cannot assert confirmed idle.

PSI is host/cgroup context, not device latency. The host plus all eight registered canonical cgroup paths are represented explicitly; no configured path is silently truncated. PSI totals are strict unsigned 64-bit microseconds, while averages are finite percentages. `/proc/PID/io` physical `read_bytes`/`write_bytes` remain distinct from logical `rchar`/`wchar`. Raw `cancelled_write_bytes` is an unsigned 64-bit kernel counter; negative raw text is rejected. The separately named signed `net_write_balance_bytes` is `write_bytes - cancelled_write_bytes`, can be negative when cancellation exceeds writes, and is contextual only—not physical throughput or device attribution. PID+starttime is bracketed, and no process is claimed as the cause of device contention.

The 64 KiB delivery envelope preserves every selected device, mapping, trigger/recovery fact, DNS selected baseline, and watched FD identity. If the combined maximum would exceed it, optional I/O process and PSI records are removed only with `process_coverage=compacted`, `pressure_coverage=compacted`, `context_trimmed=true`, and a `payload_budget` error; the registered pressure-scope inventory remains present.

## Lifecycle and safe operations

Three fresh intervals with latency at least 20 ms **and** average outstanding at least 1 open a warning. Three intervals with latency below 10 ms **and** average outstanding below 0.5, or three strictly confirmed-idle intervals, resolve it. Equality opens but does not recover. Active incidents retain opening configuration/evidence; runtime config changes reset only unopened windows.

Read-only investigation commands include `findmnt --json --mountpoint PATH -o SOURCE,TARGET,FSTYPE,MAJ:MIN`, `cat /proc/diskstats`, `readlink -f /sys/dev/block/MAJOR:MINOR`, `cat /proc/pressure/io`, and `cat /proc/PID/io`.

The native gate uses `deploy/io_resource.py` on a unique loop image and dm-delay UUID/name. It preallocates four fixed 16 MiB files on a 384 MiB ext4 filesystem, starts an independent watchdog before publishing its lease, and verifies inode/PID/starttime/loop/dm/mount identities on cleanup. The ordinary one-shot `start` CLI binds authority to its live root caller rather than the short-lived CLI child; the watchdog stops the workload when that caller exits or the deadline expires. Root-owned ancestors must not be group/world writable. Stop workload first, keep the mapping mounted for recovery, and destroy only afterward. Never alter a shared/root device or unload the shared dm-delay module.

Local proof does not establish AWS behavior, five comparable trials, a healthy hour, production overhead, deployment, or owner acceptance.
