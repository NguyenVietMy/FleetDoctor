# File-descriptor pressure

FleetDoctor opens `fd_pressure` for an exact boot/PID/start-time process identity after three fresh observations at or above 90% of that process's current finite positive soft `RLIMIT_NOFILE`. Three fresh observations below 80% resolve it as `descriptor_release`. Three fresh direct checks that the exact identity exited or was replaced resolve it as `confirmed_exit`; three eligible observations from one new boot resolve an old-boot incident as `boot_replaced`. Equality triggers at 90% and does not recover at 80%.

The configured JSON rule is `FLEETDOCTOR_FD_RULE`. It accepts `trigger_percent`, `recovery_percent`, `consecutive_samples`, `max_gap_seconds` (at most 10), and `severity`. The opening configuration is frozen for that incident. A later valid limit change is still current measurement evidence and the ratio denominator; FleetDoctor never substitutes injector configuration, the agent's own limit, or a host maximum.

Each five-second schema-v4 sample contains at most 68 compact FD observations: up to 16 configured PIDs, the bounded top CPU/RSS identity union, and up to 32 durable active watches. Configured identities have priority. The agent directly brackets `/proc/PID/stat`, reads `/proc/PID/limits`, and counts numeric `/proc/PID/fd` entries without reading link targets. Races, permission failures, unlimited/zero/malformed limits, partial inventories, and missing top-list membership remain explicit unavailable or unknown states. Only a direct exact-identity probe or genuinely complete readable inventory may establish exit.

Growth evidence carries the signed integer descriptor-count delta, agent monotonic interval, and derived descriptors/second together. First observations, identity/session resets, negative or zero elapsed time, count failures, and gaps over ten seconds leave all three unavailable. Positive growth supports suspected leakage but does not prove a cause; sustained pressure can open without growth. Negative growth records descriptor release. CPU/RSS context is independent and may be unavailable while FD evidence remains valid. A watched exact identity in Linux zombie state is terminated evidence (`exited`) with an explicit `process_zombie_terminated` marker; an unbound missing/top-list process remains unknown.

The FD block is limited to 24 KiB. The agent preserves watched exit/unknown state, compacts optional context, and falls back to an explicitly unavailable bounded FD block rather than dropping an otherwise valid sample when the combined 64 KiB request budget would be exceeded. Watch retrieval is node-authenticated, at most 16 KiB/32 identities, and has an outer one-second elapsed deadline in addition to transport timeouts. A failed refresh retains the last valid cache; a valid empty response clears it.

## Safe helper

`deploy/fd_resource.py` is a root controller for one disposable, unprivileged worker. Installation places it at the root-owned executable path `/usr/local/sbin/fleetdoctor-fd-resource`; checkout overrides are invoked through the current Python interpreter and never rely on the Git executable bit. It accepts a lowercase hexadecimal token, limit 32..1024, and lifetime 20..180 seconds. `start` prepares the worker below recovery pressure; `pressure` requests staged 65%, 80%, then 95% growth; `status` reports actual `/proc` count/limit; `release` closes only the worker's descriptors below recovery; and `cleanup` stops the owned watchdog and worker. The worker opens only `/dev/null` descriptors and changes only its own finite soft/hard limit.

The helper uses one root-owned mode-0600 authority file beneath a root-owned mode-0700 directory. A file lock serializes all tokens node-wide. The file is opened no-follow and its device/inode is revalidated before effects and updates; cleanup keeps a terminal record and refuses a replaced authority object. Process authority binds current boot ID, PID, `/proc` start-time ticks, and actual UID. The worker UID must be nonzero. Signals use pidfds only; there is no check-then-`kill(2)` fallback. Controller handlers are installed before effects, signals are blocked across spawn-to-pidfd acquisition, each boundary is recorded, failures roll back exact pidfds, and an independent watchdog plus the worker's own lifetime bound orphan duration.

Do not edit `/run/fleetdoctor-fd/active.json`, signal by PID/name, or manually delete helper state. An authority, boot, identity, UID, or ownership mismatch is a fail-closed condition. Preserve the failed record and use a new report path while investigating.

### Prepared configured-identity workflow

The reusable CLI deliberately separates preparation from pressure so the same low-count identity can enter the agent through the ordinary `FLEETDOCTOR_CPU_PIDS` configuration. Use a fresh 16-or-more-character lowercase hexadecimal token and a 180-second lifetime. The preparation report contains the exact `worker_pid`, start-time ticks, boot ID, UID, measured count, and actual limit:

```text
uv run python scripts/chaos_fd.py --prepare-only --prepared-token <fresh-hex-token> --limit 128 --seconds 180 --output <new-private-path>/fd-prepared.json
```

Before the lifetime has fewer than 90 seconds remaining, add that reported PID to the target agent's existing bounded `FLEETDOCTOR_CPU_PIDS` value (never more than 16 unique PIDs), restart only that agent, and wait for a fresh low observation with the same boot/PID/start-time identity. Do not replace existing configured PIDs inadvertently. Then run the lifecycle with the same token; the adapter refuses a different, non-prepared, wrong-limit, or nearly expired worker instead of starting another identity:

```text
uv run python scripts/chaos_fd.py --prepared-token <same-hex-token> --base-url <collector-url> --api-token <private-node-token> --node <target-node> --reference-node <healthy-reference-node> --mode release --limit 128 --output <new-private-path>/fd-release.json
```

For an exit case use a fresh token/preparation and `--mode exit`. The harness always attempts ownership-bound cleanup. In an outer `finally`, restore the original `FLEETDOCTOR_CPU_PIDS`, restart only the target agent, confirm healthy fresh telemetry, and if the harness never took control run `sudo /usr/local/sbin/fleetdoctor-fd-resource cleanup --token <same-hex-token>`. Do not reuse a token or output path. A checkout-only helper override is explicit: `--helper deploy/fd_resource.py`; the adapter invokes it with Python under sudo rather than assuming it is executable.

## Investigation

Start from `/diagnoses/{id}` and confirm the exact boot/PID/start-time resource, evidence freshness, current count/actual soft limit, signed count delta/rate/interval, configured/watched flags, and source errors. Then use bounded commands such as `ls /proc/<pid>/fd | wc -l`, `grep 'Max open files' /proc/<pid>/limits`, and service-specific connection/file summaries after independently rechecking identity and permissions. Never treat a process name, one PID read, the highest node ratio, or positive growth as proof of a leak cause.

The Node dashboard shows node-level pressure/coverage and a vertical latest-incident detail panel. Prometheus intentionally uses bounded node/rule labels only; arbitrary PIDs, commands, start times, and paths remain API/SQL evidence.

## Local proof

```text
uv run pytest
uv run python scripts/integration.py --output <new-external-directory>/task08-services.json
uv run python scripts/fd_helper_integration.py --output <new-external-directory>/task08-fd-native.json
```

The service proof uses synthetic schema-v4 values with real isolated PostgreSQL, Prometheus, Grafana queries, restart, watches, history, and lifecycle persistence. The native proof uses actual Linux `/proc`, the production agent, helper, harness, collector, and PostgreSQL. Its reference agent runs in a distinct Docker PID namespace on the same host kernel/network; this is not evidence from separate AWS nodes. The main lifecycle leaves production CPU/RSS selection unmodified. Controlled fixtures separately prove configured inclusion outside both top sets. Neither proof is AWS calibration, rendered-dashboard approval, remote CI, or owner acceptance.
