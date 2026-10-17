# Filesystem samples and freshness

The host agent uses `os.statvfs` for each configured absolute path, default `/`. These fields are Linux `statvfs` counters, not a `/proc` text parser. Fixture data in `tests/fixtures/statvfs.json` is explicitly synthetic and includes reserved blocks, zero capacity and malformed counters. Kernel OOM/process/network collectors are later slices.

| Sample field | Meaning and unit |
| --- | --- |
| `total_bytes` | `f_blocks * f_frsize`, bytes |
| `free_bytes` | `f_bfree * f_frsize`, including reserved blocks, bytes |
| `available_bytes` | `f_bavail * f_frsize`, available to the unprivileged workload, bytes |
| `used_bytes` | `(f_blocks - f_bfree) * f_frsize`, bytes |
| `block_usage_percent` | `100 * used / (used + available)`; accounts for reserves like `df`, percent |
| `inodes_total`, `inodes_free` | `f_files`, `f_ffree`, counts |
| `inode_usage_percent` | `100 * (total - free) / total`, percent |

Zero denominators, invalid counters, unreadable paths and collection deadlines produce null values with a source-specific error. Bad inode counters preserve valid block data; a bad path preserves healthy sibling paths when the worker can proceed. Prometheus ratio metrics divide sample percentages by 100. Prometheus families encode bytes, inode counts or ratios separately; only bounded node and configured filesystem labels are used.

Schema v1 retains its exact historical filesystem JSON and fingerprint shape. Schema v2 adds a required CPU envelope and exact CPU units; deploy the compatible collector before v2 agents. Every sample includes node ID, boot UUID, new agent-session UUID, increasing sequence and a timezone-aware observation time. A registered node's bearer token must match its node ID. Tokens are compared in constant time and never echoed in payload errors. This is a private-network lab transport, using HTTP within a restricted VPC; tokens are not protection against an attacker with access to that network or a host's credential. Interface access uses SSH tunnels, and Uvicorn ignores proxy headers.

The collector accepts an observation only at age **[-2,10] seconds**. Duplicates, superseded sequences, retired sessions and non-increasing observation times cannot replace current data. Late/future samples cannot refresh node age; the API exposes delivery errors separately. Resource gauges and API `filesystems` become unavailable at age >10s; stale status is true at age >15s. Before a first observation, age is null and stale is true. When freshness expires, the API retains sample identity and timestamps but removes filesystem values and clears available-field coverage. A collector restart reloads bounded ordering and age metadata, but restored samples are deliberately non-live: resource/delivery gauges remain absent and rule windows start empty until new eligible commits arrive.

Prometheus scrapes every five seconds. When gauges disappear, history reflects the live delivery gap; range evaluation can repeat the last scraped gauge within Prometheus's lookback, so freshness must be assessed using age/coverage, not an interpolated graph. Grafana uses ordinary missing-point display and does not substitute zero for missing resource metrics. Coverage is the available field fraction, set to zero when the sample is no longer fresh. Collection errors remain available through the API.

The CPU worker reads the first eight aggregate `/proc/stat` counters: user, nice, system, idle, iowait, irq, softirq, and steal. Guest fields are not added because Linux already includes them in user/nice. Executed busy percent is `(user+nice+system+irq+softirq delta) / total delta`; iowait and steal use the same denominator but remain separate. The first interval, counter decrease, zero delta, online-core-set change, or monotonic interval outside `(0,10]` seconds resets rates to unavailable. `/proc/loadavg` 1/5/15 values are context and are not interchangeable with instantaneous `procs_running`.

Process CPU is `(utime+stime tick delta) / CLK_TCK / elapsed * 100`; 100 means one logical core, so a multithreaded process may exceed 100. Identity is PID plus `/proc/PID/stat` start-time ticks and the sample boot ID. The collector reads at most 4096 process entries, at most 4096 bytes per source, with a 0.5-second scan budget; it returns bounded top CPU/RSS rows plus up to 16 configured PIDs. Partial/permission-limited coverage is explicit. Full command lines and environments are never collected.

The agent schedules with a monotonic clock every five seconds. A missed tick skips catch-up bursts. Upload has a total two-second deadline including the response body, and response size is capped at 16KiB. Filesystem collection has a one-second budget and CPU collection has a 0.75-second budget in separate long-lived spawned children. Child startup uses readiness handshakes outside those budgets. Termination/join is bounded, and no replacement worker is launched while an unkillable worker remains alive. CPU and RSS of both children **count toward** task 16 overhead measurement; no overhead result is claimed here. Failed uploads are logged by error class only and the next current sample is sent; bounded outage queue/replay support arrives in task 03.

References: [Python statvfs](https://docs.python.org/3/library/os.html#os.statvfs), [Prometheus range-query API](https://prometheus.io/docs/prometheus/latest/querying/api/).
