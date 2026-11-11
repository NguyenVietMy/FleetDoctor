# DistributedKVStore investigation

Ticket13 follows a successful DistributedKVStore read/write workload through syscall and packet captures with corresponding FleetDoctor observations. The native AWS exercise on 2026-11-11 UTC completed 16 PUT/GET pairs using the inspected fix3 controller. Its ordinary deployed-agent, collector, reference-node, history and restoration evidence is recorded below. Historical local-build2/3/4 results remain retained with their original scope.

## Frozen source and supported topology

The selected source is local revision `a22cf751799cf0f44a6bfe7a168c78a0ea6e52fb`, exported as
`dkv-source-a22cf751.tar` with SHA-256
`2a024a69840f1ece82b92be448c9431113ca663c1126b89bd5a9a7e04fb5fd36`.
That revision is twelve local commits ahead of its recorded upstream reference; this document does
not call it remote `main`. The original checkout is read-only. Build an extracted copy with:

```text
cmake -S SOURCE -B BUILD -DBUILD_TESTING=OFF
cmake --build BUILD --target dkv_node dkv_client -j2
```

The supported topology is three static processes on one Linux host, bound to `127.0.0.1` at three
ordered ports (normally 9101, 9102 and 9103). It is not one peer per VM and does not demonstrate
cross-host network tolerance. The nodes share CPU, page cache, filesystem and loopback. The AWS exercise placed all three on node-a, with node-b as the healthy FleetDoctor reference and
the monitor retaining the collector, Prometheus and Grafana.

## Bounded controller

`scripts/kv_trace.py --help` is safe on every supported development host. Actual execution is
Linux-only and requires a root controller so it can own tcpdump, attach strace and enforce cleanup.
The exact KV nodes, clients and production direct sampler run as one named non-root user. The
controller refuses an existing output path, invalid or occupied ports, missing binaries/tools,
nonmatching source hash, a root workload user, stale release gates and post-launch listeners that do
not belong to the recorded node PID/start-time identities. It records listener ownership at startup,
again immediately after any gate and before the first workload client, and before tracing.

The hardened controller additionally requires the complete output-parent chain, controller script,
invoked virtual-environment Python path and target, import directories, tools, KV binaries and source
archive to be root-owned with no group/world write. The output must therefore be under a protected
root-owned base such as `/var/lib/fleetdoctor-kv-trace/<task-id>`, never below the run user's writable
home. The run user receives only the read/execute or owned data paths it needs. Root creates sampler
configuration exclusively in protected `control/`; reads of run-user readiness and samples are
no-follow, nonblocking, regular-file/owner checked and bounded. Unsafe ancestors, symlinks, FIFOs,
wrong owners and oversized control inputs fail visibly.

Successful workload/capture validation moves the manifest only to nonterminal `finalizing`. Cleanup,
bounded sample reading, strict nested sample schema validation, intended-identity/phase assessment,
artifact bounds and port release must all complete before terminal `passed` is saved. Malformed JSON,
wrong containers, booleans or non-finite consumed numbers fail without copying input content into the
diagnostic. A schema-valid unavailable I/O observation may retain `starttime: null`; it never counts
as identity or nonbaseline coverage. Finalization exceptions and deterministic interruptions attempt
a terminal failed save, and signal handlers are restored by the outer controller boundary.

The output directory is new and retained. It contains:

| Path | Meaning |
| --- | --- |
| `manifest.json` | Terminal status, hashes, commands, identities, listener checks, cleanup and validation |
| `readiness.json` | PID/start-time/listener/data-mount scope for an optional external release gate |
| `data/node-*` | Three owned persistent Raft directories; never recursively removed by the controller |
| `logs/` | Node, sampler, watchdog, strace and tcpdump diagnostics |
| `samples/direct-samples.jsonl` | Five-second typed results from production `CollectionSupervisor.collect_all` |
| `traces/` | `strace -ff -ttt -T -yy` node and client files |
| `captures/kv-loopback.pcap` | Port-filtered loopback capture |
| `captures/kv-loopback.txt` | Timestamped numeric tcpdump decode |
| `control/` | Root watchdog state and the bounded same-UID sampler control files |

Each phase uses fresh deterministic keys, fixed values and saved 32-hex request IDs. Success requires
client exit code zero, `committed term ... index ...` for every PUT, and the exact value for every
GET. Three-port client routing is used; STATUS records role/term/log state but is never write proof.
The default eight paced pairs span at least three five-second sampling windows in each phase. The
untraced-then-traced elapsed pair is descriptive only—not a benchmark or causal overhead estimate.

The direct sampler selects all three node PIDs for CPU/RSS/FD and process I/O, selects the canonical
mount containing the owned data, uses no cgroups or FD watches, and leaves the network target
explicitly unconfigured. Host memory is distinct from PID RSS. TCP retransmission and interface
counters are host/interface context rather than KV-port attribution; the unconfigured probe does not
measure loopback KV latency. Baseline, missing, permission and mapping states remain null/error facts;
the controller never fills them with zero. Direct local collection is not production service,
collector, Prometheus or AWS evidence.

An independent watchdog reads only protected root state. It discovers actual same-UID descendants of
the registered sampler through current PPID ancestry, caches validated descendants while the sampler
is alive (including its separate-session production supervisor), and rechecks PID/start-time/UID
before every signal. Run-user auxiliary JSON is diagnostic only and grants no signal authority.
Controller EOF or the same-host monotonic deadline requests TERM and then KILL only for those owned
identities. Spawn-through-registration blocks SIGINT/SIGTERM, children restore their inherited mask,
and direct children arm a Linux parent-death signal after any UID drop plus a parent identity check.
tcpdump also receives an independent pre-exec `ITIMER_REAL`/default-unblocked `SIGALRM` expiry, so an
idle filter cannot outlive its bound. The watchdog itself has no parent-death signal and survives to
perform cleanup. Ordinary cleanup stops and reaps attached tracers and tcpdump, stops the sampler,
writes `quit` to node consoles, then applies generic bounded TERM/KILL cleanup. It retains survivors
and verifies port release. It never uses process-name/global kill, deletes retained data, changes
firewall/qdisc/Yama/sudoers/capabilities, or touches a pre-existing listener.

## What the source supports

At the frozen KV revision, a leader appends encoded log records with `pwrite64` and calls
`fdatasync` before updating its in-memory log. Followers receive AppendEntries on localhost TCP and
persist accepted records synchronously. A successful client PUT is sent only after the leader has
applied the committed entry. A GET adds no log entry: the leader waits for its current-term readiness
and a fresh majority read barrier, then reads the applied in-memory state. Heartbeats, replication,
replies and client frames share localhost TCP, one frame per connection.

The source anchors are `src/raft_server.cpp:408-476` for write proposal,
`src/raft_leader.cpp:86-106` for AppendEntries construction/local append,
`src/persistent_log.cpp:187-222` for encoded write, sync and in-memory publication,
`src/raft_server.cpp:281-307` for replies after apply/read readiness, and
`src/raft_server.cpp:479-521` for the read barrier. The source archive hash above binds those paths.
A packet alone does not prove semantic commitment. An `fdatasync` return alone does not prove
power-loss durability. Tracing can delay the single event loop and perturb election timers.

## Observed local-build2 result

Raw artifacts remain in the external `local-build2-export` bundle, not Git. Logical IDs and hashes:

| Retained artifact | SHA-256 / result |
| --- | --- |
| `local-build2/manifest.json` | `869edef7db6366ba476e27bf69487d8676edf85b747cbdd21b163c8476b0fda1` |
| `local-build2/captures/kv-loopback.pcap` | `8b513079745b7ca1cdcf1931344e833afb9cc70417374ff05a57d6c6da620b34` |
| `local-build2/captures/kv-loopback.txt` | `4b1bff19053dc3fe1536037ec2093643217985fe90de50dcdec5121bf14c62b9`; full independent decode, 7,695 lines, exit 0 |
| `local-build2/samples/direct-samples.jsonl` | `bcf108fbba713e34e59bb0bad0edd4b45f0326efd81b4b8d2e1001357407e49d`; seven typed samples |

The run used stable non-root identities node1 `455/11995`, node2 `456/11996`, and node3
`457/11996` (PID/start-time ticks), all UID 1000; the sampler was also UID 1000. All eight pairs in
each phase passed. `manifest.json#/phases/1/pairs/0` records the first traced pair: request ID
`8d0e3086ba4fa9f44f0207b06e0be493`, PUT `committed term 2 index 10`, and GET exactly
`fleetdoctor-traced-value-00`, all with exit code zero. All four diagnostic snapshots reported node2
as leader in term 2; this is four retained observations, not proof that no election occurred between
them.

The retained local environment was WSL2 Linux `6.6.87.2-microsoft-standard-WSL2` with Python
3.14.4, strace 6.19, tcpdump 4.99.6 and libpcap 1.10.6. These are reproduction metadata for the
local exercise, not AWS or AL2023 tool versions.

### First traced PUT

The short excerpts below identify one operation without publishing the raw bundle:

1. `traces/client-traced-00-put.523:18-19` sends the request to leader port 9102; leader
   `traces/node-2.456:44-45` receives the same request ID, key and value.
2. Node2 starts the 110-byte term-2/index-10 write at offset 951 at epoch
   `1794249636.812031`, then starts the successful `fdatasync` at `1794249636.812267`
   (`traces/node-2.456:46-47`).
3. The leader sends encoded entries containing the same key/value to ports 9101 and 9103
   (`traces/node-2.456:53-57`). The corresponding 180-byte loopback payloads appear at
   `captures/kv-loopback.txt:193` and `:200`.
4. Followers persist and sync the matching record at `traces/node-1.455:36-37` and
   `traces/node-3.457:20-21`.
5. Node2 sends the client reply at `traces/node-2.456:72-73`; the client receives it and exits zero
   at `traces/client-traced-00-put.523:20-22`. The human semantic receipt is the manifest pointer
   above. Together these facts support this PUT flow; neither the packets nor any one sync alone
   establishes semantic commitment or power-loss durability.

The following GET is observed at `traces/client-traced-00-get.526:18-22`, including the exact value
in the reply. The source says the leader starts a fresh majority read barrier and then reads applied
in-memory state (`src/raft_server.cpp:298-307,479-521`). The excerpt demonstrates request/reply and
the semantic result; it is not used to claim an exhaustive absence of storage calls.

The capture contains 7,695 structurally complete records (707,450 bytes), zero kernel drops and zero
snapshot payload truncations. Nineteen strace files total 1,160,794 bytes and contain 5,545 successful
timestamped lines. tcpdump and all tracers were alive through the phase and stopped deliberately;
cleanup reported no survivors and released all three ports.

Strace epochs and manifest times are UTC around `18:40:xx`. The human tcpdump decode is WSL local
`EST-0500` around `13:40:xx`; adding five hours aligns it with UTC, while the PCAP itself retains epoch
timestamps. The untraced phase was `18:40:20.984795..18:40:36.418226Z` (15.4334 s) and the traced
phase `18:40:36.710564..18:40:52.839067Z` (16.1285 s). This single paced ordered pair is descriptive,
not a causal tracing-overhead estimate or throughput benchmark.

### Direct FleetDoctor observations

Ranges come from `samples/direct-samples.jsonl`: untraced lines 1-4 completed at
`18:40:20.990205..18:40:35.983266Z`; traced lines 5-7 completed at
`18:40:40.982399..18:40:50.982831Z`.

| Measurement | Untraced lines 1-4 | Traced lines 5-7 |
| --- | --- | --- |
| Host CPU busy | 0.238-1.002% (3 available; line 1 baseline) | 2.014-2.203% |
| Host available memory | 6,362,288,128-6,384,840,704 bytes | 6,373,695,488-6,374,567,936 bytes |
| Node2 PID 456 CPU | 0.799-1.398% (3 available; line 1 baseline) | 2.59705-2.59746% |
| Node2 RSS / FD count | 4,718,592 bytes / 5 | 4,718,592 bytes / 5-7 |
| Node2 cumulative physical writes | 24,576-61,440 bytes | 73,728-98,304 bytes |
| Node2 physical-write rate | 1,638.34-3,280.41 bytes/s (3 available; line 1 baseline) | 1,638.55-3,275.98 bytes/s |
| Shared `sdd` (`8:48`, mount `/`) read/write rate | 0-54,946.79 / 81,093.80-551,301.44 bytes/s (3 available; line 1 baseline) | 0-91,748.29 / 111,421.12-306,373.77 bytes/s |
| Shared `sdd` completion latency | 1.20-5.84 ms (3 available; line 1 baseline) | 1.375-1.88 ms |
| Host TCP retransmissions / rate | cumulative 7-9 / 0-0.4001 per second (rate baseline on line 1) | cumulative 9 / 0 per second |

The first untraced sample intentionally retains baseline-null CPU and rate fields. The first traced
sample summarizes an interval beginning before tracer attachment/phase start, so it is not exclusive
to traced requests. PID counters are identity-scoped, but host CPU/memory/TCP and shared `sdd` rates
are context, not exclusive KV attribution. Cumulative physical-write bytes are not rates. RSS is not
host memory. TCP retransmission context is not KV-specific loss. Local mode configured no cgroups,
FD watches or direct-IP target, so it supplies no fabricated loopback RTT; the retained errors include
`cpu_rate_baseline_unavailable`, `process_inventory_partial`, and
`direct_sampler_no_collector_watch`.

## Protected local-build3 operational result

The coordinator ran the frozen fix2 script
`05bb04fa7d8b0891f09008a1c00321873371cfee55c17e639c3439ee0327feeb` with test hash
`c044552301e2126e50310a9cbb1129764374e433b755674712bfdc44d1542173` from the protected root-owned
runtime. Manifest `2bee7b2ed04aacd534fd06485cb0991b418d0a66ce6920b141baaaf4f3eee0fa`
is terminal `passed`: all 16 exact PUT/GET pairs succeeded; the three stable node PID/start-time
identities and sampler ran as UID 1000; and seven typed samples supplied the startup baseline plus
three completed samples in each workload phase.

The retained capture has 7,520 structurally complete records (690,999 bytes), zero kernel drops and
zero payload truncations. The 19 strace files total 1,187,400 bytes with 5,661 successful timestamped
lines. An independent full decode returned 7,520 lines with the same decoded-output hash as the
harness, and the coordinator independently checked all 16 exact replies. Capture and tracers were
stopped deliberately; the watchdog disarmed, cleanup reported no survivors, all three node identities
were dead, and all three ports were independently bindable afterward. A postrun audit also found all
23 staged source/binary/archive files unchanged and 1,965 runtime entries root-owned and not writable
by the run user.

This is local protected-runtime evidence, not AWS or ordinary agent/collector/reference-node evidence,
and it does not replace the historical excerpts or metric ranges above. The run armed tcpdump's alarm
but deliberately stopped capture before expiry; focused fake-process tests, not this workload, cover
idle timer expiry and injected-signal interruption.

## Protected local-build4 fix3 operational result

The coordinator ran the frozen fix3 script
`cc56f6b334f9028dae087263f30cd4a5ce6f6ab068b738133bef6133ae20ff4a` with test hash
`4de4a414a35fe8acdf0e1f71d9dc82f6b7be3fa52e10da440655f6f97872ec1e` from a new protected
runtime after the trusted prelaunch audits passed both before the first venv invocation and after
source staging. Manifest `2e2ba644a12dd3e2522e70f4ce27ad545850a4233526355166b5ee19dcdcc367`
is terminal `passed`: all 16 exact PUT/GET pairs passed independent semantic checking; the three
stable node identities and sampler ran as UID 1000; and the recorded post-startup listener checks,
including `after_gate_before_untraced`, retained the same PID/start-time/inode ownership. The normal
run was ungated, so that check does not claim actual gated-service behavior.

The retained PCAP has 7,676 complete records (704,555 bytes), zero kernel drops and zero payload
truncations. The independent full decode matched all 7,676 harness-decoded lines. Nineteen strace
files total 1,198,936 bytes with 5,734 successful timestamped lines. Seven schema-validated samples
include the startup baseline and three completed samples in each phase, with all three intended
CPU/RSS/FD/nonbaseline-I/O identities. The terminal manifest contains the assessment and finished
time; capture/tracers stopped intentionally, the watchdog disarmed, cleanup reported no survivors,
and all three ports were independently bindable afterward.

Postrun checks found all 23 staged source/binary/archive files unchanged, 1,965 runtime entries
root-owned and not writable by the run user, all three exact node identities dead, and the original
KV checkout clean. This remains local protected-runtime evidence, not AWS or ordinary deployed
agent/collector/reference-node evidence. The normal workload did not expire the alarm, inject faults
or exercise a real release gate. Focused fixtures cover gate publication/ownership controls and
injected controller signal/expiry handling. This local checkpoint preceded the actual gated AWS
exercise below.

## Local attempts and capture verdict

The retained `local-build1` attempt completed all 16 PUT/GET operations, collected the intended
three PID/start-time metric identities with three samples in each phase, and cleaned up without
reported survivors. It is still a failed partial capture: tcpdump reached its 7,000-packet ceiling
before the traced phase ended. External sizing evidence reports 7,000 complete PCAP records, zero
kernel drops, a 255-byte maximum original packet and no snapshot truncation. It remains failed/partial.
Fix round1 increased bounded capacity without weakening early-exit validation. `local-build2` then
passed the workload, full decode, capture/trace validation, direct sampling and cleanup described
above for the frozen fix1 code. Inspection1 subsequently required ownership/interruption hardening.
The justified coordinator-owned protected `local-build3` retry passed on the unchanged fix2 code as
the separate operational result above. The historical `local-build2` capture and metric ranges remain
valid for their recorded hashes and remain the detailed study rather than a replaced benchmark. The
new protected `local-build4` run passed on unchanged fix3 code after builder and coordinator affected
proof. Fresh inspection3 later approved that frozen local fix3 snapshot, as recorded in the
[evidence ledger](task13-evidence.md).

Capture is usable only when tcpdump reports `listening on lo`, writes a complete PCAP header, exits
without kernel drops after an intentional stop, and remains alive with every attached strace process
through the traced workload. Reaching a packet cap or otherwise exiting early is a failed capture.
The decode must contain nonempty traffic for the configured ports, and the bounded strace set must
contain representative storage-sync and localhost TCP syscalls. Empty, truncated, unreadable,
oversize or partial artifacts remain failed/partial even if every client operation succeeded.

## Observed AWS workload on 2026-11-11 UTC

The native AL2023 run used the same frozen KV archive and fix3 controller as the local preparation.
All three peers ran as `fleetdoctor`, UID 993, on node-a. Their PID/start-time identities were
`2351/6656`, `2352/6658` and `2353/6659`. Node2 was the leader in term 1 in all four retained STATUS
snapshots. The ordinary deployed agent selected these exact identities for CPU/RSS/FD and process
I/O, with `/` as the containing data mount. Node-b remained fresh with zero active incidents at every
operator poll. The monitor retained ordinary collector ingestion and Prometheus history.

The operator deployed the inspected 19-module FleetDoctor source through the existing source-freeze
gate before saving the run-specific configuration backup. Installed-package probes matched on all
three roles. Native build metadata records Python 3.11.16, GCC 11.5.0, CMake 3.22.2, glibc 2.34,
strace 6.12, tcpdump 4.99.1 and libpcap 1.10.7. The kernel was
`6.18.51-120.163.amzn2023.x86_64`. Native binary hashes are retained in the evidence ledger.

Two distinct complete deployed-agent samples preceded atomic release of the SHA-bound readiness
gate. Each contained all three PID/start-time identities, CPU rates, RSS, present FD counts and
available nonbaseline process-I/O rates. The agent session remained stable through both phases.
Three unique ordinary samples from each host fall within each phase, in addition to the controller's
11 typed direct samples, including three direct samples per phase.

| Phase | UTC interval | Elapsed seconds | Target agent sequences | Reference sequences |
| --- | --- | --- | --- | --- |
| Untraced, eight verified pairs | 03:35:21.975335–03:35:37.425924 | 15.450570 | 4, 5, 6 | 17, 18, 19 |
| Traced, eight verified pairs | 03:35:37.656666–03:35:53.515423 | 15.858736 | 7, 8, 9 | 20, 21, 22 |

Both phases returned eight successful commit replies and eight exact GET values. The independent
semantic audit rechecked all 16 pairs, their unique keys/request IDs, exit codes and reply contents.
The first traced PUT used request ID `1cc36635649d1b8b33191a4ca1b73a0d`, returned
`committed term 1 index 10`, and its GET returned `fleetdoctor-traced-value-00`.

The retained bundle contains 19 strace files with 5,510 successful timestamped syscall lines and
1,141,476 trace bytes. The PCAP contains 7,590 complete records and 697,463 bytes, with zero reported
kernel drops and zero payload truncations. A separate full tcpdump decode produced 7,590 lines
identical byte for byte to the retained native decode. All four tracer/capture stops deliberately
received SIGINT, required no escalation, and stayed below the 30,000-packet limit.

### One traced write and read

The following anchors are relative to the private `aws-live1-export` bundle. Syscall timestamps are
Unix epoch seconds. The numeric packet decode uses UTC.

1. `traces/client-traced-00-put.2648:11-14` sends the request to port 9101 and receives the initial
   reply. The client follows the leader route to 9102. `traces/node-2.2352:27` receives the matching key
   and value at `1794368137.755136`. `captures/kv-loopback.txt:141-144` records the corresponding
   four-byte frame header and 87-byte payload on the `39268 -> 9102` connection.
2. `traces/node-2.2352:28` writes 110 bytes to `node-2/raft.log` at offset 951 at
   `1794368137.755250`. Line 29 records `fdatasync` returning zero after 0.002212 seconds.
   Lines 36 and 39 send the replicated record to ports 9101 and 9103.
3. `traces/node-1.2351:26-27` and `traces/node-3.2353:20-21` show the corresponding follower writes
   and successful sync calls. Leader lines 54-55 send the client reply at
   `1794368137.771936`/`1794368137.772026`. The client exit/result and exact commit text remain the
   semantic success evidence.
4. `traces/client-traced-00-get.2652:18-21` sends the GET to 9102 and receives the frame containing
   `fleetdoctor-traced-value-00` at `1794368137.888369`. This read follows the source's majority-barrier
   path described above. Packet direction and syscall ordering provide supporting context for that
   source interpretation.

### Ordinary deployed measurements

These ranges use the three distinct ordinary samples in each phase. CPU percentages for a PID use
the agent's process convention. Host/device facts cover other activity on the same machine.

Samples are grouped by their `observed_at` timestamps. Rate fields summarize preceding intervals,
so the first sample in each phase includes earlier activity. The first untraced sample at
03:35:23.50 covers approximately 03:35:18.5–23.5, before the phase began at 03:35:21.975. The first
traced sample at 03:35:38.50 covers approximately 03:35:33.5–38.5, crossing the traced start at
03:35:37.657. The table therefore includes activity on both sides of those boundaries.

| Measurement | Untraced | Traced |
| --- | --- | --- |
| Node-a host busy CPU | 3.116–5.195% | 8.167–11.607% |
| Node1 CPU | 0.200–0.400% | 0.200–0.599% |
| Node2 CPU | 0.800–1.199% | 0.999–1.199% |
| Node3 CPU | 0–0.400% | 0.200–0.599% |
| Per-peer FD count | 5 | 5 |
| Per-peer physical write rate | 819.057–3,277.972 B/s | 1,637.781–2,456.625 B/s |
| Shared `nvme0n1p1` completion latency | 0.940–0.995 ms | 0.937–0.985 ms |
| Shared device average outstanding I/O | 0.0094–0.0372 | 0.0130–0.0296 |
| Node-b host busy CPU | 0.301–0.500% | 0.400–0.500% |

RSS remained 4,345,856 bytes for node1, 4,059,136 for node2 and 4,341,760 for node3 in these six
ordinary samples. Available process physical-read rates were zero throughout both phases. Node1's
cumulative physical-read counter remained 61,440 bytes, while the other two remained zero.
Per-peer cumulative physical-write counters ranged from 20,480 to 45,056 bytes in the untraced
samples and from 57,344 to 73,728 in the traced samples. These are counter/rate observations over
sampling intervals. Host TCP retransmission rates were available and zero for both hosts in the
observed samples. The active network probe remained unconfigured.

The fixed-query history export retained node-a CPU, host-memory, FD-count and device read/write
series over the workload window, with 9–10 points per field. Node-b retained 13 points each for CPU,
host-memory and FD count. Its I/O scope was unconfigured, and its I/O history results are retained
empty. No values were substituted for those missing series. The ordered elapsed pair includes
pacing, tracing, page-cache and scheduling effects. It supplies descriptive observations for this
single shared-host exercise.

### Restoration, retained failures and shutdown

At 03:35:57.105774 UTC, the operator restored the exact pre-scope `agent.env` bytes and metadata,
restarted the originally active service, and verified its unchanged sandbox/service properties.
The backup was taken after the approved source deployment. The first post-restart filesystem check
was incomplete, so its operator receipt remains failed. A follow-up boot verified a complete
22-second healthy window on both hosts, the same configuration hash and file metadata, matching
service properties, unchanged controller/import/archive/binary hashes, and independently bindable
ports 9101–9103. The original workload boot had ended. The workload itself was performed once.

Startup attempts are retained separately. The operator corrected SSH input newlines, root-side
wildcard expansion, the native venv's `lib64` directory alias and the sampler's inherited working
directory. The sampler startup attempt exited before any client workload and reported clean owned
cleanup. A legacy general healthy-demo check also stopped at mixed-unit Grafana panels. The
Ticket13 health checks above inspect deployed source, consecutive delivery, complete filesystem
telemetry and target/reference freshness. The general demo and rendered dashboards retain their
separate limits. A later hash-list comparison normalized transport line endings while preserving
the individual SHA-256 values and paths.

Private workload artifacts, raw agent observations, fixed-field histories, PostgreSQL and monitor
stores were exported. All three existing instances were confirmed stopped at
03:43:29.050135 UTC. Added preparation packages and the current deployment remain on the retained
stopped lab. The two SSH rules use the operator's verified current `/32`. The investigation records
the shared-host topology and the remaining Ticket18/owner verification separately.


## Hardened reproduction commands

These commands are sanitized templates; substituting paths or identities does not authorize a run.
Prepare one root-owned base whose complete ancestor chain has no group/world write. Stage the final
inspected script, the matching 19 source-only `fleetdoctor` modules, locked dependencies, two native
binaries and retained archive beneath one new runtime. Keep generated bytecode out of staging. The
selected run user/group may read/traverse and execute these paths but may not write them. The
controller's in-process checks remain defense in depth; they cannot protect its own Python startup.
A recursive prelaunch audit with a trusted system interpreter in isolated/no-site mode is mandatory
before the first privileged venv invocation and again after dependency/source staging before capture.

For a new protected local retry, root creates the venv with the trusted system interpreter and
`--without-pip`, creates protected `scripts/` and `src/`, and stages the inspected controller without
invoking the venv. Run the first audit before `ensurepip` or `pip`; after installing locked
dependencies and staging the 19 source modules plus unchanged KV/archive files, repeat the identical
audit. Only then may the controller start:

```text
BASE=/var/lib/fleetdoctor-kv-trace/<task-id>
RUNTIME=$BASE/runtime-fix3
SYSTEM_PY=/usr/bin/python3
PY=$RUNTIME/venv/bin/python
SCRIPT=$RUNTIME/scripts/kv_trace.py
RUN_USER=<local-nonroot-user>
RUN_UID=$(id -u "$RUN_USER")
export PYTHONPATH=$RUNTIME/src
test -x "$SYSTEM_PY"
sudo "$SYSTEM_PY" -I -S "$SCRIPT" \
  --_audit-protected-runtime "$RUNTIME" \
  --_audit-venv-python "$PY" --_audit-run-uid "$RUN_UID"
# Repeat the exact audit above after locked dependencies/source staging.
sudo test ! -e "$BASE/local-build4"
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin PYTHONPATH="$PYTHONPATH" \
  "$PY" "$SCRIPT" \
  --node-binary "$RUNTIME/kv/dkv_node" \
  --client-binary "$RUNTIME/kv/dkv_client" \
  --source-archive "$RUNTIME/kv/source-a22cf751.tar" \
  --source-archive-sha256 2a024a69840f1ece82b92be448c9431113ca663c1126b89bd5a9a7e04fb5fd36 \
  --kv-revision a22cf751799cf0f44a6bfe7a168c78a0ea6e52fb \
  --output "$BASE/local-build4" --run-user "$RUN_USER" \
  --ports 9101 9102 9103 --pairs 8 --pace-seconds 2 \
  --max-runtime-seconds 240 --max-output-bytes 67108864
```

Eight pairs at two-second pacing retain a minimum 15-second window in each phase; the 240-second
local bound covers startup, both phases, decode and cleanup. The controller's tcpdump alarm uses only
the remaining bound at capture start. No start gate is used for this coordinator-owned local retry.

For AWS, first require the exact interpreter used by the existing installer; do not assume the
platform `python3` is new enough. Stop before staging when either command fails:

```text
test -x /usr/bin/python3.11 || { echo "required /usr/bin/python3.11 is absent" >&2; exit 1; }
/usr/bin/python3.11 -I -S -c 'import sys; assert sys.version_info >= (3, 11), sys.version'
```

Create the root-owned venv with `/usr/bin/python3.11 -I -S -m venv --without-pip`, create protected
`scripts/` and `src/`, and stage the inspected controller using only trusted root operations. Before
the first venv invocation, run the audit below. Then bootstrap/install the locked dependencies, stage
the 19 source-only modules and native AL2023 binaries, and repeat the exact audit before capture. Use
the venv executable—not its resolved system target—for the controller, watchdog and sampler imports.
The gate parent is protected state, not a run-user directory. Create it before launch and verify its
complete absolute chain is made only of root-owned directories with no group/world write and no
symlink:

```text
RUNTIME=$BASE/runtime-aws-<utc-id>
SYSTEM_PY=/usr/bin/python3.11
PY=$RUNTIME/venv/bin/python
SCRIPT=$RUNTIME/scripts/kv_trace.py
PYTHONPATH=$RUNTIME/src
RUN_USER=fleetdoctor
RUN_UID=$(id -u "$RUN_USER")
sudo "$SYSTEM_PY" -I -S "$SCRIPT" \
  --_audit-protected-runtime "$RUNTIME" \
  --_audit-venv-python "$PY" --_audit-run-uid "$RUN_UID"
# Repeat the exact audit above after locked dependencies/source staging.
sudo install -d -o root -g root -m 0750 "$BASE/gates"
sudo env TARGET="$BASE/gates" /usr/bin/python3.11 -I -S - <<'PY'
import os, stat
target = os.path.abspath(os.environ["TARGET"])
current = "/"
for part in target.split(os.sep)[1:]:
    current = os.path.join(current, part)
    value = os.lstat(current)
    assert stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode), current
    assert value.st_uid == 0, current
    assert not value.st_mode & (stat.S_IWGRP | stat.S_IWOTH), current
PY
```

On AL2023, use `umask 022` for venv creation and dependency installation within the protected
runtime, then verify run-user read/execute access. Its default `venv/lib64 -> lib` alias must be
replaced with a real directory before the controller validates every Python import path. After the
initial trusted audit/bootstrap, the operator used this root-owned staging adjustment and repeated
the trusted system-Python audit above before invoking the venv again:

```text
sudo env RUNTIME="$RUNTIME" /usr/bin/python3.11 -I -S - <<'PY'
import os, shutil
from pathlib import Path
runtime = Path(os.environ["RUNTIME"])
assert runtime.is_absolute() and runtime.resolve() == runtime
alias = runtime / "venv/lib64"
assert alias.is_symlink() and os.readlink(alias) == "lib"
assert alias.lstat().st_uid == 0
assert alias.resolve() == runtime / "venv/lib"
alias.unlink()
shutil.copytree(runtime / "venv/lib", alias, symlinks=True)
PY
```

Launch from `/` as shown below. The nonroot multiprocessing sampler inherits its working directory
and must be able to enter it. Both corrections preserve the venv invocation path, frozen source and
native binaries.

With `BASE` and `PYTHONPATH` defined as above, the bounded command is:

```text
OUTPUT=$BASE/aws-run-<utc-id>
GATE=$BASE/gates/aws-run-<utc-id>.release.json
sudo test ! -e "$OUTPUT" && sudo test ! -e "$GATE"
cd /
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin PYTHONPATH="$PYTHONPATH" \
  "$PY" "$SCRIPT" \
  --node-binary "$RUNTIME/kv/dkv_node" \
  --client-binary "$RUNTIME/kv/dkv_client" \
  --source-archive "$RUNTIME/kv/source-a22cf751.tar" \
  --source-archive-sha256 2a024a69840f1ece82b92be448c9431113ca663c1126b89bd5a9a7e04fb5fd36 \
  --kv-revision a22cf751799cf0f44a6bfe7a168c78a0ea6e52fb \
  --output "$OUTPUT" --run-user "$RUN_USER" \
  --ports 9101 9102 9103 --pairs 8 --pace-seconds 2 \
  --start-gate "$GATE" --gate-timeout-seconds 300 \
  --max-runtime-seconds 600 --max-output-bytes 67108864
```

The gate must be absent when the controller starts. Only after the actual scoped agent has produced
the required fresh intended-PID samples, compute the exact `readiness.json` digest. Write the exact
two-key object to one exclusive root-owned temporary file in the protected gate directory, flush and
fsync it, then atomically publish it without replacement by hard-linking it to the still-absent final
path. The controller can observe only the complete final inode; an existing final gate is never
overwritten, and cleanup removes only the temporary file created by this invocation:

```text
READINESS_SHA=$(sudo sha256sum "$OUTPUT/readiness.json" | awk '{print $1}')
sudo env GATE="$GATE" READINESS_SHA="$READINESS_SHA" /usr/bin/python3.11 -I -S - <<'PY'
import json, os, uuid
path = os.environ["GATE"]
temporary = os.path.join(os.path.dirname(path), f".{os.path.basename(path)}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
encoded = (json.dumps({"release": True, "readiness_sha256": os.environ["READINESS_SHA"]}, sort_keys=True) + "\n").encode()
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
fd = -1
try:
    fd = os.open(temporary, flags, 0o600)
    os.fchmod(fd, 0o600)
    os.fchown(fd, 0, 0)
    with os.fdopen(fd, "wb") as stream:
        fd = -1
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temporary, path, follow_symlinks=False)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if fd >= 0:
        os.close(fd)
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
```

The 300-second gate allowance leaves 300 seconds inside the controller's 600-second bound for the
two paced phases, validation and cleanup; both remain inside the separate 60-minute/three-instance-
hour live ceiling. A malformed, stale, symlinked, non-root-owned or hash-mismatched gate fails.

## AWS reproduction and authorization boundary

The completed exercise was owner-authorized. Future live reproduction has a ceiling of 60 minutes
from start through restore/export/stop, or at most three
instance-hours if all three existing instances are active for the full hour. Based on the official
[AWS T3 table](https://aws.amazon.com/ec2/instance-types/t3/) and
[VPC public-IPv4 pricing](https://aws.amazon.com/vpc/pricing/), the refreshed public estimate is
approximately $0.0986 for one fleet-hour before credits, tax and transfer. This is planning context,
not a cap or an actual charge. Current account/project billing, remaining reserve and current
resources are unknown until an authorized read-only refresh; historical `docs/costs.md` values must
not be presented as remaining funds. No new instance, replacement, budget increase or extra campaign
is implied.

The authorized operator follows this order:

1. Confirm the existing three-VM inventory, current billing/resource state and native AL2023
   prerequisites. Preview the `dnf` transaction for only `gcc-c++`, `cmake`, `make`, `strace` and
   `tcpdump`. Abort if it would upgrade, downgrade or remove any installed package; install only the
   approved previewed additions and retain before/after NEVRAs and tool versions.
2. Verify the archive hash and build node-a binaries natively on AL2023 with the two commands above;
   retain compiler, glibc, `ldd` and binary hashes. Never copy Ubuntu binaries to AL2023.
3. Complete any separately approved source/deploy verification first. Then back up exact agent.env
   bytes/hash and service state. No deploy may occur while KV scoping or rollback is active.
4. Run the controller and keep it at the bounded readiness gate. AWS KV nodes and the agent use the
   same verified `fleetdoctor` UID. This is an explicit trust decision for the exact hashed external
   KV archive: attach strace only to owned KV/client PIDs, never the agent, and keep tcpdump limited to
   the three KV ports so agent traffic or credentials are not captured.
5. Bind `FLEETDOCTOR_CPU_PIDS` and `FLEETDOCTOR_IO_PIDS` to all three readiness identities and
   `FLEETDOCTOR_IO_MOUNTS` to the recorded containing mount. Restart the agent without relaxing its
   permissions/sandbox. Require PID/start-time, FD-count and available non-baseline process-I/O facts
   for every node plus at least two fresh samples before releasing the hash-bound gate.
6. Retain ordinary node-a and healthy node-b latest samples and applicable fixed-field ranged metrics
   across both phases. Polling without configured process identities does not satisfy acceptance.
7. In `finally`, restore the exact agent.env bytes, verify its SHA-256, restore/restart the original
   service state and retain fresh healthy observations. A failed restore makes the live run failed.
   Export evidence, record actual start/stop/instance-hours, then stop the lab as authorized.

AWS/SSH, deployment, service mutation, package installation, billing access and the gate release are
not performed by the builder. Raw captures, private environment details and source archives stay
outside Git. See [Ticket13 evidence status](task13-evidence.md) for the current gates.


