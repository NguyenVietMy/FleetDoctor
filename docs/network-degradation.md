# Network path degradation

FleetDoctor schema v5 adds one configured canonical numeric unicast IPv4 target per agent. Set `FLEETDOCTOR_NETWORK_TARGET`, or use an already numeric collector URL host. Hostnames, unspecified/multicast/reserved/broadcast and noncanonical addresses are rejected; FleetDoctor never performs DNS to choose the target. Deploy the v5-compatible collector before v5 agents. Older v1-v4 samples remain accepted under their original contracts.

Every five-second collection runs concurrently with the existing collectors. A Linux worker sends exactly three IPv4 ICMP echo requests within a three-second whole-worker budget. Packet loss is measured only when ping completes a valid three-packet summary; return code 1 with a complete partial/no-reply summary is measurement, while permission, missing-tool, timeout, malformed, or truncated output is unavailable. RTT is the median of individual successful replies, never the summary average. A no-reply result therefore has loss `3/3` and no RTT. Unsupported platforms remain explicitly unavailable and do not invoke a platform-specific ping.

Three fresh observations with at least one lost packet or successful-reply median RTT at least 200 ms open `network_path_degradation`. Three fresh observations with zero loss and median RTT below 150 ms resolve it. Equality opens at 200 ms and does not recover at 150 ms. `FLEETDOCTOR_NETWORK_RULE` accepts `info`, `warning`, or `critical` severity and defaults to `warning`. Boot/session identity, increasing sequence/time, a configured maximum gap no greater than ten seconds, and the exact target bind each window. The opening configuration and severity are frozen for the incident. A target change leaves the old incident active with `target_changed` unavailable evidence; observations for a different target cannot resolve it. Admission is bounded to 16 active network resources per node.

Host `Tcp:RetransSegs` is a cumulative host counter and its rate is host context, not target/interface attribution. `CurrEstab` and `/proc/net/tcp{,6}` state counts are instantaneous gauges and never rates or reset inputs. Interface error/drop counters and rates are interface-scoped context, not proof that the interface caused the path fault. First observations, gaps, identity changes and per-field decreases make only the affected cumulative rate unavailable. Route attribution is usable only when exact pre/post routes agree; the hardened service may report `route_netlink_denied` with no invented interface while ICMP still succeeds.

## Service preparation and security

`deploy/network_prepare.sh` must run as root during installation. It validates `ping`, `ip`, and `tc`, discovers the actual nonroot `fleetdoctor` GID, writes a root-owned mode-0644 sysctl file setting `net.ipv4.ping_group_range` to exactly that GID, applies it, and verifies the tokenized readback. The service keeps `User=fleetdoctor`, `NoNewPrivileges=true`, no capabilities, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `TasksMax=16`, `MemoryMax=100M`, a read-only protected system, private temporary storage, and a read-only credential. Do not grant `CAP_NET_RAW` or relax the address-family restriction.

The target must be reachable by private numeric IPv4 and allowed by the lab security group for the intended ICMP test. Ingestion and administrative HTTP/TCP traffic are deliberately outside the helper's ICMP echo-request class. This ticket does not change DNS monitoring, open public access, or authorize AWS/SSH/deployment.

## Owned fault helper

`deploy/network_resource.py` is root-only and intended only for an isolated lab network namespace. It derives the exact route itself and refuses any baseline other than the supported `noqueue` state with no foreign class/filter/ingress objects. A root-owned mode-0700 directory, mode-0600 lease/lock/run records, exact namespace/interface/ifindex/route identity, exclusive bounded lock, unique handles, and structured live-tree comparison define authority. The flower filter matches only IPv4 ICMP destination `<target>`, type 8, code 0. Latency adds 250 ms netem; loss drops 100% of that class. TCP, UDP, SSH, ingestion and administration bypass it.

An independent watchdog is established before the first `tc` mutation. Rollback intent and each pending/completed step are persisted. Signals, parent loss during setup, deadline, partial failure, and requested cleanup converge on exact owned restoration. Cleanup validates the lease before inspection or deletion, refuses route/namespace/foreign-tree changes, proves the captured baseline, and retains an actionable failed record instead of claiming success. Never point this helper at the host namespace and never manually delete its lease or qdisc.

## Investigation and dashboards

Start with `/diagnoses/{id}`: verify node/rule/resource, frozen configuration, opening and latest sample identities, loss/reply counts, successful RTTs, route coverage, and evidence freshness. Treat TCP and interface counters as scoped context. Then repeat a bounded numeric ping, inspect `ip -4 route get`, compare host retransmits and interface deltas, and check upstream route/shaping changes. Do not infer packet loss from unavailable collection or infer a culprit from one interface counter.

The Fleet and Node dashboards expose loss, successful-reply median RTT, collection/route/admission coverage, host retransmit rate, instantaneous TCP states, interface error/drop rates, active incidents, and readable evidence. Missing RTT is intentional for no-reply/unavailable states. Prometheus labels are bounded to node, rule, state and interface; the target remains structured API/evidence.

## Local proof

```text
uv run pytest
uv run python scripts/integration.py --output <new-external-directory>/task09-services.json
uv run python scripts/network_helper_integration.py --output <new-external-directory>/task09-native.json
```

The service proof uses synthetic v5 observations with actual PostgreSQL, Prometheus, Grafana datasource queries, restart, history, target change, unavailable and no-reply states. The native command is a portable outer controller for a Linux Docker engine and runs the unmodified production agent in hardened, isolated namespaces with real ping/tc/netem. It proves both profiles, the healthy reference, target-namespace unshaped HTTP, service restrictions, denied-ICMP/missing-tool unavailable states, cancellation, watchdog/rollback and exact owned cleanup. It does not claim AWS/SSH execution, five AWS runs, rendered-dashboard inspection, independent approval, deployment, or owner acceptance.

Measured trigger-to-diagnosis time starts when the API response containing the first fresh exact-target probe at the declared loss or RTT threshold completes. The later qualifying observations needed to open the incident are confirmation time inside that measurement, not a new trigger. The incident opening must use the same boot/session and an observation at or after the trigger; missed intermediate controller polls do not invalidate a later correctly bound opening. Five-run acceptance uses five complete comparable attempts and requires the median for each profile to be strictly below 30 seconds. Individual complete runs retain their own under-30 flags and may be slower than 30 seconds without being discarded from that median.
