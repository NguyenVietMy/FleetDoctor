# PRD CI coverage audit

Ticket14 audits the five checks in the [PRD CI gate](../FleetDoctor%20PRD.md#ci-gate). The [execution contract](ci-coverage.json) pins 166 exact pytest node IDs, including every selected parameter variant, and 26 required workflow step IDs. [The checker](../scripts/check_ci_coverage.py) compares those IDs with actual results separately in the Linux host, root container and non-root container. The source audit below explains the assertions; the checker verifies execution, not semantic correctness.

Status: audit and enforcement implemented locally; independent inspection and current-commit hosted CI remain pending. The baseline `f77201e9061290acf60831a61acd7bb8d22f87f9` passed [main run 42960011517](https://github.com/NguyenVietMy/FleetDoctor/actions/runs/42960011517), finishing on 2026-11-11 UTC: host 795 passed/100 skipped, root 888/7, non-root 791/104. Those results predate these changes.

## Installation and static checks

The [workflow](../.github/workflows/ci.yml) installs the committed lockfile with `uv sync --python /usr/bin/python3 --no-managed-python --locked --all-extras`, probes `os.pidfd_open`, checks Ruff format/lint, mypy and whitespace, and imports agent, collector, DNS, I/O and drafter modules. Terraform format/init/validate remain required. Every named step's outcome and conclusion must be `success`; missing/skipped steps and failures masked by `continue-on-error` fail the receipt.

## Linux collection and retry

Each named assertion group below has its full parameterized node IDs in the contract. The workflow also runs the complete suites.

| PRD case | Assertion-backed fixture coverage |
| --- | --- |
| Filesystem parsing, units, malformed/unavailable data | [test_fleetdoctor.py](../tests/test_fleetdoctor.py): `test_linux_reserved_blocks_and_units`, all `test_invalid_capacity_is_unavailable` and `test_bad_counters_rejected` cases, `test_bad_filesystem_preserves_good_sibling`. Available-to-unprivileged bytes account for reserved blocks; a bad sibling does not erase valid data. |
| CPU counters/rates/resets and process reuse | [test_cpu.py](../tests/test_cpu.py): `test_proc_parsers_and_independent_cpu_fractions`, `test_process_parser_handles_spaces_and_embedded_close_parenthesis`, `test_collector_rates_pid_reuse_hotplug_and_interval_reset` assert deltas, fractions, exact process identity and discarded hotplug/overlong baselines. |
| Cgroup OOM, generations and permissions | [test_memory.py](../tests/test_memory.py): `test_memory_parsers_units_unlimited_and_path_validation`, `test_collector_reads_rates_generation_and_event_bracket`, `test_missing_cgroup_and_journal_rebaseline_and_exact_memcg_scope`, `test_journal_validates_boot_cursor_and_permission`, `test_baselines_resets_instability_missing_limits_and_generation_isolation`. |
| FD permission/limit errors, process exit/reuse | [test_fd.py](../tests/test_fd.py): all `test_real_collector_limit_unavailable_zero_and_unlimited_semantics` cases; count-error growth reset; identity-recheck race; selected-candidate exit race; exact watched-zombie evidence. |
| ICMP success/failure and resets | [test_network.py](../tests/test_network.py): partial-loss median of successful replies, measured zero-reply loss versus unavailable permission errors, rejected malformed/duplicate replies, independent interface counter reset. |
| DNS success/failure and unavailable adapters | [test_dns.py](../tests/test_dns.py): exact-owner resolved parsing; bounded overflow/stalled child; direct-adapter provenance variants; timeout remains measured failure; provenance controls actual ingest/rule admission. |
| I/O activity/idle and malformed inventories | [test_io.py](../tests/test_io.py): bounded short reads, diskstats tails, ambiguous mount/pressure/process parsing, `test_wire_recomputes_arithmetic_idle_and_resource`, all bracketed-inventory races. [test_io_lifecycle.py](../tests/test_io_lifecycle.py) covers boot/session/sequence/counter/baseline reset cases. |
| Bounded collection under stalls | [test_supervisor.py](../tests/test_supervisor.py): production six-future DNS stall, production I/O stall and partial I/O frame preserve completed peers and reap owned process groups within the declared bound. Required on Linux; a skip blocks the contract. |
| Outage queue/retry bounds | [test_delivery.py](../tests/test_delivery.py): `test_queue_count_bytes_pinned_and_snapshot_lag`, all expiry/generic-ack cases, immutable backoff/newest selection, collection independent of a stalled uploader. [integration_outage.py](../scripts/integration_outage.py) also exercises the real uploader through a scoped proxy and checks retry bytes, queue, freshness and replay/recovery cuts. |

## All eight rules and shared lifecycle

Every fixture group is required in all three Linux environments. [integration.py](../scripts/integration.py) also calls every isolated-service proof before reporting success.

| Rule | Required fixture assertions | Isolated service |
| --- | --- | --- |
| Disk block exhaustion | [test_disk.py](../tests/test_disk.py): lifecycle/hysteresis, opening evidence, independent nodes, recurrence, all opening/recovery reset cases, replay and failed-transaction rollback | [integration_disk.py](../scripts/integration_disk.py) |
| CPU saturation | [test_cpu.py](../tests/test_cpu.py): busy/runnable trigger, healthy recovery, absent telemetry, threshold windows, stale export removal and checkpoint rollback | [integration_cpu.py](../scripts/integration_cpu.py) |
| Workload OOM | [test_memory.py](../tests/test_memory.py): immediate positive local-kill delta, updates/recurrence, gap/session/boot/counter resets, restart requiring three new healthy samples | [integration_oom.py](../scripts/integration_oom.py) |
| Inode exhaustion | [test_inode.py](../tests/test_inode.py): block/inode distinction, independent missing-block availability, all continuity resets, lost acknowledgement/recurrence and restart windows | [integration_inode.py](../scripts/integration_inode.py) |
| FD pressure | [test_fd.py](../tests/test_fd.py): watched exact identity, restart/lost acknowledgement, exit and strict new-boot/release confirmation | [integration_fd.py](../scripts/integration_fd.py) |
| Network degradation | [test_network.py](../tests/test_network.py): sustained loss/latency windows, target change cannot recover, frozen restart configuration, duplicate/conflict/failed write, resolution/recurrence | [integration_network.py](../scripts/integration_network.py) |
| DNS failure | [test_dns.py](../tests/test_dns.py): three failures/three successes, changed scope preserves active/opening facts, unhealthy direct-IP context is inconclusive, invalid/unavailable facts cannot open or resolve | [integration_dns.py](../scripts/integration_dns.py) |
| I/O bottleneck | [test_io.py](../tests/test_io.py), [test_io_lifecycle.py](../tests/test_io_lifecycle.py): full windows, idle recovery, missing/replaced resource distinction, threshold equality, reset variants, node/device isolation, recurrence, mixed-rule atomicity/replay | [integration_io.py](../scripts/integration_io.py) |

Shared collector ordering uses `test_duplicate_superseded_and_session_restart`, all `test_ingestion_freshness_boundaries` cases, disk/inode opening-and-recovery reset matrices and I/O mixed-rule ordering. `test_restart_restores_ordering_but_not_live_gauges_or_recovery_window` verifies persisted identities remain duplicate while restored gauges and pre-restart recovery observations remain unusable. Shared and rule-specific checks cover the declared clauses; this is not an exhaustive cross product of every fault and rule.

The pinned CPU, FD, network, DNS and I/O cases explicitly check the first and second eligible observations, so an early opening or recovery fails. The contract also requires `test_pending_four_is_sorted_bounded_and_rotates_before_opening`, which checks I/O pending windows before the third trigger. The actual-stack DNS probe records opening counts `[0, 0, 1]` and recovery states `[active, active, resolved]`, checking each API response as it goes.

## Collector/API and persistence

| PRD case | Isolated-stack assertion and complementary fixture |
| --- | --- |
| Request validation | [integration_contract.py](../scripts/integration_contract.py) sends malformed JSON, unsupported schema, invalid units, oversized bodies, missing authentication and wrong registered node identity through the running collector. Rejections leave node observations unpublished. `test_wire_rejects_invalid_structure` and `test_identity_authentication_and_payload_caps` supply finer fixture boundaries. |
| Ingestion idempotency | `integration_disk.prove` retries identical samples after success and storage recovery, verifies duplicate responses and checkpoint identity. Negotiated-ack fixtures reject missing/corrupt persisted publication. |
| Freshness/export | `integration.py` checks fresh two-node views, different filesystem values and real Prometheus history. `integration_outage.prove_outage` checks expiry/staleness and metric removal. `test_export_and_latest_expire_before_stale` pins exact fixture boundaries. |
| Bounded numeric history | `integration_contract.prove` rejects partial/reversed/future/over-seven-day/over-1500-point ranges, out-of-bounds steps and unknown fields, then requires a valid request to reach Prometheus. `integration.py` requires populated two-node numeric history. `test_history_bounds_and_unavailable_upstream` adds upstream-failure fixtures. |
| Incident APIs | `integration_disk.prove` verifies list/detail filtering/pagination, SQL evidence and frozen opening facts; per-rule proofs check their APIs/counts. `integration_io.prove` also retains superseded-resource state across restart. |
| PostgreSQL/restart | `integration.py` upgrades a pre-Task04 schema and restarts the real stack with retained volumes. `integration_disk.prove` reads SQL incidents/checkpoints, restarts the collector, preserves opening evidence and marks reload evidence stale. FixtureStore restart checks are complementary. |
| Failed writes/retry | `integration_disk.prove` injects SQL failure and PostgreSQL stop/pause/unpause, asserts failed requests do not claim durable publication, distinguishes expired from fresh retries and verifies same-identity retry/deduplication after recovery. `commit_ack_probe.py` checks lost-ack reconciliation. Fixture transaction tests and mixed-rule cases cover both incident/checkpoint failure boundaries. |

## Postmortem drafting and isolation

[test_postmortem.py](../tests/test_postmortem.py) requires a complete immutable fixture bundle, exact citations, retained source facts and terminal failure manifests. Saved evidence/scenario bytes remain unchanged. `test_drafting_error_does_not_interrupt_collector_diagnosis_or_recovery` injects a drafting error between opening and recovery, then checks the same monitoring instance resolves and opens a new recurrence. The drafter reads saved JSON and has no collector/store mutation path, so its output cannot rewrite the source diagnosis/severity/configuration. CLI fixture generation and `check_postmortem_examples.py` also validate the published example. Fixed responses and fake child executables make zero live model calls.

## Skips, provenance and retained failures

- Every exact selected parameter case must pass separately in Linux host/root/non-root. Missing/duplicate identities, skips, failures/errors, suite errors and empty/malformed/missing reports block the receipt. Passing siblings or other environments cannot substitute.
- Complete suites also run; any reported failure/error blocks the receipt. Windows Job Object tests, root-owned helper fixtures and non-root refusal tests may skip in an inapplicable environment. Every nonrequired skip is listed in the receipt. Applicable native/helper steps remain separately required. Skipping a mapped PRD case always blocks acceptance.
- The service receipt must identify the current commit and isolated synthetic environment, retain unchanged source snapshots, contain API/history/persistence/outage and all eight rule sections, report success and record unique-project cleanup. Presence is a mechanical check; the proof assertions establish meaning.
- A full receipt requires matching GitHub Actions commit/run/attempt context and successful outcomes/conclusions for all 26 named steps. Local `--fixtures-only` output says `fixture_coverage_passed`, scope `local-fixtures`, and cannot claim full CI acceptance.
- Always-running audit/upload steps retain JUnit traces/output, the coverage receipt, fixed-response drafter bundle and existing service/native/helper receipts in `task14-ci-proofs-<run>-<attempt>` for 30 days. GitHub run/job logs retain command failures. Commit/run/attempt and contract/report hashes identify the evidence. Missing results after early failure produce a failed receipt.

## Reproduce and acceptance

Run README's static checks and complete pytest suite. Build Docker's `test` target and run with `--init` as root and UID/GID `10001:10001`, using separate output mounts for `--junitxml`. A Linux host run is also required. Then:

```text
uv run python scripts/check_ci_coverage.py --fixtures-only --report linux-host=<host.xml> --report linux-root=<root.xml> --report linux-nonroot=<nonroot.xml> --output <external-path>/fixture-coverage.json
uv run python scripts/integration.py --output <external-path>/service.json
```

A Windows report cannot establish Linux-host proof: required POSIX cases skip and the checker rejects it. Hosted CI supplies the canonical Linux host, systemd/dm-delay/network/namespace helper checks and full current-commit gate. Local fixture/service results remain separately labelled. A successful baseline does not approve changed bytes. Commit/push/PR, latest-head CI, merge, AWS, owner acceptance and later Tickets15-19 retain their own gates. Ordinary CI makes no AWS or live model calls.
