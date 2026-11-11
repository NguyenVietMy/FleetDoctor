# Ticket13 evidence status

Ticket13 has retained local proof and a native AWS workload/capture investigation. Fresh local
inspection3 approved fix3 snapshot `7a154ca07fd106e91353f64dba1eaee4439d4c16e638ca85f485a4478a84a9dd`.
On 2026-11-11 UTC, the AWS workload completed 16 verified PUT/GET pairs with ordinary deployed-agent
observations, a healthy reference, fixed-field history and exact pre-scope configuration restoration.
Startup/operator failures remain retained. The final post-restore verification completed after a
follow-up boot, and all three instances were stopped. The delivery receipt records the fresh review
of these new documentation bytes and the commit-bound publication/CI results. Ticket18 and owner
acceptance retain their separate scope.

The owner authorized completion of Ticket13 and its remaining delivery work on 2026-11-10 local
time. This delivery also updates TASKS, the delivery summary and the local Ticket13 checklist.
Checked tracker items record verified implementation evidence. Owner acceptance remains pending.

## Frozen implementation contract

- FleetDoctor base: `3caf025699d9d01901e7cafad2f473126e8b0374`
- Approved external plan SHA-256:
  `026a7ea4c5c4c5c71bcc36da85810c57ca2a9b9cfae65281a809136ca675ef0b`
- Plan approval: external Claude result `plan-reviews/claudex-p10urgx6/result.json`
- KV source revision: `a22cf751799cf0f44a6bfe7a168c78a0ea6e52fb`
- KV archive SHA-256:
  `2a024a69840f1ece82b92be448c9431113ca663c1126b89bd5a9a7e04fb5fd36`
- Supported placement: all three localhost peers on node-a; node-b is the healthy reference.
- Historical local-build2 fix1 code/test SHA-256: `bd0882dc3c1d306ad670f1df1c70201de1cd7b07a3da5db19b5df6353b5a5e71`
  / `54afe4c1dff67ee80eeaae6015dc5a3afcf1d8e180e98c83f4a72916e9ccd5a1`.
- Hardened fix2 code/test SHA-256: `05bb04fa7d8b0891f09008a1c00321873371cfee55c17e639c3439ee0327feeb`
  / `c044552301e2126e50310a9cbb1129764374e433b755674712bfdc44d1542173`.
- Hardened fix3 code/test SHA-256: `cc56f6b334f9028dae087263f30cd4a5ce6f6ab068b738133bef6133ae20ff4a`
  / `4de4a414a35fe8acdf0e1f71d9dc82f6b7be3fa52e10da440655f6f97872ec1e`.

Fixture/fake-process checks prove controller contracts only. The external local-build2 bundle adds
actual local KV workload, syscall/packet, direct-sampling and cleanup evidence for fix1. The protected
local-build3 and local-build4 bundles add successful operational runs for fix2/fix3 protected runtimes
and cleanup, but their deliberately stopped captures do not exercise timer expiry or injected signals;
the ungated local-build4 also does not exercise an actual release gate. Focused fixtures cover gate
publication/ownership controls and injected controller signal/expiry handling. The actual gated AWS
integration is recorded in its own section below. These local bundles retain their local/direct scope.

## Retained historical local-build2 evidence

- Manifest `869edef7db6366ba476e27bf69487d8676edf85b747cbdd21b163c8476b0fda1`:
  terminal `passed`, 16 semantic PUT/GET pairs, stable node identities, four leader/term snapshots,
  usable capture/strace classification, zero survivors and released ports.
- PCAP `8b513079745b7ca1cdcf1931344e833afb9cc70417374ff05a57d6c6da620b34`:
  7,695 complete records, 707,450 bytes, zero kernel drops and zero payload truncations.
- Full decode `4b1bff19053dc3fe1536037ec2093643217985fe90de50dcdec5121bf14c62b9`:
  7,695 lines, independent tcpdump exit zero.
- Typed samples `bcf108fbba713e34e59bb0bad0edd4b45f0326efd81b4b8d2e1001357407e49d`:
  seven records, four untraced including the baseline and three traced, with intended CPU/RSS/FD/I/O
  identity coverage. Exact excerpts, ranges and limitations are in the investigation.
- Independent semantic audit
  `a9a9d5059a825025d4ca696793a8c5aeabfebdc772e19999b5d14a9619add1af`: all 16 pairs checked
  against the fixed values, request IDs and raw exit/commit/GET replies; WSL timezone observed as
  `EST-0500`.

## Protected local-build3 operational evidence

- Manifest `2bee7b2ed04aacd534fd06485cb0991b418d0a66ce6920b141baaaf4f3eee0fa`:
  terminal `passed` on unchanged fix2 code/tests, all 16 exact pairs, three stable UID 1000 node
  identities, the same-UID sampler, intentional capture stops, watchdog disarmed, no reported
  survivors and released ports.
- Capture/trace audits: 7,520 complete PCAP records and 690,999 bytes with zero kernel drops or payload
  truncations; 19 strace files, 1,187,400 bytes and 5,661 successful timestamped lines. The independent
  full decode matched all 7,520 harness-decoded lines, and the semantic audit rechecked all 16 replies.
- Sampling/postrun audits: seven typed samples with the startup baseline and three completed samples
  per phase; 23 staged source/binary/archive files unchanged; 1,965 runtime entries root-owned and not
  writable by the run user; all three node identities dead and all three ports independently bindable.
- Scope: the workload armed but did not expire the tcpdump alarm and injected no signals. Those control
  paths are focused fake-process proof, while AWS/service/reference/restore evidence remains pending.

## Protected local-build4 fix3 operational evidence

- Manifest `2e2ba644a12dd3e2522e70f4ce27ad545850a4233526355166b5ee19dcdcc367`:
  terminal `passed` on unchanged fix3 code/tests, all 16 exact pairs, stable same-UID node/sampler
  identities, the post-startup pre-workload ownership check, terminal assessment/finished time,
  intentional capture stops, watchdog disarmed, no reported survivors and released ports.
- Capture/trace audits: 7,676 complete PCAP records and 704,555 bytes with zero kernel drops or payload
  truncations; 19 strace files, 1,198,936 bytes and 5,734 successful timestamped lines. The independent
  full decode matched all 7,676 harness-decoded lines, and the semantic audit checked all 16 replies.
- Sampling/runtime audits: seven schema-validated samples with the startup baseline and three completed
  samples per phase; all intended CPU/RSS/FD/nonbaseline-I/O identities; trusted prelaunch audits before
  first venv use and after staging; 23 staged source/binary/archive files unchanged; 1,965 protected
  runtime entries; exact node identities dead and ports independently bindable after cleanup.
- Scope: this was a normal ungated local run. Focused fixtures cover gate publication/ownership
  controls and injected controller signal/expiry handling. The later actual gated AWS exercise has
  separate receipts below.

## Gate ledger

| Gate | Current state |
| --- | --- |
| Approved exact plan | Passed externally for the hash above |
| Builder affected fix1 proof | Passed: Ruff, mypy, help and diff; Windows focused 24 passed/5 POSIX skips; Linux focused 29 passed/0 skips |
| Coordinator affected fix1 proof | Passed: Ruff, mypy, help and diff; Windows 24 passed/5 POSIX skips; Linux 29 passed/0 skips as normal user and root |
| Full repository suite | Pre-capacity baseline only: 632 passed, 120 skipped, 1 existing warning; not rerun or represented as current fix proof |
| First actual local KV read/write/capture/direct-sampler run | Failed/partial and retained: workload, scoped metrics and cleanup succeeded, but tcpdump reached 7,000 packets before phase end |
| Justified local retry after capture-bound fix | Passed as historical `local-build2`: full decode, 16 pairs, scoped direct metrics and clean cleanup for fix1 bytes |
| Actual excerpts and measured ranges integrated into investigation | Integrated and claim/reference checked against the hashed retained fix1 artifacts |
| Fresh inspection1 | REVISE: KV13-I01..I05 accepted; no approval claimed |
| Builder hardened fix2 affected proof | Passed for the fix2 hashes above: Ruff format/check, mypy, help and diff; Windows focused 23 passed/13 Linux skips; Linux focused 36 passed/0 skips as normal user and root |
| Coordinator hardened fix2 affected proof | Independently repeated and passed on unchanged code: Ruff format/check, mypy, help and diff; Windows focused 23 passed/13 Linux skips; Linux focused 36 passed/0 skips as normal user and root |
| Protected `local-build3` functional retry | Passed: terminal manifest, all 16 exact pairs, complete capture/decode and traces, intended-identity sampling, protected-runtime postrun audit and clean cleanup |
| Fresh independent Claude inspection2 | REVISE: KV13-J01..J04 accepted; successful local-build3 evidence remains historical fix2 evidence |
| Builder fix3 affected proof | Passed for the fix3 hashes above: Ruff format/check, mypy, help and diff; Windows focused 25 passed/18 Linux skips; Linux focused 43 passed/0 skips as normal user and root |
| Coordinator fix3 affected proof | Passed on unchanged fix3 bytes: locked sync, Ruff format/check, mypy, help and diff; Windows focused 25 passed/18 Linux skips; Linux focused 43 passed/0 skips as normal user and root |
| Protected `local-build4` functional retry | Passed: terminal manifest, all 16 exact pairs, complete capture/decode and traces, intended-identity sampling, prelaunch/postrun protected-runtime audits and clean cleanup |
| Fresh independent Claude inspection3 of local fix3 bytes | APPROVED for the exact local snapshot above, with four low advisories retained externally |
| Latest-commit hosted CI | Commit-bound push/PR results accompany delivery in GitHub Actions |
| AWS native build, scoped agent/service capture and exact restore | Verified for the retained run and follow-up post-restore check below |
| Ticket18 verification and owner acceptance | Pending |

The final delivery receipt binds the fresh independent review of the AWS documentation to its exact
source snapshot. Hosted runs belong to their exact commits. Ticket18 and owner acceptance retain
their separate scope. Raw captures, configuration backups and private store exports remain outside Git.

## AWS evidence and coordinator closure

The workload ran at 03:35:21.975335–03:35:53.515423 UTC on 2026-11-11. The native deployment gate
matched all 380 source-inventory files before, during and after deployment. Installed package probes
matched all 19 Python modules on monitor, node-a and node-b. The controller and tests retain their
fix3 hashes above. The native node binary SHA-256 is
`426643da073f8293b620194f2fd9de576d08051910252221b0b9127e3b1c5e6a`, and the client is
`d381b9e50ed47b5bdc6567ae0e5d7ab4fcd8355c6592ddb7b39d5072e77947c5`.

The workload directory `aws-ticket13-20261111T033338Z` reused the protected runtime prepared under
`aws-ticket13-20261111T024103Z`. Its binaries, 19 FleetDoctor modules, controller and source archive
were hash-checked again before capture and after the workload.

| Private logical artifact | SHA-256 |
| --- | --- |
| Native `aws-run/manifest.json` | `b35c52a7ccecdd6ca0101e42c0fe2560bb76e8fb49ca24f77f6f4944b75ed23a` |
| `captures/kv-loopback.pcap` | `f3fe631880567ff3e987f77e0689ebe2dae26e7625d56aa6a1f13aa4ea9d9b96` |
| Full native and independent packet decode | `c04a404e28d3dd8d9d6b09bf76173beb61aa5d409b884e19b90a283bc7ed8cf3` |
| Ordinary deployed-agent observations | `17b49b715434861f0f3dde8b9bbc298e351f068d74474381b1403c16182ca797` |
| Deployed observation/identity/range audit | `053d3723bd6fbbf60223be5737c07f6e2c234d0eee6dc7ec6169764a4ace361f` |
| Independent 16-pair semantic audit | `6dcd050880094662c7660c53348c9cafbf0b0af78e358bf803c5871400ddf8c9` |
| Fixed-query Prometheus histories | `cee895004d167d9ad243a7438e451abbb07fa66c6ebbcd63b9c0be7e0f9acb01` |
| Independent restoration/ports audit | `ac7670dd7dc8b1248d790e661c4775163a80eb54131abf02e566775fe91fd604` |
| Final post-restore/export/shutdown receipt | `674e4a03b6309ea46cad5a7f30964a546315837bb474c1c6b279b99129d9c8f4` |

The controller's native manifest is the byte-bound product artifact in this table. A separately
pretty-printed Windows coordinator copy has different newline/serialization bytes but parses to the
same object. The re-exported native manifest matches the original native bytes exactly.

- The actual workload manifest is terminal `passed`, with eight semantic pairs per phase, three
  stable UID-993 node identities, all four deliberate capture stops without escalation, no reported
  cleanup survivors, a disarmed watchdog and released ports.
- Capture checks retained 7,590 complete packets, zero kernel drops/truncations, and 19 trace files
  containing 5,510 successful timestamped syscall lines. The full independent decode matches every
  retained native decode byte. All 16 raw client reply pairs passed the independent semantic audit.
- The readiness gate released after two distinct complete ordinary samples. All three intended
  CPU/RSS/FD/nonbaseline-I/O identities were present in three unique target samples per phase. The
  reference supplied three fresh healthy ordinary samples per phase. Host/device/network ranges
  and exact trace anchors are in the investigation.
- Trusted product audits ran under system Python `-I -S` before first venv use and after staging.
  The native import-directory correction was audited before capture. The prelaunch audit covered
  5,201 entries and three protected interpreter symlinks. The 23 controller/module/archive/binary
  hashes matched after the workload.
- The exact pre-scope configuration SHA-256 is
  `204f9bc6d5bdfba99fe3ea7c703866a2ac8a2f38d03cbe204e360b6608155910`.
  Restoration verified its bytes, mode and ownership plus the originally active service state and
  unchanged sandbox/service properties. A fresh 22-second healthy target/reference window passed
  after reboot. Ports were independently bindable, and the original workload boot had ended.
- Fixed-field histories retained 9–10 node-a points per CPU/memory/FD/device-I/O field and 13 node-b
  points per CPU/memory/FD field. Reference-node I/O histories are empty because its I/O scope was
  unconfigured. That absence remains explicit.
- The initial operator receipt remains failed at the first incomplete post-restart filesystem check.
  Follow-up verification completed restoration/health/history/export/shutdown without repeating the
  workload. Earlier startup failures and the unrelated mixed-unit Grafana health-demo assertion
  remain retained with their exact coverage. Rendered-dashboard acceptance remains unrun.
- Workload artifacts, PostgreSQL and monitor stores were privately exported. All three existing
  instances were confirmed stopped by 03:43:29.050135 UTC. Preparation added 23 native-build packages
  and dependencies on node-a, then the approved four `tc` prerequisite packages on each agent, with
  no preexisting RPM NEVRA removed. Those packages and the new deployment remain in the stopped lab.

This bounded exercise supplies workload investigation evidence. Ticket18 verification, scenario
calibration, the healthy-hour/overhead campaign, final budget reconciliation and owner acceptance
retain their own requirements.

