# 15: Chaos measurement validation

**What to build:** A recorded AWS acceptance batch establishes diagnosis, cleanup, recovery, and latency for all eight scenarios.

**Blocked by:** 14: Full CI validation

**Status:** ready-for-agent

- [ ] Freeze code/rules and record the lab manifest; execute five runs per scenario across both monitored nodes, one fault at a time, for 40 measured runs.
- [ ] Every run must identify the correct node/resource, retain evidence, clean up, and resolve from fresh healthy observations within the declared timeouts.
- [ ] Each scenario median trigger-to-API-diagnosis must be below 30 seconds. Each network run includes both profiles, with the slower phase defining scenario latency and both profile medians reported.
- [ ] Retain machine-readable incident-linked results, full injection timing, failures, configuration/environment, and any superseded batches.
