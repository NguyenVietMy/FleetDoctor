# 12: Postmortem drafting

**What to build:** A documented command converts a saved incident and scenario record into an evidence-linked model draft for author review.

**Blocked by:** 02: Disk-full diagnosis

**Status:** ready-for-agent

- [ ] Select a model backend and estimate costs before generation. Capture immutable input evidence, incident/timing/cleanup/recovery references, model ID, and the Markdown draft.
- [ ] Label missing facts and inference; keep diagnosis, source evidence, severity, and lifecycle state unchanged. A model failure returns a drafting error while monitoring remains operational.
- [ ] Demonstrate an actual model draft from the disk flow and a reviewed result; add fixture-based input/output, immutability, and model-failure checks plus usage instructions.
