# 12: Postmortem drafting

**What to build:** A documented command converts a saved incident and scenario record into an evidence-linked model draft for author review.

**Blocked by:** 02: Disk-full diagnosis

**Status:** merged in [PR #11](https://github.com/NguyenVietMy/FleetDoctor/pull/11); implementation delivered. Owner author acceptance remains pending.

- [x] Select a model backend and estimate costs before generation. Capture immutable input evidence, incident/timing/cleanup/recovery references, model ID, and the Markdown draft.
- [x] Label missing facts and inference; keep diagnosis, source evidence, severity, and lifecycle state unchanged. A model failure returns a drafting error while monitoring remains operational.
- [x] Demonstrate an actual model draft from the disk flow and a reviewed result; add fixture-based input/output, immutability, and model-failure checks plus usage instructions.

- [ ] Record owner (author) acceptance of the reviewed example; agent review is not author acceptance. The eight-scenario final verification remains Ticket17.

**Verified scope:** Fixture/fake-process CI, one actual Claude disk draft and an agent-reviewed result. Owner author acceptance and the eight-scenario postmortem gate remain pending.

**Evidence:** [Task12 handoff record](../../../docs/task12-evidence.md), [current delivery and CI status](../../../docs/delivery-status.md).
