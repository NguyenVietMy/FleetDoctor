# 02: Disk-full diagnosis

**What to build:** A bounded filesystem fill produces an evidence-supported disk incident in the API and Grafana; cleanup yields automatic resolution while preserving incident history.

**Blocked by:** 01: Healthy AWS fleet

**Status:** implemented; current Windows/Linux/service checks and two fresh AWS functional lifecycles passed 2026-10-11. The frozen independent verdict and unrun gates are recorded in the external handoff linked from the evidence page.

- [x] Disk observations drive the PRD trigger/recovery windows, critical severity, named filesystem evidence, and investigation steps. Preserve opening evidence, update the active incident, and create a new incident on recurrence.
- [x] Persist incident records in PostgreSQL and expose paginated/filterable summaries, detail evidence, active counts, and Grafana diagnosis views.
- [x] Establish the reusable harness: preparation checks, declared telemetry-based trigger, monotonic API timing, incident IDs, injection timing, bounded execution, interruption-safe cleanup, and diagnosis/recovery timeouts.
- [x] Demonstrate the complete disk injection-to-recovery flow and add parser/rule/API tests plus the disk runbook and measurement-record format.

All four core items have source and local/service/helper evidence. Two passing AWS runs demonstrate critical diagnosis, automatic resolution, preserved history and new recurrence IDs on node-a while node-b stays healthy. These are functional demonstrations; the calibrated five-run batch remains Task15. Source acceptance requires the independent verdict bound to the frozen manifest. See [runbook](../../../../docs/disk-full.md) and [evidence status](../../../../docs/task02-evidence.md).
