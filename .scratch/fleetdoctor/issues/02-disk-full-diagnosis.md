# 02: Disk-full diagnosis

**What to build:** A bounded filesystem fill produces an evidence-supported disk incident in the API and Grafana; cleanup yields automatic resolution while preserving incident history.

**Blocked by:** 01: Healthy AWS fleet

**Status:** ready-for-agent

- [ ] Disk observations drive the PRD trigger/recovery windows, critical severity, named filesystem evidence, and investigation steps. Preserve opening evidence, update the active incident, and create a new incident on recurrence.
- [ ] Persist incident records in PostgreSQL and expose paginated/filterable summaries, detail evidence, active counts, and Grafana diagnosis views.
- [ ] Establish the reusable harness: preparation checks, declared telemetry-based trigger, monotonic API timing, incident IDs, injection timing, bounded execution, interruption-safe cleanup, and diagnosis/recovery timeouts.
- [ ] Demonstrate the complete disk injection-to-recovery flow and add parser/rule/API tests plus the disk runbook and measurement-record format.
