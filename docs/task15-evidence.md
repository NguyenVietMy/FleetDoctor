# Ticket15 evidence status

Status: **correction4 implemented; targeted local Windows proof pending fresh independent inspection and coordinator-owned protected Linux/native checks**.

The corrections add exact selector inventory/CAS preservation, FD before-state checks, role-specific connection provenance, fixed ED25519 host pins, authenticated batch/session hello, actual protected role/instance/boot/host-key attestation and a fixed-origin read-only monitor relay. Correction4 separates immutable receipt identity from the ten-minute new-work freshness limit: delayed cleanup reauthenticates fresh sessions but is constrained to exact manifest-owned transaction lookup/adopt/restore. Synthetic authenticated subprocess tests exercise delayed 16-trial calibration and 40-attempt/45-phase CLI lifecycles; they remain non-AWS evidence.

Ticket14 is released at baseline `1b34a5d1abb364431c12860c1253e2f3b51af479`; retained main-CI run `43136058442` and its coverage receipt are external coordinator evidence. Its final one-line CI-path correction was coordinator-validated outside the earlier inspection budget; historical receipts are unchanged.

No calibration, 40-run AWS batch, deployment, cloud inventory refresh, billing check, publication CI, fresh independent source inspection or owner acceptance is claimed. Windows proof cannot replace Linux root/systemd/cgroup/dm-delay and service proof. See [the runbook](chaos-measurements.md) for exact commands and remaining work.
