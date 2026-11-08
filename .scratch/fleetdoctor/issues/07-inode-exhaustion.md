# 07: Inode exhaustion

**What to build:** An engineer can distinguish inode exhaustion from block exhaustion and observe resolution after removing the test files.

**Blocked by:** 02: Disk-full diagnosis

**Status:** merged in [PR #6](https://github.com/NguyenVietMy/FleetDoctor/pull/6); implementation delivered. Remaining validation is recorded below.

- [x] Collect and display filesystem inode/block usage and diagnose the named resource using the PRD windows, severity, and evidence requirements.
- [x] Use a bounded filesystem with a small inode budget; prove the trigger occurs while block space remains available.
- [x] Demonstrate injection, saved diagnosis, cleanup, and recovery; add parser/rule/API checks and an inode runbook with supported attribution.

**Verified scope:** Fixture/service checks plus real bounded ext4 inode exhaustion, diagnosis, cleanup and recovery in native Linux CI; AWS calibration remains separate.

**Evidence:** [Task07 handoff record](../../../docs/task07-evidence.md), [current delivery and CI status](../../../docs/delivery-status.md).
