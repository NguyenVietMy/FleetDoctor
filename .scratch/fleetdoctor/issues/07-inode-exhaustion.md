# 07: Inode exhaustion

**What to build:** An engineer can distinguish inode exhaustion from block exhaustion and observe resolution after removing the test files.

**Blocked by:** 02: Disk-full diagnosis

**Status:** ready-for-agent

- [ ] Collect and display filesystem inode/block usage and diagnose the named resource using the PRD windows, severity, and evidence requirements.
- [ ] Use a bounded filesystem with a small inode budget; prove the trigger occurs while block space remains available.
- [ ] Demonstrate injection, saved diagnosis, cleanup, and recovery; add parser/rule/API checks and an inode runbook with supported attribution.
