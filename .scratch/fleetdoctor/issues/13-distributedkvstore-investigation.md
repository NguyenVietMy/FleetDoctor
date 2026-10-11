# 13: DistributedKVStore investigation

**What to build:** An engineer can follow a successful DistributedKVStore read/write workload through syscall/packet captures and correlated FleetDoctor observations.

**Blocked by:** 05: CPU saturation; 06: Workload OOM; 08: FD pressure; 09: Network degradation; 11: I/O bottleneck

**Status:** ready-for-agent

- [ ] Run the existing supported topology within the three-VM lab and monitor its configured processes/resources. Record revision, placement/shared-host limits, workload, and successful read/write outputs.
- [ ] Retain timestamped strace and tcpdump captures, tool versions, and corresponding CPU/memory/FD/disk-I/O/network metric ranges.
- [ ] Write an evidence-supported investigation explaining storage/network flow and tracing effects, with reproducible setup, capture, and cleanup instructions.
