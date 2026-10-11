# AWS lab cost record

The Oct 11-25 calendar window includes 15 days. This conservative storage allowance supersedes the approved plan's initial 14-day approximation, as identified in plan review round 2.

Quote checked **2026-10-11**, region **us-east-1**, Linux On-Demand. Proposed capacity is one `t3.medium` monitoring host (4GiB) and two `t3.small` monitored hosts (2GiB each). All have 2vCPUs. Amazon Linux 2023 x86_64 supports cgroup v2. A common AZ for both types is selected from the account's current instance-type offerings during Terraform plan.

| Item | Conservative planning input | Estimated before credits |
| --- | --- | --- |
| Compute | 120 fleet-active hours x ($0.0418 + 2 x $0.0209) | $10.032 |
| Public IPv4 | 3 ephemeral addresses x 120 hours x $0.005 | $1.800 |
| Retained gp3 | 60GiB x $0.08/GiB-month x 15 calendar days / 30 | $2.400 |
| Shared transfer / later model contingency | Explicit reserve, including later DistributedKVStore/model phases | $3.000 |
| **Total planned** | 120 active hours during Oct 11-25 inclusive | **$17.232** |

The whole-project target is **$20 before credits**, not $20 per ticket. This estimate leaves about $2.77 beyond the explicit reserve. Credits do not reduce the recorded usage number. It is a planning estimate, not a guaranteed cap: keep an AWS Budget alert and inspect actual billing. Confirm the available credits, taxes, regional rates, transfer use and later model backend before spending. There are no NAT gateways, EIPs, managed databases, load balancers or billable EBS snapshots. Backups are downloaded locally. The retained-storage interval includes active hours; it does not add those hours again. The 30-day-month approximation is conservative here; actual AWS allocation varies.

Active compute plus IPv4 costs approximately **$0.0986/hour for the fleet**, with EBS in addition. Stopping releases ephemeral public IPs and stops instance compute billing; **EBS continues billing until disks are destroyed** ($4.80 per 30 days for 60GiB). Keep the lab stopped between sessions and export before teardown. Standard CPU credit mode avoids surplus credit charges, but sustained CPU may be throttled when credits run out. Record credit mode/balance and steal time in later measurement manifests; do not switch to unlimited without updating this estimate.

Price sources: [AWS T3 Linux pricing](https://aws.amazon.com/ec2/instance-types/t3/), [gp3 pricing](https://aws.amazon.com/ebs/pricing/), [public IPv4 pricing](https://aws.amazon.com/vpc/pricing/), [AL2023 cgroup v2](https://docs.aws.amazon.com/linux/al2023/ug/cgroupv2.html). Refresh quotes before applying a saved plan. Actual project billing is pending export; a passing fixture or live demonstration is not a billing record. The account currently has a USD35 monthly Budget, so the separate USD20 project alert remains an owner setup item.

Track every lab start/stop UTC timestamp and exact instance IDs. Export Cost Explorer **UnblendedCost**, daily, before credits/refunds, filtered by the project's activated cost-allocation tag `Project=FleetDoctor`; tag activation and billing data can lag. Inspect account-level EC2, EBS, VPC/public IPv4 and transfer totals as well so untagged charges are not silently omitted. Include any future model inference charges. Retain raw billing exports and reconcile instance active hours/retained disks; report unallocated account charges explicitly rather than guessing the lab's share.
