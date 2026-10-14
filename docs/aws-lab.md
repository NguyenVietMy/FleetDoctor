# Start, deploy, inspect, stop, export and teardown

Use profile `fleetdoctor`, region `us-east-1`, with EC2/VPC/key-pair permissions and `ssm:GetParameter` for the public AL2023 AMI parameter. Never commit AWS credentials, private SSH keys, `.env`, Terraform state or saved plans. The application requires no IAM role or AWS API credentials on the VMs. Generate the dedicated local key with `ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\fleetdoctor"`. A passphrase-protected key must be loaded into your SSH agent before automated deployment; `BatchMode=yes` fails rather than prompting invisibly.

## Prepare and create the lab

```text
aws sts get-caller-identity --profile fleetdoctor
terraform -chdir=infra/aws init -backend=false
uv run python scripts/prepare_aws_plan.py --output-dir <external-plan-directory>
```

The preparer reads only the `.pub` file and detects the current owner IPv4 using AWS's checkip service, or accepts `--owner-ip`. Review its saved `terraform-plan.txt`/JSON and the [cost record](costs.md). The plan creates an isolated VPC/subnet/IGW/routes, monitor/node security groups, one public key pair and **three** encrypted gp3-backed instances, all in one supported AZ. Only owner `/32` SSH is public. Node security group can POST to the monitoring host's TCP8000 private address and send ICMP echo. Grafana/Prometheus bind only loopback; PostgreSQL has no host port.

Once creation is authorized, apply **that exact saved plan**:

```text
terraform -chdir=infra/aws apply <absolute-external-plan-directory>/lab.tfplan
uv run python scripts/lab.py show
```

State remains local and untracked. Preserve it privately; it is needed to clean up the exact resources. Bootstrap installs Python3.11, chrony and journald limits (100MiB), verifies cgroup v2 and installs Docker plus a checksum-verified Compose v2.38.2 plugin on the monitor. Check `sudo cloud-init status --wait`; failed cloud-init is a deployment failure, not a healthy demo.

## Deploy and view

Generate secrets with the **monitor's private IP** from Terraform output. For a Task04 run, an independent coordinator first freezes the approved checkout with `audit.py freeze`; that JSON binds the repository, baseline, HEAD, tree, plan hash, changed-file inventory, every inventoried file hash, diff hash and aggregate hash. Keep the freeze and all command outputs private and outside the checkout. Then deploy with the required source gate:

```text
uv run python scripts/create_env.py <external-path>/lab.env --collector-ip <monitor-private-ip>
uv run python scripts/deploy_lab.py --profile fleetdoctor --inventory <retained-inventory> --key <retained-key> --env <external-path>/lab.env --source-freeze <approved-source-freeze.json> --approved-plan-sha256 <approved-plan-sha256> --output <unique-deploy.json>
uv run python scripts/lab.py show
```

The deployer validates every file in the approved freeze before staging, again immediately before live activation, and at completion. A missing, unreviewed or changed file aborts before live effects when detected by the pre-stage gate. It builds a local wheel, ships its SHA256 and an agent-only hash-checked dependency export, and forces wheel reinstallation without rebuilding on nodes. Per-invocation private stage files use exact owned names and bounded cleanup in `finally`; cleanup failure is retained alongside the primary failure. This replaces installed code even when the package version is unchanged. Agents run unprivileged under systemd with `LoadCredential` for per-node tokens and a root-owned environment file for nonsecret configuration. Monitor Compose reads a mode0600 `.env`. Deployer uses exact account/inventory bindings and exact instance IDs to obtain **current public IPs** every time. Keep local secrets/exports private. Treat changed SSH host keys as a reason to verify the instance; the deployer never disables host-key checking.

Run the `ssh -L ...` command printed by `lab.py show` in a visible terminal and leave it open. This tunnels localhost ports 3000/9090 and port8000 to the monitor's private bind address. Visit http://127.0.0.1:3000 and use `admin` plus your generated Grafana password. Fleet and Node dashboards refresh every five seconds. Check both nodes are fresh with readable filesystem coverage. Public-IP service requests should be denied by the security group and bind address.

```text
uv run python scripts/healthy_demo.py --env <external-path>/lab.env --output <external-path>/aws-healthy.json
```

This polls both nodes once per second across a22-second window and requires at least four distinct consecutive observations in each stable agent session. It checks raw observed-time intervals of4.5-5.5s and zero upload-failure journal lines for the observed window. It also saves Prometheus history, Grafana provisioning/datasource/live queries, exact EC2 metadata/standard-credit settings, public service-port rejection and SSH-collected kernel/boot/cgroup/clock/systemd/Compose information. The shipped wheel, extracted source and modules imported by each deployed interpreter must match the local source. Agent import probes run outside the extracted archive and record the active service PID, start time and command line. The demo saves failures with partial evidence and uses separate HTTP connections through SSH. Read the output and visually inspect dashboards through the tunnel when a browser is available. Retain the source revision **and** uncommitted source snapshot until a commit is authorized; HEAD alone does not identify uncommitted code. This is a short healthy demo; the one-hour false-incident and measured overhead gate remains task 16. Investigate permissions, clocks, missing sources and stale observations; do not substitute fixture evidence.

## Task04 collector restart proof

Run only after the frozen source deployment and a fresh healthy preflight. The restart proof targets node-a's verified dedicated disk through the existing disk harness. It reserves a 240-second harness maximum, refuses callback admission unless at least 80 seconds remain, gives the restart callback one absolute 70-second deadline and bounds collector readiness to 45 seconds including time spent inside the successful health request. Normal ownership/status handoff consumes the allocated absolute budget but does not require a fresh 70 seconds. The harness retains ownership, watchdogs and cleanup; the callback restores the collector in its own `finally`. No production fault switch is installed.

```text
uv run python scripts/healthy_demo.py --profile fleetdoctor --inventory <retained-inventory> --key <retained-key> --env <retained-env> --output <unique-preflight.json>
uv run python scripts/restart_demo.py --profile fleetdoctor --inventory <retained-inventory> --key <retained-key> --env <retained-env> --preflight <unique-preflight.json> --source-freeze <approved-source-freeze.json> --output <unique-aws-restart.json>
uv run python scripts/healthy_demo.py --profile fleetdoctor --inventory <retained-inventory> --key <retained-key> --env <retained-env> --output <unique-postrun-healthy.json>
uv run python scripts/lab.py export --profile fleetdoctor --inventory <retained-inventory> --key <retained-key> --output <new-postrun-backup-directory>
```

The proof requires three real eligible high observations before restart, captures the incident and paired checkpoint directly from PostgreSQL and through the API, restarts only the collector, and proves a new collector process identity. It then checks retained duplicate/conflict behavior, recurrence and resolution invariants, node-b continuity, provisioned Grafana datasource results, bounded checkpoint state, source binding and final healthy restoration. Read the structured output: a simulated client-side post-COMMIT error is labeled as simulation, while transaction rollback and the collector restart use the actual database/service boundaries. Rendered Grafana inspection remains a separate human gate.

## Start and stop between sessions

```text
uv run python scripts/lab.py stop
uv run python scripts/lab.py start
```

These commands use only the three IDs in this Terraform state. Start waits for status checks and then describes those IDs to discover **new ephemeral public IPs**. Reopen tunnels using the newly printed addresses. Private addresses persist, so agent ingestion continues when monitor services restart. If the owner's IP changes, update owner_cidr using a new reviewed Terraform plan in a new external output directory. Existing instances retain their selected AMI when AWS updates the image parameter. Plan preparation rejects instance deletion or replacement by default and retains rejected plans as `rejected.tfplan`, leaving no normal apply path. `--allow-instance-deletion` explicitly permits planning those actions; applying them still requires separate owner authorization and an export. Standard CPU mode can throttle later experiments; record credits, do not silently change mode.

## Export and retire

While the lab is running and SSH works:

```text
uv run python scripts/lab.py export --output <new-local-backup-directory>
```

The export saves PostgreSQL SQL, consistent Prometheus/Grafana volume copies (briefly stopped with an exit trap to restart), and the stable inventory. Copy demo, measurement and billing files into your local evidence archive too. Verify backups are nonempty and inspect their contents. They may contain private data and should not be published blindly. No EBS snapshots are created.

When retirement is explicitly authorized, review `terraform -chdir=infra/aws plan -destroy` and run `terraform -chdir=infra/aws destroy`. **Destroy terminates the instances and deletes their root volumes**, so export first. Verify the exact IDs are terminated and the project's key pair, security groups, VPC/subnet/routes/IGW and volumes are removed. Reconcile delayed billing afterward. `stop` alone does not remove retained disk charges.
