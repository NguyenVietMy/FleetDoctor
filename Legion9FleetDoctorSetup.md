# FleetDoctor setup on Legion 9

Prepared November 16, 2026. This transfers unfinished Ticket15 work. The PR stays
draft, and the remaining inspection finding stays open. This is a WIP checkpoint,
not approval to run the AWS campaign or a claim that Ticket15 is complete.

## 1. Get the current code

Install Git, GitHub CLI and uv on Windows. Sign in to GitHub with your own account.
Use a development folder outside OneDrive for the new checkout. In PowerShell:

```powershell
gh auth login
$checkoutRoot = Join-Path $env:USERPROFILE 'source'
New-Item -ItemType Directory -Path $checkoutRoot -Force | Out-Null
Set-Location $checkoutRoot
git clone --branch feat/task-15-chaos-validation-20261114-2152 https://github.com/NguyenVietMy/FleetDoctor.git
Set-Location FleetDoctor
git status --short
git log -1 --oneline
```

An ordinary clone of `main` only includes the merged Ticket14 baseline. The branch
above includes the Ticket15 WIP and this file. If the directory already exists,
inspect `git status` and preserve any local changes before switching branches or
pulling. Do not reset or overwrite another checkout.

The transfer folder's `TransferInfo.json` records the exact WIP commit. Check that
the checked-out commit matches it, or deliberately use a later commit on that branch.
PR: <https://github.com/NguyenVietMy/FleetDoctor/pull/15>.

## 2. Install dependencies and check the code

The project requires Python 3.11 or later. This command selects Python 3.12 and
rebuilds the environment from the committed lockfile; do not copy the old `.venv`.

```powershell
uv sync --python 3.12 --locked --all-extras
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests scripts
uv run pytest -q tests/test_chaos_campaign.py
```

The checkpoint's recorded local campaign module has 90 passing cases. The last
complete Windows product run had 832 passes and 142 platform skips; the private
operator had 241 passes. Those are historical results for these source bytes,
not results from Legion 9. Hosted CI on the exact new commit is a separate check:

```powershell
gh pr checks 15 --repo NguyenVietMy/FleetDoctor
```

For the local dashboard/services, install Docker Desktop with its Linux/WSL2
engine and start Docker. Generate new local secrets only if `.env` is absent:

```powershell
if (-not (Test-Path -LiteralPath .env)) {
    uv run python scripts/create_env.py .env
}
docker compose up -d --build --wait
```

See [README.md](README.md) for endpoints, service integration checks and the Linux
requirements for native fault helpers. Windows fixture tests do not replace the
Linux/systemd/cgroup tests. Creating a new local stack does not restore the old
Docker volumes; retained AWS backups remain private evidence.

## 3. Restore the private handoff

Sign in to the same personal OneDrive account and download both of these folders
fully before restoring. They are outside the Git repository:

- `OneDrive\FleetDoctor-Transfer\2026-11-16\`
- `OneDrive\FleetDoctor-TransferKeys\`

The first contains the encrypted archive, `age.exe`, `RestoreFleetDoctorHandoff.py`
and `TransferInfo.json`. The second contains the archive unlock identity
`Legion9FleetDoctor-20261116.agekey`. Keep that identity private and out of Git.
The archive uses age encryption; its Windows binary was downloaded from the
official `FiloSottile/age` v1.3.2 release and checked against the release's SHA256.

```powershell
$syncRoot = $env:OneDrive
if (-not $syncRoot) { $syncRoot = Join-Path $env:USERPROFILE 'OneDrive' }
$transferRoot = Join-Path $syncRoot 'FleetDoctor-Transfer\2026-11-16'
$archivePath = Join-Path $transferRoot 'FleetDoctor-Legion9-20261116.tar.gz.age'
$identityPath = Join-Path $syncRoot 'FleetDoctor-TransferKeys\Legion9FleetDoctor-20261116.agekey'
Test-Path -LiteralPath $archivePath
Test-Path -LiteralPath $identityPath

$ageHash = (Get-FileHash -LiteralPath (Join-Path $transferRoot 'age.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ageHash -ne '2821a4ed191da07372acd302e5f6feae7a7985e285e1417765ebe74025af45f0') {
    throw 'age.exe checksum differs; stop and verify the transfer.'
}

$privateRoot = Join-Path $env:USERPROFILE '.fleetdoctor-legion9-transfer-20261116'
uv run --no-project --python 3.12 python (Join-Path $transferRoot 'RestoreFleetDoctorHandoff.py') `
    --archive $archivePath --identity $identityPath --destination $privateRoot
```

The destination must not already exist. The restorer checks the encrypted archive
checksum, rejects unsafe archive paths and links, authenticates decryption, and
checks every restored file against the captured SHA256 manifest. It restores
files only; it does not run operator code, change AWS, import a database, or start
a guard. A failed or interrupted restore is not accepted; use a new destination
after diagnosing it, rather than overwriting a partial restore.

The private snapshot preserves the task directory's operator source, plans,
proofs, histories, source archives, current handoff and retained live evidence.
Caches, virtual environments and worktree `.git` links are omitted. It does not
copy this laptop's AWS credentials, SSH private key, Codex authentication, installed
programs, active processes or Docker daemon state. Archive-contained old `.env`
or runtime state is historical evidence, not a ready-to-use local configuration.

## 4. Resume from the actual stopping point

The restored directory is:

```text
<privateRoot>\task15-20261111-claudex\
```

Read these files there, starting with the small current handoff:

1. `LEGION9-CURRENT-HANDOFF.md`
2. `operator-inspect-20-cli\response.json`
3. `OPERATOR-INSPECTION-20-DISPOSITIONS.json`
4. `SOURCE20-INSPECTION-REVISE-VALIDATION.json`
5. `COORDINATOR-ACTIVE-HANDOFF-20261115T0704Z.md` (latest checkpoint at the end)

The remaining finding is `SANITIZED-EXCEPTION-CONTEXT-RETAINED` in
`scripts/chaos_campaign.py`: constant FD/OOM replacement errors still retain the
original external exception through `__context__`, and the FD pre-restore path
explicitly retains its cause. The next repair must discard the external exception
objects before raising safe errors and test the entire propagated cause/context
graph. Preserve terminal failure evidence, selector restoration, strict OOM
acceptance and confirmed release. The third source inspection returned REVISE;
the recorded review budget was exhausted. No source8/operator20 approval exists.

Use the fresh Git checkout for new edits. Restored worktree copies are historical
source/evidence without usable Git worktree links. Prior reports and approvals
remain bound to their original hashes and machines. Do not rewrite old evidence,
manufacture approval files, or treat this WIP push as an approved implementation.

Use the native Codex CLI with the existing subscription for this session. Herdr
and a paid model API fallback were not selected. Sign in separately on Legion 9;
authentication files are not part of this transfer. The repository's `AGENTS.md`
still requires all latest PR-commit CI checks to finish and pass after a push.

## 5. AWS stays stopped during the transfer

The existing three-instance lab was independently observed stopped while preparing
this checkpoint. No new campaign or operator20 context was initialized. Do not run
an old `init_live_operator*.py` or `launch_operator*_live_supervised*.ps1` simply
because it appears in the restored archive.

Code work and diagnosis can proceed without this laptop. Live AWS continuation
needs separate AWS sign-in/SSH access, current host trust, new machine/tool/path
bindings, current source review and a fresh preflight. Never copy old PID authority,
reuse old tokens or declare old trial rows accepted. The private operator contains
absolute paths and tool hashes for the original laptop; copying bytes does not
make those bindings valid on Legion 9.

The acceptance work still remaining after the code correction is a new complete
16-attempt/18-phase calibration, then 40 measured attempts/45 phases, original-state
restoration, private exports, exact stopped-lab/guard-exit proof and final published
evidence/CI. Ten failed or superseded histories are preserved. Ticket16's healthy
hour/overhead checks and owner acceptance remain separate. No merge is included.
