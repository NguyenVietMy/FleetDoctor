---
name: astra-loop
description: "The FurnitureOS feature workflow, hosted in Codex, run in visible Herdr tabs. Grill the user into a plan, harden it through three rounds of independent Claude review, split it into GitHub issues, then build phase by phase with Claude as executor and a fresh inspector on every phase diff. Use for 'astra-loop', 'new feature', or 'let's build X'."
---

# Astra Loop

Astra hosts every stage. Claude reviews the plan, Claude builds, and a **fresh Codex session** inspects each phase diff. Every delegated agent runs in its own labelled Herdr tab so the user can watch and intervene without the layout being resized. The orchestrator conversation owns requirements, arbitration and sequencing, and never becomes a reader of raw diffs.

## Roles

| Stage | Who | Session |
|---|---|---|
| Grill, plan, arbitrate | Astra | This conversation |
| Plan review | Claude | One `reviewer` tab, reprompted across rounds |
| Build | Claude | Fresh `builder-p<N>` tab per phase |
| Diff inspection | Codex | **Fresh** `inspector-p<N>` tab per inspection, never this one |

Roles are fixed here; this is the `host=codex, builder=claude` configuration of [claudex-loop](../claudex-loop/SKILL.md). Do not swap them mid-run. Read [the build reference](../claudex-loop/references/build.md) before the first build.

## Transport — Herdr tabs

Verify you are inside Herdr before any control command:

```bash
test "${HERDR_ENV:-}" = 1
```

If that fails, say so and stop. Do not fall back to headless silently — the user chose visible tabs so they can watch. Herdr's own CLI is authoritative for syntax; run `herdr tab`, `herdr agent` or `herdr --skill` to confirm a command before relying on it.

**Spawn a delegate.** Each delegate gets its own tab, labelled with its role, created in the
background so the user's focus never moves:

```bash
herdr tab create --workspace "$HERDR_WORKSPACE_ID" --cwd "$PWD" --label "<role>" --no-focus
```

Read the new tab's pane from `.result.root_pane.pane_id` — that pane is already at an
interactive shell prompt — then start the agent with a unique name:

```bash
herdr agent start <name> --kind <claude|codex> --pane <root-pane-id> -- <flags>
```

Never split panes for delegates. Tabs keep every agent full-width and leave the user's
layout alone.

| Delegate | Kind | Flags after `--` |
|---|---|---|
| Reviewer | `claude` | `--strict-mcp-config --mcp-config '{"mcpServers":{}}' --tools Read,Glob,Grep,Write --allowedTools Read,Glob,Grep,Write --dangerously-skip-permissions` |
| Builder | `claude` | `--dangerously-skip-permissions` |
| Inspector | `codex` | `--dangerously-bypass-approvals-and-sandbox` |

The reviewer and inspector get no shell tool. That, not the permission prompt, is what keeps them from mutating the repo. They need `Write` only to emit their result file.

**The result contract.** Every prompt ends by naming an output file. Prompt, wait, then read the **file**:

```bash
herdr agent prompt <name> "<task>. Write your result as JSON to <ARTIFACTS>/<name>.json with keys verdict (APPROVED|REVISE|BLOCKED), findings (array), coverage (string), limitations (string). Reply with only DONE." --wait --timeout 600000
```

`agent prompt --wait` settles on `idle`, `done` or `blocked`. **A background tab settles on
`done`, not `idle`** — `idle` requires the tab to have been seen in the focused UI, and a
delegate tab created with `--no-focus` never has been. Treat `done` as the normal success
state and do not wait for `idle`. `blocked` means an approval or question dialog is up: inspect it, surface it to the user, and never answer it on their behalf. `agent_prompt_stalled` means no lifecycle change within five seconds — diagnose, do not re-prompt blindly.

**Session continuity is the tab.** Re-prompting the same named agent continues its session; there is no `--resume` UUID to pass. Record `agent_session.value` from `agent start` in the log so the session is identifiable afterwards.

**Fresh means a new tab.** An inspector must be a newly started agent in a newly created tab
every time. Close the tabs you created when their phase is done with `herdr tab close <tab-id>`;
never close a tab you did not create.

## Tunables

| Argument | Default | Meaning |
|---|---|---|
| `PLAN_FILE` | `<ARTIFACTS>/PLAN.md` | Feature plan. Lives **outside** the checkout. |
| `LOG_FILE` | `<ARTIFACTS>/ASTRA-LOG.md` | Append-only transcript of rounds and dispositions. |
| `ARTIFACTS` | `%TEMP%/astra-loop/<feature-slug>` | Run directory outside the repo. |
| `rounds` | `3` | Plan-review rounds before stopping. |
| `MAX_FIX_ROUNDS` | `3` | Maximum build-fix attempts per phase, also bounded by the inspection cap. |
| `MAX_INSPECTION_ROUNDS` | `3` | Total inspections per phase: initial, plus up to two after fixes. |

Echo roles, paths and round limits before starting. **Artifacts must live outside the checkout** — a plan or log written into the repo makes it dirty and fails the clean-checkout gate.

## Gates you must enforce yourself

Herdr transport does not run `runner.py`, so its gates are yours to apply:

- **Approval binding.** Record the SHA256 of `PLAN_FILE` when review returns `APPROVED`. Re-check it before every build; any edit voids the approval.
- **Clean checkout.** `git status --porcelain --untracked-files=all` must be empty before a delegated build. Use a worktree rather than stashing live work. Do not commit merely to pass the gate.
- **Baseline.** Record the pre-build commit SHA before prompting the builder.
- **Diff for the inspector.** Generate it to a file and pass the *path*, never the contents:
  ```bash
  git diff --no-ext-diff --binary <base> -- > "$ARTIFACTS/phase-<N>.diff"
  git status --porcelain --untracked-files=all > "$ARTIFACTS/phase-<N>.manifest"
  ```
  Redirecting to disk keeps the diff out of your context. Tell the inspector to open added and untracked files listed in the manifest, not only the diff.
- **Snapshot integrity.** Re-check the baseline and worktree state after an inspection returns. If code changed mid-inspection, the verdict does not apply.

## Stage 1 — Grill

Run the [grilling](../grilling/SKILL.md) skill against the feature. Work the design tree in rounds: ask the whole frontier at once, numbered, each with your recommended answer, then wait. Do not draft a plan while questions remain open.

Read `CONTEXT.md` and the ADRs under `docs/adr/` first, and use that vocabulary. Record a new ADR only for an expensive-to-reverse, non-obvious trade-off.

## Stage 2 — Draft the plan

Write `PLAN_FILE` with goal and observable acceptance criteria, the approach with its key decisions, trade-offs and non-goals, confirmed assumptions with sources, residual risks, and exact proof commands with expected results. Derive proof commands from the repo; ask only if what counts as success is genuinely unclear.

Start `LOG_FILE` with roles, scope, authorization and round limits.

## Stage 3 — Three rounds of Claude review

Spawn one reviewer and keep it for all three rounds. Round N writes `<ARTIFACTS>/review-<N>.json`.

Each round, **you arbitrate**: judge every finding, implement the ones you accept, reject the rest with reasons. Then **stop and show the user** a table of finding, severity, your disposition and rationale. Their sign-off gates the next round. Append dispositions to `LOG_FILE`, and include them in the next round's prompt.

Read the verdict from the result file:

- **APPROVED** — record the plan SHA256. Any later edit voids it.
- **REVISE** — arbitrate, revise, reprompt.
- **BLOCKED or malformed** — never approval. Report the missing evidence. Do not burn rounds on blind retries.

Stop at `rounds`. If findings remain unresolved, present them with your position rather than manufacturing convergence. Close the reviewer's tab when the stage ends.

## Stage 4 — Split into phases

Run [phase-split](../phase-split/SKILL.md) against the approved plan. Each phase is a **tracer bullet**: a narrow but complete path through every layer, demoable on its own, sized to fit one fresh context window, declaring the phases that block it. Prefactoring goes first. A wide refactor is the exception and is sequenced expand–contract instead.

Present the numbered breakdown and iterate until the user approves it, then publish one GitHub issue per phase in dependency order via `gh`, per `docs/agents/issue-tracker.md`, labelled `ready-for-agent`.

Skip this stage only if the plan already carries an approved phase breakdown.

## Stage 5 — Build and inspect, phase by phase

Work the **frontier**: any phase whose blockers are all closed. For each phase:

1. **Materialise the phase spec.** Write `<ARTIFACTS>/phase-<N>.md` from the issue body, outside the checkout. Never pass the whole feature plan as a phase spec.
2. **Check the gates.** Approval SHA still valid, checkout clean, baseline commit recorded.
3. **Build.** Create a `builder-p<N>` tab, prompt it with the phase spec path, the acceptance criteria and the exact proof command. It writes `<ARTIFACTS>/build-<N>.json`.
4. **Run the proof commands yourself.** A builder's own success report is not verification.
5. **Inspect.** Generate the diff and manifest to files, create a **fresh** `inspector-p<N>` tab (kind `codex`), prompt it with those paths and the phase spec. It writes `<ARTIFACTS>/inspect-<N>.json`.
6. **Disposition findings.** Reprompt the builder with accepted fixes, rerun affected proofs, then inspect again in a **new** inspector tab. Stop at `MAX_FIX_ROUNDS` and `MAX_INSPECTION_ROUNDS`; report what remains rather than claiming approval.
7. **Close the issue** only after its acceptance criteria are met and its inspection is clean. Close the phase's tabs, then take the next frontier phase.

## Context hygiene

This is a hard constraint, not a preference.

- **Never read a raw diff into this conversation.** `git diff`, `git show` and reading changed files wholesale are off-limits. Redirect diffs to disk and pass paths.
- **Read result files, not terminals.** `herdr agent read` is for diagnosing a stalled or blocked agent only — never for collecting findings. Terminal transcripts also truncate: rows lost to an agent's alternate screen never reach scrollback, so reading one is unreliable as a data channel as well as unsafe for context.
- From a result file, take verdict, findings, coverage and limitations. Leave evidence bodies on disk and cite them by path.
- Each phase's build and inspection are separate agents. Do not carry one phase's file-level detail into the next; the phase spec and the issue are the interface.
- If you take over coding yourself, you have become a builder. A fresh Claude agent in its own tab must then inspect your changes.
- Artifact directories may contain private code and plans. Keep them outside the checkout and never commit them.

## Reporting

Close the run with: phases delivered, proof results per phase, inspection coverage, unresolved findings, deviations from the plan, and rounds used against budget. Commits, pushes and releases follow existing authorization; running this loop does not imply any of them.
