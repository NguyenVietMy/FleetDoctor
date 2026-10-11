# Working with Herdr

Follow the local [claudex-loop skill](.agents/skills/claudex-loop/SKILL.md) for roles, settings, gates, and round limits.

- Verify the caller's workspace/pane through `HERDR_*`. If missing, match process ancestry with `herdr pane list` and `herdr agent list`. Stop if ambiguous; use verified returned IDs.
- Give each delegate a labelled tab with `--no-focus`. Start every inspection in a fresh tab/session. Verify the delegate's actual model and permissions.
- Keep unique result files and logs outside the checkout. Assign bounded scope, absolute input/output paths, and proof commands. Collect findings from result files.
- `done` or `idle` requires a valid result for the current assignment. Diagnose blocked, unknown, stalled, or timed-out agents using `agent get` / `agent read`. Send Enter once only if the prompt is visibly unsubmitted and the agent is ready.
- Use nonblocking waits and keep the user updated. Close only tabs created for this run, after retaining results.

Check installed CLI help before using these templates. Start the agent in `.result.root_pane.pane_id` returned by tab creation.

```text
herdr tab create --workspace <verified-id> --cwd <absolute-path> --label <role> --no-focus
herdr agent start <unique-name> --kind <claude|codex> --pane <returned-id> -- <verified-cli-flags>
herdr agent prompt <name> "<task and result-file path>" --wait --timeout 600000
```
