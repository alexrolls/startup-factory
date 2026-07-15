# Team Configuration

The **one file you edit per project to run an agent team.** It maps each role to the
CLI command that runs it (this is the entire LLM coupling — one line per role), sets
coordination timings, and tells the Integrator how to validate work in *your* stack.
Read by `bin/launch-team.sh` and included in every agent's startup prompt.

The project-management tool itself is configured separately in
`project-management.config.md` — the team layer only consumes that port.

---

## Role → command map

`{prompt_file}` is replaced by the launcher with the path to the composed startup
prompt. The examples inline the file's content with `$(cat '{prompt_file}')` because these CLIs take the prompt as a string argument; a CLI that reads a prompt from a file can use `{prompt_file}` directly. Any agentic CLI works if it can read files, run shell commands, and use git.
Set a role to `null` to exclude it from launches (the team-lead composes the actual
roster per [feature] — e.g. no frontend [tasks] → no frontend agent).

```
TEAM_LEAD_CMD="claude -p \"$(cat '{prompt_file}')\" --permission-mode acceptEdits"
PRINCIPAL_ARCHITECT_CMD="claude -p \"$(cat '{prompt_file}')\" --permission-mode acceptEdits"
SCEPTICAL_ARCHITECT_CMD="codex exec --full-auto \"$(cat '{prompt_file}')\""
INTEGRATOR_CMD="claude -p \"$(cat '{prompt_file}')\" --permission-mode acceptEdits"
BACKEND_CMD="codex exec --full-auto \"$(cat '{prompt_file}')\""
FRONTEND_CMD="codex exec --full-auto \"$(cat '{prompt_file}')\""
QA_CMD=null
REVIEWER_CMD="gemini --yolo \"$(cat '{prompt_file}')\""
TEAM_DEFAULT_CMD="claude -p \"$(cat '{prompt_file}')\" --permission-mode acceptEdits"
TASK_FAST_CMD=null               # Optional task-level override for explicit or auto-detected
                                 # low-risk documentation/format/test/config tasks
TASK_STANDARD_CMD=null           # Optional task-level override; null falls back to the role command
TASK_STRONG_CMD=null             # Optional override for security/schema/concurrency/contract work
```

> Mixing LLMs is the design intent — e.g. Claude for team-lead/principal-architect,
> Codex for the sceptical-architect and implementers, Gemini for review diversity.
> Use a different model family or provider for the two architect roles when
> possible; role separation without model diversity reduces authority bias but
> does less to reduce correlated reasoning errors. Same-LLM teams still work.
>
> **Preset teams** (`teams/`) carry many specialized role names. Rather than a key
> per role, an *absent* key falls back to `TEAM_DEFAULT_CMD`. Add a `<ROLE>_CMD`
> line — e.g. `SENIOR_STAFF_ENGINEER_CMD` — only to pin a specific CLI to that
> role, or set it explicitly to `null` to disable the role (a `team` launch skips
> it; a direct `start`/`relaunch` of it is refused). Resolution per role:
> explicit `null` → disabled; a set value → used; absent → `TEAM_DEFAULT_CMD`.

## Coordination

```
TEAMWORK_ROOT=.teamwork          # Team workspace root (repo-relative). Add to .gitignore.
AGENT_ENV_ALLOWLIST="PATH TMPDIR LANG LC_ALL TERM NO_COLOR"
                                 # Complete environment inherited by LLM processes. The launcher
                                 # starts them with env -i, then adds only these non-secret names
                                 # plus fixed STARTUP_FACTORY_* role metadata and the hardening
                                 # value AWS_EC2_METADATA_DISABLED=true. PATH is required.
POLL_INTERVAL_SECONDS=120        # Fallback only; local runtime events wake dispatch within ~1s
STUCK_AFTER_MINUTES=15           # Lead treats silence longer than this as "stuck"
ESCALATE_AFTER_ATTEMPTS=2        # Failed unblock attempts before the Lead escalates to the human
TRACKER_WRITERS=broker           # broker = single-writer mode: only deterministic dispatcher/
                                 # supervisor processes hold credentials and post on agents' behalf
                                 # (reference/orchestration.md → "Tracker write modes")
EXECUTION=sequential             # Both modes use one task branch/worktree per task attempt.
                                 # sequential = one implementation task in flight; parallel =
                                 # dependency/resource-aware bounded waves. Gate roles stay
                                 # batched queue consumers and feature-branch integration is serial.
MAX_ACTIVE_IMPLEMENTERS=null     # Only under EXECUTION=parallel. 1 = pipelined dispatch:
                                 # full worktree isolation, but the team-lead dispatches
                                 # the next [task] when the current one enters [Review]
                                 # instead of after integration (reference/orchestration.md
                                 # → "Execution modes"). >=2 = bounded full parallelism;
                                 # null = conservative default of 2. Setting it under sequential
                                 # is a config error — the launcher refuses to run.
WORKTREE_SETUP=null              # Run once inside every freshly created task worktree, fail-loud
                                 # through the same sandbox runner and env -i boundary as workers
                                 # (e.g. "pnpm install --frozen-lockfile && pnpm build").
                                 # null = bare worktree. Provisioning is what makes
                                 # implementer validation claims executable — an
                                 # unprovisioned tree produced the false-green failure class.
AGENT_SANDBOX_RUNNER=null        # Absolute executable outside the agent repository. In enforced mode
                                 # the launcher invokes: runner --workdir <absolute> -- /usr/bin/env -i ...
                                 # It rejects symlinks, non-regular/non-executable files, foreign
                                 # owners, and group/world-writable runners.
AGENT_SANDBOX_ENFORCED=false     # true routes every LLM command and WORKTREE_SETUP through the runner.
                                 # Keep false only for manual/test execution without that boundary;
                                 # the autonomous PM supervisor refuses to launch while false.
BROKER_LIFECYCLE_ROOT=null       # Absolute pre-created mode-0700 directory, external and disjoint
                                 # from the repository. Required when AGENT_SANDBOX_ENFORCED=true
                                 # (or supply STARTUP_FACTORY_LIFECYCLE_STATE_ROOT to the broker).
                                 # Authenticated PID/start-time/tmux records live here; .teamwork
                                 # contains non-authoritative markers only. Agent sandboxes must not
                                 # be able to read or write this directory.
```

Review depth (`REVIEW_MODE=sequential|parallel|tiered`) is a **per-team** choice
and lives in the team file (`teams/<preset>.md`, next to `ROSTER=`), not here —
see `teams/_PLAYBOOK.md` → *Review modes*.

## Validation commands (framework-agnostic Integrator)

The Integrator runs these before every merge+commit. Set them to your project's real
commands; `null` skips that check (allowed, but the Integrator records the skip in
its completion comment on the [task]).

```
VALIDATE_BUILD=null              # e.g. "npm run build" / "dotnet build" / "cargo build"
VALIDATE_TEST=null               # e.g. "npm test" / "pytest" / "go test ./..."
VALIDATE_LINT=null               # e.g. "npm run lint" / "ruff check ."
VALIDATE_FORMAT=null             # e.g. "pnpm format:check" / "black --check ." — the CI
                                 # formatting gate. Runs after VALIDATE_LINT; null skips
                                 # (recorded). A formatter CI enforces but integration
                                 # doesn't run is a post-merge CI failure waiting to happen.
VALIDATE_SCRIPT=null             # alternative to the four above: a repo-relative script
                                 # that receives the changed-file list as arguments and
                                 # runs whatever applies (per-area suites, tools that only
                                 # exist mid-feature). When set, it replaces VALIDATE_*.
```

Validation **evolves during a feature**: the [task] that introduces a tool (a
linter, a new suite) updates `VALIDATE_SCRIPT` (or these keys) *and* the team's
`BASELINE.md` in the same diff, so every later [task] is judged by the new bar.
Results are always judged against `<TEAMWORK_ROOT>/<team>/BASELINE.md` — the bar
is "no new failures", not "all green".

## Rules

- These keys are read with a plain `grep '^KEY='` — keep one `KEY=value` per line
  inside the fenced blocks, no spaces around `=`.
- `TEAMWORK_ROOT` must be repository-relative and contain no `..`. Managed paths
  are resolved before use; an absolute root or any existing symlink component is
  rejected, including links between two in-repository team workspaces.
- `AGENT_ENV_ALLOWLIST` is a space-separated list of environment variable names,
  not values. Keep it small and non-secret. Privileged cloud/release variables are
  always refused, and tracker credentials are refused unless the explicit unsafe
  `TRACKER_WRITERS=all` mode is in use. `HOME` is intentionally absent because an
  ambient home commonly contains credential stores; if a model CLI requires it,
  allow only a dedicated sandbox home containing the minimum CLI-specific state.
- `AGENT_SANDBOX_RUNNER` must be an absolute protected executable outside the
  repository, owned by the executor or root, and not group/world-writable. It is
  responsible for enforcing worktree-only writes, hiding host/broker state, and
  applying network and process isolation before it executes the argv after `--`.
- Provision `BROKER_LIFECYCLE_ROOT` with mode `0700` under a path whose parent
  components are owned by root/the broker executor and not group/world-writable.
  No component may be a symlink; a leaf below shared `/tmp` is therefore refused.
  Keep the root outside every path mounted into an agent sandbox. In enforced mode the launcher refuses to start
  without this root. With both settings absent, manual launches are deliberately
  unmanaged: `status` never probes workspace-authored PIDs and `stop` refuses to
  signal anything, so the operator must supervise those processes directly.
- Never put tracker credentials here. API keys live in environment variables named
  by the active adapter (see `adapters/<Tool>.md` → *Access mechanisms*).
