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
INTEGRATOR_CMD="claude -p \"$(cat '{prompt_file}')\" --permission-mode acceptEdits"
BACKEND_CMD="codex exec --full-auto \"$(cat '{prompt_file}')\""
FRONTEND_CMD="codex exec --full-auto \"$(cat '{prompt_file}')\""
QA_CMD=null
REVIEWER_CMD="gemini --yolo \"$(cat '{prompt_file}')\""
TEAM_DEFAULT_CMD="claude -p \"$(cat '{prompt_file}')\" --permission-mode acceptEdits"
```

> Mixing LLMs is the design intent — e.g. Claude for team-lead/principal-architect,
> Codex for implementers, Gemini for review diversity. Same-LLM teams work too.
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
POLL_INTERVAL_SECONDS=120        # How often idle agents re-check mailbox + tracker
STUCK_AFTER_MINUTES=15           # Lead treats silence longer than this as "stuck"
ESCALATE_AFTER_ATTEMPTS=2        # Failed unblock attempts before the Lead escalates to the human
```

## Validation commands (framework-agnostic Integrator)

The Integrator runs these before every merge+commit. Set them to your project's real
commands; `null` skips that check (allowed, but the Integrator records the skip in
its completion comment on the [task]).

```
VALIDATE_BUILD=null              # e.g. "npm run build" / "dotnet build" / "cargo build"
VALIDATE_TEST=null               # e.g. "npm test" / "pytest" / "go test ./..."
VALIDATE_LINT=null               # e.g. "npm run lint" / "ruff check ."
```

## Rules

- These keys are read with a plain `grep '^KEY='` — keep one `KEY=value` per line
  inside the fenced blocks, no spaces around `=`.
- Never put tracker credentials here. API keys live in environment variables named
  by the active adapter (see `adapters/<Tool>.md` → *Access mechanisms*).
