---
name: project-management
description: Create, track, and update work items (features/tasks) in any project-management tool — Linear, Jira, GitHub Issues, or a Markdown fallback — through one tool-agnostic workflow. Use when the user wants to plan a feature, break work into tasks, start/review/complete a task, change a work item's status, or connect/switch the project-management tool, or run a multi-agent team on a feature (orchestration with a team lead, principal architect, and cross-functional implementers). Language- and framework-agnostic.
allowed-tools: *
---

# Project Management Workflow

You manage work items in whatever project-management tool this project is configured to
use, speaking **only** the generic vocabulary — never a tool-specific word. This skill is
the operational front door; the details live in sibling files (paths are relative to this
skill's directory):

- `config/project-management.config.md` — selects the active tool + settings
- `reference/vocabulary.md` — the generic contract (terms, statuses, IDs, banned words)
- `reference/lifecycle.md` — the numbered scenarios you execute
- `reference/team-roles.md` — status ownership (only if `TEAM_MODE=true`)
- `reference/orchestration.md` — multi-agent protocol (mailboxes, gates, unblocking)
- `roles/<role>.md` + `config/team.config.md` + `bin/launch-team.sh` — the agent team
- `adapters/<Tool>.md` — how to perform each operation in the active tool

> **Golden rule:** in everything you write — comments, commit messages, messages to the
> user — refer to work items as `[feature]`, `[task]`, `[subtask]` and use the generic
> statuses `[Planned]`/`[Active]`/`[Review]`/`[Completed]`. Never write "issue", "epic",
> "story", or "ticket" outside the adapter. See the banned-terms list in `vocabulary.md`.

## Mandatory Preparation (every invocation)

1. **Read the config** (`config/project-management.config.md`). Note
   `PRODUCT_MANAGEMENT_TOOL`, the per-tool settings block, and the flags `TEAM_MODE` /
   `STRICT_STATUS`.
2. **Load the adapter** for that tool: `adapters/<PRODUCT_MANAGEMENT_TOOL>.md`. This is
   your only source for concrete operations, terminology, status, and ID mappings. If the
   file doesn't exist, stop and tell the user to create it from `adapters/_TEMPLATE.md`.
3. **Read `reference/vocabulary.md` and `reference/lifecycle.md`** if not already in
   context. If `TEAM_MODE=true`, also read `reference/team-roles.md` and `reference/orchestration.md`.
4. **Initialize the tool** exactly as the adapter's *Initialization* section says (a cheap
   read proving access works). If it fails: **stop** and tell the user to fix the adapter's
   *MCP / CLI Setup* — do not proceed.

## Executing the request

Map the user's ask to a scenario in `reference/lifecycle.md` and follow it, translating
each generic operation through the adapter's *Operations* table:

| The user wants to… | Scenario |
|---|---|
| Plan / spec a feature, break work into tasks | 1 — Plan a `[feature]` |
| Start / pick up / work on a task | 2 — Start a `[task]` |
| Note a change from what a task said | 3 — Diverge |
| Send a task for review | 4 — Request review |
| Finish / close out a task | 5 — Complete a `[task]` |
| File a bug / follow-up found mid-work | 6 — File newly-discovered work |
| (anything wrong / blocked / failed) | 7 — Andon cord: stop & report |
| Run an agent team on a feature ("launch the team") | Team: set `TEAM_MODE=true`, follow `reference/orchestration.md`; launch via `bin/launch-team.sh` |
| Connect a new tool / switch tools | 8 — Connect / switch |

## Non-negotiables (the fail-loud contract)

- **Every status change is a real write** through the adapter's mechanism — then confirm
  it. Never claim a status you didn't set.
- **If any operation fails, stop and report it** (Scenario 7). Never work around a failure
  or fabricate a result.
- **Never skip a status transition.** Move in order:
  `[Planned]` → `[Active]` → `[Review]` → `[Completed]` (rework: `[Review]` → `[Active]`).
- **When `STRICT_STATUS=true`, verify the current status before writing.** If it's not what
  the step expects, pull the andon cord instead of forcing the change.
- **`[Completed]` means verified-done** — reviewed, tests/build green, and (if your project
  couples them) committed. Never mark work complete that was skipped or is failing.

## Reporting back

After acting, tell the user: the `featureId`/`taskId` affected, the status transition you
made (`from → to`), and any comment you added — in generic vocabulary. If you created a
feature and tasks, list each `taskId` with its title and status.
