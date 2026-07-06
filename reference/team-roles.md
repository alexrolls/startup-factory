# Team Roles — Optional Status Ownership (multi-agent)

**Only relevant when `TEAM_MODE=true`.** In single-agent mode, one agent performs every
transition and this file is unused — skip it.

When several agents collaborate on one [feature], the danger is two agents driving the same
[task] at once, or a status moving without the responsible role knowing. The fix is
**exclusive ownership of each transition**: exactly one role may perform each status change,
and every role verifies the *from* status before acting (the andon-cord check from
`reference/lifecycle.md`).

The scenarios in `lifecycle.md` don't change — only *who* performs each write does.

---

## Roles

When running an actual agent team (`reference/orchestration.md`), the abstract roles map to concrete role names: Coordinator = `team-lead`, Implementer = `backend` / `frontend` / `qa`, Reviewer = `reviewer`, Finalizer = `integrator`, plus `principal-architect` (technical authority). Actionable instructions (mailboxes, escalation) always use the concrete names.

| Role | Owns |
|---|---|
| **Coordinator** | Plans the [feature], creates [tasks], assigns them, decides what new work enters the current iteration. Never writes code. |
| **Implementer** | Picks up a [task], writes the code, records divergences. |
| **Reviewer** | Reviews an implementer's work, approves or sends it back. Never modifies code. |
| **Finalizer** | Runs final validation, commits, and marks [tasks] `[Completed]`. The **single** role allowed to complete tasks and to couple completion with a commit. |
| **Principal Architect** | Technical authority: planning approval, per-[task] design gate, architecture half of every review, sole editor of upcoming [task] descriptions. Never writes code. |
| **Team Lead** | Process authority: plans, launches, supervises, unblocks, reassigns, escalates. Never writes code, never overrides Finalizer/Integrator or Principal Architect. |

Small teams collapse roles (one agent can be Reviewer + Finalizer). The ownership *table*
still holds — it's about which transition, not how many humans/agents exist.

---

## Transition ownership

| Transition | Sole owner | Pre-check before acting |
|---|---|---|
| create `[task]` `[Planned]` | Coordinator | planning approval from the Principal Architect exists (team mode — see `reference/orchestration.md`) |
| `[feature]` `[Planned]` → `[Active]` | Implementer (on the feature's first claimed [task]) | only if the adapter tracks feature status explicitly |
| `[Planned]` → `[Active]` | Implementer | verify `[task]` is `[Planned]` (not already claimed) |
| `[Review]` → `[Active]` | Implementer | verify `[task]` is `[Review]` (rework requested) |
| `[Review]` → `[Completed]` | Finalizer | verify `[task]` is `[Review]` **and** commit succeeded |
| `[feature]` → `[Resolved]` | Coordinator (team-lead) — after the completion checklist | verify **all** `[tasks]` are `[Completed]` |
| `[design-note]` → `[design-approved]`/`[design-pushback]` (comment gate, no status move) | Principal Architect | a `[design-note]` exists on the `[Active]` [task] |
| `[Active]` → `[Review]` | Implementer (with `[review-request]`) | verify `[task]` is `[Active]` and `[design-approved]` exists (team mode) |
| approve in `[Review]` (comment gate) | Reviewer (`[review-approval]`) **and** Principal Architect (`[architecture-approval]`) | both lists must match the diff |

If any role finds a [task] in an unexpected status, it **pulls the andon cord**: stop,
don't guess, escalate to the Coordinator (concrete role: `team-lead`).

---

## Coupling rules

- **Completion is coupled to a commit.** The Finalizer never marks `[Completed]` without a
  corresponding successful commit, and never commits a track without moving its [task] to
  `[Completed]`. The two are one atomic step.
- **Ad-hoc work has no [task].** If an agent is pulled off to fix something unrelated
  (e.g. a production incident), it does **not** touch task statuses for that work — it
  reports back and returns to its assigned [task]. File real follow-ups as new [tasks]
  (Scenario 6).
- **One implementer per [task] at a time.** Ownership of `[Planned]` → `[Active]` is how
  you enforce this: claiming the transition *is* claiming the task.

---

## Why this maps cleanly onto adapters

None of the above mentions a tool. "Move `[Review]` → `[Completed]`" is the same generic
operation whether the Finalizer is closing a GitHub issue, dragging a Linear card, or
editing a Markdown header. The role model is pure port; the adapter is pure translation.
That separation is the whole point — you can restructure your team without touching a
single adapter, and swap tools without touching a single role.

---

## Running an actual team

This file defines *ownership*. The full multi-agent mechanics — mailboxes,
heartbeats, claiming, the design gate, dual review, the unblock ladder, launching
heterogeneous LLM agents — live in `reference/orchestration.md` with one brief per
role in `roles/`. Configure the team in `config/team.config.md` and launch with
`bin/launch-team.sh`.
