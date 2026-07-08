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
| **Finalizer** | Runs final validation, commits, and moves [tasks] to `[Ready to deploy]`. The **single** role allowed to perform the `requiresCommit` move and to couple that move with a commit. |
| **Principal Architect** | Technical authority: planning approval, per-[task] design gate, architecture half of every review, sole editor of upcoming [task] descriptions. Never writes code. |
| **Team Lead** | Process authority: plans, launches, supervises, unblocks, reassigns, escalates. Never writes code, never overrides Finalizer/Integrator or Principal Architect. |

Small teams collapse roles (one agent can be Reviewer + Finalizer). The ownership *table*
still holds — it's about which transition, not how many humans/agents exist.

---

## Status ownership — derived from the board config

Ownership is no longer a hard-coded table. `config/statuses.config.json` assigns every
status an `owner` — a single agent (`{"role": ...}`) or a team (`{"team": ...}`). One
rule derives everything:

> **The owner of status S is the only party allowed to work items sitting in S, and the
> only one allowed to perform S's outbound transitions.**

Ownership is about *authoring* a transition, not typing it: in single-writer mode
(`TRACKER_WRITERS=lead`, see `reference/orchestration.md` → *Tracker write modes*) the
team-lead performs every physical write on behalf of the authoring role, and these
ownership checks apply to the role that authored the change.

Two refinements:

- **Entering a `requiresCommit` status** is performed by *that* status's owner, atomically
  with the commit (on the default board: the integrator commits and moves `[Review]` →
  `[Ready to deploy]` after both approvals exist).
- **Routing:** when an item enters a status, the mover notifies the new owner's mailbox
  (`reference/orchestration.md` → *Status routing*). A `{"team": ...}` owner is reached
  via that team's lead, who dispatches internally.

Worked example — the default board:

| Status | Owner | May perform |
|---|---|---|
| `[Planned]` | team-lead (Coordinator) | create [tasks]; sanction claims (`Planned → Active`) |
| `[Active]` | implementer | `Active → Review` (with `[review-request]`), `Active → Blocked` |
| `[Review]` | reviewer | `Review → Active` (findings); approval hands off to the integrator for `Review → Ready to deploy` |
| `[Blocked]` | team-lead | `Blocked → Planned / Active / Review` once cleared |
| `[Ready to deploy]` | integrator | terminal — the atomic commit+move that enters it |

Feature statuses: the team-lead owns all three (`Planned`, `Active`, `Resolved`) and
moves `[feature]` → `[Resolved]` only after the completion checklist passes.

If any role finds a [task] in an unexpected status, it **pulls the andon cord**: stop,
don't guess, escalate to the Coordinator (concrete role: `team-lead`).

---

## Coupling rules

- **Entering a `requiresCommit` status is coupled to a commit.** The Finalizer never moves a [task] to `[Ready to deploy]` without a corresponding successful commit, and never commits a track without the move. The two are one atomic step.
- **Ad-hoc work has no [task].** If an agent is pulled off to fix something unrelated
  (e.g. a production incident), it does **not** touch task statuses for that work — it
  reports back and returns to its assigned [task]. File real follow-ups as new [tasks]
  (Scenario 6).
- **One implementer per [task] at a time.** Ownership of `[Planned]` → `[Active]` is how
  you enforce this: claiming the transition *is* claiming the task.

---

## Why this maps cleanly onto adapters

None of the above mentions a tool. "Move `[Review]` → `[Ready to deploy]`" is the same generic
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
