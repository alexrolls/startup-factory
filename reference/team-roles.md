# Team Roles — Optional Status Ownership (multi-agent)

**Only relevant when `TEAM_MODE=true`.** In single-agent mode, one agent performs
ordinary transitions and this file is unused—except that `[Blocked]` remains a
human-only outbound state in every mode. A single agent may report a self-review,
but it cannot emit or claim any independent review-board approval.

When several agents collaborate on one [feature], the danger is two agents driving the same
[task] at once, or a status moving without the responsible role knowing. The fix is
**exclusive ownership of each transition**: exactly one role may perform each status change,
and every role verifies the *from* status before acting (the andon-cord check from
`reference/lifecycle.md`).

The scenarios in `lifecycle.md` don't change — only *who* performs each write does.

---

## Roles

When running an actual agent team (`reference/orchestration.md`), the abstract
roles map to concrete role names: Coordinator/quality reviewer = `team-lead`,
Implementer = `backend` / `frontend` / `qa`, optional Reviewer = `reviewer`,
Finalizer = `integrator`, plus `principal-architect`, `sceptical-architect`, and
`security-reviewer`. Actionable instructions always use the concrete names.

| Role | Owns |
|---|---|
| **Coordinator** | Plans the [feature], creates [tasks], assigns them, decides what new work enters the current iteration. Never writes code. |
| **Implementer** | Picks up a [task], writes the code, records divergences. |
| **Reviewer** | Optional specialist review evidence. Never replaces a mandatory review-board verdict or modifies code. |
| **Finalizer** | Runs final validation, writes the feature-branch integration commit, and moves [tasks] to `[Ready to deploy]`. The **single** role allowed to perform the `requiresCommit` move. |
| **Principal Architect** | Primary architecture position: planning approval, per-[task] design gate, architecture review, and sole editor of upcoming [task] descriptions. Never writes code. |
| **Sceptical Architect** | Mandatory in every cross-functional team. Independent blind-first challenge: planning/design peer review and release-bound architecture approval. Never writes code and cannot be disabled or omitted. |
| **Senior Security Engineer** | On-demand independent security reviewer: threat modeling, abuse-path analysis, focused verification, and `[security-approval]` or findings when `security` is an effective gate. Always rostered by Deep Infra and Deep Security. Never writes the reviewed code. |
| **Team Lead** | Process authority and mandatory independent quality/specification reviewer. Never writes code or overrides another mandatory gate, the Finalizer/Integrator, CI, or unresolved Critical risk. |
| **Release Executor** | Deterministic, credential-separated production transaction. It alone performs the terminal [feature] transition after independent production verification; it is not an LLM role. |

Optional implementation/specialist roles may be omitted. In team mode the Team
Lead, Principal Architect, and Sceptical Principal Architect remain three
distinct rostered agents. A separately mapped Security Engineer remains
launchable on demand and is rostered by default for Deep Infra and Deep Security.

## Review rounds and time limits

The Sceptical Architect's pushback budget defaults to **two review rounds per
decision**, not two findings. One round is an independent assessment of the
current design or package and its evidence; it may contain any number of
findings. A response to revised evidence begins the next round. Record the
round number, scope, findings, and resolution in the tracker/decision ledger.
After two unresolved rounds, send a neutral decision packet to an independent
Team Lead; a conflict of interest or unresolved Critical risk goes to the human.
Track non-blocking follow-ups with owners and deadlines instead of expanding
the current task silently.

Each per-task review round has a **45-minute default wall-clock time limit**.
The operator or external timer records its start/deadline and triggers the
escalation; an LLM must not promise to wake itself. At expiry the reviewer
publishes completed checks, findings, missing evidence, and remaining work. The
Lead may narrow scope, assign help, or record an explicit extension and owner.
Partial evidence is not approval: neither a timer nor an exhausted budget
waives validation/CI, any mandatory independent verdict, production policy, or
an unresolved Critical finding. Escalation itself never accepts risk.

## Harness delivery evidence

Without protected per-instance capabilities, harness subagents provide advisory
reports only. The minimum handoff is a recorded design-gate decision, two
independent architect reports, applicable target-environment acceptance evidence
(or reasoned non-applicability), and a tracker comment linking the exact package
and limitations. The configured writer may place this work in `[Review]`; only
authenticated gate roles may authorize the later integration. This profile
creates no broker identity, mandatory approval, `[Ready to deploy]` authority,
or production access. See `reference/orchestration.md` for the evidence contract.

---

## Status ownership — derived from the board config

Ownership is no longer a hard-coded table. `config/statuses.config.json` assigns every
status an `owner` — a single agent (`{"role": ...}`) or a team (`{"team": ...}`). One
rule derives everything:

> **The owner of status S is the only party allowed to work items sitting in S, and the
> only one allowed to perform S's outbound transitions.**

Ownership is about *authoring* a transition, not typing it: in deterministic
single-writer mode (`TRACKER_WRITERS=broker`, see `reference/orchestration.md` →
*Tracker write modes*) the credentialed dispatcher performs every physical write
on behalf of the authoring role, and these ownership checks apply to that role.
For protocol gate markers, the broker derives that role from the launcher's
verified per-instance capability; a claimed actor field or tracker signature is
not an identity.

Refinements:

- **Entering a `requiresCommit` status** is performed by *that* status's owner
  after the integration commit succeeds (on the default board: the integrator
  commits and records an immutable transaction; the dispatcher independently
  validates it and idempotently writes `[Review]` → `[Ready to deploy]` after
  all three core approvals and every declared supporting approval exist).
- **Routing:** when an item enters a status, the mover notifies the new owner's mailbox
  (`reference/orchestration.md` → *Status routing*). A `{"team": ...}` owner is reached
  via that team's lead, who dispatches internally.
- **Terminal [feature] transition:** the destination's configured
  `release-executor` owner is the only authority that may enter it, and only
  after verified production success. The team-lead's completion checklist is a
  handoff, not authority to resolve. The broker refuses the terminal write
  without the release-executor flag; because an environment flag is not an
  authenticated identity, the operator must also keep tracker credentials out
  of every agent sandbox.
- **Human-held task transition:** `[Blocked]` has an explicit
  `transitionAuthority`. A verified team-lead or deterministic PM supervisor may
  enter it. Its owner is `human`, and every outbound transition is automation-
  forbidden even though the graph lists destinations so a human action can be
  normalized. A human return to queued starts resume review; direct movement to
  working/review is manual takeover. Enforce human-only exit with the
  project-management tool's workflow ACL; the normalized adapter cannot attest
  the actor of an external move.

Worked example — the default board:

| Status | Owner | May perform |
|---|---|---|
| `[Planned]` | team-lead (Coordinator) | create [tasks]; sanction claims (`Planned → Active`); enter Blocked when necessary |
| `[Active]` | implementer | `Active → Review` (with `[review-request]`); route a real block to the team-lead/PM authority |
| `[Review]` | three-agent core board plus declared supporting reviewers | `Review → Planned` (findings/rework); core and declared-gate approvals hand off to the integrator for `Review → Ready to deploy`; route a real block to the team-lead/PM authority |
| `[Blocked]` | human | Only the human may perform `Blocked → Planned / Active / Review`. Startup Factory stops/fences that task and cannot perform these moves. |
| `[Ready to deploy]` | integrator | terminal — entered after a recorded integration commit |

Feature statuses: the team-lead works `[Planned]`/`[Active]`, but the configured
terminal status is owned by the
`release-executor`. The lead's completion checklist hands off; it never resolves
the [feature]. Disabled, waiting, denied, failed, or rolled-back delivery remains
visible and non-terminal. Only verified production success triggers `[Resolved]`.

If any role finds a [task] in an unexpected status, it **pulls the andon cord**:
stop that action/[task], don't guess, and escalate to the Coordinator (concrete
role: `team-lead`). Independent portfolio work continues.

---

## Coupling rules

- **Entering a `requiresCommit` status is coupled to a commit.** The Finalizer
  never moves a [task] to `[Ready to deploy]` without a corresponding successful
  integration commit. If the tracker write fails after the commit, the durable
  transaction remains pending and retry completes the same move/comment without
  creating another commit.
- **Late findings supersede; they do not erase.** Before production release, a
  later legitimate finding causes the deterministic broker to journal an exact
  recovery record, commit a validated revert, archive the old transaction, and
  reopen the task to queued/`[Planned]` through the broker-only terminal-reopen operation.
  A new attempt must merge the preserved history and pass a completely new review.
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
heartbeats, claiming, the two-person design gate, independent core-and-supporting review, the recovery ladder, task holds, launching
heterogeneous LLM agents — live in `reference/orchestration.md` with one brief per
role in `roles/`. Configure the team in `config/team.config.md` and launch with
`bin/launch-team.sh`.
