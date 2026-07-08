# Lifecycle — Scenarios & Playbooks

How work is created, tracked, and closed out. Every scenario is written in the generic
vocabulary (`reference/vocabulary.md`); the active adapter (`adapters/<Tool>.md`) supplies
the concrete verb for each operation. These playbooks are **single-agent by default** —
one agent drives the whole flow. If `TEAM_MODE=true`, transition *ownership* splits across
roles per `reference/team-roles.md`, but the scenarios themselves are identical.

Throughout: **an "operation"** (create feature, set status, add comment…) means "do the
thing described in the active adapter's *Operations* section." Never invent an operation
the adapter doesn't define.

---

## Scenario 1 — Plan a [feature]

Turn an idea into a tracked feature with a task breakdown.

1. **Understand the goal.** Clarify scope with the user: what ships, what's explicitly out,
   and any dependencies. Research the codebase enough to size the work realistically.
2. **Create the [feature]** via the adapter, status `[Planned]`. Record its `featureId`.
   The description should state **Purpose**, **NOT included** (out of scope), and
   **Dependencies**.
3. **Break it into [tasks].** Each [task] must be a *complete vertical slice* — something
   that can be implemented, reviewed, and completed on its own. Prefer 3–8 tasks over one
   giant task or twenty trivial ones.
4. **Create each [task]** via the adapter, status `[Planned]`, linked to the `featureId`.
   Put implementation checkpoints as `[subtasks]` (checklist bullets) in the description.
5. **Confirm** the created `featureId` and `taskId`s back to the user.

> A "PRD-style" wizard (interactive requirements gathering before step 2) is a good fit
> here but optional. The tracked output is the same: one `[feature]` + N `[tasks]`.

---

## Scenario 2 — Start a [task]

1. **Read the [task]** in full via the adapter — description, `[subtasks]`, comments,
   linked `[feature]`.
2. **Verify the status is the board's initial status** (`[Planned]` on the default
   board). If it isn't and `STRICT_STATUS=true`, pull the **andon cord** (Scenario 8).
   Don't start work on something already `[Active]` elsewhere.
3. **Move the [task] to `[Active]`** via the adapter *before* writing any code.
4. If this is the feature's first `[Active]` task, the [feature] moves `[Planned]` →
   `[Active]` (do this only if the adapter tracks feature status explicitly).
5. **Team mode only (`TEAM_MODE=true`): pass the design gate.** Post a `[design-note]`
   comment (approach, contract/data-model changes, affected components) and wait for
   the principal-architect's `[design-approved]` before writing any code — see
   `reference/orchestration.md`. Single-agent mode skips this step.
6. Implement, keeping the [task] description's `[subtasks]` as your checklist.

---

## Scenario 3 — Diverge from a [task]

Reality rarely matches the plan. When you must deviate from what the [task] describes:

1. **Add a comment** on the [task] (via the adapter) explaining *what* changed and *why*.
2. If the divergence affects **other** [tasks] in the [feature], note it on those too, or
   flag it to the user — don't let a silent change strand later tasks.
3. Keep working. The comment is the audit trail. **Never edit the original [task]
   description** — reviewers need the original ask. If the change is permanent and
   affects upcoming [tasks], the description of *not-yet-started* [tasks] is updated
   by the principal-architect in team mode, or by you with the user's confirmation
   in single-agent mode.

---

## Scenario 4 — Request review

1. Before requesting review, add a comment summarizing: what changed, which files, the
   suggested commit message, and the result of any build/test you ran.
2. **Move the [task] to `[Review]`** via the adapter.
3. Single-agent: you now switch hats and review, or hand to the user. Team mode: notify the
   reviewer (see `team-roles.md`).

If review finds problems: **move the [task] back to `[Active]`**, fix, and return to
`[Review]`. Backward moves are legal exactly where `config/statuses.config.json` lists
them (on the default board: `Review → Active`, plus the `Blocked` returns).

---

## Scenario 5 — Finalize a [task]

Only after the work is reviewed **and** verified (tests/build green, change actually does
what the [task] asked):

1. Confirm the [task] is in `[Review]`. If not, andon cord.
2. The terminal status carries `requiresCommit: true` on the default board: **commit the
   work and move the [task] to `[Ready to deploy]` as one atomic step** — never one
   without the other. Cite the commit hash in the completion comment.
3. If **all** [tasks] in the [feature] have reached the terminal status, move the
   [feature] to `[Resolved]`.

`[Ready to deploy]` means: reviewed, verified, committed — awaiting deployment by humans.
**Never** move work there that was skipped, partially done, or has failing tests — see
the fail-loud invariant.

---

## Scenario 6 — File newly-discovered work

When implementation surfaces work that isn't in any existing [task] (a bug, a missing
edge case, a follow-up):

1. **Create a new [task]** in the current [feature], status `[Planned]`, describing the
   discovered work. Don't silently fold unrelated scope into the current [task].
2. Route it through the normal lifecycle. Small, in-scope fixes can be folded into the
   current [task] with a divergence comment (Scenario 3); anything larger gets its own
   [task] so it stays visible in the tool.

---

## Scenario 7 — Block a [task]

When the *work* cannot proceed — missing dependency, unanswered question, broken
external service — and it isn't a process failure (that's the andon cord, Scenario 8):

1. **Add a comment** stating what is blocking, what was tried, and what would unblock.
2. **Move the [task] to `[Blocked]`** via the adapter. The board's owner of `[Blocked]`
   (default: team-lead) now owns resolving it.
3. The `[Blocked]` owner works the blocker and, once cleared, **moves the [task] back**
   to the appropriate working status (`Planned`, `Active`, or `Review` on the default
   board) with a comment saying what changed.

---

## Scenario 8 — Andon cord (stop-the-line)

Named after the Toyota cord any worker can pull to halt the line. Pull it when:

- A [task] is in an unexpected status for the action you're about to take.
- An adapter operation **fails** (MCP error, CLI non-zero exit, file conflict).
- You're blocked, or any warning/error signal appears.

When pulled: **stop immediately, do not work around it, and report** the exact problem to
the user (or, in team mode, escalate to the coordinator (concrete role: `team-lead`, via mailbox)). Resume only once resolved. This
directly enforces the *fail-loud* invariant from `vocabulary.md` — a silent workaround is
the failure mode this whole design exists to prevent.

---

## Scenario 9 — Connect / switch tools

1. Ensure `adapters/<Tool>.md` exists (copy `adapters/_TEMPLATE.md` for a new tool).
2. Set `PRODUCT_MANAGEMENT_TOOL=<Tool>` in `config/project-management.config.md`.
3. Complete that adapter's *MCP / CLI Setup*, then run its *Initialization* check
   (usually a no-op read that proves auth works).
4. Nothing else changes — every scenario above now targets the new tool.

---

## Scenario 10 — Pre-flight design pass (batch the design gates)

By default the design gate (Scenario 2 step 5) opens per-[task] at claim time.
When the plan should be settled before any code — the user asks for all plans
up front, or the [tasks] share contracts that must not fork — run the gates as
one batch instead:

1. **One `[design-note]` per [task]**, written against the real codebase (not the
   [task] text alone), each registering its exports in the contract registry
   (`reference/orchestration.md` → *Contract registry*, team mode).
2. **Cross-[task] consistency review first.** The reviewer of the set (the
   principal-architect in team mode; you, wearing that hat, in single-agent mode)
   reads the **full set before verdicts**, checking sibling notes against each
   other and the registry — contract forks between parallel plans are the
   highest-value findings and are invisible note-by-note. Cross-cutting rulings
   are binding and recorded once, referenced by each affected [task].
3. **Per-[task] verdicts** — `[design-approved]` (with conditions) or
   `[design-pushback]`, exactly as in the normal gate.
4. **Scope sign-off per [task]** where a product owner exists —
   `[product-approval]` / `[product-pushback]`.
5. **Everything lands as comments** on the [tasks], like any gate.
6. At claim time the gate is already open: the implementer re-reads the approved
   note, its conditions, and any cross-cutting rulings, and proceeds — no second
   approval needed unless a `[divergence]` or re-plan invalidated the note.

The per-[task] gate is unchanged — this scenario only moves *when* it runs.
[Tasks] added later (Scenario 6) go through the normal per-[task] gate.

---

## Quick reference — status writes per scenario

| Scenario | Writes |
|---|---|
| 1 Plan | create `[feature]` `[Planned]`; create `[tasks]` `[Planned]` |
| 2 Start | `[task]` → `[Active]` (feature → `[Active]` on first) |
| 3 Diverge | comment only |
| 4 Review | `[task]` → `[Review]` (or back to `[Active]` on rework) |
| 5 Finalize | commit + `[task]` → `[Ready to deploy]` (atomic); feature → `[Resolved]` when all done |
| 6 New work | create `[task]` `[Planned]` |
| 7 Block | comment + `[task]` → `[Blocked]`; owner routes it back when cleared |
| 8 Andon | **no write** — stop and report |
| 10 Pre-flight design pass | comments only — one `[design-note]` + verdict (+ scope sign-off) per [task] |
