# Vocabulary — The Tool-Agnostic Contract

This is the **port**: the stable interface every workflow and agent speaks. It never
changes when you switch tools. Adapters translate it to a concrete tool; consumers must
never bypass it by naming a tool directly.

> **The one rule that makes everything else work:** in any workflow, prompt, commit
> message, comment, or agent instruction, refer to work items **only** by the generic
> terms below. Never write "issue", "epic", "story", "ticket", or "work item". If you
> find yourself typing a tool-specific word, you've leaked an implementation detail into
> the port — stop and use the generic term.

---

## Work-Item Hierarchy

| Generic term | Meaning | Notation (use consistently) |
|---|---|---|
| **Feature** | A collection of related tasks — one shippable capability or initiative. | `[feature]` `[features]` `[Feature]` `[Features]` |
| **Task** | A complete vertical slice of work — independently reviewable and completable. | `[task]` `[tasks]` `[Task]` `[Tasks]` |
| **Subtask** | A checklist item *inside* a task's description. **Not tracked as its own item.** | `[subtask]` `[subtasks]` `[Subtask]` `[Subtasks]` |

Preserve bracket, case, and pluralization exactly (`[task]` vs `[Task]` vs `[tasks]`) so
the terms are unambiguous and greppable.

### Banned terms (never appear in a workflow)

`Issue` · `Epic` · `Story` · `User Story` · `Work Item` · `Ticket` · `Bug` (as a type) ·
`Card` · `Backlog Item`

These belong **only** inside `adapters/<Tool>.md`, where the mapping is defined once.

---

## Status Model

Statuses are **configured, not fixed**. The single source of truth is
`config/statuses.config.json`: for features and for tasks it defines the status list,
each status's legal outbound `transitions`, its `owner` — the team or single agent that
works items sitting in that status — and per-adapter `tool` mappings.

Rules that hold for every board:

- **Bracket notation.** Write any status exactly as `[Status Name]` — bracketed, exact
  case, greppable (`[Planned]`, `[Ready to deploy]`).
- **Exactly one `initial` status** per machine — where new items are created.
- **At least one `terminal` status** — where work ends; it has no outbound transitions.
- **`requiresCommit`** — entering such a status requires a successful integration
  commit by that status's owner. The tracker transition is idempotent and
  recoverable from the integration transaction record.
- **"Next status" means a status listed in the current status's `transitions`.** Any
  other move is illegal — an **andon cord** condition (see `lifecycle.md`).
- **A listed transition is not sufficient authority.** `transitionAuthority`
  may narrow who can enter or exit a status. On the shipped board `[Blocked]`
  can be entered by the verified team-lead/PM supervisor, is owned by `human`,
  and can be exited only by a human project-management action. Startup Factory
  never authors an outbound Blocked move. The operator must enforce the human
  actor with the project-management tool's workflow ACL; normalized status data
  alone does not prove transition provenance.

### The default board (shipped)

Features: `[Planned]` → `[Active]` → `[Resolved]`.

Tasks:

| Status | Owner (default) | Transitions to | Notes |
|---|---|---|---|
| `[Planned]` | team-lead | Active, Blocked | initial; entering Blocked requires its explicit authority |
| `[Active]` | implementer | Review, Blocked | |
| `[Review]` | reviewer | Active, Ready to deploy, Blocked | rework returns to Active |
| `[Blocked]` | human | Planned, Active, Review | task-scoped human lock; listed exits normalize human actions only |
| `[Ready to deploy]` | integrator | — | terminal; `requiresCommit` |

This table is an **example** — the JSON is authoritative. Projects add, rename, or
remove statuses by editing the config; no other file changes as long as owners and
tool mappings are set. Validate edits with `bin/launch-team.sh validate-board`.

---

## Identifiers

| Generic ID | Meaning |
|---|---|
| `featureId` | Opaque handle for a feature. Its concrete form is defined per adapter (a project id, an epic key, a milestone, a file path…). |
| `taskId` | Opaque handle for a task (an issue key like `ENG-142`, a number, a file+section…). |

Treat both as **opaque strings**. Never parse, construct, or assume their format in a
workflow — only the adapter knows the shape.

---

## Comment markers

Kept in sync with `reference/orchestration.md` → *Structured comments* — that
table is authoritative for workflow role routing and required content. Claimed
tracker authorship is not security authentication or production authorization.

Markers are the machine-readable protocol prefixes that begin every coordination
comment. The full workflow-role rules and required content live in
`reference/orchestration.md` → *Structured comments*. Vocabulary-level meanings:

| Marker | One-line meaning |
|---|---|
| `[design-note]` | Implementer's proposed approach before any code. |
| `[design-approved]` | Principal-architect gate open; carries architecture checklist. |
| `[design-pushback]` | Principal-architect gate closed; lists required changes. |
| `[sceptical-design-approved]` | Independent architecture challenge cleared; records assumptions and risk controls. |
| `[sceptical-design-pushback]` | Independent design gate closed; records material risk and feasible resolution. |
| `[dependency-hold]` | Team-lead verdict bound to exact direct Blocked sources and current graph digest. Receipt-backed `blocked` may authorize a queued or in-flight dependent to enter `[Blocked]`; other verdicts clear only that graph for claim/continuation. |
| `[resume-review]` | Team-lead verdict over the full blocked/current communication diff, bound to an exact hold and current digest after a human returns the [task] to queued. |
| `[resume-plan]` | Team-lead revised plan after changed requirements; requires both later architect design verdicts. |
| `[api-ready]` | Backend contract available for frontend. |
| `[divergence]` | What was done differently from the plan, and why. |
| `[review-request]` | Implementation complete; ready for review. |
| `[review-findings]` | Numbered problems to fix; task returns to `[Active]`. |
| `[review-approval]` | Reviewer sign-off with explicit list of approved file paths. |
| `[architecture-approval]` | Principal-architect sign-off. |
| `[sceptical-architecture-approval]` | Independent release-bound architecture sign-off. |
| `[product-approval]` | Product owner scope/acceptance sign-off. |
| `[product-pushback]` | Product owner scope gate closed. |
| `[handoff]` | Team-lead reassignment summary for a fresh agent. |
| `[progress]` | One per [task], mechanically upserted from runtime/tracker state: stage, actor, attempt, timestamp, and one-line summary. |
| `[digest]` | One per [feature], mechanically upserted from the tracker snapshot: one line per [task] for the human's whole view. |
| `[andon]` | Stop-the-line report: what failed, exact error, what was not done. |
| `[escalation]` | Needs the human: question, options, default-if-silent. |
| `[DENIED ACTION]` | Policy gate blocked an agent's attempted action: actor, what was attempted, why it was denied, and that it was never executed. Audit evidence only — grants nothing. |

---

## Invariants every adapter must honour

1. **All operations go through the tool's real interface** (MCP, CLI, or files) — never
   fabricate an update you didn't actually perform.
2. **Fail loud.** If an operation fails, stop and report it. Never silently work around a
   failure or pretend a status changed.
3. **Status moves follow the configured `transitions` graph.** Never skip, invent, or reverse a move the board does not define.
4. **Reads are cheap, writes are deliberate.** Confirm the current status before a write
   when `STRICT_STATUS=true`.
5. **Blocked is task-scoped and human-exited.** Stop/fence only the matching
   [task], keep independent queued work moving, and refuse every automated
   outbound Blocked transition.
6. **Dependencies are first-class data.** Only the adapter-normalized
   `blockedBy` relationship may affect scheduling or dependency propagation;
   never infer an edge from comment prose.
