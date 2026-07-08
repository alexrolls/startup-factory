# Team Playbook — How Every Preset Team Works

The shared collaboration flow for the preset teams in this directory. A team file
(`teams/<team>.md`) supplies the roster and any team-specific review stages; this
playbook supplies everything else. Both are composed into every team member's
startup prompt, together with the member's role brief and
`reference/orchestration.md`.

The protocol in `reference/orchestration.md` always governs mechanics — claiming,
markers, statuses, mailboxes, worktrees, integration. A preset team *narrows* the
protocol; it never contradicts it.

## The two fixed rules

1. **The Principal Architect leads the team.** It acts as the `team-lead` AND
   `principal-architect` protocol roles: it plans, launches, supervises, unblocks,
   reassigns, escalates — and holds the technical veto (design gates, architecture
   reviews, divergence sweeps).
2. **The Senior QA Engineer is the final review gate.** No [task] reaches the
   integrator until QA's `[review-approval]` exists, and QA approves only after
   every other required approval for that [task] is already on record. Work is
   "done" only after QA's approval AND the integrator's merge + `[Ready to deploy]`.

Every member is bound by the delivery contract (`reference/orchestration.md` →
*Report before idle*): no one goes idle with an undelivered artifact, and the
lead sends an explicit assignment message after every spawn — the startup prompt
is context, not a trigger.

## Stages

1. **Intake.** The TPM turns the ask into a [feature] draft: problem statement,
   scope, explicit NOT-in-scope, dependencies, and per-[task] **acceptance
   criteria** — testable, implementation-free statements.
2. **Planning.** The architect breaks the [feature] into [tasks] (complete
   vertical slices) with the TPM. The TPM must approve scope and acceptance
   criteria **before anything is created in the tracker** — the architect cannot
   approve its own plan's scope; the TPM is the second pair of eyes. The TPM's
   sign-off is a `[product-approval]` comment (or `[product-pushback]` with the
   required changes) once the [tasks] exist to carry it.
3. **Design gate — every [task].** The implementer posts a `[design-note]` that
   registers its exports in the contract registry
   (`reference/orchestration.md` → *Contract registry*); the architect answers
   `[design-approved]` (possibly with conditions) or `[design-pushback]`. No code
   before approval.

   *Pre-flight variant (lifecycle Scenario 10):* when the plan should be settled
   before any code, run all design gates as one batch — notes for every [task],
   the architect's cross-[task] consistency review first (diffing the set against
   the contract registry), then per-[task] verdicts and TPM scope sign-offs. At
   claim time each gate is already open.
4. **Implementation.** Own worktree per implementer, the [task]'s [subtasks] as
   checklist, `[divergence]` comments for every deviation, self-validation with
   the `VALIDATE_*` commands before requesting review.
5. **Review — in this order:**
   1. **Architect** — architecture review → `[architecture-approval]`.
   2. **Team-specific specialist reviews** (listed in the team file, if any).
      Problems → `[review-findings]`; a clean pass → a plain comment stating the
      review ran and passed (specialists never invent new markers).
   3. **QA — the final gate.** Runs the reviewer's three phases with the TPM's
      acceptance criteria as the Phase-1 checklist; every criterion needs a
      `file:line` citation and a test citation; runs the applicable suites.
      Approval → `[review-approval]`, always the **last** approval.

   The protocol allows parallel dual review; in the default `sequential` mode
   preset teams sequence it so QA always judges the final shape of the change
   (see *Review modes* below for the trade-offs of the other modes).
6. **Integration.** The standard `integrator` (`roles/integrator.md`) verifies
   the approvals and file lists, validates, merges, commits, and marks
   `[Ready to deploy]` — the atomic pair. Every preset roster includes it.
7. **Close.** When all [tasks] are `[Ready to deploy]`: the architect runs the feature
   completion checklist, the TPM confirms the acceptance criteria hold at
   feature level with a feature-level `[product-approval]` comment, and only
   then does the [feature] move to `[Resolved]`.

## Review modes

A team file may declare `REVIEW_MODE=` next to its `ROSTER=` line; absent, the
default is `sequential` (the order in stage 5):

- `sequential` — each review stage starts after the previous approval. QA judges
  the final shape of the change; roughly doubles per-[task] review wall time.
- `parallel` — architect, specialists, and QA review the same diff concurrently;
  QA still **posts** `[review-approval]` only after every other required
  approval is on record, so it remains the last-in-time gate. Trades "QA sees
  the final shape" for wall time; any `[review-findings]` sends the [task] back
  and every reviewer re-reviews the reworked diff.
- `tiered` — reviews are sized to risk: for small [tasks] a single combined
  review (QA executes the numbered architecture checklist the architect
  attaches to the `[design-approved]` — the architect's brief requires it in
  this mode), with full dual review reserved for larger [tasks] and for **any**
  [task] touching a contract registered in `CONTRACTS.md`. Cheaper where the
  second reviewer's value is independent evidence rather than extra findings.

Whatever the mode, the invariants hold: every required approval exists before
integration, QA's approval is last, file lists must equal the diff.

## Escalation

The architect (as `team-lead`) runs the supervision loop and the unblock ladder
from `reference/orchestration.md`. Scope and business-rule questions go to the
TPM first; the TPM escalates to the human when the answer is not derivable from
the approved [feature]. Technical rulings are the architect's, and final — but
the architect never overrides the integrator's validation failures or QA's gate
verdict.

## Appendix — message templates

Canonical shapes for the two messages the lead writes most. Filling a template
beats re-authoring fifteen long messages per [feature] — and keeps every
teammate's inputs in the same places. Both end by naming the artifact that
closes the loop (*Report before idle*).

**ASSIGN** — lead → implementer, after spawn or claim sanction:

```
Re: <taskId>
Assignment: <one line — what this [task] delivers>
Inputs: [task] description + all comments; approved [design-note] + conditions
        <link/pointer>; cross-cutting rulings <pointer, if any>; CONTRACTS.md
        lines you consume: <lines or "none">
Baseline: BASELINE.md — bar is no new failures
Validate: <VALIDATE_* / VALIDATE_SCRIPT expectations for this change>
Report back: [review-request] with changed-file list, validation results, and
        any index-only staging operation — deliver before idling.
```

**REVIEW** — lead → reviewer(s), when a [task] enters `[Review]`:

```
Re: <taskId>  (mode: <sequential|parallel|tiered>)
Diff: <files changed, one-line summary> (worktree: <path>)
Rule on: <open [divergence]s awaiting a ruling, or "none">
Check: approved [design-note] conditions <pointer>; review-ledger.md lines that
        apply; CONTRACTS.md exports this [task] registered or consumes
Evidence: run the applicable suites yourself; judge against BASELINE.md
Report back: [architecture-approval] / [review-approval] with the explicit file
        list, or [review-findings] — deliver before idling.
```

Report-block shapes (`[review-request]`, `[divergence]`, `[andon]`, approvals)
are defined by the marker table in `reference/orchestration.md` — don't restate
them here, don't drift from them.
