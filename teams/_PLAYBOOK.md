# Team Playbook — How Every Preset Team Works

The shared collaboration flow for the preset teams in this directory. A team file
(`teams/<team>.md`) supplies the roster and any team-specific review stages; this
playbook supplies everything else. Both are composed into every team member's
startup prompt, together with the member's role brief and
`reference/orchestration.md`.

The protocol in `reference/orchestration.md` always governs mechanics — claiming,
markers, statuses, mailboxes, worktrees, integration. A preset team *narrows* the
protocol; it never contradicts it.

## The three fixed rules

1. **The Principal Architect leads the team.** It acts as the `team-lead` AND
   `principal-architect` protocol roles: it plans, launches, supervises, unblocks,
   reassigns, escalates, owns the primary design position, and performs divergence
   sweeps.
2. **The Sceptical Architect is independent.** It forms a blind-first position,
   challenges every design, and supplies a release-bound architecture approval.
   Because the lead and principal architect are the same preset agent, unresolved
   material disagreement or Critical risk acceptance goes to the human.
3. **The Senior QA Engineer is the final review gate.** No [task] reaches the
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
   required changes) once the [tasks] exist to carry it. Before creation, the
   sceptical-architect independently challenges the plan and both architects
   must approve it.
3. **Design gate — every [task].** The implementer posts a `[design-note]` that
   registers its exports in the contract registry
   (`reference/orchestration.md` → *Contract registry*); the principal architect
   answers `[design-approved]` or `[design-pushback]`, while the sceptical-
   architect independently answers `[sceptical-design-approved]` or
   `[sceptical-design-pushback]`. No code before both approvals.

   *Pre-flight pass (lifecycle Scenario 10) — the **default opener**:* unless
   the plan is genuinely emergent, run all design gates as one batch — notes
   for every [task]
   (each registering its exports in the contract registry **as it is written**),
   the architect's cross-[task] consistency review first (diffing the set against
   the registry; unregistered exports or uncited imports block approval), then
   both independent per-[task] verdicts and TPM scope sign-offs. At claim time each gate is
   already open.
   For genuinely emergent plans, keep the gate ahead of the dispatch with a
   rolling look-ahead instead: when [task] N is dispatched, N+1's
   `[design-note]` is written and reviewed while N is in flight (skip when
   N+1 depends on N's implementation detail).
4. **Implementation.** One immutable task packet, task branch, and worktree per
   attempt in both execution modes; the [task]'s [subtasks] as checklist,
   `[divergence]` comments for every deviation, checkpoint commits, and
   self-validation with the `VALIDATE_*` commands before requesting review.
5. **Review — in this order:**
   1. **Architect** — architecture review → `[architecture-approval]`.
   2. **Sceptical Architect** — blind-first challenge →
      `[sceptical-architecture-approval]` or `[review-findings]`.
   3. **Team-specific specialist reviews** (listed in the team file, if any).
      Problems → `[review-findings]`; a clean pass → a plain comment stating the
      review ran and passed (specialists never invent new markers).
   4. **QA — the final gate.** Runs the reviewer's three phases with a Phase-1
      checklist seeded by the [design-approved] architecture checklist plus the
      TPM's acceptance criteria (add items, never subtract); every criterion needs a
      `file:line` citation and a test citation; runs the applicable suites.
      Approval → `[review-approval]`, always the **last** approval.

   The protocol allows parallel triple review; in the default `sequential` mode
   preset teams sequence it so QA always judges the final shape of the change
   (see *Review modes* below for the trade-offs of the other modes).
6. **Integration.** The standard `integrator` (`roles/integrator.md`) verifies
   the exact review package, validates the task branch, merges and validates the
   feature branch, commits, then idempotently marks `[Ready to deploy]`. A
   durable transaction record makes retries safe. Every preset roster includes
   it.
7. **Close / release.** When all [tasks] are `[Ready to deploy]`, the architect
   runs the feature-completion checklist. The release executor validates the
   closed integration chain and writes
   `<TEAMWORK_ROOT>/<team>/product-acceptance-request.json`. The TPM re-runs the
   feature-level acceptance criteria and posts the request's `canonicalBody`
   unchanged as `[product-approval]` on its `anchorTaskId`. This is a
   feature-level verdict stored on a task only because feature containers are
   not uniformly commentable. It binds `scope: feature`, exact `feature-id`,
   exact `anchor-task-id`, the 40-character integrated `commit`, exact
   `integration-evidence-digest`, and `acceptance-criteria: passed`. A later
   `[product-pushback]`, stale binding, or ambiguous tracker timeline reopens
   the gate. The team-lead may author this envelope only when the team has no
   product-manager role. Production cannot begin until the deterministic
   release executor accepts the envelope; only independently verified
   production success resolves the [feature]. Disabled delivery remains
   awaiting in the PM registry with the feature non-terminal; the disabled
   executor creates no tracker `[deployment]` projection.

## Review modes

A team file may declare `REVIEW_MODE=` next to its `ROSTER=` line; absent, the
default is `sequential` (the order in stage 5):

- `sequential` — each review stage starts after the previous approval. QA judges
  the final shape of the change; strongest ordering, highest review wall time.
- `parallel` — both architects, specialists, and QA review the same diff concurrently;
  QA still **posts** `[review-approval]` only after every other required
  approval is on record, so it remains the last-in-time gate. Trades "QA sees
  the final shape" for wall time; any `[review-findings]` sends the [task] back
  and every reviewer re-reviews the reworked diff.
- `tiered` — reviews are sized to risk: for small [tasks], QA executes the
  principal architect's numbered checklist and the principal binds its approval
  to that evidence. The sceptical release gate is never collapsed. Full
  principal review remains required for larger [tasks] and for **any** [task]
  touching a contract registered in `CONTRACTS.md`.

**Recommendation:** `sequential` for a team's first feature; `tiered` once the
team has run history; `parallel` where triple review on every [task] is wanted
concurrently rather than serially. Tiered eligibility is a mechanical test the
lead applies at dispatch — combined review only if (a) the `[design-note]`
declared `Architectural impact: no` **and** (b) the [task] touches no contract
registered in `CONTRACTS.md`; anything else gets full triple review.

Whatever the mode, the invariants hold: every required approval exists before
integration, QA's approval is last, file lists must equal the diff.

## Escalation

The architect (as `team-lead`) runs the supervision loop, the non-Blocked
recovery ladder, and task-hold analysis
from `reference/orchestration.md`. Scope and business-rule questions go to the
TPM first; the TPM escalates to the human when the answer is not derivable from
the approved [feature]. Architecture rulings require both peers. The preset lead
cannot adjudicate its own principal-architect position, so unresolved material
disagreement goes to the human. Neither architect overrides the integrator's
validation failures or QA's gate
verdict. No agent moves `[Blocked]` outbound; only a human may return it to the
queued resume-review barrier. Other queued [tasks] continue meanwhile.

## Appendix — message templates

Canonical shapes for the two messages the lead writes most. Filling a template
beats re-authoring fifteen long messages per [feature] — and keeps every
teammate's inputs in the same places. Both end by naming the artifact that
closes the loop (*Report before idle*).

**ASSIGN** — lead → implementer, after spawn or claim sanction:

```
Re: <taskId>
Packet: <immutable task-packet.md path>
Worktree: <attempt worktree path>
Task branch: <agent-task/safe-task-key>
Report: <attempt report path>
Read: the packet and your role brief only; fetch other context by explicit
      pointer when the packet says it is required.
Report back: checkpoint the task branch, then submit the report artifact before
      exiting. The outbox owns tracker delivery.
```

Gate roles drain the whole queue in one boot: one boot reviews every [task] currently awaiting that gate ("drain the [Review] queue"), posting per-[task] verdicts — never one boot per [task] when several wait.

**REVIEW** — lead → reviewer(s), when a [task] enters `[Review]`:

```
Re: <taskId>  (mode: <sequential|parallel|tiered>)
Review package: <review-package.md path with exact base/head commits and diff>
Rule on: <open [divergence]s awaiting a ruling, or "none">
Check: [design-approved] numbered architecture checklist (your Phase-1 seed —
        add items, never subtract) + its conditions; review-ledger.md lines that
        apply; CONTRACTS.md exports this [task] registered or consumes
Evidence: the [review-request]'s evidence records (commit, command, exit,
        counts, log path) — spot-check per the protocol's *Evidence and
        re-execution* matrix; QA re-runs regardless.
Report back: [architecture-approval] / [sceptical-architecture-approval] /
        [review-approval] with the explicit file
        list, or [review-findings] — deliver before idling.
```

Report-block shapes (`[review-request]`, `[divergence]`, `[andon]`, approvals)
are defined by the marker table in `reference/orchestration.md` — don't restate
them here, don't drift from them.
