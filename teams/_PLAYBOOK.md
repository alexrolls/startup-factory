# Team Playbook — How Every Preset Team Works

The shared collaboration flow for the preset teams in this directory. A team file
(`teams/<team>.md`) supplies the roster and any team-specific review stages; this
playbook supplies everything else. Both are composed into every team member's
startup prompt, together with the member's role brief and
`reference/orchestration.md`.

The protocol in `reference/orchestration.md` always governs mechanics — claiming,
markers, statuses, mailboxes, worktrees, integration. A preset team *narrows* the
protocol; it never contradicts it.

## The three fixed review-board rules

1. **The Team Lead owns process and quality review.** It plans, launches,
   supervises, reassigns, escalates, and independently supplies
   `[team-lead-approval]`; it never doubles as a preset architect.
2. **The Principal Architect owns the primary technical position.** It runs the
   design gate, divergence sweeps, and independently supplies
   `[architecture-approval]`.
3. **The Sceptical Principal Architect is independent.** It forms a blind-first
   position, challenges every design and implementation, and independently
   supplies `[sceptical-architecture-approval]`.
No [task] reaches the integrator until all three commit-bound core approvals
exist on the current review request. QA, Security, and other specialists join
through declared supporting gates; they add evidence or `[review-findings]`
without replacing a core board member.

The Senior Security Engineer is mapped and launchable in every preset but is
disabled at startup except in Deep Infra and Deep Security. Planning adds
`review-gates: security` when the task touches authentication, authorization,
secrets, cryptography, tenancy or sensitive data, untrusted input, supply
chain, privileged/destructive operations, network/deployment boundaries, or a
credible domain-specific threat. Both architects must challenge an omitted
security gate. Deep Infra and Deep Security declare security as a
preset-required gate, so it is always effective even if task metadata omits it.

Every member is bound by the delivery contract (`reference/orchestration.md` →
*Report before idle*): no one goes idle with an undelivered artifact, and the
lead sends an explicit assignment message after every spawn — the startup prompt
is context, not a trigger.

## Stages

1. **Intake.** The TPM turns the ask into a [feature] draft: problem statement,
   scope, explicit NOT-in-scope, dependencies, and per-[task] **acceptance
   criteria** — testable, implementation-free statements. Before approval, the
   TPM and both architects reconcile those criteria against known system
   constraints and make every contradiction an explicit decision instead of
   leaving it for late acceptance. When a validated
   Claude/Superpowers planning handoff exists, the TPM and architects read its
   exact specification and plan as intake evidence. The handoff does not approve
   scope or authorize execution.
2. **Planning.** The architect breaks the [feature] into [tasks] (complete
   vertical slices) with the TPM. The TPM must approve scope and acceptance
   criteria **before anything is created in the tracker** — the architect cannot
   approve its own plan's scope; the TPM is the second pair of eyes. The TPM's
   sign-off is a `[product-approval]` comment (or `[product-pushback]` with the
   required changes) once the [tasks] exist to carry it. Before creation, the
   sceptical-architect independently challenges the plan and both architects
   must approve it. Every task also declares applicable supporting gates with
   `review-gates: qa`, `review-gates: security`, or both; absence means neither
   specialist gate is required. Startup Factory launches and owns the team after this point;
   no Superpowers execution/worktree/subagent workflow runs alongside it.
3. **Design gate — every [task].** The implementer posts a `[design-note]` that
   registers its exports in the contract registry
   (`reference/orchestration.md` → *Contract registry*); the principal architect
   answers `[design-approved]` or `[design-pushback]`, while the sceptical-
   architect independently answers `[sceptical-design-approved]` or
   `[sceptical-design-pushback]`. No code before both approvals.
   Cite affected code by stable `path::symbol (approx line)`, not bare line
   numbers. A `work-kind: defect` [task] first reproduces the failure; its note
   must include `Root cause:` with evidence and the failing regression test that
   will be written before the fix. Either architect pushes back if these are
   missing.

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
   self-validation with every exact configured `VALIDATE_*` command (or the
   configured `VALIDATE_SCRIPT`) before requesting review. Scoped substitutes
   are not evidence for a broader configured command.
5. **Review board.** When implementation matches the specification and is nearly
   releasable, move the [task] to `[Review]` (mapped to `In Review`) and generate
   one exact review package. The Team Lead, Principal Architect, and Sceptical
   Principal Architect independently review that same package and post their
   own bound approval or `[review-findings]`.
   The board explicitly checks test sensitivity: the relevant test must fail
   when the feature/guard is removed or reverted, and at least one test must
   exercise the real integration/entry path rather than only a helper or mock.
   Team-specific QA, SRE, penetration-test, accessibility, or other specialist
   passes may run too. Required specialist passes must be declared as task
   metadata (`review-gates: qa,security`); prose alone does not create an
   enforceable gate. Every declared supporting approval must bind the current
   package and precede the Team Lead verdict. A security declaration launches
   the preset's mapped Security Engineer only for that work.

   Any blocking quality, architecture, security, test, operability, or
   specification finding moves the [task] `[Review] → [Planned]` (mapped to
   `ToDo`). The dispatcher creates a fresh attempt; after rework the [task]
   proceeds through `[Active]`/`In Progress`, requests a new review package, and
   all three core reviewers and every declared supporting reviewer decide again.
   No prior approval survives a new request or
   branch movement.
6. **Integration.** The standard `integrator` (`roles/integrator.md`) verifies
   the exact review package, validates the task branch, merges and validates the
   feature branch, commits, then idempotently marks `[Ready to deploy]`. A
   durable transaction record makes retries safe. Every preset roster includes
   it.
7. **Close / release.** When all [tasks] are `[Ready to deploy]` (mapped to
   `Ready for production`), the Team Lead runs the feature-completion checklist.
   The release executor validates the
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
   production success resolves the [feature] (mapped to `Live`). Before planning
   and again at the apply-process boundary, the protected CI verifier must prove
   every required check for the exact commit is green. Red, pending, skipped,
   missing, stale, or unverifiable CI cannot deploy to production or any other
   environment. Disabled delivery remains
   awaiting in the PM registry with the feature non-terminal; the disabled
   executor creates no tracker `[deployment]` projection.

## Review modes

A team file may declare `REVIEW_MODE=` next to its `ROSTER=` line; absent, the
default is `sequential`:

- `sequential` — launch board members one after another; highest wall time and
  easiest operational debugging.
- `parallel` — launch the core board and declared supporting reviewers against the same immutable package;
  preferred once the team machinery is stable.
- `tiered` — vary checklist depth and specialist gates by risk, but never
  collapse, delegate, or skip any core verdict or declared gate.

Whatever the mode, all three core approvals and every declared supporting gate must
exist before integration, each file list must equal the diff, and any finding
invalidates the round. `parallel` may run the other board members concurrently,
but Team Lead review is final and is routed only after all declared supporting
gates are current.

## Escalation

The Team Lead runs the supervision loop, the non-Blocked recovery ladder, and
task-hold analysis
from `reference/orchestration.md`. Scope and business-rule questions go to the
TPM first; the TPM escalates to the human when the answer is not derivable from
the approved [feature]. Architecture rulings require both peers. The independent
Team Lead may adjudicate only non-Critical trade-offs; Critical risk acceptance
goes to the human. No reviewer overrides the integrator, another mandatory
reviewer, or the protected CI verifier. No agent moves `[Blocked]` outbound;
only a human may return it to the
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
Read: the packet—including every entry in its mandatory complete tracker-comment
      history—and your role brief only; acknowledge the comment count/digest in
      the report before changing code. Fetch other context by explicit pointer
      when the packet says it is required.
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
        counts, log path) — spot-check or re-run according to your role.
Report back: your assigned core marker, or the declared supporting marker
        ([review-approval] for qa; [security-approval] for security), with the
        exact file list; otherwise [review-findings] — deliver before idling.
```

Report-block shapes (`[review-request]`, `[divergence]`, `[andon]`, approvals)
are defined by the marker table in `reference/orchestration.md` — don't restate
them here, don't drift from them.
