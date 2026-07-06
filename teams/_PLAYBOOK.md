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
   "done" only after QA's approval AND the integrator's merge + `[Completed]`.

## Stages

1. **Intake.** The TPM turns the ask into a [feature] draft: problem statement,
   scope, explicit NOT-in-scope, dependencies, and per-[task] **acceptance
   criteria** — testable, implementation-free statements.
2. **Planning.** The architect breaks the [feature] into [tasks] (complete
   vertical slices) with the TPM. The TPM must approve scope and acceptance
   criteria **before anything is created in the tracker** — the architect cannot
   approve its own plan's scope; the TPM is the second pair of eyes.
3. **Design gate — every [task].** The implementer posts a `[design-note]`; the
   architect answers `[design-approved]` (possibly with conditions) or
   `[design-pushback]`. No code before approval.
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

   The protocol allows parallel dual review; preset teams sequence it so QA
   always judges the final shape of the change.
6. **Integration.** The standard `integrator` (`roles/integrator.md`) verifies
   the approvals and file lists, validates, merges, commits, and marks
   `[Completed]` — the atomic pair. Every preset roster includes it.
7. **Close.** When all [tasks] are `[Completed]`: the architect runs the feature
   completion checklist, the TPM confirms the acceptance criteria hold at
   feature level, and only then does the [feature] move to `[Resolved]`.

## Escalation

The architect (as `team-lead`) runs the supervision loop and the unblock ladder
from `reference/orchestration.md`. Scope and business-rule questions go to the
TPM first; the TPM escalates to the human when the answer is not derivable from
the approved [feature]. Technical rulings are the architect's, and final — but
the architect never overrides the integrator's validation failures or QA's gate
verdict.
