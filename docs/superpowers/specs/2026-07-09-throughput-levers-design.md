# Throughput Levers — Layered Execution Speedups — Design

**Date:** 2026-07-09
**Status:** Approved (pending user spec review)
**Branch:** `main` (spec); implementation on a feature branch

## Problem

Per-feature wall-clock is dominated by a serial critical path per [task]:
design-wait + implement + review + rework + integrate. Production evidence
(`FEEDBACK-parallel-and-worktrees.md`, inscribed run: 15 [tasks], ~10 rework
cycles, harness mode, `EXECUTION=sequential`):

- The shared checkout is reserved from claim until integration — a [task] in
  `[Review]` still owns it — so nothing overlaps anything.
- Default `REVIEW_MODE=sequential` "roughly doubles per-[task] review wall
  time" (`teams/_PLAYBOOK.md` → *Review modes*).
- ~67% of [tasks] bounced at review at least once; review criteria were
  discovered after code existed.
- The design gate opens per-[task] at claim time, putting the
  `[design-note] → [design-approved]` round-trip on every [task]'s critical path.

Goal: cut wall-clock **without weakening the gates that caught real defects**
(the cross-tenant IDOR, the INS-14/INS-20 contract fork).

## Inputs

- Two prior analysis rounds in-session (bottleneck: checkout reservation; flaw
  found in naive "release checkout at review" — integration would commit onto a
  tree holding the next task's uncommitted edits, contaminating validation).
- An independent principal-architect review (run as an agent against this
  repo's own `roles/principal-architect.md` brief), which returned
  `[design-pushback]` on a pipelined-mode proposal with four required changes
  (RC-1..RC-4, resolved below) and three alternatives (Alt A/B/C, adopted as
  Levers 1–3).

## Decisions (clarified with user)

| Question | Decision |
|---|---|
| Shape of pipelining | **Concurrency knob**, not a third mode: `EXECUTION=parallel` + `MAX_ACTIVE_IMPLEMENTERS=1`. All parallel-mode isolation rules apply at any N. |
| Rework contention | **Rework preempts** — oldest [task] first; the implementer parks the newer [task], clears findings on the older, resumes. |
| Scope | **One layered spec**: all four levers, ordered by value-per-risk, PA ladder as adoption order. Pipelined fully designed but gated. |
| Stacking dependent [tasks] on un-integrated branches | **Deferred** — out of scope. Dispatch only independent [tasks]; otherwise wait. |

## Adoption order (the ladder)

1. **Lever 1** — review-window compression (config guidance; immediate)
2. **Lever 2** — mandatory design checklists (root-cause rework fix)
3. **Lever 3** — design-wait elimination (pre-flight default + rolling look-ahead)
4. **Lever 4** — `MAX_ACTIVE_IMPLEMENTERS=1` pipelined dispatch (gated: machinery
   proof + rework-rate threshold)

Each lever is independently adoptable; none depends on a later one. Lever 4's
benefit is real only after Lever 2 lowers the rework rate (see *Enablement gates*).

---

## Lever 1 — Review-window compression (`REVIEW_MODE`)

Guidance change only; all three modes already exist (`teams/_PLAYBOOK.md` →
*Review modes*).

- Preset team files gain an explicit recommendation: `REVIEW_MODE=tiered` for
  teams past their first feature; `parallel` where dual review on everything is
  wanted but not serially; `sequential` remains the conservative default for a
  team's first run.
- *Review modes* gains one explicit eligibility checklist the lead applies at
  dispatch: a [task] qualifies for tiered combined review only if
  (a) `Architectural impact: no` and (b) it touches no contract registered in
  `CONTRACTS.md`. (Both conditions exist in the tiered prose today; this makes
  them a single mechanical test.)

## Lever 2 — Mandatory design checklist on every `[design-approved]`

Extend the existing tiered-mode rule to **all modes**:

- `roles/principal-architect.md` checkpoint 2: every `[design-approved]`
  carries a **numbered architecture checklist** — what will be verified at
  review time. (Today required only for tiered combined reviews.)
- The team-lead's assignment message delivers the checklist as acceptance
  input: "implement to satisfy items 1–N."
- Reviewer/QA Phase-1 checklists **start from** the PA's items — reviewers add
  items, never subtract.
- `[design-approved]` marker definition in `reference/orchestration.md`
  updated to name the checklist as required content.

Rationale: criteria exist before code, so implementation targets them instead
of guessing what review will check. Cost: ~5–10 min per design approval.

## Lever 3 — Design-wait elimination

Rule: **a [task]'s design gate should already be open when the [task] is
dispatched.** Two variants of the same rule, chosen by plan stability:

- **Settled plans → pre-flight pass is the default opener.** The pre-flight
  variant (`teams/_PLAYBOOK.md` stage 3; `reference/lifecycle.md` Scenario 10)
  flips from opt-in to default; the lead opts *out* (per-[task] gates) only
  when the plan is genuinely emergent. The registry gate condition (no approval
  while exports are unregistered or consumed names uncited) is unchanged.
- **Emergent plans → rolling look-ahead.** When dispatching [task] N for
  implementation, the lead simultaneously triggers N+1's `[design-note]`; the
  PA reviews it while N is in flight. Skip the look-ahead when N+1 depends on
  N's implementation detail (same dependency test as Lever 4's dispatch rule).
  If N's later `[divergence]` invalidates an approved look-ahead design, the
  PA's sweep flags it and N+1 opens with a revised `[design-note]`
  (existing clause: `reference/lifecycle.md` Scenario 10 step 6, "unless a
  `[divergence]` or re-plan invalidated the note").

No new markers or protocol objects.

## Lever 4 — Pipelined dispatch (`MAX_ACTIVE_IMPLEMENTERS`)

### Config shape

```
EXECUTION=sequential            # unchanged; still the default and the proven path
EXECUTION=parallel              # gains one sub-key:
MAX_ACTIVE_IMPLEMENTERS=1       # 1 = pipelined dispatch (this spec)
                                # >=2 = full parallel (existing rules)
```

Under `parallel`, all existing isolation rules apply at any N — worktree +
task branch per [task] (`bin/launch-team.sh worktree`), integrator merges
serially in dependency order, same-file collisions handed back for rebase.
The knob only bounds how many [tasks] the lead may have in implementer hands
at once. Setting `MAX_ACTIVE_IMPLEMENTERS` while `EXECUTION=sequential` is a
config error (launcher validates; see *Files touched*).

### Dispatch rule

The lead sends assignment N+1 **when [task] N enters `[Review]`** — not after
integration — provided:

1. **Independence:** N+1 consumes no `CONTRACTS.md` export of any
   un-integrated [task] and is not expected to touch the same files. Dependent
   [task] → wait; never stack on an un-integrated branch (deferred).
2. **Sweep confirmed:** the PA's divergence sweep of N is confirmed (see
   *Sweep timing*).

No eligible independent [task] → the lead waits; pipelining is opportunistic,
never forced.

### Freeze protocol (RC-1; implements rework-preempts)

When N gets `[review-findings]` (→ `[Active]`) while N+1 is being implemented:

1. The lead sends the implementer a **supersession assignment**: park N+1 at a
   clean point, switch to N's worktree, deliver the rework and a fresh
   `[review-request]` before idling. Worktrees make the park safe — N+1's WIP
   sits untouched in its own tree.
2. The lead moves N+1 `Active → Blocked` with the comment:
   `Parked (pipelined): preempted by rework on <N>. Resume on <N> re-entering [Review].`
   Stuck-detection stays honest: a parked [task] reads as **Parked** (existing
   supervision category; `[Blocked]`'s owner is the team-lead — the parker and
   resumer, per `config/statuses.config.json`).
3. When N re-enters `[Review]`, the lead moves N+1 `Blocked → Active` and
   sends a fresh resume assignment.
4. **Oldest-first always:** rework on an older [task] outranks progress on a
   newer one. One implementer never holds two [tasks] hot at once.

Board support verified: `Active → Blocked` and `Blocked → Active` transitions
already exist in `config/statuses.config.json` — no board change.

### Sweep timing (RC-2)

Under `EXECUTION=parallel` (any N), the PA divergence sweep triggers at
**`[Review]` entry** instead of post-integration — all `[divergence]` comments
exist by then. Consequences:

- Dispatch of N+1 is gated on the PA's sweep confirmation for N (mailbox +
  tracker comment).
- Rework that adds new `[divergence]` comments gets an **incremental re-sweep**
  when N re-enters `[Review]`.
- If a sweep finding invalidates the already-dispatched N+1, the PA pings its
  implementer with a binding ruling — revised `[design-note]` if needed.
- `sequential` mode keeps the post-integration trigger unchanged.

### Enablement gates (RC-3, RC-4)

A **"Before you turn the knob"** checklist in `reference/orchestration.md`;
both items mandatory, results recorded (in `BASELINE.md` or on the feature's
tracker item):

1. **Machinery proof** (the existing parallel pre-validation, which applies at
   N=1 too): (a) `launch-team.sh worktree` creates a usable isolated tree in
   *your* environment (harness subagents included) and an implementer can
   build and test inside it; (b) a deliberate same-file collision across two
   task branches ends with the integrator merging the first and handing the
   second back for rebase; (c) `CONTRACTS.md` is populated during planning.
2. **Rework-rate threshold** (new): first-pass approval rate from the team's
   most recent comparable run must justify the overlap — guidance: enable at
   rework rate **< ~25%**; above that, apply Levers 1–3 first. Documented
   honestly: pipelined saves ≈ (review + integrate time) × (first-pass-approved
   [task] count); rework cycles gain nothing from it.

### Deliberately unchanged

- `TRACKER_WRITERS=lead` stays the recommended write path.
- QA's `[review-approval]` remains the serialized last-in-time gate.
- Relaunch hygiene gets structurally simpler: kill+relaunch = quarantine is
  just discarding the dead instance's worktree (satisfies feedback R2).

---

## Expected effect (per production-run numbers)

| Lever | Estimated saving per feature run | Cost |
|---|---|---|
| 1 — tiered/parallel review | 3–5 h | 1 config line + guidance |
| 2 — mandatory checklists | 3–5 h (rework rate ↓) | 3 file edits; +5–10 min/approval |
| 3 — design-wait elimination | 3.5–7 h | 2 doc edits |
| 4 — pipelined dispatch | ≈(review+integrate) × first-pass count — meaningful only after Lever 2 | doc edits + launcher validation + gates |

## Files touched

| File | Change |
|---|---|
| `reference/orchestration.md` | Execution modes (knob, dispatch rule, freeze protocol), Claiming (sweep gate), `[design-approved]` marker content, sweep timing, "Before you turn the knob" checklist |
| `config/team.config.md` | `MAX_ACTIVE_IMPLEMENTERS` key + comments; note that it is invalid under `sequential` |
| `teams/_PLAYBOOK.md` | Pre-flight pass as default opener; review-mode recommendation + tiered eligibility checklist; rolling look-ahead pattern; ASSIGN template carries the PA checklist |
| `reference/lifecycle.md` | Scenario 10 default-opener note; sweep-timing amendment cross-reference |
| `roles/principal-architect.md` | Checklist mandatory in all modes (checkpoint 2); sweep trigger at `[Review]` entry under `parallel` |
| `roles/team-lead.md` | Dispatch loop: pipelined dispatch rule, freeze protocol, look-ahead trigger |
| `roles/backend.md`, `roles/frontend.md`, `roles/reviewer.md`, `roles/qa.md` | Wording that assumes per-task worktrees are parallel-only / checklist-driven review inputs — touch only where wording conflicts |
| `bin/launch-team.sh` | Validate: `MAX_ACTIVE_IMPLEMENTERS` set while `EXECUTION=sequential` → die |
| `tests/launcher-test.sh` | One test for the new validation |

## Testing

- **Launcher validation test** (`tests/launcher-test.sh`): `MAX_ACTIVE_IMPLEMENTERS=1`
  with `EXECUTION=sequential` → non-zero exit with a clear message; with
  `EXECUTION=parallel` → accepted.
- **Doc consistency:** the repo's existing test suites (`launcher-test.sh`,
  `tracker-ops-test.sh`) must stay green; a consistency review pass over the
  changed docs (per the repo's established practice) checks that no section
  still asserts worktrees are unconditional or that the sweep is
  post-integration-only under `parallel`.
- **Runtime validation** is deliberately deferred to the enablement gates: the
  machinery proof (worktree-in-harness, rebase-handback, registry) runs as a
  controlled exercise before the knob is first enabled — documented as the
  checklist itself, not as CI.

## Out of scope

- `MAX_ACTIVE_IMPLEMENTERS >= 2` behavior changes (full parallel is already
  specified; only the shared pre-validation checklist references it).
- Stacked task branches (dependent [task] pipelining).
- Async/write-behind tracker layer (separate concern, discussed and parked).
