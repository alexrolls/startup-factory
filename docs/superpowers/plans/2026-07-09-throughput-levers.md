# Throughput Levers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the four-lever throughput design (spec: `docs/superpowers/specs/2026-07-09-throughput-levers-design.md`): review-window compression guidance, mandatory design checklists, design-wait elimination, and gated pipelined dispatch via `MAX_ACTIVE_IMPLEMENTERS`.

**Architecture:** This is a protocol-documentation change plus one launcher guard. The knob is a concurrency cap under the existing `EXECUTION=parallel` machinery (no new mode); all behavior rules land in `reference/orchestration.md` and are narrowed by role briefs and the playbook, following the repo's existing layering (protocol → briefs → playbook → config).

**Tech Stack:** Markdown protocol docs, bash (`bin/launch-team.sh`, `tests/launcher-test.sh`).

## Global Constraints

- Config keys are read with plain `grep '^KEY='` — one `KEY=value` per line inside fenced blocks, no spaces around `=` (`config/team.config.md` → Rules).
- Markers are machine-readable protocol: never invent new ones, never rename existing ones. This plan adds NO new markers.
- Bracketed vocabulary (`[task]`, `[feature]`, `[design-note]`, `[Review]`, …) must be used exactly as in existing docs.
- The knob key is spelled `MAX_ACTIVE_IMPLEMENTERS` everywhere — no variants.
- The freeze-protocol comment is spelled exactly: `Parked (pipelined): preempted by rework on <N>. Resume on <N> re-entering [Review].`
- Both test suites must stay green: `tests/launcher-test.sh` and `tests/tracker-ops-test.sh` end with `ALL PASS`.
- Work on a feature branch: `feature/throughput-levers` off `main`.

---

### Task 0: Create the feature branch

**Files:** none (git only)

- [ ] **Step 1: Branch**

```bash
cd "$(git rev-parse --show-toplevel)"
git checkout -b feature/throughput-levers main
```

---

### Task 1: Launcher guard — `MAX_ACTIVE_IMPLEMENTERS` requires `EXECUTION=parallel`

**Files:**
- Modify: `bin/launch-team.sh` (add `validate_config` after the `role_cmd_key`/`key_is_null` helpers, near line 35; call it before the main `case`)
- Test: `tests/launcher-test.sh` (insert before the `# -- status + stop` section)

**Interfaces:**
- Consumes: `read_key` (existing: returns `''` for `null`/missing keys), `die`.
- Produces: launcher exits non-zero with a message containing `MAX_ACTIVE_IMPLEMENTERS` when the key is set while `EXECUTION` is not `parallel`, or when it is not a positive integer.

- [ ] **Step 1: Write the failing tests**

In `tests/launcher-test.sh`, insert this block immediately BEFORE the line `# -- status + stop --------------------------------------------------------------`:

```bash
# -- config guard: MAX_ACTIVE_IMPLEMENTERS requires EXECUTION=parallel ---------
CFG=.claude/skills/pm/config/team.config.md
printf 'MAX_ACTIVE_IMPLEMENTERS=1\n' >> "$CFG"
if out="$("$LAUNCH" compose test-feature FEAT-1 backend 2>&1)"; then
  echo "FAIL: MAX_ACTIVE_IMPLEMENTERS under sequential should be refused"; FAILURES=$((FAILURES+1))
elif printf '%s' "$out" | grep -q "MAX_ACTIVE_IMPLEMENTERS"; then
  echo "ok: knob refused under sequential"
else
  echo "FAIL: knob refusal has wrong message: $out"; FAILURES=$((FAILURES+1))
fi
printf 'EXECUTION=parallel\n' >> "$CFG"
check "knob accepted under parallel" "$LAUNCH" compose test-feature FEAT-1 backend
sed -i '' '/^MAX_ACTIVE_IMPLEMENTERS=1$/d;/^EXECUTION=parallel$/d' "$CFG"
printf 'EXECUTION=parallel\nMAX_ACTIVE_IMPLEMENTERS=zero\n' >> "$CFG"
if "$LAUNCH" compose test-feature FEAT-1 backend >/dev/null 2>&1; then
  echo "FAIL: non-integer MAX_ACTIVE_IMPLEMENTERS should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: non-integer knob refused"
fi
sed -i '' '/^EXECUTION=parallel$/d;/^MAX_ACTIVE_IMPLEMENTERS=zero$/d' "$CFG"
```

Note: the fixture config has no `EXECUTION` line, so the first case exercises the "absent = sequential" default. The `sed -i ''` form is macOS bash — this suite already runs on darwin.

- [ ] **Step 2: Run the suite to verify the new checks fail**

Run: `bash tests/launcher-test.sh 2>&1 | tail -8`
Expected: `FAIL: MAX_ACTIVE_IMPLEMENTERS under sequential should be refused` (the guard doesn't exist yet, so compose succeeds), and the suite exits with `FAILURE(S)`.

- [ ] **Step 3: Implement the guard**

In `bin/launch-team.sh`, add after the `key_is_null()` function definition:

```bash
validate_config() { # MAX_ACTIVE_IMPLEMENTERS is a parallel-only knob (spec: throughput levers)
  local exec_mode max_active
  exec_mode="$(read_key EXECUTION)"
  max_active="$(read_key MAX_ACTIVE_IMPLEMENTERS)"
  [ -z "$max_active" ] && return 0
  [ "$exec_mode" = "parallel" ] || die "MAX_ACTIVE_IMPLEMENTERS is set but EXECUTION is '${exec_mode:-sequential}' — the knob only applies under EXECUTION=parallel"
  case "$max_active" in
    ''|*[!0-9]*) die "MAX_ACTIVE_IMPLEMENTERS must be a positive integer, got '$max_active'" ;;
  esac
  [ "$max_active" -ge 1 ] || die "MAX_ACTIVE_IMPLEMENTERS must be >= 1"
}
```

Then, immediately before the main `case "${1:-}" in` dispatch, add:

```bash
case "${1:-}" in validate-board|'') ;; *) validate_config ;; esac
```

(`validate-board` checks a board config file and must not depend on team-config sanity; `''` falls through to the usage error.)

- [ ] **Step 4: Run the suite to verify it passes**

Run: `bash tests/launcher-test.sh 2>&1 | tail -8`
Expected: `ok: knob refused under sequential`, `ok: knob accepted under parallel`, `ok: non-integer knob refused`, ending `ALL PASS`.

- [ ] **Step 5: Commit**

```bash
git add bin/launch-team.sh tests/launcher-test.sh
git commit -m "feat: launcher guard — MAX_ACTIVE_IMPLEMENTERS requires EXECUTION=parallel"
```

---

### Task 2: `config/team.config.md` — declare the knob

**Files:**
- Modify: `config/team.config.md` (Coordination fenced block, after the `EXECUTION=` comment lines ending `# merge; REQUIRED the moment >=2 implementers should work` / `# concurrently (reference/orchestration.md → "Execution modes")`)

**Interfaces:**
- Produces: the key `MAX_ACTIVE_IMPLEMENTERS=null` with semantics comment; every later doc task refers to this exact key name.

- [ ] **Step 1: Add the key**

Append inside the Coordination fenced block, directly after the `EXECUTION=sequential` entry's last comment line:

```
MAX_ACTIVE_IMPLEMENTERS=null     # Only under EXECUTION=parallel. 1 = pipelined dispatch:
                                 # full worktree isolation, but the team-lead dispatches
                                 # the next [task] when the current one enters [Review]
                                 # instead of after integration (reference/orchestration.md
                                 # → "Execution modes"). >=2 = bounded full parallelism;
                                 # null = unbounded parallel. Setting it under sequential
                                 # is a config error — the launcher refuses to run.
```

- [ ] **Step 2: Verify the launcher still accepts the default config**

Run: `bash tests/launcher-test.sh 2>&1 | tail -3`
Expected: `ALL PASS` (the fixture writes its own config; this catches accidental fence breakage via the repo copy used by `compose` in other tests).

- [ ] **Step 3: Commit**

```bash
git add config/team.config.md
git commit -m "feat: MAX_ACTIVE_IMPLEMENTERS key in team config"
```

---

### Task 3: `reference/orchestration.md` — knob semantics, sweep timing, checklist, marker content

**Files:**
- Modify: `reference/orchestration.md` — four edits: (a) Execution modes section, (b) pre-parallel validation checklist, (c) `[design-approved]` marker row, (d) Claiming step 2.

**Interfaces:**
- Consumes: `MAX_ACTIVE_IMPLEMENTERS` key name (Task 2).
- Produces: the canonical rules every brief cites — "Execution modes" gains the *pipelined dispatch* rules (dispatch-on-Review, independence test, freeze protocol, sweep timing); the validation checklist becomes "before setting `EXECUTION=parallel` at any cap"; `[design-approved]` requires a numbered checklist.

- [ ] **Step 1: Edit (a) — insert the knob bullet in "Execution modes"**

Insert AFTER the `**`parallel`.**` bullet (ends `…handed back to the implementer for rebase.`) and BEFORE the paragraph starting `Deliberately **not** mode-dependent:`:

```markdown
- **Concurrency cap — `MAX_ACTIVE_IMPLEMENTERS` (parallel only).** Bounds how
  many [tasks] may be in implementer hands at once; `null` leaves parallelism
  unbounded. With the cap set (any value), claims are **lead-dispatched**
  exactly as in sequential mode — the cap lives in the lead's single dispatch
  point, never in self-claiming agents racing the tracker. Setting the key
  under `EXECUTION=sequential` is a config error (the launcher refuses it).

  `MAX_ACTIVE_IMPLEMENTERS=1` is **pipelined dispatch**: full parallel
  isolation (worktree + task branch per [task], serial integrator merges), but
  the lead sends assignment N+1 when [task] N **enters `[Review]`** rather
  than after integration — N's review, rework, and integration overlap N+1's
  implementation. Its rules:

  - **Independence.** N+1 must consume no `CONTRACTS.md` export of any
    un-integrated [task] and must not be expected to touch the same files.
    No independent [task] ready → the lead waits; never stack a task branch
    on un-integrated work.
  - **Sweep gate.** N+1 is dispatched only after the principal-architect
    confirms its divergence sweep of N (see *Sweep timing* below).
  - **Freeze protocol — rework preempts.** If N gets `[review-findings]`
    while N+1 is being implemented: the lead sends a supersession assignment
    (park N+1 at a clean point — its WIP is safe in its own worktree — switch
    to N's worktree, deliver the rework and a fresh `[review-request]` before
    idling), moves N+1 `Active → Blocked` with the comment
    `Parked (pipelined): preempted by rework on <N>. Resume on <N> re-entering [Review].`,
    and when N re-enters `[Review]`, moves N+1 `Blocked → Active` with a
    fresh resume assignment. Oldest [task] first, always; one implementer
    never holds two [tasks] hot at once. A parked [task] reads as **Parked**
    in the supervision loop, not Stuck.
  - **Sweep timing.** Under `parallel` (any cap), the principal-architect's
    divergence sweep for a [task] runs at **`[Review]` entry** instead of
    post-integration — every `[divergence]` comment exists by then. Rework
    that adds new `[divergence]` comments gets an incremental re-sweep at
    `[Review]` re-entry. A sweep finding that invalidates an
    already-dispatched [task] is a binding mailbox ruling to its implementer
    (revised `[design-note]` if needed). Sequential mode keeps the
    post-integration trigger.
  - **When to enable.** Only after the pre-parallel validation checklist
    below passes — including its pipelined rework-rate item.
```

- [ ] **Step 2: Edit (b) — widen the pre-parallel validation checklist**

Replace the line:

```markdown
**Before switching to `parallel`, validate the machinery once** — docs are not
evidence, and a sequential run proves nothing about it:
```

with:

```markdown
**Before setting `EXECUTION=parallel` — at any `MAX_ACTIVE_IMPLEMENTERS`,
pipelined `1` included — validate the machinery once** — docs are not
evidence, and a sequential run proves nothing about it. Record what ran and
where (in `BASELINE.md` or on the [feature]):
```

Then append a fourth item after item 3 (`…the plan-time contract forks that parallel planning actually produces.`):

```markdown
4. **Pipelined (`MAX_ACTIVE_IMPLEMENTERS=1`) additionally requires:** the
   team's most recent comparable run shows a first-pass rework rate below
   ~25%. Pipelined saves ≈ (review + integrate time) × (first-pass-approved
   [task] count); rework cycles gain nothing from it — at a high rework rate,
   fix review predictability first (mandatory design checklists,
   `REVIEW_MODE` — see `teams/_PLAYBOOK.md` → *Review modes*).
```

- [ ] **Step 3: Edit (c) — `[design-approved]` marker row**

In the *Structured comments* table, replace the `[design-approved]` row:

```markdown
| `[design-approved]` | principal-architect | Gate open. May carry conditions the implementation must honour. |
```

with:

```markdown
| `[design-approved]` | principal-architect | Gate open. Carries a **numbered architecture checklist** — the items the architecture review will verify — plus any binding conditions. The lead delivers the checklist in the assignment; reviewer/QA Phase-1 checklists start from it (add items, never subtract). |
```

- [ ] **Step 4: Edit (d) — Claiming step 2**

In *Claiming a [task]* step 2, replace the sentence:

```markdown
Also verify the previously integrated [task] on your track has no `[divergence]` comments still awaiting the principal-architect's sweep — if it does, wait or ask the PA by mailbox.
```

with:

```markdown
Also verify the sweep is not pending on your track: under `EXECUTION=sequential`, the previously integrated [task] has no `[divergence]` comments still awaiting the principal-architect's sweep; under `parallel`, the most recent [task] that entered `[Review]` on your track has the PA's sweep confirmation. If pending, wait or ask the PA by mailbox.
```

And in the same step, replace:

```markdown
Under `EXECUTION=sequential`, you claim only on the team-lead's assignment (never self-serve — see *Execution modes*)
```

with:

```markdown
Under `EXECUTION=sequential` — and under `parallel` whenever `MAX_ACTIVE_IMPLEMENTERS` is set — you claim only on the team-lead's assignment (never self-serve — see *Execution modes*)
```

- [ ] **Step 5: Verify and commit**

Run: `grep -c "MAX_ACTIVE_IMPLEMENTERS" reference/orchestration.md`
Expected: `4` or more (knob bullet ×2+, checklist item, claiming step).

Run: `grep -n "Parked (pipelined)" reference/orchestration.md`
Expected: exactly 1 match, spelled per Global Constraints.

```bash
git add reference/orchestration.md
git commit -m "feat: pipelined dispatch rules, sweep-at-Review-entry, design checklists in protocol"
```

---

### Task 4: `roles/principal-architect.md` — mandatory checklist + sweep trigger

**Files:**
- Modify: `roles/principal-architect.md` — checkpoint 2 and the "Your exclusive right: task descriptions" section.

**Interfaces:**
- Consumes: `[design-approved]` checklist rule (Task 3c), sweep timing (Task 3a).

- [ ] **Step 1: Checkpoint 2 — checklist in every mode**

Replace (checkpoint 2, currently):

```markdown
2. **Design gate — every [task], before any code.** Answer every `[design-note]`
   with `[design-approved]` (optionally with binding conditions) or
   `[design-pushback]` (numbered required changes). Backend [tasks] always get a
   full design review. Frontend [tasks] declare `Architectural impact: yes/no`;
   for a credible "no", reply `[design-approved]` fast — keep the gate cheap where
   it should be cheap. When the team runs `REVIEW_MODE=tiered`
   (`teams/_PLAYBOOK.md` → *Review modes*) and the [task] qualifies for a
   combined review, attach a **numbered architecture checklist** to your
   `[design-approved]` — it is what QA executes in your stead at review time.
```

with:

```markdown
2. **Design gate — every [task], before any code.** Answer every `[design-note]`
   with `[design-approved]` or `[design-pushback]` (numbered required changes).
   Every `[design-approved]` carries a **numbered architecture checklist** — the
   items you will verify at architecture-review time — plus any binding
   conditions. The checklist is the implementer's target (the lead delivers it
   in the assignment message) and the seed of the reviewer's Phase-1 checklist
   (reviewers add items, never subtract). In `REVIEW_MODE=tiered` combined
   reviews (`teams/_PLAYBOOK.md` → *Review modes*), QA executes your checklist
   in your stead at review time — write it to be executable without you.
   Backend [tasks] always get a full design review. Frontend [tasks] declare
   `Architectural impact: yes/no`; for a credible "no", reply
   `[design-approved]` fast — the checklist may be short, never absent.
```

- [ ] **Step 2: Sweep trigger amendment**

In "Your exclusive right: task descriptions", after the sentence ending `This sweep blocks the next [task] from being claimed on your track — do it promptly.`, append:

```markdown
Under `EXECUTION=parallel` your sweep for a [task] runs when it **enters
`[Review]`** (every `[divergence]` comment exists by then) and gates the
lead's dispatch of the next [task] — confirm completion by mailbox and
tracker comment. Rework that adds new `[divergence]` comments gets an
incremental re-sweep at `[Review]` re-entry. A finding that invalidates an
already-dispatched [task] is a binding mailbox ruling to its implementer —
revised `[design-note]` if needed. Sequential mode keeps the
post-integration trigger.
```

- [ ] **Step 3: Verify and commit**

Run: `grep -n "numbered architecture checklist" roles/principal-architect.md`
Expected: 1 match in checkpoint 2.

```bash
git add roles/principal-architect.md
git commit -m "feat: PA brief — mandatory design checklist, sweep at [Review] entry under parallel"
```

---

### Task 5: `roles/team-lead.md` — pipelined dispatch + design-gate look-ahead

**Files:**
- Modify: `roles/team-lead.md` — Phase 1, after step 8.

**Interfaces:**
- Consumes: dispatch rules and freeze protocol exactly as defined in Task 3a; look-ahead pattern (spec Lever 3).

- [ ] **Step 1: Add steps 9 and 10**

Append after step 8 (`…cannot race a claim you never issued.`):

```markdown
9. **Pipelined execution (`EXECUTION=parallel` + `MAX_ACTIVE_IMPLEMENTERS=1`):
   dispatch on `[Review]` entry.** You still dispatch every claim (the cap
   lives in your single dispatch point), but you send assignment N+1 the
   moment [task] N enters `[Review]` — provided N+1 consumes no `CONTRACTS.md`
   export of any un-integrated [task], is not expected to touch its files, and
   the principal-architect has confirmed its sweep of N. No independent [task]
   ready → wait. Rework preempts (protocol: *Execution modes* → freeze
   protocol): if N bounces while N+1 is in flight, send a supersession
   assignment (park N+1, fix N, fresh `[review-request]` first), move N+1
   `Active → Blocked` with the parked comment, and resume it
   (`Blocked → Active`, fresh assignment) when N re-enters `[Review]`.
   Oldest [task] first, always.
10. **Keep the design gate ahead of the dispatch (any mode).** Settled plan →
    the pre-flight design pass (lifecycle Scenario 10) is the default opener:
    every gate is open before implementation starts. Emergent plan → rolling
    look-ahead: when dispatching [task] N, trigger N+1's `[design-note]` so
    the principal-architect reviews it while N is in flight; skip the
    look-ahead when N+1 depends on N's implementation detail.
```

- [ ] **Step 2: Verify and commit**

Run: `grep -n "supersession" roles/team-lead.md reference/orchestration.md`
Expected: 1 match in each file.

```bash
git add roles/team-lead.md
git commit -m "feat: team-lead brief — pipelined dispatch, freeze protocol, design-gate look-ahead"
```

---

### Task 6: `teams/_PLAYBOOK.md` — pre-flight default, review-mode guidance, ASSIGN checklist line

**Files:**
- Modify: `teams/_PLAYBOOK.md` — stage 3, *Review modes*, ASSIGN template.

**Interfaces:**
- Consumes: checklist marker content (Task 3c), tiered eligibility conditions (spec Lever 1).

- [ ] **Step 1: Stage 3 — pre-flight becomes the default opener**

Replace the stage-3 pre-flight paragraph:

```markdown
   *Pre-flight variant (lifecycle Scenario 10):* when the plan should be settled
   before any code, run all design gates as one batch — notes for every [task]
```

with:

```markdown
   *Pre-flight pass (lifecycle Scenario 10) — the **default opener**:* unless
   the plan is genuinely emergent, run all design gates as one batch — notes
   for every [task]
```

(the rest of the paragraph is unchanged), and append at the end of the same paragraph, after `At claim time each gate is already open.`:

```markdown
   For genuinely emergent plans, keep the gate ahead of the dispatch with a
   rolling look-ahead instead: when [task] N is dispatched, N+1's
   `[design-note]` is written and reviewed while N is in flight (skip when
   N+1 depends on N's implementation detail).
```

- [ ] **Step 2: Review modes — recommendation + tiered eligibility test**

Append after the `tiered` bullet (ends `…independent evidence rather than extra findings.`), before the `Whatever the mode` paragraph:

```markdown
**Recommendation:** `sequential` for a team's first feature; `tiered` once the
team has run history. Tiered eligibility is a mechanical test the lead applies
at dispatch — combined review only if (a) the `[design-note]` declared
`Architectural impact: no` **and** (b) the [task] touches no contract
registered in `CONTRACTS.md`; anything else gets full dual review.
```

- [ ] **Step 3: ASSIGN template — deliver the checklist**

In the ASSIGN template, after the `Inputs:` lines and before `Baseline:`, add:

```
Checklist: numbered architecture checklist from [design-approved] — implement
        to satisfy every item
```

- [ ] **Step 4: Verify and commit**

Run: `grep -n "default opener" teams/_PLAYBOOK.md`
Expected: 1 match in stage 3.

```bash
git add teams/_PLAYBOOK.md
git commit -m "feat: playbook — pre-flight default opener, review-mode guidance, ASSIGN checklist line"
```

---

### Task 7: `reference/lifecycle.md` — Scenario 10 default note + sweep cross-reference

**Files:**
- Modify: `reference/lifecycle.md` — Scenario 10 intro and step 6.

**Interfaces:**
- Consumes: sweep timing (Task 3a), default-opener rule (Task 6).

- [ ] **Step 1: Scenario 10 intro**

After the intro sentence ending `— run the gates as one batch instead:`, the paragraph break, add before the numbered list:

```markdown
For preset teams this batch is the **default opener** (`teams/_PLAYBOOK.md`
stage 3); per-[task] gates at claim time are the opt-out for genuinely
emergent plans.
```

- [ ] **Step 2: Step 6 sweep cross-reference**

Replace Scenario 10 step 6's ending:

```markdown
   approval needed unless a `[divergence]` or re-plan invalidated the note.
```

with:

```markdown
   approval needed unless a `[divergence]` or re-plan invalidated the note
   (under `EXECUTION=parallel` the sweep that flags this runs at `[Review]`
   entry — see `reference/orchestration.md` → *Execution modes*).
```

- [ ] **Step 3: Verify and commit**

Run: `grep -n "default opener" reference/lifecycle.md`
Expected: 1 match.

```bash
git add reference/lifecycle.md
git commit -m "feat: lifecycle — Scenario 10 default opener, sweep-timing cross-reference"
```

---

### Task 7b: Role briefs — claim dispatch under the cap, checklist seeding

**Files:**
- Modify: `roles/backend.md` (Loop step 1), `roles/reviewer.md` (Phase 1), `reference/orchestration.md` (Dual review, reviewer phase 1 sentence)

**Interfaces:**
- Consumes: lead-dispatched-claims rule (Task 3d), `[design-approved]` checklist (Task 3c).

- [ ] **Step 1: backend.md — claims are lead-dispatched under the cap too**

Replace in Loop step 1:

```markdown
   `EXECUTION=sequential`: claim only the [task] the team-lead's assignment
   message names — never self-claim — and only with the shared checkout free.
```

with:

```markdown
   `EXECUTION=sequential` — and `parallel` whenever `MAX_ACTIVE_IMPLEMENTERS`
   is set — claim only the [task] the team-lead's assignment message names,
   never self-claim; in sequential additionally only with the shared checkout
   free.
```

(`roles/frontend.md` needs no edit — it defers to "the protocol and the backend
brief"; `roles/qa.md` and `roles/integrator.md` are already EXECUTION-conditional.)

- [ ] **Step 2: reviewer.md — Phase-1 checklist seeded by the design checklist**

Replace in Phase 1:

```markdown
Extract every business rule, validation, edge case,
and permission check into your own numbered checklist.
```

with:

```markdown
Extract every business rule, validation, edge case,
and permission check into your own numbered checklist — seeded by the numbered
architecture checklist in the `[design-approved]` (you add items, never
subtract).
```

- [ ] **Step 3: orchestration.md — Dual review phase-1 sentence**

In *Dual review*, replace:

```markdown
(1) *Plan*: before reading any code, read the
  [feature] and [task], extract every business rule / validation / edge case into an
  independent checklist with an expected file list.
```

with:

```markdown
(1) *Plan*: before reading any code, read the
  [feature] and [task], extract every business rule / validation / edge case into an
  independent checklist — seeded by the `[design-approved]` architecture
  checklist (add items, never subtract) — with an expected file list.
```

- [ ] **Step 4: Verify and commit**

Run: `grep -rn "add items, never subtract\|never subtract" roles/reviewer.md reference/orchestration.md roles/principal-architect.md | wc -l`
Expected: `4` (marker table, Dual review, reviewer brief, PA brief).

```bash
git add roles/backend.md roles/reviewer.md reference/orchestration.md
git commit -m "feat: role briefs — lead-dispatched claims under the cap, checklist-seeded reviews"
```

---

### Task 8: Consistency review + full validation

**Files:** none new — verification and fixes only.

- [ ] **Step 1: Run both suites**

```bash
bash tests/launcher-test.sh 2>&1 | tail -3
bash tests/tracker-ops-test.sh 2>&1 | tail -3
```

Expected: both end `ALL PASS`.

- [ ] **Step 2: Cross-doc consistency greps**

```bash
# Key spelled identically everywhere it appears:
grep -rn "MAX_ACTIVE" --include="*.md" --include="*.sh" . | grep -v "MAX_ACTIVE_IMPLEMENTERS" ; echo "expect: no output"
# No doc still claims the sweep is post-integration-only without the parallel carve-out:
grep -n "After every integration" roles/principal-architect.md ; echo "expect: 1 hit, immediately followed by the parallel amendment added in Task 4"
# Freeze comment spelled once per file that defines/uses it:
grep -rn "Parked (pipelined)" --include="*.md" .
# expect: reference/orchestration.md and roles/team-lead.md refer to it; identical spelling
```

Fix any inconsistency found, amend the relevant commit or add a `fix:` commit.

- [ ] **Step 3: Read-through check**

Re-read the changed sections of `reference/orchestration.md` and `teams/_PLAYBOOK.md` end-to-end once, checking: no section still asserts worktrees are unconditional; sequential-mode text is untouched; no new markers were introduced.

- [ ] **Step 4: Final commit if fixes were made, then summarize**

```bash
git log --oneline main..HEAD
```

Expected: ~8 commits (Tasks 1–7b), all suites green.

---

## Out of scope (per spec)

- `MAX_ACTIVE_IMPLEMENTERS >= 2` behavior changes.
- Stacked task branches.
- Async/write-behind tracker layer.
- Running the enablement-gate machinery proof (that is a runtime exercise for a real team run, not CI).
