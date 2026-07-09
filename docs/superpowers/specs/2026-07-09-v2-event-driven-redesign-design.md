# v2 — Event-Driven, Batched, Evidence-Based Orchestration — Design

**Date:** 2026-07-09
**Status:** Proposed (pending user spec review)
**Branch:** `feature/v2-event-driven-redesign`
**Method:** six-role team research (team-lead, project-manager, product-manager,
principal-architect, fullstack-engineer, qa-engineer) over three sources, synthesized.

## Problem

A production run on coachbot-monorepo (Linear, full-stack preset, CLI runtime)
spent **~3 h on 1 [task]** in its slow phase vs **~55 min for 4 [tasks] + 1 defect**
in its fast phase — identical rigor, different coordination. Root causes
(`AGENT_SQUAD_PM_SESSION_RESEARCH.md`):

1. **Execution-model mismatch.** The skill's docs assume long-running agents;
   the CLI runtime gives one-shot `claude -p` processes. Agents wrote "I'll poll
   again in ~2 minutes" and exited; every gate transition silently stalled until
   a human relaunched the right role (≥4 stalls × 5–20 min; 60–90 min of pure
   ceremony on one [task]).
2. **Dead launch.** The Linear adapter doc drifted from the real environment
   (server name / tool prefix / deferred loading); all five agents concluded
   "tracker unavailable" — ~40 min lost before a single tracker write.
3. **Unverifiable claims.** Unprovisioned worktrees (no `node_modules`/`dist`)
   produced two false "tests green" claims → integrator andon (11 failures),
   QA rejection (5 failures), a full extra review round each time.
4. **Unenforced marker ownership.** The architect twice posted the QA-owned
   `[review-approval]`; only manual supervision stopped red tests from merging.
5. **Tracker noise.** Multi-KB comments, superseded approvals stacking, no
   human-readable board state; the escalation channel sat empty when human
   decisions were genuinely needed.

What must NOT change: tracker-as-single-source-of-truth (~20 relaunches
recovered from tracker state alone), structured markers, batched gates,
dual review with executed evidence (caught a real data-correctness bug and,
in the inscribed run, a cross-tenant IDOR), the Scenario-6 discipline.

## Inputs

1. `~/Projects/coachbot-monorepo/AGENT_SQUAD_PM_SESSION_RESEARCH.md` — coachbot run, T1–T10.
2. `FEEDBACK-parallel-and-worktrees.md` — inscribed run (harness mode), R1–R6.
3. Current repo post-PR #5 (`throughput-levers`): EXECUTION modes, pipelined
   dispatch (`MAX_ACTIVE_IMPLEMENTERS`), review modes, design checklists,
   design-wait elimination, freeze protocol, sweep timing, enablement gates.

### Already shipped — not re-solved here

Cross-mapping T1–T10 × R1–R6 against the merged work: R1 (execution modes),
R4 (machinery-proof gate), R5 (idle-without-marker = Stuck), R6 (single-writer
tracker + serialized QA gate), Lever 1–4 (review modes, mandatory design
checklists, pre-flight default opener + rolling look-ahead, pipelined dispatch)
are **done**. R2 (relaunch quarantine) and R3 (CONTRACTS.md at planning) are
partially done. This spec covers only the remainder.

## Arbitrated decisions

| Tension | Position |
|---|---|
| Dispatcher now (coachbot T1, team-lead, architect) vs Phase 2 (product-manager) | **Ship it now, as Option C** (below). The 60–90 min poll-gap was the single largest cost and hits CLI mode — the runtime the coachbot session used. Constraint honored: pure deterministic bash reusing `tracker-ops.sh`; nothing speculative. |
| Parallel-by-default (coachbot T6) vs sequential-first (inscribed R1) | **Sequential stays the default**; the throughput-levers dial (`sequential` → `parallel+MAX=1` → `parallel+MAX≥2`) and its enablement gates are unchanged. `MAX≥2` remains out of scope. |
| Worktree per task (coachbot T4) vs per instance (inscribed R2) | **Both, one rule:** the worktree is the *instance's* scratch space for a [task] — `<team>/<role>#<attempt>-<taskId>/`, provisioned by `WORKTREE_SETUP`, discarded on kill+relaunch. |
| Dispatcher as an agent role | **Vetoed** (principal-architect). LLM self-scheduling is the original failure mode. The dispatcher is a thin shell script (CLI) or the harness orchestrator itself (harness) — never a third agent. |

## Rigor invariants (may never be weakened)

- **I1** QA always re-executes suites independently — evidence is context, not gate.
- **I2** Integrator always re-executes suites independently.
- **I3** QA approval is always last-in-time.
- **I4** Approved file list == `git diff --name-only` at the cited commit; post-approval change voids the approval.
- **I5** No self-approval — independent-verifier substitution is mandatory when the marker owner is the implementer.
- **I6** Idle without a delivered artifact = Stuck immediately (enforced, not advisory).
- **I7** A validation claim without an evidence record is treated as NOT validated.

---

## Target architecture

Eight components. A–C fix the stalls and dead launches; D–E fix unverifiable
claims and self-approval; F–H fix tracker noise and the human interface.

### A. Dispatcher — the loop lives outside the agent

**Core principle:** "dispatch" is one stateless read-and-act pass; the loop is
owned by machinery, never by an agent's promise to check back.

New doc **`reference/dispatch.md`** — the single source of dispatch logic,
shared by both runtimes:

| Event (tracker + mailbox + heartbeats) | Action |
|---|---|
| `[Planned]` task, blockers terminal, slot free per EXECUTION/MAX | Launch implementer with ASSIGN |
| `[design-note]` without PA verdict | Launch PA — batch: all pending design gates, one boot |
| Task(s) in `[Review]` | Launch reviewer/PA — batch: drain the whole queue |
| All required approvals present | Launch integrator — batch: dependency order |
| `[Blocked]` task, all `blockedBy` terminal | Auto `Blocked → Active` + comment (no agent launch) |
| Heartbeat stale OR idle-without-artifact | Unblock ladder (rung 1; rung 3/4 on repeat) |
| Nothing actionable | Exit cleanly |

**CLI runtime:** `bin/dispatch.sh <team> <featureId> [--once|--watch]` — pure
bash + the same inline-Python pattern as `tracker-ops.sh`. One
`tracker-ops.sh export` per cycle drives the whole decision tree; launches go
through `launch-team.sh start` (never the tracker directly). Dedup via tmux
window names / `kill -0` on pid files. `--watch` = `--once` in a
`sleep POLL_INTERVAL_SECONDS` loop — zero LLM tokens per cycle; documented
honestly as requiring a persistent shell (tmux/nohup) owned by the human.
`--once` prints the action plan it took.

**Harness runtime:** the team-lead orchestrator IS the dispatcher — same
`dispatch.md` event table, executed natively (subagent spawn = role launch,
idle notifications = heartbeats). No new mechanism; `launch-team.sh compose`
already emits the prompts it needs.

**Auto-unblock scope:** only on adapters with a reliable `blockedBy` read
(Linear, Jira). GitHubIssues (label convention) and Markdown (prose parsing)
are suggest-only: the dispatcher flags, the lead confirms.

**Role-brief purge:** every "I'll check back / poll again / wait for" line is
replaced with **"end of turn = deliver your artifact and exit; the dispatcher
owns time."** The capability-matrix "relaunch on a schedule" footnote becomes
the first-class model. The Lever-4 pipelined policy (independence check, sweep
confirmation, freeze protocol) is unchanged — the dispatcher is the *trigger
mechanism* that makes "the moment N enters `[Review]`" actually fire.

### B. Preflight — fail before five agents do

`launch-team.sh preflight <team> <featureId>` (auto before `team`;
`--skip-preflight` for development):

1. `validate-board` (exists) — config sanity first.
2. Adapter read probe: `tracker-ops.sh export <featureId> /dev/null` —
   surfaces credentials/network/naming errors in one cheap call.
3. Workspace write test on `.teamwork/<team>/`.
4. UTC pin: `date -u` output written to `.teamwork/<team>/preflight/utc.txt`
   and injected into every composed prompt (kills the timezone-suffix bug).
5. **MCP tool discovery (LLM probe, not bash):** for MCP-based adapters, a
   minimal one-shot agent resolves the real tool prefix (deferred-tool loading
   included) and writes it to `.teamwork/<team>/preflight/tool-prefix.txt`;
   `compose_prompt` injects "Verified tool prefix: …" into every brief.

Abort with one actionable error before any role starts. Adapter docs' 
*Initialization* sections gain: "executed once by preflight, not per-agent" —
and the per-agent "if you can't reach the tracker, try…" prose is deleted.

### C. Worktree policy — instance-bound and provisioned

| Mode | Worktree | Provisioning |
|---|---|---|
| `sequential` | None (feature-branch checkout; quarantine-on-relaunch via existing `git stash -u`) | n/a |
| `parallel` (any N, incl. pipelined) | One per implementer **instance/attempt**: `<team>/<role>#<attempt>-<taskId>/` | `WORKTREE_SETUP` |

New `team.config.md` key: `WORKTREE_SETUP=null` (e.g.
`pnpm install --frozen-lockfile && pnpm --filter <scope>^... build`), executed
by `launch-team.sh worktree` on first creation, fail-loud. New
`worktree-remove` subcommand: `git worktree remove --force` + `git worktree
prune`, called by the integrator at completion (fixes the leaked-registration
incident).

Kill+relaunch = discard the dead instance's worktree; the successor starts
clean (completes inscribed R2 for the parallel path).

### D. Evidence ledger — verify instead of re-derive

Every `[review-request]` carries, per validated command:

```
Evidence:
  commit:   <sha at execution time>
  command:  <exact command>
  exit:     <code>
  counts:   <e.g. 47 passed, 0 failed, 2 skipped>
  duration: <seconds>
  log:      .teamwork/<team>/artifacts/<taskId>/validate-<round>-<role>.log
NOT validated:
  <command> — <reason>
```

A claim without its record = NOT validated (I7). Review policy matrix:

| Role | Suites | Condition |
|---|---|---|
| Implementer | Runs; records evidence | Always |
| Principal architect | Inspect + spot-check, **no blind re-run** | Only if evidence `commit == HEAD`; else re-run |
| QA final gate | **Always re-runs** | Unconditional (I1) |
| Integrator | **Always re-runs** | Unconditional (I2) |

Any mismatch between evidence and a re-run → `[review-findings]` with
`trust-breach (severity: critical)`, resolvable only by a fresh implementer
run + new record. Expected effect: removes 1–2 redundant suite executions per
round while keeping the two independent executions that caught real bugs.

### E. Marker authorization — ownership enforced, not narrated

New `"markers"` section in `statuses.config.json` (preset-overridable):

```json
"markers": {
  "design-approved":       { "authorizedRoles": ["principal-architect"] },
  "design-pushback":       { "authorizedRoles": ["principal-architect"] },
  "architecture-approval": { "authorizedRoles": ["principal-architect"] },
  "review-approval":       { "authorizedRoles": ["reviewer", "qa"] },
  "review-findings":       { "authorizedRoles": ["reviewer", "qa", "principal-architect"] },
  "product-approval":      { "authorizedRoles": ["team-lead", "product"] },
  "product-pushback":      { "authorizedRoles": ["team-lead", "product"] }
}
```

- **Independent-verifier substitution (I5):** if a [task]'s implementer holds
  an authorized role for a marker, that role is ineligible for that [task];
  the next authorized role signs. None available → `[andon]`.
- **Integrator step 1.5:** extract the `— <role>` signer from each approval;
  signer not in `authorizedRoles` → `[andon]`, no override path. This check is
  deliberately LLM-side (free-form comment parsing is too high-stakes for a
  bash regex); the table rides in the integrator's prompt.
- `validate-board` rejects unknown or empty `authorizedRoles`.
- Every role brief lists its allowed markers in one line.
- Compat: no `"markers"` key → check skipped; `MARKERS_ENFORCED=true` in
  `team.config.md` turns it on strictly.

### F. Comment protocol v2 — signal in the tracker, logs in artifacts

| Type | Mechanism | Trigger | Budget |
|---|---|---|---|
| gate-marker | append | state transition only | 30 lines |
| `[progress]` (one per task) | **edit in place** | stage boundaries, ≥10 min apart | 20 lines |
| `[digest]` (one per feature) | **edit in place** | milestones only: task terminal, gate rejected, andon, feature done | 15 lines |
| `[escalation]` | append | human decision required | 25 lines |

- Gate-marker fixed shape: marker, `round: N`, `supersedes: <comment-id>`
  (round ≥ 2), verdict, delta since last round, file list, evidence path,
  signer. Full checklists/logs → `.teamwork/<team>/artifacts/<taskId>/`,
  cited by path; integrator verifies cited paths exist.
- State reconstruction: per marker type, highest `round:` not referenced by a
  later `supersedes:` is current; everything else is history. Pre-v2 comments
  = round 0.
- `[escalation]` contract: question (one sentence), context, options with
  one-line consequences, `default-if-silent: <option> after <N h>`. Missing
  options/default = protocol error (andon). ESCALATIONS.md stays as file mirror.
- New `tracker-ops.sh update-comment <taskId> <commentId> [bodyfile]`:
  Linear `commentUpdate` / Jira `PUT /comment/<id>` / GitHub
  `gh issue comment edit`. **Markdown degrades to append-only** (no stable
  comment IDs; budgets still apply). Comment IDs persisted in
  `.teamwork/<team>/progress-ids/<taskId>`; a relaunched lead re-scans the
  trail as fallback.
- `tracker-ops.sh comment` warns (not fails) on bodies > 50 lines.
- Removed from tracker entirely: WIP narration, environment/setup chatter,
  full command logs, verbatim checklist repetition, restated task descriptions
  (design-notes are delta-only), heartbeats, mailbox traffic.

### G. Integrator v2 — match CI, drain the queue, clean up

- New key `VALIDATE_FORMAT=null` (e.g. `pnpm format:check`), run after lint;
  null → skip recorded in the integration comment.
- **Stale-base rule codified:** if the feature branch moved since the approval
  diff → merge feature→task branch, re-run all validations, then merge back.
  Detection is scriptable; the procedure is integrator judgment (LLM-side).
- **Queue consumer:** one boot drains all dual-approved [tasks] in dependency
  order — per-task atomic commit + status move + authorization check (E) +
  file-list==diff (I4).
- Mandatory `worktree-remove` (C) on each completed [task].

### H. Human interface

The human reads exactly one `[digest]` comment to know feature state, gets
`[escalation]` comments for genuine decisions, and receives the final MR link.
Everything else is agent-internal. (GitHub Milestones can't hold comments —
the digest lives in the milestone description via `gh api PATCH`; documented
in the adapter.)

---

## What gets deleted (ceremony ↓, not just features ↑)

1. All agent self-scheduling language, every role brief (highest-leverage single change).
2. Per-agent adapter initialization + "tracker unreachable? try…" fallbacks (preflight owns this).
3. "Worktrees are required per role" prose → "your startup prompt names your workspace."
4. Heartbeat timezone prose → preflight-injected `date -u` command, exactly.
5. Manual `Blocked → Active` coordination for dependency blocks (dispatcher owns it; the lead keeps only non-dependency blocks).

## Implementation phasing

| Phase | Contents | Effort |
|---|---|---|
| **A — stalls & dead launches** | `reference/dispatch.md` + role-brief purge; `bin/dispatch.sh --once/--watch`; `preflight` (bash checks S, MCP probe M); export gains `blockedBy` (Linear/Jira M) | ~1 wk |
| **B — claims & authorization** | `WORKTREE_SETUP` + `worktree-remove` (S); evidence ledger + policy matrix (docs); `markers` table + integrator step 1.5 + `validate-board` checks (S) | ~3 d |
| **C — batching & integrator v2** | Queue-consumer briefs (reviewer/PA/QA/integrator); `VALIDATE_FORMAT`; stale-base rule; merge queue | ~2 d |
| **D — comment protocol & digest** | `update-comment` op (S for Linear/Jira/GitHub, Markdown degrades); budgets + supersession + `[progress]`/`[digest]`/`[escalation]` contracts | ~3 d |

No L-sized items; everything builds on existing patterns (`tracker-ops.sh`
inline-Python, `launch-team.sh` subcommand structure).

## Success metrics

| Metric | Baseline (coachbot slow phase) | Target |
|---|---|---|
| Boots per [task] | ~10 | ≤ 3 on multi-task features |
| Dead launches | 1/session (40 min) | 0 — preflight aborts first |
| Idle gap at an open gate | ≥4 × 5–20 min | ≤ 1 dispatch interval |
| False-green claims | 2/feature | 0 |
| Review rounds per [task] | 4 | ≤ 2 (1 with valid evidence at HEAD) |
| Unauthorized approvals reaching integration | 1 (near-merge) | 0 — integrator refuses |
| Post-integration CI failures | 1 (prettier) | 0 — `VALIDATE_FORMAT` |
| Human board readability | trail-reading required | one `[digest]` comment |

## Testing

- `tests/launcher-test.sh`: preflight abort on broken config (zero agents
  launched); `WORKTREE_SETUP` failure is fail-loud; `markers` validation
  (unknown role, empty list); composed integrator prompt contains the markers
  table; `--skip-preflight` bypass.
- `tests/tracker-ops-test.sh`: `update-comment` (Markdown documents the
  append-only degradation); export includes `blockedBy`; >50-line comment
  warning; signer-line extraction incl. scribe variant.
- New `tests/dispatch-test.sh`: `--once` action plan from a fixture export
  (implementer launch, review-queue batch, auto-unblock, no-op exit); dedup
  against a live pid; auto-unblock suppressed on Markdown adapter.
- New `tests/marker-auth-test.sh`: unauthorized signer → andon text;
  substitution triggers when implementer == sole authorized role;
  trust-breach emitted on evidence/re-run mismatch.
- Doc consistency review pass over all changed docs (repo's established
  practice), both existing suites stay green.

## Out of scope / YAGNI

- `MAX_ACTIVE_IMPLEMENTERS ≥ 2` behavior changes; stacked task branches.
- Async/write-behind tracker layer.
- Heartbeat pid/instance tracking beyond what dispatch dedup needs.
- Automatic dependency-order computation in the integrator (mailbox instruction suffices).
- Bash-side marker-authorship or stale-base *decision* logic (detection yes, judgment no).

## Risks

- `--watch` process ownership is the human's (tmux/nohup) — documented, not hidden; hiding it caused the 3-hour incident.
- Overlapping `--once` invocations can double-launch: pid check + dispatch interval > worst-case boot time; harness mode is immune (orchestrator awaits).
- Cold `WORKTREE_SETUP` on large monorepos is slow once per machine; documented.
- `MARKERS_ENFORCED` will surface substitution edge cases — enable per-preset after the substitute is configured.
- Orchestrator context growth on >~20-task features in harness mode — mitigation (state compression between turns) deferred with a note in `dispatch.md`.
