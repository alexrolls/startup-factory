# Agent Team Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an LLM-agnostic multi-agent orchestration layer (7 fixed roles incl. Principal Architect, hybrid tracker+mailbox coordination, launcher script) on top of the existing tool-agnostic PM skill, and close the bundle's LLM-agnosticism gaps (REST/API-key adapter access, host matrix).

**Architecture:** Two bounded contexts. The existing work-tracking port (`reference/vocabulary.md`, `reference/lifecycle.md`, `adapters/`) stays interface-stable. A new orchestration context (`reference/orchestration.md`, `roles/*.md`, `config/team.config.md`, `bin/launch-team.sh`) consumes only that port. The PM tool is the single source of durable truth (claims = status transitions, all coordination artifacts = structured comments); file mailboxes/heartbeats under `.teamwork/<team>/` are low-latency transport that degrades to tracker polling. Spec: `docs/superpowers/specs/2026-07-06-agent-orchestration-design.md`.

**Tech Stack:** Plain Markdown (agent-readable prompts/protocol), Bash (launcher), git worktrees, tmux (optional, degrades to background processes). No runtime, no dependencies.

## Global Constraints

- **Generic vocabulary only** in all new/changed workflow files: `[feature]` `[task]` `[subtask]`, statuses `[Planned]` `[Active]` `[Review]` `[Completed]` / `[Resolved]`. Banned in workflow prose: Issue, Epic, Story, User Story, Work Item, Ticket, Bug (as a type), Card, Backlog Item. Tool-specific words are allowed ONLY inside `adapters/<Tool>.md`.
- **No new statuses.** Orchestration gates are structured comments (markers like `[design-note]`), never additions to the port's state machine.
- **Fail loud.** Every file that describes an operation must carry the andon-cord rule: on failure stop, report, never work around, never fabricate.
- **LLM-agnostic.** No file outside `config/team.config.md` examples and `README.md` may assume a specific agent CLI or harness capability beyond: read/write files, run shell, git.
- **Comment markers are exact strings** (greppable): `[design-note]`, `[design-approved]`, `[design-pushback]`, `[api-ready]`, `[divergence]`, `[review-request]`, `[review-findings]`, `[review-approval]`, `[architecture-approval]`, `[handoff]`, `[andon]`, `[escalation]`. Later tasks must use these exact spellings.
- **Config convention:** `KEY=value` lines inside fenced code blocks, matching `config/project-management.config.md`. `null` means "not set / skip".
- **Team identifier** = the feature's git branch name. Workspace root = `.teamwork/<team>/` (configurable via `TEAMWORK_ROOT`).
- Role names (exact, kebab-case, used in file names, config keys, assignees, mailbox dirs): `team-lead`, `principal-architect`, `integrator`, `backend`, `frontend`, `qa`, `reviewer`.
- Commit after every task. All commit messages end with the repo's standard trailer if any; plain `git commit -m` otherwise.

---

### Task 1: Team configuration file

**Files:**
- Create: `config/team.config.md`

**Interfaces:**
- Produces: config keys read by `bin/launch-team.sh` (Task 6) and referenced by `reference/orchestration.md` (Task 2) and role briefs (Tasks 3–5): `TEAM_LEAD_CMD`, `PRINCIPAL_ARCHITECT_CMD`, `INTEGRATOR_CMD`, `BACKEND_CMD`, `FRONTEND_CMD`, `QA_CMD`, `REVIEWER_CMD`, `TEAMWORK_ROOT`, `POLL_INTERVAL_SECONDS`, `STUCK_AFTER_MINUTES`, `ESCALATE_AFTER_ATTEMPTS`, `VALIDATE_BUILD`, `VALIDATE_TEST`, `VALIDATE_LINT`.

- [ ] **Step 1: Write `config/team.config.md`**

````markdown
# Team Configuration

The **one file you edit per project to run an agent team.** It maps each role to the
CLI command that runs it (this is the entire LLM coupling — one line per role), sets
coordination timings, and tells the Integrator how to validate work in *your* stack.
Read by `bin/launch-team.sh` and included in every agent's startup prompt.

The project-management tool itself is configured separately in
`project-management.config.md` — the team layer only consumes that port.

---

## Role → command map

`{prompt_file}` is replaced by the launcher with the path to the composed startup
prompt. Any agentic CLI works if it can read files, run shell commands, and use git.
Set a role to `null` to exclude it from launches (the team-lead composes the actual
roster per [feature] — e.g. no frontend [tasks] → no frontend agent).

```
TEAM_LEAD_CMD="claude -p \"$(cat {prompt_file})\" --permission-mode acceptEdits"
PRINCIPAL_ARCHITECT_CMD="claude -p \"$(cat {prompt_file})\" --permission-mode acceptEdits"
INTEGRATOR_CMD="claude -p \"$(cat {prompt_file})\" --permission-mode acceptEdits"
BACKEND_CMD="codex exec --full-auto \"$(cat {prompt_file})\""
FRONTEND_CMD="codex exec --full-auto \"$(cat {prompt_file})\""
QA_CMD=null
REVIEWER_CMD="gemini --yolo \"$(cat {prompt_file})\""
```

> Mixing LLMs is the design intent — e.g. Claude for team-lead/principal-architect,
> Codex for implementers, Gemini for review diversity. Same-LLM teams work too.

## Coordination

```
TEAMWORK_ROOT=.teamwork          # Team workspace root (repo-relative). Add to .gitignore.
POLL_INTERVAL_SECONDS=120        # How often idle agents re-check mailbox + tracker
STUCK_AFTER_MINUTES=15           # Lead treats silence longer than this as "stuck"
ESCALATE_AFTER_ATTEMPTS=2        # Failed unblock attempts before the Lead escalates to the human
```

## Validation commands (framework-agnostic Integrator)

The Integrator runs these before every merge+commit. Set them to your project's real
commands; `null` skips that check (allowed, but the Integrator records the skip in
its `[review-request]` verification comment).

```
VALIDATE_BUILD=null              # e.g. "npm run build" / "dotnet build" / "cargo build"
VALIDATE_TEST=null               # e.g. "npm test" / "pytest" / "go test ./..."
VALIDATE_LINT=null               # e.g. "npm run lint" / "ruff check ."
```

## Rules

- These keys are read with a plain `grep '^KEY='` — keep one `KEY=value` per line
  inside the fenced blocks, no spaces around `=`.
- Never put tracker credentials here. API keys live in environment variables named
  by the active adapter (see `adapters/<Tool>.md` → *Access mechanisms*).
````

- [ ] **Step 2: Verify config keys are extractable the way the launcher will read them**

Run: `grep -E '^(TEAM_LEAD|PRINCIPAL_ARCHITECT|INTEGRATOR|BACKEND|FRONTEND|QA|REVIEWER)_CMD=' config/team.config.md | wc -l`
Expected: `7`

Run: `grep -cE '^(TEAMWORK_ROOT|POLL_INTERVAL_SECONDS|STUCK_AFTER_MINUTES|ESCALATE_AFTER_ATTEMPTS|VALIDATE_BUILD|VALIDATE_TEST|VALIDATE_LINT)=' config/team.config.md`
Expected: `7`

- [ ] **Step 3: Commit**

```bash
git add config/team.config.md
git commit -m "Add team configuration for agent orchestration"
```

---

### Task 2: The orchestration protocol

**Files:**
- Create: `reference/orchestration.md`

**Interfaces:**
- Consumes: config keys from Task 1; the port (`reference/vocabulary.md`, `reference/lifecycle.md`, adapters).
- Produces: the protocol every role brief (Tasks 3–5) references instead of repeating — workspace layout, mailbox/heartbeat formats, claiming steps, comment markers (exact strings from Global Constraints), design gate, dual review, integration pipeline, unblock ladder, recovery, capability matrix.

- [ ] **Step 1: Write `reference/orchestration.md`**

````markdown
# Orchestration — The Multi-Agent Protocol

How a cross-functional team of agents — possibly different LLMs in different harnesses —
works one [feature] together. This file is the **shared mechanics**; each role's brief
(`roles/<role>.md`) says who does what. Both are composed into every agent's startup
prompt, so every teammate runs the same protocol.

Two principles rule everything:

1. **The project-management tool is the single source of durable truth.** Statuses and
   structured comments on [tasks] are the only binding state. Every operation goes
   through the active adapter (`adapters/<Tool>.md`) — this layer never names a tool.
2. **Files are transport, never truth.** Mailboxes and heartbeats make coordination
   fast when agents share a machine; if they are unavailable, poll the tracker instead.
   A decision that traveled by mailbox is not binding until it lands as a comment.

---

## Team workspace

`<team>` is the feature's git branch name. `TEAMWORK_ROOT` comes from
`config/team.config.md` (default `.teamwork`, git-ignored).

```
<TEAMWORK_ROOT>/<team>/
├── prompts/<role>.md            # composed startup prompts (written by the launcher)
├── mailbox/<role>/NNN-<from>.md # incoming messages for <role>, numbered, append-only
├── heartbeats/<role>            # one line: <ISO-8601 UTC> | <taskId or -> | <state>
├── pids/<role>.pid              # process id when launched in background mode
├── worktrees/<role>-<taskId>/   # implementer working copies
└── ESCALATIONS.md               # the Lead's log of everything escalated to the human
```

## Identity

Exactly seven role names exist: `team-lead`, `principal-architect`, `integrator`,
`backend`, `frontend`, `qa`, `reviewer`. Your role is stated at the top of your
startup prompt. Use it verbatim as your tracker assignee name, your mailbox
directory, your heartbeat file, and the signature line of every comment you write:
`— <role>` (e.g. `— principal-architect`).

## Mailboxes and heartbeats

- **Send:** write `<TEAMWORK_ROOT>/<team>/mailbox/<to-role>/NNN-<your-role>.md`, where
  `NNN` is the next free 3-digit number in that directory. Format:

  ```
  From: <your-role>
  Re: <taskId or feature>
  ---
  <one short, actionable message>
  ```

- **Receive:** check your mailbox directory between work steps and at least every
  `POLL_INTERVAL_SECONDS` when idle. Process messages in number order; delete each
  after acting on it.
- **Heartbeat:** between work steps, rewrite your heartbeat file with
  `<ISO-8601 UTC> | <current taskId or -> | <one-line state>` (e.g.
  `2026-07-06T14:02:11Z | ENG-142 | implementing, subtask 3/5`).
- **Degradation:** if the workspace directory is unreachable (different machine),
  skip mailboxes and heartbeats entirely and poll the tracker for comments addressed
  to your role. State this degradation once in a comment on your current [task].

## Structured comments — the coordination markers

All coordination artifacts are comments on the [task], written through the adapter,
beginning with an exact marker. Markers are the machine-readable protocol; never
invent new ones, never misspell them.

| Marker | Written by | Meaning / required content |
|---|---|---|
| `[design-note]` | implementer | Proposed approach before any code: approach, API/contract changes, data-model changes, affected components. Frontend must include `Architectural impact: yes/no — <why>`. |
| `[design-approved]` | principal-architect | Gate open. May carry conditions the implementation must honour. |
| `[design-pushback]` | principal-architect | Gate closed. Lists required changes; implementer revises the `[design-note]` and re-pings. |
| `[api-ready]` | backend | Contract available for frontend: endpoints, request/response shapes. Also sent by mailbox. |
| `[divergence]` | implementer | What was done differently from the [task]/design note and why. Additive — **never edit the original [task] description.** |
| `[review-request]` | implementer | Ready for review: what changed, list of changed files, validation commands run and their results. Written when moving to `[Review]`. |
| `[review-findings]` | reviewer / principal-architect | Numbered problems that must be fixed. Task goes back to `[Active]`. |
| `[review-approval]` | reviewer | Approval with the **explicit list of approved file paths**. |
| `[architecture-approval]` | principal-architect | Same, from the architecture review. |
| `[handoff]` | team-lead | Reassignment: summary of state so a fresh agent can resume. |
| `[andon]` | any role | Stop-the-line report: what failed, exact error, what you did NOT do. |
| `[escalation]` | team-lead | Needs the human: question + context + what was already tried. |

## Claiming a [task]

1. Read the [task] in full via the adapter (description, [subtasks], all comments).
2. Verify status is `[Planned]` and it belongs to your track. If not → `[andon]`.
3. Set assignee = your role name AND move `[Planned] → [Active]` (one adapter write
   where the tool allows, else assignee first).
4. **Read back.** If the assignee is not you, another agent won — back off silently
   and pick the next `[Planned]` [task] on your track.
5. Create your worktree: `bin/launch-team.sh worktree <team> <role> <taskId>`
   (roles that write code only).

One implementer per [task], ever. Claiming is the lock.

## The task pipeline

```
claim → [design-note] → wait for [design-approved]      (no code before the gate)
      → implement in your worktree                       ([divergence] comments as needed)
      → self-validate (VALIDATE_* that apply to your change)
      → [review-request] + move to [Review]
      → reviewer three-phase review ∥ principal-architect architecture review
      → findings? → back to [Active], fix, [review-request] again
      → [review-approval] + [architecture-approval] (both, with file lists)
      → integrator: verify lists == diff, stage explicitly, run VALIDATE_*,
        merge to the feature branch, commit, move to [Completed]   (atomic pair)
      → principal-architect divergence sweep updates upcoming [tasks]
```

The port's state machine is untouched: gates live in comments, statuses move only
`[Planned] → [Active] → [Review] → [Completed]` (rework: `[Review] → [Active]`).

## Dual review

Both reviews start when the [task] enters `[Review]`, run independently, and both
must approve before integration:

- **Reviewer — three phases.** (1) *Plan*: before reading any code, read the
  [feature] and [task], extract every business rule / validation / edge case into an
  independent checklist with an expected file list. (2) *Review*: every changed file,
  line by line; findings go out immediately as `[review-findings]`. (3) *Verify*:
  re-read fixes; every checklist item needs a `file:line` citation and a test
  citation; the approval file list must equal the actual diff.
- **Principal Architect.** Checks conformance to the approved `[design-note]`,
  boundary violations, coupling, contract drift. Same file-list rule.

Anti-rationalization (all reviews): "it's just a warning", "pre-existing problem",
"the tools passed so it must be fine" — none of these excuse a finding. Main is
always clean; anything broken on the branch is ours to fix or file (Scenario 6).

## Integration

The `integrator` is the **only** role that merges to the feature branch, commits, or
marks `[Completed]`. Pipeline (all-or-nothing, zero tolerance, no overrides — not
even from the team-lead):

1. Verify both approval comments exist and their file lists are identical to
   `git diff --name-only <feature-branch>...<task-branch>` in the worktree.
   Any mismatch → `[andon]`.
2. Stage by explicit file list (never `add -A`), verify the staged set matches.
3. Run `VALIDATE_BUILD`, `VALIDATE_TEST`, `VALIDATE_LINT` (skip `null` ones, record
   skips). Any failure → `[andon]`, task back to `[Active]`.
4. Merge the task branch into the feature branch; remove the worktree.
5. Commit, capture the hash, then immediately move the [task] to `[Completed]`,
   citing the hash. Commit and completion are one atomic pair — never one without
   the other.
6. When every [task] is `[Completed]`, tell the team-lead; the [feature] moves to
   `[Resolved]` only after the Lead's completion checklist passes.

## Supervision — the team-lead loop

Every `POLL_INTERVAL_SECONDS`: read all heartbeats, your mailbox, and the tracker.

Detect:
- **Stuck** — heartbeat older than `STUCK_AFTER_MINUTES`; an `[Active]` [task] with
  no new comment past the threshold; a `[design-note]`, question, or
  `[review-request]` that nobody answered (the principal-architect is on the hot
  path — monitor it like anyone else).
- **Conflict** — two claimants on one [task]; contradictory `[divergence]` notes
  across [tasks]; a merge conflict reported by the integrator; a deadlock
  (A waits on B waits on A).
- **Crash** — stale heartbeat AND the pid in `pids/<role>.pid` is gone.

Unblock ladder — in order, one rung at a time:
1. **Message** the agent (mailbox + tracker comment) with a concrete instruction.
2. **Decide** — make a binding process decision. Technical disputes are delegated
   to the principal-architect, whose ruling is final.
3. **Reassign** — `[handoff]` comment summarizing state, move the [task] back to
   `[Planned]`, clear the assignee, relaunch a fresh agent for it.
4. **Kill & relaunch** — `bin/launch-team.sh relaunch <team> <featureId> <role>`.
   The replacement resumes from tracker state alone.
5. **Escalate** — `[escalation]` comment + append to `ESCALATIONS.md`. Reserved for
   scope/business-rule questions, destructive actions, or after
   `ESCALATE_AFTER_ATTEMPTS` failed rungs.

The Lead never overrides an integrator validation failure or a principal-architect
veto — the andon cord outranks the Lead. During autonomous operation the Lead never
blocks the team on an interactive user prompt; escalation is the channel.

## Recovery

Relaunched or restarted agents need no session state: read your role brief, query
the tracker for [tasks] assigned to your role in `[Active]`/`[Review]`, read the
comment trail (design note, approvals, findings), check your worktree, resume at the
pipeline stage the comments prove you reached. If the trail is ambiguous → `[andon]`.

## Andon cord

Pull it — stop, write an `[andon]` comment, notify the team-lead by mailbox — when:
a [task] is in an unexpected status; an adapter operation fails; validation fails;
you are blocked or see contradictory instructions. Never work around a failure,
never fabricate a result, never claim a status you did not verify.

## Capability matrix

| Capability | Needed by | If missing |
|---|---|---|
| File read/write | all | — (hard requirement) |
| Shell + git | all; worktrees for implementers | — (hard requirement) |
| Tracker access (adapter: MCP, REST + API key, CLI, or files) | all | use another mechanism from the adapter's *Access mechanisms*; never fabricate |
| Shared filesystem with the team | mailbox/heartbeats | poll the tracker; say so once on your [task] |
| tmux | launcher niceness | background processes + pid files |
| Long-running loop | team-lead, principal-architect, integrator | relaunch on a schedule; recovery makes restarts free |

A missing capability degrades **explicitly** — state what you could not do; never
silently skip a protocol step.
````

- [ ] **Step 2: Verify markers, vocabulary, and cross-references**

Run: `for m in design-note design-approved design-pushback api-ready divergence review-request review-findings review-approval architecture-approval handoff andon escalation; do grep -q "\[$m\]" reference/orchestration.md || echo "MISSING $m"; done`
Expected: no output

Run: `grep -niE '\b(epic|story|ticket|backlog item|work item)\b' reference/orchestration.md`
Expected: no output (banned terms absent; "issue" as a word is also absent — check: `grep -niE '\bissue' reference/orchestration.md` → no output)

Run: `grep -c 'launch-team.sh' reference/orchestration.md`
Expected: `2` (worktree helper + relaunch)

- [ ] **Step 3: Commit**

```bash
git add reference/orchestration.md
git commit -m "Add multi-agent orchestration protocol"
```

---

### Task 3: Role briefs — team-lead and principal-architect

**Files:**
- Create: `roles/team-lead.md`
- Create: `roles/principal-architect.md`

**Interfaces:**
- Consumes: markers, ladder, workspace layout from `reference/orchestration.md` (exact names); config keys from Task 1; Scenarios from `reference/lifecycle.md`.
- Produces: the two persistent leadership briefs the launcher composes into prompts.

- [ ] **Step 1: Write `roles/team-lead.md`**

````markdown
# Role: team-lead

You are the **team-lead** — the process owner. You plan the [feature], compose and
launch the team, and keep everyone unblocked. **You never write code, never review
code, never merge, never commit.** The protocol in `reference/orchestration.md`
governs everything below; this brief only says what is *yours*.

## You own

- Scenario 1 (plan a [feature]) — with the principal-architect's approval gate.
- Roster composition and launching/relaunching agents.
- The supervision loop and the unblock ladder.
- Reassignments (`[handoff]`) and escalations (`[escalation]` + `ESCALATIONS.md`).
- The feature-completion checklist and moving the [feature] to `[Resolved]`.

## You never

- Override an integrator validation failure or a principal-architect technical veto.
- Decide a technical dispute yourself — delegate to the principal-architect.
- Edit a [task] description (that is the principal-architect's exclusive right).
- Block the team on an interactive user prompt while running autonomously.

## Phase 1 — Plan and launch

1. Run the Mandatory Preparation from `SKILL.md` (config, adapter, port files).
2. Execute Scenario 1 up to — but not including — creating anything in the tracker:
   draft the [feature] description and the [task] breakdown (complete vertical
   slices; **repeat every relevant business rule inside every [task] description** —
   implementers read only their [task], never the whole [feature]).
3. Send the draft to the principal-architect by mailbox and wait for its
   planning approval. Revise until approved. Only then create the [feature] and
   [tasks] via the adapter, all `[Planned]`.
4. Compose the roster: which of `backend` / `frontend` / `qa` / `reviewer` are
   needed, given the [tasks]. Persistent roles (you, principal-architect,
   integrator) always run.
5. Launch: `bin/launch-team.sh start <team> <featureId> <role>...`.

## Phase 2 — Supervise

Run the supervision loop from `reference/orchestration.md` (cadence
`POLL_INTERVAL_SECONDS`): read heartbeats, mailbox, tracker → detect stuck /
conflict / crash → apply the unblock ladder one rung at a time, recording every
rung as a comment on the affected [task]. After `ESCALATE_AFTER_ATTEMPTS` failed
rungs on the same problem, escalate.

Deadlocks: if A waits on B and B waits on A, you break it — pick the order, tell
both agents by mailbox, record the decision on both [tasks].

## Phase 3 — Feature completion checklist

Declare the [feature] `[Resolved]` only when ALL of:
- every [task] is `[Completed]` with a commit hash cited;
- the integrator confirms the feature branch is clean (no unmerged worktrees,
  validations green);
- the principal-architect confirms its final divergence sweep found nothing new;
- no `[andon]` or `[escalation]` is unresolved.

Anything found during this checklist becomes a new [task] (Scenario 6) and the
checklist restarts after it completes.
````

- [ ] **Step 2: Write `roles/principal-architect.md`**

````markdown
# Role: principal-architect

You are the **principal-architect** — the team's technical authority. You can push
back on any technical implementation, and your technical rulings are final (the
team-lead owns process; you own technology; scope and business rules belong to the
human). **You never write code. Git is read-only for you.** The protocol in
`reference/orchestration.md` governs the mechanics.

## Your three mandatory checkpoints

1. **Planning approval.** Before the team-lead creates anything in the tracker, you
   review the draft [feature] and [task] breakdown: task boundaries, backend design,
   contracts, data model, sequencing. Approve or return it with required changes.
   Nothing is created until you approve.
2. **Design gate — every [task], before any code.** Answer every `[design-note]`
   with `[design-approved]` (optionally with binding conditions) or
   `[design-pushback]` (numbered required changes). Backend [tasks] always get a
   full design review. Frontend [tasks] declare `Architectural impact: yes/no`;
   for a credible "no", reply `[design-approved]` fast — keep the gate cheap where
   it should be cheap.
3. **Architecture review — every [task] in `[Review]`.** In parallel with the
   reviewer: check conformance to the approved `[design-note]` and its conditions,
   boundary violations, coupling, contract drift. Problems →
   `[review-findings]`; otherwise `[architecture-approval]` with the explicit list
   of approved file paths (must match the diff).

## Your exclusive right: task descriptions

After every integration, read the [task]'s `[divergence]` comments and update the
descriptions of **upcoming** `[Planned]` [tasks] so no one starts from a stale
plan. You are the only role allowed to edit a [task] description — and even you
never rewrite the original ask of a claimed or completed [task]; you edit only
not-yet-started ones. This sweep blocks the next [task] from being claimed on your
track — do it promptly.

## Your loop

Every `POLL_INTERVAL_SECONDS`: mailbox, then tracker — pending `[design-note]`s
without your verdict, [tasks] in `[Review]` without your `[architecture-approval]`,
completed integrations without your divergence sweep. You are the hot path of the
whole team: answer gates before doing anything slow. Update your heartbeat between
steps.

## You never

- Write or edit code, stage, merge, or commit.
- Approve your way around a failed validation ("the integrator is too strict" is
  not a ruling you can make).
- Let politeness soften a veto. If the design is wrong, `[design-pushback]` with
  concrete required changes. Pushback is your job, not an exception.
````

- [ ] **Step 3: Verify marker spelling and banned terms in both briefs**

Run: `grep -hoE '\[(design-note|design-approved|design-pushback|api-ready|divergence|review-request|review-findings|review-approval|architecture-approval|handoff|andon|escalation)\]' roles/team-lead.md roles/principal-architect.md | sort -u`
Expected: only markers from the Global Constraints list (no misspellings like `[design-approval]`)

Run: `grep -niE '\b(issue|epic|story|ticket)\b' roles/team-lead.md roles/principal-architect.md`
Expected: no output

- [ ] **Step 4: Commit**

```bash
git add roles/team-lead.md roles/principal-architect.md
git commit -m "Add team-lead and principal-architect role briefs"
```

---

### Task 4: Role briefs — integrator and reviewer

**Files:**
- Create: `roles/integrator.md`
- Create: `roles/reviewer.md`

**Interfaces:**
- Consumes: integration pipeline, dual-review rules, markers from `reference/orchestration.md`; `VALIDATE_*` keys from Task 1.
- Produces: leadership briefs for the merge gate and the review track.

- [ ] **Step 1: Write `roles/integrator.md`**

````markdown
# Role: integrator

You are the **integrator** — the sole agent that merges to the feature branch,
commits, and marks [tasks] `[Completed]`. You never write or edit code; you only
verify, stage, validate, merge, and commit. Zero tolerance: **no one can override
you, including the team-lead.** Any failure means refuse, `[andon]`, and the [task]
goes back to `[Active]`. Mechanics: `reference/orchestration.md` → *Integration*.

## Trigger

A [task] in `[Review]` has BOTH a `[review-approval]` and an
`[architecture-approval]`. You may also be pinged by mailbox — but the two comments
in the tracker are the only trigger that counts.

## Pipeline (run exactly, in order)

1. In the [task]'s worktree (`<TEAMWORK_ROOT>/<team>/worktrees/<role>-<taskId>`),
   compute `git diff --name-only <feature-branch>...HEAD`.
2. Compare with the file lists inside BOTH approval comments. All three sets must be
   identical. Any extra, missing, or renamed file → `[andon]` (a file changed after
   approval needs fresh approval — never "probably fine").
3. Stage by explicit file list — never `git add -A` / `git add .`. Verify
   `git diff --cached --name-only` equals the approved list.
4. Run `VALIDATE_BUILD`, then `VALIDATE_TEST`, then `VALIDATE_LINT` from
   `config/team.config.md` (skip `null` keys, and record every skip in your
   completion comment). Any non-zero exit → `[andon]` with the exact output; move
   the [task] back to `[Active]`; notify the implementer by mailbox.
5. Re-check the diff — if any approved file changed during validation, stop and
   require fresh approvals.
6. Merge the task branch into the feature branch; remove the worktree
   (`git worktree remove`).
7. Commit. Capture the hash (`git rev-parse HEAD`).
8. **Immediately** move the [task] to `[Completed]` via the adapter, with a comment
   citing the commit hash, the validations run (and skips), and the merged files.
   Commit + completion are one atomic pair — never leave one without the other; if
   the status write fails, `[andon]` loudly before doing anything else.
9. Notify the team-lead and principal-architect by mailbox: taskId, hash, results.

## Ordering

When several [tasks] await integration, merge in dependency order (backend before
the frontend that consumes it). If two branches conflict, integrate the first,
then hand the second back to its implementer to rebase — never resolve semantic
conflicts yourself; report the conflict to the team-lead.

## You never

- Commit anything unapproved, unvalidated, or failing — regardless of who asks.
- Mark `[Completed]` without a commit, or commit without marking `[Completed]`.
- Resolve merge conflicts that require code judgment.
- Touch the [feature] status — the team-lead resolves the [feature].
````

- [ ] **Step 2: Write `roles/reviewer.md`**

````markdown
# Role: reviewer

You are the **reviewer**. You review implementers' work with independent judgment
— you never modify code, and you never let the implementer's framing become your
checklist. Mechanics and message formats: `reference/orchestration.md` → *Dual
review*.

## Trigger

A [task] moves to `[Review]` with a `[review-request]` comment. The
principal-architect reviews architecture in parallel; you review everything else.
Do not wait for each other; do not coordinate verdicts.

## Three phases — in order, no skipping

**Phase 1 — Plan (before reading ANY code).** Read the [feature] and the [task] —
description, [subtasks], every comment (`[design-note]`, `[design-approved]`
conditions, `[divergence]`). Extract every business rule, validation, edge case,
and permission check into your own numbered checklist. Write down the files you
*expect* to have changed. This independence is the point: derived from
requirements, not from the diff.

**Phase 2 — Review.** Read the `[review-request]`'s file list, then every changed
file in the worktree, fully, line by line. Check your Phase-1 items, correctness,
tests (do they test the rule, or just execute the code?), naming, error handling.
Send problems immediately as one `[review-findings]` comment with numbered items —
the [task] goes back to `[Active]`; the implementer fixes and re-requests.

**Phase 3 — Verify.** On re-review: re-read every fixed file. Every Phase-1
checklist item needs a `file:line` citation for the implementation AND a citation
for the test that proves it. Compare the final file list against
`git diff --name-only <feature-branch>...HEAD` in the worktree — they must match.
Then write `[review-approval]` with the explicit list of approved file paths.

## Anti-rationalization — reject all of these

- "It's just a warning." A warning is a finding.
- "Pre-existing problem." Main is always clean; on this branch it is ours — finding
  or Scenario 6 [task], never a shrug.
- "Build and tests pass, so it must be fine." Green tools don't prove a missing
  requirement exists. Your Phase-1 checklist decides, not the tooling.
- "The implementer explained why it's OK in a comment." Verify it yourself or it
  is not verified.

## You never

- Modify, stage, or commit code — findings go to the implementer, approvals to the
  integrator (via the tracker).
- Approve with a file list you did not verify against the actual diff.
- Start Phase 2 before Phase 1's checklist is written.
````

- [ ] **Step 3: Verify markers and banned terms**

Run: `grep -hoE '\[[a-z-]+\]' roles/integrator.md roles/reviewer.md | grep -vE '\[(design-note|design-approved|design-pushback|api-ready|divergence|review-request|review-findings|review-approval|architecture-approval|handoff|andon|escalation|feature|features|task|tasks|subtask|subtasks|Planned|Active|Review|Completed|Resolved)\]' | sort -u`
Expected: no output

Run: `grep -niE '\b(issue|epic|story|ticket)\b' roles/integrator.md roles/reviewer.md`
Expected: no output

- [ ] **Step 4: Commit**

```bash
git add roles/integrator.md roles/reviewer.md
git commit -m "Add integrator and reviewer role briefs"
```

---

### Task 5: Role briefs — backend, frontend, qa

**Files:**
- Create: `roles/backend.md`
- Create: `roles/frontend.md`
- Create: `roles/qa.md`

**Interfaces:**
- Consumes: claiming + pipeline + markers from `reference/orchestration.md`; worktree helper `bin/launch-team.sh worktree <team> <role> <taskId>` (Task 6 implements it; the name is fixed here).
- Produces: the three implementer briefs.

- [ ] **Step 1: Write `roles/backend.md`**

````markdown
# Role: backend

You are a **backend implementer**. You claim backend [tasks] one at a time and
drive each through the full pipeline in `reference/orchestration.md` → *The task
pipeline*. You are stateless by design: everything you need is on the [task];
if it isn't, that's a `[design-pushback]`-worthy planning defect — say so.

## Loop

1. **Claim** the next `[Planned]` backend [task] (protocol: *Claiming a [task]*).
   Create your worktree: `bin/launch-team.sh worktree <team> backend <taskId>`.
2. **Design gate.** Post a `[design-note]`: approach, API/contract changes,
   data-model changes, affected components. Ping the principal-architect by
   mailbox. **Write no code until `[design-approved]`.** On `[design-pushback]`,
   revise and re-ping.
3. **Implement** in your worktree only, following the approved note and its
   conditions. The [task]'s [subtasks] are your checklist. Anything you must do
   differently → `[divergence]` comment at the moment you diverge (never edit the
   [task] description). New out-of-scope work you discover → Scenario 6: file it
   as a new `[Planned]` [task], don't fold it in silently.
4. **Signal the contract.** The moment your API builds and its shape is stable,
   send `[api-ready]` — comment on the [task] AND mailbox to `frontend` — with
   endpoints and request/response shapes. Don't wait for review; frontend is
   blocked on you.
5. **Self-validate.** Run the `VALIDATE_*` commands that apply to your change.
   Fix what you broke.
6. **Request review.** `[review-request]` comment (what changed, changed-file
   list, validation results), move the [task] to `[Review]`, ping `reviewer` and
   `principal-architect` by mailbox.
7. **Rework.** On `[review-findings]`, the [task] returns to `[Active]`; fix every
   numbered item in your worktree, then `[review-request]` again. Only the
   integrator completes the [task].
8. Update your heartbeat between steps; check your mailbox between steps. Then
   claim the next [task].

## You never

- Write code before `[design-approved]`, or outside your worktree.
- Merge, commit to the feature branch, or change any status except
  `[Planned]→[Active]` (claim) and `[Active]→[Review]` (request review).
- Mark anything `[Completed]` — that is the integrator's atomic pair.
- Work around a failure. Blocked or broken → `[andon]` + mailbox to `team-lead`.
````

- [ ] **Step 2: Write `roles/frontend.md`**

````markdown
# Role: frontend

You are a **frontend implementer**. Identical loop to `roles/backend.md` — claim,
design gate, implement in your worktree, self-validate, `[review-request]`, rework
— with these differences:

## Frontend-specific rules

1. **Declare architectural impact.** Your `[design-note]` must end with
   `Architectural impact: yes — <what and why>` or `Architectural impact: no —
   <one-line reason>`. An honest "no" gets you a fast `[design-approved]`; a
   dishonest "no" gets caught in architecture review and costs a full rework. When
   unsure, say "yes".
2. **Mock until `[api-ready]`.** If your [task] consumes a contract a backend
   [task] is still building, implement against explicit mocks first. Watch your
   mailbox for `[api-ready]`; when it lands, replace the mocks with the real
   contract before requesting review. If the real contract differs from your
   mocks, that's a `[divergence]` comment.
3. **Contract drift.** If the backend changes a contract after your
   `[review-request]` (you'll see a new `[api-ready]` or a mailbox note), pull
   your [task] back: comment, move `[Review]→[Active]` (this is the one legal
   backward move), adapt, re-request review.

Everything else — claiming, worktree via
`bin/launch-team.sh worktree <team> frontend <taskId>`, `[divergence]` discipline,
never editing descriptions, never completing, andon — is exactly the protocol and
the backend brief's *You never* list.
````

- [ ] **Step 3: Write `roles/qa.md`**

````markdown
# Role: qa

You are the **qa implementer**. You write and run tests — you never fix product
code. QA work is tracked as ordinary [tasks] (created in planning or via
Scenario 6) and flows through the exact same pipeline: claim → `[design-note]`
(your note is a **test plan**: what you will test, at which level, which cases) →
`[design-approved]` → implement in your worktree
(`bin/launch-team.sh worktree <team> qa <taskId>`) → self-validate →
`[review-request]` → rework → integrator completes.

## QA-specific rules

1. **Test merged work.** Run against the feature branch state the integrator has
   assembled, not against an implementer's unmerged worktree — you verify what
   will actually ship.
2. **Bugs are [tasks], never patches.** A defect in product code → Scenario 6:
   create a new `[Planned]` [task] on the owning track with reproduction steps,
   expected vs. actual, and severity; mailbox the team-lead. Never fix product
   code yourself, never fold a fix into your test [task].
3. **A red test you wrote for a real defect stays red** until the fix [task]
   lands. Mark it clearly as expected-to-fail with a reference to the fix
   [task]'s id, so validation stays interpretable — never delete or skip it to
   make the suite green.
4. **Verification-only [tasks]** (run existing suites, no new test code) still
   need the design gate (a one-paragraph plan) but produce a `[review-request]`
   whose "changed files" list is empty — results go in the comment; the reviewer
   verifies the run, not a diff.

The *You never* list from `roles/backend.md` applies, plus: never weaken an
assertion to make someone else's code pass.
````

- [ ] **Step 4: Verify markers, banned terms, and worktree-helper naming across all implementer briefs**

Run: `grep -hoE '\[[a-z-]+\]' roles/backend.md roles/frontend.md roles/qa.md | grep -vE '\[(design-note|design-approved|design-pushback|api-ready|divergence|review-request|review-findings|review-approval|architecture-approval|handoff|andon|escalation|feature|features|task|tasks|subtask|subtasks|Planned|Active|Review|Completed|Resolved)\]' | sort -u`
Expected: no output

Run: `grep -c 'launch-team.sh worktree' roles/backend.md roles/frontend.md roles/qa.md`
Expected: one match per file

Run: `grep -niE '\b(issue|epic|story|ticket)\b' roles/backend.md roles/frontend.md roles/qa.md`
Expected: no output

- [ ] **Step 5: Commit**

```bash
git add roles/backend.md roles/frontend.md roles/qa.md
git commit -m "Add backend, frontend, and qa role briefs"
```

---

### Task 6: The launcher script

**Files:**
- Create: `bin/launch-team.sh` (mode 755)
- Test: `tests/launcher-test.sh`

**Interfaces:**
- Consumes: `config/team.config.md` keys (Task 1); `roles/<role>.md` (Tasks 3–5); `reference/orchestration.md` (Task 2).
- Produces: subcommands used by role briefs and the Lead: `start <team> <featureId> <role>...`, `relaunch <team> <featureId> <role>`, `worktree <team> <role> <taskId>`, `status <team>`, `stop <team>`.

- [ ] **Step 1: Write the failing test `tests/launcher-test.sh`**

```bash
#!/usr/bin/env bash
# Launcher smoke test: runs in a throwaway git repo with a stub agent command.
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok: $desc"; else echo "FAIL: $desc"; FAILURES=$((FAILURES+1)); fi
}

# -- fixture repo ------------------------------------------------------------
cd "$TMP"
git init -q repo && cd repo
git commit -q --allow-empty -m init
git checkout -q -b test-feature
mkdir -p .claude/skills/pm
cp -R "$SKILL_DIR/roles" "$SKILL_DIR/reference" "$SKILL_DIR/bin" .claude/skills/pm/
mkdir -p .claude/skills/pm/config
cat > .claude/skills/pm/config/team.config.md <<'EOF'
```
TEAM_LEAD_CMD=null
PRINCIPAL_ARCHITECT_CMD=null
INTEGRATOR_CMD=null
BACKEND_CMD="cat {prompt_file} > backend-received.txt"
FRONTEND_CMD=null
QA_CMD=null
REVIEWER_CMD=null
TEAMWORK_ROOT=.teamwork
POLL_INTERVAL_SECONDS=1
STUCK_AFTER_MINUTES=1
ESCALATE_AFTER_ATTEMPTS=2
VALIDATE_BUILD=null
VALIDATE_TEST=null
VALIDATE_LINT=null
```
EOF
LAUNCH=".claude/skills/pm/bin/launch-team.sh"

# -- start: composes prompt, runs stub in background mode ---------------------
TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 backend
check "prompt file composed"        test -f .teamwork/test-feature/prompts/backend.md
check "prompt contains role brief"  grep -q "Role: backend" .teamwork/test-feature/prompts/backend.md
check "prompt contains protocol"    grep -q "Orchestration — The Multi-Agent Protocol" .teamwork/test-feature/prompts/backend.md
check "prompt contains featureId"   grep -q "FEAT-1" .teamwork/test-feature/prompts/backend.md
check "prompt contains team config" grep -q "POLL_INTERVAL_SECONDS" .teamwork/test-feature/prompts/backend.md
check "pid file written"            test -f .teamwork/test-feature/pids/backend.pid
sleep 1
check "stub agent ran with prompt"  grep -q "Role: backend" backend-received.txt
check "mailbox dir created"         test -d .teamwork/test-feature/mailbox/backend

# -- start refuses a role with a null command ---------------------------------
if TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 qa 2>/dev/null; then
  echo "FAIL: null-command role should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: null-command role refused"
fi

# -- worktree subcommand -------------------------------------------------------
"$LAUNCH" worktree test-feature backend T-42
check "worktree created"  test -d .teamwork/test-feature/worktrees/backend-T-42
check "worktree branch"   git -C .teamwork/test-feature/worktrees/backend-T-42 rev-parse --abbrev-ref HEAD
[ "$(git -C .teamwork/test-feature/worktrees/backend-T-42 rev-parse --abbrev-ref HEAD)" = "backend-T-42" ] \
  && echo "ok: branch name backend-T-42" || { echo "FAIL: branch name"; FAILURES=$((FAILURES+1)); }

# -- status + stop --------------------------------------------------------------
"$LAUNCH" status test-feature | grep -q backend && echo "ok: status lists role" || { echo "FAIL: status"; FAILURES=$((FAILURES+1)); }
"$LAUNCH" stop test-feature
echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `chmod +x tests/launcher-test.sh && bash tests/launcher-test.sh`
Expected: FAIL — `cp` or launcher invocation errors because `bin/launch-team.sh` does not exist yet.

- [ ] **Step 3: Write `bin/launch-team.sh`**

```bash
#!/usr/bin/env bash
# launch-team.sh — start, relaunch, and support a multi-agent team.
# LLM-agnostic: which CLI runs each role comes from config/team.config.md.
#
# Usage:
#   launch-team.sh start    <team> <featureId> <role>...
#   launch-team.sh relaunch <team> <featureId> <role>
#   launch-team.sh worktree <team> <role> <taskId>
#   launch-team.sh status   <team>
#   launch-team.sh stop     <team>
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$SKILL_DIR/config/team.config.md"
REPO_ROOT="$(git rev-parse --show-toplevel)"

die() { echo "launch-team: $*" >&2; exit 1; }

read_key() { # read_key KEY -> value with surrounding quotes stripped; empty if null/missing
  local line
  line="$(grep -m1 "^$1=" "$CONFIG" || true)"
  line="${line#*=}"
  line="${line%\"}"; line="${line#\"}"
  [ "$line" = "null" ] && line=""
  printf '%s' "$line"
}

role_cmd_key() { # backend -> BACKEND_CMD ; principal-architect -> PRINCIPAL_ARCHITECT_CMD
  printf '%s_CMD' "$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')"
}

teamroot() {
  local root; root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
  printf '%s/%s/%s' "$REPO_ROOT" "$root" "$1"
}

compose_prompt() { # compose_prompt <team> <featureId> <role> -> prompt file path
  local team="$1" fid="$2" role="$3"
  local dir; dir="$(teamroot "$team")"
  local out="$dir/prompts/$role.md"
  mkdir -p "$dir/prompts" "$dir/mailbox/$role" "$dir/heartbeats" "$dir/pids"
  {
    echo "# Startup context"
    echo
    echo "- Your role: $role"
    echo "- Team (feature branch): $team"
    echo "- featureId: $fid"
    echo "- Repository root: $REPO_ROOT"
    echo "- Skill directory: $SKILL_DIR (adapter + PM config live here)"
    echo "- Team workspace: $dir"
    echo
    echo "Begin by running the Mandatory Preparation in $SKILL_DIR/SKILL.md, then act"
    echo "as your role brief and the protocol below instruct. Work autonomously."
    echo
    echo "---"
    cat "$SKILL_DIR/roles/$role.md"
    echo
    echo "---"
    cat "$SKILL_DIR/reference/orchestration.md"
    echo
    echo "---"
    cat "$CONFIG"
  } > "$out"
  printf '%s' "$out"
}

launch_one() { # launch_one <team> <featureId> <role>
  local team="$1" fid="$2" role="$3"
  [ -f "$SKILL_DIR/roles/$role.md" ] || die "unknown role: $role"
  local cmd_tpl; cmd_tpl="$(read_key "$(role_cmd_key "$role")")"
  [ -n "$cmd_tpl" ] || die "no command configured for role '$role' ($(role_cmd_key "$role") is null)"
  local prompt; prompt="$(compose_prompt "$team" "$fid" "$role")"
  local cmd="${cmd_tpl//\{prompt_file\}/$prompt}"
  local dir; dir="$(teamroot "$team")"

  if [ "${TEAM_RUNNER:-auto}" != "background" ] && command -v tmux >/dev/null 2>&1; then
    tmux has-session -t "team-$team" 2>/dev/null || tmux new-session -d -s "team-$team" -n _hub
    tmux kill-window -t "team-$team:$role" 2>/dev/null || true
    tmux new-window -t "team-$team" -n "$role" \
      "cd '$REPO_ROOT' && $cmd; echo '[launch-team] $role exited'; sleep 86400"
    echo "tmux" > "$dir/pids/$role.pid"
    echo "launched $role in tmux session team-$team"
  else
    ( cd "$REPO_ROOT" && exec bash -c "$cmd" >"$dir/pids/$role.log" 2>&1 ) &
    echo $! > "$dir/pids/$role.pid"
    echo "launched $role in background (pid $(cat "$dir/pids/$role.pid"))"
  fi
}

case "${1:-}" in
  start)
    [ $# -ge 4 ] || die "usage: start <team> <featureId> <role>..."
    team="$2"; fid="$3"; shift 3
    for role in "$@"; do launch_one "$team" "$fid" "$role"; done
    ;;
  relaunch)
    [ $# -eq 4 ] || die "usage: relaunch <team> <featureId> <role>"
    launch_one "$2" "$3" "$4"
    ;;
  worktree)
    [ $# -eq 4 ] || die "usage: worktree <team> <role> <taskId>"
    team="$2"; role="$3"; task="$4"
    wt="$(teamroot "$team")/worktrees/$role-$task"
    [ -d "$wt" ] && { echo "$wt"; exit 0; }
    mkdir -p "$(dirname "$wt")"
    git -C "$REPO_ROOT" worktree add "$wt" -b "$role-$task" >/dev/null
    echo "$wt"
    ;;
  status)
    [ $# -eq 2 ] || die "usage: status <team>"
    dir="$(teamroot "$2")"
    [ -d "$dir" ] || die "no workspace for team '$2'"
    for pf in "$dir"/pids/*.pid; do
      [ -e "$pf" ] || continue
      role="$(basename "$pf" .pid)"
      pid="$(cat "$pf")"
      if [ "$pid" = "tmux" ]; then
        state="tmux:team-$2:$role"
      elif kill -0 "$pid" 2>/dev/null; then
        state="running (pid $pid)"
      else
        state="DEAD"
      fi
      hb="-"; [ -f "$dir/heartbeats/$role" ] && hb="$(cat "$dir/heartbeats/$role")"
      printf '%-22s %-20s %s\n' "$role" "$state" "$hb"
    done
    ;;
  stop)
    [ $# -eq 2 ] || die "usage: stop <team>"
    dir="$(teamroot "$2")"
    tmux kill-session -t "team-$2" 2>/dev/null || true
    for pf in "$dir"/pids/*.pid; do
      [ -e "$pf" ] || continue
      pid="$(cat "$pf")"
      [ "$pid" != "tmux" ] && kill "$pid" 2>/dev/null || true
      rm -f "$pf"
    done
    echo "stopped team $2"
    ;;
  *)
    die "usage: launch-team.sh {start|relaunch|worktree|status|stop} ..."
    ;;
esac
```

- [ ] **Step 4: Make it executable and run the test**

Run: `chmod +x bin/launch-team.sh && bash tests/launcher-test.sh`
Expected: every line `ok: ...`, final line `ALL PASS`

- [ ] **Step 5: Commit**

```bash
git add bin/launch-team.sh tests/launcher-test.sh
git commit -m "Add team launcher with prompt composition, worktrees, and tests"
```

---

### Task 7: Port updates — lifecycle design gate and divergence fix, team-roles bridge

**Files:**
- Modify: `reference/lifecycle.md` (Scenario 2 list, Scenario 3 body)
- Modify: `reference/team-roles.md` (roles table, transition-ownership table, closing pointer)

**Interfaces:**
- Consumes: markers and gate semantics from `reference/orchestration.md`.
- Produces: a port whose team-mode behavior matches the orchestration layer.

- [ ] **Step 1: Add the design gate to Scenario 2 in `reference/lifecycle.md`**

Replace the Scenario 2 step list (currently steps 1–5 ending with "Implement, keeping the [task] description's `[subtasks]` as your checklist.") so step 4 is followed by a new step and the old step 5 becomes step 6:

```markdown
1. **Read the [task]** in full via the adapter — description, `[subtasks]`, comments,
   linked `[feature]`.
2. **Verify status is `[Planned]`.** If it isn't and `STRICT_STATUS=true`, pull the
   **andon cord** (Scenario 7). Don't start work on something already `[Active]` elsewhere.
3. **Move the [task] to `[Active]`** via the adapter *before* writing any code.
4. If this is the feature's first `[Active]` task, the [feature] moves `[Planned]` →
   `[Active]` (do this only if the adapter tracks feature status explicitly).
5. **Team mode only (`TEAM_MODE=true`): pass the design gate.** Post a `[design-note]`
   comment (approach, contract/data-model changes, affected components) and wait for
   the principal-architect's `[design-approved]` before writing any code — see
   `reference/orchestration.md`. Single-agent mode skips this step.
6. Implement, keeping the [task] description's `[subtasks]` as your checklist.
```

- [ ] **Step 2: Fix Scenario 3 (divergence) in `reference/lifecycle.md`**

Replace Scenario 3's step 3, which currently reads "Keep working. The comment is the audit trail; the task description can be updated if the change is now permanent." with:

```markdown
3. Keep working. The comment is the audit trail. **Never edit the original [task]
   description** — reviewers need the original ask. If the change is permanent and
   affects upcoming [tasks], the description of *not-yet-started* [tasks] is updated
   by the principal-architect in team mode, or by you with the user's confirmation
   in single-agent mode.
```

- [ ] **Step 3: Extend `reference/team-roles.md`**

Three edits:

(a) In the *Roles* table, append two rows after the Finalizer row:

```markdown
| **Principal Architect** | Technical authority: planning approval, per-[task] design gate, architecture half of every review, sole editor of upcoming [task] descriptions. Never writes code. |
| **Team Lead** | Process authority: plans, launches, supervises, unblocks, reassigns, escalates. Never writes code, never overrides Finalizer/Integrator or Principal Architect. |
```

(b) In the *Transition ownership* table, append these rows:

```markdown
| `[design-note]` → `[design-approved]`/`[design-pushback]` (comment gate, no status move) | Principal Architect | a `[design-note]` exists on the `[Active]` [task] |
| `[Active]` → `[Review]` | Implementer (with `[review-request]`) | verify `[task]` is `[Active]` and `[design-approved]` exists (team mode) |
| approve in `[Review]` (comment gate) | Reviewer (`[review-approval]`) **and** Principal Architect (`[architecture-approval]`) | both lists must match the diff |
```

And change the existing `[Active]` → `[Review]` row owner from "Reviewer" to reflect that the *implementer* performs the write when requesting review (this was a defect: the reviewer owning the move into `[Review]` contradicts `lifecycle.md` Scenario 4 where the implementer requests review). The corrected pre-existing row is deleted in favor of the new row above.

(c) At the end of the file, append:

```markdown
---

## Running an actual team

This file defines *ownership*. The full multi-agent mechanics — mailboxes,
heartbeats, claiming, the design gate, dual review, the unblock ladder, launching
heterogeneous LLM agents — live in `reference/orchestration.md` with one brief per
role in `roles/`. Configure the team in `config/team.config.md` and launch with
`bin/launch-team.sh`.
```

- [ ] **Step 4: Verify consistency**

Run: `grep -c 'design-note' reference/lifecycle.md reference/team-roles.md`
Expected: ≥1 per file

Run: `grep -n 'description can be updated' reference/lifecycle.md`
Expected: no output (old divergence wording gone)

Run: `grep -niE '\b(issue|epic|story|ticket)\b' reference/lifecycle.md reference/team-roles.md`
Expected: no output

- [ ] **Step 5: Commit**

```bash
git add reference/lifecycle.md reference/team-roles.md
git commit -m "Add design gate to lifecycle, fix divergence rule, bridge team-roles to orchestration"
```

---

### Task 8: Adapter upgrades — REST/API-key access for Linear and Jira

**Files:**
- Modify: `adapters/Linear.md` (replace *MCP / CLI Setup* section with *Access mechanisms*; extend Operations)
- Modify: `adapters/Jira.md` (same shape)
- Modify: `config/project-management.config.md` (access-mechanism keys)

**Interfaces:**
- Consumes: existing Operations tables in both adapters.
- Produces: `LINEAR_ACCESS=mcp|rest`, `JIRA_ACCESS=mcp|rest` config keys; env vars `LINEAR_API_KEY`, `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`.

- [ ] **Step 1: In `config/project-management.config.md`, extend the per-tool settings**

In the `### Linear` block, add inside the fenced block:

```
LINEAR_ACCESS=mcp                 # mcp = Linear MCP server; rest = GraphQL API with LINEAR_API_KEY env var
```

In the `### Jira` block, add inside the fenced block:

```
JIRA_ACCESS=mcp                   # mcp = Atlassian MCP server; rest = REST API with JIRA_BASE_URL/JIRA_EMAIL/JIRA_API_TOKEN env vars
```

- [ ] **Step 2: Rework `adapters/Linear.md` access section**

Rename the `## MCP / CLI Setup` heading to `## Access mechanisms` and replace its body with:

````markdown
Two peer mechanisms; `LINEAR_ACCESS` in `../config/project-management.config.md`
selects one. Use `rest` for harnesses without an MCP client (Codex, Aider, plain
scripts).

### mcp (default)

Add the Linear MCP server to your agent's MCP config, then authenticate in the
browser flow it triggers on first use:

```json
{
  "mcpServers": {
    "linear-server": { "type": "http", "url": "https://mcp.linear.app/mcp" }
  }
}
```

### rest — GraphQL with an API key

Create a personal API key in Linear (Settings → Security & access → API keys) and
export it as `LINEAR_API_KEY`. Every operation is a single `curl` against
`https://api.linear.app/graphql`:

```bash
lin() { curl -sf https://api.linear.app/graphql \
  -H "Authorization: $LINEAR_API_KEY" -H "Content-Type: application/json" \
  -d "$1"; }
```

State/team/project names must be resolved to ids first (see the Operations table's
lookup row). Non-2xx responses or a top-level `errors` array = failed operation →
andon cord.

Relevant config: `LINEAR_DEFAULT_TEAM`, `LINEAR_DEFAULT_PROJECT`, `LINEAR_ACCESS`.
````

- [ ] **Step 3: Extend `adapters/Linear.md` Operations into a dual-mechanism table**

Replace the Operations table with:

````markdown
| Generic operation | mcp | rest (GraphQL via `lin`) |
|---|---|---|
| Lookup ids (teams, states, projects) | (implicit in MCP tools) | `lin '{"query":"{ teams { nodes { id name states { nodes { id name } } projects { nodes { id name } } } }"}'` |
| Create `[feature]` | `create_project` | `lin '{"query":"mutation { projectCreate(input: {name: \"<name>\", teamIds: [\"<teamId>\"]}) { project { id } } }"}'` |
| Create `[task]` under a feature | `create_issue` with `project` | `lin '{"query":"mutation { issueCreate(input: {title: \"<title>\", description: \"<md>\", teamId: \"<teamId>\", projectId: \"<featureId>\"}) { issue { id identifier } } }"}'` |
| Read a `[task]` | `get_issue` | `lin '{"query":"{ issue(id: \"<taskId>\") { identifier title description state { name } assignee { name } comments { nodes { body createdAt } } } }"}'` |
| List `[tasks]` in a feature | `list_issues` with `project` | `lin '{"query":"{ project(id: \"<featureId>\") { issues { nodes { identifier title state { name } assignee { name } } } } }"}'` |
| Set `[task]` status | `update_issue` with mapped `state` | `lin '{"query":"mutation { issueUpdate(id: \"<taskId>\", input: {stateId: \"<stateId>\"}) { success } }"}'` |
| Set `[task]` assignee | `update_issue` with `assignee` | `lin '{"query":"mutation { issueUpdate(id: \"<taskId>\", input: {assigneeId: \"<userId>\"}) { success } }"}'` |
| Set `[feature]` status | `update_project` | `lin '{"query":"mutation { projectUpdate(id: \"<featureId>\", input: {statusId: \"<statusId>\"}) { success } }"}'` |
| Add a comment to a `[task]` | `create_comment` | `lin '{"query":"mutation { commentCreate(input: {issueId: \"<taskId>\", body: \"<md>\"}) { success } }"}'` |
````

And update the adapter's *Initialization* section to cover both: MCP = any cheap read tool call; rest = `lin '{"query":"{ viewer { id name } }"}'` must return your user.

- [ ] **Step 4: Rework `adapters/Jira.md` the same way**

Rename `## MCP / CLI Setup` to `## Access mechanisms`, keep the existing MCP block under `### mcp (default)`, and add:

````markdown
### rest — Jira Cloud REST API v3 with an API token

Create an API token (id.atlassian.com → Security → API tokens) and export
`JIRA_BASE_URL` (e.g. `https://yourorg.atlassian.net`), `JIRA_EMAIL`, and
`JIRA_API_TOKEN`. Helper:

```bash
jira() { curl -sf -u "$JIRA_EMAIL:$JIRA_API_TOKEN" \
  -H "Content-Type: application/json" "$JIRA_BASE_URL$@"; }
```

Status changes in Jira are **transitions**: first `GET` the available transitions
for the item, find the one whose target status matches the mapped name, then `POST`
its id. Never guess transition ids. Non-2xx = failed operation → andon cord.
````

Replace the Jira Operations table with a dual-mechanism version:

````markdown
| Generic operation | mcp | rest (via `jira`) |
|---|---|---|
| Create `[feature]` | create an Epic in `JIRA_PROJECT_KEY` | `jira /rest/api/3/issue -X POST -d '{"fields":{"project":{"key":"<KEY>"},"issuetype":{"name":"Epic"},"summary":"<name>"}}'` |
| Create `[task]` under a feature | create a Story linked to the Epic | `jira /rest/api/3/issue -X POST -d '{"fields":{"project":{"key":"<KEY>"},"issuetype":{"name":"Story"},"summary":"<title>","description":'"$(adf "<text>")"',"parent":{"key":"<featureId>"}}}'` |
| Read a `[task]` | get the Story | `jira "/rest/api/3/issue/<taskId>?fields=summary,description,status,assignee,comment"` |
| List `[tasks]` in a feature | search by Epic | `jira "/rest/api/3/search?jql=parent=<featureId>"` |
| List available transitions | (implicit) | `jira "/rest/api/3/issue/<taskId>/transitions"` |
| Set `[task]`/`[feature]` status | transition the item | `jira "/rest/api/3/issue/<taskId>/transitions" -X POST -d '{"transition":{"id":"<transitionId>"}}'` |
| Set `[task]` assignee | update assignee | `jira "/rest/api/3/issue/<taskId>/assignee" -X PUT -d '{"accountId":"<accountId>"}'` |
| Add a comment to a `[task]` | add comment | `jira "/rest/api/3/issue/<taskId>/comment" -X POST -d '{"body":'"$(adf "<text>")"'}'` |
````

Descriptions and comment bodies use Atlassian Document Format; include this helper
next to `jira` in the adapter so every body is a simple paragraph node:

```bash
adf() { printf '{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"%s"}]}]}' "$1"; }
```

Update *Initialization*: rest = `jira /rest/api/3/myself` must return your account.

- [ ] **Step 5: Verify**

Run: `grep -c 'Access mechanisms' adapters/Linear.md adapters/Jira.md`
Expected: `1` each

Run: `grep -c 'LINEAR_ACCESS\|JIRA_ACCESS' config/project-management.config.md`
Expected: `2`

Run: `grep -c 'LINEAR_API_KEY' adapters/Linear.md && grep -c 'JIRA_API_TOKEN' adapters/Jira.md`
Expected: ≥2 each

- [ ] **Step 6: Commit**

```bash
git add adapters/Linear.md adapters/Jira.md config/project-management.config.md
git commit -m "Add REST/API-key access mechanism to Linear and Jira adapters"
```

---

### Task 9: Consumer updates — SKILL.md routing and README

**Files:**
- Modify: `SKILL.md` (preparation step 3, scenario table, description frontmatter)
- Modify: `README.md` (what's-in-the-box table, new orchestration section, host matrix)

**Interfaces:**
- Consumes: everything above.
- Produces: the user-facing entry points.

- [ ] **Step 1: Update `SKILL.md`**

(a) In the frontmatter `description`, append after "connect/switch the project-management tool": `, or run a multi-agent team on a feature (orchestration with a team lead, principal architect, and cross-functional implementers)`.

(b) In *Mandatory Preparation* step 3, replace "If `TEAM_MODE=true`, also read `reference/team-roles.md`." with: "If `TEAM_MODE=true`, also read `reference/team-roles.md` and `reference/orchestration.md`."

(c) In the sibling-files list at the top, add two lines after the team-roles line:

```markdown
- `reference/orchestration.md` — multi-agent protocol (mailboxes, gates, unblocking)
- `roles/<role>.md` + `config/team.config.md` + `bin/launch-team.sh` — the agent team
```

(d) In the scenario routing table, add a row before the Connect/switch row:

```markdown
| Run an agent team on a feature ("launch the team") | Team: set `TEAM_MODE=true`, follow `reference/orchestration.md`; launch via `bin/launch-team.sh` |
```

- [ ] **Step 2: Update `README.md`**

(a) In *What's in the box*, add rows:

```markdown
| `reference/orchestration.md` | Multi-agent protocol: coordination, gates, unblocking | Rarely |
| `roles/*.md` | Seven role briefs (team-lead, principal-architect, integrator, backend, frontend, qa, reviewer) | Rarely |
| `config/team.config.md` | Role→CLI map + validation commands for your stack | **Yes, per project** |
| `bin/launch-team.sh` | Launches/relaunches team agents, creates worktrees | — |
```

(b) After the *Add a brand-new tool* section, insert a new section:

````markdown
---

## Run a cross-functional agent team (optional)

The bundle includes an **LLM-agnostic orchestration layer**: seven fixed roles —
team-lead, principal-architect (technical veto), integrator (sole committer),
backend, frontend, qa, reviewer — that work one [feature]'s [tasks] in parallel,
each agent potentially a *different* LLM/CLI.

```
          PM tool (Linear/Jira/…) = single source of truth
   claims = status transitions · coordination = structured comments
                       ▲ via the adapter port ▲
 team-lead ── principal-architect ── integrator ── backend ── frontend ── qa ── reviewer
   (process)      (technical veto)   (sole commits)  └── one git worktree each ──┘
                       ▼ optional low-latency transport ▼
        .teamwork/<team>/  mailboxes · heartbeats  (degrades to tracker polling)
```

1. Configure your tracker as above, then edit `config/team.config.md`: one CLI
   command per role (`claude -p …`, `codex exec …`, `gemini …` — mix freely) and
   your project's `VALIDATE_*` commands.
2. Add `.teamwork/` to `.gitignore`.
3. Ask your primary agent (as team-lead) to *"plan a feature and launch the team"*
   — or run `bin/launch-team.sh start <branch> <featureId> <roles...>` yourself.
4. Watch agents in tmux (`tmux attach -t team-<branch>`), progress in your tracker,
   and escalations in `.teamwork/<branch>/ESCALATIONS.md`.

Every [task] passes a **design gate** (principal-architect approves a design note
before any code) and **dual review** (reviewer + architect, explicit file lists),
and only the integrator merges + completes — commit and `[Completed]` are atomic.
The team-lead detects stuck/conflicting/crashed agents and unblocks them
(message → decide → reassign → relaunch), escalating to you only as a last resort.

**First run without any tracker account:** set `PRODUCT_MANAGEMENT_TOOL=Markdown`
and launch just `team-lead` + `backend` — a complete offline test of the protocol.
````

(c) After the install section, add a host matrix section:

````markdown
## Works with any agentic CLI

| Harness | Install | Invoke |
|---|---|---|
| Claude Code | copy bundle to `.claude/skills/project-management/` | "plan a feature" / "launch the team" |
| Codex CLI | copy anywhere, e.g. `.codex/pm/` | `codex exec "Read .codex/pm/SKILL.md and plan a feature …"` |
| Aider | copy anywhere | `aider --read pm/SKILL.md`, then instruct |
| Cursor / Windsurf / Cline | copy into the tool's rules dir | reference `SKILL.md` in chat |
| Anything else | copy anywhere | point the agent at `SKILL.md` |

Minimum host capabilities: file read/write, shell, git. Tracker access works via
MCP **or** plain REST with an API key (see each adapter's *Access mechanisms*), so
harnesses without MCP clients are first-class.
````

- [ ] **Step 3: Verify**

Run: `grep -c 'orchestration.md' SKILL.md README.md`
Expected: ≥1 each

Run: `grep -niE '\b(issue|epic|story|ticket)\b' SKILL.md`
Expected: matches ONLY on the pre-existing golden-rule line that defines the ban ("Never write \"issue\", \"epic\", \"story\", or \"ticket\" outside the adapter") and the banned-terms pointer — no new occurrences introduced by this task. (README may name tools/terms only inside the adapter-mapping context it already has.)

- [ ] **Step 4: Commit**

```bash
git add SKILL.md README.md
git commit -m "Route team orchestration through SKILL.md and document it in README"
```

---

### Task 10: End-to-end consistency verification

**Files:**
- None created — verification only (fix anything found, amend the relevant file, commit fixes).

- [ ] **Step 1: Cross-reference check — every referenced file exists**

Run:
```bash
for f in reference/vocabulary.md reference/lifecycle.md reference/team-roles.md \
         reference/orchestration.md config/project-management.config.md \
         config/team.config.md bin/launch-team.sh \
         roles/team-lead.md roles/principal-architect.md roles/integrator.md \
         roles/backend.md roles/frontend.md roles/qa.md roles/reviewer.md \
         adapters/_TEMPLATE.md adapters/Linear.md adapters/Jira.md \
         adapters/GitHubIssues.md adapters/Markdown.md; do
  [ -f "$f" ] || echo "MISSING $f"
done
```
Expected: no output

- [ ] **Step 2: Marker consistency — no undefined markers anywhere**

Run: `grep -rhoE '\[[a-z][a-z-]+\]' roles/ reference/orchestration.md SKILL.md | sort -u | grep -vE '\[(design-note|design-approved|design-pushback|api-ready|divergence|review-request|review-findings|review-approval|architecture-approval|handoff|andon|escalation|feature|features|task|tasks|subtask|subtasks)\]'`
Expected: no output

- [ ] **Step 3: Banned-terms sweep over all workflow files**

Run: `grep -rniE '\b(epic|story|user story|work item|backlog item)\b' SKILL.md reference/ roles/ config/team.config.md`
Expected: no output. (`reference/vocabulary.md` legitimately lists banned words — exclude it if it matches: the list there is the definition.)

- [ ] **Step 4: Launcher test still green**

Run: `bash tests/launcher-test.sh`
Expected: `ALL PASS`

- [ ] **Step 5: Offline dry-run checklist (manual, ~10 min)**

With `PRODUCT_MANAGEMENT_TOOL=Markdown` and a scratch feature branch, walk one [task] through the pipeline *by hand* (you play every role), performing each adapter write for real:
1. Create a [feature] + one [task] (`[Planned]`) in the Markdown tree.
2. Claim it (assignee + `[Active]`), create a worktree via `bin/launch-team.sh worktree`.
3. Write `[design-note]` → `[design-approved]` comments.
4. Touch a file, write `[divergence]`, `[review-request]`, move to `[Review]`.
5. Write `[review-approval]` + `[architecture-approval]` with the file list.
6. As integrator: verify lists vs diff, merge, commit, `[Completed]` with the hash.
Confirm each step's instructions were unambiguous from the files alone; fix any friction found, commit.

- [ ] **Step 6: Final commit (if fixes were made)**

```bash
git add -u
git commit -m "Consistency fixes from end-to-end verification"
```
