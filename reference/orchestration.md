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
├── worktrees/<role>#<attempt>-<taskId>/ # per-instance working copies, provisioned via WORKTREE_SETUP (parallel execution only)
├── CONTRACTS.md                 # append-only registry of names plans export/consume (see "Contract registry")
├── BASELINE.md                  # known state of the branch at creation: test counts, known failures, validation commands (see "Baseline manifest")
├── review-ledger.md             # reviewers' one-line-per-ruling ledger of still-live conditions
├── tasks.json                   # read-only [task] export for credential-less roles (adapter "export" operation)
├── artifacts/<taskId>/          # full logs, checklists, evidence files — cited by path from budgeted comments
├── progress-ids/<taskId>        # comment id of the [task]'s editable [progress] comment
└── ESCALATIONS.md               # the Lead's log of everything escalated to the human
```

## Identity

Exactly seven **protocol roles** exist: `team-lead`, `principal-architect`,
`integrator`, `backend`, `frontend`, `qa`, `reviewer` — the protocol's rules,
gates, and status ownership are written against these. Preset teams (`teams/`)
add **specialized role names** (`principal-software-architect`,
`senior-qa-engineer`, …), each acting as one or more protocol roles per the
*Protocol mapping* line in its brief.

One signing rule: **use the role name at the top of your startup prompt,
verbatim and only that name** — as your tracker assignee name, your mailbox
directory, your heartbeat file, and the signature of every comment: `— <role>`.
A specialized role signs its specialized name; when it writes a protocol-role
marker and the mapping isn't already on the [task], it states the mapping once —
e.g. `— principal-software-architect (as principal-architect)` — and plain
`— <specialized-name>` thereafter. Never alternate between the two names within
a run: signatures are grep keys.

## Mailboxes and heartbeats

- **Send:** write `<TEAMWORK_ROOT>/<team>/mailbox/<to-role>/NNN-<your-role>.md`, where
  `NNN` is the next free 3-digit number in that directory. Format:

  ```
  From: <your-role>
  Re: <taskId or feature>
  ---
  <one short, actionable message>
  ```

- **Receive:** check your mailbox directory between work steps. Process messages in
  number order; delete each after acting on it. **Never sit idle polling:** when your
  turn's work is done, deliver your artifact and exit — you will not be alive later,
  so never plan to "check back". The dispatcher owns time (`reference/dispatch.md`);
  `POLL_INTERVAL_SECONDS` is *its* cadence, not yours.
- **Heartbeat:** between work steps, rewrite your heartbeat file with
  `<ISO-8601 UTC> | <current taskId or -> | <one-line state>` (e.g.
  `2026-07-06T14:02:11Z | ENG-142 | implementing, subtask 3/5`).
- **Degradation:** if the workspace directory is unreachable (different machine),
  skip mailboxes and heartbeats entirely and poll the tracker for comments addressed
  to your role. State this degradation once in a comment on your current [task].

## Report before idle — the delivery contract

**You never go idle without first delivering your current structured artifact**
(`[design-note]`, `[review-request]`, a review verdict, `[andon]`, …) to the
tracker and notifying the team-lead. Finishing the work is half the job; the
protocol only sees what was delivered. This includes rework: a rework pass ends
with a fresh `[review-request]` — fixes applied silently are undelivered work.
Idle with undelivered work is a protocol violation — the lead treats it as
**Stuck** immediately, and a repeat on the same assignment as grounds to
reassign or relaunch.

The launch handshake is the same contract from the lead's side:

- **The spawn prompt is context, not a trigger.** After spawning or relaunching a
  teammate, the lead always sends an explicit assignment message (mailbox or
  harness message): the [task] or gate to act on, pointers to conditions, and the
  expected artifact. Teammates act on assignment messages; a teammate that has a
  startup prompt but no assignment asks the lead instead of guessing — or idling.
- Every assignment names the artifact that ends it. When that artifact is
  delivered, the loop closes; until then, the teammate is accountable for it.

## Harness mode — teammates as in-session subagents

Teams don't have to run as external CLI processes. When the orchestrating agent's
harness can spawn subagents and message them directly, run the whole team inside
it — same protocol, different transport:

| CLI-process mechanism | Harness-mode equivalent |
|---|---|
| `launch-team.sh start/team` (spawn) | `launch-team.sh compose <team> <featureId> <role> [preset]` writes the identical startup prompt without spawning; the lead spawns the role natively with it |
| Mailbox files | The harness's agent-to-agent messages. Same rule as mailboxes: transport, never truth — a decision is binding only once it lands as a tracker comment |
| Heartbeats | The harness's lifecycle/idle notifications |
| pid files, tmux, `status`/`stop` | Not applicable — the harness owns process supervision |
| Filesystem-degradation statement | Not needed — the harness delivers messages |

Everything else is unchanged: the tracker is still the single source of durable
truth, markers and statuses are still the protocol, worktrees (in parallel
execution) still come from `launch-team.sh worktree`, and the *Report before
idle* contract applies with the harness's idle notification standing in for a
stale heartbeat. The two modes mix freely — e.g. harness subagents for
implementers, a CLI process for a long-lived reviewer.

## Execution modes — sequential by default, parallel by declaration

`EXECUTION` in `config/team.config.md` names how much implementation concurrency
the team runs. It changes **where code is written and how integration commits** —
nothing else: markers, gates, reviews, and statuses are identical in both modes.

- **`sequential` (default).** Exactly one [task] is **in flight** at a time,
  and it **reserves the shared checkout from claim until its atomic
  commit+move to the terminal status** — not merely while `[Active]`. A [task]
  in `[Review]` (or bounced back for rework) still owns the checkout: its
  uncommitted diff sits there until the integrator commits it. Implementers
  edit the feature-branch checkout directly; the integrator verifies, stages,
  validates, and commits **in place** — no task branches, no worktrees, no
  merge step. Because agents checking tracker state before claiming is not
  atomic across [tasks], sequential claiming is **lead-dispatched**: the
  team-lead (owner of `[Planned]`) sends one assignment at a time and sends
  the next only after the previous [task] integrated — implementers never
  self-claim in this mode. One serialized writer needs no isolation; per-task
  branches would be pure overhead. This is the proven path for harness-run
  teams.
- **`parallel`.** Required the moment two implementers can be `[Active]` at
  once. The full isolation machinery applies: one worktree + task branch per
  [task] (`bin/launch-team.sh worktree`), the integrator merges serially in
  dependency order, and same-file collisions are handed back to the implementer
  for rebase.

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
    `Parked (pipelined): preempted by rework on <N>. Resume on <N> re-entering [Review].`
    (this parked comment deliberately carries **no** `resume-status:` — the lead
    owns the resume assignment and performs the `Blocked → Active` move directly
    when N re-enters `[Review]`; the dispatcher must not auto-resume a parked task),
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

Deliberately **not** mode-dependent: `TRACKER_WRITERS=lead` stays the
recommended write path under parallelism (more concurrent writers means more
races, not fewer), and QA's last-in-time `[review-approval]` remains a
serialized final gate no matter how many implementers run.

**Before setting `EXECUTION=parallel` — at any `MAX_ACTIVE_IMPLEMENTERS`,
pipelined `1` included — validate the machinery once** — docs are not
evidence, and a sequential run proves nothing about it. Record what ran and
where (in `BASELINE.md` or on the [feature]):

1. `bin/launch-team.sh worktree` creates a usable isolated tree in *your*
   environment (harness subagents included) and an implementer can build and
   test inside it.
2. Deliberately collide two task branches on one file and confirm the
   integrator merges the first and hands the second back for rebase — never
   resolving the conflict itself.
3. The contract registry is populated **during** planning (see *Contract
   registry*): worktrees isolate code-in-progress; only the registry prevents
   the plan-time contract forks that parallel planning actually produces.
4. **Pipelined (`MAX_ACTIVE_IMPLEMENTERS=1`) additionally requires:** the
   team's most recent comparable run shows a first-pass rework rate below
   ~25%. Pipelined saves ≈ (review + integrate time) × (first-pass-approved
   [task] count); rework cycles gain nothing from it — at a high rework rate,
   fix review predictability first (mandatory design checklists,
   `REVIEW_MODE` — see `teams/_PLAYBOOK.md` → *Review modes*).

## Structured comments — the coordination markers

All coordination artifacts are comments on the [task], written through the adapter,
beginning with an exact marker. Markers are the machine-readable protocol; never
invent new ones, never misspell them.

Marker **authorship is enforced, not narrated**: the board config's `markers`
table names the role(s) authorized to post each gate marker (presets may
override it). The integrator refuses any approval whose signer is not
authorized (its step 1.5). When a marker's only authorized role is the [task]'s
own implementer, an **independent verifier** from the roster substitutes — no
role ever approves its own work; none available → `[andon]`.

**Budgets and supersession.** A gate-marker comment is ≤ **30 lines**: marker,
`round: N`, `supersedes: <comment-id>` (round ≥ 2; Markdown adapter:
`<marker>-<round>` stands in for the id), verdict, delta since the last round,
file list, evidence/artifact paths, signature. Full checklists, logs, and long
rationale live in `<TEAMWORK_ROOT>/<team>/artifacts/<taskId>/` and are cited by
path — the integrator verifies cited paths exist. Reconstructing current state
from a trail: per marker type, the comment with the highest `round:` not named
by a later `supersedes:` is current; everything else is history (unnumbered
pre-v2 comments count as round 0). WIP narration, setup chatter, and restated
[task] descriptions never enter the tracker — design notes are **delta-only**.

| Marker | Written by | Meaning / required content |
|---|---|---|
| `[design-note]` | implementer | Proposed approach before any code: approach, API/contract changes, data-model changes, affected components. Frontend must include `Architectural impact: yes/no — <why>`. Registers every name it exports in `CONTRACTS.md` and cites the registry line for every sibling export it consumes (see *Contract registry*). |
| `[design-approved]` | principal-architect | Gate open. Carries a **numbered architecture checklist** — the items the architecture review will verify — plus any binding conditions. The lead delivers the checklist in the assignment; reviewer/QA Phase-1 checklists start from it (add items, never subtract). |
| `[design-pushback]` | principal-architect | Gate closed. Lists required changes; implementer revises the `[design-note]` and re-pings. |
| `[api-ready]` | backend | Contract available for frontend: endpoints, request/response shapes. Also sent by mailbox. |
| `[divergence]` | implementer | What was done differently from the [task]/design note and why. Additive — **never edit the original [task] description.** |
| `[review-request]` | implementer | Ready for review: what changed, list of changed files, an **evidence record per validated command** (see *Evidence and re-execution*), an explicit `NOT validated:` section for anything not run (with reason), and any index-only staging operation performed. A claimed result without its evidence record **is** NOT validated. Written when moving to `[Review]`. |
| `[review-findings]` | reviewer / qa / principal-architect | Numbered problems that must be fixed. Task goes back to `[Active]`. |
| `[review-approval]` | reviewer / qa | Approval with the **explicit list of approved file paths**. |
| `[architecture-approval]` | principal-architect | Same, from the architecture review. |
| `[product-approval]` | product owner role (e.g. `senior-technical-product-manager`; the team-lead where no product role exists) | Scope/acceptance sign-off: scope ruling, acceptance-criteria verdict, any conditions. |
| `[product-pushback]` | product owner role (same) | Scope gate closed: what must change in scope or acceptance criteria before work proceeds. |
| `[handoff]` | team-lead | Reassignment: summary of state so a fresh agent can resume. |
| `[progress]` | implementer (via lead in scribe mode) | **One per [task], edited in place** (`tracker-ops.sh update-comment`; Markdown adapter: append a superseding one). Content: stage (`claimed / design-approved / implementing / validating / review-round-N`), updated-at (UTC), ≤ 3 lines of state. Edit on stage boundaries only, ≥ 10 min apart. First post: capture the comment id in `<TEAMWORK_ROOT>/<team>/progress-ids/<taskId>`; a relaunched scribe re-reads the trail to find it. |
| `[digest]` | team-lead | **One per [feature], on the [feature] itself, edited in place** at milestones only (a [task] hits terminal status, a gate rejects, an `[andon]`, feature done): one line per [task] (`<taskId> <title> — [Status] (<reason if blocked/rejected>)`) + `⚠ escalation open: <taskId>` lines. The human reads this one comment, never the trails. GitHubIssues: milestones take no comments — keep the digest in the milestone description (`gh api PATCH`). |
| `[andon]` | any role | Stop-the-line report: what failed, exact error, what you did NOT do. |
| `[escalation]` | team-lead | Needs the human. Required shape: `question:` (one sentence), `context:` (≤ 4 lines), `options:` (≥ 2, each with a one-line consequence), `default-if-silent: <option> after <N hours>`. Also appended to `ESCALATIONS.md`. An `[escalation]` without options + default is a protocol error (`[andon]`). |

## Contract registry — parallel plans share names, not assumptions

When [tasks] are planned or implemented in parallel, the cheapest defect filter is
a single place where cross-[task] names live. `<TEAMWORK_ROOT>/<team>/CONTRACTS.md`
is an **append-only registry**:

- Every `[design-note]` **registers what it exports** — schema/field names, event
  constants, endpoint paths, enum values, anything a sibling [task] will spell —
  one line each: `<taskId> exports <kind> <name> — <one-line shape>`.
- Every plan that **consumes** a sibling's export cites the registry line instead
  of restating the name from memory. No matching line yet? That's a sequencing
  question for the principal-architect, not a guess.
- The principal-architect's reviews (batch or per-[task]) **diff plans against
  the registry** — two [tasks] spelling the same concept differently is a
  `[design-pushback]` on the later one, caught before code exists. Unregistered
  exports or an uncited consumed name are themselves `[design-pushback]`
  grounds: the registry only prevents forks if it is populated **while plans are
  being written**, not reconstructed afterwards.
- Renames are new lines that supersede old ones (`supersedes: <line>`), never
  edits — the history is the audit trail.

## Baseline manifest — no oral tradition about branch state

At feature-branch creation the team-lead records
`<TEAMWORK_ROOT>/<team>/BASELINE.md`: current test counts, **known failures with
their cause**, and the validation commands that exist right now. Every brief and
review judges work against it: **the bar is "no new failures", not "all green"** —
nobody restates known-failure lore in assignment messages, and nobody gets blamed
for red that predates the branch. When a [task] changes the validation landscape
(adds a linter, a suite, a build step), updating `BASELINE.md` is part of that
[task]'s diff. The integrator cites `BASELINE.md` when recording skips or judging
a validation run.

## Tracker write modes

`TRACKER_WRITERS` in `config/team.config.md` sets who physically writes to the
tracker:

- **`all` (default).** Every role performs its own adapter operations. Requires
  every agent to hold tracker access.
- **`lead` — single-writer ("scribe") mode.** Only the team-lead holds tracker
  credentials. Roles compose their artifacts exactly as the protocol requires —
  same markers, same content, signed `— <role>` — but deliver them to the lead
  (mailbox or harness message) instead of posting. The lead posts each block
  **verbatim**, appending `(posted by team-lead)` to the signature:
  `— <role> (posted by team-lead)`. Status changes work the same way: the role
  requests the move, the lead performs the write.

  In `lead` mode, status ownership and marker authorship rules apply to the
  **authoring** role, not the writing one — the lead is a scribe, never an
  author, and gains no authority from holding the pen: it still cannot approve a
  design, soften a finding, or override a veto, and it must not edit, summarize,
  or reorder a block it posts. Trade-offs to accept knowingly: signatures no
  longer prove authorship (acceptable inside one supervised team), and the lead
  becomes a serialization point (which is also the point — no credential sprawl,
  no write races, uniform formatting).

## Status routing

The board (`config/statuses.config.json`, composed into your startup prompt) assigns
every status an owner. **Whenever you move an item into a status, notify the new
owner's mailbox** (and, as always, the move itself lands as tracker state). If the
owner is a `{"team": ...}`, send to that team's lead, who dispatches internally.
The owner of a status is the only role that works items sitting in it and the only
one that performs its outbound transitions.

## Claiming a [task]

1. Read the [task] in full via the adapter (description, [subtasks], all comments).
2. Verify status is `[Planned]` and it belongs to your track. If not → `[andon]`.
   Also verify the sweep is not pending on your track: under `EXECUTION=sequential`,
   the previously integrated [task] has no `[divergence]` comments still awaiting
   the principal-architect's sweep; under `parallel`, the most recent [task] that
   entered `[Review]` on your track has the PA's sweep confirmation. If pending,
   wait or ask the PA by mailbox. Under `EXECUTION=sequential` — and under
   `parallel` whenever `MAX_ACTIVE_IMPLEMENTERS` is set — you claim only on the
   team-lead's assignment (never self-serve — see *Execution modes*). Under
   `sequential`, additionally verify before touching anything that
   **the shared checkout is free**: no [task] anywhere is in flight
   (`[Active]` **or** `[Review]` — a [task] in review still owns the checkout
   until integrated), and `git status --porcelain -uall` on the feature-branch
   checkout is clean. Dirty checkout or an in-flight [task] → don't claim;
   tell the lead.
3. Set assignee = your role name AND move `[Planned] → [Active]` (one adapter write
   where the tool allows, else assignee first).
4. **Read back.** If the assignee is not you, another agent won — back off silently
   and pick the next `[Planned]` [task] on your track.
5. Set up your working copy (roles that write code only). `EXECUTION=parallel`:
   create your worktree — `bin/launch-team.sh worktree <team> <role> <taskId>`.
   The worktree is your **instance's** scratch space (attempt-numbered); it arrives provisioned when `WORKTREE_SETUP` is set — validation claims may only cite commands actually executed inside it.
   `EXECUTION=sequential`: work in the feature-branch checkout directly; there
   is no worktree and no task branch (see *Execution modes*).

One implementer per [task], ever. Claiming is the lock.

## The task pipeline

```
claim → [design-note] → wait for [design-approved]      (no code before the gate)
      → implement in your working copy                   ([divergence] comments as needed)
        (worktree in parallel execution; feature-branch checkout in sequential)
      → self-validate (VALIDATE_SCRIPT or the VALIDATE_* that apply; bar =
        no new failures vs BASELINE.md)
      → [review-request] + move to [Review]
      → reviewer three-phase review ∥ principal-architect architecture review
      → findings? → back to [Active], fix, [review-request] again
      → [review-approval] + [architecture-approval] (both, with file lists)
      → integrator: verify lists == diff, stage explicitly, validate
        (VALIDATE_SCRIPT or VALIDATE_*, judged against BASELINE.md),
        merge to the feature branch (parallel execution only), commit,
        move to [Ready to deploy] (atomic pair)
      → principal-architect divergence sweep updates upcoming [tasks]
        (sequential: runs here; parallel: already ran at [Review] entry)
```

Gates live in comments; statuses move only along the `transitions` graph in
`config/statuses.config.json`. Default board: `[Planned] → [Active] → [Review] →
[Ready to deploy]`, rework `[Review] → [Active]`, and `[Blocked]` as the parking
status for stuck work (owner: team-lead — see lifecycle Scenario 7).

## Dual review

Both reviews start when the [task] enters `[Review]`, run independently, and both
must approve before integration:

- **Reviewer — three phases.** (1) *Plan*: before reading any code, read the
  [feature] and [task], extract every business rule / validation / edge case into an
  independent checklist — seeded by the `[design-approved]` architecture
  checklist (add items, never subtract) — with an expected file list. (2) *Review*: every changed file,
  line by line; findings go out immediately as `[review-findings]`. (3) *Verify*:
  re-read fixes; every checklist item needs a `file:line` citation and a test
  citation; the approval file list must equal the actual diff.
- **Principal Architect.** Checks conformance to the approved `[design-note]`,
  boundary violations, coupling, contract drift. Same file-list rule.

Anti-rationalization (all reviews): "it's just a warning", "pre-existing problem",
"the tools passed so it must be fine" — none of these excuse a finding. Main is
always clean; anything broken on the branch is ours to fix or file (Scenario 6).

## Evidence and re-execution — verify instead of re-derive

Every validated command in a `[review-request]` carries an evidence record:

```
Evidence:
  commit:   <sha of the working copy HEAD when the command ran>
  command:  <exact command>
  exit:     <code>
  counts:   <e.g. 47 passed, 0 failed, 2 skipped>
  duration: <seconds>
  log:      <TEAMWORK_ROOT>/<team>/artifacts/<taskId>/validate-<round>-<role>.log
NOT validated:
  <command> — <reason (e.g. worktree unprovisioned, N/A for this change)>
```

Who executes suites (the two independent executions that catch real defects are
**never** traded away):

| Role | Suites | Condition |
|---|---|---|
| Implementer | runs; records evidence | always — in the provisioned working copy |
| Principal architect | inspect + spot-check, no blind re-run | only while `Evidence.commit` == branch HEAD; else re-run |
| QA final gate | **always re-runs** | unconditional — evidence is context, not gate |
| Integrator | **always re-runs** | unconditional |

Any mismatch between an evidence record and a re-run (exit code or counts) is an
automatic `[review-findings]` labeled `trust-breach (severity: critical)` —
resolvable only by a fresh implementer run and a new record, never by explanation.

## Integration

The `integrator` is the **only** role that merges to the feature branch, commits, or
marks `[Ready to deploy]`. Pipeline (all-or-nothing, zero tolerance, no overrides — not
even from the team-lead):

1. Verify both approval comments exist and their file lists are identical to the
   full changed-file set — `git diff --name-only <feature-branch>...HEAD` plus
   `git status --porcelain -uall` for uncommitted work (always `-uall`: plain
   porcelain hides the files inside a new directory), run from inside the
   [task]'s worktree (parallel execution) or the feature-branch checkout
   (sequential — the changed set is just the uncommitted work). Any mismatch →
   `[andon]`.
2. Stage by explicit file list (never `add -A`), verify the staged set matches.
   Index-only operations (untracking a file) are the implementer's one sanctioned
   staging exception — allowed only when named in the `[review-request]`.
3. Validate — `VALIDATE_SCRIPT` with the changed-file list if set, else
   `VALIDATE_BUILD`, `VALIDATE_TEST`, `VALIDATE_LINT`, `VALIDATE_FORMAT` (skip `null` ones, record
   skips). Judge against `BASELINE.md`: the bar is no NEW failures. Any new
   failure → `[andon]`, task back to `[Active]`.
4. Parallel execution only: merge the task branch into the feature branch;
   remove the worktree. (Sequential: nothing to merge — the staged work already
   sits on the feature-branch checkout.)
5. Commit, capture the hash, then immediately move the [task] to `[Ready to deploy]`,
   citing the hash. Commit and completion are one atomic pair — never one without
   the other.
6. When every [task] is `[Ready to deploy]`, tell the team-lead and principal-architect; the [feature] moves to
   `[Resolved]` only after the Lead's completion checklist passes.

## Supervision — the team-lead loop

**On each invocation** — the dispatcher (`reference/dispatch.md`) or the harness
loop decides when that is — read all heartbeats, your mailbox, and the tracker,
act on **every** pending event in one pass, then exit.

Detect:
- **Stuck** — heartbeat older than `STUCK_AFTER_MINUTES`; an `[Active]` [task] with
  no new comment past the threshold; a `[design-note]`, question, or
  `[review-request]` that nobody answered (the principal-architect is on the hot
  path — monitor it like anyone else). **A teammate that goes idle while you are
  still waiting on its artifact is Stuck immediately** — the delivery contract was
  violated; do not wait out `STUCK_AFTER_MINUTES`, go straight to rung 1.
- **Parked** — a [task] sitting in `[Blocked]` with no new comment past the threshold; the team-lead owns driving it out.
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
4. **Kill & relaunch** — quarantine the dead instance's working copy first (see
   *Recovery* → *Relaunch hygiene*), then
   `bin/launch-team.sh relaunch <team> <featureId> <role>` (or respawn in the
   harness). The replacement resumes from tracker state alone.
5. **Escalate** — `[escalation]` comment + append to `ESCALATIONS.md`. Reserved for
   scope/business-rule questions, destructive actions, or after
   `ESCALATE_AFTER_ATTEMPTS` failed rungs.

The Lead never overrides an integrator validation failure or a principal-architect
veto — the andon cord outranks the Lead. During autonomous operation the Lead never
blocks the team on an interactive user prompt; escalation is the channel.

**Idle-notification hygiene.** Heartbeats and harness idle pings are liveness
signals, not events. The lead's test is mechanical: *did the teammate's last
message/comment for its current assignment carry the expected marker artifact?*
Act on exactly two things: (a) an artifact arrived — process it; (b) idle
**without** it — that is a delivery-contract violation, not a heartbeat: Stuck,
rung 1 now, demanding the artifact by name. A **second** artifact-less idle on
the same assignment means the instance is not executing the protocol — skip to
rung 3/4 (reassign or relaunch); do not keep nudging. Everything else (routine
idle pings, repeated heartbeats, "still working" noise) gets no reply and no
acknowledgment — answering it burns your turns and everyone else's context.
An idle ping is never a completion signal; only the artifact is.

## Recovery

Relaunched or restarted agents need no session state: read your role brief, query
the tracker for [tasks] assigned to your role in any non-terminal status, read the
comment trail (design note, approvals, findings), check your working copy, resume
at the pipeline stage the comments prove you reached. If the trail is ambiguous →
`[andon]`.

### Relaunch hygiene

A killed or unresponsive instance may have left uncommitted
writes in its working copy; a successor must never inherit them silently — orphan
files reaching review as if they were deliberate is exactly how a relaunch
contaminates a [task]. Before the replacement starts, the lead quarantines the
residue: parallel execution — discard the dead instance's worktree (`bin/launch-team.sh worktree-remove <team> <role> <taskId> [attempt]`; use `git worktree move` first if salvage is on the table) and let the successor create attempt N+1 on the same task branch; sequential — `git stash -u` on the feature-branch
checkout (safe to attribute wholesale: the checkout-reservation rule means the
only uncommitted work there is the dead instance's own [task]). The successor then rules **explicitly**, as a comment on the [task]:
**salvage** (restore the quarantined changes and justify every kept file against
the approved `[design-note]`) or **discard** (drop them and redo from the tracker
trail). Since implementers don't commit, "start clean" always means giving up the
dead instance's work — that trade is the successor's call to make on the record,
never an accident of inheritance.

## Andon cord

Pull it — stop, write an `[andon]` comment, notify the team-lead by mailbox — when:
a [task] is in an unexpected status; an adapter operation fails; validation fails;
you are blocked or see contradictory instructions. Never work around a failure,
never fabricate a result, never claim a status you did not verify.

## Capability matrix

| Capability | Needed by | If missing |
|---|---|---|
| File read/write | all | — (hard requirement) |
| Shell + git | all; worktrees for implementers (parallel execution) | — (hard requirement) |
| Tracker access (adapter: MCP, REST + API key, CLI, or files) | all | use another mechanism from the adapter's *Access mechanisms*; never fabricate |
| Shared filesystem with the team | mailbox/heartbeats | poll the tracker; say so once on your [task] |
| Harness-native teammates (subagent spawn + messaging) | harness mode | launch CLI processes via `bin/launch-team.sh` (tmux / background) |
| tmux | launcher niceness | background processes + pid files |
| Long-running loop | nobody — the loop lives outside agents (`reference/dispatch.md`) | one-shot turns are the primary path: `bin/dispatch.sh --watch` (CLI) or the harness orchestrator converts events into launches; recovery makes restarts free |

A missing capability degrades **explicitly** — state what you could not do; never
silently skip a protocol step.
