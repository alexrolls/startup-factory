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
├── CONTRACTS.md                 # append-only registry of names plans export/consume (see "Contract registry")
├── BASELINE.md                  # known state of the branch at creation: test counts, known failures, validation commands (see "Baseline manifest")
├── review-ledger.md             # reviewers' one-line-per-ruling ledger of still-live conditions
├── tasks.json                   # read-only [task] export for credential-less roles (adapter "export" operation)
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

- **Receive:** check your mailbox directory between work steps and at least every
  `POLL_INTERVAL_SECONDS` when idle. Process messages in number order; delete each
  after acting on it.
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
protocol only sees what was delivered. Idle with undelivered work is a protocol
violation — the lead treats it as **Stuck** immediately.

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
truth, markers and statuses are still the protocol, worktrees still come from
`launch-team.sh worktree`, and the *Report before idle* contract applies with the
harness's idle notification standing in for a stale heartbeat. The two modes mix
freely — e.g. harness subagents for implementers, a CLI process for a long-lived
reviewer.

## Structured comments — the coordination markers

All coordination artifacts are comments on the [task], written through the adapter,
beginning with an exact marker. Markers are the machine-readable protocol; never
invent new ones, never misspell them.

| Marker | Written by | Meaning / required content |
|---|---|---|
| `[design-note]` | implementer | Proposed approach before any code: approach, API/contract changes, data-model changes, affected components. Frontend must include `Architectural impact: yes/no — <why>`. Registers every name it exports in `CONTRACTS.md` and cites the registry line for every sibling export it consumes (see *Contract registry*). |
| `[design-approved]` | principal-architect | Gate open. May carry conditions the implementation must honour. |
| `[design-pushback]` | principal-architect | Gate closed. Lists required changes; implementer revises the `[design-note]` and re-pings. |
| `[api-ready]` | backend | Contract available for frontend: endpoints, request/response shapes. Also sent by mailbox. |
| `[divergence]` | implementer | What was done differently from the [task]/design note and why. Additive — **never edit the original [task] description.** |
| `[review-request]` | implementer | Ready for review: what changed, list of changed files, validation commands run and their results (judged against `BASELINE.md`), and any index-only staging operation performed (e.g. untracking a file) — the one staging act an implementer may perform. Written when moving to `[Review]`. |
| `[review-findings]` | reviewer / principal-architect | Numbered problems that must be fixed. Task goes back to `[Active]`. |
| `[review-approval]` | reviewer | Approval with the **explicit list of approved file paths**. |
| `[architecture-approval]` | principal-architect | Same, from the architecture review. |
| `[product-approval]` | product owner role (e.g. `senior-technical-product-manager`; the team-lead where no product role exists) | Scope/acceptance sign-off: scope ruling, acceptance-criteria verdict, any conditions. |
| `[product-pushback]` | product owner role (same) | Scope gate closed: what must change in scope or acceptance criteria before work proceeds. |
| `[handoff]` | team-lead | Reassignment: summary of state so a fresh agent can resume. |
| `[andon]` | any role | Stop-the-line report: what failed, exact error, what you did NOT do. |
| `[escalation]` | team-lead | Needs the human: question + context + what was already tried. |

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
  `[design-pushback]` on the later one, caught before code exists.
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
2. Verify status is `[Planned]` and it belongs to your track. If not → `[andon]`. Also verify the previously integrated [task] on your track has no `[divergence]` comments still awaiting the principal-architect's sweep — if it does, wait or ask the PA by mailbox.
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
      → self-validate (VALIDATE_SCRIPT or the VALIDATE_* that apply; bar =
        no new failures vs BASELINE.md)
      → [review-request] + move to [Review]
      → reviewer three-phase review ∥ principal-architect architecture review
      → findings? → back to [Active], fix, [review-request] again
      → [review-approval] + [architecture-approval] (both, with file lists)
      → integrator: verify lists == diff, stage explicitly, validate
        (VALIDATE_SCRIPT or VALIDATE_*, judged against BASELINE.md),
        merge to the feature branch, commit, move to [Ready to deploy] (atomic pair)
      → principal-architect divergence sweep updates upcoming [tasks]
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
marks `[Ready to deploy]`. Pipeline (all-or-nothing, zero tolerance, no overrides — not
even from the team-lead):

1. Verify both approval comments exist and their file lists are identical to the
   full changed-file set — `git diff --name-only <feature-branch>...HEAD` plus
   `git status --porcelain -uall` for uncommitted work (always `-uall`: plain
   porcelain hides the files inside a new directory), run from inside the
   [task]'s worktree. Any mismatch → `[andon]`.
2. Stage by explicit file list (never `add -A`), verify the staged set matches.
   Index-only operations (untracking a file) are the implementer's one sanctioned
   staging exception — allowed only when named in the `[review-request]`.
3. Validate — `VALIDATE_SCRIPT` with the changed-file list if set, else
   `VALIDATE_BUILD`, `VALIDATE_TEST`, `VALIDATE_LINT` (skip `null` ones, record
   skips). Judge against `BASELINE.md`: the bar is no NEW failures. Any new
   failure → `[andon]`, task back to `[Active]`.
4. Merge the task branch into the feature branch; remove the worktree.
5. Commit, capture the hash, then immediately move the [task] to `[Ready to deploy]`,
   citing the hash. Commit and completion are one atomic pair — never one without
   the other.
6. When every [task] is `[Ready to deploy]`, tell the team-lead and principal-architect; the [feature] moves to
   `[Resolved]` only after the Lead's completion checklist passes.

## Supervision — the team-lead loop

Every `POLL_INTERVAL_SECONDS`: read all heartbeats, your mailbox, and the tracker.

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
4. **Kill & relaunch** — `bin/launch-team.sh relaunch <team> <featureId> <role>`.
   The replacement resumes from tracker state alone.
5. **Escalate** — `[escalation]` comment + append to `ESCALATIONS.md`. Reserved for
   scope/business-rule questions, destructive actions, or after
   `ESCALATE_AFTER_ATTEMPTS` failed rungs.

The Lead never overrides an integrator validation failure or a principal-architect
veto — the andon cord outranks the Lead. During autonomous operation the Lead never
blocks the team on an interactive user prompt; escalation is the channel.

**Idle-notification hygiene.** Heartbeats and harness idle pings are liveness
signals, not events. Act on exactly two things: (a) an artifact arrived — process
it; (b) idle **without** the artifact you are waiting for — Stuck, rung 1 now.
Everything else (routine idle pings, repeated heartbeats, "still working" noise)
gets no reply and no acknowledgment — answering it burns your turns and everyone
else's context.

## Recovery

Relaunched or restarted agents need no session state: read your role brief, query
the tracker for [tasks] assigned to your role in any non-terminal status, read the
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
| Harness-native teammates (subagent spawn + messaging) | harness mode | launch CLI processes via `bin/launch-team.sh` (tmux / background) |
| tmux | launcher niceness | background processes + pid files |
| Long-running loop | team-lead, principal-architect, integrator | relaunch on a schedule; recovery makes restarts free |

A missing capability degrades **explicitly** — state what you could not do; never
silently skip a protocol step.
