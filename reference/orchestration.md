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
   `git diff --name-only <feature-branch>...HEAD` (run from inside the [task]'s worktree).
   Any mismatch → `[andon]`.
2. Stage by explicit file list (never `add -A`), verify the staged set matches.
3. Run `VALIDATE_BUILD`, `VALIDATE_TEST`, `VALIDATE_LINT` (skip `null` ones, record
   skips). Any failure → `[andon]`, task back to `[Active]`.
4. Merge the task branch into the feature branch; remove the worktree.
5. Commit, capture the hash, then immediately move the [task] to `[Completed]`,
   citing the hash. Commit and completion are one atomic pair — never one without
   the other.
6. When every [task] is `[Completed]`, tell the team-lead and principal-architect; the [feature] moves to
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
