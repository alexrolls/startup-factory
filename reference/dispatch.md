# Dispatch — the loop lives outside the agent

Both production runs proved the same thing: the tracker+marker state model
survives any restart, but an agent's promise to "check back in N minutes"
does not — one-shot runtimes exit, and the gate stalls. So no agent owns
time. **Dispatch is a stateless read-and-act pass** executed by machinery:

| Runtime | Loop owner | One pass = |
|---|---|---|
| CLI (tmux / background processes) | `bin/dispatch.sh <team> <featureId> --once` (or `--watch`) | fresh tracker export → establish/act on task holds → finalize integrations/process artifact outbox → refresh export/projection → claim/launch task instances and gate roles |
| Harness (in-session subagents) | the team-lead orchestrator itself — its native event loop | same table, executed directly: subagent spawn = role launch, idle notifications = heartbeats; use `compose-task` for one implementation [task] and `compose-review` for one exact-package verdict |

An unscoped pass is deliberately feature-wide. Inspect
`dispatch.sh <team> <featureId> --once --dry-run` before the first mutating pass
for a new run. When the operator named one [task], use
`--once --dry-run --task <taskId>`: the planner retains the complete feature
dependency/concurrency evidence but emits actions only for that [task]. Targeted
dispatch is read-only; execute the approved task with `launch-team.sh
start-task` (or `compose-task` in a harness). This makes scope widening visible
before any status write, outbox processing, integration, or launch.

`--watch` needs a persistent shell (tmux window or `nohup`) — **the human
owns that process**, explicitly. Hiding this ownership is how a pipeline
silently stalls for hours.

## What an idle pass costs

The [feature] export dominates a pass. On a [feature] with hundreds of [tasks]
it is hundreds of tracker requests, so a watch loop at the default cadence can
exhaust an hourly hosted-tracker budget without any work having changed — which
is how an affordable-looking mechanism becomes unusable and operators fall back
to invisible manual dispatch.

A pass therefore asks the adapter for a **change token**
(`tracker-ops.sh change-token <featureId>`) and reuses the cached export when
the token has not moved.

A pass reads the board **twice** — once before planning and once after the
brokers run, to close the observation race their writes create. Both reads go
through the same rule, which matters: gating only the first would leave every
idle cycle paying full price for the second, and halve the cost rather than
remove it. Anything a broker publishes is itself a tracker write, so it moves
the token and the second read exports for real.

The contract on that token is the important part:

- It must move whenever anything the export reads moves. An adapter that cannot
  promise this must not implement `change_token` at all; absence degrades to a
  full export every pass, never to a false "nothing moved".
- Reuse is bounded by `EXPORT_MAX_REUSE_SECONDS` (default 900). A full export
  runs once that elapses regardless of the token, so a token that misses an edit
  delays an export rather than cancelling one.
- The token is recorded only after a successful export, so a failed export
  cannot leave a token claiming the cached snapshot is current.

Shipped support: Markdown (exact, a digest of the single board file) and Linear
(a high-water mark over the project, its most recently updated issue including
archived ones, and its most recently updated comment). Jira and GitHub Issues
export every pass.

## Seeing a stalled board

Every role reaching `exited` is the normal end of a pass, so per-role health
cannot distinguish a board that finished cleanly from one nobody is driving.
`launch-team.sh health` adds one board-level line per team:

```
factory-one: STALLED — 2 queued tasks, 4 undrained artifacts, last pass 31m ago
```

`STALLED` means outstanding work, no live agent, and no dispatch pass in the
last 15 minutes. `IDLE` is the same without the elapsed-time evidence,
`WORKING` has live agents, and `DRAINED` is the quiet, healthy end of a run.
Each completed non-dry pass records its time in `dispatch.last-pass`, which is
the evidence the verdict rests on. All of it is presentation only.

## The event table

One pass reads the [feature]'s task export, the team mailboxes, and the
heartbeat files, then acts top to bottom:

| State observed | Action |
|---|---|
| Any [task] matching `ignoredTaskLabels` (default `human-work`) | Make no claim/launch/progress write; if it is in flight, stop its managed worker and fence publication, integration, and release. Independent work continues. |
| Any `[Blocked]` [task] | Record/refresh its durable hold, stop only its matching workers, and revoke only its publication capabilities. Never move it outbound. |
| Human moved a held [task] to the queued status | Snapshot and diff all communication, route the authenticated `[resume-review]` barrier to the team-lead, and launch no worker until it clears. |
| Queued/`[Active]`/`[Review]` [task] directly `blockedBy` a currently `[Blocked]` [task] | Route a graph-digest-bound dependency-impact review to the team-lead; enter `[Blocked]` only after an authenticated `blocked` verdict survives fresh graph validation. A partial/independent verdict gives only that exact graph a scheduling clearance. |
| `[design-note]` with no later `[design-approved]`/`[design-pushback]` | Launch principal-architect with the **whole** pending-design queue |
| `[design-note]` with no later `[sceptical-design-approved]`/`[sceptical-design-pushback]` | Launch sceptical-architect with the **whole** independent-design queue |
| [Task](s) in `[Review]` missing `[team-lead-approval]`, `[architecture-approval]`, or `[sceptical-architecture-approval]` since the last `[review-request]` | Launch Team Lead / Principal Architect / Sceptical Principal Architect with their **whole** core-review queues |
| [Task](s) in `[Review]` with effective `review-gates: qa` or `review-gates: security` but no current mapped supporting approval | Launch the preset's QA or Security role with its whole queue; hold Team Lead review until every declared supporting gate is current |
| [Task](s) in `[Review]` holding all three core approvals and every declared supporting approval, with Team Lead newer than supporting gates | Launch integrator with the merge queue in dependency order |
| Dispatchable `[Planned]` [tasks] (including review rework; not held, both design approvals current, every blocker terminal or carrying a fresh partial/independent clearance for its current Blocked graph, slot/resource-safe) | Atomically claim and launch one fresh task instance per ready-wave member |
| Valid `product-acceptance-request.json` after all integrations | Launch the configured product-manager role with the exact feature-level acceptance request; use team-lead only when no product role is mapped |
| `[Planned]` task missing metadata/gate, resource conflict, stale/artifact-less-idle teammate | Launch team-lead with the whole exception queue |
| Nothing actionable | Exit cleanly, print "nothing actionable" |

## Rules

- **Dedup:** gate roles are deduplicated by role; workers by
  `<role>/<taskId>/<attempt>`. Two independent backend tasks may run at once,
  while the same task attempt never double-launches. An atomic dispatch lock
  prevents overlapping passes from racing the claim.
- **Queue message before boot:** the pass writes the queue into the role's
  mailbox (`mailbox/<role>/NNN-dispatcher.md`) *before* launching, so the
  role boots as a queue consumer (drain every item, post per-[task] markers,
  exit).
- **Task packet before boot:** a worker launch creates its task branch and
  provisioned worktree, performs a fresh exhaustive tracker export, then creates
  the immutable task packet, report path, execution record, and task-scoped pid
  before starting the model. The packet carries every normalized tracker comment
  in oldest-first order plus its count and digest; the worker must read and
  acknowledge them before changing code. This applies to every queued pickup,
  including rework and human Blocked → queued resumes. The task prompt does not
  inline the full orchestration reference.
- **Adapter-neutral claim recovery:** before asking the tracker to claim a task,
  dispatch writes a digest-bound durable claim record containing the exact
  team/feature/task/attempt/role/status identity. On later passes the planner
  cross-checks that record, the immutable execution record, and the exact tracker
  claim receipt. This lets remote adapters that cannot persist a role in the
  assignee field safely recover an active task; missing, ambiguous, or tampered
  evidence fails closed rather than launching a guessed worker.
- **End of turn = exit.** Role briefs contain no self-scheduling. An agent
  that finished its queue delivers its artifacts and exits; the next pass
  owns what happens next.
- **Launch only consumers with work.** `gate-team` is the normal feature-level
  bootstrap; dispatch starts task workers and wakes gate consumers only for a
  concrete queue. The eager `team` command is an explicit operator choice, not
  the default response to a one-task request.
- **Blocked is a task-scoped human lock:** observation stops only the protected
  task workers and revokes only their broker capabilities. It does not stop the
  team, PM loop, gate roles, sibling [tasks], or other [features]. No dispatch
  option enables automatic outbound movement; only a human may change
  `[Blocked]` in the project-management tool. Enforce that promise with an
  external workflow ACL restricting outbound moves to human principals; adapter
  state alone cannot prove who made the move.
- **Dependency propagation is just in time:** independent queued work continues.
  A queued dependency on unfinished non-Blocked work remains unclaimable. For
  every queued or in-flight direct dependent of a currently Blocked task, only
  a first-class
  adapter-normalized `blockedBy` edge and a broker-authenticated team-lead
  `[dependency-hold]` verdict bound to the freshly revalidated graph can cause
  the deterministic broker to enter `[Blocked]` or clear that exact dependency
  for claim/continuation. Prose is never a dependency.
- **Human resume is a new attempt:** only a human `[Blocked]` → queued move opens
  the resume barrier. The team-lead compares complete blocked/current snapshots
  and publishes a receipt-backed `[resume-review]`. Changed requirements also
  need a later `[resume-plan]` and both architect design approvals; a dirty prior worktree
  remains held. A cleared barrier archives the old claim and launches a fresh
  attempt. Human movement directly to working/review is manual takeover.
- **Policy stays where it was:** the pipelined dispatch rules (independence,
  sweep gate, freeze protocol — `reference/orchestration.md` → *Execution
  modes*) are decisions the **team-lead** makes during its pass. The
  dispatcher is the trigger mechanism that makes "the moment [task] N enters
  `[Review]`" actually fire; it never overrides lead policy.
- **Event wakeup with polling fallback:** every runtime/outbox/projection event
  appends to `events.ndjson`. `--watch` wakes within about one second when the
  count changes and otherwise falls back to `POLL_INTERVAL_SECONDS`. Events are
  hints only; every pass re-reads the tracker as truth.
- **PM projection:** every non-dry pass idempotently upserts one `[progress]`
  artifact per task and one `[digest]` per feature. No agent is trusted to keep
  the human view current manually.
- **Preset rosters:** the script resolves nine status-owning protocol lanes,
  any optional specialists, and explicitly mapped specialist dispatch lanes
  such as Deep LLM's `track: llm` → `PROTOCOL_LLM`. An unmapped specialist
  track safely falls back to `backend`. The three core review mappings must
  resolve to distinct rostered roles, and the on-demand Security mapping must be
  distinct from them; launch fails closed otherwise.
- **Long features (harness):** past ~20 [tasks] the orchestrator should
  compress processed-event state between turns (its context is the loop
  state); the tracker remains the source of truth for anything dropped.

## Board-wide clock owner

`dispatch.sh` remains one-[feature]-at-a-time. Cron and service timers invoke
`bin/pm-agent.py --once`, whose adapter-normalized `scan` discovers semantic
`queued`/`blocked` [tasks] for observation but launches only `queued` work. For
every registered in-flight [feature], it performs
an exhaustive per-feature export before restoring authority, then creates one
isolated integration worktree per [feature] and invokes this dispatcher. See
`reference/automation.md`. The PM supervisor is deterministic and zero-LLM when
nothing is actionable.
