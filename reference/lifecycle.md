# Lifecycle — Scenarios & Playbooks

How work is created, tracked, and closed out. Every scenario is written in the generic
vocabulary (`reference/vocabulary.md`); the active adapter (`adapters/<Tool>.md`) supplies
the concrete verb for each operation. The shipped skill enables **team mode by default**:
transition *ownership* splits across roles per `reference/team-roles.md`, while the
scenarios themselves remain identical. Set `TEAM_MODE=false` explicitly when one agent
should drive the whole flow.

Throughout: **an "operation"** (create feature, set status, add comment…) means "do the
thing described in the active adapter's *Operations* section." Never invent an operation
the adapter doesn't define.

---

## Scenario 1 — Plan a [feature]

Turn an idea into a tracked feature with a task breakdown.

Before step 1, select the configured planning intake. If
`USE_SUPERPOWERS=true` and the current runtime is Claude Code, follow
`reference/superpowers-planning.md`: use Superpowers for brainstorming and
writing the committed specification/plan, then create the Startup Factory
planning handoff. Treat those documents as reviewed inputs to the steps below,
not as authority to launch Superpowers execution. If the flag is false or the
runtime is not Claude Code, begin directly with the native workflow.

1. **Understand the goal.** Clarify scope with the user: what ships, what's explicitly out,
   and any dependencies. Research the codebase enough to size the work realistically.
2. **Create the [feature]** via the adapter, status `[Planned]`. Record its `featureId`.
   The description should state **Purpose**, **NOT included** (out of scope), and
   **Dependencies**.
3. **Break it into [tasks].** Each [task] must be a *complete vertical slice* — something
   that can be implemented, reviewed, and completed on its own. Prefer 3–8 tasks over one
   giant task or twenty trivial ones.
4. **Create each [task]** via the adapter, status `[Planned]`, linked to the `featureId`.
   Put implementation checkpoints as `[subtasks]` (checklist bullets) in the description.
   In team mode add scheduler metadata on separate lines:
   `track: backend|frontend|qa`, `parallel-safe: true|false`, `files: <comma-list>`,
   `resources: <contracts/migrations/shared-state>`, and optional
   `model-profile: fast|standard|strong`. Unknown or unsafe tasks serialize.
5. **Confirm** the created `featureId` and `taskId`s back to the user.

> A "PRD-style" wizard (interactive requirements gathering before step 2) is a good fit
> here but optional. The tracked output is the same: one `[feature]` + N `[tasks]`.

---

## Scenario 2 — Start a [task]

1. **Read the [task]** in full via the adapter — description, `[subtasks]`, every
   comment in oldest-first order (including ordinary comments, not only
   structured markers), and the linked `[feature]`. Do this on every pickup from
   `[Planned]`/ToDo before changing code; prior attempts do not satisfy the read.
2. **Verify the status is the board's initial status** (`[Planned]` on the default
   board). If it isn't and `STRICT_STATUS=true`, pull the **andon cord** (Scenario 8).
   Don't start work on something already `[Active]` elsewhere.
3. **Move the [task] to `[Active]`** via the adapter *before* writing any code.
4. If this is the feature's first `[Active]` task, the [feature] moves `[Planned]` →
   `[Active]` (do this only if the adapter tracks feature status explicitly).
5. **Team mode only (`TEAM_MODE=true`): pass the design gate.** Post a `[design-note]`
   comment (approach, contract/data-model changes, affected components) and exit;
   the dispatcher/harness relaunches you when both architects' design approvals
   arrive — see `reference/orchestration.md`. Single-agent mode
   skips this step.
6. The dispatcher claims the task and launches a fresh task instance with an
   immutable packet, task branch, attempt worktree, and report path. Immediately
   before worker boot, the packet's fresh exhaustive tracker export captures the
   complete normalized comment history, count, and digest. The worker reads every
   entry and acknowledges that count/digest in its report before changing code.
   Implement only from that packet, keeping `[subtasks]` as the checklist.

---

## Scenario 3 — Diverge from a [task]

Reality rarely matches the plan. When you must deviate from what the [task] describes:

1. **Add a comment** on the [task] (via the adapter) explaining *what* changed and *why*.
2. If the divergence affects **other** [tasks] in the [feature], note it on those too, or
   flag it to the user — don't let a silent change strand later tasks.
3. Keep working. The comment is the audit trail. **Never edit the original [task]
   description** — reviewers need the original ask. If the change is permanent and
   affects upcoming [tasks], the description of *not-yet-started* [tasks] is updated
   by the principal-architect in team mode, or by you with the user's confirmation
   in single-agent mode.

---

## Scenario 4 — Request review

1. Before requesting review, leave the task worktree clean with checkpoint
   commits on the task branch. Write the task report and evidence records.
2. Submit `[review-request]` through `bin/submit-artifact.sh`; the durable outbox
   posts the comment and moves the [task] to `[Review]` idempotently.
3. Single-agent: you now switch hats and review, or hand to the user. Team mode:
   route the exact package to the Team Lead, Principal Architect, Sceptical
   Principal Architect, and Senior Security Engineer.

If review finds problems: **move the [task] back to `[Planned]`** (mapped to
`ToDo`) and let the dispatcher create a fresh implementation attempt. That
attempt proceeds through `[Active]`/`In Progress` and returns with a new request
to `[Review]`/`In Review`. Backward moves are legal exactly where
`config/statuses.config.json` lists them. `[Blocked]` exits are listed so a
human project-management action can be represented, but Startup Factory itself
is forbidden to author them.

---

## Scenario 5 — Finalize a [task]

Only after all four mandatory reviewers approve the exact package and the work
is verified (tests/build green, change actually does what the [task] asked):

1. Confirm the [task] is in `[Review]`. If not, andon cord.
2. The terminal status carries `requiresCommit: true`. The integrator runs
   `bin/integrate-task.sh`, which validates the task branch, merges and validates
   the feature branch, commits, and records an exact broker request. In default
   `TRACKER_WRITERS=broker` mode, the deterministic dispatcher verifies that request,
   updates the tracker, removes the worktree last, and closes the transaction.
3. If **all** [tasks] in the [feature] have reached the terminal status, leave the
   [feature] visibly non-terminal and awaiting deployment. This is also the
   behavior when production delivery is disabled or no external deployment
   configuration is installed; the disabled executor creates no `[deployment]`
   projection, while the PM registry records local awaiting state. Only Scenario 12's release executor may move the
   [feature] to `[Resolved]`, and only after independent production verification.

`[Ready to deploy]` means: reviewed, verified, committed—awaiting a disabled,
externally approved, or automatic release path. Disabled means visibly waiting,
not implicitly delivered.
**Never** move work there that was skipped, partially done, or has failing tests — see
the fail-loud invariant.

---

## Scenario 6 — File newly-discovered work

When implementation surfaces work that isn't in any existing [task] (a bug, a missing
edge case, a follow-up):

1. **Create a new [task]** in the current [feature], status `[Planned]`, describing the
   discovered work. Don't silently fold unrelated scope into the current [task].
2. Route it through the normal lifecycle. Small, in-scope fixes can be folded into the
   current [task] with a divergence comment (Scenario 3); anything larger gets its own
   [task] so it stays visible in the tool.

---

## Scenario 7 — Block a [task]

When the *work* cannot proceed — missing dependency, unanswered question, broken
external service — and it isn't a process failure (that's the andon cord, Scenario 8):

1. **Report the block** with enough context for a human and the lead:
   ```
   block-kind: dependency|approval|policy|incident
   reason: <what is blocking, what was tried, what would unblock>
   ```
   This prose explains the situation but grants no workflow authority. For a
   dependency, record the edge through the adapter's first-class `blockedBy`
   mechanism; never infer one from this comment, a title, or similarity.
2. **Ask the team-lead to enter `[Blocked]`.** On the shipped board only the
   authenticated team-lead or deterministic PM supervisor may author an inbound
   Blocked transition. Do not continue while waiting for the status write.
3. **On observation, fence only this [task].** The dispatcher records a durable
   hold and full communication snapshot, stops only matching task workers, and
   revokes only their publication capabilities. It does not stop the PM loop,
   gate roles, sibling [tasks], or other [features]. Independent queued work
   continues.
4. **Do not move the [task] out of `[Blocked]`.** Only a human may perform that
   action in the project-management tool. No agent, role, broker, supervisor,
   dependency completion, or comment may do it automatically. Enforce this with
   a project-management workflow ACL that denies outbound Blocked transitions
   to automation identities; normalized adapter state cannot prove the actor.
5. A human move to the configured queued status starts the resume barrier. The
   lead reads complete blocked/current snapshots and their comment/attachment
   diff, then publishes a broker-authenticated `[resume-review]` bound to the
   exact hold and communication digest. If requirements changed, publish a later
   `[resume-plan]` and obtain a later `[design-approved]`. The prior worktree must
   be clean. Only then does the dispatcher archive the old claim and launch a
   fresh attempt.
6. A human move directly to `[Active]` or `[Review]` means manual takeover. The
   automated hold remains closed; no old or new worker is launched.

---

## Scenario 8 — Andon cord (stop-the-line)

Named after the Toyota cord any worker can pull to halt the line. Pull it when:

- A [task] is in an unexpected status for the action you're about to take.
- An adapter operation **fails** (MCP error, CLI non-zero exit, file conflict).
- You're blocked, or any warning/error signal appears.

When pulled: **stop the affected action/[task] immediately, do not work around
it, and report** the exact problem to the user (or, in team mode, escalate to the
coordinator (concrete role: `team-lead`, via mailbox)). This is task-scoped by
default: the deterministic PM process and independent work continue unless the
failure invalidates their shared authority or state. Resume the affected work
only once resolved. This directly enforces the *fail-loud* invariant from
`vocabulary.md` — a silent workaround is the failure mode this whole design
exists to prevent.

---

## Scenario 9 — Connect / switch tools

1. Ensure `adapters/<Tool>.md` exists (copy `adapters/_TEMPLATE.md` for a new tool).
   For unattended dispatch, also implement the deterministic backend contract in
   `bin/tracker-ops.sh` (including exhaustive `scan`/`export`, idempotent writes,
   read-backs, and pagination tests); prose alone does not register a backend.
2. Set `PRODUCT_MANAGEMENT_TOOL=<Tool>` in `config/project-management.config.md`.
3. Complete that adapter's *MCP / CLI Setup*, then run its *Initialization* check
   (usually a no-op read that proves auth works).
4. Once both the adapter guide and deterministic backend are registered and their
   contract tests pass, every scenario above targets the new tool.

---

## Scenario 10 — Pre-flight design pass (batch the design gates)

By default the design gate (Scenario 2 step 5) opens per-[task] at claim time.
When the plan should be settled before any code — the user asks for all plans
up front, or the [tasks] share contracts that must not fork — run the gates as
one batch instead:

For preset teams this batch is the **default opener** (`teams/_PLAYBOOK.md`
stage 3); per-[task] gates at claim time are the opt-out for genuinely
emergent plans.

An approved Claude/Superpowers planning handoff may seed these notes, but it
does not replace the cross-[task] consistency pass, independent architectural
challenge, per-[task] verdicts, product scope sign-off, or tracker comments.

1. **One `[design-note]` per [task]**, written against the real codebase (not the
   [task] text alone). Registering exports in the contract registry
   (`reference/orchestration.md` → *Contract registry*, team mode) is part of
   **writing** the note — when notes are produced by parallel planners, the
   registry is the only shared surface between them, so a note that defers
   registration defeats the pass.
2. **Cross-[task] consistency and independent challenge first.** In team mode the
   principal-architect checks the full set and registry while the sceptical-
   architect independently tests assumptions, cross-task risks, and simpler
   alternatives; in single-agent mode, you perform both passes separately. Read
   the **full set before verdicts**, checking sibling notes against each
   other and the registry — contract forks between parallel plans are the
   highest-value findings and are invisible note-by-note. Cross-cutting rulings
   are binding and recorded once, referenced by each affected [task].
   **Gate condition:** no plan is approved while its exports are unregistered or
   a consumed sibling name lacks a registry citation.
3. **Per-[task] verdicts** — both the principal
   `[design-approved]`/`[design-pushback]` and independent
   `[sceptical-design-approved]`/`[sceptical-design-pushback]`, exactly as in the
   normal gate.
4. **Scope sign-off per [task]** where a product owner exists —
   `[product-approval]` / `[product-pushback]`.
5. **Everything lands as comments** on the [tasks], like any gate.
6. At claim time the gate is already open: the implementer re-reads the approved
   note, its conditions, and any cross-cutting rulings, and proceeds — no second
   approval needed unless a `[divergence]` or re-plan invalidated the note
   (under `EXECUTION=parallel` the sweep that flags this runs at `[Review]`
   entry — see `reference/orchestration.md` → *Execution modes*).

The per-[task] gate is unchanged — this scenario only moves *when* it runs.
[Tasks] added later (Scenario 6) go through the normal per-[task] gate.

---

## Scenario 11 — Portfolio automation

Run the adapter-neutral supervisor from one scheduler:

1. Read `reference/automation.md`, `reference/guardrails.md`, and
   `config/automation.config.json`.
2. Configure a scriptable adapter and exact board scope. MCP-only sessions cannot
   be called by cron. Configure the project-management workflow ACL so only
   human principals can move a task out of Blocked.
3. Set the absolute target checkout and protected config environment variables,
   then use protected Python with `-I -S -E -s` to run the external
   `pm-agent.py --once --dry-run`; inspect every route.
4. Set `scanIntervalMinutes` (default `3`), set `enabled: true`, and use that same protected invocation for
   `pm-agent.py --print-cron`, and install its output in
   one scheduler, and configure overlap prevention there too.
5. Each pass observes exactly semantic `queued` and `blocked` status kinds, but
   launches only `queued` work. It re-authorizes every registered unfinished [feature] through a
   separate exhaustive feature export, bootstraps an isolated integration
   worktree, launches only the selected preset's persistent gate/supervision
   roles, then calls the existing per-[feature] dispatcher, which creates fresh
   task-scoped implementers. A Blocked-only [feature] consumes no cold-start
   budget; independent queued [tasks] continue even while other [tasks] are held.
   A task matching `ignoredTaskLabels` is never claimed/launched; if labeled
   mid-flight, it is stopped/fenced on reconciliation.
6. A registered run first synchronizes task holds: Blocked tasks stop only their
   workers and cannot publish/integrate; queued and in-flight direct dependents
   require an authenticated lead verdict plus fresh graph validation. Only a
   true blocker enters Blocked; partial/independent work receives an exact
   graph-bound scheduling clearance. Human Blocked → queued starts the full
   communication-diff and
   resume-review barrier, then a fresh attempt. Startup Factory never moves
   Blocked outbound.
7. A registered run pauses before dispatch or release when its authoritative
   feature export is unreadable/empty, it loses opt-in, is disabled, conflicts
   on routing, or changes preset. Moving from queued/blocked into working/review
   status does not pause it. Unknown/
   conflicting routing, orphaned [tasks], adapter errors, stale claims, or unsafe
   identifiers fail closed and receive an idempotent escalation when appropriate.
   They never become paths or commands.

The PM supervisor is deterministic. A team-lead agent handles the judgment its
snapshot exposes; no agent sleeps or owns a polling loop.

---

## Scenario 12 — Production release

After every [task] is `[Ready to deploy]`, run the provider-neutral transaction
from `reference/deployment.md`:

1. Verify every [task] has exactly one completed integration transaction and
   that all transactions form a gap-free chain from history under the protected
   `trustedBaseRef` to the exact feature HEAD.
2. Require the latest product verdict across the feature's tasks to be a
   feature-scope `[product-approval]` on the portable anchor task, bound to the
   exact feature id, final HEAD, integration-evidence digest,
   and `acceptance-criteria: passed`. Missing, stale, ambiguous, or later-pushed-
   back evidence emits a product-acceptance request and waits before planning.
3. Require a protected `verifyCi` proof that every required CI/CD check for the
   exact final commit succeeded, with no failed, pending, skipped, missing,
   stale, or unverifiable check. Recheck at the apply-process boundary.
4. Generate a normalized plan bound to the exact branch commit and immutable
   artifact digest.
5. Pass the plan and every structured hook argv through `bin/policy-check.py`.
   A denied operation stops permanently; an approval-only operation remains
   blocked until the external exact-manifest verifier authorizes it.
6. Query current release state before apply. After a crash or uncertain response,
   query again; never blindly apply twice.
7. Apply, independently verify production health and version, and record the
   durable transaction. A command exit alone is not success.
8. On objective verification failure, run only a predeclared safe rollback to
   the immediately previous immutable artifact; otherwise escalate and remain
   failed.
9. Upsert the `[deployment]` feature projection. The release executor—and no
   agent role—moves the [feature] to its terminal status only after verification
   succeeds. Disabled delivery remains visibly awaiting deployment, not resolved.

---

## Quick reference — status writes per scenario

| Scenario | Writes |
|---|---|
| 1 Plan | create `[feature]` `[Planned]`; create `[tasks]` `[Planned]` |
| 2 Start | `[task]` → `[Active]` (feature → `[Active]` on first) |
| 3 Diverge | comment only |
| 4 Review | `[task]` → `[Review]` (or back to `[Planned]`/`ToDo` for fresh-attempt rework) |
| 5 Finalize | recoverable merge/broker transaction + `[task]` → `[Ready to deploy]`; feature remains non-terminal awaiting verified production delivery |
| 6 New work | create `[task]` `[Planned]` |
| 7 Block | report + authorized inbound `[task]` → `[Blocked]`; stop only that task; only a human may move it outbound, and queued re-entry requires resume review plus a fresh attempt |
| 8 Andon | **no write** — stop and report |
| 10 Pre-flight design pass | comments only — one `[design-note]` + verdict (+ scope sign-off) per [task] |
| 11 Portfolio automation | board scan + durable run registry + bounded team/dispatcher launches |
| 12 Production release | normalized plan + recoverable apply/verify transaction + `[deployment]`; feature terminal only on verified success |
