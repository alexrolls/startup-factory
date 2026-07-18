# Portfolio automation

Use the protected, externally installed `bin/pm-agent.py` as the deterministic portfolio supervisor above the
per-[feature] dispatcher. It owns time; no LLM agent sleeps, polls, or promises to
return later.

## Runtime shape

```text
cron / service timer
  -> protected external pm-agent.py --once
  -> tracker-ops.sh scan (adapter-normalized discovery)
  -> one isolated integration worktree per [feature]
  -> task-hold.py sync + launch-team.sh gate-team + dispatch.sh --once
  -> release-feature.py after every [task] is integrated
```

`--once` is the scheduler primitive. `--watch` is a convenience for a dedicated
host. The `scan` call is discovery-only and requests `observeStatusKinds`, which
must be exactly the semantic `queued` and `blocked` kinds; the shipped board maps
those task kinds to Linear `ToDo`/`Blocked`. `launchStatusKinds` is separately
fixed to `queued`, so observation never becomes authority to start Blocked work.
Before grouping or routing, the supervisor excludes every task
whose labels case-insensitively match `ignoredTaskLabels` (shipped value:
`human-work`). Discovery never becomes durable authority for a registered run.
Before every reconcile, the supervisor performs an
exhaustive `export <featureId>` and re-authorizes that run from its full current
[task] set. An unreadable/empty export, lost opt-in, explicit disablement,
conflicting routing metadata, or preset drift pauses the run. A durable registry
entry is never standing authority.

The supervisor is deliberately not an LLM. It discovers, routes, deduplicates,
bootstraps, and invokes deterministic state machines. A team-lead is launched
when a hold, comment, routing exception, dependency-impact review, resume review,
or delivery decision needs judgment.

## Enable and schedule

Automation is fail-closed by default. Install the reviewed skill outside the
target checkout and every agent mount; the supervisor, Python interpreter,
automation/team/project-management configs, runner, and broker scripts must be
owned by the scheduler identity or root and not group/world writable. Keep the
shipped `TEAM_MODE=true` setting, configure the scriptable adapter, copy
`config/automation.config.json` to that protected installation, set `enabled`,
and verify a dry run from the target checkout:

```bash
STARTUP_FACTORY_PROJECT_ROOT=/absolute/target-checkout \
STARTUP_FACTORY_AUTOMATION_CONFIG=/protected/config/automation.json \
  /protected/python/bin/python3 -I -S -E -s \
  /protected/startup-factory/bin/pm-agent.py --once --dry-run

STARTUP_FACTORY_PROJECT_ROOT=/absolute/target-checkout \
STARTUP_FACTORY_AUTOMATION_CONFIG=/protected/config/automation.json \
  /protected/python/bin/python3 -I -S -E -s \
  /protected/startup-factory/bin/pm-agent.py --print-cron
```

The supervisor refuses autonomous execution when its own `pm-agent.py`, Python,
automation config, team config, or project-management config resolves inside the
target repository. `STARTUP_FACTORY_PROJECT_ROOT` is mandatory and is resolved
using filesystem operations before any config-selected tool executes. The
automation config is rejected if it is inside that project; only then is Git
resolved and used to verify the exact checkout root. `trustedPath` in the
protected automation config must contain only absolute, external,
scheduler/root-owned, non-writable directories. A root-owned OS alias such as
usrmerge `/bin` is resolved to its canonical target and the complete target
chain is revalidated; user-owned or writable symlinks are rejected. The
portable template `/usr/bin:/bin` therefore works on both usrmerge Linux and
platforms whose bash remains only under `/bin`.

`requireAgentSandbox` and `requireSingleTrackerWriter` are mandatory invariants;
setting either to false or omitting it is a configuration error. The supervisor
also requires `TRACKER_WRITERS=broker`, a non-no-op `WORKTREE_SETUP`, at least one
non-no-op `VALIDATE_*` command, `AGENT_SANDBOX_ENFORCED=true`, and a valid
`AGENT_SANDBOX_RUNNER`. The runner must be an absolute protected executable
outside the repository, owned by the executor or root, non-symlink, regular,
executable, and not group/world-writable. The launcher routes every LLM command
and `WORKTREE_SETUP` through `runner --workdir <absolute> -- /usr/bin/env -i ...`;
the runner supplies the actual OS/container/network isolation.

Autonomous preflight also requires an absolute, pre-created mode-0700
`BROKER_LIFECYCLE_ROOT` (or scheduler-provided
`STARTUP_FACTORY_LIFECYCLE_STATE_ROOT`) disjoint from both the target checkout and
the installed skill. Every path component must be broker/root-owned,
non-symlink, and not group/world-writable; consequently a root below shared
`/tmp` is intentionally refused. Keep this root outside every agent sandbox
mount. Only the deterministic broker may access its HMAC key and authenticated
PID/start-identity/tmux records. The emitted cron command pins the canonical root
so child launch/dispatch processes use the same authority store.

Install the printed line in one scheduler only. For hosted schedulers, configure
the equivalent of `concurrencyPolicy: Forbid`. The filesystem lease prevents
overlap on one host; multi-host operation requires an external distributed lock
or an adapter-native compare-and-set claim. Do not run two independent hosts and
call that safe.

`scanIntervalMinutes` controls how often the board is scanned. It must be an
integer from 1 through 1440 and defaults to `3` when omitted, so the standard
configuration checks ToDo/queued and Blocked work every three minutes. Existing
external configs that specify only `pollSeconds` remain supported for migration;
setting both fields is rejected as ambiguous.

`observeStatusKinds`, `launchStatusKinds`, and `blockedTaskPolicy` intentionally
have no permissive variants. Autonomous delivery requires observation of exactly
`queued` plus `blocked`, launches exactly `queued`, and enforces a task-scoped,
human-exit, no-automatic-resume hold that continues independent work, refreshes
all communication, propagates only lead-confirmed direct dependencies, and uses
a fresh attempt on resume. Undifferentiated observation/launch configuration is
rejected because seeing a status is not authority to launch it.

The printed crontab line intentionally contains no credentials and cannot copy
the interactive shell environment into cron. Provision tracker and deployment
variables through the scheduler's secret facility, a service unit, or a
root/scheduler-owned wrapper that loads secrets and then `exec`s the printed
isolated Python command. Never paste tokens into a crontab. The emitted command
fixes the protected `PATH` and starts Python with `-I -S -E -s`; preserve those
flags in a wrapper.

`--print-cron` emits only stable conventional cron cadences: a whole-minute
interval below one hour must divide 60, and a whole-hour interval must divide
24 (with 24 hours rendered as a daily schedule). It rejects intervals such as
seven minutes because `*/7` resets at each hour and does not preserve a stable
seven-minute cadence. Use a service timer or hosted scheduler for other valid
polling intervals.

Cron cannot call an MCP client. Linear and Jira automation therefore use their
scriptable REST modes; GitHub uses its CLI; Markdown uses files. Keep credentials
in the scheduler's secret facility, never in repository config or a crontab line.
Remote adapter HTTP/CLI calls use a 60-second deadline by default; an operator
may set the non-secret `TRACKER_OPERATION_TIMEOUT_SECONDS` from 1 to 300, while
the supervisor's outer `operationTimeoutSeconds` remains the hard process-group
deadline.
Remote scans also require an explicit scope and fail closed if it cannot be resolved:
`LINEAR_DEFAULT_TEAM`, exact `JIRA_PROJECT_KEY` plus `JIRA_TASK_ISSUE_TYPE`, or
`GITHUB_REPO` respectively. Jira resolves the configured project before every
scan/export, includes the configured child issue type in JQL, and rejects any
returned issue whose project or type does not match; an Epic can therefore never
be normalized as an actionable child ticket.
Those are shipped adapter examples, not core dependencies. A custom
project-management tool must provide the same deterministic, exhaustive
`scan`/`export`, idempotent-write, and read-back contract in `tracker-ops.sh` and
an explicit automation scope; the supervisor consumes only normalized records.

If production delivery is enabled, point the scheduler at the protected external
deployment config with `STARTUP_FACTORY_DEPLOYMENT_CONFIG` **and** set
`STARTUP_FACTORY_RELEASE_FEATURE` to the absolute `release-feature.py` in the
protected external skill installation. The supervisor refuses an enabled config
with a repository-local executor. Before launching it, the supervisor
descriptor-verifies and snapshots the exact pinned external helper set plus
deployment config beneath the private external `stateRoot`, then supplies only
the configured positive environment allowlists. A disabled or absent external
deployment config launches no executor. That external installation's pinned
`team.config.md` and `project-management.config.md` must describe the target
project's canonical teamwork root and adapter. Never copy production trust pins,
target state, or credential paths into an agent-editable branch.

## Scope and routing

Discovery returns only generic records: `featureId`, `taskId`, generic and raw
status, description, comments, blockers, routing hints, and revision. A [task]
without a `featureId` is quarantined and never launched.

`ignoredTaskLabels` is an adapter-neutral, case-insensitive list of exact label
names. It defaults to `["human-work"]`. New matching tasks and orphans are
excluded without tracker mutation or escalation. In a mixed [feature], only the matching
tasks are removed from autonomous routing and dispatch; non-matching siblings
continue normally. If every task in a registered run becomes human-owned, the
run pauses out of autonomous scope. Removing the label restores normal
status-specific handling on the next exhaustive scan. If the label appears on
an in-flight task, reconciliation stops its authenticated managed workers and
fences publication, integration, progress projection, and release; independent
tasks continue. An escaped process may survive outside lifecycle authority, but
its output remains unauthorized.

Put initial adapter-neutral metadata in a [task] description:

```text
automation: enabled|disabled
team-preset: full-stack|deep-backend|deep-frontend|deep-infra|deep-security|deep-llm
```

Descriptions are baseline metadata because a tracker record's general
`updatedAt` does not prove when its description changed. Put every later opt-in,
disablement, or preset change in a comment carrying the adapter's sortable
`createdAt`/`updatedAt`/numeric revision (Markdown uses its exported offset).
The latest comparable comment wins over the baseline. Missing ordering,
same-revision conflicts, unknown automation values, and conflicting latest
values fail closed and receive an idempotent `[escalation]`; they never fall
through to a guessed specialist team. With `requireMetadataOptIn: true`, only
the latest `automation: enabled` value launches. The shipped project policy sets
it to `false`, so non-ignored work is eligible unless the latest metadata
explicitly says `automation: disabled`. With no explicit preset,
`defaultTeamPreset` applies. The selected preset,
branch, integration worktree, and run id are durable. If the latest preset changes,
the existing run pauses rather than being rerouted in place.

The same routing check runs over an exhaustive authoritative feature export for
every registered unfinished [feature] on every pass. Progressing from discovery
into working/review status does not pause a run. An unreadable or empty export,
losing the required opt-in, receiving `automation: disabled`, conflicting on
latest routing metadata, or changing the preset records a durable pause. Paused
or out-of-scope runs cannot dispatch, integrate, or enter the release executor.
A later exhaustive export can resume only the same registered route after its
original preset and all eligibility conditions match again.

## Blocked lifecycle and continuous portfolio progress

`[Blocked]` is a task-scoped human lock, not a global stop condition. As soon as
a dispatch or portfolio reconcile observes it, `task-hold.py` records a durable
hold and full communication snapshot. If the [task] is in flight,
`launch-team.sh stop-task` stops worker processes whose protected lifecycle
identity matches that [task], and the broker revokes only that [task]'s active
publication capabilities. Gate roles,
the PM loop, sibling workers, independent queued [tasks], and other [features]
continue. A held [task] is rejected by the outbox and integration brokers even
if a stale process survives outside managed lifecycle authority.

The supervisor never writes an outbound `[Blocked]` transition. This applies to
the PM supervisor, dispatcher, team-lead, deterministic tracker port, and
artifact brokers, without exception. Only a human may change that state in the
project-management tool. In broker mode no LLM has tracker credentials; for
end-to-end enforcement, configure the tool's workflow permissions so outbound
Blocked transitions are available only to human principals and denied to every
automation identity. Normalized exports do not authenticate the transition
actor. If the tool cannot enforce this ACL or provide verified transition
provenance, keep autonomous portfolio automation disabled for that tool.

### Dependency propagation

- A queued [task] with an unfinished non-Blocked dependency remains naturally
  unclaimable. Do not infer a clearance for it.
- Independent queued [tasks] remain claimable, including siblings of a held
  [task]. A blocked-only discovered [feature] does not consume the new-feature
  launch budget.
- For a queued, `[Active]`, or `[Review]` [task], consider only direct
  adapter-normalized `blockedBy` edges whose source is currently `[Blocked]`.
  Project-management prose, labels, titles, comments, and similarity never
  establish dependencies.
- The supervisor writes a local review request and routes the team-lead. The
  lead publishes:

  ```text
  [dependency-hold]
  blocked-by: <sorted direct taskIds>
  graph-digest: <sha256 binding current task status/revision/edges/sources>
  verdict: blocked|partially-actionable|independent
  reason: <why implementation can or cannot continue>

  — team-lead
  ```

  Only `blocked`, authenticated by the local published broker receipt and still
  matching a fresh exhaustive graph, permits the deterministic broker to enter
  `[Blocked]`. `partially-actionable` and `independent` persist an exact
  graph-bound clearance that lets a queued dependent be claimed or an in-flight
  dependent keep running.
  A stale graph or missing receipt is no authority and triggers another review.

### Human resume barrier

A human move of a held [task] from `[Blocked]` to the configured queued status
does not resurrect the old worker. It moves the local hold to
`resume-review-pending`. The
supervisor preserves the blocked snapshot, writes a new resume snapshot, and
diffs title, description, every comment by stable id/body/author/time/revision
(including additions, edits, and deletions), and adapter-provided normalized
attachment metadata.
The lead must read both snapshots in full and publish:

```text
[resume-review]
hold-id: <exact hold id>
communication-digest: <digest of current non-resolution communication>
verdict: unchanged|requirements-changed|needs-human
summary: <changes, open questions, and design impact>

— team-lead
```

The broker accepts this control marker only with a local published receipt that
binds the exact body, task, feature, role, and verified launched-role
capability. A raw project-management comment with the same marker or claimed
signature cannot impersonate the protocol. Resolution markers themselves are
excluded from the communication digest, so publishing a verdict does not create
a self-invalidating snapshot.

`unchanged` may clear the barrier. `requirements-changed` requires a later
broker-authenticated `[resume-plan]`, followed by later `[design-approved]` and
`[sceptical-design-approved]` markers with no newer pushback from either
architect. `needs-human` remains held. In every
case the previous attempt worktree must be clean; dirty work stays preserved
until explicitly salvaged or quarantined and is never silently deleted. Once
clear, the old claim is archived and the dispatcher starts attempt N+1 with a
fresh packet containing the hold and both snapshot paths.

A human move from `[Blocked]` directly to a working/review status is treated as
manual takeover: the local hold remains closed to automation. Moving it to the
queued status later starts the normal resume barrier.

### Integration and release

Hold state is rechecked against a fresh tracker export at publication and
integration boundaries. A held [task] cannot publish ordinary artifacts,
authorize or finalize integration, or be counted as finished. Consequently its
parent [feature] cannot enter production until the human-resume path completes
and every [task] is integrated. This is feature-local backpressure: independent
[features] continue through integration and release.

A deployed feature ID is not a permanent tombstone. If a later portfolio scan
finds new or reopened queued work under that feature, the supervisor
first uses the active tracker adapter to reopen the terminal [feature] to the
configured nonterminal queue/working status, with exact readback. It then creates
a new numbered generation with a new run ID, team ID, feature branch, and team
evidence directory. The stable repository worktree path is rotated only from the
exact previously verified feature HEAD; the old generation's evidence directory
is retained unchanged and named as the new generation's predecessor. This keeps
new task work and receipts generation-local without discarding the protected
release evidence needed to revalidate unchanged older terminal tasks. A preset
change is refused rather than silently breaking or rerouting that evidence chain.

Every [feature] receives its own integration worktree. Task worktrees are nested
under it, so two [features] never compete for the root checkout or feature branch.
Externally sourced identifiers are hashed before becoming paths, branch names,
or process identifiers.
At first registration the supervisor stores the full immutable `baseCommit`.
It refuses a pre-positioned feature branch, requires later feature commits to
descend from that base, and requires the configured base ref still to contain it.
Immediately before release it captures the canonical Git common/worktree
directories plus their device/inode identities. The protected executor validates
those identities, binds all later Git reads directly to those directories, and
rechecks them and feature HEAD at the apply boundary; swapping a worktree `.git`
pointer cannot redirect production source provenance.

## Recovery and limits

- A repository-global lease serializes scans and has bounded stale recovery.
- Every child command has the configured `operationTimeoutSeconds` deadline;
  timeout sends bounded TERM→KILL to its launcher-managed process group before
  the pass reports failure. A child that deliberately escapes with `setsid`, a
  double-fork, or an external supervisor requires the mandatory OS sandbox,
  cgroup/container, or service-job boundary for complete descendant containment.
- Production handoffs run as identity-bound detached jobs under the protected
  lifecycle root. A pass waits only for a short fast-completion window, then
  releases the scan lease; later passes poll the same job and never start a
  duplicate. Loss of tracker/run authority writes a protected cancellation
  request which makes the worker terminate its exact release process group.
  The release child waits behind an inherited launch barrier until its PID,
  dedicated session, and process group are authenticated in protected lifecycle
  state. A stale protected heartbeat causes the next pass to cancel that exact
  group, even if the detached worker died. If the supervisor stops after launch
  but before saving its run registry, the next pass reconstructs the one
  deterministic job from protected state instead of launching a duplicate.
  Only cancellation before the inherited launch barrier opens is recorded as a
  safe cancellation. Once release may have started, authority loss or worker
  liveness loss records an uncertain completed attempt and blocks deployment
  until protected provider-state reconciliation proves the outcome.
- The detached worker enforces the separate `releaseTimeoutSeconds` deadline so
  provider apply/verify hooks may use longer bounded timeouts without blocking
  board scans. It must exceed the entire configured
  plan/three-CI-verifications/attestation/status/apply/verify/rollback path.
  Startup refuses an enabled deployment when the outer deadline is shorter
  than that conservative sum; the shipped default is 7200 seconds.
- The run registry is atomically replaced and reconstructs unfinished work.
- `maxFeaturesPerPass` bounds cold starts; existing eligible runs are reconciled first.
- A failed adapter read, malformed record, preflight, claim, or launch stops the
  pass without fabricating state and emits a sanitized, idempotent tracker escalation
  when a task target is available; raw command output remains in protected local logs.
- A normalized production-plan denial is projected by the release executor as
  an idempotent `[DENIED ACTION]` comment. Other supervisor/launcher/broker
  preflight refusals stop before mutation and remain in protected runtime logs;
  see `reference/guardrails.md` for the exact coverage boundary.
- Project-management text is untrusted data. It is never interpolated into a
  shell command, filesystem path, role command, or deployment hook.
- Most marker names and claimed authors are routing/gate evidence, not
  authenticated security identities. Hold-control markers are narrower: they
  require matching local published broker receipts, but still grant no
  production authority. Automatic production additionally requires the
  external delivery attestation described in `reference/deployment.md`.
- `[Blocked]` work always reaches task-scoped hold processing. No dependency
  state, comment, marker, or role can move it outbound; only a human can return
  it to the queued resume barrier.

See `reference/guardrails.md` for authority boundaries and
`reference/deployment.md` for the production transaction.
