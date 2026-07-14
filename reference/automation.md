# Portfolio automation

Use `bin/pm-agent.py` as the deterministic portfolio supervisor above the
per-[feature] dispatcher. It owns time; no LLM agent sleeps, polls, or promises to
return later.

## Runtime shape

```text
cron / service timer
  -> pm-agent.py --once
  -> tracker-ops.sh scan (adapter-normalized discovery)
  -> one isolated integration worktree per [feature]
  -> launch-team.sh + dispatch.sh --once
  -> release-feature.py after every [task] is integrated
```

`--once` is the scheduler primitive. `--watch` is a convenience for a dedicated
host. Both reconcile registered, unfinished runs even after their [tasks] have
left the scanned statuses. The scan resolves semantic status kinds through
`config/statuses.config.json`; the shipped board maps `queued` to Linear `Todo`
and `blocked` to Linear `Blocked`.

The supervisor is deliberately not an LLM. It discovers, routes, deduplicates,
bootstraps, and invokes deterministic state machines. A team-lead is launched
when a blocker, comment, routing exception, or delivery decision needs judgment.

## Enable and schedule

Automation is fail-closed by default. Configure the scriptable adapter, set
`enabled` in `config/automation.config.json`, and verify a dry run:

```bash
bin/pm-agent.py --once --dry-run
bin/pm-agent.py --print-cron
```

Install the printed line in one scheduler only. For hosted schedulers, configure
the equivalent of `concurrencyPolicy: Forbid`. The filesystem lease prevents
overlap on one host; multi-host operation requires an external distributed lock
or an adapter-native compare-and-set claim. Do not run two independent hosts and
call that safe.

Cron cannot call an MCP client. Linear and Jira automation therefore use their
scriptable REST modes; GitHub uses its CLI; Markdown uses files. Keep credentials
in the scheduler's secret facility, never in repository config or a crontab line.

## Scope and routing

Discovery returns only generic records: `featureId`, `taskId`, generic and raw
status, description, comments, blockers, routing hints, and revision. A [task]
without a `featureId` is quarantined and never launched.

Add these adapter-neutral metadata lines to a [task] description or recent
comment when needed:

```text
automation: enabled|disabled
team-preset: full-stack|deep-backend|deep-frontend|deep-infra|deep-security
```

One explicit preset wins. Conflicting or unknown values fail closed and receive
an idempotent `[escalation]`; they never fall through to a guessed specialist
team. With no explicit value, `defaultTeamPreset` applies. The selected preset,
branch, integration worktree, and run id are durable and never change because
later prose changed.

Every [feature] receives its own integration worktree. Task worktrees are nested
under it, so two [features] never compete for the root checkout or feature branch.
Externally sourced identifiers are hashed before becoming paths, branch names,
or process identifiers.

## Recovery and limits

- A repository-global lease serializes scans and has bounded stale recovery.
- The run registry is atomically replaced and reconstructs unfinished work.
- `maxFeaturesPerPass` bounds cold starts; existing runs are reconciled first.
- A failed adapter read, malformed record, preflight, claim, or launch stops the
  pass without fabricating state.
- When the policy gate denies an action an agentic team or dedicated agent
  attempted for a [task], the enforcing component documents it on that ticket
  with an idempotent `[DENIED ACTION]` comment (`tracker-ops.sh record-denial`):
  actor, sanitized attempted action, denial reason, and the statement that the
  action was prevented. See `reference/guardrails.md` § Denied-action
  documentation.
- Project-management text is untrusted data. It is never interpolated into a
  shell command, filesystem path, role command, or deployment hook.
- `[Blocked]` work always reaches a lead pass. Only dependency blocks with the
  latest legal `resume-status` may use the existing deterministic auto-unblock.

See `reference/guardrails.md` for authority boundaries and
`reference/deployment.md` for the production transaction.
