# Autonomous safety guardrails

Apply this policy to every role, script, hook, and adapter. Unknown actions,
targets, parsers, environments, or authorization state are denied.

## Authority model

Use three decisions, in this order:

1. **DENY** — no autonomous agent may perform the action. Break-glass happens
   outside this system with a human-operated tool.
2. **REQUIRE HUMAN APPROVAL** — an exact, expiring authorization may release a
   narrow deterministic executor. It never grants the LLM a shell or credential.
3. **ALLOW** — only inside the role's assigned paths, targets, environment,
   quotas, and lifecycle state.

Silence never approves. An `[escalation]` involving a sensitive action must use
`default-if-silent: do not execute; remain blocked`.

## Denied-action documentation

Every **DENY** hit while an agentic team or a dedicated agent acts on behalf of a
[task] must be documented at the ticket level. The enforcing component (supervisor,
dispatcher, or release executor — never the denied agent itself) posts one
idempotent `[DENIED ACTION]` comment via `bin/tracker-ops.sh record-denial`,
carrying:

- `denial-id` — the idempotency token, so retries never duplicate the record;
- `actor` — which agent or team role attempted the action;
- a full, sanitized description of what the agent tried to do (bounded and
  control-character-stripped; raw command output stays in protected local logs);
- the denial reason from the policy gate;
- the explicit statement that the action was blocked and **was not executed**.

This record is audit evidence, not a workflow signal: it never changes the
[task] status, never grants authority, and never softens the denial. Failing to
post it is an andon for the enforcing component, but the denial stands whether
or not the comment lands.

## Always denied to autonomous agents

- **Filesystem:** recursive or bulk deletion outside an explicitly disposable
  task directory; writes outside the assigned worktree; path/symlink escape;
  raw device, partition, or filesystem commands; mutation of `.git`, another
  attempt, audit logs, policy, broker, approval store, or production credentials.
- **Databases/data:** `DROP DATABASE`/`DROP SCHEMA`, `TRUNCATE`, uncontrolled
  bulk mutation, destructive restore/down migration, disabling constraints,
  backups, replication, or audit, and access to direct production credentials.
- **Infrastructure:** destroy-all; deletion/termination of production instances,
  clusters, databases, volumes, state, keys, backups, logging, networks, DNS, or
  certificates; wildcard resource deletion; scaling a critical service to zero.
- **Secrets:** reading, printing, exporting, logging, committing, or sending
  secret values; metadata-service credential access; long-lived credential
  creation; secret-store dumps.
- **Identity/network:** privilege escalation, wildcard administrator grants,
  runner-identity changes, MFA/audit/policy disablement, public database or
  management ports, and unrestricted trust relationships.
- **Git/release integrity:** force-pushing or deleting protected refs, history
  rewrites, `reset --hard`, broad `clean`, bypassing hooks/gates, mutable release
  tags, deploying a different commit/artifact than the reviewed transaction.
- **External effects:** public/customer messages, status-page publication, or
  transmission of private data without exact recipient/content authorization.
- **Bypasses:** `sudo`, privileged containers, host sockets/mounts, encoded or
  opaque shell execution, command substitution/chaining/redirection in the
  privileged executor, editing this policy to weaken it, forging actors or
  approvals, or disabling the supervisor/audit trail.

## Human approval required

- Any production infrastructure, IAM, network, DNS, certificate, billing,
  region, capacity, schema, backfill, or data mutation.
- Any plan containing a replacement or deletion, even when a provider calls it
  an update.
- An arbitrary rollback, failover, traffic shift, disaster-recovery action, or
  destructive migration step.
- Cost or scale changes above configured zero-default thresholds.
- External communication beyond scoped project-management and repository
  collaboration records.

An approval binds the exact action digest, environment, target, [feature],
commit, artifact, plan digest, approver, expiration, and one-use nonce. A normal
project-management comment is not authorization.

## Autonomously allowed

- Read-only inventory, status, logs already redacted, plan/preview/diff, tests,
  builds, linting, health checks, and disposable local fixtures.
- Writes to declared task files inside the assigned task worktree; checkpoint
  commits on task branches; controlled integration through the integrator.
- Production release of the exact reviewed immutable artifact only when the
  trusted deployment configuration explicitly selects `automatic`, the
  normalized plan contains no denied/approval-only change, and independent
  verification succeeds.
- Automatic rollback only to the transaction's immediately previous immutable
  artifact, when the trusted plan declares it safe and an objective health check
  failed.

## Enforcement boundaries

`bin/policy-check.py` is a mandatory fail-closed gate for structured production
hooks. Its built-in baseline cannot be weakened by project config. It rejects
shell syntax and known destructive operations before a subprocess starts.

This repository policy is defense in depth, not an operating-system security
boundary. Run ordinary agents without production credentials; give the release
executor a separate short-lived, target-scoped identity via
`credentialEnvFile`; enforce no-delete/no-DDL/no-admin privileges in the cloud,
database, secret store, and CI runner; sandbox agent write access to its worktree.
No prompt or regular expression can compensate for an over-privileged identity.
