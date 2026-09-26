# Autonomous safety guardrails

Every component must honor this policy, but enforcement is layered: agent sandboxes
constrain ordinary roles, tracker/integration brokers constrain workflow writes, and the
release policy gate constrains digest-pinned production hooks. Unknown actions, targets,
parsers, environments, or authorization state are denied.

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

The release executor automatically documents a **DENY** from the normalized
production-plan gate at `[task]` level. It posts one idempotent `[DENIED ACTION]`
comment via `bin/tracker-ops.sh record-denial`, carrying:

- `denial-id` — the idempotency token, so retries never duplicate the record;
- `actor` — which agent or team role attempted the action;
- a full, sanitized description of what the agent tried to do (bounded and
  control-character-stripped; raw command output stays in protected local logs);
- the denial reason from the policy gate;
- the explicit statement that the action was blocked and **was not executed**.

This record is audit evidence, not a workflow signal: it never changes the
[task] status, never grants authority, and never softens the denial. Failing to
post it is an andon for the enforcing component, but the denial stands whether
or not the comment lands. Generic launcher, sandbox, path, actor, and broker
preflight refusals occur before a safe authenticated `[task]` projection is always
available; they stay in protected runtime logs unless an owning deterministic
component explicitly records them. Do not claim blanket tracker coverage.

## Always denied to autonomous agents

- **Filesystem:** recursive or bulk deletion outside an explicitly disposable
  task directory; writes outside the assigned worktree; path/symlink escape;
  raw device, partition, or filesystem commands; mutation of `.git`, another
  attempt, audit logs, policy, broker, approval store, or production credentials.
- **Databases/data:** `DROP DATABASE`/`DROP SCHEMA`, `TRUNCATE`, uncontrolled
  table/object drops, bulk mutation, destructive restore/down migration, disabling constraints,
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
  tags, deploying a different commit/artifact than the reviewed transaction, or
  deploying any environment while required CI is red, pending, skipped,
  missing, stale, or unverifiable.
- **External effects:** public/customer messages, status-page publication, or
  transmission of private data without exact recipient/content authorization.
- **Bypasses:** `sudo`, privileged containers, host sockets/mounts, encoded or
  opaque shell execution, command substitution/chaining/redirection in the
  privileged executor, editing this policy to weaken it, forging actors or
  approvals, or disabling the supervisor/audit trail.

`DELETE`, `REPLACE`, destructive migrations/data effects, resource termination, and
arbitrary rollback are break-glass actions outside Startup Factory. A human approval
cannot turn an always-denied action into an allowed agent action.

## Human approval required

- Any production infrastructure, IAM, network, DNS, certificate, billing,
  region, capacity, schema, backfill, or data mutation.
- A non-destructive failover or traffic shift with a predeclared bounded target and
  recovery path. Arbitrary rollback and destructive disaster-recovery steps remain denied.
- Cost or scale changes above configured zero-default thresholds.
- External communication beyond scoped project-management and repository
  collaboration records.

An approval binds the exact action digest, hook argv/executable digests, environment,
target, [feature], commit, artifact, plan digest, approver, expiration, and one-use nonce.
A normal project-management comment is not authorization.

## Autonomously allowed

- Read-only inventory, status, logs already redacted, plan/preview/diff, tests,
  builds, linting, health checks, and disposable local fixtures.
- Writes to declared task files inside the assigned task worktree; checkpoint
  commits on task branches; controlled integration through the integrator.
- Production release of the exact reviewed immutable artifact only when the
  trusted deployment configuration explicitly selects `automatic`, the
  normalized plan contains no denied/approval-only change, a protected external
  `verifyCi` hook proves every required check for the exact commit is green,
  and a protected external
  `verifyDelivery` attestor proves OS role isolation, protected planning
  isolation, and approval authenticity
  for the exact feature commit, `integrationEvidenceDigest`, and
  `productAcceptanceDigest`, and independent production verification succeeds.
- Automatic rollback only to the transaction's immediately previous immutable
  artifact, when the trusted plan declares it safe and an objective health check
  failed.

## Enforcement boundaries

Pre-integration launch and workspace handling are also fail closed:

- Fresh task packets pass tracker titles, descriptions, every comment body and
  author, and derived string metadata through `bin/ticket_content_security.py`
  before an implementation agent starts. The scanner uses only bounded,
  precompiled Python standard-library `re` patterns plus `unicodedata` and
  `hashlib`: potential credentials are redacted, dangerous control characters
  are exposed, and prompt/tool injection, credential access/exfiltration,
  executable code, SQL/shell injection, active content, and encoded payloads are
  labeled. Oversized individual fields or aggregate packet content fail closed
  before agent launch instead of causing context/memory exhaustion. Descriptions and comments are always line-delimited as
  `TICKET-DATA`, including when no known pattern matches; suspicious lines also
  receive `SECURITY INJECTION — NOT ALLOWED TO EXECUTE`.
- A pattern scan is not proof that content is safe. No tracker-provided SQL,
  shell, source code, URL, template, or tool instruction may be copied into an
  execution sink. Agents reconstruct the required operation from trusted
  repository code and policy. Application database code must use the database
  driver's parameterized-query API; labeling or escaping a ticket payload is
  not a SQL-injection defense at the database boundary. Tool calls remain
  independently allowlisted and validated against task intent.
- Every agent-authored tracker write supported by `bin/tracker-ops.sh` passes
  through that same scanner immediately before the selected backend is called.
  Potential API keys, passwords, tokens, private keys, and other recognized
  credentials are replaced with `[REDACTED POTENTIAL SECRET]` in comments and
  managed progress, digest, deployment, denial, and integration text. Unsafe
  structural values such as assignee roles and idempotency identifiers fail
  closed because silently rewriting them would alter routing or retry semantics.
  Adapter implementations, including project-owned adapters, receive only the
  protected value. The warning and error paths never echo the detected secret.
  SQL, shell, file-deletion, and other dangerous examples remain inert ticket
  data: posting them is not execution and does not bypass the independent tool
  and release-policy gates described above.
- `TEAMWORK_ROOT` must be repository-relative, cannot contain `..`, and every
  managed child path is resolved before a read, directory creation, or write.
  Absolute roots and every existing symlink component are rejected, including a
  link from one in-repository team workspace to another. This is defense in
  depth; the OS sandbox must still prevent races and writes outside the assigned
  worktree.
- LLM processes start under `env -i`. Only names in `AGENT_ENV_ALLOWLIST`, fixed
  `STARTUP_FACTORY_*` role metadata, and
  `AWS_EC2_METADATA_DISABLED=true` are passed through. Never add a secret,
  production credential, deploy token, SSH agent socket, or privileged runtime
  endpoint to that allowlist. Known cloud/release variables are refused by the
  launcher; tracker credentials are also refused in `broker`/`lead` mode. The
  shipped default omits `HOME` so ambient credential stores are not exposed. If a
  model CLI requires `HOME`, point it at a dedicated, minimally populated sandbox
  home before explicitly adding the name to the allowlist.
  `env -i` does not block network traffic or filesystem reads by itself. The
  required OS/container/CI sandbox and identity policy must deny metadata-service
  routes, host sockets, undeclared egress, and paths outside the assigned mount.
  Only an enforced launch through a validated external sandbox runner receives
  the non-secret, generation-bound publication-socket locator and canonical
  routing context. Manual/unenforced children may remain lifecycle-supervised,
  but receive no authenticated publication transport.
- Late-invalidation recovery validation uses a second, narrower `env -i`
  boundary after a revert is prepared. Its positive list is exactly `PATH`,
  `TMPDIR`, `LANG`, `LC_ALL`, `TERM`, and `NO_COLOR`; all other configured names
  fail closed. The helper itself starts through absolute `/usr/bin/python3 -I -B`
  under a fixed environment, and changed Git paths cross as bounded NUL records.
  In unenforced mode this is credential scrubbing, not an OS sandbox. Enforced
  mode requires a canonical external runner whose file and complete ancestor
  chain are root-owned, non-writable by the executor/group/world, and rechecked
  immediately before launch. Commands have bounded time/output and process-group
  cleanup. Validation failure aborts the pending revert.
- The deterministic outbox broker pins one canonical, identity-checked Python
  3.10+ interpreter selected only from approved standard host toolchain roots;
  unauthenticated environment overrides are ignored. Every authority-bearing launch uses its
  absolute path with `-I -B` under a fixed `env -i` environment. Its
  nested tracker/review shell tools receive that same absolute interpreter
  directly through `STARTUP_FACTORY_PINNED_PYTHON`; they execute it with `-I -B`
  rather than creating a replaceable temporary `PATH` shim. Other executable
  lookup uses only root-owned, non-group/world-writable canonical directories
  from the validated `trustedPath`, with Python and shell startup-hook variables
  removed.
  Ambient `python3`, `gh`, `PYTHONPATH`, user `sitecustomize`, and startup hooks
  therefore cannot execute while lifecycle keys or protected publication
  receipts are accessible; a missing trusted interpreter fails closed. The
  broker requires `BROKER_LIFECYCLE_ROOT`, validates its complete path chain,
  and accepts `STARTUP_FACTORY_LIFECYCLE_STATE_ROOT` only when it repeats that
  configured canonical root. Tracker adapter subprocesses retain adapter
  credentials but receive neither lifecycle/HMAC authority nor caller-selected
  adapter or ignored-label policy; those policy values come only from installed
  configuration.
- Authority-bearing launcher `PATH` validation likewise retains only
  root-owned canonical directory chains with no group/world write bit. A
  caller-owned directory is rejected even at mode `0700`, because its owner can
  replace a command after validation. Intentionally untrusted model CLI
  commands may use an absolute executable or dedicated wrapper; they still run
  behind the credential-free agent environment and configured sandbox and do
  not turn their parent directory into launcher authority. Individually pinned
  Python runtimes use a narrower file-identity capture and recheck contract;
  production should prefer a root-managed runtime or separate service identity.
- The release executor uses three additional positive environment allowlists:
  non-secret planning/attestation/approval variables, minimum tracker-broker
  variables, and the non-secret release-hook base. Credential-file names require
  a fourth explicit credential-name allowlist; they are never inherited by
  planning or agent processes. It also supplies fixed operational values: a
  `PATH` fallback, canonical `TRACKER_PROJECT_ROOT`, and
  `STARTUP_FACTORY_RELEASE_EXECUTOR=1`; none carries a secret.

`bin/policy-check.py` is a mandatory fail-closed gate for structured, externally
installed production hooks. Its built-in baseline cannot be weakened by project config.
It rejects shell syntax and known destructive operations before a subprocess starts.
The release executor also requires external protected config/state, exact file
and hook digests, an OS lock, canonical plan effects, exact-commit green CI
proof, and structured status/verification evidence.
Privileged hooks are dedicated pinned executables—generic interpreters are
rejected—and cannot receive the agent repository path or run from it.
The source-consuming `plan` wrapper is also dedicated and pinned, but it must
cross a stronger OS boundary: a separate identity/container/VM/remote CI
workload with the credential file and protected state unmounted and no production
egress. The protected `planningIsolation` config is mandatory in both modes;
automatic delivery additionally requires its external attestor to confirm the
same provider. The apply wrapper receives the exact earliest authorization
expiry and must enforce it with a trusted provider-side clock immediately before
mutation.

Tracker markers, names in tracker signatures, and comments are workflow routing
evidence, not authenticated security principals. They cannot grant gate or
production authority. Automatic production requires the external delivery
attestation; approval-required production requires the external exact-manifest
verifier. Task-mode outbox writes remain bound to the canonical execution
record. Protocol gate markers additionally require a valid HMAC capability for
the exact launcher-created role instance; the broker derives the effective actor
from its protected verifier record, never from producer JSON or tracker text.
Capabilities bind the canonical repository/workspace, team, feature, role,
execution kind, process generation, and expiry. The worker receives no raw key:
it gets only a non-secret locator for a launcher-owned supervisor that verifies
native stable peer identity and bounded ancestry before signing. Task lanes are
stable by task id across attempts and roles; gate lanes are stable by concrete
role. A newer launch therefore supersedes the old generation. A tracker
signature alone never satisfies that boundary.

Signing and durable exact-package admission occur atomically under the broker
authority lock. Mint, revoke, protected hold mutation, and the final tracker
effect use that same lock, giving stop/hold/effect one fail-closed order. A
supervisor exact-revokes itself on exit without deleting a successor pointer.
Only an entry/body pair admitted before that fence may be recovered afterward;
stale generations cannot admit a new or modified package.

The worker-authored envelope is a closed immutable schema whose `phase` remains
`pending`; unknown fields and changes to its body path, target, or phase are
rejected. Broker progression (`brokerPhase`) and the exact staged/final bytes
live only in owner-only Git-common broker storage outside the agent-writable
workspace. The broker secure-opens and re-hashes those exact bytes immediately
before a serialized tracker effect. A workspace copy of a completed receipt is
audit data only and cannot be replayed as a new producer package.

Verifier records live below the Git common directory, outside linked task
worktrees, with owner-only modes. That placement and file mode are defense in
depth, not same-UID isolation: the required OS/container sandbox must make the
broker capability directory unreadable and unwritable to every agent process
while allowing only the deterministic launcher/broker to access it. The only
worker-side transport exception is `connect` to its exact lifecycle-root socket;
the sandbox must deny directory listing and every read/write/create/rename/
unlink operation on lifecycle state and transport parents. It must also
prevent an agent from inspecting another process's environment or command line.
If this separation is unavailable, gate-marker authentication is not safe; do
not run autonomous gate publication.

Repository code and prompts are defense in depth, not an operating-system security
boundary. In broker mode no LLM—including the team lead or integrator—receives tracker
credentials. Run every agent in a worktree-scoped sandbox that cannot access protected
broker/release files or undeclared network targets. Give the release executor a separate
short-lived, target-scoped identity via `credentialEnvFile` that is not shared
with ordinary agents; enforce no-delete/no-DDL/
no-admin privileges in the cloud, database, secret store, and CI runner. No prompt,
sandbox configuration flag, or regular expression can compensate for an
over-privileged runner or identity.
Enforce protected branches, no force-push, required review, and trusted CI in the
git host. `trustedBaseRef` verifies integration-chain provenance but is not a
substitute for those operator-owned controls.

Process lifecycle authority follows the same boundary. The deterministic launcher
stores authenticated PID, process start identity, launch token, and (when used) tmux
pane identity below the external mode-0700 `BROKER_LIFECYCLE_ROOT`. Every parent path
is ownership/mode checked and symlinks are refused. Agent sandboxes must be unable to
read or write that root. `.teamwork/<team>/pids` contains logs and non-authoritative
markers only: its contents are never passed to `kill`, `kill -0`, or tmux. A missing,
modified, unauthenticated, or process-identity-mismatched protected record fails closed
without signalling. If protected lifecycle state is not configured, manual launches
remain unmanaged and `stop` deliberately refuses to signal processes.
`stop <team>` is a point-in-time operation: its exclusive protected team fence
waits for launches and control operations already holding the shared fence,
then snapshots, revokes, and stops those generations before reporting success.
A new launch that acquires the shared fence after stop may run; `stop` is not a
persistent administrative shutdown or cancellation of queued future launches.
Roster preflight and doctor run before the shared fence and can therefore
finish after a concurrent stop, then launch as a later operation.
Detached production release admission uses the same shared team fence through
its authenticated guardian registration and launch decision. If any protected
release lifecycle record exists, generic `stop <team>` refuses before revoking
or signalling anything; use the release supervisor's authenticated
cancel/reconciliation path and confirm its durable terminal result first.
An authenticated stop sends bounded TERM→KILL to the launcher-managed process
group/session, but ordinary process groups cannot contain a descendant that
deliberately calls `setsid`, double-forks, or delegates to an external
supervisor. The required OS sandbox/cgroup/container/service job must provide
the complete descendant boundary; task holds and broker checks independently
reject output from stale escaped processes.
