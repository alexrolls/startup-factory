# Provider-neutral production delivery

Production delivery is a separate deterministic trust domain. The configured
project-management adapter says what is ready; `bin/release-feature.py` releases
one exact immutable artifact through externally installed hooks. No LLM receives
production credentials, writes release state, or owns the terminal [feature]
transition.

## Trust boundary and preconditions

Deployment is disabled by default. Disabled means **awaiting deployment**, not
`[Resolved]`: the feature remains non-terminal and the PM supervisor records
local `awaiting-deployment`, but the disabled executor returns before creating a
release transaction or tracker `[deployment]` projection. When enabled, the
executor refuses unless all of these hold:

- the caller is on the named feature branch in the canonical
  `<repository>/<TEAMWORK_ROOT>/<team>` workspace; `TEAMWORK_ROOT` is
  repository-relative and no existing component may be a symlink;
- the supervisor-provided Git worktree/common-directory paths and device/inode
  identities match the checkout; the executor then binds Git directly to those
  directories, ignores later `.git` pointer changes, and rechecks directory
  identity plus exact feature HEAD at the apply boundary;
- every [task] is terminal; every task changed or added in the current generation
  has exactly one completed schema-v2 integration transaction revalidated by the
  deterministic finalizer. An unchanged terminal task may instead be inherited
  only from the latest protected, independently verified successful release when
  its task identity, lifecycle fields, implementation/review markers, integration
  receipt, manifest, and release snapshot still match exactly;
- no prepared, recovery-pending, or superseded integration occupies the canonical
  transaction slot; late findings before apply are converted to an explicit
  revert/rework cycle, so release fails closed until the replacement transaction
  completes;
- the integration records form one gap-free chain, feature HEAD is the final
  integration commit, and the chain base is an ancestor of the current tip of
  the protected `trustedBaseRef` on every pass;
- the latest product verdict across the feature's tasks is a feature-scope
  `[product-approval]` on the portable anchor (the
  lexicographically smallest task id), unambiguous, and bound to the exact
  feature id, anchor task id, final HEAD, and `integrationEvidenceDigest`, with
  `acceptance-criteria: passed`; any later pushback invalidates it;
- the tracked index/worktree is clean (untracked bytes and ignored submodule
  dirt are not release inputs), and the requested branch resolves to a full
  immutable commit; archive inspection separately rejects every gitlink;
- the external config and private state root pass path/type/owner/permission
  checks; the config digest is transaction-bound; and configured hook
  executables plus all sixteen trusted Startup Factory files match their protected pins;
- the exact commit is exported with credential-free Git into the protected release
  directory, gitlinks/submodules, unsafe archive members, and Git LFS pointers are
  rejected, and `plan` runs only inside that read-only materialization. Untracked
  worktree bytes and the live repository are never planning inputs.

`trustedBaseRef` is a provenance anchor, not branch protection. The operator must
separately enforce protected-branch review, no force-push, and trusted CI in the
git host. Cloud IAM, database permissions, secret-store policy, and runner
isolation are likewise operator controls; the repository config cannot create
those boundaries.

The enabled deployment config and `stateRoot` must be absolute paths outside the
agent repository and agent mounts. The config must be an executor/root-owned,
non-symlink regular file that is not group/world writable. `stateRoot` must be an
executor/root-owned, non-symlink directory with mode 0700. Hooks must be absolute,
non-symlink executables outside the repository, executor/root-owned, not
group/world writable, and pinned in `trustedHookDigests`.

This is a security boundary only when the release executor runs from a protected
CI/service installation that ordinary agent sandboxes cannot read or write. The
executor identity must be short-lived, target-scoped, and unable to delete
resources, run DDL, administer identities, or bypass audit. Repository prompts,
marker signatures, and `AGENT_SANDBOX_ENFORCED=true` are declarations and defense
in depth—not OS isolation.

Choose one mode:

- `approval-required`: a protected external `verifyApproval` hook must return an
  exact, expiring, one-use approval proof. A tracker comment is never approval.
- `automatic`: the normalized plan must be reversible, non-destructive, and free
  of approval-only effects, **and** a protected external `verifyDelivery` hook
  must attest real OS role isolation, the configured separate-identity planning
  sandbox, and approval authenticity for the exact
  integrated commit, integration evidence, and product-acceptance digest.
  Without that attestor, automatic production is refused.

For an approval-gated fixed destination, copy
`config/deployment.production.approval-required.example.json` and
`config/pm-agent.production.env.example` to protected external locations. The
deployment config—not ticket text—selects `environment: production` and the
exact `target.id`; optional target fields such as provider, region, and service
become `{target_<key>}` hook arguments. Keep the example disabled until every
placeholder, pin, hook, sandbox declaration, credential allowlist, and protected
path is real. Once enabled, all terminal/approved task work triggers the release
handoff; a valid `verifyApproval` proof lets apply/status/verify continue without
another agent action. The [feature] reaches its terminal state only after that
verification succeeds.

The product marker is a mandatory workflow gate in both modes, but it is still
tracker evidence rather than a security principal. The release executor writes
`<TEAMWORK_ROOT>/<team>/product-acceptance-request.json` when it is missing or
stale and exits retryably before planning/apply. The dispatcher routes that
request to the configured product-manager role (falling back to the team-lead
only when no product role is mapped). These fields are exact:

```text
[product-approval]
scope: feature
feature-id: <exact feature id>
anchor-task-id: <lexicographically smallest task id>
commit: <40-hex final feature HEAD>
integration-evidence-digest: sha256:<64 hex>
acceptance-criteria: passed
summary: <feature-level acceptance evidence and conditions>

— product-manager (team-lead only when no product role exists)
```

Missing fields, stale bindings, a later `[product-pushback]`, or ambiguous or
non-comparable revision timestamps remain `awaiting-product-approval`.
The request file is untrusted routing transport: the dispatcher validates its
canonical body against a fresh feature export, and the release executor always
re-evaluates the resulting tracker marker before granting any later phase.
The local outbox broker accepts this envelope only from a launched instance with
a valid capability for the configured product role (or its explicit
no-product-role fallback), but the later tracker-text
evaluator does not authenticate a remote commenter/signature. Product-role
selection is workflow routing, not a security identity. Automatic mode relies
on the external attestor for approval authenticity, while approval-required
mode relies on the external exact-manifest verifier.

## Protected external configuration

Copy `config/deployment.config.json` outside the repository, keep the repository
copy disabled, and point only the scheduler/release service at the external file
with `STARTUP_FACTORY_DEPLOYMENT_CONFIG`. Also set
`STARTUP_FACTORY_RELEASE_FEATURE` to the absolute executor in the protected
external skill installation; enabled delivery rejects a skill installed inside
the target repository. Before starting Python from that installation, the
supervisor reads the config and every pinned helper through stable no-follow
descriptors, verifies owner/mode/digest, and installs the captured bytes under
`stateRoot/supervisor-entrypoints/<config-digest>`. It executes that snapshot
with only the positive planning/tracker/runtime allowlists; ambient scheduler,
cloud, and credential variables are not inherited. A disabled or absent
external config starts no release executor. The pinned external `team.config.md` and
`project-management.config.md` must match the target project's canonical
teamwork root and active adapter/scope. A complete external config has this
shape (replace every example path, target, environment name, and digest before
setting `enabled`):

```json
{
  "schemaVersion": 1,
  "enabled": true,
  "mode": "approval-required",
  "environment": "production",
  "trustedBaseRef": "main",
  "target": {"id": "customer-api-eu"},
  "stateRoot": "/protected/startup-factory-state",
  "trustedPath": "/usr/bin:/bin",
  "gitLfsPolicy": "reject-pointers",
  "maxSourceArchiveBytes": 1073741824,
  "maxSourceBytes": 2147483648,
  "maxSourceFiles": 200000,
  "approvalTtlSeconds": 900,
  "deliveryAttestationTtlSeconds": 900,
  "planningIsolation": {
    "enforced": true,
    "provider": "protected-build-sandbox",
    "separateIdentity": true,
    "credentialPathsUnmounted": true,
    "statePathsUnmounted": true,
    "productionEgress": false
  },
  "credentialEnvFile": "/protected/release.env",
  "credentialEnvironmentAllowlist": ["PROVIDER_DEPLOY_TOKEN"],
  "planningEnvironmentAllowlist": ["PATH", "TMPDIR", "LANG", "LC_ALL"],
  "trackerEnvironmentAllowlist": ["PATH", "TMPDIR", "LANG", "LC_ALL", "TRACKER_ADAPTER", "LINEAR_API_KEY"],
  "environmentAllowlist": ["PATH", "TMPDIR", "LANG", "LC_ALL"],
  "trustedCodeDigests": {
    "release-feature.py": "sha256:<64 lowercase hex>",
    "policy-check.py": "sha256:<64 lowercase hex>",
    "tracker-ops.sh": "sha256:<64 lowercase hex>",
    "finalize-integrations.sh": "sha256:<64 lowercase hex>",
    "task-hold.py": "sha256:<64 lowercase hex>",
    "outbox_capability.py": "sha256:<64 lowercase hex>",
    "broker_evidence.py": "sha256:<64 lowercase hex>",
    "runtime-state.py": "sha256:<64 lowercase hex>",
    "task_metadata.py": "sha256:<64 lowercase hex>",
    "product_acceptance.py": "sha256:<64 lowercase hex>",
    "teamwork-path.py": "sha256:<64 lowercase hex>",
    "review_evidence.py": "sha256:<64 lowercase hex>",
    "statuses.config.json": "sha256:<64 lowercase hex>",
    "guardrails.config.json": "sha256:<64 lowercase hex>",
    "team.config.md": "sha256:<64 lowercase hex>",
    "project-management.config.md": "sha256:<64 lowercase hex>"
  },
  "trustedHookDigests": {
    "plan": "sha256:<64 lowercase hex>",
    "apply": "sha256:<64 lowercase hex>",
    "status": "sha256:<64 lowercase hex>",
    "verify": "sha256:<64 lowercase hex>",
    "rollback": "sha256:<64 lowercase hex>",
    "verifyDelivery": "sha256:<64 lowercase hex>",
    "verifyApproval": "sha256:<64 lowercase hex>"
  },
  "hooks": {
    "plan": ["/protected/hooks/release-plan", "--source", "{source_dir}", "--out", "{plan_file}", "--commit", "{commit}", "--source-digest", "{source_archive_digest}"],
    "apply": ["/protected/hooks/release-apply", "--manifest", "{manifest_file}", "--authority-expires-at", "{authorization_expires_at}"],
    "status": ["/protected/hooks/release-status", "--release", "{release_id}"],
    "verify": ["/protected/hooks/release-verify", "--release", "{release_id}"],
    "rollback": ["/protected/hooks/release-rollback", "--transaction", "{transaction_file}"],
    "verifyDelivery": ["/protected/hooks/verify-delivery", "--feature-digest", "{feature_id_digest}", "--commit", "{commit}", "--source-digest", "{source_archive_digest}", "--evidence", "{integration_evidence_digest}", "--product-acceptance", "{product_acceptance_digest}"],
    "verifyApproval": ["/protected/hooks/verify-approval", "--manifest", "{manifest_file}"]
  },
  "timeoutsSeconds": {
    "plan": 300,
    "apply": 1800,
    "status": 120,
    "verify": 600,
    "rollback": 900,
    "verifyDelivery": 60,
    "verifyApproval": 60
  }
}
```

The sample `trackerEnvironmentAllowlist` happens to show Linear. For Jira,
GitHub Issues, Markdown, or a custom deterministic adapter, replace that entry
with only the exact variables its scriptable backend consumes. The release
executor interprets normalized tracker records, not provider-specific objects.

Only configured hooks need a `trustedHookDigests` entry; `plan`, `apply`,
`status`, and `verify` are required. `verifyApproval` is required in
`approval-required`; `verifyDelivery` is required in `automatic`. The sixteen
`trustedCodeDigests` keys above are exact and all are required whenever delivery
is enabled with a shipped adapter. A custom adapter adds exactly one required
entry, `"tracker-backend.<AdapterName>.py": "sha256:<64 lowercase hex>"`, for
`extensions/tracker-backends/<AdapterName>.py`. Hash the installed reviewed
bytes (for example, `shasum -a 256 <file>`) and store each value with the
`sha256:` prefix. Any code/config update requires operator review and pin
rotation in the protected external config. The PM supervisor and release
executor independently capture the pinned custom backend into their protected
snapshots.

There are four positive environment boundaries:

- `AGENT_ENV_ALLOWLIST` controls ordinary LLM processes (see
  `config/team.config.md`); the launcher starts them with `env -i`, then adds
  fixed `STARTUP_FACTORY_*` role metadata and the non-secret hardening value
  `AWS_EC2_METADATA_DISABLED=true`.
- `planningEnvironmentAllowlist` is used by `plan`, `verifyDelivery`, and
  `verifyApproval`; it must contain no production secret. `HOME` is intentionally
  absent from the shipped template.
- `trackerEnvironmentAllowlist` is used only for deterministic export,
  integration revalidation, projections, and the terminal status write. List only
  the active adapter's minimum credential variables. The executor additionally
  sets `TRACKER_PROJECT_ROOT` to the canonical repository.
- `environmentAllowlist` is the non-secret base for `status`, `apply`, `verify`,
  and `rollback`. The credential file adds only names explicitly listed in
  `credentialEnvironmentAllowlist`, and the executor adds
  `STARTUP_FACTORY_RELEASE_EXECUTOR=1`. Caller `PATH` is never inherited; every
  child receives the protected `trustedPath`. Loader/control variables such as
  `HOME`, `BASH_ENV`, `ENV`, `PYTHONPATH`, `NODE_OPTIONS`, `LD_*`, `DYLD_*`, and
  Git config injection variables are rejected even if listed.
  Every `trustedPath` directory must exist outside the agent repository, be
  executor/root-owned, and have no group/world write bit. Root-owned OS aliases
  such as usrmerge `/bin` are canonicalized and their full target chain is
  revalidated; user-owned or writable symlinks are rejected. Git is resolved
  once to an absolute, regular, non-symlink executable with the same
  ownership/write protections before any repository inspection.

`credentialEnvFile` must be an absolute, executor/root-owned, non-symlink regular
file outside the repository, with no group/other permission bits (0600 or
stricter). Every non-comment line must be `UPPERCASE_NAME=value`, and every name
must appear exactly in `credentialEnvironmentAllowlist`. Secret values are
redacted from hook logs, but least privilege remains mandatory. The executor
validates the parent path, opens the file once with no-follow, checks bounded
size/owner/mode and stable descriptor metadata, and parses only those captured
bytes. Run the release service under an identity ordinary agents do not share;
mode 0600 is not isolation from another process with the same uid.

## Hook argv and execution rules

Hooks are JSON argv arrays, never shell strings. Their first token must be a
dedicated pinned executable; generic interpreters/runtimes such as `sh`, `bash`,
`python`, `node`, `env`, or PowerShell are rejected. A dedicated wrapper may use
an interpreter internally, but its pinned bytes must not source or execute
agent-controlled repository code. No hook may receive the live repository path.
Privileged hooks run with the protected release transaction directory as their
working directory; only `plan` runs in `{source_dir}`, the read-only tree
materialized from `{source_archive}`.

`planningIsolation` is mandatory in both release modes. The pinned `plan`
wrapper must execute its untrusted build/parser workload under the named
separate OS uid, container, VM, or remote CI identity, with
`credentialEnvFile` and `stateRoot` unmounted and production endpoints
unreachable. Environment scrubbing alone does not satisfy this contract. In
automatic mode, `verifyDelivery` independently attests that same configured
planning provider; if the isolation cannot be provided, keep delivery disabled.

Every configured hook executable is captured through one no-follow descriptor
and installed under private `stateRoot/trusted-hooks/<config-digest>` storage
before it starts. Policy evaluates the original configured argv (so a
destructive executable cannot hide behind its snapshot filename), while the
protected snapshot argv is executed. A wrapper must be self-contained and must
not source mutable sidecars.

Tokens may use `{feature_id_digest}`, `{team}`, `{commit}`,
`{environment}`, `{release_id}`, `{plan_file}`, `{manifest_file}`,
`{proof_file}`, `{transaction_file}`, `{attestation_file}`,
`{source_dir}`, `{source_archive}`, `{source_archive_digest}`,
`{integration_evidence_digest}`, `{product_acceptance_digest}`,
`{artifact_digest}`, `{authorization_expires_at}`, `{target_id}`, and
`{target_<key>}` for target fields. `{source_dir}` and `{source_archive}` are
planning inputs only and are rejected from privileged hook argv. Unknown
placeholders fail closed.

Immediately before `plan`, the executor validates its executable against the
protected pin; the output plan is then digest-bound. The manifest records the
deployment-config digest, exact rendered argv/executable digests for configured
privileged/status/verifier hooks, plan digest, feature commit, and
`integrationEvidenceDigest`. It recomputes those post-plan hook bindings before
privileged execution; changing config, those argv/executable bytes, integration
evidence, plan, or manifest after authorization stops the transaction. `plan`
itself is not a manifest hook binding; its argv/pin are covered by the immutable
config digest and its output by `planDigest`.

## Hook contracts

### `plan`

Writes `{plan_file}`. Every effect uses provider-neutral closed enums; native
resource names may appear only as descriptive ids.

```json
{
  "schemaVersion": 1,
  "environment": "production",
  "target": {"id": "customer-api-eu"},
  "commit": "<full 40-character commit>",
  "sourceArchiveDigest": "sha256:<exact protected Git archive digest>",
  "artifactDigest": "sha256:<64 hex>",
  "changes": [{
    "action": "UPDATE",
    "resourceClass": "application",
    "resourceId": "api",
    "destructive": false,
    "reversible": true,
    "publicExposure": false,
    "dataEffect": "none",
    "estimatedCostDelta": 0,
    "secretValueAccess": false,
    "privilegeEscalation": false,
    "disablesSafeguard": false
  }],
  "rollback": {
    "automaticSafe": true,
    "previousArtifactDigest": "sha256:<64 hex>"
  }
}
```

The top-level object, every change, and rollback use the exact fields shown;
unknown or omitted fields are denied so a provider hook cannot smuggle
unmodeled semantics past policy. Allowed actions are `CREATE`, `READ`, and
`UPDATE`. `DELETE`, `REPLACE`, declared destruction, destructive data effects,
secret-value access, wildcard/administrator escalation, safeguard disabling,
and unknown classes/effects are always denied—not human-approvable inside
Startup Factory. Sensitive classes,
non-reversible updates, data mutation, public exposure, and above-threshold cost
require the external approval path and cannot run in automatic mode.

### `verifyDelivery` (required for automatic mode)

This external attestor must authenticate the real execution identities and
isolation controls behind the integration and product-approval evidence. Tracker/comment marker
authors and role-name signatures are workflow routing evidence, not security
authentication. The attestor prints one object bound to the exact inputs:

```json
{
  "schemaVersion": 1,
  "trusted": true,
  "featureIdDigest": "sha256:<digest of exact feature id>",
  "team": "<exact team/branch>",
  "commit": "<full feature HEAD>",
  "sourceArchiveDigest": "sha256:<exact protected Git archive digest>",
  "integrationEvidenceDigest": "sha256:<exact digest>",
  "productAcceptanceDigest": "sha256:<exact product-verdict digest>",
  "roleIsolation": true,
  "planningIsolation": true,
  "approvalAuthenticity": true,
  "isolationProvider": "protected-ci-workload-identity",
  "planningIsolationProvider": "protected-build-sandbox",
  "attestationId": "stable-external-attestation-id",
  "issuedAt": "2026-07-14T12:00:00+00:00",
  "expiresAt": "2026-07-14T12:15:00+00:00"
}
```

The validity interval must be positive, unexpired, and no longer than
`deliveryAttestationTtlSeconds` (60–3600 seconds). Its canonical digest is bound
into the release manifest and protected transaction. The attestor must verify
actual OS/container/CI separation and authenticated approval principals; merely
re-parsing tracker claims does not satisfy this contract. It must also verify
that source planning used the exact protected `planningIsolation.provider`
without release credential/state mounts or production egress.

The attestation must be fresh before first apply. If it expires while the
transaction is still pre-apply, the executor atomically invalidates the derived
plan, manifest, delivery proof, and external approval, obtains a fresh
attestation, and rebuilds those bindings. Once apply authority is consumed, the
recorded proof becomes immutable historical evidence: recovery still verifies
its exact bytes, original validity interval, commit, integration evidence, and
product-acceptance digest, but does not demand that it remain unexpired. This
allows status/verify/rollback recovery without creating new authority or
stranding an in-flight release.

### `verifyApproval` (required for approval-required mode)

Reads `{manifest_file}` and prints one exact proof:

```json
{
  "schemaVersion": 1,
  "approved": true,
  "manifestDigest": "sha256:<canonical manifest digest>",
  "nonce": "<manifest nonce>",
  "approver": {"id": "release-manager@example.com"},
  "approvalId": "stable-external-approval-id",
  "approvedAt": "2026-07-14T12:00:00+00:00",
  "expiresAt": "<exact manifest expiry>"
}
```

The manifest binds environment, complete target, feature/team/commit, artifact,
source archive, plan/config/integration/product-acceptance/attestation digests,
release id, hook bindings,
expiration, and a random 256-bit nonce. Approval is marked consumed before
apply. If a consumed attempt is still `not-applied`, the executor rotates the
nonce and requires a fresh proof; it never replays the old approval.
After the final tracker/evidence fence, the hook launcher reloads and
digest-checks the proof (or automatic delivery attestation) after executable
binding and policy validation. It validates freshness, persists the durable
apply/lease marker, validates freshness again, and then immediately creates the
apply process. If authority expires during those writes, the marker and target
lease are safely released/reset and no apply process starts. Expiry during
planning or revalidation rotates/invalidates every derived authorization instead
of allowing apply.

The apply argv must include `{authorization_expires_at}`, the earliest relevant
manifest/delivery-attestation deadline. The dedicated pinned provider wrapper
must compare it with its trusted clock immediately before provider-side
mutation; this closes the scheduling interval between parent validation and
child execution.

### `status`, `apply`, `verify`, and `rollback`

- `status` prints `state`: `not-applied`, `in-progress`, `applied`, or `failed`.
  `applied` includes the observed `artifactDigest`; `not-applied` should include
  `currentArtifactDigest` when a previous version exists. `in-progress`,
  `applied`, and `failed` must include the exact matching `releaseId`.
- `apply` is idempotent for `{release_id}`, refuses an expired
  `{authorization_expires_at}` provider-side, and deploys only the
  manifest-bound artifact/target.
- `verify` prints `{"healthy": true|false, "artifactDigest": "sha256:..."}`
  and optionally the matching `releaseId`; exit zero alone is not success.
- `rollback` is optional and callable only when the plan's previous digest equals
  the objectively observed pre-apply digest. Afterwards `status` must report that
  exact previous digest or rollback is failed.
- Every hook timeout is a strict positive integer. Hooks start in a dedicated
  process group; a timeout sends bounded `TERM` then `KILL` to that group and
  records only redacted partial output before the transaction reports failure.
  Trusted hooks must not daemonize, create a new session, or hand production
  mutation to an unfenced child; enforce that rule again with the release
  service's OS job/container boundary. Long-running provider work must return a
  durable operation ID that `status` can reconcile.

## Transaction behavior

A per-feature lock and canonical `(environment,target)` OS lock serialize each
pass. A durable target CAS record is claimed before apply/in-progress/applied
recovery, remains owned across cron passes and failures, and is released only
after verified success or verified rollback. A failed owner fences the target
until explicit operator recovery. Durable state lives only under
the protected state root and uses phases `new`, `awaiting-product-approval`,
`awaiting-attestation`, `planned`, `awaiting-approval`, `applying`, `verifying`,
and `rolling-back`, with terminal `succeeded`, `denied`, `failed`, `rolled-back`,
and `superseded` outcomes. When a newer reviewed commit receives a release pass,
an older transaction that is still safely pre-apply and has consumed no product
or external approval is atomically marked `superseded` with the replacement
release id/commit. An older transaction in `applying`, `verifying`, or
`rolling-back`—or one that already consumed authority—blocks the new commit and
requires recovery; two commits never apply concurrently. Plan, manifest, proofs,
transaction, snapshot, and redacted hook logs stay in the release-owned
directory; agent-workspace transaction files are ignored.

Fleet-wide fencing requires every release executor that can reach the same
production target to use the same protected `stateRoot`, byte-identical
canonical `environment` plus complete `target` object, and a filesystem/lock
domain whose `flock` and atomic-rename semantics are reliable across those
hosts. Different state roots or differently spelled target objects are distinct
fence domains and must not share production authority.

If `active.json` is retained for a `failed` owner, there is deliberately no
automatic unlock. Stop all schedulers, reconcile provider state against that
record and its referenced transaction, and preserve both as incident evidence.
Resume the same release only when its exact status can reach verified success or
verified rollback. Clearing a genuinely irrecoverable failed fence is a
break-glass mutation outside Startup Factory: require two-person review, record
the observed target/artifact/release ID, archive `active.json`, remove it, and
only then re-enable one scheduler.

The supervisor first captures the sixteen pinned helper/config files into
`stateRoot/supervisor-entrypoints/<config-digest>` and starts only that protected
entrypoint/config snapshot. The release executor then independently reads and
hashes those snapshot files through open descriptors and copies them beneath
`stateRoot/trusted-code/<config-digest>` before later use. Tracker, policy, and
integration subprocesses execute those protected copies. This two-stage handoff
prevents both a first-instruction race and later pin-check/use races in the
mutable installed skill tree. The enabled executor installation itself must live
outside the target repository and outside every ordinary agent mount.

The current tip of `trustedBaseRef` is resolved and used for the chain-base
ancestry check on every pass. A first generation must start from that protected
history. A later generation may instead start at the exact commit of the latest
protected, verified-success predecessor transaction; its manifest, release
snapshot, and saved integration evidence are revalidated before any task evidence
can be inherited. That moving protected-ref tip is intentionally excluded from
the canonical `integrationEvidenceDigest`; the digest includes the stable ref
name, chain trust, feature HEAD, current transactions, and inherited evidence. A
legitimate protected-base advance therefore does not stale product/release
evidence, while a rewrite, unverifiable predecessor, or changed inherited task
still fails closed.

For enabled delivery, waiting, denial, failure, rollback, and success are
projected to the [feature]. Disabled delivery has no transaction/projection; the
feature simply stays non-terminal and the PM registry records it as awaiting.
Only independently verified `succeeded` lets the **release executor** perform the
configured terminal feature transition. The tracker broker refuses a terminal
feature write without `STARTUP_FACTORY_RELEASE_EXECUTOR=1`; that flag is defense
in depth, while protected tracker credentials and OS separation are the actual
identity boundary. Hooks use the release id as their
provider-side idempotency key; uncertain apply responses are resolved through
`status`, never a blind second apply.

The same rule applies when a detached release worker loses liveness after its
launch barrier opens, or tracker authority changes during a release. The PM
supervisor records the attempt as deployment-blocked (worker-loss exit `125`)
and requires protected provider `status` reconciliation; a later Todo status
does not retroactively authorize the uncertain attempt or permit a blind
re-apply.
