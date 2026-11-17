# Docker Sandboxes execution and qualification

The opt-in Docker backend connects task launch, fresh per-role VMs, the external
native publication broker, raw task-ref import and isolated validation. It stays
disabled until a dedicated installation has a valid root-issued enrollment.
The ordinary-account smoke evidence below cannot enable it. See
[deployment and live qualification](docker-sandboxes-deployment.md) before setup.

## Prerequisite report

From a checkout or an installed skill:

```sh
python3 bin/sandbox-qualify.py --json
```

From the release CLI:

```sh
startup-factory sandbox qualify --json
```

The command works without a project installation. It discovers the location of
`sbx` without executing it, starting a daemon, accessing credentials, changing
configuration, or creating a VM. A discovered binary is not trusted or qualified.

The report always returns `qualified=false`, `autonomousReady=false`, and
`liveChecksExecuted=false` in this milestone. Exit status 1 means live
qualification remains incomplete. The JSON is an offline inventory, not a
host-authenticated containment receipt. Launch and release code do not consume it
as authorization.

The eight required evidence gates are:

1. Pinned CLI/daemon version and supported platform.
2. Mountless startup without shared storage or host integrations.
3. Effective deny-by-default policy before any guest setup code.
4. Stable backend identity across execution, replacement, and removal.
5. Bounded non-TTY stdin/stdout framing and separate stderr.
6. Host-enforced CPU, memory, storage, and output bounds.
7. Cancellation, orphan reconciliation, and confirmed resource cleanup.
8. Scoped credentials without privileged global fallback.

## Guest exec fixture

`bin/sandbox_qualification_fixture.py` is a trusted test program for future live
exec-channel qualification. It is not a publication relay or an agent launcher.
Run hostile transport cases only in a bounded disposable test environment.

Requests use a four-byte network-order length followed by strict UTF-8 JSON.
The closed request contains `schemaVersion`, `id`, `operation`, and `payloadHex`.
Only the fixture's fixed ping, echo, stderr, and exit operations are allowed.
It accepts no path, executable, shell command, network destination, or capability.
It bounds frame size, JSON depth, read/write time, and session lifetime. Frame
errors fail closed; diagnostic stderr is separate from framed stdout.

`tests/sandbox-qualification-fixture-test.py` covers fragmented/binary frames,
multiple messages, malformed and oversized input, duplicate keys, unsupported
schemas, slow input, and output backpressure. Passing these local contract tests
does not prove Docker isolation or Docker exec-stream behavior.

For an existing disposable VM, an operator can run the fixed real-exec experiment:

```sh
python3 -I -B bin/sandbox-exec-probe.py \
  --sbx /absolute/path/to/verified/sbx \
  --sbx-sha256 EXPECTED_EXECUTABLE_SHA256 \
  --app-name sf-qualification \
  --sandbox DISPOSABLE_NAME \
  --expected-id EXPECTED_UUID \
  --expected-created-at EXACT_CREATION_TIMESTAMP \
  --json
```

The probe verifies the supplied executable digest, checks the VM's identity and
empty mount/MCP metadata, copies only the fixed fixture, and tests four non-TTY
frames, binary echo, separate stderr, and guest exit status. It bounds command
time and output and uses a fixed namespace and command tree. It creates no VM,
changes no policy or credentials, and performs no cleanup; the operator owns the
disposable VM and must remove it afterward. Copy and exec can start a stopped VM.

Success returns `scope=exec-channel-only` while `qualified`, `autonomousReady`,
and `productionBackendAllowed` remain false. Inspections do not make name-based
operations atomically identity-safe. This operator experiment is never exposed
as an agent tool or accepted as a production authorization receipt.

## Startup Factory smoke inside a real VM

On 2026-11-17, all 368 selected Startup Factory tests passed, with no skips,
inside a disposable Docker Sandboxes v0.54.0 microVM. The run took about 71
seconds and covered CLI installation/readiness, lifecycle contracts, native
publication authentication, guest transport, durable artifact admission, finite
source transfer and authorized Git ref promotion.

The pinned shell VM had one CPU, 512 MiB memory, no host mounts, `--skills off`,
no configured MCP servers and an active deny-all network rule. A finite source copy was
provided without host Git metadata or personal credentials. Inside the VM, the
fixed suite ran as UID 1000 with no effective capabilities, no-new-privileges,
an isolated network namespace, read-only input/toolchain and bounded writable
scratch. The controller and broker fixtures also ran inside that VM; this run
does not establish the external macOS controller-to-guest broker boundary.

The experiment exposed two test fixture issues: a crash test rejected a harmless
signal-zero process-group existence query, and a wrapper published its PID file
before finishing the write. Both fixtures were corrected, and deterministic
missing-leader coverage was added. Production security code was unchanged.

The VM was stopped and removed, an empty qualification namespace was observed,
and its daemon was stopped without signing out. The diagnostic evidence is at
`docs/superpowers/qualification/2026-11-17-docker-sandboxes-startup-factory-smoke.json`.
No model agent or external tracker publication was run. Production launcher
integration and the remaining qualification gates below are still required.

## Live qualification prerequisites

Use the standalone `sbx` runtime. The older `docker sandbox` plugin is a separate
interface and cannot satisfy the planned v0.54.0 profile.

Docker's current official macOS cask pins v0.54.0. Verify the downloaded release
checksum, code signature, and notarization before running it. Version and help
checks establish only the CLI interface; they do not establish daemon behavior.
[Official cask](https://raw.githubusercontent.com/docker/homebrew-tap/main/Casks/sbx.rb),
[release notes](https://github.com/docker/sbx-releases/releases/tag/v0.54.0).

Docker's own conformance tooling uses `--app-name` to isolate test resources,
skills, secrets, and policies from the default installation. This is a candidate
qualification context; production execution still requires the dedicated
factory-account profile. The namespace needs its own Docker sign-in. Use a short
suffix, for example `sf-qualification`; v0.54.0 rejects suffixes over 20 characters.
[Official conformance adapter](https://github.com/docker/sandbox-kit-spec/blob/main/tck/adapters/sbx),
[test prerequisites](https://github.com/docker/sbx-kits-contrib#end-to-end-e2e-tests).

An operator can authenticate the separate namespace with a verified installation:

```sh
sbx --app-name sf-qualification login
```

When the CLI prints a device-confirmation code, open the activation URL from that
same running command and complete device authorization. A signed-in Docker Hub
dashboard alone does not confirm that the CLI's pending code was approved. Keep
the command running until it reports the result. If it ends with `context deadline
exceeded`, start a new login and use the new code; do not reuse the expired one.
[Docker's device-code flow](https://docs.docker.com/reference/cli/docker/login/#authenticate-to-docker-hub-with-web-based-login).

Never copy personal authentication files or bulk-import credentials into the
test namespace. Do not change personal global policy, restart its daemon, or run
an unscoped reset/prune as part of qualification. A temporary HOME alone does not
establish an isolated daemon or credential store.

Actual qualification must still demonstrate identity-safe operations, a policy
effective before creation, absence of host integrations, hard disk limits,
independent cancellation, and cleanup. A Docker sign-in or successful VM start
cannot satisfy those gates by itself.

The local v0.54.0 installation reports immutable IDs but rejected those IDs as
selectors for inspect and exec during qualification. Production must therefore
qualify either an atomic identity-bound interface or a dedicated service account
whose namespace has one exclusive trusted controller. The latter requires
protected endpoint access, durable random names that are never reused, permanent
reservations/tombstones, controller locks and epochs, and mismatch fencing. An
ordinary user's separate `--app-name` context does not establish those account
and ownership protections.

The source checkout includes the complete implementation sequence, broker design,
test matrix, and release criteria at
`docs/superpowers/plans/2026-11-16-docker-sandboxes.md`. Design plans are not part of
the operational skill bundle.

## Implemented host and guest boundaries

Select `AGENT_EXECUTION_BACKEND=docker-sandboxes`, set
`AGENT_SANDBOX_ENFORCED=true` and `AGENT_SANDBOX_DEPLOYMENT` to the protected
deployment, and provide an explicit Linux `SANDBOX_DEFAULT_CMD` consuming
`{prompt_file}`. Role and task-profile overrides use `SANDBOX_<ROLE>_CMD` and
`SANDBOX_TASK_<PROFILE>_CMD`. There is no native fallback from a refused Docker
operation. The default remains `protected-runner`.

The persistent `sandbox-custody.py serve` process owns native CLI children and
generation journals. Its private socket accepts only finite prepared jobs from
the dedicated account. The dispatcher assigns one concrete task/attempt to each
gate invocation with `start-gate-task`; startup rosters wait for an assignment.
The first release serializes one active VM per namespace and bounds queued work.
Each implementation, reviewer and validation invocation gets a fresh generation.
`WORKTREE_SETUP` runs inside each fresh job; no repository setup or validation
command runs on the host when this backend is selected.

| Component | Implemented behavior |
|---|---|
| `execution_backend.py`, `config/sandbox.schema.json` | Closed, digest-pinned profile and literal guest command contracts; root-protected profile/runtime verification for a nonroot controller. The example contains placeholder hashes and grants no authority. |
| `sandbox_registry.py` | Protected, locked ownership journal; permanent random names and tombstones; controller epochs; exact backend ID and creation binding; fail-closed quotas and uncertain writes. |
| `native_clients.py`, `sandbox-native-gate.py` | Durable native launch intent, paused child identity registration before exec release, bounded protected history and same-owner child cleanup. Restart inspection is diagnostic only and never signals persisted numeric PIDs or certifies daemon queue clearance. |
| `docker_backend.py` | Fixed v0.54.0 mountless commands, bounded non-TTY native streams, exact metadata checks and positive removal observations. Each native command requires a current controller permit and durable child custody. |
| `sandbox_enrollment.py`, `sandbox_controller.py`, `native_authority.py` | Root-issued receipt verification, phase sequencing, persistent native custody and conservative reconciliation. Uncertain daemon delivery fences the pool until independent qualification. |
| `sandbox_watchdog.py`, `sandbox-watchdog.py` | Separate process and ledger for deadlines and revocation, independent of a blocked launcher/controller. Killing a native CLI alone never establishes daemon queue clearance. |
| `sandbox_service.py`, `sandbox_client.py`, `sandbox_jobs.py` | Closed host job RPC, independent disconnect cancellation, framed source/bootstrap transfer, private guest execution, finite artifact collection, role-scoped native relay and host-authorized import. |
| `sandbox_acceptance.py`, `execution_descriptor.py` | Version 2 execution projections verified against external immutable import receipts before code review publication and integration. Version 1 remains the native contract. |
| `sandbox_completion.py`, `sandbox-execution-guard.py` | Positive gate verdicts wait for a protected capability/job/generation completion receipt, normal exit, unchanged tracked source and confirmed VM cleanup. Code approvals also bind the exact review request, accepted head, package and current attempt. |
| `sandbox_projection.py`, `sandbox_validation.py` | Raw accepted-file projection without checkout programs, and fresh-VM validation of the exact staged tree, including uncommitted integration/revert candidates. |
| `sandbox_transport.py`, `sandbox-relay.py` | Native publication-supervisor descendant, protected host assignment, framed `artifact.submit`, running/collecting generation checks, explicit marker/status grants and no guest-supplied identity or host paths. Production approval and deployment markers are denied. |
| `sandbox_ingest.py` | Host-assigned envelopes and paths, journal-before-signing, durable admission recovery, stable retry receipts, and persistent per-generation request/body quotas. Acknowledgment means admitted, not delivered to the tracker. |
| `sandbox_guest_bridge.py`, `sandbox_guest_client.py` | Guest-local socket, framed requests on non-TTY exec I/O, bounded diagnostics on stderr and no host credentials. Identical default CLI retries reuse a content-derived request ID. |
| `sandbox_source.py` | Finite approved-commit object export, required host secret scanner, explicit source budgets, and an independent shallow guest repository with no host Git configuration or remote. Source symlinks, submodules and LFS hydration are currently refused. |
| `host_git.py`, `sandbox_artifacts.py` | Bounded raw Git plumbing, constrained regular-file manifests, durable quarantine and host-created accepted commits. Ref promotion requires an external task lock and current authorizer, then compare-and-swaps only the assigned ref at the approved base. |

`submit-artifact.sh` routes through the guest client when
`STARTUP_FACTORY_GUEST_SOCKET` is present. It sends only marker, body bytes and
target status; the native relay supplies the immutable assignment. It rejects
mixed guest and host publication transports before any host workspace lookup.
`STARTUP_FACTORY_GUEST_REQUEST_ID` can supply an explicit retry ID when needed.

The relay context is host-only, owner-readable mode 0600, and stored directly
inside the protected registry root. It binds the registry identity, epoch,
generation, backend identity, project/team/role and concrete task/attempt. The
native gate capability retains its gate scope, while each publishing Docker job
and artifact relay receive one explicit positive task/attempt assignment. Never copy this context or the native
publication socket into a guest. Existing broker role/status/hold checks remain
authoritative; the controller must fence generations when their authorization
changes.

Durable defaults allow 64 retained artifact request IDs and 4 MiB aggregate body
bytes per generation, including prepared requests. Reconnects retain the same
quota policy and history. Exact already-admitted retries can complete after a
fence; changed bytes or new requests cannot use that recovery rule.

Admission does not authorize early approval. Code approvals and the canonical
positive design, resume and product markers remain pending until their native
capability has a protected successful completion receipt. The broker returns
status 75 while completion is absent or running, and rejects a recorded failed
job. Design, resume and product gates can complete without an implementation
record. Code approval additionally requires the current accepted task commit and
attempt, and the producer-signed request/head/package fields must match the
completed review assignment. Existing marker ownership, tracker evidence and
hold checks still run before any external effect. Findings and other negative
or diagnostic messages do not wait for a positive completion receipt.

Review and validation jobs perform a final read-only source check. The fixed
guest-root collector first retires live processes belonging to the agent UID
through Linux pidfds, including processes that started separate sessions. It
requires two clean censuses before reading files. Unsupported kernel/Python
APIs, an incomplete census or a process that does not retire denies collection.
The host rejects replacement, deletion or executable-mode changes to baseline
tracked files. New build outputs are allowed only within the ordinary finite
export limits; no import receipt is returned for a read-only job. The pinned
image must qualify this root collector and the separation between its trusted
infrastructure processes and the agent UID.

The fixed worker identity is the locked guest account `sf-agent`, UID/GID 2000,
with private HOME `/home/sf-agent`. Root provisioning creates only those exact
passwd/group records when absent and rejects an occupied name or identifier.
The built-in shell image uses UID 1000 for infrastructure, so that identity is
not suitable for whole-agent retirement. A real v0.54.0 dummy-source probe
verified UID2000 account lookup, retirement of a detached session, preserved
UID1000 init, exact export and symlink denial, then removed the VM and stopped
the empty qualification daemon. Its redacted evidence is
`docs/superpowers/qualification/2026-11-17-docker-sandboxes-agent-quiescence.json`.
This observation does not qualify model access or a production installation.

`sandbox-validation.py` names the exact controlled Git index tree in a raw
synthetic commit, without updating a ref or checking out files. It therefore
validates staged integration and revert candidates rather than their previous
`HEAD`. A fresh validation VM runs `WORKTREE_SETUP` and then the configured
validation script or build/test/lint/format commands. Changed filenames remain
literal NUL-delimited records and script arguments. The complete guest plan is
limited to 64 KiB. Validation receives neither a publication capability nor a
model credential, and repository commands never execute on the host through
this Docker path.

Real native-supervisor tests demonstrate that a descendant relay can admit a
package and recover its exact receipt after revocation. A protected context
file by itself cannot replace native peer authentication. Container tests of
these modules are not Docker Sandbox containment evidence.

Artifact collection rejects unsafe/control paths, symlink or submodule changes,
case/Unicode collisions, mismatched hashes or tree claims, and oversized output.
It imports no guest `.git`, pack, archive, hook or configuration. Host Git uses
raw objects without checkout, filters, merge drivers or repository programs.
Collection cannot advance a ref. Promotion creates a stable host commit and
durable intent before the exact ref update, allowing recovery of that same
acceptance after an interrupted acknowledgment. A changed host projection head
requires a new assignment and approved source base. Existing symlinks/gitlinks
may remain unchanged in artifact bases; initial source transfer currently
refuses them, so they are not supported for an end-to-end Docker job yet.

## Remaining enablement requirements

The current personal-account qualification namespace cannot enroll a factory
profile. Dedicated-account endpoint exclusivity, effective policy and settings,
credential isolation, aggregate host storage limits, cancellation and independent
cleanup still need qualification.

The native gate keeps each child paused until its launch intent and process
identity are durable. Unresolved delivery or cleanup retains the reservation,
fences publication and blocks new dispatch. A signed model credential does not
establish model connectivity: the selected image must prove its CLI, proxy
sentinel and CA trust under the dedicated guest worker UID2000, along with restrictive effective
policy and hard provider quotas. No real model task or dedicated deployment has
yet passed those live gates on the qualification host.

No receipt may be synthesized from the diagnostic JSON, example profile, unit
test fixtures or successful sign-in. Enrollment pins the exact root-issued
receipt bytes, a profile digest excluding its receipt hash, the dedicated UID,
namespace, registry identity and inode, all mandatory evidence digests and an
expiry. Changing the account, registry or protected profile requires fresh
qualification and reconciliation.
