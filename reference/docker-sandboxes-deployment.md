# Dedicated Docker Sandbox deployment and qualification

The deployment tools prepare a protected installation. They do not convert the
368-test VM smoke run into production enrollment. The example manifest contains
placeholder hashes, UID/GID, volume identity and project identity and cannot be
used as evidence.

The service runs as a dedicated nonlogin account with its own private group and
complete HOME on a quota-limited APFS volume. Root owns the installation,
Python/runtime, profile, deployment manifest and reviewed evidence. Controller
registry, native journal, queue and watchdog state use separate private 0700
directories. Controller and watchdog keep their native children in persistent
processes. Native publication authentication still requires the trusted host
supervisor ancestry; a queue file or authenticated RPC is not tracker authority.
The first release uses one active job per namespace. Implementation, review and
validation run sequentially in fresh disposable VMs; additional work queues.
Parallel namespace protocols require separate qualification.

Use Apple silicon and macOS 14 or later, with a root-managed Python 3.10 or later.
Do not assume the system Python or a user-writable Homebrew Python meets the
runtime contract. Verify the vendor release checksum, signature and notarization
before placing the complete Sbx.app under protected real ancestors. The installer
does not download or execute an unreviewed release. Docker documents the local
platform requirements and installation at [Install Docker Sandboxes](https://docs.docker.com/ai/sandboxes/install/).

Before running setup, review the dedicated account name and confirm its proposed
UID/GID are unused. `sandbox-deploy.py plan` prints literal `dscl` argument arrays
and the exact installed service argv. It does not execute them, set a password,
add supplementary groups or modify an existing account. Account creation needs
administrator action. Apple documents [directory-service account creation](https://developer.apple.com/library/archive/documentation/Porting/Conceptual/PortingUnix/additionalfeatures/additionalfeatures.html).

Create a dedicated APFS volume with the reviewed finite quota and host headroom.
Record its UUID and mount point; place the complete account HOME there so VM
disks, images, caches, logs, queue, artifacts and canonical project storage share
the host-enforced bound. A filesystem size environment variable alone does not
establish aggregate host storage isolation. Apple describes the APFS allocation
limit under [Quota Size](https://support.apple.com/guide/disk-utility/dskua9e6a110/mac).
The issuer reads `diskutil` metadata and rejects an absent or changed quota;
independently observed guest-root pressure and cleanup tests are still required.

Prepare the exact release and installation data:

1. Fill the dedicated account, storage, root Python and runtime pins in reviewed
   copies of `sandbox-deployment.example.json` and `sandbox.config.example.json`.
   Leave `qualificationDigest` as the zero placeholder for first installation.
   Copy `sandbox-network-policy.example.json` to the root-protected
   `networkPolicyPath`, use the same dedicated namespace and pin its exact raw
   file SHA-256 as the profile's `policyDigest`. Only the supported OpenAI HTTP
   methods and paths are accepted; host-wide, wildcard and extra kit rules are
   refused. The adapter installs scoped model rules behind the create-time
   deny lock, verifies them, then removes that exact lock before credentials or
   source provisioning. Dependency downloads stay blocked; provision required
   tools and dependencies in the reviewed pinned image.
   Review a deployment-specific source revision and build its canonical release
   archive with `config/team.config.md` already containing
   `AGENT_EXECUTION_BACKEND=docker-sandboxes`, `AGENT_SANDBOX_ENFORCED=true`, the
   exact final `AGENT_SANDBOX_DEPLOYMENT` path, `BROKER_LIFECYCLE_ROOT` equal to
   the manifest's `lifecycleRoot`, and an explicit credential-free Linux
   `SANDBOX_DEFAULT_CMD` consuming `{prompt_file}`. The default release archive
   intentionally uses the native backend and is rejected by `prepare-bundle`.
   Configuration is included in the reviewed archive SHA and installed bundle
   digest; editing the installed configuration invalidates enrollment.
2. Run `sandbox-deploy.py prepare-bundle --deployment CANDIDATE --destination
   /Library/StartupFactory/deployment.json --profile PROFILE --bundle ARCHIVE
   --bundle-sha256 SHA256`. Review its finite source pins, normalized installed
   bundle digest and `preparedDeployment`. Save precisely that object and hash
   its exact saved bytes for the install confirmation argument.
3. Run `sandbox-deploy.py plan` against the reviewed candidate and destination.
   After the account, volume and signed root-protected runtime prerequisites are
   satisfied, the administrator can run `install` with the same inputs and
   `--expected-deployment-digest sha256:HEX`. It refuses existing destinations,
   symlink/archive special files and changed release/program pins. It writes a
   protected bundle, unenrolled profile and unloaded launchd candidates.

The generated launchd files live under the protected installation's `launchd/`
directory. They do not load themselves or start at installation. Review their
dedicated `UserName`/`GroupName`, exact Python/program argv, explicit environment,
umask, log location and limits before administrator installation into
`/Library/LaunchDaemons`. Apple documents the [launchd ownership and service configuration](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

Bootstrap only the dedicated runtime before supplying untrusted source. Docker
settings can start a daemon. Turn off host integrations and the bundled model
server, restart that dedicated daemon and observe the effective settings. The
bundled model server has no environment-variable override and can start its
download before a settings change and restart. See [Docker settings](https://docs.docker.com/ai/sandboxes/configuration/settings/)
and [model-service behavior](https://docs.docker.com/ai/sandboxes/configuration/models/).
Use dedicated Docker sign-in and dummy scoped model identities during
qualification; import no personal credential store. Removing a scoped model
secret restores any global secret, so absence of global fallback must be tested.
See [Docker credential scopes](https://docs.docker.com/ai/sandboxes/configuration/credentials/).

Run `sandbox-enroll.py inventory --deployment PROTECTED_PATH` to obtain incomplete
templates. Every template deliberately fails verification until real methods
have been performed and independently reviewed. Root must retain bounded,
redacted raw artifacts beneath `evidenceRoot` and record their exact SHA-256.
Evidence uses `kind=root-reviewed-live-qualification`, the inventory's exact
method, deployment/profile/account/registry bindings, observation time and a
validity interval of at most 24 hours. The review scope must be the actual
dedicated macOS host. A generic `passed: true` report is rejected.

Production custody and watchdog entrypoints require enrollment before starting.
Pre-enrollment methods therefore need a separate administrator-operated live
fixture with declared dummy authority, independent observation and retained raw
results. That complete fixture is not currently supplied as a command. Existing
real Sbx source/collector and dry model-policy probes do not establish the
external native macOS broker boundary, independent watchdog, daemon queue or
storage recovery methods. Offline tests with mock enrollment/reconciliation
authorities do not establish them either. These are remaining qualification
blockers; neither fixture success nor a unit-test count creates authority, and
there is no production `--skip-enrollment` path.

Required methods cover the signed exact platform/runtime; effective mountless
and integration settings; policy preceding every guest phase with positive and
negative network controls; private daemon endpoints and replacement/stale epoch
faults; bounded non-TTY transport/disconnects; host-enforced resources and pressure;
independent watchdog plus daemon-queue and storage reconciliation; and dummy
scoped model access, no privileged/global fallback, quotas and the external
native publication boundary. The exact closed observation schemas are enforced
in `sandbox_qualification_evidence.py`. A root-reviewed statement is an explicit
administrator attestation, not an automatic proof that a test happened.

Only after all live methods pass may the administrator use `sandbox-enroll.py
issue --deployment PROTECTED_PATH` for verification, followed by the same command
with `--install` to commit authority. The issuer rechecks current account,
profile, runtime, installed bundle, registry and endpoint identities, actual
dedicated settings/policy and APFS quota. It requires a quiescent registry with
no live or uncertain reservation. It retains immutable content-addressed proof,
writes the receipt and commits its profile digest last. Interrupted writes deny
dispatch and require reconciliation. Receipt expiry cannot exceed the earliest
proof expiry. The service rechecks the protected deployment and receipt on
startup and before mutations; replaced endpoints or changed pins require fresh
qualification. Issuance never starts a service, grants tracker write scope or
bypasses task/role/attempt/hold checks.

For model jobs, configure only the deployment's `modelCredentials.providers`
and role mapping. This release supports the observed `openai` scoped secret
protocol. The source is a single-link root-owned mode `0640` file readable only
through the dedicated private GID, under root-owned protected ancestors. It is
never placed in a job JSON, guest file, environment, argv, diagnostic or journal
hash. The broker durably prepares a generation lease before reading the source,
sets the sandbox-scoped secret through bounded native stdin before source/agent
activation, and attempts scoped removal before VM cleanup even after a partial
installation. Unfinished credential history blocks further dispatch and receipt
issuance. Empty provider configuration supports validation fixtures; it cannot
run a model job or fall back to a personal/global model key.

Before enrollment, exercise the actual pinned Linux model CLI as agent UID
`2000`, its CA trust, Docker TLS proxy and model sentinel against a dummy scoped
principal. Retain an allowed real model response, denied non-model HTTP paths,
other hosts/direct IPs/host services, denied guest plaintext-secret reads, and a
denied request after scoped removal with no global fallback. Independently
enforced per-agent provider or gateway spending/request limits must reject a
request at the declared quota; job deadlines and credential scoping alone do
not prove a hard model quota. None of these live model gates is established by
the offline tests or the 368-test VM smoke run.
The credential proof requires `agentUid=2000`, the actual `modelCliSha256`,
`modelCliRequestSucceeded`, `tlsProxySentinelObserved`, `caTrusted`, and a
nonsecret `dummyModelResponseDigest`. The image's UID `1000` belongs to sandbox
infrastructure and is excluded from agent cleanup; the historical smoke test's
UID `1000` describes a separate nested fixture and is not agent enrollment.

All private control roots, project repositories and workspace roots must already
exist on the enrolled quota volume, without nested mounts escaping its device.
The service rejects a conflicting ambient lifecycle root and binds each native
publication transport to the exact capability locator beneath `lifecycleRoot`.
Positive code, design, resume and product gate verdicts also wait for a protected
capability/job/generation completion receipt after normal exit, unchanged
tracked-source verification and successful VM removal. Running or absent
completion leaves an admitted verdict pending; a recorded failure rejects it.
Design/resume/product gates need no implementation record. Code approval must
also match the current accepted commit/attempt and exact producer-signed review
request/head/package. Existing native broker authorization remains mandatory.

Qualify the pinned image's guest-root exporter with the actual Linux pidfd APIs:
it must retire the agent UID's live processes, including detached sessions, and
establish two clean process censuses before snapshotting. Trusted image
infrastructure must not be confused with disposable agent processes. A missing
API, failed retirement, unsafe source file or tracked-source mutation must deny
the job. Read-only jobs may create only bounded untracked build outputs; their
exports cannot enter task import. Integration and late-revert validation must
use the exact staged index tree and run setup and all repository checks inside
a fresh VM, with no publication or model capability.

Historical import/completion receipts retain their original full
profile digest; renewal is accepted only through their protected stable
deployment/profile-basis anchors. Legacy import receipts without those anchors
continue to require the original full profile digest.
After a quiescent receipt renewal, restart the persistent custody and watchdog
services with the new protected profile. Live instances never adopt changed
profile bytes; stable history anchors allow a fresh instance to retain history
without rewriting old provenance or resetting tombstones.
