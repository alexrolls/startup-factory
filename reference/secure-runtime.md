# Secure runtime kit

The runtime kit configures one Linux profile: rootless Podman 5 with a locally
present digest-pinned image. It previews by default and writes only when the
operator repeats the reported plan digest with `--apply`.

```bash
startup-factory runtime-kit --project "$PWD" --install-dir /opt/startup-factory \
  --runtime-root /var/lib/startup-factory-runtime --engine /usr/bin/podman \
  --image registry.example/agent@sha256:<64-hex> --json

startup-factory runtime-kit --project "$PWD" --install-dir /opt/startup-factory \
  --runtime-root /var/lib/startup-factory-runtime --engine /usr/bin/podman \
  --image registry.example/agent@sha256:<64-hex> \
  --apply --plan-digest sha256:<preview-digest> --json
```

The runtime root's parent must already be an operator-owned mode-0700 directory.
Podman must report major version 5, rootless mode, UID/GID namespace mappings,
and exactly one already-local image containing the requested repository digest.
The profile always uses `--pull=never`; provisioning never contacts a registry.

Applying creates versioned external assets and then updates the preserved team
configuration last. A mode-0600 lock, phase-aware journal, complete pre-image,
and digest-bound commit marker protect the compensating transaction. Foreign,
hard-linked, malformed, or incomplete recovery evidence is preserved and
requires operator inspection; a lock whose recorded owner process is still
alive cannot be recovered. An idempotent no-op is accepted only after the
commit marker is revalidated. Any unresolved lock or journal makes static
verification, `doctor`, and governed launch fail closed.

Recovery is preview-first and uses the same immutable transaction evidence:

```bash
startup-factory runtime-kit --project "$PWD" --install-dir /opt/startup-factory \
  --runtime-root /var/lib/startup-factory-runtime --engine /usr/bin/podman \
  --image registry.example/agent@sha256:<64-hex> --recover --json

startup-factory runtime-kit --project "$PWD" --install-dir /opt/startup-factory \
  --runtime-root /var/lib/startup-factory-runtime --engine /usr/bin/podman \
  --image registry.example/agent@sha256:<64-hex> --recover --apply \
  --plan-digest sha256:<recovery-digest> --json
```

The recovery preview validates the lock, journal phase, owner, target/config,
asset pre/post-images, created-directory scope, plan and installation digests,
commit marker, and every existing component of the reserved runtime namespaces,
even when the final asset path is absent. Directory and exclusive-file creation
walk pinned directory descriptors and never follows a substituted ancestor.
Transaction schema 3 binds each reserved namespace's present/absent state plus
its type, device, inode, owner, exact mode-0700 policy, and link count in the
lock; the journal additionally binds each transaction-created directory after
every durable creation. Safe-looking but unbound directories are substitutions,
not cleanup candidates. Older unresolved transaction schemas are preserved for
manual inspection rather than guessed or upgraded in place.
If an ancestor changes after a process death or preview, recovery/apply preserves
the lock, journal, and substituted path; inspect the named mismatch, restore the
exact caller-owned non-symlink namespace, and request a new `--recover` digest.
`locked` clears only its exact orphaned lock; `prepared`,
`assets-written`, and `config-replaced` compensate to the recorded pre-state;
`commit-marked` finalizes only an exact durable post-state. Changed, foreign,
or ambiguous evidence is never removed. The resulting state is **configured,
not proved**. File
modes and repository scripts are not an OS boundary. `doctor` remains yellow
until an authenticated external execution boundary proves the required
isolation; the fixed probe is useful negative-control evidence but never grants
readiness or delivery authority.

Native macOS apply is refused. Run the command inside an operator-controlled
Linux guest. Ordinary linked Git worktrees are also refused because their Git
common directory exposes sibling and broker state. The supported task mode uses
broker-created standalone clones and imports their exact validated commit into
a quarantine ref before review or integration.

In enforced standalone mode, project validation runs only from a fresh
broker-created disposable clone of that exact quarantine commit, through the
manifest-bound runner with `network=none`, a sanitized environment, and no
outbox or other capability. The canonical repository and producer clone are
not mounted. Its review evidence binds the imported commit/tree, runtime and
image identities, validation configuration, and changed-file digest. A failed
validation clone is deliberately preserved for inspection and can only be
reused after the broker revalidates its exact Git state. Legacy linked or
explicitly unenforced manual configurations retain host validation. Automatic
late-invalidation revert validation is refused in governed mode until the same
exact protected recovery workflow exists; its recovery journal is preserved.

Network defaults to `none`. Networked model access requires a separately
provisioned, named, digest-bound egress gateway and a short-lived model session
capability; upstream provider credentials remain outside the agent container.
Tracker, cloud, release, broker, lifecycle, host-home, SSH-agent, and container
socket paths are never mounted. Each doctor, gate, and task role receives a
broker-created standalone clone, bounded read-only prompt/packet copies, the
immutable installed tool bundle read-only, and at most one capability-named
outbox ingress. The broker revalidates the runtime manifest and all locally
provable engine, image, runner, policy, network, source, and commit-marker
bindings before every launch. Agent submissions are promoted from the scoped
ingress into the canonical outbox by the trusted broker; agents never mount the
canonical repository, `.git`, `.teamwork`, lifecycle, or broker state.

The first release has no uninstall command and never removes operator-modified
assets or old versioned runtime bundles.

## Protected Beads authority protocol

`startup_factory_cli.beads_protected_runtime` is the broker-side protected
authority surface for the optional Beads backend. It does not implement tracker
semantics and it is never an alternative tracker source of truth. When Beads is
selected, ordinary claim, mutation, and launch capabilities require one current
active authority epoch. Preparation is allowed only while that epoch is
revoked, through one-use HMAC capabilities and immutable intent, consumption,
history, current-pointer, step, and receipt records under an external mode-0700
protected root. Requests contain the protected-root and HMAC-key locations;
key bytes are read only by the broker and are never returned or passed to an
agent process.

The compatibility baseline is `gastownhall/beads` v1.1.2 at full commit
`20e493e569c922d1253bdeff068c5e56c94957fb`. Re-attestation admits only the
literal ordered child argv `[B,"--db",S,"--json","--sandbox","config","list"]`,
where `S=P/.beads/embeddeddolt`. The selected `D=S/DB` directory and `D/.dolt`
are separate no-follow physical observations and are never substituted into
argv. The deterministic offline fixture is
`tests/fixtures/beads-protected-runtime-v1.json`; genuine binary/source
conformance remains a release gate and a missing or skipped proof is non-green.

Repository-only verification functions require the broker to establish the
explicit lexical `use_beads_protected_runtime_v1(...)` locator context. They do
not consult environment variables or discover roots. Historical verification
is audit-only. A stale current pointer, generation overflow, reused capability,
unknown transition, malformed canonical payload, HMAC mismatch, unsafe mode,
link, type, owner, or exact-byte CAS mismatch fails closed and preserves the
append-only records for operator inspection. These Python and same-UID file
controls are governance evidence inside the external runner boundary; they are
not themselves an operating-system security boundary.

After apply, `startup-factory runtime-kit ... --probe --json` creates a
disposable standalone clone and executes fixed positive and negative controls
through the configured runner. It records worktree write/commit observations
and denial of the host sentinel, canonical repository, broker/lifecycle state,
sibling workspace, loopback service, and metadata route. Failed evidence is
preserved for inspection; passing evidence never changes readiness. The shipped
`tests/runtime-boundary-linux-opt-in.sh` is the explicit real-engine check; it
is skipped unless the operator supplies a disposable standalone clone and sets
`STARTUP_FACTORY_REAL_RUNTIME_PROBE=1`. Even a passing probe is evidence, not an
attestation and not permission for autonomous, release, or production delivery.
