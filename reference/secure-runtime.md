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
requires operator inspection; an idempotent no-op is accepted only after the
commit marker is revalidated. The resulting state is **configured, not proved**. File
modes and repository scripts are not an OS boundary. `doctor` remains yellow
until an authenticated external execution boundary proves the required
isolation; the fixed probe is useful negative-control evidence but never grants
readiness or delivery authority.

Native macOS apply is refused. Run the command inside an operator-controlled
Linux guest. Ordinary linked Git worktrees are also refused because their Git
common directory exposes sibling and broker state. The supported task mode uses
broker-created standalone clones and imports their exact validated commit into
a quarantine ref before review or integration.

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

The first release supports rollback of an incomplete transaction only. It has
no uninstall command and never removes operator-modified assets.

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
