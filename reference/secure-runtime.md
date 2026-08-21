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
configuration last. The resulting state is **configured, not proved**. File
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
socket paths are never mounted.

The first release supports rollback of an incomplete transaction only. It has
no uninstall command and never removes operator-modified assets.

`startup-factory runtime-kit ... --probe --json` emits digest-bound fixed probe
definitions but does not execute a container or change readiness. The shipped
`tests/runtime-boundary-linux-opt-in.sh` is the explicit real-engine check; it
is skipped unless the operator supplies a disposable standalone clone and sets
`STARTUP_FACTORY_REAL_RUNTIME_PROBE=1`. Even a passing probe is evidence, not an
attestation and not permission for autonomous, release, or production delivery.
