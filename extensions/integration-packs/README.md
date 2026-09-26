# Integration packs

Integration packs are inert, data-only JSON manifests. They describe one
tracker, CI evidence contract, or deployment target without embedding commands,
hooks, credential values, or release authority.

The canonical loader in `startup_factory_cli.integration_packs` validates the
manifest before any preview, apply, or doctor operation. The installed command
surface is `startup-factory integration-pack <list|validate|preview|apply|doctor>`;
human output gives the next operator action and `--json` returns the stable
machine result used for a saved preview plan. The repository `bin` entry point
is a thin JSON-only caller of the same loader. The CLI treats the user-supplied
`--project` as the host repository and its own installed
Startup Factory directory as the runtime root. Tracker configuration and
adapter detection belong to that runtime root; CI and deployment templates and
project-shape detection belong to the host repository. This separation also
applies when the skill is installed outside the host repository.

A schema-v2 preview is digest-bound to the exact pack bytes, runtime version
and platform, compatibility opt-in, target-root kind, current target, rendered
output, and the device/inode/mode identities of the source, host-project, and
runtime roots. Apply reopens those roots without following links, requires the
same identities, and keeps verified directory descriptors open through target
inspection and mutation. Pack, target, configuration, and saved-plan reads are
bounded regular-file reads using non-blocking, no-follow, directory-relative
opens. Applying a plan may change exactly one target:

- tracker packs update only the existing `PRODUCT_MANAGEMENT_TOOL` and
  `TEAM_MODE` assignments;
- CI and deployment packs create one inactive JSON file below
  `.startup-factory/generated/<kind>/<pack-id>/`.

Credential entries have an exact policy and contain environment-variable names
only. `none` means the pack needs no external credential,
`required-environment` means every listed name is unconditionally needed, and
`adapter-managed` means the existing adapter access mode owns authentication and
the pack must list no unconditional names. The Markdown pack uses `none`; the
hosted tracker packs use `adapter-managed`. Applying them does not change `LINEAR_ACCESS`, `JIRA_ACCESS`,
or `GITHUB_USE_MCP`, so MCP OAuth, REST environment variables, and `gh` stored
authentication remain conditional choices documented by the adapters. Doctor
therefore never falsely labels REST tokens as missing for the default MCP path,
and never treats absent GitHub token variables as failure when stored `gh` auth
may be in use. It invokes no auth or network command. Doctor output reports only
required names and their presence; it does not read or print values.
Configuration, local detection, and proof remain separate states. Local doctor
output always leaves proof unknown: only an authenticated external integration
adapter may establish that state. `operatorActions` explains the next safe
step, including missing credential names, without reading or serializing their
values. The report is red when local prerequisites fail, yellow when local
setup is ready but protected proof is unknown, and green only with proof. The
CLI exits `1` for a valid non-ready report and `0` only for green readiness.

`supported` packs must name the current platform and a minimum runtime version
no newer than the installed runtime. `unsupported` packs, platform mismatches,
and future-version packs cannot be previewed or applied. `experimental` packs
require `preview --allow-experimental`; that explicit decision is bound into
the saved plan and rechecked on apply. `list` and `validate` remain descriptive,
while `doctor` reports the compatibility decision and reasons without mutating
anything.

Reference compatibility is intentionally limited to macOS and Linux for this
release. Windows is not claimed by these packs until the beta compatibility
contract is proved there.

The CI and deployment outputs are deliberately inactive boundary descriptors,
not runnable workflow, Compose, or Kubernetes manifests. They capture the
exact-commit proof and release-authority constraints an operator must carry into
a separately reviewed provider configuration; applying a pack never executes or
activates that configuration. A CI pack must name at least one exact required
check using the provider's real check name; an empty set is invalid. The shipped
GitHub Actions reference names this repository's
`Runtime, package, and reproducible artifacts` check. For another repository,
copy the manifest into `.startup-factory/integration-packs/` under a distinct
pack id and replace that list with the target repository's protected required
checks before previewing it. The release verifier independently requires the
authenticated successful-check set to equal that non-empty required set.
