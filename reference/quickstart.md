# Quickstart: governed delivery benchmark path

This is the shortest documented path for measuring a local, non-production
governed delivery from an existing Git project. It uses the Markdown tracker,
keeps credentials out of the repository, and does not grant deployment or
release authority. Completing it in less than 15 minutes is an unproven beta
criterion, not a supported outcome. Startup Factory 0.2.0 does not ship an OS
sandbox runner; an already-provisioned protected runner is a prerequisite for
authenticated team publication. Without one, solo or manually supervised work
remains possible, but it cannot complete governed approvals or integration
evidence.

## Prerequisites

- macOS or Linux; native Windows is unsupported and WSL is currently untested;
- Git, Bash, and `uv` with the `uvx` command available (`uvx --version` must
  succeed), plus a protected CPython in the 3.10 through 3.14 beta support range
  at `/opt/homebrew/bin/python3`,
  `/usr/local/bin/python3`, or `/usr/bin/python3`; an environment-managed Python
  can run the installer but does not by itself satisfy the governed broker
  runtime boundary;
- a root-managed OS isolation runner that accepts
  `runner --workdir <absolute-path> -- <argv...>`, is an executable regular file
  under a canonical system path whose file and complete ancestor chain are
  root-owned and not writable by the operator, group, or world, lives outside
  the project and installed runtime, and actually enforces the worktree,
  process, network, and broker-state policy described in
  [`orchestration.md`](orchestration.md). Startup Factory validates its
  structure but cannot certify the runner's isolation implementation;
- authenticated commands for the required team roles (one CLI may run multiple
  distinct agent processes; model diversity is recommended). Commands outside
  a root-owned system `PATH` should use an absolute executable or dedicated
  wrapper because caller-owned `PATH` directories are deliberately excluded
  from authority-bearing launcher processes;
- a clean project branch that you can discard.

## 1. Install and initialize

From the project root, replace `0.2.0` with the exact reviewed version you intend
to use after it is published:

```bash
uvx startup-factory@0.2.0 install --agent codex
uvx startup-factory@0.2.0 init --agent codex --mode team \
  --product-management-tool Markdown --apply
```

Use `--agent claude-code` for Claude Code.

## 2. Configure the protected publication boundary

The broker lifecycle directory is mandatory for a governed team. Create it as
the human operator, outside both the project and installed runtime. This
per-user example needs no `sudo`; choose a stable project-specific name instead
of sharing one directory between projects:

```bash
authority_root="$HOME/.local/state/startup-factory/my-project/lifecycle"
umask 077
mkdir -p -- "$authority_root"
chmod 700 -- "$authority_root"
(cd "$authority_root" && pwd -P)
```

Copy the printed canonical path and the canonical path of the separately
provisioned runner into the existing assignments in
`.agents/skills/startup-factory/config/team.config.md` (Codex), or the same path
below `.claude/skills/startup-factory/` (Claude Code). These four exact keys are
the minimum publication-boundary configuration:

```text
TRACKER_WRITERS=broker
AGENT_SANDBOX_RUNNER="/absolute/canonical/path/to/protected-runner"
AGENT_SANDBOX_ENFORCED=true
BROKER_LIFECYCLE_ROOT="/absolute/canonical/path/to/lifecycle"
```

Keep path values quoted if they contain spaces. Do not use the repository, its
installed skill, `/tmp`, `/private/tmp`, or a symlink for lifecycle authority.
The runner must keep worker processes from reading or writing the lifecycle
directory; mode `0700` alone does not isolate two unsandboxed processes running
as the same OS user.

Now diagnose the static boundary:

```bash
uvx startup-factory@0.2.0 doctor --agent codex --mode team
```

The report must show `tracker-writer-boundary.configured`,
`sandbox-runner.configured`, and `lifecycle-authority.configured` as `pass`.
This offline doctor never executes the runner or configured agent commands,
creates the directory, or edits authority configuration. It therefore stays
yellow while runtime proofs remain unknown. A missing runner is reported as a
warning in `team` mode because manually supervised team processes remain
possible, but that mode has no authenticated review, integration, or release
publication authority. `autonomous` and `release` modes fail the same missing
boundary.

After the `[feature]` exists, run the installed launcher's doctor with the real
preset, team name, and feature ID before starting persistent roles:

```bash
.agents/skills/startup-factory/bin/launch-team.sh doctor \
  full-stack <team-name> <feature-id>
```

For Claude Code, use the equivalent path below `.claude/skills/`. This probe
runs the configured commands through the runner and verifies their
authentication challenge, but it does not itself approve a review or release.
A yellow or red offline report, or a failed launcher doctor, is an instruction
to complete the named prerequisite—not permission to bypass it.

The runner path is always a production authority boundary: an operator-owned
wrapper is refused even at mode `0700`, because its owner could replace it after
the static doctor check. Use a root-managed install and a dedicated service
identity where appropriate. For production or a shared broker, also use a
root-managed lifecycle location rather than the per-user example. Do not put
credentials in this directory or in repository configuration.

## 3. Validate the local tracker pack

The installed pack tool treats every manifest as untrusted data. It emits a
digest-bound preview and applies only that saved plan:

```bash
uvx startup-factory@0.2.0 integration-pack validate tracker-markdown \
  --agent codex --project .
mkdir -p .startup-factory/plans
uvx startup-factory@0.2.0 integration-pack preview tracker-markdown \
  --agent codex --project . --json \
  > .startup-factory/plans/tracker-markdown.json
uvx startup-factory@0.2.0 integration-pack apply \
  .startup-factory/plans/tracker-markdown.json --agent codex --project .
uvx startup-factory@0.2.0 integration-pack doctor tracker-markdown \
  --agent codex --project .
```

For Claude Code installations, use `--agent claude-code`. Human output guides
each step; `--json` emits the stable machine result used to save the exact plan.
Review that plan before apply. Pack JSON never contains commands or credential
values. Saved plans bind absolute local paths and filesystem identities: keep
`.startup-factory/plans/` local and transient, do not commit it, and remove a
plan after use. Doctor reports credential policy/name presence separately from local
detection and leaves proof `unknown`; it does not authenticate a provider. CI
and deployment packs create inactive templates; they do not activate CI,
deploy, or release.

`--project .` identifies the host repository for discovery and doctor
detection. A tracker pack applies its adapter selection only inside the
installed Startup Factory runtime—for Codex,
`.agents/skills/startup-factory/config/project-management.config.md`; for Claude
Code, the equivalent path starts `.claude/skills/`. It never writes the host
repository's `config/` directory. CI and deployment packs instead place their
inactive templates at their declared host-repository targets.

The local pack doctor therefore exits `1` with a yellow report after successful
local setup: protected external proof is still unknown. Treat that as an
expected readiness gate, not a command failure to bypass. Markdown correctly
reports that no external credential is required.

## 4. Deliver one bounded task

Give the installed agent this product intent:

```text
Use the installed Startup Factory with the Markdown tracker. Create one [feature]
for adding a short “Local development” section to README.md and one [task] that
changes only README.md. Do not deploy or release. Show me the plan before work.
```

Approve the scope, then continue in plain language:

```text
Start the task. Send the exact package to review. Finalize it only if all required
checks and independent reviews pass. Stop before any release action.
```

If the external runner enforces the documented isolation contract and all
runtime gates pass, the expected result is a board under
`.workspace/task-manager/`, implementation isolated from the main checkout,
approvals bound to the exact reviewed package, and a completed task ready for a
human merge decision. This document supplies no benchmark result and authorizes
no release. The precise files and commands to inspect are in the reproducible
walkthrough.

## Next integrations

List the shipped catalog with:

```bash
uvx startup-factory@0.2.0 integration-pack list --agent codex --project .
```

The first catalog includes Markdown, GitHub Issues, Jira, and Linear trackers;
GitHub Actions exact-commit verification; and inactive Docker Compose and
Kubernetes deployment-boundary descriptors. They are operator inputs, not
runnable workflows or deployable manifests. Follow the same validate, preview,
apply, doctor sequence for one pack at a time. Configure credentials in the operator
environment or provider secret store only—never in a pack, plan, generated
template, task description, or repository configuration.
