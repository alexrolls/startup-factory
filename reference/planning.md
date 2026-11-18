# Planning providers

Planning providers shape requirements and produce a specification and an
implementation plan. Startup Factory owns the resulting [feature] and [tasks],
the design gates, worktrees, dispatch, mandatory reviews, integration, and
release. A provider report or a handoff digest does not grant approval authority.

Read `config/planning.config.md`, then resolve the provider for the runtime that
is doing the planning:

```bash
python3 bin/planning.py preflight --runtime codex
```

Use `claude`, `codex`, `deepseek-harness`, or `other`. The commands in this guide
use a source checkout; for an installed skill, use its `bin/` and `config/`
paths instead. Pass `--config <path>` before the subcommand when selecting a
different configuration file.

## Selection and compatibility

| `PLANNING_PROVIDER` | Behavior |
| --- | --- |
| `auto` or absent | Preserve the legacy policy: `USE_SUPERPOWERS=true` selects Superpowers for Claude Code; all other combinations use native planning. |
| `native` | Use Factory planning regardless of the legacy flag. |
| `superpowers` | Use the existing Claude/Superpowers adapter; require Claude Code and its installed, enabled plugin. |
| `egm` | Use the portable Factory EGM adapter and require a valid, complete external bundle. |

An explicit provider wins over `USE_SUPERPOWERS`. An explicitly selected provider
that cannot run fails visibly; do not fall back to another provider. Selecting
EGM never changes the default for another project. The updater preserves existing
project planning configuration, so older files without the new keys continue to
use `auto` and the legacy flag.

| Provider | Specification root | Plan root | Reference |
| --- | --- | --- | --- |
| Native | `NATIVE_SPEC_ROOT=docs/specs` | `NATIVE_PLAN_ROOT=docs/plans` | This guide and `reference/lifecycle.md` |
| Superpowers | `SUPERPOWERS_SPEC_ROOT=docs/superpowers/specs` | `SUPERPOWERS_PLAN_ROOT=docs/superpowers/plans` | `reference/superpowers-planning.md` |
| EGM | `EGM_SPEC_ROOT=docs/egm/specs` | `EGM_PLAN_ROOT=docs/egm/plans` | `reference/egm-planning.md` |

These defaults are repository-relative directories. Keep the selected artifacts
under their configured roots. EGM's separate `EGM_PLUGIN_ROOT` points to a full
bundle, not an artifact directory or a network URL. An absolute external path is
recommended. Relative bundle paths resolve against the repository selected by
`--repo`; pass that repository explicitly when invoking the planning API from
elsewhere. Keep the EGM checkout outside the installed Factory bundle and project
source tree.

## Intake and output

1. Read the requested work, existing decisions, relevant code, and local
   conventions before asking questions. Record the product goal, measurable
   acceptance criteria, constraints, scope, non-goals, and material failure cases.
2. Select the intake. Use `brainstormed` when discovery is needed. Use
   `spec-provided` when the supplied specification is complete, internally
   consistent, and the user explicitly asked to proceed. Preserve its intent;
   ask only about material gaps rather than repeating requirements discovery.
3. Follow the selected provider reference. Native planning writes the same
   inputs directly: a specification covering behavior, constraints, interfaces,
   data effects, alternatives, and risks; and a plan covering bounded [tasks],
   dependencies, exact file boundaries, interfaces, tests, and migration or
   rollout where applicable. Label assumptions and delegated decisions.
4. Resolve material contradictions before implementation. Respect the user's
   already granted authorization and delegated technical choices. Present the
   finished design for review where design approval is still required; a draft
   that has not been reviewed is not an approved specification.
5. For Superpowers or EGM, commit the specification and plan, then bind their
   exact contents into the handoff. Native planning may opt into this shared
   artifact contract; the legacy native lifecycle without a handoff remains
   supported. The provider does not create tracker work or start implementation
   during intake. Continue with Lifecycle Scenario 1 and the normal Factory
   planning approvals after the handoff, or directly after native planning when
   no handoff is requested.

## Bind and validate the handoff

For example, after an EGM-assisted Codex planning session:

```bash
bash bin/launch-team.sh planning-handoff full-stack \
  docs/egm/specs/export.md docs/egm/plans/export.md brainstormed codex
```

The launcher accepts:

```text
planning-handoff <team> <spec-path> <plan-path> [brainstormed|spec-provided] [runtime]
```

The intake defaults to `brainstormed`. The omitted runtime defaults to `claude`
for compatibility with existing launcher callers; pass it explicitly for other
runtimes. The runtime here identifies the planning session, not every later
worker's model.

The lower-level API lets a caller choose its handoff output path:

```bash
python3 bin/planning.py create-handoff --runtime codex \
  --repo /absolute/project --team full-stack --intake brainstormed \
  --spec docs/egm/specs/export.md --plan docs/egm/plans/export.md \
  --output /absolute/project/.teamwork/full-stack/planning/handoff.json
python3 bin/planning.py validate-handoff --repo /absolute/project \
  --handoff /absolute/project/.teamwork/full-stack/planning/handoff.json \
  --team full-stack
```

Use the output path returned by the launcher when validating a launcher-created
handoff. Both artifacts must be committed and unmodified. Validation binds the
selected provider, exact artifact digests, source commit, team, and Factory
execution ownership. EGM also binds the configured bundle identity. Changes to
an artifact, provider, or bound EGM bundle require a new handoff and the affected
planning reviews. Revalidate before consuming previously prepared inputs.

The old `bin/superpowers-planning.py` entry point remains available, and valid
schema-v2 Claude/Superpowers handoffs remain supported under that provider.
Do not reinterpret an old handoff as evidence for another provider. The launcher
retains `planning/superpowers-handoff.json` for Superpowers and uses
`planning/handoff.json` for EGM/native under the team's workspace. Both files for
the same team are ambiguous and fail validation. When changing providers, use a
new team or explicitly retire the superseded handoff after preserving any needed
audit record; do not leave two competing handoffs in place.

## What preflight establishes

Preflight checks provider configuration and its local prerequisites. EGM bundle
validation establishes the local files and identity used to compose the prompt.
It does not execute the model, prove that the agent followed the review protocol,
prove context isolation, or grant authenticated review authority.

The EGM adapter is expressed through Factory's composed instructions and the
host's actual tools. It does not add an automatic EGM orchestration service.
Record actual reviewer completion, isolation limits, and findings in the planning
reports. Live workflow conformance must be established separately for each host;
do not describe an unperformed Codex or DeepSeek Harness run as verified.
