# Planning Configuration

Select requirements and specification intake before Startup Factory launches its
own delivery team. Providers produce planning inputs; Startup Factory retains
execution, worktrees, dispatch, review, integration, and release authority.

```
PLANNING_PROVIDER=auto
USE_SUPERPOWERS=true
SUPERPOWERS_PLUGIN_ID=superpowers@claude-plugins-official
SUPERPOWERS_SPEC_ROOT=docs/superpowers/specs
SUPERPOWERS_PLAN_ROOT=docs/superpowers/plans
NATIVE_SPEC_ROOT=docs/specs
NATIVE_PLAN_ROOT=docs/plans
EGM_SPEC_ROOT=docs/egm/specs
EGM_PLAN_ROOT=docs/egm/plans
EGM_PLUGIN_ROOT=null
```

## Provider selection

- `auto` preserves existing behavior: Claude Code uses Superpowers when the
  legacy `USE_SUPERPOWERS` flag is true; other runtimes use native planning.
  With the legacy flag false, all runtimes use native planning.
- `native` selects Startup Factory planning for every runtime.
- `superpowers` explicitly selects the existing Claude Code integration. The
  plugin must pass its preflight; another runtime reports an unsupported intake
  instead of silently changing provider.
- `egm` selects the portable Elephant Goldfish Model planning integration for
  Claude Code, Codex, DeepSeek Harness, and other file-reading runtimes. Set
  `EGM_PLUGIN_ROOT` to a complete EGM plugin/source bundle. Relative paths resolve
  against the project repository root. A null root is valid while EGM is not
  selected; selecting EGM requires a real bundle and successful resource checks.

An explicit provider takes precedence over `USE_SUPERPOWERS`. Existing projects
without `PLANNING_PROVIDER` retain the `auto` behavior. Selection does not install
plugins, authenticate agent CLIs, or prove live model compatibility.

## Planning handoff

Use the selected provider to produce a specification and implementation plan,
then commit both and create the digest-bound Factory handoff. A complete approved
user specification can use the `spec-provided` intake without another discovery
interview. Changed documents or EGM resources require a new handoff and affected
planning approvals. See [planning providers](../reference/planning.md) and the
[EGM workflow](../reference/egm-planning.md).

Superpowers must not invoke its `using-git-worktrees`,
`subagent-driven-development`, `executing-plans`, or
`finishing-a-development-branch` skills for Factory work. EGM reviewers provide
advisory planning reports and do not publish Factory approvals or execute tasks.

## Rules

- Keep exactly one `KEY=value` per line inside the configuration block.
- `PLANNING_PROVIDER` must be `auto`, `native`, `superpowers`, or `egm`.
- `USE_SUPERPOWERS` must be exactly `true` or `false`.
- `SUPERPOWERS_PLUGIN_ID` must be a `plugin@marketplace` identifier.
- Specification and plan roots must be normalized repository-relative paths.
- `EGM_PLUGIN_ROOT` is a directory path or `null`; quote paths containing spaces.
- This project configuration is preserved during updates unless
  `--overwrite-config` is explicitly requested.
