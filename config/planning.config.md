# Planning Configuration

This project-wide configuration selects whether Claude Code uses
[`obra/superpowers`](https://github.com/obra/superpowers) to shape specification
and implementation planning before Startup Factory launches its own team.

```
USE_SUPERPOWERS=true
SUPERPOWERS_PLUGIN_ID=superpowers@claude-plugins-official
SUPERPOWERS_SPEC_ROOT=docs/superpowers/specs
SUPERPOWERS_PLAN_ROOT=docs/superpowers/plans
```

## Behavior

- `USE_SUPERPOWERS=true` (default): make Claude Code runtimes eligible to invoke
  `superpowers:brainstorming`, then `superpowers:writing-plans`. Bind the
  resulting committed specification and plan into a Startup Factory planning
  handoff before launching the team. This value does not enable Superpowers for
  any non-Claude runtime.
- `USE_SUPERPOWERS=false`: skip every Superpowers-specific planning and worker
  instruction. Use the native Startup Factory planning, design, implementation,
  review, integration, and release workflow.
- Non-Claude runtimes always use the native workflow. They do not receive the
  Superpowers planning reference or Claude worker-method instructions, and the
  flag does not require another model or harness to install Superpowers.

Superpowers never owns execution in this integration. Do not invoke its
`using-git-worktrees`, `subagent-driven-development`, `executing-plans`, or
`finishing-a-development-branch` skills for Startup Factory work. Startup
Factory owns task packets, worktrees, dispatch, review, integration, and
production release.

## Rules

- Keep exactly one `KEY=value` per line inside the fenced block.
- `USE_SUPERPOWERS` must be exactly `true` or `false`.
- `SUPERPOWERS_PLUGIN_ID` must be a Claude Code plugin id.
- `SUPERPOWERS_SPEC_ROOT` and `SUPERPOWERS_PLAN_ROOT` must be normalized,
  repository-relative directories.
- This file is project configuration and is preserved during Startup Factory
  updates unless `--overwrite-config` is explicitly requested.
