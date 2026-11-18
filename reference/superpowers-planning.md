# Claude + obra/superpowers planning

Use this workflow only when all of the following are true:

1. The resolved provider is `superpowers`: either explicit
   `PLANNING_PROVIDER=superpowers`, or `PLANNING_PROVIDER=auto` (also the default
   when absent) with `USE_SUPERPOWERS=true` on Claude Code.
2. The current runtime is Claude Code.
3. `bin/planning.py preflight --runtime claude` succeeds.

In `auto` mode, non-Claude runtimes and projects with the legacy flag disabled
use native Startup Factory planning without emulating or copying Superpowers.
Explicit `superpowers` remains a Claude-only Factory adapter and fails on other
runtimes. Upstream Superpowers supports additional hosts, including Codex; this
Factory adapter does not claim to integrate those hosts. Use `native` or the
portable `egm` adapter when appropriate. See `reference/planning.md` for provider
selection, artifact roots, and compatibility.

The launcher recognizes a direct `claude` command automatically. If a configured
command invokes Claude through a wrapper, mark that command template explicitly:

```bash
STARTUP_FACTORY_LLM_RUNTIME=claude /path/to/wrapper {prompt_file}
```

In harness mode, set `STARTUP_FACTORY_LLM_RUNTIME=claude` while composing the
prompt. Any absent or non-Claude runtime marker is treated as `other`, so the
default-on project flag remains Claude-only.

## Ownership boundary

Superpowers owns two inputs:

1. Specification intake — normally `superpowers:brainstorming` to clarify intent,
   compare approaches, obtain human design approval, and write the specification
   under the configured spec root. A complete user-provided specification may be
   written directly and recorded as `spec-provided`.
2. `superpowers:writing-plans` — turn the approved specification into a detailed
   implementation plan under the configured plan root.

Startup Factory owns everything after that:

- cross-functional planning review and task shaping;
- project-management creation and status transitions;
- design gates and contract registration;
- task packets, branches, worktrees, and dispatch;
- implementation, core-and-declared-gate review, and integration;
- product acceptance, protected CI proof, and production release.

The Superpowers plan may contain its standard instruction to use
`subagent-driven-development` or `executing-plans`. Treat that instruction as
superseded by this integration. Do not invoke:

- `superpowers:using-git-worktrees`;
- `superpowers:subagent-driven-development`;
- `superpowers:executing-plans`;
- `superpowers:finishing-a-development-branch`.

This prevents two schedulers, worktree owners, review systems, and branch
finishers from operating on the same [feature].

## Planning workflow

1. Run the Claude plugin preflight:

   ```bash
   python3 bin/planning.py preflight --runtime claude
   ```

2. Select and record one intake:
   - `brainstormed`: invoke `superpowers:brainstorming` and follow its human
     approval gates.
   - `spec-provided`: use only when the user's supplied specification already
     defines scope, acceptance criteria, constraints, interfaces/data effects,
     and material failure cases, and the user explicitly asked to proceed.
     Write it under the configured spec root without re-running an interactive
     requirements ritual. Missing or contradictory content falls back to
     `brainstormed`; never silently invent material requirements.

   Do not create project-management work or launch implementation agents during
   either intake.
3. Invoke `superpowers:writing-plans` after the written specification is
   approved. Let it write and self-review the implementation plan.
4. Do not offer or start a Superpowers execution mode. Instead create the
   digest-bound handoff:

   ```bash
   bin/launch-team.sh planning-handoff <team> <spec-path> <plan-path> <brainstormed|spec-provided> claude
   ```

5. Use the specification and plan as planning inputs, not unquestioned
   authority. The Product Manager, Team Lead, Principal Architect, and Sceptical
   Architect still check scope, acceptance criteria, boundaries, dependencies,
   risks, contracts, task metadata, and implementation order.
6. Create the [feature] and [tasks] only after the normal Startup Factory
   planning approvals. Then run the pre-flight design pass and normal team
   lifecycle through verified production.

The handoff binds the exact committed specification, plan, plugin id, repository
commit, and execution owner. If either document changes, recreate the handoff
and repeat the affected planning approvals.

`bin/superpowers-planning.py` remains the compatibility entry point for existing
callers. Existing valid schema-v2 Claude/Superpowers handoffs remain usable when
that provider is selected; do not relabel one as EGM or native. New integrations
should use `bin/planning.py`. Changing the provider or artifact content requires
a new handoff for the selected provider.

## Claude task-worker methods

Claude task workers may invoke these focused Superpowers skills where relevant:

- `superpowers:test-driven-development`;
- `superpowers:systematic-debugging`;
- `superpowers:receiving-code-review`;
- `superpowers:verification-before-completion`.

These skills improve the method used inside one assigned task. They never expand
scope, launch their own implementation team, create a second worktree, merge,
finish the branch, or claim completion without Startup Factory artifacts and
gates.
