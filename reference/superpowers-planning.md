# Claude + obra/superpowers planning

Use this workflow only when all of the following are true:

1. `USE_SUPERPOWERS=true` in `config/planning.config.md`.
2. The current runtime is Claude Code.
3. `bin/superpowers-planning.py preflight --runtime claude` succeeds.

Non-Claude runtimes and projects with the flag disabled use the native Startup
Factory lifecycle without emulating or copying Superpowers.

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

1. `superpowers:brainstorming` — clarify intent, compare approaches, obtain human
   design approval, and write the specification under the configured spec root.
2. `superpowers:writing-plans` — turn the approved specification into a detailed
   implementation plan under the configured plan root.

Startup Factory owns everything after that:

- cross-functional planning review and task shaping;
- project-management creation and status transitions;
- design gates and contract registration;
- task packets, branches, worktrees, and dispatch;
- implementation, four-party review, and integration;
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
   python3 bin/superpowers-planning.py preflight --runtime claude
   ```

2. Invoke `superpowers:brainstorming`. Follow its human approval gates. Do not
   create tracker work or launch implementation agents during brainstorming.
3. Invoke `superpowers:writing-plans` after the written specification is
   approved. Let it write and self-review the implementation plan.
4. Do not offer or start a Superpowers execution mode. Instead create the
   digest-bound handoff:

   ```bash
   bin/launch-team.sh planning-handoff <team> <spec-path> <plan-path>
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
