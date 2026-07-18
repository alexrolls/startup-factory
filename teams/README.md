# Preset Teams

Six ready-to-launch engineering teams. Each team is a roster of specialized
roles (`teams/roles/`) + the shared collaboration flow (`_PLAYBOOK.md`) + the
orchestration protocol (`reference/orchestration.md`). Team files are *data*:
the protocol's claiming, markers, statuses, and integration rules apply
unchanged — a specialized role always states which protocol role(s) it acts as.

| Preset | File | Use when |
|---|---|---|
| Full Stack | `full-stack.md` | Product features cutting through schema, API, and UI — the default |
| Deep Backend | `deep-backend.md` | Domain logic, data models, APIs, performance — little or no UI |
| Deep Frontend | `deep-frontend.md` | UI architecture, complex client state, design-system work |
| Deep Security | `deep-security.md` | Security features, hardening, threat-model-driven work on your own codebase |
| Deep Infra | `deep-infra.md` | Cloud infrastructure, delivery pipelines, reliability and operability |
| Deep LLM | `deep-llm.md` | LLM systems, data science, RAG, evaluation, serving, and LLM product work |

Every team carries four distinct mandatory review-board agents: **Team Lead**,
**Principal Architect**, **Sceptical Principal Architect**, and **Senior
Security Engineer**. All four independently approve the exact review package
before the standard `integrator` may merge. QA and other specialists are
optional evidence/finding roles.

## Use a team

1. Configure your tracker (`config/project-management.config.md`; the shipped
   default is `TEAM_MODE=true`) and the team layer (`config/team.config.md`): set
   `TEAM_DEFAULT_CMD` — roles with no `<ROLE>_CMD` key of their own fall back to
   it, so you don't need a key per role. Add `<ROLE>_CMD` (e.g.
   `SENIOR_STAFF_ENGINEER_CMD`) only to pin a specific CLI to a specific role; set
   it explicitly to `null` to disable an optional role (a `team` launch skips
   it). The Sceptical Architect and Senior Security Engineer are mandatory and
   cannot be disabled. Pick
   `EXECUTION` too: `sequential` (default — one [task] worker in flight at a
   time) or `parallel` (dependency/resource-safe waves bounded by
   `MAX_ACTIVE_IMPLEMENTERS`). Both modes isolate every attempt on a task branch
   and worktree; use `parallel` only after the checklist in
   `reference/orchestration.md` → *Execution modes* has passed.
   Presets whose rosters carry more than one implementation-capable role (e.g.
   Deep Infra's cloud + SRE engineers, Deep Security's engineer + pen-tester)
   are still safe under `sequential` **because** claims come only from the
   lead's single dispatch point — but they work one at a time; choose
   `parallel` to actually use them concurrently.
2. Launch the whole roster:

   ```bash
   bin/launch-team.sh team <preset> <feature-branch> <featureId>
   # e.g.
   bin/launch-team.sh team deep-backend payments-revamp ENG-100
   ```

   Each member's startup prompt is composed from: its role brief + the team file
   + this directory's `_PLAYBOOK.md` + `reference/orchestration.md` + the team
   config. Watch agents in tmux (`tmux attach -t team-<feature-branch>`).

   Running the team as subagents inside your own harness instead? Compose each
   member's prompt without spawning and spawn natively (see
   `reference/orchestration.md` → *Harness mode*):

   ```bash
   bin/launch-team.sh compose <feature-branch> <featureId> <role> <preset>
   ```
3. Relaunch a single member (keeps team context):
   `bin/launch-team.sh relaunch <feature-branch> <featureId> <role> <preset>`.

## Add a team or a role

- **New team:** copy an existing team file; keep the section shape — charter,
  `ROSTER=` line (space-separated role names the launcher resolves), roster
  table with protocol mappings, team-specific review stages, launch line.
  Include exactly one distinct mapping and roster member for
  `PROTOCOL_TEAM_LEAD`, `PROTOCOL_PRINCIPAL_ARCHITECT`,
  `PROTOCOL_SCEPTICAL_ARCHITECT`, and `PROTOCOL_SECURITY_REVIEWER`, plus
  `integrator`; the launcher rejects the preset before any team process starts
  if a mandatory reviewer is missing, duplicated, disabled, unlaunchable, or
  mapped to the same concrete agent. Optionally declare a review mode
  (`REVIEW_MODE=sequential|parallel|tiered` — see `_PLAYBOOK.md` → *Review
  modes*; absent = `sequential`).
- **Identity:** specialized roles sign with their specialized name everywhere;
  when writing a protocol-role marker they state the mapping once per [task] if
  it isn't already on record (`reference/orchestration.md` → *Identity*).
- **New role:** add `teams/roles/<kebab-name>.md` with the standard sections —
  identity, **Protocol mapping**, Responsibilities, Decision authority,
  Deliverables, Handoffs, You never. The launcher resolves any role name that
  has a brief in `roles/` or `teams/roles/`; its command comes from
  `<ROLE>_CMD` or the `TEAM_DEFAULT_CMD` fallback.
- Keep the generic vocabulary (`[feature]`, `[task]`, statuses) and the exact
  protocol markers — never invent new markers.
