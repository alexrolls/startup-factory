# Team: Deep Backend

A four-role team for work that lives entirely in the backend: domain logic, data
models, APIs, migrations, and performance or scale concerns. Use this preset when
there is little or no UI surface — the deliverable is a correct, safe, and
performant service boundary.

```
ROSTER=principal-backend-architect senior-technical-product-manager senior-staff-engineer senior-qa-engineer integrator
```

## Roster

| Role | Brief | Protocol mapping | Charter |
|---|---|---|---|
| Principal Backend Architect — **leads** | `teams/roles/principal-backend-architect.md` | `team-lead` + `principal-architect` | All technical decisions; runs the team |
| Senior Technical Product Manager | `teams/roles/senior-technical-product-manager.md` | no status writes | Scope and acceptance criteria |
| Senior Staff Engineer | `teams/roles/senior-staff-engineer.md` | `backend` | Implements domain logic, APIs, and migrations |
| Senior QA Engineer — **final gate** | `teams/roles/senior-qa-engineer.md` | `qa` + `reviewer` | Verifies acceptance criteria; last approval |
| integrator (standard) | `roles/integrator.md` | `integrator` | Mechanical merge gate; commit + `[Completed]` |

## Collaboration flow

The standard playbook (`teams/_PLAYBOOK.md`); one team-specific rule: every
migration [task] must include a tested rollback [subtask]. The rollback path is
verified by QA before `[review-approval]` is granted — no exceptions.

## Review order

1. Architect — `[architecture-approval]`
2. QA — `[review-approval]` (**final gate**)

Then the `integrator` merges, commits, and marks the [task] `[Completed]`.

## Launch

```bash
bin/launch-team.sh team deep-backend <feature-branch> <featureId>
```
