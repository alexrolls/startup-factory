# Team: Deep Backend

A five-role team for work that lives entirely in the backend: domain logic, data
models, APIs, migrations, and performance or scale concerns. Use this preset when
there is little or no UI surface — the deliverable is a correct, safe, and
performant service boundary.

```
ROSTER=principal-backend-architect sceptical-architect senior-technical-product-manager senior-staff-engineer senior-qa-engineer integrator
PROTOCOL_TEAM_LEAD=principal-backend-architect
PROTOCOL_PRODUCT_MANAGER=senior-technical-product-manager
PROTOCOL_PRINCIPAL_ARCHITECT=principal-backend-architect
PROTOCOL_SCEPTICAL_ARCHITECT=sceptical-architect
PROTOCOL_REVIEWER=senior-qa-engineer
PROTOCOL_QA=senior-qa-engineer
PROTOCOL_INTEGRATOR=integrator
PROTOCOL_BACKEND=senior-staff-engineer
```

## Roster

| Role | Brief | Protocol mapping | Charter |
|---|---|---|---|
| Principal Backend Architect — **leads** | `teams/roles/principal-backend-architect.md` | `team-lead` + `principal-architect` | All technical decisions; runs the team |
| Sceptical Architect — **independent gate** | `roles/sceptical-architect.md` | `sceptical-architect` | Blind-first design challenge and release-bound architecture review |
| Senior Technical Product Manager | `teams/roles/senior-technical-product-manager.md` | no status writes | Scope and acceptance criteria |
| Senior Staff Engineer | `teams/roles/senior-staff-engineer.md` | `backend` | Implements domain logic, APIs, and migrations |
| Senior QA Engineer — **final gate** | `teams/roles/senior-qa-engineer.md` | `qa` + `reviewer` | Verifies acceptance criteria; last approval |
| integrator (standard) | `roles/integrator.md` | `integrator` | Mechanical merge gate; commit + `[Ready to deploy]` |

## Collaboration flow

The standard playbook (`teams/_PLAYBOOK.md`); one team-specific rule: every
migration [task] must include a tested rollback [subtask]. The rollback path is
verified by QA before `[review-approval]` is granted — no exceptions.

## Review order

1. Architect — `[architecture-approval]`
2. Sceptical Architect — `[sceptical-architecture-approval]`
3. QA — `[review-approval]` (**final gate**)

Then the `integrator` merges, commits, and marks the [task] `[Ready to deploy]`.

## Launch

```bash
bin/launch-team.sh team deep-backend <feature-branch> <featureId>
```
