# Team: Full Stack

A four-role team for product features that cut through the whole stack — schema
to API to UI. The default preset when the work isn't deeply specialized.

```
ROSTER=principal-software-architect senior-technical-product-manager senior-full-stack-engineer senior-qa-engineer integrator
```

## Roster

| Role | Brief | Protocol mapping | Charter |
|---|---|---|---|
| Principal Software Architect — **leads** | `teams/roles/principal-software-architect.md` | `team-lead` + `principal-architect` | All technical decisions; runs the team |
| Senior Technical Product Manager | `teams/roles/senior-technical-product-manager.md` | no status writes | Scope and acceptance criteria |
| Senior Full Stack Engineer | `teams/roles/senior-full-stack-engineer.md` | `backend` + `frontend` | Implements complete vertical slices |
| Senior QA Engineer — **final gate** | `teams/roles/senior-qa-engineer.md` | `qa` + `reviewer` | Verifies acceptance criteria; last approval |
| integrator (standard) | `roles/integrator.md` | `integrator` | Mechanical merge gate; commit + `[Ready to deploy]` |

## Collaboration flow

The standard playbook (`teams/_PLAYBOOK.md`); no team-specific stages.

## Review order

1. Architect — `[architecture-approval]`
2. QA — `[review-approval]` (**final gate**)

Then the `integrator` merges, commits, and marks the [task] `[Ready to deploy]`.

## Launch

```bash
bin/launch-team.sh team full-stack <feature-branch> <featureId>
```
