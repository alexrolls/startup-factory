# Team: Deep Frontend

A five-role team for work that lives entirely in the UI layer: component
architecture, complex client state, design-system work, accessibility, and
rendering performance. Use this preset when the deliverable is a correct,
accessible, and performant frontend — the backend contract is stable or can
be mocked until `[api-ready]` arrives.

```
ROSTER=principal-frontend-architect sceptical-architect senior-technical-product-manager senior-frontend-engineer senior-qa-engineer integrator
PROTOCOL_TEAM_LEAD=principal-frontend-architect
PROTOCOL_PRODUCT_MANAGER=senior-technical-product-manager
PROTOCOL_PRINCIPAL_ARCHITECT=principal-frontend-architect
PROTOCOL_SCEPTICAL_ARCHITECT=sceptical-architect
PROTOCOL_REVIEWER=senior-qa-engineer
PROTOCOL_QA=senior-qa-engineer
PROTOCOL_INTEGRATOR=integrator
PROTOCOL_FRONTEND=senior-frontend-engineer
```

## Roster

| Role | Brief | Protocol mapping | Charter |
|---|---|---|---|
| Principal Frontend Architect — **leads** | `teams/roles/principal-frontend-architect.md` | `team-lead` + `principal-architect` | All technical decisions; runs the team |
| Sceptical Architect — **independent gate** | `roles/sceptical-architect.md` | `sceptical-architect` | Blind-first design challenge and release-bound architecture review |
| Senior Technical Product Manager | `teams/roles/senior-technical-product-manager.md` | no status writes | Scope and acceptance criteria |
| Senior Frontend Engineer | `teams/roles/senior-frontend-engineer.md` | `frontend` | Implements components, state wiring, and accessibility |
| Senior QA Engineer — **final gate** | `teams/roles/senior-qa-engineer.md` | `qa` + `reviewer` | Verifies acceptance criteria; last approval |
| integrator (standard) | `roles/integrator.md` | `integrator` | Mechanical merge gate; commit + `[Ready to deploy]` |

## Collaboration flow

The standard playbook (`teams/_PLAYBOOK.md`); one team-specific rule: every
[task]'s acceptance criteria must include explicit accessibility expectations
(WCAG level, interaction patterns, or assistive-technology behaviour), and QA
verifies them the same way it verifies any other criterion — with a `file:line`
citation and a test citation.

## Review order

1. Architect — `[architecture-approval]`
2. Sceptical Architect — `[sceptical-architecture-approval]`
3. QA — `[review-approval]` (**final gate**)

Then the `integrator` merges, commits, and marks the [task] `[Ready to deploy]`.

## Launch

```bash
bin/launch-team.sh team deep-frontend <feature-branch> <featureId>
```
