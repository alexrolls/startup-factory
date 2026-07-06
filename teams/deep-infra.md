# Team: Deep Infra

A five-role team for work that lives in cloud infrastructure: environment topology,
infrastructure-as-code, delivery pipelines, reliability engineering, and
operability. Use this preset when the deliverable is a safe, observable, and
cost-efficient platform layer — not a product feature.

```
ROSTER=principal-cloud-infrastructure-architect senior-technical-product-manager senior-cloud-engineer senior-sre-engineer senior-qa-engineer integrator
```

## Roster

| Role | Brief | Protocol mapping | Charter |
|---|---|---|---|
| Principal Cloud and Infrastructure Architect — **leads** | `teams/roles/principal-cloud-infrastructure-architect.md` | `team-lead` + `principal-architect` | All technical decisions; runs the team |
| Senior Technical Product Manager | `teams/roles/senior-technical-product-manager.md` | no status writes | Scope and acceptance criteria |
| Senior Cloud Engineer | `teams/roles/senior-cloud-engineer.md` | `backend` | Implements IaC, pipelines, cloud services, and networking |
| Senior SRE Engineer | `teams/roles/senior-sre-engineer.md` | `backend` (own [tasks]); `reviewer` (operability pass on cloud engineer's [tasks]) | Observability, SLOs, alerting, runbooks; operability review |
| Senior QA Engineer — **final gate** | `teams/roles/senior-qa-engineer.md` | `qa` + `reviewer` | Verifies acceptance criteria; last approval |
| integrator (standard) | `roles/integrator.md` | `integrator` | Mechanical merge gate; commit + `[Ready to deploy]` |

## Collaboration flow

The standard playbook (`teams/_PLAYBOOK.md`); one team-specific rule: every
`[design-note]` — whether from the cloud engineer or the SRE engineer — must
explicitly state the **rollback strategy** and **blast radius** before the
architect will grant `[design-approved]`. No exceptions.

## Review order

1. Architect — `[architecture-approval]`
2. SRE Engineer — operability pass (plain comment listing what was checked, or
   `[review-findings]` if problems exist; skipped on the SRE's own [tasks], which
   the architect covers instead)
3. QA — `[review-approval]` (**final gate**; QA verifies the SRE operability pass
   exists on cloud-engineer [tasks] before approving)

Then the `integrator` merges, commits, and marks the [task] `[Ready to deploy]`.

## Launch

```bash
bin/launch-team.sh team deep-infra <feature-branch> <featureId>
```
