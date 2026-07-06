# Team: Deep Security

A six-role team for security-feature development, codebase hardening, and
threat-model-driven work — including authorized adversarial verification of the
team's own changes. Use when the primary deliverable is a security property of
the codebase itself.

```
ROSTER=principal-security-architect senior-technical-product-manager senior-security-engineer senior-penetration-tester senior-qa-engineer integrator
```

## Roster

| Role | Brief | Protocol mapping | Charter |
|---|---|---|---|
| Principal Security Architect — **leads** | `teams/roles/principal-security-architect.md` | `team-lead` + `principal-architect` | All security-technical decisions; writes the threat model; runs the team |
| Senior Technical Product Manager | `teams/roles/senior-technical-product-manager.md` | no status writes | Scope and acceptance criteria; co-authors the threat model |
| Senior Security Engineer | `teams/roles/senior-security-engineer.md` | `backend` | Implements security features, hardening, and vulnerability fixes |
| Senior Penetration Tester | `teams/roles/senior-penetration-tester.md` | specialist reviewer (stage 5.2); `qa` for test-tooling [tasks] | Authorized adversarial verification of the team's own implemented changes |
| Senior QA Engineer — **final gate** | `teams/roles/senior-qa-engineer.md` | `qa` + `reviewer` | Verifies acceptance criteria; confirms pentest pass exists; last approval |
| integrator (standard) | `roles/integrator.md` | `integrator` | Mechanical merge gate; commit + `[Completed]` |

## Collaboration flow

The standard playbook (`teams/_PLAYBOOK.md`), plus one team-specific stage
inserted between Intake and Planning:

**Threat model (planning).** Before any [task] is created, the Principal
Security Architect and the TPM jointly produce a threat model for the [feature]:
assets, trust boundaries, identified threats, and mitigations. Each mitigation
maps directly to a [task] acceptance criterion. The TPM must approve the threat
model's scope before the architect creates [tasks] in the tracker. [tasks] that
address threat-model mitigations must name the mitigation ID(s) in their
acceptance criteria so QA and the penetration tester can trace coverage.

## Review order

1. Architect — `[architecture-approval]`
2. Penetration tester — authorized adversarial pass against the feature branch
   (plain comment listing what was attempted and that it held, or
   `[review-findings]` with reproduction steps and severity)
3. QA — `[review-approval]` (**final gate**; QA verifies the pentest pass comment
   exists before issuing its approval)

Then the `integrator` merges, commits, and marks the [task] `[Completed]`.

## Launch

```bash
bin/launch-team.sh team deep-security <feature-branch> <featureId>
```
