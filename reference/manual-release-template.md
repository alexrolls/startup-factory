# Manual release runbook template

Use this template when the protected release hooks are not yet fully automated
and a human operator needs an explicit, reviewable procedure. The completed
runbook is planning evidence only: it does not grant production authority,
replace `verifyCi`/`verifyApproval`/`verifyDelivery`, expose credentials to an
agent, or permit direct provider commands outside the protected executor.

Store the completed runbook with the release-owned artifacts and bind it to the
exact release commit and manifest digest.

## Identity and scope

- Environment and target:
- Release id:
- Feature id:
- Exact 40-character commit:
- Artifact/package digest:
- Integration-evidence digest:
- Product-acceptance digest:
- Runbook owner:
- Operator and independent approver:
- Planned window:
- Explicit non-goals:

## Preconditions

- [ ] Every [task] is terminal with a current exact-package review round.
- [ ] Product acceptance binds the exact feature commit and integration evidence.
- [ ] All required CI/CD checks for that commit are green and current.
- [ ] The protected release plan and policy decision bind this exact target and manifest.
- [ ] Required approval/attestation is current, exact, unexpired, and unused.
- [ ] The previous known-good artifact and rollback procedure are available.
- [ ] Target health, capacity, backups, and change freeze are checked.
- [ ] The operator can observe deploy, activation, probes, and rollback without exposing secrets.

## Deploy steps

List deterministic protected hook steps. For each, record command/hook identity,
expected output, timeout, idempotency key, and stop condition. Do not put secret
values in this document.

1. Materialize/verify artifact:
2. Apply artifact to target:
3. Wait for provider status:

## Environment activation

Code delivery is not necessarily activation. List every required configuration,
cache, index, data, schema, model, prompt, tenant, or routing refresh in execution
order. Name the owner, compatibility direction (old code/new state and new
code/old state), and observable success condition for each. Schema migrations
must be explicit steps; never assume the artifact deploy runs them. If none
apply, state why.

| Order | Activation step | Owner | Compatibility direction | Expected evidence | Failure action |
|---|---|---|---|---|---|
|  |  |  |  |  | stop / rollback / escalate |

## Post-deploy probes

Derive stable probe ids from every acceptance criterion, review condition, and
changed trust boundary. Configure those ids in
`deployment.config.json.verification.requiredProbeIds`. Exercise the real entry
path, declare non-secret preconditions needed to make the probe meaningful, and
include at least one negative/failure-path probe when configured.

| Probe id / acceptance row | Real entry path | Non-secret preconditions | Pass criterion | Evidence digest/location | Failure action |
|---|---|---|---|---|---|
|  |  |  |  |  | stop / rollback / file [task] |

## Rollback

- Trigger thresholds:
- Exact previous artifact/config/data identity:
- Protected rollback hook and idempotency key:
- Data/schema compatibility constraints:
- Rollback verification probes:
- Conditions that require incident escalation instead of retry:

Never blind-retry an uncertain apply. Reconcile protected provider status using
the release id, then continue the same transaction or roll it back.

## Monitoring and closeout

- Monitoring window and owner:
- Signals, dashboards, logs, and alert thresholds:
- Residual risks and review date:
- Evidence archive location:
- Newly discovered work filed as Scenario-6 [tasks]:
- Final verified outcome: succeeded / rolled back / failed / uncertain

Only the protected release executor may project success and perform the terminal
[feature] transition after every activation step and probe passes.
