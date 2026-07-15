#!/usr/bin/env bash
# dispatch smoke test: offline, Markdown adapter, stub agent commands.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; TMP="$(cd "$TMP" && pwd -P)"; trap 'rm -rf "$TMP"' EXIT
FAILURES=0
check() { local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok: $desc"; else echo "FAIL: $desc"; FAILURES=$((FAILURES+1)); fi; }

cd "$TMP"; git init -q repo && cd repo
git commit -q --allow-empty -m init; git checkout -q -b feat-team
LIFECYCLE_ROOT="$TMP/protected-lifecycle"
mkdir -m 700 "$LIFECYCLE_ROOT"
mkdir -p .claude/skills/pm
cp -R "$SKILL_DIR/roles" "$SKILL_DIR/reference" "$SKILL_DIR/bin" "$SKILL_DIR/teams" .claude/skills/pm/
mkdir -p .claude/skills/pm/config
cp "$SKILL_DIR/config/statuses.config.json" "$SKILL_DIR/config/automation.config.json" .claude/skills/pm/config/
cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Markdown
MARKDOWN_ROOT=.
STATUS_CONFIG=config/statuses.config.json
```
EOF
cat > .claude/skills/pm/config/team.config.md <<'EOF'
```
TEAM_DEFAULT_CMD="true"
TEAMWORK_ROOT=.teamwork
AGENT_ENV_ALLOWLIST="PATH TMPDIR LANG LC_ALL TERM"
AGENT_SANDBOX_ENFORCED=false
BROKER_LIFECYCLE_ROOT=__LIFECYCLE_ROOT__
POLL_INTERVAL_SECONDS=1
STUCK_AFTER_MINUTES=15
EXECUTION=sequential
VALIDATE_BUILD=null
VALIDATE_TEST=null
VALIDATE_LINT=null
```
EOF
sed -i '' "s|^BROKER_LIFECYCLE_ROOT=.*|BROKER_LIFECYCLE_ROOT=\"$LIFECYCLE_ROOT\"|" .claude/skills/pm/config/team.config.md
DISPATCH=".claude/skills/pm/bin/dispatch.sh"

mkdir -p feat
cat > feat/feature.md <<'EOF'
# Fixture [Active]

## 1 Done thing [Ready to deploy]

**Assignee:** backend

> [review-request] round 1

> [review-approval] files ok — reviewer

> [architecture-approval] files ok — principal-architect

> [sceptical-architecture-approval] files ok — sceptical-architect

## 2 Blocked thing [Blocked]

**Assignee:** backend
**BlockedBy:** 1

> block-kind: dependency
> blocked-by: 1
> resume-status: Active

## 3 In review [Review]

**Assignee:** backend

> [review-request] please review — backend

## 4 Needs design verdict [Active]

**Assignee:** backend

> [design-note] approach — backend

## 5 Ready to start [Planned]

**Assignee:** —

Independent.

## 6 Dual approved [Review]

**Assignee:** backend

> [review-request] round 1 — backend

> [review-approval] files ok — reviewer

> [architecture-approval] files ok — principal-architect

> [sceptical-architecture-approval] files ok — sceptical-architect
EOF
FID="feat/feature.md"

# -- dry-run prints the full action plan, changes nothing ----------------------
plan="$(TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once --dry-run)"
echo "$plan" | grep -q "keep $FID#2 \[Blocked\].*human-held" \
  && echo "ok: plans human-held block" \
  || { echo "FAIL: blocked task was not held: $plan"; FAILURES=$((FAILURES+1)); }
echo "$plan" | grep -q "launch reviewer" && echo "ok: plans reviewer queue" || { echo "FAIL: reviewer queue"; FAILURES=$((FAILURES+1)); }
echo "$plan" | grep -q "launch principal-architect" && echo "ok: plans PA queue" || { echo "FAIL: PA queue"; FAILURES=$((FAILURES+1)); }
echo "$plan" | grep -q "launch sceptical-architect" && echo "ok: plans independent architecture queue" || { echo "FAIL: sceptical queue"; FAILURES=$((FAILURES+1)); }
echo "$plan" | grep -q "launch team-lead" && echo "ok: plans lead (Planned #5)" || { echo "FAIL: lead launch"; FAILURES=$((FAILURES+1)); }
echo "$plan" | grep -q "launch integrator" && echo "ok: plans integrator merge queue (#6)" || { echo "FAIL: integrator queue"; FAILURES=$((FAILURES+1)); }
check "dry-run does not move status" grep -q '^## 2 Blocked thing \[Blocked\]$' "$FID"
check "dry-run launches nothing"     test ! -d .teamwork/feat-team/pids

# -- PM-supervisor label policy excludes human-owned work but keeps siblings --
cat > feat/human-work.md <<'EOF'
# Human/agent split [Active]

## 1 Manual decision [Planned]

**Assignee:** —
**Labels:** human-work

track: backend
parallel-safe: true
files: src/manual.py

> [design-note] round 1
> - backend
>
> [design-approved] round 1
> - principal-architect
>
> [sceptical-design-approved] round 1
> - sceptical-architect

## 2 Automatic implementation [Planned]

**Assignee:** —

track: backend
parallel-safe: true
files: src/automatic.py

> [design-note] round 1
> - backend
>
> [design-approved] round 1
> - principal-architect
>
> [sceptical-design-approved] round 1
> - sceptical-architect
EOF
HUMAN_FID="feat/human-work.md"
human_plan="$(STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON='["human-work"]' TEAM_RUNNER=background "$DISPATCH" feat-human-team "$HUMAN_FID" --once --dry-run)"
if echo "$human_plan" | grep -q "claim $HUMAN_FID#1"; then
  echo "FAIL: human-work task entered autonomous plan"; FAILURES=$((FAILURES+1))
else
  echo "ok: human-work task is absent from autonomous plan"
fi
echo "$human_plan" | grep -q "claim $HUMAN_FID#2.*backend" \
  && echo "ok: non-human sibling remains automatically claimable" \
  || { echo "FAIL: automatic sibling was not claimed: $human_plan"; FAILURES=$((FAILURES+1)); }

# -- real pass: blocked task stays held while unrelated gate queues still run --
TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once
check "dispatcher never moves Blocked outbound" grep -q '^## 2 Blocked thing \[Blocked\]$' "$FID"
if grep -q 'Auto-unblocked by dispatcher' "$FID"; then
  echo "FAIL: dispatcher left an obsolete auto-unblock comment"; FAILURES=$((FAILURES+1))
else
  echo "ok: dispatcher leaves no auto-unblock comment"
fi
check "reviewer queue in mailbox"    grep -rq "$FID#3" .teamwork/feat-team/mailbox/reviewer/
check "PA queue in mailbox"          grep -rq "$FID#4" .teamwork/feat-team/mailbox/principal-architect/
check "sceptical queue in mailbox"   grep -rq "$FID#4" .teamwork/feat-team/mailbox/sceptical-architect/
check "reviewer launched"            test -f .teamwork/feat-team/pids/reviewer.pid

# -- agent-writable PID text is not a liveness authority -----------------------
mkdir -p .teamwork/feat-team/pids
echo $$ > .teamwork/feat-team/pids/reviewer.pid
plan2="$(TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once --dry-run)"
echo "$plan2" | grep -q "launch reviewer" \
  && echo "ok: workspace PID spoof cannot suppress protected liveness lookup" \
  || { echo "FAIL: workspace PID spoof affected dedup"; FAILURES=$((FAILURES+1)); }

# -- legacy unblock option is a compatibility no-op, never an authority -------
legacy_out="$(TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once --dry-run --unblock=auto 2>&1)"
echo "$legacy_out" | grep -q "deprecated and ignored.*human-only" \
  && echo "ok: legacy unblock option reports human-only policy" \
  || { echo "FAIL: legacy unblock option was not safely deprecated: $legacy_out"; FAILURES=$((FAILURES+1)); }
check "legacy unblock option cannot move Blocked" grep -q '^## 2 Blocked thing \[Blocked\]$' "$FID"

# -- anomaly: [Review] task with no [review-request] routes to team-lead -------
cat >> "$FID" <<'EOF'

## 7 Anomalous review [Review]

**Assignee:** backend

Independent, no comments.
EOF
plan4="$(TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once --dry-run)"
echo "$plan4" | grep -q "anomalous" \
  && echo "ok: anomalous [Review] routed to team-lead" || { echo "FAIL: anomalous [Review] not in lead detail"; FAILURES=$((FAILURES+1)); }
echo "$plan4" | grep "launch reviewer" | grep -q "#7" \
  && { echo "FAIL: #7 incorrectly in reviewer queue"; FAILURES=$((FAILURES+1)); } || echo "ok: #7 not in reviewer queue"
echo "$plan4" | grep "launch principal-architect" | grep -q "#7" \
  && { echo "FAIL: #7 incorrectly in PA queue"; FAILURES=$((FAILURES+1)); } || echo "ok: #7 not in PA queue"

# -- nothing actionable exits cleanly ------------------------------------------
cat > feat/quiet.md <<'EOF'
# Quiet [Active]

## 1 Done [Ready to deploy]

**Assignee:** backend
EOF
out="$("$DISPATCH" feat-quiet-team feat/quiet.md --once --dry-run)"
echo "$out" | grep -q "nothing actionable" && echo "ok: clean exit" || { echo "FAIL: clean exit"; FAILURES=$((FAILURES+1)); }

# -- all-terminal product closeout routes exact release request -----------------
cat > feat/product-close.md <<'EOF'
# Product Close [Active]

## 1 Integrated [Ready to deploy]

**Assignee:** backend
EOF
PRODUCT_FID="feat/product-close.md"
PRODUCT_TEAM="feat-product-team"
mkdir -p ".teamwork/$PRODUCT_TEAM"
cat > ".teamwork/$PRODUCT_TEAM/preset.env" <<'EOF'
PRESET=full-stack
PROTOCOL_TEAM_LEAD=principal-software-architect
PROTOCOL_PRODUCT_MANAGER=senior-technical-product-manager
EOF
python3 - "$PRODUCT_FID" ".teamwork/$PRODUCT_TEAM/product-acceptance-request.json" ".claude/skills/pm/bin" <<'PY'
import json,sys
sys.path.insert(0,sys.argv[3])
from product_acceptance import request_payload
fid,out=sys.argv[1:3]
snapshot={'featureId':fid,'tasks':[{'taskId':fid+'#1','comments':[]}]}
payload=request_payload(snapshot,feature_id=fid,commit='a'*40,
                        integration_evidence_digest='sha256:'+'b'*64,reason='missing')
json.dump(payload,open(out,'w'),indent=2)
PY
product_plan="$(TEAM_RUNNER=background "$DISPATCH" "$PRODUCT_TEAM" "$PRODUCT_FID" --once --dry-run)"
echo "$product_plan" | grep -q "launch product-manager (→senior-technical-product-manager)" \
  && echo "ok: product closeout routes configured product-manager" \
  || { echo "FAIL: product closeout not routed: $product_plan"; FAILURES=$((FAILURES+1)); }
python3 - "$PRODUCT_FID" ".teamwork/$PRODUCT_TEAM/product-acceptance-request.json" <<'PY'
import json,sys
path,request_path=sys.argv[1:]
body=json.load(open(request_path))['canonicalBody']
with open(path,'a') as handle:
    handle.write('\n\n'+'\n'.join('> '+line for line in body.splitlines())+'\n')
PY
approved_plan="$(TEAM_RUNNER=background "$DISPATCH" "$PRODUCT_TEAM" "$PRODUCT_FID" --once --dry-run)"
if echo "$approved_plan" | grep -q "launch product-manager"; then
  echo "FAIL: exact product approval did not close queue"; FAILURES=$((FAILURES+1))
else
  echo "ok: exact product approval closes product queue"
fi
cat >> "$PRODUCT_FID" <<'EOF'

> [product-pushback]
> reason: feature criterion regressed
EOF
pushback_plan="$(TEAM_RUNNER=background "$DISPATCH" "$PRODUCT_TEAM" "$PRODUCT_FID" --once --dry-run)"
echo "$pushback_plan" | grep -q "launch product-manager" \
  && echo "ok: later product pushback reopens closeout" \
  || { echo "FAIL: later product pushback did not reopen closeout"; FAILURES=$((FAILURES+1)); }

FALLBACK_TEAM="feat-product-fallback"
mkdir -p ".teamwork/$FALLBACK_TEAM"
cp ".teamwork/$PRODUCT_TEAM/product-acceptance-request.json" ".teamwork/$FALLBACK_TEAM/product-acceptance-request.json"
fallback_plan="$(TEAM_RUNNER=background "$DISPATCH" "$FALLBACK_TEAM" "$PRODUCT_FID" --once --dry-run)"
echo "$fallback_plan" | grep -q "launch team-lead" \
  && echo "ok: no product role falls back to team-lead" \
  || { echo "FAIL: missing product-role fallback: $fallback_plan"; FAILURES=$((FAILURES+1)); }

# -- null-CMD: skips launch instead of dying, no mailbox written ---------------
# Inject REVIEWER_CMD=null into the fixture config so the reviewer role is disabled.
printf '\nREVIEWER_CMD=null\n' >> .claude/skills/pm/config/team.config.md
# Restore task 3 to [Review] in case earlier blocks altered it.
sed -i '' 's/^## 3 In review \[.*\]$/## 3 In review [Review]/' "$FID"
# Clear reviewer pid and mailbox so this is a clean slate for the assertion.
rm -rf .teamwork/feat-team/pids/reviewer.pid .teamwork/feat-team/mailbox/reviewer
null_out="$(TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once)"
echo "$null_out" | grep -q "skipped (REVIEWER_CMD=null" \
  && echo "ok: null-CMD reviewer skipped" || { echo "FAIL: null-CMD reviewer not skipped"; FAILURES=$((FAILURES+1)); }
check "null-CMD: reviewer.pid not created" test ! -f .teamwork/feat-team/pids/reviewer.pid
check "null-CMD: reviewer mailbox not written" test ! -d .teamwork/feat-team/mailbox/reviewer
# Remove the injected line to leave the config clean for any future assertions.
sed -i '' '/^REVIEWER_CMD=null$/d' .claude/skills/pm/config/team.config.md

# -- tracker comments cannot grant automated authority to leave Blocked -------
cat > feat/human-held.md <<'EOF'
# Human-held fixture [Active]

## 1 Finished dependency [Ready to deploy]

**Assignee:** backend

Done.

## 2 Human-held ticket [Blocked]

**Assignee:** backend
**BlockedBy:** 1

> block-kind: dependency
> blocked-by: 1
> resume-status: Active

## 3 Independent Todo [Planned]

**Assignee:** —

track: backend

> [design-note] ready — backend

> [design-approved] approved — principal-architect

> [sceptical-design-approved] approved — sceptical-architect

## 4 Potential dependent [Planned]

**Assignee:** —
**BlockedBy:** 2

track: backend

> [design-note] ready — backend

> [design-approved] approved — principal-architect

> [sceptical-design-approved] approved — sceptical-architect
EOF
HELD_FID="feat/human-held.md"
held_plan="$(TEAM_RUNNER=background "$DISPATCH" feat-human-held "$HELD_FID" --once --dry-run)"
echo "$held_plan" | grep -q "keep $HELD_FID#2 \[Blocked\].*human-held" \
  && echo "ok: resume-status metadata cannot release a human hold" \
  || { echo "FAIL: human hold missing from plan: $held_plan"; FAILURES=$((FAILURES+1)); }
echo "$held_plan" | grep -q "claim $HELD_FID#3.*backend" \
  && echo "ok: human-held ticket does not stop independent Todo work" \
  || { echo "FAIL: independent Todo not dispatched: $held_plan"; FAILURES=$((FAILURES+1)); }
if echo "$held_plan" | grep -q "claim $HELD_FID#4"; then
  echo "FAIL: dependent Todo was dispatched through a Blocked prerequisite"; FAILURES=$((FAILURES+1))
else
  echo "ok: dependent Todo remains undispatched"
fi
echo "$held_plan" | grep -q "possible downstream impact: $HELD_FID#4" \
  && echo "ok: queued direct dependent is sent for lead dependency review" \
  || { echo "FAIL: queued direct dependent was not routed for dependency review: $held_plan"; FAILURES=$((FAILURES+1)); }
git branch feat-human-held
TEAM_RUNNER=background "$DISPATCH" feat-human-held "$HELD_FID" --once >/dev/null
check "resume-status metadata leaves task Blocked" grep -q '^## 2 Human-held ticket \[Blocked\]$' "$HELD_FID"
check "independent Todo is claimed"              grep -q '^## 3 Independent Todo \[Active\]$' "$HELD_FID"
check "dependent stays queued pending lead verdict" grep -q '^## 4 Potential dependent \[Planned\]$' "$HELD_FID"

# -- D2.5: Linear+MCP → dispatch fails before tracker-ops ----------------------
cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Linear
LINEAR_ACCESS=mcp                 # mcp = Linear MCP server
STATUS_CONFIG=config/statuses.config.json
```
EOF
if mcp_d_out="$(TEAM_RUNNER=background "$DISPATCH" feat-team-mcp "$FID" --once --dry-run 2>&1)"; then
  echo "FAIL: Linear+MCP dispatch should exit non-zero"; FAILURES=$((FAILURES+1))
elif echo "$mcp_d_out" | grep -q "dispatch requires scriptable tracker access"; then
  echo "ok: Linear+MCP dispatch fails with scriptable-access message"
else
  echo "FAIL: wrong dispatch MCP error: $mcp_d_out"; FAILURES=$((FAILURES+1))
fi
# Negative guard: false MCP flag with shipped inline-comment format must NOT trip the MCP guard
cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=GitHubIssues
GITHUB_USE_MCP=false              # false = gh CLI
STATUS_CONFIG=config/statuses.config.json
```
EOF
neg_d_out="$(TEAM_RUNNER=background "$DISPATCH" feat-team-gh "$FID" --once --dry-run 2>&1 || true)"
if echo "$neg_d_out" | grep -q "dispatch requires scriptable tracker access"; then
  echo "FAIL: GITHUB_USE_MCP=false incorrectly triggered MCP guard"; FAILURES=$((FAILURES+1))
else
  echo "ok: GITHUB_USE_MCP=false (with inline comment) not treated as MCP-only"
fi
# restore to Markdown
cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Markdown
MARKDOWN_ROOT=.
STATUS_CONFIG=config/statuses.config.json
```
EOF

# -- D3.8: preset routing + signer check ---------------------------------------
cat > feat/preset-test.md <<'EOF'
# Preset Test [Active]

## 1 Design pending [Active]

**Assignee:** senior-full-stack-engineer

> [design-note] approach — senior-full-stack-engineer
EOF
PT_FID="feat/preset-test.md"
mkdir -p .teamwork/feat-preset-team
cat > .teamwork/feat-preset-team/preset.env <<'EOF'
PRESET=full-stack
PROTOCOL_TEAM_LEAD=principal-software-architect
PROTOCOL_PRINCIPAL_ARCHITECT=principal-software-architect
PROTOCOL_SCEPTICAL_ARCHITECT=sceptical-architect
PROTOCOL_REVIEWER=senior-qa-engineer
PROTOCOL_QA=senior-qa-engineer
PROTOCOL_INTEGRATOR=integrator
PROTOCOL_BACKEND=senior-full-stack-engineer
PROTOCOL_FRONTEND=senior-full-stack-engineer
EOF
preset_plan="$(TEAM_RUNNER=background "$DISPATCH" feat-preset-team "$PT_FID" --once --dry-run 2>&1)"
echo "$preset_plan" | grep -q "launch principal-architect (→principal-software-architect)" \
  && echo "ok: preset: PA routes to principal-software-architect" \
  || { echo "FAIL: preset routing wrong; plan: $preset_plan"; FAILURES=$((FAILURES+1)); }
# real pass: concrete-role pid written, generic protocol-role pid absent
TEAM_RUNNER=background "$DISPATCH" feat-preset-team "$PT_FID" --once
check "preset: concrete role pid written"   test -f .teamwork/feat-preset-team/pids/principal-software-architect.pid
check "preset: generic protocol pid absent" test ! -f .teamwork/feat-preset-team/pids/principal-architect.pid

# D3.8.2+3: signer check
cat > feat/signer-test.md <<'EOF'
# Signer Test [Active]

## 1 Terminal [Ready to deploy]

**Assignee:** senior-full-stack-engineer

Done.

## 2 Generic reviewer [Review]

**Assignee:** senior-full-stack-engineer

> [review-request] ready — senior-full-stack-engineer

> [review-approval] LGTM — reviewer

> [architecture-approval] LGTM — principal-software-architect

> [sceptical-architecture-approval] LGTM — sceptical-architect

## 3 Preset QA approved [Review]

**Assignee:** senior-full-stack-engineer

> [review-request] ready — senior-full-stack-engineer

> [review-approval] LGTM — senior-qa-engineer

> [architecture-approval] LGTM — principal-software-architect

> [sceptical-architecture-approval] LGTM — sceptical-architect
EOF
SIG_FID="feat/signer-test.md"
mkdir -p .teamwork/feat-signer-team
cat > .teamwork/feat-signer-team/preset.env <<'EOF'
PRESET=full-stack
PROTOCOL_TEAM_LEAD=principal-software-architect
PROTOCOL_PRINCIPAL_ARCHITECT=principal-software-architect
PROTOCOL_SCEPTICAL_ARCHITECT=sceptical-architect
PROTOCOL_REVIEWER=senior-qa-engineer
PROTOCOL_QA=senior-qa-engineer
PROTOCOL_INTEGRATOR=integrator
PROTOCOL_BACKEND=senior-full-stack-engineer
PROTOCOL_FRONTEND=senior-full-stack-engineer
EOF
signer_plan="$(TEAM_RUNNER=background "$DISPATCH" feat-signer-team "$SIG_FID" --once --dry-run 2>&1)"
echo "$signer_plan" | grep -q "signed by 'reviewer', expected preset final gate 'senior-qa-engineer'" \
  && echo "ok: generic reviewer: warning printed" \
  || { echo "FAIL: no signer warning in: $signer_plan"; FAILURES=$((FAILURES+1)); }
echo "$signer_plan" | grep "launch integrator" | grep -qv "signer-test.*#2" \
  && echo "ok: generic reviewer: task 2 not in merge queue" \
  || { echo "FAIL: task 2 incorrectly in merge queue"; FAILURES=$((FAILURES+1)); }
echo "$signer_plan" | grep -q "launch integrator.*signer-test.*#3" \
  && echo "ok: preset QA (task 3) unlocks integrator" \
  || { echo "FAIL: integrator not in plan or missing task 3; plan: $signer_plan"; FAILURES=$((FAILURES+1)); }
echo "$signer_plan" | grep -q "launch team-lead" \
  && echo "ok: generic reviewer: team-lead notified" \
  || { echo "FAIL: team-lead not in plan"; FAILURES=$((FAILURES+1)); }

# -- D2.4: multiline [review-approval] with signer on last line ----------------
cat > feat/ml-signer-test.md <<'EOF'
# Multiline Signer Test [Active]

## 1 Multiline QA approved [Review]

**Assignee:** senior-full-stack-engineer

> [review-request] ready — senior-full-stack-engineer

> [review-approval] round 1
> verdict: approved
> — senior-qa-engineer

> [architecture-approval] LGTM — principal-software-architect

> [sceptical-architecture-approval] LGTM — sceptical-architect

## 2 Multiline generic reviewer [Review]

**Assignee:** senior-full-stack-engineer

> [review-request] ready — senior-full-stack-engineer

> [review-approval] round 1
> verdict: approved
> — reviewer

> [architecture-approval] LGTM — principal-software-architect

> [sceptical-architecture-approval] LGTM — sceptical-architect

## 3 As-role suffix [Review]

**Assignee:** senior-full-stack-engineer

> [review-request] ready — senior-full-stack-engineer

> [review-approval] round 1
> verdict: approved
> — senior-qa-engineer (as reviewer)

> [architecture-approval] LGTM — principal-software-architect

> [sceptical-architecture-approval] LGTM — sceptical-architect

## 4 Posted-by suffix [Review]

**Assignee:** senior-full-stack-engineer

> [review-request] ready — senior-full-stack-engineer

> [review-approval] round 1
> verdict: approved
> — senior-qa-engineer (posted by team-lead)

> [architecture-approval] LGTM — principal-software-architect

> [sceptical-architecture-approval] LGTM — sceptical-architect
EOF
ML_FID="feat/ml-signer-test.md"
mkdir -p .teamwork/feat-ml-team
cat > .teamwork/feat-ml-team/preset.env <<'EOF'
PRESET=full-stack
PROTOCOL_TEAM_LEAD=principal-software-architect
PROTOCOL_PRINCIPAL_ARCHITECT=principal-software-architect
PROTOCOL_SCEPTICAL_ARCHITECT=sceptical-architect
PROTOCOL_REVIEWER=senior-qa-engineer
PROTOCOL_QA=senior-qa-engineer
PROTOCOL_INTEGRATOR=integrator
PROTOCOL_BACKEND=senior-full-stack-engineer
PROTOCOL_FRONTEND=senior-full-stack-engineer
EOF
ml_plan="$(TEAM_RUNNER=background "$DISPATCH" feat-ml-team "$ML_FID" --once --dry-run 2>&1)"
echo "$ml_plan" | grep -q "launch integrator.*ml-signer.*#1" \
  && echo "ok: multiline QA approval unlocks integrator" \
  || { echo "FAIL: multiline QA approval did not unlock integrator; plan: $ml_plan"; FAILURES=$((FAILURES+1)); }
echo "$ml_plan" | grep "launch integrator" | grep -q "ml-signer.*#2" \
  && { echo "FAIL: multiline generic reviewer: task 2 incorrectly in merge queue"; FAILURES=$((FAILURES+1)); } \
  || echo "ok: multiline generic reviewer: task 2 not in merge queue"
echo "$ml_plan" | grep -q "signed by 'reviewer'.*expected preset final gate 'senior-qa-engineer'" \
  && echo "ok: multiline generic reviewer: signer warning printed" \
  || { echo "FAIL: no signer warning for multiline generic reviewer; plan: $ml_plan"; FAILURES=$((FAILURES+1)); }
echo "$ml_plan" | grep -q "launch integrator.*ml-signer.*#3" \
  && echo "ok: (as reviewer) suffix: signer accepted, integrator unlocked" \
  || { echo "FAIL: (as reviewer) suffix not accepted; plan: $ml_plan"; FAILURES=$((FAILURES+1)); }
echo "$ml_plan" | grep -q "launch integrator.*ml-signer.*#4" \
  && echo "ok: (posted by team-lead) suffix: signer accepted, integrator unlocked" \
  || { echo "FAIL: (posted by team-lead) suffix not accepted; plan: $ml_plan"; FAILURES=$((FAILURES+1)); }

# -- bounded parallel scheduler: two same-role task instances, one conflict held --
cat > feat/parallel-test.md <<'EOF'
# Parallel Test [Active]

## 1 Backend A [Planned]

**Assignee:** —

track: backend
parallel-safe: true
files: src/a.py
resources: schema:a

> [design-note] round 1
> - backend
>
> [design-approved] round 1
> - principal-architect
>
> [sceptical-design-approved] round 1
> - sceptical-architect

## 2 Backend B [Planned]

**Assignee:** —

track: backend
parallel-safe: true
files: src/b.py
resources: schema:b

> [design-note] round 1
> - backend
>
> [design-approved] round 1
> - principal-architect
>
> [sceptical-design-approved] round 1
> - sceptical-architect

## 3 Conflicts with A [Planned]

**Assignee:** —

track: backend
parallel-safe: true
files: src
resources: schema:c

> [design-note] round 1
> - backend
>
> [design-approved] round 1
> - principal-architect
>
> [sceptical-design-approved] round 1
> - sceptical-architect
EOF
PAR_FID=feat/parallel-test.md
sed -i '' 's/^EXECUTION=sequential$/EXECUTION=parallel/' .claude/skills/pm/config/team.config.md
printf 'MAX_ACTIVE_IMPLEMENTERS=2\n' >> .claude/skills/pm/config/team.config.md
PAR_TEAM=feat-parallel-team
parallel_plan="$(TEAM_RUNNER=background "$DISPATCH" "$PAR_TEAM" "$PAR_FID" --once --dry-run)"
echo "$parallel_plan" | grep -q "claim $PAR_FID#1.*backend" && echo "ok: parallel scheduler claims task 1" || { echo "FAIL: task 1 not claimed"; FAILURES=$((FAILURES+1)); }
echo "$parallel_plan" | grep -q "claim $PAR_FID#2.*backend" && echo "ok: parallel scheduler claims task 2" || { echo "FAIL: task 2 not claimed"; FAILURES=$((FAILURES+1)); }
echo "$parallel_plan" | grep -q "constrained ready tasks: $PAR_FID#3" && echo "ok: conflicting resource held" || { echo "FAIL: conflict not constrained"; FAILURES=$((FAILURES+1)); }

cat > feat/unsafe-test.md <<'EOF'
# Unsafe Test [Active]

## 1 Exclusive migration [Planned]

**Assignee:** —

track: backend
parallel-safe: false

> [design-note] round 1
> - backend
>
> [design-approved] round 1
> - principal-architect
>
> [sceptical-design-approved] round 1
> - sceptical-architect

## 2 Otherwise parallel safe [Planned]

**Assignee:** —

track: backend
parallel-safe: true
files: src/safe.py

> [design-note] round 1
> - backend
>
> [design-approved] round 1
> - principal-architect
>
> [sceptical-design-approved] round 1
> - sceptical-architect
EOF
UNSAFE_FID=feat/unsafe-test.md
unsafe_plan="$(TEAM_RUNNER=background "$DISPATCH" feat-unsafe-team "$UNSAFE_FID" --once --dry-run)"
echo "$unsafe_plan" | grep -q "claim $UNSAFE_FID#1.*backend" && echo "ok: unsafe task can claim an empty wave" || { echo "FAIL: unsafe task not claimed"; FAILURES=$((FAILURES+1)); }
if echo "$unsafe_plan" | grep -q "claim $UNSAFE_FID#2"; then
  echo "FAIL: scheduler mixed a parallel-safe task into an unsafe wave"; FAILURES=$((FAILURES+1))
else
  echo "ok: unsafe task remains exclusive within its wave"
fi
sed -i '' -e 's/^## 1 Exclusive migration \[Planned\]$/## 1 Exclusive migration [Active]/' \
  -e '/^## 1 Exclusive migration /,/^## 2 /s/^\*\*Assignee:\*\* —$/**Assignee:** backend/' "$UNSAFE_FID"
active_unsafe_plan="$(TEAM_RUNNER=background "$DISPATCH" feat-unsafe-team "$UNSAFE_FID" --once --dry-run)"
if echo "$active_unsafe_plan" | grep -q "claim $UNSAFE_FID#2"; then
  echo "FAIL: scheduler launched beside an active unsafe task"; FAILURES=$((FAILURES+1))
else
  echo "ok: active unsafe task keeps the wave exclusive"
fi
git branch "$PAR_TEAM"
TEAM_RUNNER=background "$DISPATCH" "$PAR_TEAM" "$PAR_FID" --once >/dev/null
check "parallel task 1 becomes Active" grep -q '^## 1 Backend A \[Active\]$' "$PAR_FID"
check "parallel task 2 becomes Active" grep -q '^## 2 Backend B \[Active\]$' "$PAR_FID"
check "conflicting task remains Planned" grep -q '^## 3 Conflicts with A \[Planned\]$' "$PAR_FID"
check "same role gets two isolated worktrees" test "$(find ".teamwork/$PAR_TEAM/worktrees" -maxdepth 1 -type d -name 'backend#1-*' | wc -l | tr -d ' ')" -ge 2
check "two execution records persisted" test "$(find ".teamwork/$PAR_TEAM/executions" -type f -name '*.json' | wc -l | tr -d ' ')" -ge 2
sed -i '' '/^MAX_ACTIVE_IMPLEMENTERS=2$/d;s/^EXECUTION=parallel$/EXECUTION=sequential/' .claude/skills/pm/config/team.config.md

# -- a first successful claim advances the feature lifecycle -----------------
cat > feat/activation-test.md <<'EOF'
# Activation Test [Planned]

## 1 First implementation [Planned]

**Assignee:** —

track: backend
parallel-safe: true
files: src/activation.py

> [design-note] round 1
> - backend
>
> [design-approved] round 1
> - principal-architect
>
> [sceptical-design-approved] round 1
> - sceptical-architect
EOF
ACT_FID=feat/activation-test.md
git branch feat-activation-team
TEAM_RUNNER=background "$DISPATCH" feat-activation-team "$ACT_FID" --once >/dev/null
check "first claim moves queued feature to Active" grep -q '^# Activation Test \[Active\]$' "$ACT_FID"
check "first claim still moves task to Active" grep -q '^## 1 First implementation \[Active\]$' "$ACT_FID"

# -- planner never follows agent-controlled execution/heartbeat symlinks -----
cat > feat/planner-path-test.md <<'EOF'
# Planner Path Test [Active]

## 1 Existing worker [Active]

**Assignee:** backend
EOF
PATH_FID=feat/planner-path-test.md
PATH_TEAM=feat-planner-path-team
mkdir -p ".teamwork/$PATH_TEAM/executions" ".teamwork/$PATH_TEAM/heartbeats"
PATH_TASK="$PATH_FID#1"
PATH_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$PATH_TASK")"
ln -s /etc/passwd ".teamwork/$PATH_TEAM/executions/$PATH_KEY.json"
if path_out="$(TEAM_RUNNER=background "$DISPATCH" "$PATH_TEAM" "$PATH_FID" --once --dry-run 2>&1)"; then
  echo "FAIL: planner followed or ignored a symlink execution record"; FAILURES=$((FAILURES+1))
elif echo "$path_out" | grep -q 'cannot securely open task execution record'; then
  echo "ok: planner rejects a symlink execution record"
else
  echo "FAIL: wrong execution-symlink failure: $path_out"; FAILURES=$((FAILURES+1))
fi
rm ".teamwork/$PATH_TEAM/executions/$PATH_KEY.json"
ln -s /etc/passwd ".teamwork/$PATH_TEAM/heartbeats/forged"
heartbeat_out="$(TEAM_RUNNER=background "$DISPATCH" "$PATH_TEAM" "$PATH_FID" --once --dry-run 2>&1)"
echo "$heartbeat_out" | grep -q 'unsafe non-file heartbeat' \
  && echo "ok: planner reports heartbeat symlinks without following them" \
  || { echo "FAIL: heartbeat symlink was not surfaced: $heartbeat_out"; FAILURES=$((FAILURES+1)); }

# -- remote adapters may not persist role names in the assignee field ---------
cat > feat/remote-claim-test.md <<'EOF'
# Remote Claim Recovery [Active]

## 1 Claimed remotely [Active]

**Assignee:** —
EOF
REMOTE_FID=feat/remote-claim-test.md
REMOTE_TEAM=feat-remote-claim-team
REMOTE_TASK="$REMOTE_FID#1"
REMOTE_WORKSPACE="$(pwd)/.teamwork/$REMOTE_TEAM"
REMOTE_CLAIM_ID="$(python3 - "$REMOTE_TEAM" "$REMOTE_FID" "$REMOTE_TASK" <<'PY'
import hashlib,sys
team,feature,task=sys.argv[1:]
print('dispatch-' + hashlib.sha256('\0'.join(
    (team,feature,task,'backend','1','Active')
).encode()).hexdigest()[:32])
PY
)"
python3 .claude/skills/pm/bin/runtime-state.py claim \
  --workspace "$REMOTE_WORKSPACE" --team "$REMOTE_TEAM" --feature "$REMOTE_FID" \
  --task "$REMOTE_TASK" --role backend --attempt 1 --claim-id "$REMOTE_CLAIM_ID" \
  --target Active >/dev/null
python3 - "$REMOTE_FID" "$REMOTE_CLAIM_ID" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
claim_id = sys.argv[2]
body = (
    f"[claim]\nclaim-id: {claim_id}\nrole: backend\n"
    "target-status: Active\n\n— dispatcher"
)
with path.open("a", encoding="utf-8") as handle:
    handle.write("\n\n" + "\n".join("> " + line for line in body.splitlines()) + "\n")
PY
remote_plan="$(TEAM_RUNNER=background "$DISPATCH" "$REMOTE_TEAM" "$REMOTE_FID" --once --dry-run)"
echo "$remote_plan" | grep -q "launch task $REMOTE_TASK as backend (attempt 1)" \
  && echo "ok: durable claim relaunches remote active task with null assignee" \
  || { echo "FAIL: remote null-assignee claim was stranded: $remote_plan"; FAILURES=$((FAILURES+1)); }
REMOTE_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$REMOTE_TASK")"
python3 - "$REMOTE_WORKSPACE/claims/$REMOTE_KEY.json" <<'PY'
import json,sys
path=sys.argv[1]; value=json.load(open(path)); value['taskId']='forged-task'; json.dump(value,open(path,'w'))
PY
if forged_claim_out="$(TEAM_RUNNER=background "$DISPATCH" "$REMOTE_TEAM" "$REMOTE_FID" --once --dry-run 2>&1)"; then
  echo "FAIL: planner accepted a forged durable claim binding"; FAILURES=$((FAILURES+1))
elif echo "$forged_claim_out" | grep -q 'claim record does not match its team/feature/task/attempt binding'; then
  echo "ok: durable claim fallback fails closed on identity tampering"
else
  echo "FAIL: forged durable claim produced wrong error: $forged_claim_out"; FAILURES=$((FAILURES+1))
fi

# -- read_key: inline comments stripped; quoted values with inner # untouched -----
cat > feat/rk-test.md <<'EOF'
# ReadKey Test [Active]

## 1 In review [Review]

**Assignee:** backend

> [review-request] ready — backend
EOF
RK_FID="feat/rk-test.md"

# Unquoted key with inline comment: Python int(STUCK_AFTER_MINUTES) must succeed
sed -i '' 's/^STUCK_AFTER_MINUTES=.*/STUCK_AFTER_MINUTES=7   # inline comment/' .claude/skills/pm/config/team.config.md
if TEAM_RUNNER=background "$DISPATCH" feat-rk-team "$RK_FID" --once --dry-run >/dev/null 2>&1; then
  echo "ok: read_key: unquoted value with inline comment parses clean (int(7) ok)"
else
  echo "FAIL: read_key: inline comment not stripped — Python int() threw ValueError"; FAILURES=$((FAILURES+1))
fi
sed -i '' 's/^STUCK_AFTER_MINUTES=.*/STUCK_AFTER_MINUTES=15/' .claude/skills/pm/config/team.config.md

# Quoted key with outer inline comment: CMD must still be executable (inner content preserved)
sed -i '' 's|^TEAM_DEFAULT_CMD=.*|TEAM_DEFAULT_CMD="true"   # outer-comment|' .claude/skills/pm/config/team.config.md
TEAM_RUNNER=background "$DISPATCH" feat-rk-team "$RK_FID" --once >/dev/null 2>&1 || true
sleep 0.2
if [ -f .teamwork/feat-rk-team/pids/reviewer.log ] && \
   ! grep -q "command not found\|unexpected EOF\|not found" .teamwork/feat-rk-team/pids/reviewer.log 2>/dev/null; then
  echo "ok: read_key: quoted CMD with outer inline comment ran cleanly (inner preserved)"
else
  echo "FAIL: read_key: quoted CMD broken by outer-comment stripping (or reviewer not launched)"; FAILURES=$((FAILURES+1))
fi
sed -i '' 's|^TEAM_DEFAULT_CMD=.*|TEAM_DEFAULT_CMD="true"|' .claude/skills/pm/config/team.config.md

echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
