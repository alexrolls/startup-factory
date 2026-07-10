#!/usr/bin/env bash
# dispatch smoke test: offline, Markdown adapter, stub agent commands.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
FAILURES=0
check() { local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok: $desc"; else echo "FAIL: $desc"; FAILURES=$((FAILURES+1)); fi; }

cd "$TMP"; git init -q repo && cd repo
git commit -q --allow-empty -m init; git checkout -q -b feat-team
mkdir -p .claude/skills/pm
cp -R "$SKILL_DIR/roles" "$SKILL_DIR/reference" "$SKILL_DIR/bin" "$SKILL_DIR/teams" .claude/skills/pm/
mkdir -p .claude/skills/pm/config
cp "$SKILL_DIR/config/statuses.config.json" .claude/skills/pm/config/
cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Markdown
STATUS_CONFIG=config/statuses.config.json
```
EOF
cat > .claude/skills/pm/config/team.config.md <<'EOF'
```
TEAM_DEFAULT_CMD="true"
TEAMWORK_ROOT=.teamwork
POLL_INTERVAL_SECONDS=1
STUCK_AFTER_MINUTES=15
EXECUTION=sequential
VALIDATE_BUILD=null
VALIDATE_TEST=null
VALIDATE_LINT=null
```
EOF
DISPATCH=".claude/skills/pm/bin/dispatch.sh"

mkdir -p feat
cat > feat/feature.md <<'EOF'
# Fixture [Active]

## 1 Done thing [Ready to deploy]

**Assignee:** backend

> [review-request] round 1
> [review-approval] files ok — reviewer
> [architecture-approval] files ok — principal-architect

## 2 Blocked thing [Blocked]

**Assignee:** backend
**BlockedBy:** 1

Blocked on 1.

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
EOF
FID="feat/feature.md"

# -- dry-run prints the full action plan, changes nothing ----------------------
plan="$(TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once --dry-run --unblock=auto)"
echo "$plan" | grep -q "unblock $FID#2" && echo "ok: plans unblock" || { echo "FAIL: plans unblock"; FAILURES=$((FAILURES+1)); }
echo "$plan" | grep -q "launch reviewer" && echo "ok: plans reviewer queue" || { echo "FAIL: reviewer queue"; FAILURES=$((FAILURES+1)); }
echo "$plan" | grep -q "launch principal-architect" && echo "ok: plans PA queue" || { echo "FAIL: PA queue"; FAILURES=$((FAILURES+1)); }
echo "$plan" | grep -q "launch team-lead" && echo "ok: plans lead (Planned #5)" || { echo "FAIL: lead launch"; FAILURES=$((FAILURES+1)); }
echo "$plan" | grep -q "launch integrator" && echo "ok: plans integrator merge queue (#6)" || { echo "FAIL: integrator queue"; FAILURES=$((FAILURES+1)); }
check "dry-run does not move status" grep -q '^## 2 Blocked thing \[Blocked\]$' "$FID"
check "dry-run launches nothing"     test ! -d .teamwork/feat-team/pids

# -- real pass: auto-unblock writes, queues land in mailboxes, roles launch ----
TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once --unblock=auto
check "auto-unblock moved status"    grep -q '^## 2 Blocked thing \[Active\]$' "$FID"
check "auto-unblock left a comment"  grep -q 'Auto-unblocked by dispatcher' "$FID"
check "reviewer queue in mailbox"    grep -rq "$FID#3" .teamwork/feat-team/mailbox/reviewer/
check "PA queue in mailbox"          grep -rq "$FID#4" .teamwork/feat-team/mailbox/principal-architect/
check "reviewer launched"            test -f .teamwork/feat-team/pids/reviewer.pid

# -- dedup: a live pid suppresses relaunch -------------------------------------
mkdir -p .teamwork/feat-team/pids
echo $$ > .teamwork/feat-team/pids/reviewer.pid
plan2="$(TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once --dry-run)"
echo "$plan2" | grep -q "launch reviewer — skipped (live instance)" \
  && echo "ok: dedup skips live reviewer" || { echo "FAIL: dedup"; FAILURES=$((FAILURES+1)); }

# -- suggest mode: Markdown default never writes -------------------------------
# (state resets between blocks use sed on the fixture file, never tracker ops)
sed -i '' 's/^## 2 Blocked thing \[Active\]$/## 2 Blocked thing [Blocked]/' "$FID"
plan3="$(TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once --dry-run)"
echo "$plan3" | grep -q "unblock $FID#2 — SUGGESTED" \
  && echo "ok: Markdown defaults to suggest-only" || { echo "FAIL: suggest default"; FAILURES=$((FAILURES+1)); }

# real suggest pass: never writes the blocked task
TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once
check "suggest never writes blocked status" grep -q '^## 2 Blocked thing \[Blocked\]$' "$FID"

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
out="$("$DISPATCH" feat-team feat/quiet.md --once --dry-run)"
echo "$out" | grep -q "nothing actionable" && echo "ok: clean exit" || { echo "FAIL: clean exit"; FAILURES=$((FAILURES+1)); }

# -- null-CMD: skips launch instead of dying, no mailbox written ---------------
# Inject REVIEWER_CMD=null into the fixture config so the reviewer role is disabled.
printf '\nREVIEWER_CMD=null\n' >> .claude/skills/pm/config/team.config.md
# Restore task 3 to [Review] in case earlier blocks altered it.
sed -i '' 's/^## 3 In review \[.*\]$/## 3 In review [Review]/' "$FID"
# Clear reviewer pid and mailbox so this is a clean slate for the assertion.
rm -rf .teamwork/feat-team/pids/reviewer.pid .teamwork/feat-team/mailbox/reviewer
null_out="$(TEAM_RUNNER=background "$DISPATCH" feat-team "$FID" --once --unblock=off)"
echo "$null_out" | grep -q "skipped (REVIEWER_CMD=null" \
  && echo "ok: null-CMD reviewer skipped" || { echo "FAIL: null-CMD reviewer not skipped"; FAILURES=$((FAILURES+1)); }
check "null-CMD: reviewer.pid not created" test ! -f .teamwork/feat-team/pids/reviewer.pid
check "null-CMD: reviewer mailbox not written" test ! -d .teamwork/feat-team/mailbox/reviewer
# Remove the injected line to leave the config clean for any future assertions.
sed -i '' '/^REVIEWER_CMD=null$/d' .claude/skills/pm/config/team.config.md

# -- resume-status: auto-unblock routes to the correct phase ------------------
cat > feat/rs-test.md <<'EOF'
# RS Test [Active]

## 1 Terminal [Ready to deploy]

**Assignee:** backend

Done.

## 2 Needs Review [Blocked]

**Assignee:** backend
**BlockedBy:** 1

> resume-status: Review

## 3 Needs Planned [Blocked]

**Assignee:** backend
**BlockedBy:** 1

> resume-status: Planned

## 4 No resume-status [Blocked]

**Assignee:** backend
**BlockedBy:** 1

No resume-status here.

## 5 Invalid resume-status [Blocked]

**Assignee:** backend
**BlockedBy:** 1

> resume-status: Nonesuch
EOF
RS_FID="feat/rs-test.md"

# real auto pass — tasks 2 and 3 should be moved; 4 and 5 must not be touched
TEAM_RUNNER=background "$DISPATCH" feat-team-rs "$RS_FID" --once --unblock=auto
check "resume-status Review: moved to [Review]"  grep -q '^## 2 Needs Review \[Review\]$'  "$RS_FID"
check "resume-status Planned: moved to [Planned]" grep -q '^## 3 Needs Planned \[Planned\]$' "$RS_FID"
check "no-rs: not moved (still Blocked)"          grep -q '^## 4 No resume-status \[Blocked\]$' "$RS_FID"
check "invalid-rs: not moved (still Blocked)"     grep -q '^## 5 Invalid resume-status \[Blocked\]$' "$RS_FID"

# auto comments on moved tasks name the chosen resume status
check "Review unblock comment present"  grep -rq 'Resuming to \[Review\]'  "$RS_FID"
check "Planned unblock comment present" grep -rq 'Resuming to \[Planned\]' "$RS_FID"

# dry-run captures the no-rs suggestion and the invalid-rs warning
rs_dry="$(TEAM_RUNNER=background "$DISPATCH" feat-team-rs2 "$RS_FID" --once --dry-run --unblock=auto 2>&1)"
echo "$rs_dry" | grep -q "NO RESUME STATUS" \
  && echo "ok: no-rs: lead-actionable suggestion printed" \
  || { echo "FAIL: no-rs: suggestion not printed"; FAILURES=$((FAILURES+1)); }
echo "$rs_dry" | grep -q "invalid resume-status" \
  && echo "ok: invalid-rs: warning printed" \
  || { echo "FAIL: invalid-rs: no warning"; FAILURES=$((FAILURES+1)); }

# under Markdown suggest-only default: no write even for a task with a valid resume-status
sed -i '' 's/^## 2 Needs Review \[Review\]$/## 2 Needs Review [Blocked]/' "$RS_FID"
rs_sug="$(TEAM_RUNNER=background "$DISPATCH" feat-team-rs3 "$RS_FID" --once --dry-run 2>&1)"
echo "$rs_sug" | grep -q "unblock $RS_FID#2 — SUGGESTED" \
  && echo "ok: suggest-only: valid-rs task shows SUGGESTED" \
  || { echo "FAIL: suggest-only: wrong message for valid-rs task"; FAILURES=$((FAILURES+1)); }
check "suggest-only: no write for valid-rs task" grep -q '^## 2 Needs Review \[Blocked\]$' "$RS_FID"

echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
