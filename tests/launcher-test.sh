#!/usr/bin/env bash
# Launcher smoke test: runs in a throwaway git repo with a stub agent command.
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok: $desc"; else echo "FAIL: $desc"; FAILURES=$((FAILURES+1)); fi
}

# -- fixture repo ------------------------------------------------------------
cd "$TMP"
git init -q repo && cd repo
git commit -q --allow-empty -m init
git checkout -q -b test-feature
mkdir -p .claude/skills/pm
cp -R "$SKILL_DIR/roles" "$SKILL_DIR/reference" "$SKILL_DIR/bin" .claude/skills/pm/
mkdir -p .claude/skills/pm/config
cat > .claude/skills/pm/config/team.config.md <<'EOF'
```
TEAM_LEAD_CMD=null
PRINCIPAL_ARCHITECT_CMD=null
INTEGRATOR_CMD=null
BACKEND_CMD="cat {prompt_file} > backend-received.txt"
FRONTEND_CMD=null
QA_CMD=null
REVIEWER_CMD=null
TEAMWORK_ROOT=.teamwork
POLL_INTERVAL_SECONDS=1
STUCK_AFTER_MINUTES=1
ESCALATE_AFTER_ATTEMPTS=2
VALIDATE_BUILD=null
VALIDATE_TEST=null
VALIDATE_LINT=null
```
EOF
LAUNCH=".claude/skills/pm/bin/launch-team.sh"

# -- start: composes prompt, runs stub in background mode ---------------------
TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 backend
check "prompt file composed"        test -f .teamwork/test-feature/prompts/backend.md
check "prompt contains role brief"  grep -q "Role: backend" .teamwork/test-feature/prompts/backend.md
check "prompt contains protocol"    grep -q "Orchestration — The Multi-Agent Protocol" .teamwork/test-feature/prompts/backend.md
check "prompt contains featureId"   grep -q "FEAT-1" .teamwork/test-feature/prompts/backend.md
check "prompt contains team config" grep -q "POLL_INTERVAL_SECONDS" .teamwork/test-feature/prompts/backend.md
check "pid file written"            test -f .teamwork/test-feature/pids/backend.pid
sleep 1
check "stub agent ran with prompt"  grep -q "Role: backend" backend-received.txt
check "mailbox dir created"         test -d .teamwork/test-feature/mailbox/backend

# -- start refuses a role with a null command ---------------------------------
if TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 qa 2>/dev/null; then
  echo "FAIL: null-command role should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: null-command role refused"
fi

# -- worktree subcommand -------------------------------------------------------
"$LAUNCH" worktree test-feature backend T-42
check "worktree created"  test -d .teamwork/test-feature/worktrees/backend-T-42
check "worktree branch"   git -C .teamwork/test-feature/worktrees/backend-T-42 rev-parse --abbrev-ref HEAD
[ "$(git -C .teamwork/test-feature/worktrees/backend-T-42 rev-parse --abbrev-ref HEAD)" = "backend-T-42" ] \
  && echo "ok: branch name backend-T-42" || { echo "FAIL: branch name"; FAILURES=$((FAILURES+1)); }

# -- status + stop --------------------------------------------------------------
"$LAUNCH" status test-feature | grep -q backend && echo "ok: status lists role" || { echo "FAIL: status"; FAILURES=$((FAILURES+1)); }
"$LAUNCH" stop test-feature
echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
