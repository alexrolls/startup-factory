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
cp -R "$SKILL_DIR/roles" "$SKILL_DIR/reference" "$SKILL_DIR/bin" "$SKILL_DIR/teams" .claude/skills/pm/
mkdir -p .claude/skills/pm/config
cp "$SKILL_DIR/config/statuses.config.json" .claude/skills/pm/config/
cat > .claude/skills/pm/config/team.config.md <<'EOF'
```
TEAM_LEAD_CMD=null
PRINCIPAL_ARCHITECT_CMD=null
BACKEND_CMD="cat {prompt_file} > backend-received.txt"
FRONTEND_CMD=null
REVIEWER_CMD=null
TEAM_DEFAULT_CMD="true"
SENIOR_QA_ENGINEER_CMD="cat {prompt_file} > qa-received.txt"
SENIOR_TECHNICAL_PRODUCT_MANAGER_CMD=null
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
for i in $(seq 1 20); do [ -f backend-received.txt ] && break; sleep 0.1; done
check "stub agent ran with prompt"  grep -q "Role: backend" backend-received.txt
check "mailbox dir created"         test -d .teamwork/test-feature/mailbox/backend

# -- start refuses an unknown role (no brief anywhere) ------------------------
if TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 no-such-role 2>/dev/null; then
  echo "FAIL: unknown role should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: unknown role refused"
fi

# -- role with no _CMD key of its own falls back to TEAM_DEFAULT_CMD ----------
TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 qa
check "absent-key role falls back to TEAM_DEFAULT_CMD" test -f .teamwork/test-feature/prompts/qa.md

# -- explicit <ROLE>_CMD=null disables the role even when TEAM_DEFAULT_CMD is set --
if TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 reviewer 2>/dev/null; then
  echo "FAIL: explicit-null role should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: explicit-null role refused (no fallback)"
fi

# -- worktree subcommand -------------------------------------------------------
"$LAUNCH" worktree test-feature backend T-42
check "worktree created"  test -d .teamwork/test-feature/worktrees/backend-T-42
check "worktree branch"   git -C .teamwork/test-feature/worktrees/backend-T-42 rev-parse --abbrev-ref HEAD
[ "$(git -C .teamwork/test-feature/worktrees/backend-T-42 rev-parse --abbrev-ref HEAD)" = "backend-T-42" ] \
  && echo "ok: branch name backend-T-42" || { echo "FAIL: branch name"; FAILURES=$((FAILURES+1)); }

# -- worktree re-add: remove the worktree dir but keep the branch, re-add should succeed --
git worktree remove .teamwork/test-feature/worktrees/backend-T-42
"$LAUNCH" worktree test-feature backend T-42
check "worktree re-add with existing branch" test -d .teamwork/test-feature/worktrees/backend-T-42

# -- team preset: launch a full roster from teams/full-stack.md ----------------
TEAM_RUNNER=background "$LAUNCH" team full-stack test-feature FEAT-2
check "preset composes fallback-role prompt" test -f .teamwork/test-feature/prompts/principal-software-architect.md
check "preset brief resolved from teams/roles" grep -q "Role: principal-software-architect" .teamwork/test-feature/prompts/principal-software-architect.md
check "preset prompt includes team file"     grep -q "Team: Full Stack" .teamwork/test-feature/prompts/principal-software-architect.md
check "preset prompt includes playbook"      grep -q "Team Playbook" .teamwork/test-feature/prompts/principal-software-architect.md
check "preset composes integrator (roles/)"  test -f .teamwork/test-feature/prompts/integrator.md
check "preset skips explicit-null role"      test ! -f .teamwork/test-feature/prompts/senior-technical-product-manager.md
for i in $(seq 1 20); do [ -f qa-received.txt ] && break; sleep 0.1; done
check "preset per-role override ran"         grep -q "Role: senior-qa-engineer" qa-received.txt

# -- compose: emits the composed startup prompt without spawning (harness mode) --
out="$("$LAUNCH" compose test-compose FEAT-3 backend)"
check "compose prints an existing prompt path" test -f "$out"
check "compose prompt contains role brief"     grep -q "Role: backend" "$out"
check "compose prompt contains protocol"       grep -q "Orchestration — The Multi-Agent Protocol" "$out"
check "compose spawns nothing"                 test ! -f .teamwork/test-compose/pids/backend.pid
out2="$("$LAUNCH" compose test-compose FEAT-3 senior-qa-engineer full-stack)"
check "compose with preset includes team file" grep -q "Team: Full Stack" "$out2"
# compose is command-map-agnostic: a role with <ROLE>_CMD=null still composes
# (harness mode spawns natively; the command map only gates CLI launches)
out3="$("$LAUNCH" compose test-compose FEAT-3 reviewer)"
check "compose works for CLI-disabled role"    grep -q "Role: reviewer" "$out3"
if "$LAUNCH" compose test-compose FEAT-3 no-such-role 2>/dev/null; then
  echo "FAIL: compose should refuse an unknown role"; FAILURES=$((FAILURES+1))
else
  echo "ok: compose refuses unknown role"
fi

# -- team preset: unknown preset is refused ------------------------------------
if TEAM_RUNNER=background "$LAUNCH" team nonesuch test-feature FEAT-2 2>/dev/null; then
  echo "FAIL: unknown preset should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: unknown preset refused"
fi

# -- validate-board: shipped config passes --------------------------------------
check "validate-board accepts shipped config" "$LAUNCH" validate-board

# -- validate-board: prompt composition includes the board ----------------------
check "prompt contains board config" grep -q '"Ready to deploy"' .teamwork/test-feature/prompts/backend.md

# -- validate-board: each broken config is refused with the right message -------
bad() { # bad <desc> <needle> <json>
  local desc="$1" needle="$2" json="$3" out
  printf '%s' "$json" > "$TMP/bad.json"
  if out="$("$LAUNCH" validate-board "$TMP/bad.json" 2>&1)"; then
    echo "FAIL: $desc (accepted)"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$out" | grep -q "$needle"; then
    echo "ok: $desc"
  else
    echo "FAIL: $desc (wrong message: $out)"; FAILURES=$((FAILURES+1))
  fi
}
MINF='"features":{"statuses":[{"name":"P","initial":true,"owner":{"role":"team-lead"},"transitions":["R"]},{"name":"R","terminal":true,"owner":{"role":"team-lead"},"transitions":[]}]}'
bad "invalid JSON refused"            "invalid JSON" '{nope'
bad "two initials refused"            "exactly one initial" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"initial\":true,\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"
bad "unknown transition refused"      "undefined status" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Nope\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"
bad "unreachable status refused"      "unreachable" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]},{\"name\":\"Island\",\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]}]}}"
bad "terminal with outbound refused"  "terminal status must have empty transitions" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"A\"]}]}}"
bad "bad owner refused"               "unknown role" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"nobody-such\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"
bad "two-key owner refused"           "exactly one of" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\",\"team\":\"full-stack\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"
bad "requiresCommit on initial refused" "not allowed on the initial" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"requiresCommit\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"
bad "no terminal refused"             "at least one terminal" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"A\"]}]}}"
bad "zero initials refused"           "exactly one initial"   "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"

# -- status + stop --------------------------------------------------------------
# Capture first (grep -q closes the pipe early → SIGPIPE on the writer under pipefail).
status_out="$("$LAUNCH" status test-feature)"
echo "$status_out" | grep -q backend && echo "ok: status lists role" || { echo "FAIL: status"; FAILURES=$((FAILURES+1)); }
"$LAUNCH" stop test-feature
echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
