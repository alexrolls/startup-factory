#!/usr/bin/env bash
# Launcher smoke test: runs in a throwaway git repo with a stub agent command.
set -euo pipefail

if sed --version >/dev/null 2>&1; then
  sed_i() { sed -i "$@"; }
else
  sed_i() { sed -i '' "$@"; }
fi

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_STATUS_FIXTURE="$SKILL_DIR/tests/fixtures/statuses.default-profile.json"
TMP="$(mktemp -d)"
TMP="$(cd "$TMP" && pwd -P)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok: $desc"; else echo "FAIL: $desc"; FAILURES=$((FAILURES+1)); fi
}

SANDBOX_RUNNER="$TMP/protected-agent-sandbox-runner"
SANDBOX_RUNNER_LOG="$TMP/agent-sandbox-runner.log"
cat > "$SANDBOX_RUNNER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = "--workdir" ] && [ $# -ge 4 ] || exit 91
workdir="$2"
shift 2
[ "${1:-}" = "--" ] || exit 92
shift
if [ -n "${SANDBOX_RUNNER_LOG:-}" ]; then
  printf '%s|%s|%s\n' "$workdir" "${1:-}" "${2:-}" >> "$SANDBOX_RUNNER_LOG"
fi
cd "$workdir"
exec "$@"
EOF
chmod 700 "$SANDBOX_RUNNER"
export SANDBOX_RUNNER_LOG
: > "$SANDBOX_RUNNER_LOG"
LIFECYCLE_ROOT="$TMP/protected-lifecycle"
mkdir -m 700 "$LIFECYCLE_ROOT"

# -- fixture repo ------------------------------------------------------------
cd "$TMP"
git init -q repo && cd repo
git config user.email test@example.com
git config user.name Test
git commit -q --allow-empty -m init
git checkout -q -b test-feature
mkdir -p .claude/skills/pm
cp -R "$SKILL_DIR/roles" "$SKILL_DIR/reference" "$SKILL_DIR/bin" "$SKILL_DIR/teams" .claude/skills/pm/
mkdir -p .claude/skills/pm/config
cp "$DEFAULT_STATUS_FIXTURE" .claude/skills/pm/config/statuses.config.json
cp "$SKILL_DIR/config/planning.config.md" .claude/skills/pm/config/
cat > .claude/skills/pm/config/team.config.md <<'EOF'
```
TEAM_LEAD_CMD="true"
PRINCIPAL_ARCHITECT_CMD=null
BACKEND_CMD="cat {prompt_file} > backend-received.txt"
FRONTEND_CMD=null
REVIEWER_CMD=null
SENIOR_SECURITY_ENGINEER_CMD="true"
TEAM_DEFAULT_CMD="true"
SENIOR_QA_ENGINEER_CMD="cat {prompt_file} > qa-received.txt"
SENIOR_TECHNICAL_PRODUCT_MANAGER_CMD=null
TEAMWORK_ROOT=.teamwork
AGENT_ENV_ALLOWLIST="PATH TMPDIR LANG LC_ALL TERM SAFE_AGENT_FLAG"
POLL_INTERVAL_SECONDS=1
STUCK_AFTER_MINUTES=1
ESCALATE_AFTER_ATTEMPTS=2
TRACKER_WRITERS=broker
AGENT_SANDBOX_RUNNER=__SANDBOX_RUNNER__
AGENT_SANDBOX_ENFORCED=true
BROKER_LIFECYCLE_ROOT=__LIFECYCLE_ROOT__
VALIDATE_BUILD=null
VALIDATE_TEST=null
VALIDATE_LINT=null
```
EOF
sed_i "s|^AGENT_SANDBOX_RUNNER=.*|AGENT_SANDBOX_RUNNER=\"$SANDBOX_RUNNER\"|" .claude/skills/pm/config/team.config.md
sed_i "s|^BROKER_LIFECYCLE_ROOT=.*|BROKER_LIFECYCLE_ROOT=\"$LIFECYCLE_ROOT\"|" .claude/skills/pm/config/team.config.md
LAUNCH=".claude/skills/pm/bin/launch-team.sh"

printf 'TRACKER_WRITERS=all\n' >> .claude/skills/pm/config/team.config.md
if "$LAUNCH" status test-feature >duplicate-config.out 2>&1; then
  echo "FAIL: launcher accepted duplicate safety configuration"; FAILURES=$((FAILURES+1))
elif grep -q 'duplicate configuration key TRACKER_WRITERS' duplicate-config.out; then
  echo "ok: launcher rejects duplicate safety configuration"
else
  echo "FAIL: launcher reported wrong duplicate-key error"; FAILURES=$((FAILURES+1))
fi
sed_i '$d' .claude/skills/pm/config/team.config.md

# -- enforced sandbox runner trust and direct-mode fallback -----------------
CFG_SANDBOX=.claude/skills/pm/config/team.config.md
expect_runner_refused() { # description value expected-error
  local description="$1" value="$2" expected="$3" out
  sed_i "s|^AGENT_SANDBOX_RUNNER=.*|AGENT_SANDBOX_RUNNER=\"$value\"|" "$CFG_SANDBOX"
  if out="$("$LAUNCH" status sandbox-check 2>&1)"; then
    echo "FAIL: $description accepted"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$out" | grep -q "$expected"; then
    echo "ok: $description refused"
  else
    echo "FAIL: $description wrong error: $out"; FAILURES=$((FAILURES+1))
  fi
}

INSIDE_RUNNER="$PWD/repository-agent-runner"
cp "$SANDBOX_RUNNER" "$INSIDE_RUNNER"
chmod 700 "$INSIDE_RUNNER"
SYMLINK_RUNNER="$TMP/symlink-agent-runner"
ln -s "$SANDBOX_RUNNER" "$SYMLINK_RUNNER"
WRITABLE_RUNNER="$TMP/writable-agent-runner"
cp "$SANDBOX_RUNNER" "$WRITABLE_RUNNER"
chmod 722 "$WRITABLE_RUNNER"
NONEXEC_RUNNER="$TMP/nonexec-agent-runner"
cp "$SANDBOX_RUNNER" "$NONEXEC_RUNNER"
chmod 600 "$NONEXEC_RUNNER"

expect_runner_refused "relative sandbox runner" "relative-runner" "path must be absolute"
expect_runner_refused "repository-local sandbox runner" "$INSIDE_RUNNER" "external to the agent repository"
expect_runner_refused "symlink sandbox runner" "$SYMLINK_RUNNER" "must not be a symlink"
expect_runner_refused "directory sandbox runner" "$TMP" "regular file"
expect_runner_refused "group/world-writable sandbox runner" "$WRITABLE_RUNNER" "group- or world-writable"
expect_runner_refused "non-executable sandbox runner" "$NONEXEC_RUNNER" "must be executable"

sed_i 's|^AGENT_SANDBOX_ENFORCED=.*|AGENT_SANDBOX_ENFORCED=false|' "$CFG_SANDBOX"
sed_i 's|^AGENT_SANDBOX_RUNNER=.*|AGENT_SANDBOX_RUNNER="relative-runner"|' "$CFG_SANDBOX"
runner_lines_before="$(wc -l < "$SANDBOX_RUNNER_LOG" 2>/dev/null || printf '0')"
TEAM_RUNNER=background "$LAUNCH" start manual-direct FEAT-DIRECT backend
runner_lines_after="$(wc -l < "$SANDBOX_RUNNER_LOG" 2>/dev/null || printf '0')"
check "manual non-enforced mode retains direct execution" test -f .teamwork/manual-direct/prompts/backend.md
[ "$runner_lines_before" = "$runner_lines_after" ] \
  && echo "ok: manual non-enforced mode does not invoke configured runner" \
  || { echo "FAIL: manual non-enforced mode invoked sandbox runner"; FAILURES=$((FAILURES+1)); }
sed_i 's|^AGENT_SANDBOX_RUNNER=.*|AGENT_SANDBOX_RUNNER="'"$SANDBOX_RUNNER"'"|' "$CFG_SANDBOX"
sed_i 's|^AGENT_SANDBOX_ENFORCED=.*|AGENT_SANDBOX_ENFORCED=true|' "$CFG_SANDBOX"
: > "$SANDBOX_RUNNER_LOG"

# -- start: composes prompt, runs stub in background mode ---------------------
TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 backend
check "prompt file composed"        test -f .teamwork/test-feature/prompts/backend.md
check "prompt contains role brief"  grep -q "Role: backend" .teamwork/test-feature/prompts/backend.md
check "prompt contains protocol"    grep -q "Orchestration — The Multi-Agent Protocol" .teamwork/test-feature/prompts/backend.md
check "prompt contains safety policy" grep -q "Autonomous safety guardrails" .teamwork/test-feature/prompts/backend.md
check "prompt contains featureId"   grep -q "FEAT-1" .teamwork/test-feature/prompts/backend.md
check "prompt contains team config" grep -q "POLL_INTERVAL_SECONDS" .teamwork/test-feature/prompts/backend.md
check "non-Claude command is classified as other" grep -q "LLM runtime family: other" .teamwork/test-feature/prompts/backend.md
if grep -q "Claude + obra/superpowers planning" .teamwork/test-feature/prompts/backend.md; then
  echo "FAIL: non-Claude command received Superpowers planning instructions"; FAILURES=$((FAILURES+1))
else
  echo "ok: non-Claude command excludes Superpowers planning instructions"
fi
check "pid file written"            test -f .teamwork/test-feature/pids/backend.pid
check "workspace process marker contains no PID" grep -qx managed .teamwork/test-feature/pids/backend.pid
for i in $(seq 1 20); do
  [ -f backend-received.txt ] && grep -Fq "$PWD|/usr/bin/env|-i" "$SANDBOX_RUNNER_LOG" && break
  sleep 0.1
done
check "enforced gate launch uses protected runner argv" grep -Fq "$PWD|/usr/bin/env|-i" "$SANDBOX_RUNNER_LOG"
check "stub agent ran with prompt"  grep -q "Role: backend" backend-received.txt
check "mailbox dir created"         test -d .teamwork/test-feature/mailbox/backend

# -- Superpowers prompt wiring is Claude-only --------------------------------
cat > claude <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > codex <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > gemini <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > custom-wrapper <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x claude codex gemini custom-wrapper

sed_i 's|^FRONTEND_CMD=.*|FRONTEND_CMD="./claude {prompt_file}"|' "$CFG_SANDBOX"
unmarked_harness_prompt="$("$LAUNCH" compose native-harness FEAT-NATIVE-HARNESS frontend)"
check "unmarked harness defaults to non-Claude" grep -q "LLM runtime family: other" "$unmarked_harness_prompt"
if grep -q "Claude + obra/superpowers planning" "$unmarked_harness_prompt"; then
  echo "FAIL: unmarked harness inferred Claude from the unused command map"; FAILURES=$((FAILURES+1))
else
  echo "ok: unmarked harness excludes Superpowers despite a Claude CLI command"
fi

sed_i 's|^FRONTEND_CMD=.*|FRONTEND_CMD="./codex {prompt_file}"|' "$CFG_SANDBOX"
TEAM_RUNNER=background "$LAUNCH" start codex-planning FEAT-CODEX frontend
codex_prompt=.teamwork/codex-planning/prompts/frontend.md
check "Codex CLI command is classified as non-Claude" grep -q "LLM runtime family: other" "$codex_prompt"
if grep -q "Claude + obra/superpowers planning" "$codex_prompt"; then
  echo "FAIL: Codex CLI command received Superpowers planning instructions"; FAILURES=$((FAILURES+1))
else
  echo "ok: Codex CLI command excludes Superpowers planning instructions"
fi

sed_i 's|^FRONTEND_CMD=.*|FRONTEND_CMD="./gemini {prompt_file}"|' "$CFG_SANDBOX"
TEAM_RUNNER=background "$LAUNCH" start gemini-planning FEAT-GEMINI frontend
gemini_prompt=.teamwork/gemini-planning/prompts/frontend.md
check "Gemini CLI command is classified as non-Claude" grep -q "LLM runtime family: other" "$gemini_prompt"
if grep -q "Claude + obra/superpowers planning" "$gemini_prompt"; then
  echo "FAIL: Gemini CLI command received Superpowers planning instructions"; FAILURES=$((FAILURES+1))
else
  echo "ok: Gemini CLI command excludes Superpowers planning instructions"
fi

sed_i 's|^FRONTEND_CMD=.*|FRONTEND_CMD="./custom-wrapper {prompt_file}"|' "$CFG_SANDBOX"
TEAM_RUNNER=background "$LAUNCH" start unmarked-wrapper FEAT-UNMARKED frontend
unmarked_wrapper_prompt=.teamwork/unmarked-wrapper/prompts/frontend.md
check "unmarked wrapper is classified as non-Claude" grep -q "LLM runtime family: other" "$unmarked_wrapper_prompt"
if grep -q "Claude + obra/superpowers planning" "$unmarked_wrapper_prompt"; then
  echo "FAIL: unmarked wrapper received Superpowers planning instructions"; FAILURES=$((FAILURES+1))
else
  echo "ok: unmarked wrapper excludes Superpowers planning instructions"
fi

sed_i 's|^FRONTEND_CMD=.*|FRONTEND_CMD="./claude {prompt_file}"|' "$CFG_SANDBOX"
TEAM_RUNNER=background "$LAUNCH" start claude-planning FEAT-CLAUDE frontend
claude_prompt=.teamwork/claude-planning/prompts/frontend.md
check "direct Claude command is classified as Claude" grep -q "LLM runtime family: claude" "$claude_prompt"
check "direct Claude command receives Superpowers planning boundary" \
  grep -q "Claude + obra/superpowers planning" "$claude_prompt"

sed_i 's|^FRONTEND_CMD=.*|FRONTEND_CMD="STARTUP_FACTORY_LLM_RUNTIME=claude ./custom-wrapper {prompt_file}"|' "$CFG_SANDBOX"
TEAM_RUNNER=background "$LAUNCH" start wrapper-planning FEAT-WRAPPER frontend
wrapper_prompt=.teamwork/wrapper-planning/prompts/frontend.md
check "explicit Claude wrapper marker is classified as Claude" grep -q "LLM runtime family: claude" "$wrapper_prompt"
check "explicit Claude wrapper receives Superpowers planning boundary" \
  grep -q "Claude + obra/superpowers planning" "$wrapper_prompt"
sed_i 's|^FRONTEND_CMD=.*|FRONTEND_CMD=null|' "$CFG_SANDBOX"

harness_prompt="$(STARTUP_FACTORY_LLM_RUNTIME=claude "$LAUNCH" compose harness-planning FEAT-HARNESS reviewer)"
check "Claude harness override is classified as Claude" grep -q "LLM runtime family: claude" "$harness_prompt"
check "Claude harness override receives Superpowers planning boundary" \
  grep -q "Claude + obra/superpowers planning" "$harness_prompt"
if STARTUP_FACTORY_LLM_RUNTIME=gemini "$LAUNCH" compose invalid-runtime FEAT-INVALID reviewer >/dev/null 2>&1; then
  echo "FAIL: invalid harness runtime override accepted"; FAILURES=$((FAILURES+1))
else
  echo "ok: invalid harness runtime override refused"
fi

# -- global planning opt-out removes all Superpowers prompt wiring -------------
PLANNING_CFG=.claude/skills/pm/config/planning.config.md
sed_i 's/^USE_SUPERPOWERS=true$/USE_SUPERPOWERS=false/' "$PLANNING_CFG"
native_prompt="$(STARTUP_FACTORY_LLM_RUNTIME=claude "$LAUNCH" compose native-planning FEAT-NATIVE backend)"
if grep -q "Claude + obra/superpowers planning\\|Claude Superpowers task method" "$native_prompt"; then
  echo "FAIL: USE_SUPERPOWERS=false left Superpowers prompt wiring"; FAILURES=$((FAILURES+1))
else
  echo "ok: USE_SUPERPOWERS=false removes Superpowers prompt wiring"
fi
if "$LAUNCH" planning-handoff native-planning docs/superpowers/specs/missing.md docs/superpowers/plans/missing.md >/dev/null 2>&1; then
  echo "FAIL: disabled planning accepted a handoff"; FAILURES=$((FAILURES+1))
else
  echo "ok: disabled planning refuses a handoff"
fi
sed_i 's/^USE_SUPERPOWERS=false$/USE_SUPERPOWERS=true/' "$PLANNING_CFG"

# -- committed planning inputs become a digest-bound team handoff --------------
mkdir -p docs/superpowers/specs docs/superpowers/plans
printf '# Approved design\n' > docs/superpowers/specs/launcher.md
printf '# Approved implementation plan\n' > docs/superpowers/plans/launcher.md
git add docs/superpowers/specs/launcher.md docs/superpowers/plans/launcher.md
git commit -qm 'planning inputs'
handoff="$("$LAUNCH" planning-handoff planning-team docs/superpowers/specs/launcher.md docs/superpowers/plans/launcher.md)"
check "planning-handoff creates a manifest" test -f "$handoff"
check "planning-handoff assigns execution to Startup Factory" \
  python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["executionOwner"] == "startup-factory"' "$handoff"
check "planning-handoff records the default intake" \
  python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["intake"] == "brainstormed"' "$handoff"
planning_prompt="$("$LAUNCH" compose planning-team FEAT-PLAN team-lead)"
check "team prompt carries validated planning handoff" grep -q "Planning handoff:" "$planning_prompt"
check "team prompt carries exact approved specification" grep -q "docs/superpowers/specs/launcher.md" "$planning_prompt"
if grep -q "Claude + obra/superpowers planning" "$planning_prompt"; then
  echo "FAIL: non-Claude handoff consumer received Superpowers instructions"; FAILURES=$((FAILURES+1))
else
  echo "ok: non-Claude handoff consumer keeps model-neutral planning inputs"
fi
claude_planning_prompt="$(STARTUP_FACTORY_LLM_RUNTIME=claude "$LAUNCH" compose planning-team FEAT-PLAN team-lead)"
check "Claude handoff consumer receives Superpowers planning boundary" \
  grep -q "Claude + obra/superpowers planning" "$claude_planning_prompt"

# -- agent child environment strips tracker/cloud/host credentials ------------
cat > env-probe.sh <<'EOF'
#!/usr/bin/env bash
printf '%s|%s|%s|%s\n' "${LINEAR_API_KEY-unset}" "${AWS_ACCESS_KEY_ID-unset}" "${KUBECONFIG-unset}" "${SSH_AUTH_SOCK-unset}" > agent-env.txt
printf '%s|%s|%s|%s\n' "${SAFE_AGENT_FLAG-unset}" "${UNLISTED_AGENT_VALUE-unset}" "${STARTUP_FACTORY_ROLE-unset}" "${STARTUP_FACTORY_EXECUTION_KIND-unset}" >> agent-env.txt
printf '%s\n' "${HOME-unset}" >> agent-env.txt
case "${STARTUP_FACTORY_OUTBOX_CAPABILITY_ID-unset}|${STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET-unset}|${STARTUP_FACTORY_CANONICAL_REPO-unset}|${STARTUP_FACTORY_CANONICAL_WORKSPACE-unset}" in
  cap-[0-9a-f][0-9a-f]*\|[0-9a-f][0-9a-f]*\|/*\|/*) echo capability-context-valid >> agent-env.txt ;;
  *) echo capability-context-invalid >> agent-env.txt ;;
esac
EOF
chmod +x env-probe.sh
sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="./env-probe.sh {prompt_file}"|' .claude/skills/pm/config/team.config.md
LINEAR_API_KEY=tracker-secret AWS_ACCESS_KEY_ID=cloud-secret KUBECONFIG=/secret/kube SSH_AUTH_SOCK=/secret/agent \
  SAFE_AGENT_FLAG=allowed UNLISTED_AGENT_VALUE=must-not-leak \
  TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 backend
for i in $(seq 1 20); do [ -f agent-env.txt ] && break; sleep 0.1; done
check "non-lead agent environment strips sensitive credentials" grep -q '^unset|unset|unset|unset$' agent-env.txt
check "agent environment keeps explicitly allowlisted value" grep -q '^allowed|unset|backend|gate$' agent-env.txt
check "agent environment omits ambient HOME by default" grep -q '^unset$' agent-env.txt
check "launcher injects bounded outbox capability context" grep -q '^capability-context-valid$' agent-env.txt
check "broker verifier state is outside linked task worktrees" python3 - <<'PY'
import os,stat,subprocess
common=subprocess.check_output(['git','rev-parse','--git-common-dir'],text=True).strip()
if not os.path.isabs(common): common=os.path.join(os.getcwd(),common)
root=os.path.realpath(os.path.join(common,'startup-factory-broker'))
assert os.path.isdir(root)
assert stat.S_IMODE(os.stat(root).st_mode) == 0o700
records=os.path.join(root,'outbox-capabilities')
assert any(name.endswith('.json') for name in os.listdir(records))
assert all(stat.S_IMODE(os.stat(os.path.join(records,name)).st_mode) == 0o600 for name in os.listdir(records))
PY

AGENT_CLI_HOME="$TMP/agent-cli-home"
mkdir -m 700 "$AGENT_CLI_HOME"
printf 'AGENT_SANDBOX_HOME="%s"\n' "$AGENT_CLI_HOME" >> .claude/skills/pm/config/team.config.md
TEAM_RUNNER=background "$LAUNCH" start dedicated-home FEAT-HOME backend
for i in $(seq 1 20); do
  [ -f agent-env.txt ] && grep -qx "$AGENT_CLI_HOME" agent-env.txt && break
  sleep 0.1
done
check "dedicated CLI-state home is passed without ambient HOME" grep -qx "$AGENT_CLI_HOME" agent-env.txt
sed_i 's|^AGENT_ENV_ALLOWLIST=.*|AGENT_ENV_ALLOWLIST="PATH HOME"|' .claude/skills/pm/config/team.config.md
if TEAM_RUNNER=background "$LAUNCH" start ambient-home FEAT-HOME backend >/dev/null 2>&1; then
  echo "FAIL: launcher accepted ambient HOME inheritance"; FAILURES=$((FAILURES+1))
else
  echo "ok: launcher refuses ambient HOME inheritance"
fi
sed_i 's|^AGENT_ENV_ALLOWLIST=.*|AGENT_ENV_ALLOWLIST="PATH TMPDIR LANG LC_ALL TERM SAFE_AGENT_FLAG"|' .claude/skills/pm/config/team.config.md
sed_i '/^AGENT_SANDBOX_HOME=/d' .claude/skills/pm/config/team.config.md

sed_i 's|^AGENT_ENV_ALLOWLIST=.*|AGENT_ENV_ALLOWLIST="PATH LINEAR_API_KEY"|' .claude/skills/pm/config/team.config.md
if LINEAR_API_KEY=tracker-secret TEAM_RUNNER=background "$LAUNCH" start blocked-env FEAT-ENV backend >/dev/null 2>&1; then
  echo "FAIL: broker mode accepted a tracker credential in AGENT_ENV_ALLOWLIST"; FAILURES=$((FAILURES+1))
else
  echo "ok: broker mode refuses tracker credentials in AGENT_ENV_ALLOWLIST"
fi
sed_i 's|^AGENT_ENV_ALLOWLIST=.*|AGENT_ENV_ALLOWLIST="PATH TMPDIR LANG LC_ALL TERM SAFE_AGENT_FLAG"|' .claude/skills/pm/config/team.config.md

# -- doctor: real env/prompt/auth round trip before a persistent team launch ---
cp .claude/skills/pm/config/team.config.md "$TMP/team.config.before-doctor"
sed_i 's|^TEAM_LEAD_CMD=.*|TEAM_LEAD_CMD="cat '\''{prompt_file}'\''"|' .claude/skills/pm/config/team.config.md
sed_i 's|^SENIOR_SECURITY_ENGINEER_CMD=.*|SENIOR_SECURITY_ENGINEER_CMD="cat '\''{prompt_file}'\''"|' .claude/skills/pm/config/team.config.md
sed_i 's|^SENIOR_QA_ENGINEER_CMD=.*|SENIOR_QA_ENGINEER_CMD="cat '\''{prompt_file}'\''"|' .claude/skills/pm/config/team.config.md
sed_i 's|^TEAM_DEFAULT_CMD=.*|TEAM_DEFAULT_CMD="cat '\''{prompt_file}'\''"|' .claude/skills/pm/config/team.config.md
doctor_out="$("$LAUNCH" doctor full-stack doctor-team FEAT-DOCTOR)"
printf '%s' "$doctor_out" | grep -q "every distinct configured command completed" \
  && echo "ok: doctor completes prompt/auth round trips under the real agent environment" \
  || { echo "FAIL: doctor did not complete: $doctor_out"; FAILURES=$((FAILURES+1)); }
sed_i 's|^SENIOR_QA_ENGINEER_CMD=.*|SENIOR_QA_ENGINEER_CMD="false"|' .claude/skills/pm/config/team.config.md
if doctor_out="$("$LAUNCH" doctor full-stack doctor-fail FEAT-DOCTOR 2>&1)"; then
  echo "FAIL: doctor accepted a configured command that could not complete the round trip"; FAILURES=$((FAILURES+1))
elif printf '%s' "$doctor_out" | grep -q "doctor FAILED"; then
  echo "ok: doctor fails before launch when one configured command is unusable"
else
  echo "FAIL: doctor produced the wrong failure: $doctor_out"; FAILURES=$((FAILURES+1))
fi
sed_i 's|^SENIOR_QA_ENGINEER_CMD=.*|SENIOR_QA_ENGINEER_CMD="true"|' .claude/skills/pm/config/team.config.md
if doctor_out="$("$LAUNCH" doctor full-stack doctor-no-token FEAT-DOCTOR 2>&1)"; then
  echo "FAIL: doctor accepted exit zero without the prompt challenge token"; FAILURES=$((FAILURES+1))
elif printf '%s' "$doctor_out" | grep -q "did not complete the prompt/authentication round trip"; then
  echo "ok: doctor rejects exit zero without the prompt challenge token"
else
  echo "FAIL: doctor produced the wrong no-token failure: $doctor_out"; FAILURES=$((FAILURES+1))
fi
cp "$TMP/team.config.before-doctor" .claude/skills/pm/config/team.config.md

# Broker mode strips tracker credentials from the team lead too. The broker is
# a deterministic process, not an LLM role with a privileged environment.
cat > lead-env-probe.sh <<'EOF'
#!/usr/bin/env bash
printf '%s|%s\n' "${LINEAR_API_KEY-unset}" "${GH_TOKEN-unset}" > lead-agent-env.txt
EOF
chmod +x lead-env-probe.sh
sed_i 's|^TEAM_LEAD_CMD=.*|TEAM_LEAD_CMD="./lead-env-probe.sh {prompt_file}"|' .claude/skills/pm/config/team.config.md
LINEAR_API_KEY=tracker-secret GH_TOKEN=github-secret SKIP_PREFLIGHT=1 TEAM_RUNNER=background \
  "$LAUNCH" gate-team full-stack broker-gates FEAT-BROKER
for i in $(seq 1 20); do [ -f lead-agent-env.txt ] && break; sleep 0.1; done
check "broker mode strips tracker credentials from team lead" grep -q '^unset|unset$' lead-agent-env.txt
check "gate-team launches team lead" test -f .teamwork/broker-gates/prompts/team-lead.md
check "gate-team launches Principal Architect" test -f .teamwork/broker-gates/prompts/principal-software-architect.md
check "gate-team launches Sceptical Architect" test -f .teamwork/broker-gates/prompts/sceptical-architect.md
check "ordinary gate-team leaves Security disabled by default" test ! -f .teamwork/broker-gates/prompts/senior-security-engineer.md
check "gate-team may launch optional QA specialist" test -f .teamwork/broker-gates/prompts/senior-qa-engineer.md
check "gate-team launches integration gate" test -f .teamwork/broker-gates/prompts/integrator.md
check "gate-team does not launch long-lived implementer" test ! -f .teamwork/broker-gates/prompts/senior-full-stack-engineer.md
check "gate-team skips explicitly disabled product-manager gate" test ! -f .teamwork/broker-gates/prompts/senior-technical-product-manager.md

SKIP_PREFLIGHT=1 TEAM_RUNNER=background \
  "$LAUNCH" gate-team deep-infra broker-infra-gates FEAT-INFRA
check "deep-infra gate-team always launches Senior Security Engineer" test -f .teamwork/broker-infra-gates/prompts/senior-security-engineer.md

SKIP_PREFLIGHT=1 TEAM_RUNNER=background \
  "$LAUNCH" gate-team deep-security broker-security-gates FEAT-SECURITY
check "deep-security gate-team always launches Senior Security Engineer" test -f .teamwork/broker-security-gates/prompts/senior-security-engineer.md

for preset in full-stack deep-backend deep-frontend deep-llm; do
  preset_file=".claude/skills/pm/teams/$preset.md"
  security_role="$(sed -n 's/^PROTOCOL_SECURITY_REVIEWER=//p' "$preset_file")"
  roster="$(sed -n 's/^ROSTER=//p' "$preset_file")"
  case " $roster " in
    *" $security_role "*)
      echo "FAIL: ordinary preset $preset starts its Security reviewer"; FAILURES=$((FAILURES+1)) ;;
    *) echo "ok: ordinary preset $preset keeps Security out of its startup roster" ;;
  esac
  grep -q '^REQUIRED_REVIEW_GATES=null$' "$preset_file" \
    || { echo "FAIL: ordinary preset $preset unexpectedly requires Security"; FAILURES=$((FAILURES+1)); }
done
check "Deep Infra is a preset-required Security gate" \
  grep -q '^REQUIRED_REVIEW_GATES=security$' .claude/skills/pm/teams/deep-infra.md
check "Deep Security is a preset-required Security gate" \
  grep -q '^REQUIRED_REVIEW_GATES=security$' .claude/skills/pm/teams/deep-security.md

# -- start refuses an unknown role (no brief anywhere) ------------------------
if TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 no-such-role 2>/dev/null; then
  echo "FAIL: unknown role should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: unknown role refused"
fi
if TEAM_RUNNER=background "$LAUNCH" start '../escape' FEAT-1 backend 2>/dev/null; then
  echo "FAIL: unsafe team id should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: unsafe team id refused"
fi
if "$LAUNCH" compose '.' FEAT-1 backend >/dev/null 2>&1; then
  echo "FAIL: dot team id should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: dot team id refused"
fi

CFG_ROOT=.claude/skills/pm/config/team.config.md
ABS_ESCAPE="$TMP/absolute-workspace"
sed_i "s|^TEAMWORK_ROOT=.*|TEAMWORK_ROOT=$ABS_ESCAPE|" "$CFG_ROOT"
if "$LAUNCH" compose absolute-root FEAT-ROOT backend >/dev/null 2>&1; then
  echo "FAIL: absolute TEAMWORK_ROOT should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: absolute TEAMWORK_ROOT refused"
fi
check "absolute TEAMWORK_ROOT wrote nothing" test ! -e "$ABS_ESCAPE"
sed_i 's|^TEAMWORK_ROOT=.*|TEAMWORK_ROOT=../traversal-workspace|' "$CFG_ROOT"
if "$LAUNCH" compose traversal-root FEAT-ROOT backend >/dev/null 2>&1; then
  echo "FAIL: traversing TEAMWORK_ROOT should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: traversing TEAMWORK_ROOT refused"
fi
check "traversing TEAMWORK_ROOT wrote nothing" test ! -e "$TMP/traversal-workspace"
mkdir -p "$TMP/symlink-workspace"
ln -s "$TMP/symlink-workspace" workspace-link
sed_i 's|^TEAMWORK_ROOT=.*|TEAMWORK_ROOT=workspace-link|' "$CFG_ROOT"
if "$LAUNCH" compose symlink-root FEAT-ROOT backend >/dev/null 2>&1; then
  echo "FAIL: escaping TEAMWORK_ROOT symlink should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: escaping TEAMWORK_ROOT symlink refused"
fi
check "TEAMWORK_ROOT symlink escape wrote nothing" test -z "$(find "$TMP/symlink-workspace" -mindepth 1 -print -quit)"
sed_i 's|^TEAMWORK_ROOT=.*|TEAMWORK_ROOT=.teamwork|' "$CFG_ROOT"
mkdir -p .teamwork/other-team
ln -s other-team .teamwork/cross-team
if "$LAUNCH" compose cross-team FEAT-ROOT backend >/dev/null 2>&1; then
  echo "FAIL: in-repository cross-team workspace symlink should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: in-repository cross-team workspace symlink refused"
fi
check "cross-team symlink wrote no prompt" test ! -e .teamwork/other-team/prompts/backend.md
if "$LAUNCH" worktree test-feature '../escape-role' T-BAD >/dev/null 2>&1; then
  echo "FAIL: unsafe role should be refused before worktree path use"; FAILURES=$((FAILURES+1))
else
  echo "ok: unsafe role refused before worktree path use"
fi
cat > .claude/skills/pm/teams/unsafe-roster.md <<'EOF'
ROSTER=../escape-role
PROTOCOL_TEAM_LEAD=../escape-role
EOF
if SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" gate-team unsafe-roster unsafe-gate FEAT-BAD >/dev/null 2>&1; then
  echo "FAIL: unsafe preset roster role should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: unsafe preset roster role refused before workspace creation"
fi
check "unsafe preset roster creates no workspace" test ! -e .teamwork/unsafe-gate

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
T42_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key T-42)"
T42_WT=".teamwork/test-feature/worktrees/backend#1-$T42_KEY"
"$LAUNCH" worktree test-feature backend T-42
check "worktree created"  test -d "$T42_WT"
check "worktree branch"   git -C "$T42_WT" rev-parse --abbrev-ref HEAD
[ "$(git -C "$T42_WT" rev-parse --abbrev-ref HEAD)" = "agent-task/test-feature/$T42_KEY" ] \
  && echo "ok: collision-safe task branch" || { echo "FAIL: branch name"; FAILURES=$((FAILURES+1)); }

# -- worktree re-add: remove the worktree dir but keep the branch, re-add should succeed --
git worktree remove "$T42_WT"
"$LAUNCH" worktree test-feature backend T-42
check "worktree re-add with existing branch" test -d "$T42_WT"

# -- worktree provisioning: WORKTREE_SETUP runs once, fail-loud -----------------
CFG_WT=.claude/skills/pm/config/team.config.md
printf 'WORKTREE_SETUP="! env | grep -q '\''^LINEAR_API_KEY='\'' && ! env | grep -q '\''^HOME='\'' && touch provisioned.txt"\n' >> "$CFG_WT"
T77_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key T-77)"
T78_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key T-78)"
LINEAR_API_KEY=must-not-leak HOME=/secret/home "$LAUNCH" worktree test-feature backend T-77
check "WORKTREE_SETUP provisioned the tree" test -f ".teamwork/test-feature/worktrees/backend#1-$T77_KEY/provisioned.txt"
check "WORKTREE_SETUP receives no scheduler credentials or ambient HOME" test -f ".teamwork/test-feature/worktrees/backend#1-$T77_KEY/provisioned.txt"
check "WORKTREE_SETUP uses protected runner argv" grep -Fq "$PWD/.teamwork/test-feature/worktrees/backend#1-$T77_KEY|/usr/bin/env|-i" "$SANDBOX_RUNNER_LOG"
sed_i '/^WORKTREE_SETUP=/d' "$CFG_WT"
printf 'WORKTREE_SETUP="false"\n' >> "$CFG_WT"
if "$LAUNCH" worktree test-feature backend T-78 >/dev/null 2>&1; then
  echo "FAIL: failing WORKTREE_SETUP should die"; FAILURES=$((FAILURES+1))
else
  echo "ok: failing WORKTREE_SETUP is fail-loud"
fi
check "failed provisioning removed the tree" test ! -d ".teamwork/test-feature/worktrees/backend#1-$T78_KEY"
sed_i '/^WORKTREE_SETUP="false"$/d' "$CFG_WT"

# -- attempt-bound relaunch isolation ------------------------------------------
"$LAUNCH" worktree-remove test-feature backend T-77
check "worktree-remove cleaned the dir" test ! -d ".teamwork/test-feature/worktrees/backend#1-$T77_KEY"
git worktree list | grep -q "backend#1-$T77_KEY" && { echo "FAIL: stale worktree registration"; FAILURES=$((FAILURES+1)); } || echo "ok: worktree pruned"
"$LAUNCH" worktree test-feature backend T-77 2
check "attempt 2 gets a fresh tree on the same branch" test -d ".teamwork/test-feature/worktrees/backend#2-$T77_KEY"
[ "$(git -C ".teamwork/test-feature/worktrees/backend#2-$T77_KEY" rev-parse --abbrev-ref HEAD)" = "agent-task/test-feature/$T77_KEY" ] \
  && echo "ok: attempt 2 reuses task branch" || { echo "FAIL: attempt-2 branch"; FAILURES=$((FAILURES+1)); }

# -- every cross-functional preset requires a live Sceptical Architect ----------
cp .claude/skills/pm/teams/full-stack.md .claude/skills/pm/teams/missing-sceptical.md
sed_i '/^PROTOCOL_SCEPTICAL_ARCHITECT=/d' .claude/skills/pm/teams/missing-sceptical.md
if mandatory_out="$(SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" team missing-sceptical mandatory-missing FEAT-MANDATORY 2>&1)"; then
  echo "FAIL: preset without Sceptical Architect mapping launched"; FAILURES=$((FAILURES+1))
elif printf '%s' "$mandatory_out" | grep -q 'must define exactly one mandatory PROTOCOL_SCEPTICAL_ARCHITECT'; then
  echo "ok: preset cannot omit mandatory Sceptical Architect mapping"
else
  echo "FAIL: missing mandatory mapping produced wrong error: $mandatory_out"; FAILURES=$((FAILURES+1))
fi
check "missing mandatory mapping creates no workspace" test ! -e .teamwork/mandatory-missing
if "$LAUNCH" compose mandatory-compose FEAT-MANDATORY backend missing-sceptical >/dev/null 2>&1; then
  echo "FAIL: harness composition accepted a preset without its mandatory Sceptical Architect"; FAILURES=$((FAILURES+1))
else
  echo "ok: harness composition also enforces the mandatory Sceptical Architect"
fi
check "invalid harness preset creates no workspace" test ! -e .teamwork/mandatory-compose

cp .claude/skills/pm/teams/full-stack.md .claude/skills/pm/teams/missing-sceptical-roster.md
sed_i 's/ sceptical-architect//' .claude/skills/pm/teams/missing-sceptical-roster.md
if mandatory_out="$(SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" gate-team missing-sceptical-roster mandatory-roster FEAT-MANDATORY 2>&1)"; then
  echo "FAIL: preset without Sceptical Architect in roster launched"; FAILURES=$((FAILURES+1))
elif printf '%s' "$mandatory_out" | grep -q 'mandatory Sceptical Architect.*exactly once'; then
  echo "ok: preset roster cannot omit mandatory Sceptical Architect"
else
  echo "FAIL: missing mandatory roster role produced wrong error: $mandatory_out"; FAILURES=$((FAILURES+1))
fi
check "missing mandatory roster role creates no workspace" test ! -e .teamwork/mandatory-roster

cp .claude/skills/pm/teams/full-stack.md .claude/skills/pm/teams/duplicate-sceptical-roster.md
sed_i 's/^ROSTER=/ROSTER=sceptical-architect /' .claude/skills/pm/teams/duplicate-sceptical-roster.md
if mandatory_out="$(SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" team duplicate-sceptical-roster mandatory-duplicate FEAT-MANDATORY 2>&1)"; then
  echo "FAIL: preset with duplicate Sceptical Architect roster entries launched"; FAILURES=$((FAILURES+1))
elif printf '%s' "$mandatory_out" | grep -q 'mandatory Sceptical Architect.*exactly once'; then
  echo "ok: preset roster requires exactly one mandatory Sceptical Architect"
else
  echo "FAIL: duplicate mandatory roster role produced wrong error: $mandatory_out"; FAILURES=$((FAILURES+1))
fi
check "duplicate mandatory role creates no workspace" test ! -e .teamwork/mandatory-duplicate

printf 'SCEPTICAL_ARCHITECT_CMD=null\n' >> .claude/skills/pm/config/team.config.md
if mandatory_out="$(SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" team full-stack mandatory-disabled FEAT-MANDATORY 2>&1)"; then
  echo "FAIL: disabled mandatory Sceptical Architect launched"; FAILURES=$((FAILURES+1))
elif printf '%s' "$mandatory_out" | grep -q 'mandatory Sceptical Architect.*cannot be disabled'; then
  echo "ok: mandatory Sceptical Architect cannot be disabled by command config"
else
  echo "FAIL: disabled mandatory role produced wrong error: $mandatory_out"; FAILURES=$((FAILURES+1))
fi
check "disabled mandatory role creates no workspace" test ! -e .teamwork/mandatory-disabled
sed_i '/^SCEPTICAL_ARCHITECT_CMD=null$/d' .claude/skills/pm/config/team.config.md

# -- every preset retains a distinct on-demand security mapping ----------------
cp .claude/skills/pm/teams/full-stack.md .claude/skills/pm/teams/missing-security.md
sed_i '/^PROTOCOL_SECURITY_REVIEWER=/d' .claude/skills/pm/teams/missing-security.md
if mandatory_out="$(SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" team missing-security mandatory-security FEAT-MANDATORY 2>&1)"; then
  echo "FAIL: preset without Senior Security Engineer mapping launched"; FAILURES=$((FAILURES+1))
elif printf '%s' "$mandatory_out" | grep -q 'must define exactly one PROTOCOL_SECURITY_REVIEWER mapping for on-demand security review'; then
  echo "ok: preset cannot omit its on-demand Senior Security Engineer mapping"
else
  echo "FAIL: missing security mapping produced wrong error: $mandatory_out"; FAILURES=$((FAILURES+1))
fi
check "missing security mapping creates no workspace" test ! -e .teamwork/mandatory-security

cp .claude/skills/pm/teams/full-stack.md .claude/skills/pm/teams/missing-team-lead-roster.md
sed_i 's/^ROSTER=team-lead /ROSTER=/' .claude/skills/pm/teams/missing-team-lead-roster.md
if mandatory_out="$(SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" gate-team missing-team-lead-roster mandatory-team-lead FEAT-MANDATORY 2>&1)"; then
  echo "FAIL: preset without Team Lead in its roster launched"; FAILURES=$((FAILURES+1))
elif printf '%s' "$mandatory_out" | grep -q "mandatory review-board role 'team-lead' exactly once"; then
  echo "ok: preset roster cannot omit the mandatory Team Lead"
else
  echo "FAIL: missing Team Lead roster role produced wrong error: $mandatory_out"; FAILURES=$((FAILURES+1))
fi
check "missing Team Lead roster role creates no workspace" test ! -e .teamwork/mandatory-team-lead

cp .claude/skills/pm/teams/full-stack.md .claude/skills/pm/teams/duplicate-reviewer-identity.md
sed_i 's/^PROTOCOL_SECURITY_REVIEWER=.*/PROTOCOL_SECURITY_REVIEWER=team-lead/' \
  .claude/skills/pm/teams/duplicate-reviewer-identity.md
if mandatory_out="$(SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" team duplicate-reviewer-identity mandatory-distinct FEAT-MANDATORY 2>&1)"; then
  echo "FAIL: preset reused a core reviewer as its security specialist"; FAILURES=$((FAILURES+1))
elif printf '%s' "$mandatory_out" | grep -Eq 'optional security reviewer.*out of its startup roster|security reviewer.*distinct'; then
  echo "ok: on-demand security specialist remains distinct from core reviewers"
else
  echo "FAIL: duplicate review-board identity produced wrong error: $mandatory_out"; FAILURES=$((FAILURES+1))
fi
check "duplicate review-board identity creates no workspace" test ! -e .teamwork/mandatory-distinct

sed_i 's|^TEAM_LEAD_CMD=.*|TEAM_LEAD_CMD=null|' .claude/skills/pm/config/team.config.md
if mandatory_out="$(SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" gate-team full-stack mandatory-lead-disabled FEAT-MANDATORY 2>&1)"; then
  echo "FAIL: disabled mandatory Team Lead launched"; FAILURES=$((FAILURES+1))
elif printf '%s' "$mandatory_out" | grep -q "mandatory review-board role 'team-lead' cannot be disabled"; then
  echo "ok: mandatory Team Lead cannot be disabled by command config"
else
  echo "FAIL: disabled Team Lead produced wrong error: $mandatory_out"; FAILURES=$((FAILURES+1))
fi
check "disabled Team Lead creates no workspace" test ! -e .teamwork/mandatory-lead-disabled
sed_i 's|^TEAM_LEAD_CMD=.*|TEAM_LEAD_CMD="./lead-env-probe.sh {prompt_file}"|' .claude/skills/pm/config/team.config.md

# -- team preset: launch a full roster from teams/full-stack.md ----------------
SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" team full-stack test-feature FEAT-2
check "preset composes fallback-role prompt" test -f .teamwork/test-feature/prompts/principal-software-architect.md
check "preset composes sceptical gate prompt" test -f .teamwork/test-feature/prompts/sceptical-architect.md
check "ordinary preset does not compose Security at startup" test ! -f .teamwork/test-feature/prompts/senior-security-engineer.md
check "preset composes team-lead gate prompt" test -f .teamwork/test-feature/prompts/team-lead.md
check "sceptical prompt contains blind-first protocol" grep -q "blind-first" .teamwork/test-feature/prompts/sceptical-architect.md
check "preset brief resolved from teams/roles" grep -q "Role: principal-software-architect" .teamwork/test-feature/prompts/principal-software-architect.md
check "preset prompt includes team file"     grep -q "Team: Full Stack" .teamwork/test-feature/prompts/principal-software-architect.md
check "preset prompt includes playbook"      grep -q "Team Playbook" .teamwork/test-feature/prompts/principal-software-architect.md
check "preset composes integrator (roles/)"  test -f .teamwork/test-feature/prompts/integrator.md
check "preset skips explicit-null role"      test ! -f .teamwork/test-feature/prompts/senior-technical-product-manager.md
for i in $(seq 1 20); do [ -f qa-received.txt ] && break; sleep 0.1; done
check "preset per-role override ran"         grep -q "Role: senior-qa-engineer" qa-received.txt

# -- Deep LLM preset: specialized prompts and independent gates ----------------
llm_arch_prompt="$("$LAUNCH" compose llm-compose FEAT-LLM principal-llm-architect deep-llm)"
llm_sceptical_prompt="$("$LAUNCH" compose llm-compose FEAT-LLM sceptical-principal-llm-architect deep-llm)"
llm_engineer_prompt="$("$LAUNCH" compose llm-compose FEAT-LLM senior-llm-engineer deep-llm)"
llm_backend_prompt="$("$LAUNCH" compose llm-compose FEAT-LLM senior-staff-backend-engineer deep-llm)"
llm_full_stack_prompt="$("$LAUNCH" compose llm-compose FEAT-LLM senior-llm-full-stack-engineer deep-llm)"
llm_qa_prompt="$("$LAUNCH" compose llm-compose FEAT-LLM senior-llm-qa-engineer deep-llm)"
llm_security_prompt="$("$LAUNCH" compose llm-compose FEAT-LLM senior-llm-security-engineer deep-llm)"
check "deep-llm prompt includes team evidence contract" grep -q "LLM evidence contract" "$llm_arch_prompt"
check "deep-llm principal prompt requires frozen holdout" grep -q "frozen holdout" "$llm_arch_prompt"
check "deep-llm sceptical prompt tests no-LLM alternative" grep -q "no-LLM" "$llm_sceptical_prompt"
check "deep-llm engineer prompt enforces split discipline" grep -q "frozen holdout" "$llm_engineer_prompt"
check "deep-llm backend prompt covers inference gateway" grep -q "inference gateway" "$llm_backend_prompt"
check "deep-llm full-stack prompt covers streaming state" grep -q "streaming as a state machine" "$llm_full_stack_prompt"
check "deep-llm QA prompt rejects sole LLM judge" grep -q "never the sole oracle" "$llm_qa_prompt"
check "deep-llm security prompt covers prompt injection" grep -q "prompt injection" "$llm_security_prompt"

# -- compose: emits the composed startup prompt without spawning (harness mode) --
out="$("$LAUNCH" compose test-compose FEAT-3 backend)"
check "compose prints an existing prompt path" test -f "$out"
check "compose prompt contains role brief"     grep -q "Role: backend" "$out"
check "compose prompt contains protocol"       grep -q "Orchestration — The Multi-Agent Protocol" "$out"
check "compose ends with artifact delivery contract" \
  test "$(tail -n 1 "$out")" = "A summary of your process without the closing artifact is a protocol violation."
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
if SKIP_PREFLIGHT=1 TEAM_RUNNER=background "$LAUNCH" team nonesuch test-feature FEAT-2 2>/dev/null; then
  echo "FAIL: unknown preset should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: unknown preset refused"
fi

# -- validate-board: canonical fixture and installed config pass ----------------
check "validate-board accepts canonical default profile" "$LAUNCH" validate-board
check "installed status config remains structurally valid" \
  "$SKILL_DIR/bin/launch-team.sh" validate-board "$SKILL_DIR/config/statuses.config.json"

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
GOODTASKS='"tasks":{"statuses":[{"name":"A","initial":true,"owner":{"role":"team-lead"},"transitions":["Z"]},{"name":"Z","terminal":true,"owner":{"role":"team-lead"},"transitions":[]}]}'
bad "markers with unknown role refused"  "unknown role" "{$MINF,$GOODTASKS,\"markers\":{\"review-approval\":{\"authorizedRoles\":[\"nobody-such\"]}}}"
bad "markers with empty list refused"    "non-empty list" "{$MINF,$GOODTASKS,\"markers\":{\"review-approval\":{\"authorizedRoles\":[]}}}"
bad "markers non-object refused"         "must be a non-empty object" "{$MINF,$GOODTASKS,\"markers\":[]}"
check "canonical default profile still passes with markers" "$LAUNCH" validate-board
check "integrator prompt carries the markers table" grep -q '"authorizedRoles"' .teamwork/test-feature/prompts/integrator.md

# -- config guard: MAX_ACTIVE_IMPLEMENTERS requires EXECUTION=parallel ---------
CFG=.claude/skills/pm/config/team.config.md
printf 'MAX_ACTIVE_IMPLEMENTERS=1\n' >> "$CFG"
if out="$("$LAUNCH" compose test-feature FEAT-1 backend 2>&1)"; then
  echo "FAIL: MAX_ACTIVE_IMPLEMENTERS under sequential should be refused"; FAILURES=$((FAILURES+1))
elif printf '%s' "$out" | grep -q "MAX_ACTIVE_IMPLEMENTERS"; then
  echo "ok: knob refused under sequential"
else
  echo "FAIL: knob refusal has wrong message: $out"; FAILURES=$((FAILURES+1))
fi
printf 'EXECUTION=parallel\n' >> "$CFG"
check "knob accepted under parallel" "$LAUNCH" compose test-feature FEAT-1 backend
sed_i '/^MAX_ACTIVE_IMPLEMENTERS=1$/d;/^EXECUTION=parallel$/d' "$CFG"
printf 'EXECUTION=parallel\nMAX_ACTIVE_IMPLEMENTERS=zero\n' >> "$CFG"
if "$LAUNCH" compose test-feature FEAT-1 backend >/dev/null 2>&1; then
  echo "FAIL: non-integer MAX_ACTIVE_IMPLEMENTERS should be refused"; FAILURES=$((FAILURES+1))
else
  echo "ok: non-integer knob refused"
fi
sed_i '/^EXECUTION=parallel$/d;/^MAX_ACTIVE_IMPLEMENTERS=zero$/d' "$CFG"

# -- preflight: aborts before any launch when the adapter probe fails -----------
cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Markdown
MARKDOWN_ROOT=.
STATUS_CONFIG=config/statuses.config.json
```
EOF
if out="$(TEAM_RUNNER=background "$LAUNCH" team full-stack pf-team missing/feature.md 2>&1)"; then
  echo "FAIL: preflight should abort on a broken adapter read"; FAILURES=$((FAILURES+1))
elif printf '%s' "$out" | grep -q "preflight"; then
  echo "ok: preflight aborts team launch on probe failure"
else
  echo "FAIL: wrong preflight abort message: $out"; FAILURES=$((FAILURES+1))
fi
check "preflight abort launched nothing" test ! -d .teamwork/pf-team/prompts

# -- preflight: passes on a working adapter; prompts carry the UTC pin ----------
mkdir -p pf && printf '# F [Planned]\n\n## 1 T [Planned]\n\n**Assignee:** —\n\nx.\n' > pf/feature.md
TEAM_RUNNER=background "$LAUNCH" start pf-team pf/feature.md backend   # start skips preflight
"$LAUNCH" preflight pf-team pf/feature.md
check "preflight writes UTC pin" test -s .teamwork/pf-team/preflight/utc.txt
out="$("$LAUNCH" compose pf-team pf/feature.md backend)"
check "composed prompt carries UTC pin" grep -q "Preflight UTC pin" "$out"

# -- preflight: MCP-style adapter needs the recorded tool prefix ----------------
cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=SomeMcpTool
STATUS_CONFIG=config/statuses.config.json
```
EOF
if "$LAUNCH" preflight pf-team pf/feature.md >/dev/null 2>&1; then
  echo "FAIL: MCP adapter without tool-prefix.txt should fail preflight"; FAILURES=$((FAILURES+1))
else
  echo "ok: MCP preflight demands a recorded tool prefix"
fi
printf 'mcp__sometool__' > .teamwork/pf-team/preflight/tool-prefix.txt
check "MCP preflight passes with prefix on record" "$LAUNCH" preflight pf-team pf/feature.md
out="$("$LAUNCH" compose pf-team pf/feature.md backend)"
check "composed prompt carries verified prefix" grep -q "mcp__sometool__" "$out"

# -- preflight: Linear+MCP fails; tool-prefix.txt does NOT bypass the guard ----
cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Linear
LINEAR_ACCESS=mcp                 # mcp = Linear MCP server
STATUS_CONFIG=config/statuses.config.json
```
EOF
mcp_pf_out="$("$LAUNCH" preflight pf-team pf/feature.md 2>&1 || true)"
echo "$mcp_pf_out" | grep -q "CLI dispatcher requires scriptable tracker access for Linear" \
  && echo "ok: Linear+MCP: preflight fails with scriptable-access message" \
  || { echo "FAIL: Linear+MCP preflight wrong message: $mcp_pf_out"; FAILURES=$((FAILURES+1)); }
printf 'mcp__linear__' > .teamwork/pf-team/preflight/tool-prefix.txt
mcp_pf_out2="$("$LAUNCH" preflight pf-team pf/feature.md 2>&1 || true)"
echo "$mcp_pf_out2" | grep -q "CLI dispatcher requires scriptable tracker access for Linear" \
  && echo "ok: tool-prefix.txt does not bypass Linear+MCP guard" \
  || { echo "FAIL: tool-prefix bypassed the MCP guard: $mcp_pf_out2"; FAILURES=$((FAILURES+1)); }

# Negative guard: false MCP flag with shipped inline-comment format must NOT trip the MCP guard
cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=GitHubIssues
GITHUB_USE_MCP=false              # false = gh CLI
STATUS_CONFIG=config/statuses.config.json
```
EOF
neg_pf_out="$("$LAUNCH" preflight pf-team pf/feature.md 2>&1 || true)"
if echo "$neg_pf_out" | grep -q "CLI dispatcher requires scriptable tracker access"; then
  echo "FAIL: GITHUB_USE_MCP=false incorrectly triggered MCP guard"; FAILURES=$((FAILURES+1))
else
  echo "ok: GITHUB_USE_MCP=false (with inline comment) not treated as MCP-only"
fi

cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Markdown
MARKDOWN_ROOT=.
STATUS_CONFIG=config/statuses.config.json
```
EOF

# -- tmux liveness: pid file removed on agent exit; dead pane never blocks relaunch ----
tmux_usable=no
tmux_probe="startup-factory-probe-$$"
if command -v tmux >/dev/null 2>&1 && tmux new-session -d -s "$tmux_probe" 'sleep 1' >/dev/null 2>&1; then
  tmux_usable=yes
  tmux kill-session -t "$tmux_probe" 2>/dev/null || true
fi
if [ "${TEAM_RUNNER:-auto}" != "background" ] && [ "$tmux_usable" = yes ]; then
  TL_TEAM="tmux-liveness"
  tmux kill-session -t "team-$TL_TEAM" 2>/dev/null || true
  rm -rf ".teamwork/$TL_TEAM"
  # Launch backend via tmux (no TEAM_RUNNER override → auto picks tmux when available)
  "$LAUNCH" start "$TL_TEAM" FEAT-T backend
  check "tmux: pid file written on launch" test -f ".teamwork/$TL_TEAM/pids/backend.pid"
  # Poll up to 10 s for pid file removal (agent command exits → rm -f in pane → sleep)
  _tl_done=no
  for _tl_i in $(seq 1 50); do
    [ ! -f ".teamwork/$TL_TEAM/pids/backend.pid" ] && _tl_done=yes && break
    sleep 0.2
  done
  if [ "$_tl_done" = "yes" ]; then
    echo "ok: tmux: pid file removed after agent exit"
  else
    echo "FAIL: tmux: pid file still present after 10 s — rm -f not running in pane"
    FAILURES=$((FAILURES+1))
  fi
  # A re-start must succeed (role is not live — pid absent); new pid file written
  relaunch_out="$("$LAUNCH" start "$TL_TEAM" FEAT-T backend 2>&1)"
  echo "$relaunch_out" | grep -q "launched backend in tmux" \
    && echo "ok: tmux: relaunch succeeds (not considered live)" \
    || { echo "FAIL: tmux: relaunch did not say launched — output: $relaunch_out"; FAILURES=$((FAILURES+1)); }
  tmux kill-session -t "team-$TL_TEAM" 2>/dev/null || true
else
  echo "skip: tmux tests (tmux unavailable/unusable or TEAM_RUNNER=background)"
fi

# -- lifecycle authority is external; workspace/PID tampering never selects a signal target --
CFG_LIFECYCLE=.claude/skills/pm/config/team.config.md
sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="sleep 30"|' "$CFG_LIFECYCLE"

record_for() { # team instance
  python3 - "$LIFECYCLE_ROOT" "$1" "$2" <<'PY'
import json, pathlib, sys
root, team, instance = sys.argv[1:]
matches = []
for path in pathlib.Path(root, "records").glob("*.json"):
    record = json.loads(path.read_text())
    if record["team"] == team and record["instance"] == instance:
        matches.append(path)
assert len(matches) == 1, matches
print(matches[0])
PY
}

SESSION_SLEEPER="$TMP/session-sleeper.py"
cat > "$SESSION_SLEEPER" <<'PY'
import os
import pathlib
import sys
import time

os.setsid()
pathlib.Path(sys.argv[1]).touch()
time.sleep(30)
PY

spawn_lifecycle_sleep() { # print PID of a detached, dedicated session leader
  local ready_dir ready pid
  ready_dir="$(mktemp -d "$TMP/session-ready.XXXXXX")"
  ready="$ready_dir/ready"
  pid="$(/bin/sh -c '"$1" "$2" "$3" </dev/null >/dev/null 2>&1 & printf "%s\n" "$!"' \
    lifecycle-session-sleeper "$(command -v python3)" "$SESSION_SLEEPER" "$ready")"
  for _i in $(seq 1 40); do [ -f "$ready" ] && break; sleep 0.05; done
  [ -f "$ready" ] || { kill "$pid" 2>/dev/null || true; return 1; }
  rm -f "$ready"; rmdir "$ready_dir"
  printf '%s\n' "$pid"
}

TERM_IGNORER="$TMP/term-ignorer.py"
cat > "$TERM_IGNORER" <<'PY'
import os
import pathlib
import signal
import subprocess
import sys
import time

os.setsid()
child_ready = pathlib.Path(str(sys.argv[1]) + ".child")
child_code = """
import pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(sys.argv[1]).touch()
time.sleep(30)
"""
child = subprocess.Popen([sys.executable, "-c", child_code, str(child_ready)])
for _ in range(200):
    if child_ready.exists():
        break
    time.sleep(0.01)
else:
    child.kill()
    raise SystemExit("child did not install its TERM handler")
pathlib.Path(sys.argv[1]).write_text(
    f"{os.getpid()} {child.pid}\n", encoding="ascii"
)
time.sleep(30)
PY

spawn_term_ignoring_process() { # ready-file -> detached PID
  /bin/sh -c '"$1" "$2" "$3" </dev/null >/dev/null 2>&1 & printf "%s\n" "$!"' \
    lifecycle-term-ignorer "$(command -v python3)" "$TERM_IGNORER" "$1"
}

register_lifecycle_process() { # team category instance pid
  python3 .claude/skills/pm/bin/process-lifecycle.py register \
    --root "$LIFECYCLE_ROOT" --repo "$PWD" \
    --team "$1" --category "$2" --instance "$3" --kind background --pid "$4" >/dev/null
}

record_count() { # team instance
  python3 - "$LIFECYCLE_ROOT" "$1" "$2" <<'PY'
import json, pathlib, sys
root, team, instance = sys.argv[1:]
count = 0
for path in pathlib.Path(root, "records").glob("*.json"):
    record = json.loads(path.read_text())
    count += record["team"] == team and record["instance"] == instance
print(count)
PY
}

active_capability_count() { # team execution-kind task-id
  python3 - "$PWD" "$1" "$2" "$3" <<'PY'
import json, pathlib, subprocess, sys
repo, team, kind, task = sys.argv[1:]
common = pathlib.Path(subprocess.check_output(
    ["git", "-C", repo, "rev-parse", "--git-common-dir"], text=True
).strip())
if not common.is_absolute():
    common = pathlib.Path(repo, common)
broker = common.resolve() / "startup-factory-broker"
records = broker / "outbox-capabilities"
active = broker / "outbox-active"
count = 0
for pointer in active.glob("*.id"):
    capability_id = pointer.read_text().strip()
    record = json.loads((records / (capability_id + ".json")).read_text())
    count += (
        record.get("team") == team
        and record.get("executionKind") == kind
        and record.get("taskId") == task
    )
print(count)
PY
}

# A tmux pane is only a presentation/supervisor identity.  The task itself is
# bound to a separate authenticated session/group so descendants cannot escape
# merely because their pane wrapper exits.
if [ "${TEAM_RUNNER:-auto}" != "background" ] && [ "$tmux_usable" = yes ]; then
  TMUX_GROUP_WRAPPER="$TMP/tmux-group-wrapper.py"
  cat > "$TMUX_GROUP_WRAPPER" <<'PY'
import os
import sys

child = os.fork()
if child == 0:
    os.execv(sys.executable, [sys.executable, sys.argv[1], sys.argv[2]])
_, status = os.waitpid(child, 0)
raise SystemExit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))
PY
  TMUX_STOP_TEAM=stop-task-tmux
  TMUX_STOP_TASK='T-tmux-child'
  TMUX_STOP_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$TMUX_STOP_TASK")"
  TMUX_STOP_INSTANCE="backend--$TMUX_STOP_KEY--a1"
  TMUX_STOP_SESSION="team-$TMUX_STOP_TEAM"
  TMUX_STOP_READY="$TMP/tmux-stop-ready"
  tmux kill-session -t "$TMUX_STOP_SESSION" 2>/dev/null || true
  tmux new-session -d -s "$TMUX_STOP_SESSION" -n _hub
  printf -v _tmux_python_q '%q' "$(command -v python3)"
  printf -v _tmux_wrapper_q '%q' "$TMUX_GROUP_WRAPPER"
  printf -v _tmux_ignorer_q '%q' "$TERM_IGNORER"
  printf -v _tmux_ready_q '%q' "$TMUX_STOP_READY"
  tmux_stop_pane_info="$(tmux new-window -d -P -F '#{pane_id}|#{pane_pid}' \
    -t "$TMUX_STOP_SESSION" -n "$TMUX_STOP_INSTANCE" \
    "exec $_tmux_python_q $_tmux_wrapper_q $_tmux_ignorer_q $_tmux_ready_q")"
  TMUX_STOP_PANE="${tmux_stop_pane_info%%|*}"
  TMUX_STOP_PANE_PID="${tmux_stop_pane_info#*|}"
  for _i in $(seq 1 100); do [ -s "$TMUX_STOP_READY" ] && break; sleep 0.02; done
  read -r TMUX_STOP_LEADER_PID TMUX_STOP_CHILD_PID < "$TMUX_STOP_READY"
  python3 .claude/skills/pm/bin/process-lifecycle.py register \
    --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$TMUX_STOP_TEAM" \
    --category task --instance "$TMUX_STOP_INSTANCE" --kind tmux --pid "$TMUX_STOP_LEADER_PID" \
    --tmux-session "$TMUX_STOP_SESSION" --tmux-window "$TMUX_STOP_INSTANCE" \
    --tmux-pane "$TMUX_STOP_PANE" --tmux-pane-pid "$TMUX_STOP_PANE_PID" >/dev/null
  mkdir -p ".teamwork/$TMUX_STOP_TEAM/pids/tasks"
  printf 'managed\n' > ".teamwork/$TMUX_STOP_TEAM/pids/tasks/$TMUX_STOP_INSTANCE.pid"
  "$LAUNCH" stop-task "$TMUX_STOP_TEAM" "$TMUX_STOP_TASK" >/dev/null
  for _i in $(seq 1 80); do
    if ! kill -0 "$TMUX_STOP_LEADER_PID" 2>/dev/null \
        && ! kill -0 "$TMUX_STOP_CHILD_PID" 2>/dev/null; then break; fi
    sleep 0.05
  done
  check "tmux stop-task terminates dedicated task group leader" bash -c "! kill -0 '$TMUX_STOP_LEADER_PID' 2>/dev/null"
  check "tmux stop-task SIGKILL terminates TERM-resistant child" bash -c "! kill -0 '$TMUX_STOP_CHILD_PID' 2>/dev/null"
  check "tmux stop-task retires protected group lifecycle" test "$(record_count "$TMUX_STOP_TEAM" "$TMUX_STOP_INSTANCE")" -eq 0
  tmux_stop_observed_pane="$(tmux display-message -p -t "$TMUX_STOP_PANE" '#{pane_id}' 2>/dev/null || true)"
  if [ "$tmux_stop_observed_pane" = "$TMUX_STOP_PANE" ]; then
    echo "FAIL: tmux stop-task left its verified pane live"; FAILURES=$((FAILURES+1))
  else
    echo "ok: tmux stop-task retires its verified pane"
  fi
  tmux kill-session -t "$TMUX_STOP_SESSION" 2>/dev/null || true
else
  echo "skip: tmux task process-group stop test"
fi

TEAM_RUNNER=background "$LAUNCH" start lifecycle-workspace FEAT-LIFE backend >/dev/null
workspace_record="$(record_for lifecycle-workspace backend)"
workspace_agent_pid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' "$workspace_record")"
sleep 30 & workspace_victim_pid=$!
printf '%s\n' "$workspace_victim_pid" > .teamwork/lifecycle-workspace/pids/backend.pid
"$LAUNCH" stop lifecycle-workspace >/dev/null
check "workspace PID tampering never signals unrelated process" kill -0 "$workspace_victim_pid"
for _i in $(seq 1 20); do kill -0 "$workspace_agent_pid" 2>/dev/null || break; sleep 0.05; done
check "stop signals the protected identity instead of workspace PID" bash -c "! kill -0 '$workspace_agent_pid' 2>/dev/null"
kill "$workspace_victim_pid" 2>/dev/null || true
wait "$workspace_victim_pid" 2>/dev/null || true

TEAM_RUNNER=background "$LAUNCH" start lifecycle-auth FEAT-LIFE backend >/dev/null
auth_record="$(record_for lifecycle-auth backend)"
auth_agent_pid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' "$auth_record")"
sleep 30 & auth_victim_pid=$!
python3 - "$auth_record" "$auth_victim_pid" <<'PY'
import json, sys
path, victim = sys.argv[1:]
record = json.load(open(path))
record["pid"] = int(victim)
open(path, "w").write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
if "$LAUNCH" stop lifecycle-auth >lifecycle-auth-stop.out 2>&1; then
  echo "FAIL: unauthenticated protected lifecycle tampering was accepted"; FAILURES=$((FAILURES+1))
elif grep -q 'authentication failed\|failed authentication' lifecycle-auth-stop.out; then
  echo "ok: protected lifecycle record tampering fails closed"
else
  echo "FAIL: protected lifecycle tamper returned wrong error: $(cat lifecycle-auth-stop.out)"; FAILURES=$((FAILURES+1))
fi
check "tampered protected record does not signal original process" kill -0 "$auth_agent_pid"
check "tampered protected record does not signal substituted process" kill -0 "$auth_victim_pid"
kill "$auth_agent_pid" "$auth_victim_pid" 2>/dev/null || true
wait "$auth_agent_pid" 2>/dev/null || true
wait "$auth_victim_pid" 2>/dev/null || true
rm -f "$auth_record"

TEAM_RUNNER=background "$LAUNCH" start lifecycle-identity FEAT-LIFE backend >/dev/null
identity_record="$(record_for lifecycle-identity backend)"
identity_agent_pid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' "$identity_record")"
python3 - "$identity_record" "$LIFECYCLE_ROOT/record-auth.key" <<'PY'
import hashlib, hmac, json, sys
record_path, key_path = sys.argv[1:]
record = json.load(open(record_path))
record["processIdentity"] = "forged-start-identity"
record.pop("auth")
payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
record["auth"] = hmac.new(open(key_path, "rb").read(), payload, hashlib.sha256).hexdigest()
open(record_path, "w").write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
if "$LAUNCH" stop lifecycle-identity >lifecycle-identity-stop.out 2>&1; then
  echo "FAIL: protected process identity mismatch was accepted"; FAILURES=$((FAILURES+1))
elif grep -q 'identity mismatch' lifecycle-identity-stop.out; then
  echo "ok: protected process identity mismatch fails closed"
else
  echo "FAIL: identity mismatch returned wrong error: $(cat lifecycle-identity-stop.out)"; FAILURES=$((FAILURES+1))
fi
check "identity mismatch never signals recorded PID" kill -0 "$identity_agent_pid"
kill "$identity_agent_pid" 2>/dev/null || true
wait "$identity_agent_pid" 2>/dev/null || true
rm -f "$identity_record"

sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="cat {prompt_file} > backend-received.txt"|' "$CFG_LIFECYCLE"

# -- task-scoped stop: exact collision-safe task selection, stale retirement, idempotence --
STOP_TASK_TEAM=stop-task-scope
STOP_TASK_ID='T/blocked 42'
STOP_TASK_SIBLING_ID='T blocked 42'
STOP_TASK_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$STOP_TASK_ID")"
STOP_TASK_SIBLING_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$STOP_TASK_SIBLING_ID")"
STOP_TASK_INSTANCE_1="backend--$STOP_TASK_KEY--a1"
STOP_TASK_INSTANCE_2="senior-qa-engineer--$STOP_TASK_KEY--a2"
STOP_TASK_STALE_INSTANCE="reviewer--$STOP_TASK_KEY--a3"
STOP_TASK_TERM_INSTANCE="frontend--$STOP_TASK_KEY--a4"
STOP_TASK_SIBLING_INSTANCE="backend--$STOP_TASK_SIBLING_KEY--a1"
STOP_TASK_GATE_INSTANCE=team-lead
STOP_TASK_PID_1="$(spawn_lifecycle_sleep)"
STOP_TASK_PID_2="$(spawn_lifecycle_sleep)"
STOP_TASK_STALE_PID="$(spawn_lifecycle_sleep)"
STOP_TASK_TERM_READY="$TMP/stop-task-term-ready"
STOP_TASK_TERM_PID="$(spawn_term_ignoring_process "$STOP_TASK_TERM_READY")"
STOP_TASK_SIBLING_PID="$(spawn_lifecycle_sleep)"
STOP_TASK_GATE_PID="$(spawn_lifecycle_sleep)"
for _i in $(seq 1 40); do [ -f "$STOP_TASK_TERM_READY" ] && break; sleep 0.05; done
check "TERM-resistant lifecycle fixture installed its signal handler" test -f "$STOP_TASK_TERM_READY"
read -r STOP_TASK_TERM_REPORTED_LEADER STOP_TASK_TERM_CHILD_PID < "$STOP_TASK_TERM_READY"
check "TERM-resistant fixture reports authenticated group leader" test "$STOP_TASK_TERM_REPORTED_LEADER" = "$STOP_TASK_TERM_PID"
check "TERM-resistant lifecycle fixture started a child" kill -0 "$STOP_TASK_TERM_CHILD_PID"
register_lifecycle_process "$STOP_TASK_TEAM" task "$STOP_TASK_INSTANCE_1" "$STOP_TASK_PID_1"
register_lifecycle_process "$STOP_TASK_TEAM" task "$STOP_TASK_INSTANCE_2" "$STOP_TASK_PID_2"
register_lifecycle_process "$STOP_TASK_TEAM" task "$STOP_TASK_STALE_INSTANCE" "$STOP_TASK_STALE_PID"
register_lifecycle_process "$STOP_TASK_TEAM" task "$STOP_TASK_TERM_INSTANCE" "$STOP_TASK_TERM_PID"
register_lifecycle_process "$STOP_TASK_TEAM" task "$STOP_TASK_SIBLING_INSTANCE" "$STOP_TASK_SIBLING_PID"
register_lifecycle_process "$STOP_TASK_TEAM" gate "$STOP_TASK_GATE_INSTANCE" "$STOP_TASK_GATE_PID"
mkdir -p ".teamwork/$STOP_TASK_TEAM/pids/tasks" ".teamwork/$STOP_TASK_TEAM/pids"
printf 'managed\n' > ".teamwork/$STOP_TASK_TEAM/pids/tasks/$STOP_TASK_INSTANCE_1.pid"
printf 'managed\n' > ".teamwork/$STOP_TASK_TEAM/pids/tasks/$STOP_TASK_INSTANCE_2.pid"
printf 'managed\n' > ".teamwork/$STOP_TASK_TEAM/pids/tasks/$STOP_TASK_STALE_INSTANCE.pid"
printf 'managed\n' > ".teamwork/$STOP_TASK_TEAM/pids/tasks/$STOP_TASK_TERM_INSTANCE.pid"
printf 'managed\n' > ".teamwork/$STOP_TASK_TEAM/pids/tasks/$STOP_TASK_SIBLING_INSTANCE.pid"
printf 'managed\n' > ".teamwork/$STOP_TASK_TEAM/pids/$STOP_TASK_GATE_INSTANCE.pid"
python3 .claude/skills/pm/bin/outbox_capability.py mint \
  --repo "$PWD" --workspace "$PWD/.teamwork/$STOP_TASK_TEAM" --team "$STOP_TASK_TEAM" \
  --feature FEAT-STOP --role backend --kind task --task "$STOP_TASK_ID" \
  --attempt 1 --instance "$STOP_TASK_INSTANCE_1" >/dev/null
python3 .claude/skills/pm/bin/outbox_capability.py mint \
  --repo "$PWD" --workspace "$PWD/.teamwork/$STOP_TASK_TEAM" --team "$STOP_TASK_TEAM" \
  --feature FEAT-STOP --role backend --kind task --task "$STOP_TASK_SIBLING_ID" \
  --attempt 1 --instance "$STOP_TASK_SIBLING_INSTANCE" >/dev/null
python3 .claude/skills/pm/bin/outbox_capability.py mint \
  --repo "$PWD" --workspace "$PWD/.teamwork/$STOP_TASK_TEAM" --team "$STOP_TASK_TEAM" \
  --feature FEAT-STOP --role team-lead --kind gate --task - \
  --attempt 0 --instance "$STOP_TASK_GATE_INSTANCE" >/dev/null
kill "$STOP_TASK_STALE_PID"
for _i in $(seq 1 40); do kill -0 "$STOP_TASK_STALE_PID" 2>/dev/null || break; sleep 0.05; done

"$LAUNCH" stop-task "$STOP_TASK_TEAM" "$STOP_TASK_ID" >/dev/null
for _i in $(seq 1 40); do
  if ! kill -0 "$STOP_TASK_PID_1" 2>/dev/null \
      && ! kill -0 "$STOP_TASK_PID_2" 2>/dev/null \
      && ! kill -0 "$STOP_TASK_TERM_PID" 2>/dev/null \
      && ! kill -0 "$STOP_TASK_TERM_CHILD_PID" 2>/dev/null; then break; fi
  sleep 0.05
done
check "stop-task stops every live role and attempt for the task" bash -c "! kill -0 '$STOP_TASK_PID_1' 2>/dev/null && ! kill -0 '$STOP_TASK_PID_2' 2>/dev/null"
check "stop-task process-group TERM stops the task leader" bash -c "! kill -0 '$STOP_TASK_TERM_PID' 2>/dev/null"
check "stop-task identity-bound group SIGKILL stops TERM-resistant child" bash -c "! kill -0 '$STOP_TASK_TERM_CHILD_PID' 2>/dev/null"
check "stop-task leaves sibling task process live" kill -0 "$STOP_TASK_SIBLING_PID"
check "stop-task never stops gate role" kill -0 "$STOP_TASK_GATE_PID"
check "stop-task retires first live lifecycle record" test "$(record_count "$STOP_TASK_TEAM" "$STOP_TASK_INSTANCE_1")" -eq 0
check "stop-task retires every matching attempt record" test "$(record_count "$STOP_TASK_TEAM" "$STOP_TASK_INSTANCE_2")" -eq 0
check "stop-task retires stale matching record" test "$(record_count "$STOP_TASK_TEAM" "$STOP_TASK_STALE_INSTANCE")" -eq 0
check "stop-task retires TERM-resistant lifecycle record after SIGKILL" test "$(record_count "$STOP_TASK_TEAM" "$STOP_TASK_TERM_INSTANCE")" -eq 0
check "stop-task preserves sibling lifecycle record" test "$(record_count "$STOP_TASK_TEAM" "$STOP_TASK_SIBLING_INSTANCE")" -eq 1
check "stop-task preserves gate lifecycle record" test "$(record_count "$STOP_TASK_TEAM" "$STOP_TASK_GATE_INSTANCE")" -eq 1
check "stop-task removes first matching task marker" test ! -e ".teamwork/$STOP_TASK_TEAM/pids/tasks/$STOP_TASK_INSTANCE_1.pid"
check "stop-task removes all matching task markers" test ! -e ".teamwork/$STOP_TASK_TEAM/pids/tasks/$STOP_TASK_STALE_INSTANCE.pid"
check "stop-task removes TERM-resistant task marker" test ! -e ".teamwork/$STOP_TASK_TEAM/pids/tasks/$STOP_TASK_TERM_INSTANCE.pid"
check "stop-task preserves sibling task marker" test -e ".teamwork/$STOP_TASK_TEAM/pids/tasks/$STOP_TASK_SIBLING_INSTANCE.pid"
check "stop-task preserves gate marker" test -e ".teamwork/$STOP_TASK_TEAM/pids/$STOP_TASK_GATE_INSTANCE.pid"
check "stop-task revokes target task capabilities" test "$(active_capability_count "$STOP_TASK_TEAM" task "$STOP_TASK_ID")" -eq 0
check "stop-task preserves sibling task capabilities" test "$(active_capability_count "$STOP_TASK_TEAM" task "$STOP_TASK_SIBLING_ID")" -eq 1
check "stop-task preserves gate capabilities" test "$(active_capability_count "$STOP_TASK_TEAM" gate -)" -eq 1
if "$LAUNCH" stop-task "$STOP_TASK_TEAM" "$STOP_TASK_ID" >/dev/null 2>&1; then
  echo "ok: stop-task is idempotent after lifecycle records are retired"
else
  echo "FAIL: repeated stop-task was not idempotent"; FAILURES=$((FAILURES+1))
fi
check "repeated stop-task still leaves sibling live" kill -0 "$STOP_TASK_SIBLING_PID"
check "repeated stop-task still leaves gate live" kill -0 "$STOP_TASK_GATE_PID"
"$LAUNCH" stop "$STOP_TASK_TEAM" >/dev/null

# Refuse the whole task stop before signalling if any matching protected
# identity has changed, so one forged record cannot produce a partial stop.
STOP_TASK_BAD_TEAM=stop-task-identity
STOP_TASK_BAD_ID='T-identity-stop'
STOP_TASK_BAD_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$STOP_TASK_BAD_ID")"
STOP_TASK_GOOD_INSTANCE="backend--$STOP_TASK_BAD_KEY--a1"
STOP_TASK_BAD_INSTANCE="reviewer--$STOP_TASK_BAD_KEY--a2"
STOP_TASK_GOOD_PID="$(spawn_lifecycle_sleep)"
STOP_TASK_BAD_PID="$(spawn_lifecycle_sleep)"
register_lifecycle_process "$STOP_TASK_BAD_TEAM" task "$STOP_TASK_GOOD_INSTANCE" "$STOP_TASK_GOOD_PID"
register_lifecycle_process "$STOP_TASK_BAD_TEAM" task "$STOP_TASK_BAD_INSTANCE" "$STOP_TASK_BAD_PID"
mkdir -p ".teamwork/$STOP_TASK_BAD_TEAM/pids/tasks"
printf 'managed\n' > ".teamwork/$STOP_TASK_BAD_TEAM/pids/tasks/$STOP_TASK_GOOD_INSTANCE.pid"
printf 'managed\n' > ".teamwork/$STOP_TASK_BAD_TEAM/pids/tasks/$STOP_TASK_BAD_INSTANCE.pid"
stop_task_good_record="$(record_for "$STOP_TASK_BAD_TEAM" "$STOP_TASK_GOOD_INSTANCE")"
stop_task_bad_record="$(record_for "$STOP_TASK_BAD_TEAM" "$STOP_TASK_BAD_INSTANCE")"
python3 - "$stop_task_bad_record" "$LIFECYCLE_ROOT/record-auth.key" <<'PY'
import hashlib, hmac, json, sys
record_path, key_path = sys.argv[1:]
record = json.load(open(record_path))
record["processIdentity"] = "forged-task-stop-identity"
record.pop("auth")
payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
record["auth"] = hmac.new(open(key_path, "rb").read(), payload, hashlib.sha256).hexdigest()
open(record_path, "w").write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
if "$LAUNCH" stop-task "$STOP_TASK_BAD_TEAM" "$STOP_TASK_BAD_ID" >stop-task-identity.out 2>&1; then
  echo "FAIL: stop-task accepted a protected identity mismatch"; FAILURES=$((FAILURES+1))
elif grep -q 'identity mismatch' stop-task-identity.out; then
  echo "ok: stop-task refuses a protected identity mismatch"
else
  echo "FAIL: stop-task identity mismatch returned wrong error: $(cat stop-task-identity.out)"; FAILURES=$((FAILURES+1))
fi
check "stop-task identity preflight leaves valid matching process live" kill -0 "$STOP_TASK_GOOD_PID"
check "stop-task identity preflight never signals mismatched PID" kill -0 "$STOP_TASK_BAD_PID"
check "failed stop-task preserves matching marker" test -e ".teamwork/$STOP_TASK_BAD_TEAM/pids/tasks/$STOP_TASK_GOOD_INSTANCE.pid"
kill "$STOP_TASK_GOOD_PID" "$STOP_TASK_BAD_PID" 2>/dev/null || true
for _i in $(seq 1 40); do
  if ! kill -0 "$STOP_TASK_GOOD_PID" 2>/dev/null && ! kill -0 "$STOP_TASK_BAD_PID" 2>/dev/null; then break; fi
  sleep 0.05
done
rm -f "$stop_task_good_record" "$stop_task_bad_record"

# -- status + stop --------------------------------------------------------------
# Capture first (grep -q closes the pipe early → SIGPIPE on the writer under pipefail).
status_out="$("$LAUNCH" status test-feature)"
echo "$status_out" | grep -q backend && echo "ok: status lists role" || { echo "FAIL: status"; FAILURES=$((FAILURES+1)); }
"$LAUNCH" stop test-feature
echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
