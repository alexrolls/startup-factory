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
LIFECYCLE_ROOT="$(mktemp -d "$HOME/.sf-launcher-lifecycle.XXXXXXXX")"
LIFECYCLE_ROOT="$(cd "$LIFECYCLE_ROOT" && pwd -P)"
trap 'rm -rf "$TMP" "$LIFECYCLE_ROOT"' EXIT
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
chmod 700 "$LIFECYCLE_ROOT"

# -- fixture repo ------------------------------------------------------------
cd "$TMP"
git init -q repo && cd repo
git config user.email test@example.com
git config user.name Test
printf '/.startup-factory-retrospective.md\n/.startup-factory-retrospective.lock\n' > .gitignore
git add .gitignore
git commit -q -m init
git checkout -q -b test-feature
mkdir -p .claude/skills/pm
cp -R "$SKILL_DIR/roles" "$SKILL_DIR/reference" "$SKILL_DIR/bin" \
  "$SKILL_DIR/src" "$SKILL_DIR/teams" .claude/skills/pm/
mkdir -p .claude/skills/pm/config
cp "$DEFAULT_STATUS_FIXTURE" .claude/skills/pm/config/statuses.config.json
cp "$SKILL_DIR/config/planning.config.md" "$SKILL_DIR/config/automation.config.json" \
  .claude/skills/pm/config/
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
cat > .claude/skills/pm/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Markdown
MARKDOWN_ROOT=.
STATUS_CONFIG=config/statuses.config.json
```
EOF
LAUNCH=".claude/skills/pm/bin/launch-team.sh"

prepare_task_claim() { # team feature task role attempt [target]
  local claim_team="$1" claim_feature="$2" claim_task="$3" claim_role="$4"
  local claim_attempt="$5" claim_target="${6:-Active}" claim_workspace claim_id
  claim_workspace="$PWD/.teamwork/$claim_team"
  claim_id="$(python3 - "$claim_team" "$claim_feature" "$claim_task" "$claim_role" "$claim_attempt" "$claim_target" <<'PY'
import hashlib,sys
print("dispatch-"+hashlib.sha256("\0".join(sys.argv[1:]).encode()).hexdigest()[:32])
PY
)"
  python3 .claude/skills/pm/bin/runtime-state.py claim \
    --repo "$PWD" --workspace "$claim_workspace" --team "$claim_team" \
    --feature "$claim_feature" --task "$claim_task" --role "$claim_role" \
    --attempt "$claim_attempt" --claim-id "$claim_id" --target "$claim_target" >/dev/null
  printf '[claim]\nclaim-id: %s\nrole: %s\ntarget-status: %s\n\n— dispatcher\n' \
    "$claim_id" "$claim_role" "$claim_target" | \
    .claude/skills/pm/bin/tracker-ops.sh comment "$claim_task" - >/dev/null
}

check "managed tmux launch pins the verified authority interpreter" \
  grep -Fq 'printf -v quoted_python '\''%q'\'' "$AUTHORITY_PYTHON"' "$LAUNCH"
check "managed tmux wrapper isolates the pinned interpreter" \
  grep -Fq 'shell_cmd="exec $quoted_python -I -B $quoted_wrapper' "$LAUNCH"
check "tmux ready-failure cleanup carries its exact lifecycle generation and token" \
  python3 - "$LAUNCH" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
tmux = source.split("spawn_managed_tmux()", 1)[1].split(
    "lifecycle_wait_and_retire()", 1
)[0]
assert 'launch_token="$(python3 -c' in tmux
assert tmux.index('launch_token="$(python3 -c') < tmux.index('pane_info="$(tmux_cmd new-window')
assert 'shell_cmd=": sfgen-$generation_tag; $shell_cmd"' in tmux
assert tmux.index('shell_cmd=": sfgen-$generation_tag; $shell_cmd"') < tmux.index('pane_info="$(tmux_cmd new-window')
assert tmux.index('pane_info="$(tmux_cmd new-window') < tmux.index('lifecycle_register "$team"')
assert '"$pane_pid" "$launch_token"' in tmux
assert tmux.count('tmux_cmd set-option') == 0
assert re.search(
    r'lifecycle_stop_instance\s+\\?\s*\n?\s*"\$team" "\$category" "\$instance"\s+\\?\s*\n?\s*'
    r'"\$LAST_LAUNCH_CREATED_AT" "\$LAST_LAUNCH_TOKEN"',
    tmux,
)
stop = source.split("lifecycle_stop_instance()", 1)[1].split(
    "prepare_execution()", 1
)[0]
assert 'expected_created="$4"' in stop
assert '--expected-created-at "$expected_created"' in stop
assert 'verify_args+=(--expect-token-stdin)' in stop
PY
if grep -Eq 'quoted_python=.*command -v python3' "$LAUNCH"; then
  echo "FAIL: managed tmux launch resolves ambient python3"; FAILURES=$((FAILURES+1))
else
  echo "ok: managed tmux launch never resolves ambient python3"
fi
TMUX_RETIRE_FUNCTION="$(python3 - "$LAUNCH" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
tag_start = source.index("tmux_generation_tag() {")
tag_end = source.index("\nacquire_launch_lane_lock() {", tag_start)
start = source.index("lifecycle_retire_tmux_pane() {")
end = source.index("\nlifecycle_stop_instance() {", start)
function = source[start:end]
assert function.count("tmux_cmd ") == 1
assert "tmux_cmd if-shell -F" in function
assert "display-message" not in function
assert "#{pane_start_command}" in function
assert '"$launch_token"' in function
print(source[tag_start:tag_end] + "\n" + function)
PY
)"
TMUX_RESTART_WITNESS="$TMP/tmux-restarted-server-wrong-pane"
if bash -c '
set -eu
eval "$1"
witness="$2"
calls=0
tmux_cmd() {
  calls=$((calls + 1))
  case "$1" in
    if-shell)
      # The old server accepted this one request and then disappeared.  A safe
      # client never reconnects to apply the pane id to the successor server.
      return 1
      ;;
    display-message)
      printf "%s\n" "4242|team-race|worker|%1|0"
      ;;
    kill-pane)
      : > "$witness"
      ;;
  esac
}
lifecycle_retire_tmux_pane 4242 team-race worker %1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[ "$calls" -eq 1 ]
[ ! -e "$witness" ]
' _ "$TMUX_RETIRE_FUNCTION" "$TMUX_RESTART_WITNESS"; then
  echo "ok: tmux pane retirement cannot cross a server-restart command boundary"
else
  echo "FAIL: tmux pane retirement can target a reused pane after server restart"
  FAILURES=$((FAILURES+1))
fi
if command -v tmux >/dev/null 2>&1; then
  TMUX_RESTART_SOCKET="$TMP/tmux-generation-restart.sock"
  if bash -c '
set -euo pipefail
eval "$1"
socket="$2"
tmux_cmd() { tmux -S "$socket" "$@"; }
trap "tmux_cmd kill-server >/dev/null 2>&1 || true" EXIT
tmux_cmd new-session -d -s team-race -n _hub "sleep 60"
token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
tag="$(tmux_generation_tag "$token")"
duplicate="$(tmux_cmd new-window -d -P -F "#{pane_id}" -t team-race -n worker "sleep 60")"
old="$(tmux_cmd new-window -d -P -F "#{pane_id}|#{pane_pid}" -t team-race -n worker ": sfgen-$tag; exec sleep 60")"
old_pane="${old%%|*}"
old_pid="${old#*|}"
[ "$old_pane" != "$duplicate" ]
tmux_cmd display-message -p -t "$old_pane" "#{m:*sfgen-$tag*,#{pane_start_command}}" | grep -Fxq 1
tmux_cmd display-message -p -t "$duplicate" "#{m:*sfgen-$tag*,#{pane_start_command}}" | grep -Fxq 0
tmux_cmd kill-server
tmux_cmd new-session -d -s team-race -n _hub "sleep 60"
tmux_cmd set-option -g remain-on-exit on
tmux_cmd new-window -d -t team-race -n worker "sleep 60"
new_pane="$(tmux_cmd new-window -d -P -F "#{pane_id}" -t team-race -n worker "true")"
[ "$new_pane" = "$old_pane" ]
for _ in $(seq 1 50); do
  [ "$(tmux_cmd display-message -p -t "$new_pane" "#{pane_dead}")" = 1 ] && break
  sleep 0.02
done
[ "$(tmux_cmd display-message -p -t "$new_pane" "#{pane_dead}")" = 1 ]
lifecycle_retire_tmux_pane "$old_pid" team-race worker "$old_pane" "$token"
tmux_cmd list-panes -a -F "#{pane_id}" | grep -Fqx "$new_pane"
# Positive control: an original dead pane still reports its own pane PID and
# is retired, while the untagged replacement above remains live.
tagged_info="$(tmux_cmd new-window -d -P -F "#{pane_id}|#{pane_pid}" -t team-race -n worker ": sfgen-$tag; true")"
tagged_pane="${tagged_info%%|*}"
tagged_pid="${tagged_info#*|}"
for _ in $(seq 1 50); do
  [ "$(tmux_cmd display-message -p -t "$tagged_pane" "#{pane_dead}")" = 1 ] && break
  sleep 0.02
done
[ "$(tmux_cmd display-message -p -t "$tagged_pane" "#{pane_dead}")" = 1 ]
lifecycle_retire_tmux_pane "$tagged_pid" team-race worker "$tagged_pane" "$token"
for _ in $(seq 1 50); do
  ! tmux_cmd list-panes -a -F "#{pane_id}" | grep -Fqx "$tagged_pane" && break
  sleep 0.02
done
! tmux_cmd list-panes -a -F "#{pane_id}" | grep -Fqx "$tagged_pane"
tmux_cmd list-panes -a -F "#{pane_id}" | grep -Fqx "$new_pane"
# A no-argument respawn keeps the pane id and start command.  It must not let
# stale cleanup delete the successor after its different PID exits.
respawn_info="$(tmux_cmd new-window -d -P -F "#{pane_id}|#{pane_pid}" -t team-race -n worker ": sfgen-$tag; true")"
respawn_pane="${respawn_info%%|*}"
respawn_old_pid="${respawn_info#*|}"
for _ in $(seq 1 50); do
  [ "$(tmux_cmd display-message -p -t "$respawn_pane" "#{pane_dead}")" = 1 ] && break
  sleep 0.02
done
tmux_cmd respawn-pane -t "$respawn_pane"
for _ in $(seq 1 50); do
  respawn_new_pid="$(tmux_cmd display-message -p -t "$respawn_pane" "#{pane_pid}")"
  [ "$respawn_new_pid" != "$respawn_old_pid" ] \
    && [ "$(tmux_cmd display-message -p -t "$respawn_pane" "#{pane_dead}")" = 1 ] && break
  sleep 0.02
done
[ "$respawn_new_pid" != "$respawn_old_pid" ]
lifecycle_retire_tmux_pane "$respawn_old_pid" team-race worker "$respawn_pane" "$token"
tmux_cmd list-panes -a -F "#{pane_id}" | grep -Fqx "$respawn_pane"
' _ "$TMUX_RETIRE_FUNCTION" "$TMUX_RESTART_SOCKET"; then
    echo "ok: restarted tmux server cannot retire a reused dead pane without its generation tag"
  else
    echo "FAIL: restarted tmux server retired a reused dead pane or generation tag failed"
    FAILURES=$((FAILURES+1))
  fi
fi
check "task launch and restart share one stable task-key transaction" \
  python3 - "$LAUNCH" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
launch = source.split("launch_task() {", 1)[1].split("\nrestart_task() {", 1)[0]
restart = source.split("restart_task() {", 1)[1].split("\nretire_role() {", 1)[0]
assert 'task_lane="$(task_key "$task")"' in launch
assert 'acquire_launch_lane_lock "$team" task "$task_lane"' in launch
assert 'LAUNCH_LANE_LOCK_INSTANCE" = "$task_lane"' in launch
acquire = restart.index('acquire_launch_lane_lock "$team" task "$key"')
observe = restart.index('record="$(python3 "$SKILL_DIR/bin/process-lifecycle.py" list')
revoke = restart.index('outbox_capability.py" revoke-task')
successor = restart.index('launch_task "$team" "$feature"')
release = restart.rindex("release_launch_lane_lock")
assert acquire < observe < revoke < successor < release
PY

printf 'TRACKER_WRITERS=all\n' >> .claude/skills/pm/config/team.config.md
if "$LAUNCH" status test-feature >duplicate-config.out 2>&1; then
  echo "FAIL: launcher accepted duplicate safety configuration"; FAILURES=$((FAILURES+1))
elif grep -q 'duplicate configuration key TRACKER_WRITERS' duplicate-config.out; then
  echo "ok: launcher rejects duplicate safety configuration"
else
  echo "FAIL: launcher reported wrong duplicate-key error"; FAILURES=$((FAILURES+1))
fi
sed_i '$d' .claude/skills/pm/config/team.config.md
CFG_SANDBOX=.claude/skills/pm/config/team.config.md

# -- command values are parsed inertly and reach the real launcher entry path --
set_config_line() { # set_config_line KEY RAW_ASSIGNMENT_VALUE (no sed escaping)
  python3 - "$CFG_SANDBOX" "$1" "$2" <<'PY'
import sys

path, key, raw = sys.argv[1:]
lines = open(path, encoding="utf-8").read().splitlines()
replaced = False
for index, line in enumerate(lines):
    if "=" in line and line.split("=", 1)[0] == key:
        lines[index] = "%s=%s" % (key, raw)
        replaced = True
if not replaced:
    lines.insert(1, "%s=%s" % (key, raw))
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
}

legacy_read_key() { # Deliberately retain the pre-fix parser as a negative control.
  local line
  line="$(grep -m1 "^$1=" "$CFG_SANDBOX" || true)"
  line="${line#*=}"
  if [ "${line#\"}" != "$line" ]; then
    line="${line#\"}"; line="${line%%\"*}"
  fi
  printf '%s' "$line"
}

# Deterministic fake model CLI: records its own argv count and the exact bytes of
# the single prompt argument, so field splitting cannot pass unnoticed.
cat > quoted-prompt-cli <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$#" > "${QUOTED_PROMPT_ARGC:-quoted-prompt-argc.txt}"
[ "$#" -eq 2 ] && [ "$1" = "--prompt" ] || exit 81
printf '%s' "$2" > "${QUOTED_PROMPT_OUT:-quoted-prompt-received.txt}"
EOF
chmod +x quoted-prompt-cli

# The shipped role defaults use exactly this shape: one outer double-quoted
# configuration value whose interior prompt substitution is quote-escaped.
QUOTED_TEMPLATE='"./quoted-prompt-cli --prompt \"$(cat '"'"'{prompt_file}'"'"')\""'
NORMALIZED_TEMPLATE='./quoted-prompt-cli --prompt "$(cat '"'"'{prompt_file}'"'"')"'
PRESERVED_TEMPLATE='./quoted-prompt-cli --prompt \"$(cat '"'"'{prompt_file}'"'"')\"'
set_config_line FRONTEND_CMD "$QUOTED_TEMPLATE"

# Negative control 1 — the pre-fix parser truncates the shipped template.
legacy_command="$(legacy_read_key FRONTEND_CMD)"
if [ "$legacy_command" = "$NORMALIZED_TEMPLATE" ]; then
  echo "FAIL: broken-parser negative control unexpectedly preserved a quoted prompt template"; FAILURES=$((FAILURES+1))
else
  echo "ok: broken-parser negative control reproduces quoted prompt truncation ($legacy_command)"
fi

# Negative control 2 — retaining the configuration escape bytes reaches
# /bin/bash -c as literal quote bytes and field-splits a multiline prompt.
CONTROL_PROMPT="$TMP/control-prompt.md"
printf 'alpha line one\nbeta line two\n' > "$CONTROL_PROMPT"
QUOTED_PROMPT_ARGC="$TMP/control-argc.txt" QUOTED_PROMPT_OUT="$TMP/control-received.txt" \
  /bin/bash -c "${PRESERVED_TEMPLATE//\{prompt_file\}/$CONTROL_PROMPT}" >/dev/null 2>&1 || true
if [ "$(cat "$TMP/control-argc.txt" 2>/dev/null || echo missing)" = 2 ]; then
  echo "FAIL: escape-preserving control unexpectedly delivered one prompt argument"; FAILURES=$((FAILURES+1))
else
  echo "ok: removal of functional quote normalization field-splits the prompt (argc $(cat "$TMP/control-argc.txt" 2>/dev/null || echo missing))"
fi
QUOTED_PROMPT_ARGC="$TMP/normalized-argc.txt" QUOTED_PROMPT_OUT="$TMP/normalized-received.txt" \
  /bin/bash -c "${NORMALIZED_TEMPLATE//\{prompt_file\}/$CONTROL_PROMPT}" >/dev/null 2>&1 || true
check "normalized template delivers exactly one prompt argument" \
  test "$(cat "$TMP/normalized-argc.txt" 2>/dev/null || echo missing)" = 2

# Production path — exercise the real launcher in its supported unmanaged
# manual mode, isolating this parser assertion from sandbox/lifecycle trust.
set_config_line AGENT_SANDBOX_ENFORCED false
set_config_line BROKER_LIFECYCLE_ROOT null
rm -f quoted-prompt-argc.txt quoted-prompt-received.txt
if TEAM_RUNNER=background "$LAUNCH" start quoted-command FEAT-QUOTED frontend >quoted-start.out 2>&1; then
  for _ in $(seq 1 50); do [ -s quoted-prompt-argc.txt ] && break; sleep 0.1; done
else
  echo "FAIL: launcher refused the shipped quoted command template: $(cat quoted-start.out)"; FAILURES=$((FAILURES+1))
fi
QUOTED_PROMPT_PATH=.teamwork/quoted-command/prompts/frontend.md
check "launcher composed a multiline prompt for the quoted template" \
  test "$(wc -l < "$QUOTED_PROMPT_PATH" 2>/dev/null || echo 0)" -gt 5
check "shipped quoted template delivers exactly one prompt argument" \
  test "$(cat quoted-prompt-argc.txt 2>/dev/null || echo missing)" = 2
check "shipped command substitution removes only trailing prompt newlines" \
  python3 - "$QUOTED_PROMPT_PATH" quoted-prompt-received.txt <<'PY'
from pathlib import Path
import sys

raw = Path(sys.argv[1]).read_bytes()
received = Path(sys.argv[2]).read_bytes()
assert raw.endswith(b"\n")
assert received == raw.rstrip(b"\n")
PY
set_config_line FRONTEND_CMD null
set_config_line AGENT_SANDBOX_ENFORCED true
set_config_line BROKER_LIFECYCLE_ROOT "$LIFECYCLE_ROOT"

cp "$CFG_SANDBOX" "$TMP/team.config.parser-cases"
expect_config_refused() { # description KEY raw-value expected-error-fragment
  local description="$1" key="$2" raw="$3" expected="$4" out
  cp "$TMP/team.config.parser-cases" "$CFG_SANDBOX"
  set_config_line "$key" "$raw"
  if out="$("$LAUNCH" status malformed-value 2>&1)"; then
    echo "FAIL: $description accepted"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$out" | grep -q "$expected"; then
    echo "ok: $description rejected"
  else
    echo "FAIL: $description produced the wrong error: $out"; FAILURES=$((FAILURES+1))
  fi
  cp "$TMP/team.config.parser-cases" "$CFG_SANDBOX"
}
expect_config_refused "unmatched outer quote" TEAMWORK_ROOT '"unterminated' "unmatched outer quote"
expect_config_refused "trailing bytes after an outer quote" TEAMWORK_ROOT '".teamwork" junk' "trailing bytes"
expect_config_refused "ambiguous escape inside an outer quoted value" TEAMWORK_ROOT '".teamwork\q"' "unsupported escape"
expect_config_refused "outer-quoted empty value" TEAMWORK_ROOT '""' "empty value"

expect_config_start_refused() { # description raw-value team
  local description="$1" raw="$2" team="$3" out
  cp "$TMP/team.config.parser-cases" "$CFG_SANDBOX"
  set_config_line TEAM_DEFAULT_CMD "$raw"
  if out="$(TEAM_RUNNER=background "$LAUNCH" start "$team" FEAT-MALFORMED backend 2>&1)"; then
    echo "FAIL: $description accepted and launched"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$out" | grep -q "unmatched quote or escape"; then
    echo "ok: $description rejected before launch"
  else
    echo "FAIL: $description produced the wrong error: $out"; FAILURES=$((FAILURES+1))
  fi
  check "$description creates no workspace" test ! -e ".teamwork/$team"
  cp "$TMP/team.config.parser-cases" "$CFG_SANDBOX"
}
expect_config_start_refused "comment trimming cannot synthesize a dangling command escape" \
  'cmd\   # note' malformed-comment-escape
expect_config_start_refused "comment trimming cannot synthesize a lone dangling escape" \
  '\   # disabled' malformed-comment-lone-escape

expect_malformed_config_line_refused() { # description replacement expected-error-fragment
  local description="$1" replacement="$2" expected="$3" out
  cp "$TMP/team.config.parser-cases" "$CFG_SANDBOX"
  sed_i "s|^TEAMWORK_ROOT=.*|$replacement|" "$CFG_SANDBOX"
  if out="$("$LAUNCH" status malformed-line 2>&1)"; then
    echo "FAIL: $description accepted"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$out" | grep -q "$expected"; then
    echo "ok: $description rejected"
  else
    echo "FAIL: $description produced the wrong error: $out"; FAILURES=$((FAILURES+1))
  fi
  cp "$TMP/team.config.parser-cases" "$CFG_SANDBOX"
}
expect_malformed_config_line_refused "indented key-like assignment" ' TEAMWORK_ROOT=.teamwork' "malformed configuration assignment"
expect_malformed_config_line_refused "space before assignment separator" 'TEAMWORK_ROOT =.teamwork' "malformed configuration assignment"
expect_malformed_config_line_refused "mixed-case key-like assignment" 'Teamwork_ROOT=.teamwork' "malformed configuration assignment"
expect_config_refused "DEL control character" TEAMWORK_ROOT "$(printf '.teamwork\177unsafe')" "control character"
expect_config_refused "C1 control character" TEAMWORK_ROOT "$(printf '.teamwork\302\200unsafe')" "control character"

expect_config_value() { # description KEY raw-value expected-value
  local description="$1" key="$2" raw="$3" expected="$4" actual
  cp "$TMP/team.config.parser-cases" "$CFG_SANDBOX"
  set_config_line "$key" "$raw"
  actual="$("$LAUNCH" config-value "$key" 2>&1)" || actual="<error> $actual"
  if [ "$actual" = "$expected" ]; then
    echo "ok: $description"
  else
    echo "FAIL: $description — expected <$expected> got <$actual>"; FAILURES=$((FAILURES+1))
  fi
  cp "$TMP/team.config.parser-cases" "$CFG_SANDBOX"
}
expect_config_value "unquoted command value is preserved" TEAM_DEFAULT_CMD \
  'codex exec --approve-for-me {prompt_file}' 'codex exec --approve-for-me {prompt_file}'
expect_config_value "interior horizontal tab is preserved" TEAM_DEFAULT_CMD \
  "$(printf 'codex\texec {prompt_file}')" "$(printf 'codex\texec {prompt_file}')"
expect_config_value "outer-quoted escapes normalize to shell-grouping quotes" TEAM_DEFAULT_CMD \
  '"claude -p \"$(cat '"'"'{prompt_file}'"'"')\" --permission-mode acceptEdits"' \
  'claude -p "$(cat '"'"'{prompt_file}'"'"')" --permission-mode acceptEdits'
expect_config_value "escaped backslash normalizes to one backslash" TEAM_DEFAULT_CMD \
  '"printf %s\\\\ {prompt_file}"' 'printf %s\\ {prompt_file}'
expect_config_value "assignment-prefixed command values survive" TEAM_DEFAULT_CMD \
  '"STARTUP_FACTORY_LLM_RUNTIME=other dsh \"$(cat '"'"'{prompt_file}'"'"')\""' \
  'STARTUP_FACTORY_LLM_RUNTIME=other dsh "$(cat '"'"'{prompt_file}'"'"')"'
expect_config_value "true trailing comment after an outer quote is stripped" TEAM_DEFAULT_CMD \
  '"claude -p {prompt_file}"   # role default' 'claude -p {prompt_file}'
expect_config_value "inline comment in an unquoted value is stripped" TEAM_DEFAULT_CMD \
  'claude -p {prompt_file}   # role default' 'claude -p {prompt_file}'
expect_config_value "a hash inside outer quotes is value data" TEAM_DEFAULT_CMD \
  '"claude -p {prompt_file} --tag a#b"' 'claude -p {prompt_file} --tag a#b'
expect_config_value "single-quoted values keep interior double quotes literally" TEAM_DEFAULT_CMD \
  "'claude -p \"literal\"'" 'claude -p "literal"'
expect_config_value "exact null maps to absent" TEAM_DEFAULT_CMD 'null' ''

sed_i 's|^TEAMWORK_ROOT=.*|TEAMWORK_ROOT=$(touch parser-evaluation-sentinel)|' "$CFG_SANDBOX"
"$LAUNCH" status inert-value >/dev/null 2>&1 || true
check "configuration parsing never evaluates substitutions" test ! -e parser-evaluation-sentinel
cp "$TMP/team.config.parser-cases" "$CFG_SANDBOX"

# -- enforced sandbox runner trust and direct-mode fallback -----------------
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
expect_runner_refused "repository-local sandbox runner" "$INSIDE_RUNNER" "must be root-owned"
expect_runner_refused "symlink sandbox runner" "$SYMLINK_RUNNER" "must not be a symlink"
expect_runner_refused "directory sandbox runner" "$TMP" "regular file"
expect_runner_refused "group/world-writable sandbox runner" "$WRITABLE_RUNNER" "group- or world-writable"
expect_runner_refused "non-executable sandbox runner" "$NONEXEC_RUNNER" "must be executable"
expect_runner_refused "operator-owned sandbox runner" "$SANDBOX_RUNNER" "must be root-owned"

# A root-owned system executable satisfies the same structural trust contract
# used by recovery validation. Status never executes it as a sandbox runner.
sed_i 's|^AGENT_SANDBOX_RUNNER=.*|AGENT_SANDBOX_RUNNER="/usr/bin/env"|' "$CFG_SANDBOX"
if "$LAUNCH" validate-board >/dev/null 2>&1; then
  echo "ok: root-protected system runner is accepted"
else
  echo "FAIL: root-protected system runner was refused"; FAILURES=$((FAILURES+1))
fi

# The remaining tests exercise argv routing with an executable fixture. Patch
# only the throwaway copied launcher after the production trust assertions;
# no packaged/runtime code contains a test-mode bypass.
python3 - "$LAUNCH" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
replacements = (
    (
        'if metadata.st_uid != 0:\n    fail("file must be root-owned")',
        'if metadata.st_uid not in {0, os.geteuid()}:\n'
        '    fail("file must be owned by the fixture executor or root")',
    ),
    (
        'if executor_can_write:\n    fail("file must not be writable by the executor")',
        'if executor_can_write and metadata.st_uid != os.geteuid():\n'
        '    fail("file must not be writable by the executor")',
    ),
    (
        'if ancestor_metadata.st_uid != 0:\n'
        '        fail(f"ancestor must be root-owned: {ancestor}")',
        'if ancestor_metadata.st_uid not in {0, os.geteuid()}:\n'
        '        fail(f"ancestor must be fixture-executor/root-owned: {ancestor}")',
    ),
    (
        'if executor_can_write:\n'
        '        fail(f"ancestor must not be writable by the executor: {ancestor}")',
        'if executor_can_write and ancestor_metadata.st_uid != os.geteuid():\n'
        '        fail(f"ancestor must not be writable by the executor: {ancestor}")',
    ),
)
for old, new in replacements:
    if text.count(old) != 1:
        raise SystemExit(f"fixture patch contract drifted: {old!r}")
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")
PY

sed_i 's|^AGENT_SANDBOX_ENFORCED=.*|AGENT_SANDBOX_ENFORCED=false|' "$CFG_SANDBOX"
sed_i 's|^AGENT_SANDBOX_RUNNER=.*|AGENT_SANDBOX_RUNNER="relative-runner"|' "$CFG_SANDBOX"
runner_lines_before="$(wc -l < "$SANDBOX_RUNNER_LOG" 2>/dev/null || printf '0')"
TEAM_RUNNER=background "$LAUNCH" start manual-direct FEAT-DIRECT backend
runner_lines_after="$(wc -l < "$SANDBOX_RUNNER_LOG" 2>/dev/null || printf '0')"
check "manual non-enforced mode retains direct execution" test -f .teamwork/manual-direct/prompts/backend.md
[ "$runner_lines_before" = "$runner_lines_after" ] \
  && echo "ok: manual non-enforced mode does not invoke configured runner" \
  || { echo "FAIL: manual non-enforced mode invoked sandbox runner"; FAILURES=$((FAILURES+1)); }
sed_i 's|^BROKER_LIFECYCLE_ROOT=.*|BROKER_LIFECYCLE_ROOT=null|' "$CFG_SANDBOX"
TEAM_RUNNER=background "$LAUNCH" start manual-unmanaged FEAT-UNMANAGED backend
check "manual non-enforced mode remains available without lifecycle authority" \
  test -f .teamwork/manual-unmanaged/prompts/backend.md
if STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$LIFECYCLE_ROOT" \
    "$LAUNCH" status manual-unmanaged >ambient-root.out 2>&1; then
  echo "FAIL: ambient lifecycle root replaced absent config"; FAILURES=$((FAILURES+1))
elif grep -q 'cannot replace an absent BROKER_LIFECYCLE_ROOT' ambient-root.out; then
  echo "ok: ambient lifecycle root cannot replace absent config"
else
  echo "FAIL: ambient lifecycle replacement reported wrong error"; FAILURES=$((FAILURES+1))
fi
sed_i "s|^BROKER_LIFECYCLE_ROOT=.*|BROKER_LIFECYCLE_ROOT=\"$LIFECYCLE_ROOT\"|" "$CFG_SANDBOX"
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
for i in $(seq 1 100); do
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
cat > dsh <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x claude codex gemini custom-wrapper dsh

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

# Shipped-shape outer-quoted template with an escaped interior prompt substitution.
set_config_line FRONTEND_CMD '"./dsh --profile headless \"$(cat '"'"'{prompt_file}'"'"')\""'
TEAM_RUNNER=background "$LAUNCH" start dsh-planning FEAT-DSH frontend
dsh_prompt=.teamwork/dsh-planning/prompts/frontend.md
check "DeepSeek Harness command is classified as non-Claude" grep -q "LLM runtime family: other" "$dsh_prompt"
if grep -q "Claude + obra/superpowers planning" "$dsh_prompt"; then
  echo "FAIL: DeepSeek Harness command received Superpowers planning instructions"; FAILURES=$((FAILURES+1))
else
  echo "ok: DeepSeek Harness command excludes Superpowers planning instructions"
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
case "${STARTUP_FACTORY_OUTBOX_CAPABILITY_ID-unset}|${STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET-unset}|${STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT-unset}|${STARTUP_FACTORY_OUTBOX_TRANSPORT-unset}|${STARTUP_FACTORY_CANONICAL_REPO-unset}|${STARTUP_FACTORY_CANONICAL_WORKSPACE-unset}" in
  unset\|unset\|unset\|/*\|/*\|/*) echo capability-context-valid >> agent-env.txt ;;
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

# Lifecycle supervision remains available for explicitly unenforced/manual
# execution, but publication authority never crosses that boundary.  A manual
# child must not receive even the non-secret socket locator or canonical
# publication routing context.
cat > unenforced-env-probe.sh <<'EOF'
#!/usr/bin/env bash
case "${STARTUP_FACTORY_OUTBOX_TRANSPORT-unset}|${STARTUP_FACTORY_INSTANCE-unset}|${STARTUP_FACTORY_CANONICAL_REPO-unset}|${STARTUP_FACTORY_CANONICAL_WORKSPACE-unset}" in
  unset\|unset\|unset\|unset) echo no-publication-authority > unenforced-env.txt ;;
  *) echo publication-authority-leaked > unenforced-env.txt ;;
esac
EOF
chmod +x unenforced-env-probe.sh
sed_i 's|^AGENT_SANDBOX_ENFORCED=.*|AGENT_SANDBOX_ENFORCED=false|' .claude/skills/pm/config/team.config.md
sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="./unenforced-env-probe.sh {prompt_file}"|' .claude/skills/pm/config/team.config.md
TEAM_RUNNER=background "$LAUNCH" start manual-unenforced FEAT-MANUAL backend >/dev/null
for i in $(seq 1 20); do [ -f unenforced-env.txt ] && break; sleep 0.1; done
check "unenforced lifecycle-supervised agent receives no publication authority" \
  grep -q '^no-publication-authority$' unenforced-env.txt
sed_i 's|^AGENT_SANDBOX_ENFORCED=.*|AGENT_SANDBOX_ENFORCED=true|' .claude/skills/pm/config/team.config.md
sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="./env-probe.sh {prompt_file}"|' .claude/skills/pm/config/team.config.md

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
sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="cat {prompt_file} > backend-received.txt"|' .claude/skills/pm/config/team.config.md
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
sed_i 's|^AGENT_SANDBOX_ENFORCED=.*|AGENT_SANDBOX_ENFORCED=false|' .claude/skills/pm/config/team.config.md
sed_i 's|^BROKER_LIFECYCLE_ROOT=.*|BROKER_LIFECYCLE_ROOT=null|' .claude/skills/pm/config/team.config.md
if doctor_out="$("$LAUNCH" doctor full-stack doctor-no-lifecycle FEAT-DOCTOR 2>&1)"; then
  echo "FAIL: doctor accepted missing lifecycle authority"; FAILURES=$((FAILURES+1))
elif printf '%s' "$doctor_out" | grep -q 'doctor: BROKER_LIFECYCLE_ROOT'; then
  echo "ok: doctor requires pre-created lifecycle authority"
else
  echo "FAIL: doctor produced the wrong lifecycle error: $doctor_out"; FAILURES=$((FAILURES+1))
fi
cp "$TMP/team.config.before-doctor" .claude/skills/pm/config/team.config.md
cat > doctor-cli-a <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 2 ] && [ "$1" = "--prompt" ] && [ -n "${HOME:-}" ] || exit 71
python3 - "$2" <<'PY'
import re
import sys

lines = sys.argv[1].splitlines()
assert lines[:3] == [
    "This is a non-mutating agent CLI startup and authentication check.",
    "Do not inspect or modify files, call tools, or continue other work.",
    "Reply with exactly this token and nothing else:",
]
assert len(lines) == 4 and re.fullmatch(r"STARTUP_FACTORY_DOCTOR_OK_[0-9a-f]{24}", lines[3])
print(lines[3])
PY
EOF
cp doctor-cli-a doctor-cli-b
chmod +x doctor-cli-a doctor-cli-b
cat > doctor-cli-echo <<'EOF'
#!/usr/bin/env bash
python3 - "$2" <<'PY'
import sys
lines = sys.argv[1].splitlines()
print("Reply with exactly this token and nothing else:")
print(lines[-1])
PY
EOF
cat > doctor-cli-extra <<'EOF'
#!/usr/bin/env bash
python3 - "$2" <<'PY'
import sys
token = sys.argv[1].splitlines()[-1]
print(token)
print("extra output")
PY
EOF
cat > doctor-cli-adversarial <<'EOF'
#!/usr/bin/env bash
python3 - "$1" "$2" <<'PY'
import sys

mode, prompt = sys.argv[1:]
token = prompt.splitlines()[-1]
responses = {
    "same-line-prefix": "prefix" + token,
    "same-line-suffix": token + "suffix",
    "same-line-duplicate": token + token,
    "duplicate-line": token + "\n" + token,
}
print(responses[mode])
PY
EOF
chmod +x doctor-cli-echo doctor-cli-extra doctor-cli-adversarial
DOCTOR_CLI_HOME="$TMP/doctor-cli-home"
mkdir -m 700 "$DOCTOR_CLI_HOME"
set_config_line AGENT_SANDBOX_HOME "\"$DOCTOR_CLI_HOME\""
set_config_line TEAM_LEAD_CMD '"./doctor-cli-a --prompt \"$(cat '"'"'{prompt_file}'"'"')\""'
set_config_line SENIOR_SECURITY_ENGINEER_CMD '"./doctor-cli-b --prompt \"$(cat '"'"'{prompt_file}'"'"')\""'
set_config_line SENIOR_QA_ENGINEER_CMD '"./doctor-cli-b --prompt \"$(cat '"'"'{prompt_file}'"'"')\""'
set_config_line TEAM_DEFAULT_CMD '"./doctor-cli-a --prompt \"$(cat '"'"'{prompt_file}'"'"')\""'
# Both normalized null spellings must remain disabled even with a viable
# TEAM_DEFAULT_CMD. Doctor's covered-role count makes accidental fallback
# observable without launching either disabled role.
set_config_line SENIOR_TECHNICAL_PRODUCT_MANAGER_CMD ' null '
set_config_line SENIOR_FULL_STACK_ENGINEER_CMD '"null"'
doctor_out="$("$LAUNCH" doctor full-stack doctor-team FEAT-DOCTOR)"
printf '%s' "$doctor_out" | grep -Eq "2 distinct command\(s\) verified, covering 6 enabled roster role\(s\)" \
  && echo "ok: doctor reports verified commands and covered roles accurately" \
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
elif printf '%s' "$doctor_out" | grep -q "did not return exactly the prompt challenge token"; then
  echo "ok: doctor rejects exit zero without the prompt challenge token"
else
  echo "FAIL: doctor produced the wrong no-token failure: $doctor_out"; FAILURES=$((FAILURES+1))
fi
for bad_cli in doctor-cli-echo doctor-cli-extra; do
  set_config_line SENIOR_QA_ENGINEER_CMD \
    '"./'"$bad_cli"' --prompt \"$(cat '"'"'{prompt_file}'"'"')\""'
  if doctor_out="$("$LAUNCH" doctor full-stack "doctor-$bad_cli" FEAT-DOCTOR 2>&1)"; then
    echo "FAIL: doctor accepted non-exact token output from $bad_cli"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$doctor_out" | grep -q "did not return exactly the prompt challenge token"; then
    echo "ok: doctor rejects non-exact token output from $bad_cli"
  else
    echo "FAIL: doctor produced the wrong non-exact response failure: $doctor_out"; FAILURES=$((FAILURES+1))
  fi
done
for mode in same-line-prefix same-line-suffix same-line-duplicate duplicate-line; do
  set_config_line SENIOR_QA_ENGINEER_CMD \
    '"./doctor-cli-adversarial '"$mode"' \"$(cat '"'"'{prompt_file}'"'"')\""'
  if doctor_out="$("$LAUNCH" doctor full-stack "doctor-$mode" FEAT-DOCTOR 2>&1)"; then
    echo "FAIL: doctor accepted $mode challenge-token output"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$doctor_out" | grep -q "did not return exactly the prompt challenge token"; then
    echo "ok: doctor rejects $mode challenge-token output"
  else
    echo "FAIL: doctor produced the wrong $mode response failure: $doctor_out"; FAILURES=$((FAILURES+1))
  fi
done
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
if "$LAUNCH" worktree test-feature unsafe-feature.md '../escape-role' T-BAD >/dev/null 2>&1; then
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
for null_case in ' null ' '"null"'; do
  set_config_line REVIEWER_CMD "$null_case"
  if disabled_out="$(TEAM_RUNNER=background "$LAUNCH" start test-feature FEAT-1 reviewer 2>&1)"; then
    echo "FAIL: normalized explicit-null role fell back to TEAM_DEFAULT_CMD"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$disabled_out" | grep -q "role 'reviewer' is disabled"; then
    echo "ok: normalized explicit-null role refused without fallback ($null_case)"
  else
    echo "FAIL: normalized explicit-null role produced the wrong refusal: $disabled_out"; FAILURES=$((FAILURES+1))
  fi
done
set_config_line REVIEWER_CMD null

# -- worktree subcommand -------------------------------------------------------
cat > worktree-feature.md <<'EOF'
# Worktree helper fixture [Active]

## 1 Re-add one governed worktree [Active]

**Assignee:** backend

Exercise idempotent worktree creation.

## 2 Provision governed attempts [Active]

**Assignee:** backend

Exercise setup and generation reuse.

## 3 Reject failed provisioning [Active]

**Assignee:** backend

Exercise rollback after setup failure.
EOF
WORKTREE_FID=worktree-feature.md
T42_TASK="$WORKTREE_FID#1"
T77_TASK="$WORKTREE_FID#2"
T78_TASK="$WORKTREE_FID#3"
prepare_task_claim test-feature "$WORKTREE_FID" "$T42_TASK" backend 1
prepare_task_claim test-feature "$WORKTREE_FID" "$T77_TASK" backend 1
prepare_task_claim test-feature "$WORKTREE_FID" "$T78_TASK" backend 1

cat > missing-worktree-feature.md <<'EOF'
# Missing branch fixture [Active]

## 1 Refuse implicit feature branch creation [Active]

**Assignee:** backend

The launcher must report how to create the intended feature branch.
EOF
MISSING_WORKTREE_FID=missing-worktree-feature.md
MISSING_WORKTREE_TASK="$MISSING_WORKTREE_FID#1"
prepare_task_claim missing-feature "$MISSING_WORKTREE_FID" "$MISSING_WORKTREE_TASK" backend 1
if missing_branch_out="$("$LAUNCH" worktree missing-feature "$MISSING_WORKTREE_FID" backend "$MISSING_WORKTREE_TASK" 2>&1)"; then
  echo "FAIL: missing feature branch was accepted"; FAILURES=$((FAILURES+1))
elif printf '%s' "$missing_branch_out" | grep -q "feature branch 'missing-feature' does not exist.*git branch 'missing-feature' <base-commit>"; then
  echo "ok: missing feature branch reports an actionable creation command"
else
  echo "FAIL: missing feature branch produced the wrong error: $missing_branch_out"; FAILURES=$((FAILURES+1))
fi
check "missing feature branch creates no task worktree" test ! -e .teamwork/missing-feature/worktrees

T42_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$T42_TASK")"
T42_WT=".teamwork/test-feature/worktrees/backend#1-$T42_KEY"
"$LAUNCH" worktree test-feature "$WORKTREE_FID" backend "$T42_TASK"
check "worktree created"  test -d "$T42_WT"
check "worktree branch"   git -C "$T42_WT" rev-parse --abbrev-ref HEAD
[ "$(git -C "$T42_WT" rev-parse --abbrev-ref HEAD)" = "agent-task/test-feature/$T42_KEY" ] \
  && echo "ok: collision-safe task branch" || { echo "FAIL: branch name"; FAILURES=$((FAILURES+1)); }

# -- worktree re-add: remove the worktree dir but keep the branch, re-add should succeed --
git worktree remove "$T42_WT"
"$LAUNCH" worktree test-feature "$WORKTREE_FID" backend "$T42_TASK"
check "worktree re-add with existing branch" test -d "$T42_WT"

# -- worktree provisioning: WORKTREE_SETUP runs once, fail-loud -----------------
CFG_WT=.claude/skills/pm/config/team.config.md
printf 'WORKTREE_SETUP="! env | grep -q '\''^LINEAR_API_KEY='\'' && ! env | grep -q '\''^HOME='\'' && touch provisioned.txt"\n' >> "$CFG_WT"
T77_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$T77_TASK")"
T78_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$T78_TASK")"
LINEAR_API_KEY=must-not-leak HOME=/secret/home "$LAUNCH" worktree test-feature "$WORKTREE_FID" backend "$T77_TASK"
check "WORKTREE_SETUP provisioned the tree" test -f ".teamwork/test-feature/worktrees/backend#1-$T77_KEY/provisioned.txt"
check "WORKTREE_SETUP receives no scheduler credentials or ambient HOME" test -f ".teamwork/test-feature/worktrees/backend#1-$T77_KEY/provisioned.txt"
check "WORKTREE_SETUP uses protected runner argv" grep -Fq "$PWD/.teamwork/test-feature/worktrees/backend#1-$T77_KEY|/usr/bin/env|-i" "$SANDBOX_RUNNER_LOG"
sed_i '/^WORKTREE_SETUP=/d' "$CFG_WT"
printf 'WORKTREE_SETUP="false"\n' >> "$CFG_WT"
if "$LAUNCH" worktree test-feature "$WORKTREE_FID" backend "$T78_TASK" >/dev/null 2>&1; then
  echo "FAIL: failing WORKTREE_SETUP should die"; FAILURES=$((FAILURES+1))
else
  echo "ok: failing WORKTREE_SETUP is fail-loud"
fi
check "failed provisioning removed the tree" test ! -d ".teamwork/test-feature/worktrees/backend#1-$T78_KEY"
sed_i '/^WORKTREE_SETUP="false"$/d' "$CFG_WT"

# -- attempt-bound relaunch isolation ------------------------------------------
"$LAUNCH" compose-task test-feature "$WORKTREE_FID" backend "$T77_TASK" 1 >/dev/null
"$LAUNCH" worktree-remove test-feature backend "$T77_TASK"
check "worktree-remove cleaned the dir" test ! -d ".teamwork/test-feature/worktrees/backend#1-$T77_KEY"
git worktree list | grep -q "backend#1-$T77_KEY" && { echo "FAIL: stale worktree registration"; FAILURES=$((FAILURES+1)); } || echo "ok: worktree pruned"
prepare_task_claim test-feature "$WORKTREE_FID" "$T77_TASK" backend 2
"$LAUNCH" worktree test-feature "$WORKTREE_FID" backend "$T77_TASK" 2
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

# -- Safe Turbo is explicit, bounded, and fail-closed -------------------------
sed_i 's|^VALIDATE_TEST=null$|VALIDATE_TEST="test -e .git"|' "$CFG"
cat >> "$CFG" <<'EOF'
TURBO_MODE=safe
EXECUTION=parallel
MAX_ACTIVE_IMPLEMENTERS=2
WORKTREE_SETUP="test -d ."
EOF
check "Safe Turbo accepts the parallel full-stack preset" \
  "$LAUNCH" compose test-feature FEAT-1 backend full-stack
if out="$("$LAUNCH" compose test-feature FEAT-1 backend deep-backend 2>&1)"; then
  echo "FAIL: Safe Turbo accepted a preset without explicit parallel review"; FAILURES=$((FAILURES+1))
elif printf '%s' "$out" | grep -q 'REVIEW_MODE=parallel'; then
  echo "ok: Safe Turbo refuses a non-parallel review preset"
else
  echo "FAIL: Safe Turbo review refusal has wrong message: $out"; FAILURES=$((FAILURES+1))
fi
sed_i 's/^MAX_ACTIVE_IMPLEMENTERS=2$/MAX_ACTIVE_IMPLEMENTERS=5/' "$CFG"
if out="$("$LAUNCH" compose test-feature FEAT-1 backend full-stack 2>&1)"; then
  echo "FAIL: Safe Turbo accepted more than four implementers"; FAILURES=$((FAILURES+1))
elif printf '%s' "$out" | grep -q 'from 1 to 4'; then
  echo "ok: Safe Turbo enforces its concurrency ceiling"
else
  echo "FAIL: Safe Turbo ceiling refusal has wrong message: $out"; FAILURES=$((FAILURES+1))
fi
sed_i '/^TURBO_MODE=safe$/d;/^EXECUTION=parallel$/d;/^MAX_ACTIVE_IMPLEMENTERS=5$/d;/^WORKTREE_SETUP="test -d ."$/d' "$CFG"
sed_i 's|^VALIDATE_TEST="test -e .git"$|VALIDATE_TEST=null|' "$CFG"

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

# Direct task paths also export tracker state, so adapter authority must be
# bound before they create a task worktree, packet, prompt, or worker.
if TRACKER_ADAPTER=GitHubIssues "$LAUNCH" compose-task \
    adapter-compose missing-feature.md backend missing-feature.md#1 1 \
    >adapter-compose.out 2>&1; then
  echo "FAIL: compose-task accepted tracker adapter replacement"; FAILURES=$((FAILURES+1))
elif grep -q 'must exactly repeat configured PRODUCT_MANAGEMENT_TOOL' adapter-compose.out; then
  echo "ok: compose-task rejects tracker adapter replacement before mutation"
else
  echo "FAIL: compose-task adapter refusal has wrong error"; FAILURES=$((FAILURES+1))
fi
check "compose-task adapter refusal creates no task workspace" \
  test ! -e .teamwork/adapter-compose

if TRACKER_ADAPTER=GitHubIssues TEAM_RUNNER=background "$LAUNCH" start-task \
    adapter-start missing-feature.md backend missing-feature.md#1 1 \
    >adapter-start.out 2>&1; then
  echo "FAIL: start-task accepted tracker adapter replacement"; FAILURES=$((FAILURES+1))
elif grep -q 'must exactly repeat configured PRODUCT_MANAGEMENT_TOOL' adapter-start.out; then
  echo "ok: start-task rejects tracker adapter replacement before mutation"
else
  echo "FAIL: start-task adapter refusal has wrong error"; FAILURES=$((FAILURES+1))
fi
check "start-task adapter refusal creates no task workspace" \
  test ! -e .teamwork/adapter-start

# -- dirty-attempt quarantine inventories ignored bytes and converges replay --
cat > quarantine-feature.md <<'EOF'
# Quarantine fixture [Active]

## 1 Preserve ignored WIP [Active]

**Assignee:** backend

track: backend
parallel-safe: true
files: src/quarantine-one.txt
resources: quarantine:one

Preserve all abandoned attempt bytes before replacement.

## 2 Resume a post-move quarantine [Active]

**Assignee:** backend

track: backend
parallel-safe: true
files: src/quarantine-two.txt
resources: quarantine:two

Converge a broker replay after the worktree move.
EOF
printf '\n/ignored-quarantine/\n' >> .git/info/exclude
CFG_QUARANTINE=.claude/skills/pm/config/team.config.md
cp "$CFG_QUARANTINE" "$TMP/team.config.before-quarantine"
sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="true"|' "$CFG_QUARANTINE"
QUARANTINE_FID=quarantine-feature.md

wait_task_exit() { # team role task attempt
  local _qt_i _qt_rc
  for _qt_i in $(seq 1 80); do
    if "$LAUNCH" live-task "$1" "$2" "$3" "$4" >/dev/null 2>&1; then
      sleep 0.05
    else
      _qt_rc=$?
      [ "$_qt_rc" -eq 3 ] && return 0
      return "$_qt_rc"
    fi
  done
  return 1
}

QUARANTINE_TEAM=quarantine-ignored
QUARANTINE_TASK="$QUARANTINE_FID#1"
QUARANTINE_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$QUARANTINE_TASK")"
QUARANTINE_SOURCE="$PWD/.teamwork/$QUARANTINE_TEAM/worktrees/backend#1-$QUARANTINE_KEY"
QUARANTINE_SUFFIX="$(python3 -c 'import hashlib; print(hashlib.sha256(b"attempt-2").hexdigest()[:12])')"
QUARANTINE_MANIFEST="$PWD/.teamwork/$QUARANTINE_TEAM/quarantine/$QUARANTINE_KEY/attempt-1-$QUARANTINE_SUFFIX.json"
READY_HANDSHAKE_ENV="$TMP/ready-handshake-races.bash"
READY_EXIT_RACE_WITNESS="$TMP/ready-exit-race.witness"
READY_CREATED_MISMATCH_WITNESS="$TMP/ready-created-mismatch.witness"
cat > "$READY_HANDSHAKE_ENV" <<'EOF'
kill() {
  local _sf_i _sf_ready _sf_mode="${STARTUP_FACTORY_TEST_READY_HANDSHAKE:-}"
  if [ -n "$_sf_mode" ] \
      && [ "${1:-}" = -0 ] && [ "$#" -eq 2 ]; then
    if [ "$_sf_mode" = ready-exit-final ] \
        && [ -n "${_STARTUP_FACTORY_TEST_READY_HELD:-}" ]; then
      _STARTUP_FACTORY_TEST_READY_KILLS=$(( ${_STARTUP_FACTORY_TEST_READY_KILLS:-1} + 1 ))
      return 0
    fi
    # BASH_ENV affects only this test launcher; the worker's env -i boundary
    # does not inherit these controls.
    _sf_ready="${LAUNCH_READY_FILE:-}"
    [ -n "$_sf_ready" ] || return 125
    for _sf_i in $(seq 1 400); do
      [ ! -L "$_sf_ready" ] && [ -f "$_sf_ready" ] && break
      sleep 0.01
    done
    [ ! -L "$_sf_ready" ] && [ -f "$_sf_ready" ] || return 125
    if [ "$_sf_mode" = created-mismatch ]; then
      "$AUTHORITY_PYTHON" -I -B - "$_sf_ready" \
          "$STARTUP_FACTORY_TEST_READY_HANDSHAKE_WITNESS" <<'PY_READY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
# This remains syntactically valid and ends in Z, so the old shape-only check
# accepts it.  Only exact binding to the authenticated registration rejects it.
value["lifecycleCreatedAt"] = "1970-01-01T00:00:00Z"
with path.open("w", encoding="utf-8") as handle:
    json.dump(value, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
Path(sys.argv[2]).write_text("mismatched-created-at\n", encoding="ascii")
PY_READY
      builtin kill "$@"
      return $?
    fi
    [ "$_sf_mode" = ready-exit-final ] || return 125
    # Force the precise ordering that used to fail: the launcher has already
    # observed no receipt, then the supervisor publishes it and exits.  Hide
    # the durable receipt while kill -0 is made to report live for all 200
    # polls; the sleep hook restores it only after the last in-loop probe.
    _STARTUP_FACTORY_TEST_READY_ORIGINAL="$_sf_ready"
    _STARTUP_FACTORY_TEST_READY_HELD="${_sf_ready}.held"
    command mv "$_sf_ready" "$_STARTUP_FACTORY_TEST_READY_HELD" || return 125
    for _sf_i in $(seq 1 400); do
      if ! builtin kill -0 "$2" 2>/dev/null; then
        _STARTUP_FACTORY_TEST_READY_KILLS=1
        return 0
      fi
      command sleep 0.01
    done
    return 125
  fi
  builtin kill "$@"
}

sleep() {
  if [ "${STARTUP_FACTORY_TEST_READY_HANDSHAKE:-}" = ready-exit-final ] \
      && [ "$#" -eq 1 ] && [ "${1:-}" = 0.05 ]; then
    _STARTUP_FACTORY_TEST_READY_SLEEPS=$(( ${_STARTUP_FACTORY_TEST_READY_SLEEPS:-0} + 1 ))
    if [ "$_STARTUP_FACTORY_TEST_READY_SLEEPS" -eq 200 ]; then
      command mv "$_STARTUP_FACTORY_TEST_READY_HELD" \
        "$_STARTUP_FACTORY_TEST_READY_ORIGINAL" || return 125
      printf 'ready-then-dead-at-final-probe\n' \
        > "$STARTUP_FACTORY_TEST_READY_HANDSHAKE_WITNESS"
    fi
    return 0
  fi
  command sleep "$@"
}
EOF
git branch "$QUARANTINE_TEAM"
mkdir -p "$PWD/.teamwork/$QUARANTINE_TEAM"
prepare_task_claim "$QUARANTINE_TEAM" "$QUARANTINE_FID" "$QUARANTINE_TASK" backend 1
if BASH_ENV="$READY_HANDSHAKE_ENV" \
    STARTUP_FACTORY_TEST_READY_HANDSHAKE=created-mismatch \
    STARTUP_FACTORY_TEST_READY_HANDSHAKE_WITNESS="$READY_CREATED_MISMATCH_WITNESS" \
    TEAM_RUNNER=background "$LAUNCH" start-task \
      "$QUARANTINE_TEAM" "$QUARANTINE_FID" backend "$QUARANTINE_TASK" 1 \
      >"$TMP/quarantine-ready-created-mismatch.out" 2>&1; then
  echo "FAIL: quarantine launch accepted a ready receipt for another lifecycle generation"
  FAILURES=$((FAILURES+1))
elif grep -q 'publication supervisor failed its protected ready handshake' \
      "$TMP/quarantine-ready-created-mismatch.out" \
    && grep -qx 'mismatched-created-at' "$READY_CREATED_MISMATCH_WITNESS"; then
  echo "ok: quarantine launch rejects a ready receipt for another lifecycle generation"
else
  echo "FAIL: lifecycle-generation mismatch did not exercise the protected ready validator"
  cat "$TMP/quarantine-ready-created-mismatch.out" >&2
  FAILURES=$((FAILURES+1))
fi
if ! BASH_ENV="$READY_HANDSHAKE_ENV" \
    STARTUP_FACTORY_TEST_READY_HANDSHAKE=ready-exit-final \
    STARTUP_FACTORY_TEST_READY_HANDSHAKE_WITNESS="$READY_EXIT_RACE_WITNESS" \
    TEAM_RUNNER=background "$LAUNCH" start-task \
      "$QUARANTINE_TEAM" "$QUARANTINE_FID" backend "$QUARANTINE_TASK" 1 \
      >"$TMP/quarantine-ready-exit-race.out" 2>&1; then
  cat "$TMP/quarantine-ready-exit-race.out" >&2
  for path in "$PWD/.teamwork/$QUARANTINE_TEAM/pids/tasks/"*.log; do
    [ -f "$path" ] || continue
    echo "--- $path" >&2
    sed -n '1,200p' "$path" >&2
  done
  exit 1
fi
check "quarantine launch exercises ready-publication versus supervisor-exit race" \
  grep -qx 'ready-then-dead-at-final-probe' "$READY_EXIT_RACE_WITNESS"
check "quarantine fixture attempt exits" wait_task_exit \
  "$QUARANTINE_TEAM" backend "$QUARANTINE_TASK" 1
QUARANTINE_DEST="$(python3 .claude/skills/pm/bin/quarantine-attempt.py destination \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$QUARANTINE_TEAM" \
  --task-key "$QUARANTINE_KEY" --attempt 1 --suffix "$QUARANTINE_SUFFIX")"
mkdir -p "$QUARANTINE_SOURCE/ignored-quarantine"
printf 'ignored but valuable WIP\000with bytes\n' > "$QUARANTINE_SOURCE/ignored-quarantine/wip.bin"
printf 'external target remains untouched\n' > "$TMP/outside-quarantine-target"
ln -s "$TMP/outside-quarantine-target" "$QUARANTINE_SOURCE/ignored-quarantine/outside-link"
prepare_task_claim "$QUARANTINE_TEAM" "$QUARANTINE_FID" "$QUARANTINE_TASK" backend 2
TEAM_RUNNER=background "$LAUNCH" start-task \
  "$QUARANTINE_TEAM" "$QUARANTINE_FID" backend "$QUARANTINE_TASK" 2 >/dev/null
check "ignored-only WIP is quarantined, never removed as clean" test -d "$QUARANTINE_DEST"
check "ignored WIP bytes survive quarantine" test -f "$QUARANTINE_DEST/ignored-quarantine/wip.bin"
check "quarantine inventories symlink without replacing it" test -L "$QUARANTINE_DEST/ignored-quarantine/outside-link"
check "quarantine never follows or changes external symlink target" \
  grep -qx 'external target remains untouched' "$TMP/outside-quarantine-target"
check "replacement attempt receives a fresh worktree" \
  test -d "$PWD/.teamwork/$QUARANTINE_TEAM/worktrees/backend#2-$QUARANTINE_KEY"
check "quarantine writes its workspace projection" test -f "$QUARANTINE_MANIFEST"
check "quarantine receipts HMAC-bind every ignored byte and symlink" python3 - \
    "$LIFECYCLE_ROOT" "$QUARANTINE_TEAM" "$QUARANTINE_MANIFEST" \
    "$TMP/outside-quarantine-target" "$QUARANTINE_DEST" <<'PY'
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys

root, team, manifest_path, symlink_target, destination = sys.argv[1:]
key = Path(root, "record-auth.key").read_bytes()
receipts = Path(root, "quarantine-receipts")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def authenticated(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    supplied = value.pop("auth")
    expected = "hmac-sha256:" + hmac.new(key, canonical(value), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(supplied, expected)
    value["auth"] = supplied
    return value


prepares = [
    authenticated(path)
    for path in receipts.glob("*.prepare.json")
    if json.loads(path.read_text())["operation"]["team"] == team
]
finals = [
    authenticated(path)
    for path in receipts.glob("*.final.json")
    if json.loads(path.read_text())["operation"]["team"] == team
]
assert len(prepares) == len(finals) == 1
prepare, final = prepares[0], finals[0]
prepare_path = Path(next(path for path in receipts.glob("*.prepare.json") if json.loads(path.read_text())["operation"]["team"] == team))
final_path = Path(next(path for path in receipts.glob("*.final.json") if json.loads(path.read_text())["operation"]["team"] == team))
assert stat.S_IMODE(receipts.stat().st_mode) == 0o700
assert stat.S_IMODE(prepare_path.stat().st_mode) == 0o600
assert stat.S_IMODE(final_path.stat().st_mode) == 0o600
entries = {
    base64.b64decode(item["pathB64"]): item
    for item in prepare["inventory"]["entries"]
}


def actual_entries(root_path):
    result = {}

    def visit(directory, prefix=b""):
        for item in sorted(os.scandir(directory), key=lambda candidate: os.fsencode(candidate.name)):
            name = os.fsencode(item.name)
            relative = name if not prefix else prefix + b"/" + name
            info = item.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISREG(info.st_mode):
                content = Path(item.path).read_bytes()
                result[relative] = {
                    "kind": "file",
                    "mode": mode,
                    "size": len(content),
                    "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
                }
            elif stat.S_ISDIR(info.st_mode):
                result[relative] = {"kind": "directory", "mode": mode}
                visit(item.path, relative)
            elif stat.S_ISLNK(info.st_mode):
                target_bytes = os.fsencode(os.readlink(item.path))
                result[relative] = {
                    "kind": "symlink",
                    "mode": mode,
                    "size": len(target_bytes),
                    "sha256": "sha256:" + hashlib.sha256(target_bytes).hexdigest(),
                }
            else:
                raise AssertionError(f"unsupported fixture entry: {relative!r}")

    visit(root_path)
    return result


assert {
    path: {key: value for key, value in item.items() if key != "pathB64"}
    for path, item in entries.items()
} == actual_entries(destination)
assert prepare["inventory"]["rootMode"] == stat.S_IMODE(Path(destination).stat().st_mode)
wip = b"ignored but valuable WIP\x00with bytes\n"
assert entries[b"ignored-quarantine/wip.bin"]["sha256"] == "sha256:" + hashlib.sha256(wip).hexdigest()
target = symlink_target.encode()
assert entries[b"ignored-quarantine/outside-link"]["kind"] == "symlink"
assert entries[b"ignored-quarantine/outside-link"]["sha256"] == "sha256:" + hashlib.sha256(target).hexdigest()
assert final["inventorySha256"] == prepare["inventory"]["treeSha256"]
manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
assert manifest["schemaVersion"] == 2
assert manifest["treeSha256"] == prepare["inventory"]["treeSha256"]
assert Path(manifest["prepareReceipt"]).is_file()
assert Path(manifest["finalReceipt"]).is_file()
PY

# Model the exact crash window: durable prepare receipt, successful Git move,
# no final receipt or workspace projection. Starting N+1 must finalize that
# operation rather than declaring the old source absent and silently returning.
REPLAY_TEAM=quarantine-replay
REPLAY_TASK="$QUARANTINE_FID#2"
REPLAY_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$REPLAY_TASK")"
REPLAY_SOURCE="$PWD/.teamwork/$REPLAY_TEAM/worktrees/backend#1-$REPLAY_KEY"
REPLAY_MANIFEST="$PWD/.teamwork/$REPLAY_TEAM/quarantine/$REPLAY_KEY/attempt-1-$QUARANTINE_SUFFIX.json"
REPLAY_BRANCH="agent-quarantine/$REPLAY_TEAM/$REPLAY_KEY/a1-$QUARANTINE_SUFFIX"
git branch "$REPLAY_TEAM"
mkdir -p "$PWD/.teamwork/$REPLAY_TEAM"
prepare_task_claim "$REPLAY_TEAM" "$QUARANTINE_FID" "$REPLAY_TASK" backend 1
TEAM_RUNNER=background "$LAUNCH" start-task \
  "$REPLAY_TEAM" "$QUARANTINE_FID" backend "$REPLAY_TASK" 1 >/dev/null
check "post-move replay fixture attempt exits" wait_task_exit \
  "$REPLAY_TEAM" backend "$REPLAY_TASK" 1
REPLAY_DEST="$(python3 .claude/skills/pm/bin/quarantine-attempt.py destination \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$REPLAY_TEAM" \
  --task-key "$REPLAY_KEY" --attempt 1 --suffix "$QUARANTINE_SUFFIX")"
mkdir -p "$REPLAY_SOURCE/ignored-quarantine"
printf 'replay must preserve me\n' > "$REPLAY_SOURCE/ignored-quarantine/replay.txt"
REPLAY_HEAD="$(git -C "$REPLAY_SOURCE" rev-parse HEAD)"
git -C "$REPLAY_SOURCE" switch -q -c "$REPLAY_BRANCH"
python3 .claude/skills/pm/bin/quarantine-attempt.py prepare \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" --workspace "$PWD/.teamwork/$REPLAY_TEAM" \
  --team "$REPLAY_TEAM" --task "$REPLAY_TASK" --task-key "$REPLAY_KEY" \
  --role backend --attempt 1 --control-id attempt-2 --branch "$REPLAY_BRANCH" \
  --source "$REPLAY_SOURCE" --destination "$REPLAY_DEST" --head "$REPLAY_HEAD" >/dev/null
git worktree move "$REPLAY_SOURCE" "$REPLAY_DEST"
check "crash simulation has prepare but no final receipt" python3 - \
    "$LIFECYCLE_ROOT" "$REPLAY_TEAM" <<'PY'
import json
from pathlib import Path
import sys

root, team = sys.argv[1:]
receipts = Path(root, "quarantine-receipts")
prepare = [p for p in receipts.glob("*.prepare.json") if json.loads(p.read_text())["operation"]["team"] == team]
final = [p for p in receipts.glob("*.final.json") if json.loads(p.read_text())["operation"]["team"] == team]
assert len(prepare) == 1 and not final
PY
prepare_task_claim "$REPLAY_TEAM" "$QUARANTINE_FID" "$REPLAY_TASK" backend 2
TEAM_RUNNER=background "$LAUNCH" start-task \
  "$REPLAY_TEAM" "$QUARANTINE_FID" backend "$REPLAY_TASK" 2 >/dev/null
check "post-move replay preserves quarantined bytes" \
  grep -qx 'replay must preserve me' "$REPLAY_DEST/ignored-quarantine/replay.txt"
check "post-move replay writes protected final receipt" python3 - \
    "$LIFECYCLE_ROOT" "$REPLAY_TEAM" <<'PY'
import json
from pathlib import Path
import sys

root, team = sys.argv[1:]
matches = [
    path
    for path in Path(root, "quarantine-receipts").glob("*.final.json")
    if json.loads(path.read_text())["operation"]["team"] == team
]
assert len(matches) == 1
PY
check "post-move replay reconstructs workspace projection" test -f "$REPLAY_MANIFEST"
check "post-move replay launches replacement worktree" \
  test -d "$PWD/.teamwork/$REPLAY_TEAM/worktrees/backend#2-$REPLAY_KEY"
cp "$TMP/team.config.before-quarantine" "$CFG_QUARANTINE"

# -- tmux liveness: pid file removed on agent exit; dead pane never blocks relaunch ----
tmux_usable=no
tmux_probe="startup-factory-probe-$$"
if command -v tmux >/dev/null 2>&1 && tmux new-session -d -s "$tmux_probe" 'sleep 1' >/dev/null 2>&1; then
  tmux_usable=yes
  tmux kill-session -t "$tmux_probe" 2>/dev/null || true
fi
if [ "${TEAM_RUNNER:-auto}" != "background" ] && [ "$tmux_usable" = yes ]; then
  TMUX_STOP_SOCKET="$TMP/tmux-stop-isolated.sock"
  TMUX_STOP_PREVIOUS="${TMUX-}"
  TMUX_STOP_HAD_PREVIOUS="${TMUX+x}"
  export TMUX="$TMUX_STOP_SOCKET,0,0"
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
sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="sleep 120"|' "$CFG_LIFECYCLE"

# The supported macOS/Python 3.10-3.12 combinations do not expose os.waitid.
# Exercise the portable waitpid reaper on every platform and pin the source
# boundary so a future waitid-only regression cannot hide behind newer CI.
if grep -Fq 'os.waitid' "$LAUNCH"; then
  echo "FAIL: background reaper requires unavailable os.waitid"
  FAILURES=$((FAILURES+1))
else
  echo "ok: background reaper uses the portable waitpid contract"
fi
PORTABLE_REAPER_HELPER="$TMP/portable-background-reaper-test.py"
cat > "$PORTABLE_REAPER_HELPER" <<'PY'
import json
from pathlib import Path
import subprocess
import sys
import time

launch, lifecycle, lifecycle_root, repository, team = sys.argv[1:]
environment = dict(__import__("os").environ)
environment["TEAM_RUNNER"] = "background"
log = Path(repository, ".teamwork", team, "pids", "backend.log")


def launch_once(previous_generation):
    result = subprocess.run(
        [launch, "start", team, "FEAT-PORTABLE-REAPER", "backend"],
        cwd=repository,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(70)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        observed = subprocess.run(
            [
                sys.executable,
                lifecycle,
                "list",
                "--root",
                lifecycle_root,
                "--repo",
                repository,
                "--team",
                team,
            ],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if observed.returncode != 0:
            raise SystemExit(71)
        rows = [json.loads(line) for line in observed.stdout.splitlines() if line.strip()]
        if len(rows) != 1:
            raise SystemExit(72)
        generation = rows[0]["createdAt"]
        if generation == previous_generation:
            raise SystemExit(73)
        if rows[0]["state"] == "live":
            time.sleep(0.02)
            continue
        if rows[0]["state"] == "dead" and rows[0]["kind"] == "background":
            # waitpid() and the exact, lock-protected completion transition are
            # separate operations. A reader may briefly observe the verified-
            # dead source record before it becomes non-authoritative evidence.
            time.sleep(0.02)
            continue
        if rows[0]["state"] != "dead" or rows[0]["kind"] != "completed-background":
            raise SystemExit(74)
        contents = log.read_text(encoding="utf-8")
        if "Traceback" in contents or "AttributeError" in contents:
            raise SystemExit(75)
        return generation
    raise SystemExit(76)


first = launch_once("")
second = launch_once(first)
if first == second:
    raise SystemExit(77)
PY
set_config_line BACKEND_CMD '"sleep 1"'
if python3 "$PORTABLE_REAPER_HELPER" "$PWD/$LAUNCH" \
    "$PWD/.claude/skills/pm/bin/process-lifecycle.py" \
    "$LIFECYCLE_ROOT" "$PWD" lifecycle-portable-reaper; then
  echo "ok: short-lived background roles reap and relaunch without a traceback"
else
  echo "FAIL: portable background reaper did not retire and relaunch cleanly"
  FAILURES=$((FAILURES+1))
fi
set_config_line BACKEND_CMD '"sleep 120"'

# Linux CI runners may act as subreapers without promptly waitpid()ing orphaned
# grandchildren.  Reproduce that host shape deterministically: the actual
# launcher must leave only its out-of-group wrapper zombie behind, while the
# registered PID=PGID=SID child is reaped and therefore reports dead.
LINUX_REAPER_HELPER="$TMP/linux-background-reaper-test.py"
cat > "$LINUX_REAPER_HELPER" <<'PY'
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time

launch, lifecycle, lifecycle_root, repository, team = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    raise SystemExit(70)

environment = dict(os.environ)
environment["TEAM_RUNNER"] = "background"
try:
    launched = subprocess.run(
        [launch, "start", team, "FEAT-REAPER", "backend"],
        cwd=repository,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
except subprocess.TimeoutExpired:
    raise SystemExit(71)
if launched.returncode != 0:
    raise SystemExit(72)

managed_pid = 0
first_created = ""
deadline = time.monotonic() + 8
while time.monotonic() < deadline:
    observed = subprocess.run(
        [
            sys.executable,
            lifecycle,
            "list",
            "--root",
            lifecycle_root,
            "--repo",
            repository,
            "--team",
            team,
        ],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if observed.returncode != 0:
        raise SystemExit(73)
    rows = [json.loads(line) for line in observed.stdout.splitlines() if line.strip()]
    if len(rows) != 1:
        raise SystemExit(74)
    if first_created and rows[0]["createdAt"] != first_created:
        raise SystemExit(76)
    managed_pid = rows[0]["pid"]
    first_created = rows[0]["createdAt"]
    if rows[0]["state"] == "dead":
        if rows[0]["kind"] == "background":
            time.sleep(0.02)
            continue
        if rows[0]["kind"] != "completed-background":
            raise SystemExit(75)
        break
    if rows[0]["state"] != "live":
        raise SystemExit(75)
    time.sleep(0.02)
else:
    raise SystemExit(76)

if not first_created:
    raise SystemExit(76)

children_path = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")
deadline = time.monotonic() + 8
zombies = []
while time.monotonic() < deadline:
    children = children_path.read_text(encoding="ascii").split()
    zombies = []
    for value in children:
        pid = int(value)
        try:
            raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        fields = raw[raw.rfind(")") + 2 :].split()
        if len(fields) >= 4 and fields[0] == "Z":
            # The retained wrapper must be outside the managed session.  A
            # zombie at the lifecycle PID/PGID would reproduce the CI defect.
            if pid == managed_pid or int(fields[2]) == managed_pid:
                raise SystemExit(77)
            zombies.append(pid)
    if zombies:
        break
    time.sleep(0.02)
else:
    raise SystemExit(78)

# Keep the first wrapper zombie unreaped while launching the exact same role.
# Its PID is outside lifecycle authority and must not block or alias the new
# self-registered generation.
relaunched = subprocess.run(
    [launch, "start", team, "FEAT-REAPER", "backend"],
    cwd=repository,
    env=environment,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    timeout=15,
    check=False,
)
if relaunched.returncode != 0:
    raise SystemExit(79)
second_pid = 0
deadline = time.monotonic() + 8
while time.monotonic() < deadline:
    observed = subprocess.run(
        [
            sys.executable,
            lifecycle,
            "list",
            "--root",
            lifecycle_root,
            "--repo",
            repository,
            "--team",
            team,
        ],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if observed.returncode != 0:
        raise SystemExit(80)
    rows = [json.loads(line) for line in observed.stdout.splitlines() if line.strip()]
    if len(rows) != 1:
        raise SystemExit(81)
    if rows[0]["createdAt"] == first_created:
        raise SystemExit(82)
    if second_pid and rows[0]["pid"] != second_pid:
        raise SystemExit(83)
    second_pid = rows[0]["pid"]
    if rows[0]["state"] == "dead":
        if rows[0]["kind"] == "background":
            time.sleep(0.02)
            continue
        if rows[0]["kind"] != "completed-background":
            raise SystemExit(82)
        break
    if rows[0]["state"] != "live":
        raise SystemExit(82)
    time.sleep(0.02)
else:
    raise SystemExit(83)

managed_pids = {managed_pid, second_pid}
deadline = time.monotonic() + 8
while time.monotonic() < deadline:
    children = children_path.read_text(encoding="ascii").split()
    zombies = []
    for value in children:
        pid = int(value)
        try:
            raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        fields = raw[raw.rfind(")") + 2 :].split()
        if len(fields) >= 4 and fields[0] == "Z":
            if pid in managed_pids or int(fields[2]) in managed_pids:
                raise SystemExit(84)
            zombies.append(pid)
    if len(zombies) >= 2:
        break
    time.sleep(0.02)
else:
    raise SystemExit(85)

for pid in zombies:
    os.waitpid(pid, 0)
PY

if [ "$(uname -s)" = Linux ]; then
  # Keep the managed child alive just long enough for its launcher parent to
  # exit, so the outer reaper is deterministically adopted by our subreaper.
  set_config_line BACKEND_CMD '"sleep 1"'
  if python3 "$LINUX_REAPER_HELPER" "$PWD/$LAUNCH" \
      "$PWD/.claude/skills/pm/bin/process-lifecycle.py" \
      "$LIFECYCLE_ROOT" "$PWD" lifecycle-background-reaper; then
    echo "ok: unreaped wrapper zombie stays outside lifecycle authority across same-role relaunch"
  else
    rc=$?
    echo "FAIL: background reaper did not retire the registered child under a non-reaping host (helper rc=$rc)"
    FAILURES=$((FAILURES+1))
  fi
  set_config_line BACKEND_CMD '"sleep 120"'
else
  echo "skip: Linux orphan-zombie background reaper regression"
fi

# Remove the protected FIFO after self-registration but before shell release.
# The launcher must fail promptly, stop and forget only that authenticated
# generation, and never spill its launch token into the role log or stdout.
RELEASE_FAILURE_HELPER="$TMP/background-release-failure-test.py"
RELEASE_FAILURE_METADATA="$TMP/background-release-failure-metadata.json"
RELEASE_FAILURE_OUTPUT="$TMP/background-release-failure.out"
cat > "$RELEASE_FAILURE_HELPER" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

launch, lifecycle_root, repository, team, metadata_path, output_path = sys.argv[1:]
stop = threading.Event()
injected = threading.Event()


def break_release():
    root = Path(lifecycle_root)
    while not stop.is_set():
        for candidate in root.rglob("group.pid"):
            try:
                raw = candidate.read_bytes()
                value = json.loads(raw.decode("ascii"))
                if set(value) != {"createdAt", "launchToken", "pid"}:
                    continue
                Path(metadata_path).write_bytes(raw)
                (candidate.parent / "go").unlink()
            except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeError):
                continue
            injected.set()
            return
        time.sleep(0.001)


watcher = threading.Thread(target=break_release, daemon=True)
watcher.start()
environment = dict(os.environ)
environment["TEAM_RUNNER"] = "background"
started = time.monotonic()
process = subprocess.Popen(
    [launch, "start", team, "FEAT-RELEASE", "backend"],
    cwd=repository,
    env=environment,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)
try:
    output, _ = process.communicate(timeout=20)
except subprocess.TimeoutExpired:
    process.terminate()
    output, _ = process.communicate(timeout=5)
    Path(output_path).write_bytes(output)
    raise SystemExit(70)
finally:
    stop.set()
watcher.join(timeout=1)
Path(output_path).write_bytes(output)
if not injected.is_set():
    raise SystemExit(71)
if process.returncode == 0:
    raise SystemExit(72)
if time.monotonic() - started > 12:
    raise SystemExit(73)
PY

set_config_line BACKEND_CMD '"true"'
if python3 "$RELEASE_FAILURE_HELPER" "$PWD/$LAUNCH" "$LIFECYCLE_ROOT" "$PWD" \
    lifecycle-release-failure "$RELEASE_FAILURE_METADATA" "$RELEASE_FAILURE_OUTPUT"; then
  echo "ok: missing background release FIFO fails promptly without blocking"
else
  echo "FAIL: missing background release FIFO did not fail closed within its bound"
  FAILURES=$((FAILURES+1))
fi
if grep -q 'could not release protected background launch barrier' "$RELEASE_FAILURE_OUTPUT"; then
  echo "ok: background release failure is reported"
else
  echo "FAIL: background release failure reported the wrong diagnostic"
  FAILURES=$((FAILURES+1))
fi
release_failure_token=""
if [ -s "$RELEASE_FAILURE_METADATA" ]; then
  release_failure_token="$(python3 - "$RELEASE_FAILURE_METADATA" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="ascii"))["launchToken"])
PY
)"
else
  echo "FAIL: background release failure captured no lifecycle metadata"
  FAILURES=$((FAILURES+1))
fi
if [ -n "$release_failure_token" ] && grep -Fq "$release_failure_token" \
    .teamwork/lifecycle-release-failure/pids/backend.log "$RELEASE_FAILURE_OUTPUT"; then
  echo "FAIL: background release failure leaked its lifecycle token"
  FAILURES=$((FAILURES+1))
else
  echo "ok: background release failure keeps lifecycle token out of diagnostics"
fi
if [ -e .teamwork/lifecycle-release-failure/pids/backend.pid ]; then
  echo "FAIL: background release failure left a workspace marker"
  FAILURES=$((FAILURES+1))
else
  echo "ok: background release failure removes its workspace marker"
fi
if python3 .claude/skills/pm/bin/process-lifecycle.py list \
    --root "$LIFECYCLE_ROOT" --repo "$PWD" \
    --team lifecycle-release-failure | grep -q .; then
  echo "FAIL: background release failure left a lifecycle record"
  FAILURES=$((FAILURES+1))
else
  echo "ok: background release failure retires its exact lifecycle generation"
fi
set_config_line BACKEND_CMD '"sleep 120"'

LIFECYCLE_WITNESS="$TMP/lifecycle-witness.py"
LIFECYCLE_READY_DIR="$TMP/lifecycle-witness-ready"
LIFECYCLE_SIGNAL_DIR="$TMP/lifecycle-witness-signals"
mkdir -p "$LIFECYCLE_READY_DIR" "$LIFECYCLE_SIGNAL_DIR"
cat > "$LIFECYCLE_WITNESS" <<'PY'
#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import sys

ready_dir, signal_dir = map(Path, sys.argv[1:3])
mode = sys.argv[3]
if mode not in {"term-exit", "ignore"}:
    raise SystemExit("invalid witness mode")
instance = os.environ.get("STARTUP_FACTORY_INSTANCE", sys.argv[4] if len(sys.argv) > 4 else "")
if not instance or "/" in instance or instance in {".", ".."}:
    raise SystemExit("invalid witness instance")


def observed(signum, _frame):
    name = signal.Signals(signum).name
    (signal_dir / f"{instance}.{name}").write_text("observed\n", encoding="ascii")
    if mode == "term-exit" and signum == signal.SIGTERM:
        raise SystemExit(0)


for watched in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(watched, observed)
(ready_dir / f"{instance}.ready").write_text("ready\n", encoding="ascii")
while True:
    signal.pause()
PY
chmod 700 "$LIFECYCLE_WITNESS"

wait_for_witness_ready() { # ready-path
  local ready="$1"
  for _i in $(seq 1 600); do
    [ -s "$ready" ] && return 0
    sleep 0.1
  done
  return 1
}

signal_witness_is_quiet() { # directory instance
  local directory="$1" instance="$2"
  [ ! -e "$directory/$instance.SIGTERM" ] \
    && [ ! -e "$directory/$instance.SIGINT" ] \
    && [ ! -e "$directory/$instance.SIGHUP" ]
}

signal_witness_stays_quiet() { # directory instance
  local directory="$1" instance="$2"
  for _i in $(seq 1 10); do
    signal_witness_is_quiet "$directory" "$instance" || return 1
    sleep 0.05
  done
}

process_group_is_live() { # pgid
  kill -0 -- "-$1"
}

require_live_task() { # description team role task attempt instance
  local description="$1" team="$2" role="$3" task="$4" attempt="$5" instance="$6"
  local output rc diagnostic log
  set +e
  output="$("$LAUNCH" live-task "$team" "$role" "$task" "$attempt" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "ok: $description"
    return 0
  fi
  diagnostic="$(
    python3 .claude/skills/pm/bin/process-lifecycle.py list \
      --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$team" 2>/dev/null | \
    python3 -c 'import json,sys
for line in sys.stdin:
    if not line.strip():
        continue
    row=json.loads(line)
    print("%s/%s:%s" % (row.get("category"), row.get("instance"), row.get("state")))'
  )" || diagnostic='<unavailable>'
  log="$PWD/.teamwork/$team/pids/tasks/$instance.log"
  echo "FAIL: $description (rc=$rc, output=$output, lifecycle=${diagnostic:-<empty>}, log=$log)"
  if [ -f "$log" ]; then
    echo "--- bounded fixture log ---"
    tail -40 "$log"
    echo "--- end fixture log ---"
  fi
  FAILURES=$((FAILURES+1))
}

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
signal.signal(signal.SIGTERM, signal.SIG_IGN)
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

LEADER_EXIT_CHILD_SURVIVES="$TMP/leader-exit-child-survives.py"
cat > "$LEADER_EXIT_CHILD_SURVIVES" <<'PY'
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

# Two real launchers are queued behind a deliberately held lane.  Releasing
# the holder makes them contend from the same deterministic starting point:
# exactly one may pass the absent check, mint, and register; the other must see
# that registered generation before it can mint a superseding capability.
SIMULTANEOUS_TEAM=simultaneous-launch-lane
SIMULTANEOUS_BARRIER="$(mktemp -d "$LIFECYCLE_ROOT/.simultaneous-lane.XXXXXXXX")"
chmod 700 "$SIMULTANEOUS_BARRIER"
PYTHONDONTWRITEBYTECODE=1 python3 -I -B \
  .claude/skills/pm/bin/launch-lane-lock.py \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$SIMULTANEOUS_TEAM" \
  --category gate --instance backend --barrier "$SIMULTANEOUS_BARRIER" \
  2>"$TMP/simultaneous-lane-holder.err" &
SIMULTANEOUS_HOLDER=$!
for _i in $(seq 1 200); do
  [ -s "$SIMULTANEOUS_BARRIER/ready" ] && break
  /bin/kill -0 "$SIMULTANEOUS_HOLDER" 2>/dev/null || break
  sleep 0.02
done
check "simultaneous-launch fixture holds the exact gate lane" \
  test -s "$SIMULTANEOUS_BARRIER/ready"
TEAM_RUNNER=background "$LAUNCH" start \
  "$SIMULTANEOUS_TEAM" FEAT-SIMULTANEOUS backend \
  >"$TMP/simultaneous-launch-a.out" 2>&1 &
SIMULTANEOUS_A=$!
TEAM_RUNNER=background "$LAUNCH" start \
  "$SIMULTANEOUS_TEAM" FEAT-SIMULTANEOUS backend \
  >"$TMP/simultaneous-launch-b.out" 2>&1 &
SIMULTANEOUS_B=$!
SIMULTANEOUS_WAITERS=0
for _i in $(seq 1 400); do
  SIMULTANEOUS_WAITERS="$(python3 -c \
    'import pathlib,sys; print(sum(path.is_dir() for path in pathlib.Path(sys.argv[1]).glob(".launch-lane.*")))' \
    "$LIFECYCLE_ROOT")"
  [ "$SIMULTANEOUS_WAITERS" -ge 2 ] && break
  sleep 0.02
done
check "both launchers reach the protected lane before release" \
  test "$SIMULTANEOUS_WAITERS" -ge 2
mkdir -m 700 "$SIMULTANEOUS_BARRIER/release"
wait "$SIMULTANEOUS_HOLDER"
if wait "$SIMULTANEOUS_A" && wait "$SIMULTANEOUS_B"; then
  echo "ok: simultaneous same-lane launcher calls converge"
else
  echo "FAIL: simultaneous same-lane launcher call failed"
  sed -n '1,80p' "$TMP/simultaneous-launch-a.out" >&2
  sed -n '1,80p' "$TMP/simultaneous-launch-b.out" >&2
  FAILURES=$((FAILURES+1))
fi
check "one simultaneous launcher wins and one observes the live generation" \
  python3 - "$TMP/simultaneous-launch-a.out" "$TMP/simultaneous-launch-b.out" <<'PY'
from pathlib import Path
import sys

outputs = [Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]]
assert sum("launched backend in background" in value for value in outputs) == 1
assert sum("role instance already live: backend" in value for value in outputs) == 1
PY
check "live simultaneous winner retains the lane's active capability" \
  python3 - "$PWD" "$LIFECYCLE_ROOT" "$SIMULTANEOUS_TEAM" <<'PY'
import json
from pathlib import Path
import subprocess
import sys

repo, lifecycle_root, team = sys.argv[1:]
lifecycle = Path(repo, ".claude/skills/pm/bin/process-lifecycle.py")
listed = subprocess.run(
    [sys.executable, str(lifecycle), "list", "--root", lifecycle_root,
     "--repo", repo, "--team", team],
    text=True, capture_output=True, check=True,
)
rows = [json.loads(line) for line in listed.stdout.splitlines() if line.strip()]
matches = [row for row in rows if row.get("category") == "gate"
           and row.get("instance") == "backend"]
assert len(matches) == 1 and matches[0].get("state") == "live", matches
command = subprocess.check_output(
    ["ps", "-p", str(matches[0]["pid"]), "-o", "command="], text=True
)
common = Path(subprocess.check_output(
    ["git", "-C", repo, "rev-parse", "--git-common-dir"], text=True
).strip())
if not common.is_absolute():
    common = Path(repo, common)
broker = common.resolve() / "startup-factory-broker"
records = broker / "outbox-capabilities"
active_ids = []
for pointer in (broker / "outbox-active").glob("*.id"):
    capability_id = pointer.read_text(encoding="ascii").strip()
    record = json.loads((records / (capability_id + ".json")).read_text())
    if (record.get("team") == team and record.get("executionKind") == "gate"
            and record.get("role") == "backend"):
        active_ids.append(capability_id)
assert len(active_ids) == 1, active_ids
assert "--handle " + active_ids[0] in command, (active_ids[0], command)
PY
"$LAUNCH" stop "$SIMULTANEOUS_TEAM" >/dev/null
rm -f "$SIMULTANEOUS_BARRIER/ready" "$TMP/simultaneous-lane-holder.err"
rmdir "$SIMULTANEOUS_BARRIER/release" "$SIMULTANEOUS_BARRIER"

# Queue an authorized successor ahead of a stale start while a broker-held
# stable task lane is blocked.  The stale caller packetizes attempt one before
# release, but it must observe attempt two after the successor's mint/register
# transaction and must never replace attempt two's active capability pointer.
TASK_LANE_TEAM=stable-task-lane-race
TASK_LANE_FEATURE=stable-task-lane-feature.md
TASK_LANE_TASK="$TASK_LANE_FEATURE#1"
TASK_LANE_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$TASK_LANE_TASK")"
TASK_LANE_CONTROL=control-66666666666666666666666666666666
TASK_LANE_WORKSPACE="$PWD/.teamwork/$TASK_LANE_TEAM"
cat > "$TASK_LANE_FEATURE" <<'EOF'
# Stable task lane fixture [Active]

## 1 Serialize successor authority [Active]

**Assignee:** backend

A stale attempt must not mint after an authorized successor.
EOF
git branch "$TASK_LANE_TEAM"
prepare_task_claim \
  "$TASK_LANE_TEAM" "$TASK_LANE_FEATURE" "$TASK_LANE_TASK" backend 1
STARTUP_FACTORY_LLM_RUNTIME=other "$LAUNCH" compose-task \
  "$TASK_LANE_TEAM" "$TASK_LANE_FEATURE" backend "$TASK_LANE_TASK" 1 \
  >/dev/null
python3 .claude/skills/pm/bin/control-grant.py issue \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" \
  --team "$TASK_LANE_TEAM" --feature "$TASK_LANE_FEATURE" \
  --action restart-task --target "$TASK_LANE_TASK" --attempt 1 \
  --generation - --control-id "$TASK_LANE_CONTROL" --reason authorized \
  >/dev/null
TASK_LANE_BARRIER="$(mktemp -d "$LIFECYCLE_ROOT/.stable-task-lane.XXXXXXXX")"
chmod 700 "$TASK_LANE_BARRIER"
PYTHONDONTWRITEBYTECODE=1 python3 -I -B \
  .claude/skills/pm/bin/launch-lane-lock.py \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$TASK_LANE_TEAM" \
  --category task --instance "$TASK_LANE_KEY" --barrier "$TASK_LANE_BARRIER" \
  2>"$TMP/stable-task-lane-holder.err" &
TASK_LANE_HOLDER=$!
for _i in $(seq 1 200); do
  [ -s "$TASK_LANE_BARRIER/ready" ] && break
  /bin/kill -0 "$TASK_LANE_HOLDER" 2>/dev/null || break
  sleep 0.02
done
check "stable-task race fixture holds the task-key lane" \
  test -s "$TASK_LANE_BARRIER/ready"
TEAM_RUNNER=background STARTUP_FACTORY_CONTROL_BROKER=1 \
  STARTUP_FACTORY_CONTROL_REASON=authorized \
  STARTUP_FACTORY_EXPECTED_LIFECYCLE_CREATED_AT=- \
  "$LAUNCH" restart-task "$TASK_LANE_TEAM" "$TASK_LANE_FEATURE" \
    "$TASK_LANE_TASK" 1 "$TASK_LANE_CONTROL" \
    >"$TMP/stable-task-successor.out" 2>&1 &
TASK_LANE_SUCCESSOR=$!
for _i in $(seq 1 400); do
  TASK_LANE_WAITERS="$(python3 -c \
    'import pathlib,sys; print(sum(path.is_dir() for path in pathlib.Path(sys.argv[1]).glob(".launch-lane.*")))' \
    "$LIFECYCLE_ROOT")"
  [ "$TASK_LANE_WAITERS" -ge 1 ] && break
  sleep 0.02
done
check "authorized successor queues first on the stable task lane" \
  test "$TASK_LANE_WAITERS" -ge 1
TASK_LANE_STALE_PROMPT="$TASK_LANE_WORKSPACE/prompts/tasks/backend--$TASK_LANE_KEY--a1.md"
rm -f "$TASK_LANE_STALE_PROMPT"
TEAM_RUNNER=background "$LAUNCH" start-task \
  "$TASK_LANE_TEAM" "$TASK_LANE_FEATURE" backend "$TASK_LANE_TASK" 1 \
  >"$TMP/stable-task-stale.out" 2>&1 &
TASK_LANE_STALE=$!
for _i in $(seq 1 400); do
  TASK_LANE_WAITERS="$(python3 -c \
    'import pathlib,sys; print(sum(path.is_dir() for path in pathlib.Path(sys.argv[1]).glob(".launch-lane.*")))' \
    "$LIFECYCLE_ROOT")"
  [ "$TASK_LANE_WAITERS" -ge 2 ] && [ -s "$TASK_LANE_STALE_PROMPT" ] && break
  sleep 0.02
done
check "stale attempt reaches the same task lane before release" \
  python3 -c \
    'import pathlib,sys; assert int(sys.argv[1]) >= 2; assert pathlib.Path(sys.argv[2]).stat().st_size > 0' \
    "$TASK_LANE_WAITERS" "$TASK_LANE_STALE_PROMPT"
mkdir -m 700 "$TASK_LANE_BARRIER/release"
wait "$TASK_LANE_HOLDER"
if wait "$TASK_LANE_SUCCESSOR"; then
  echo "ok: authorized successor completes under the stable task lane"
else
  echo "FAIL: authorized successor failed under stable task lane"
  sed -n '1,120p' "$TMP/stable-task-successor.out" >&2
  FAILURES=$((FAILURES+1))
fi
if wait "$TASK_LANE_STALE"; then
  echo "FAIL: stale attempt launched after the authorized successor"
  FAILURES=$((FAILURES+1))
elif grep -qi 'stale\|lineage\|attempt' "$TMP/stable-task-stale.out"; then
  echo "ok: stale attempt is rejected after the successor transaction"
else
  echo "FAIL: stale attempt returned an unexpected error"
  sed -n '1,120p' "$TMP/stable-task-stale.out" >&2
  FAILURES=$((FAILURES+1))
fi
check "successor retains the stable task capability pointer" \
  python3 - "$PWD" "$TASK_LANE_TEAM" "$TASK_LANE_TASK" <<'PY'
import json
from pathlib import Path
import subprocess
import sys

repo, team, task = sys.argv[1:]
common = Path(subprocess.check_output(
    ["git", "-C", repo, "rev-parse", "--git-common-dir"], text=True
).strip())
if not common.is_absolute():
    common = Path(repo, common)
broker = common.resolve() / "startup-factory-broker"
records = broker / "outbox-capabilities"
matches = []
for pointer in (broker / "outbox-active").glob("*.id"):
    capability = pointer.read_text(encoding="ascii").strip()
    record = json.loads((records / (capability + ".json")).read_text())
    if (record.get("team") == team and record.get("executionKind") == "task"
            and record.get("taskId") == task):
        matches.append(record)
assert len(matches) == 1, matches
assert matches[0]["attempt"] == 2, matches
PY
"$LAUNCH" stop-task "$TASK_LANE_TEAM" "$TASK_LANE_TASK" >/dev/null
rm -f "$TASK_LANE_BARRIER/ready" "$TMP/stable-task-lane-holder.err"
rmdir "$TASK_LANE_BARRIER/release" "$TASK_LANE_BARRIER"

# Packetization can finish before a dispatcher records a durable human hold.
# The queued start must recheck that hold under the stable task lane before
# minting a capability, even though its earlier preflight was valid.
HOLD_LANE_TEAM=hold-after-packetization
HOLD_LANE_FEATURE=hold-after-packetization-feature.md
HOLD_LANE_TASK="$HOLD_LANE_FEATURE#1"
HOLD_LANE_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$HOLD_LANE_TASK")"
cat > "$HOLD_LANE_FEATURE" <<'EOF'
# Hold lane fixture [Active]

## 1 Fence queued launch [Active]

**Assignee:** backend

The protected hold must win before authority is minted.
EOF
git branch "$HOLD_LANE_TEAM"
prepare_task_claim "$HOLD_LANE_TEAM" "$HOLD_LANE_FEATURE" "$HOLD_LANE_TASK" backend 1
STARTUP_FACTORY_LLM_RUNTIME=other "$LAUNCH" compose-task \
  "$HOLD_LANE_TEAM" "$HOLD_LANE_FEATURE" backend "$HOLD_LANE_TASK" 1 >/dev/null
HOLD_LANE_BARRIER="$(mktemp -d "$LIFECYCLE_ROOT/.hold-task-lane.XXXXXXXX")"
chmod 700 "$HOLD_LANE_BARRIER"
python3 .claude/skills/pm/bin/launch-lane-lock.py \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$HOLD_LANE_TEAM" \
  --category task --instance "$HOLD_LANE_KEY" --barrier "$HOLD_LANE_BARRIER" \
  >"$TMP/hold-task-lane-holder.out" 2>&1 &
HOLD_LANE_HOLDER=$!
for _i in $(seq 1 100); do [ -s "$HOLD_LANE_BARRIER/ready" ] && break; sleep 0.02; done
check "hold race fixture owns the stable task lane" test -s "$HOLD_LANE_BARRIER/ready"
HOLD_LANE_PROMPT="$PWD/.teamwork/$HOLD_LANE_TEAM/prompts/tasks/backend--$HOLD_LANE_KEY--a1.md"
rm -f "$HOLD_LANE_PROMPT"
TEAM_RUNNER=background "$LAUNCH" start-task \
  "$HOLD_LANE_TEAM" "$HOLD_LANE_FEATURE" backend "$HOLD_LANE_TASK" 1 \
  >"$TMP/hold-lane-start.out" 2>&1 &
HOLD_LANE_START=$!
for _i in $(seq 1 200); do [ -s "$HOLD_LANE_PROMPT" ] && break; sleep 0.02; done
check "queued start passes preflight and reaches the held lane" test -s "$HOLD_LANE_PROMPT"
python3 - "$TMP/hold-lane-blocked.json" "$HOLD_LANE_FEATURE" "$HOLD_LANE_TASK" <<'PY'
import json,pathlib,sys
path,feature,task=sys.argv[1:]
pathlib.Path(path).write_text(json.dumps({"featureId":feature,"tasks":[{
  "taskId":task,"title":"fixture","description":"fixture","status":"Blocked",
  "statusRaw":"Blocked","assignee":"backend","blockedBy":[],"labels":[],
  "comments":[],"attachments":[]}]})+"\n")
PY
python3 .claude/skills/pm/bin/task-hold.py sync \
  --repo "$PWD" --workspace "$PWD/.teamwork/$HOLD_LANE_TEAM" \
  --tasks "$TMP/hold-lane-blocked.json" --feature "$HOLD_LANE_FEATURE" \
  --team "$HOLD_LANE_TEAM" --blocked-status Blocked --queued-status Planned \
  --inflight-status Planned --inflight-status Active --inflight-status Review \
  --ignored-labels-json '["human-work"]' >/dev/null
mkdir -m 700 "$HOLD_LANE_BARRIER/release"
wait "$HOLD_LANE_HOLDER"
if wait "$HOLD_LANE_START"; then
  echo "FAIL: queued start minted after a durable task hold"; FAILURES=$((FAILURES+1))
elif grep -q 'became held while waiting' "$TMP/hold-lane-start.out"; then
  echo "ok: queued start rechecks the durable hold under its task lane"
else
  echo "FAIL: queued held start returned the wrong error: $(cat "$TMP/hold-lane-start.out")"; FAILURES=$((FAILURES+1))
fi
check "held queued start mints no publication capability" \
  test "$(active_capability_count "$HOLD_LANE_TEAM" task "$HOLD_LANE_TASK")" -eq 0

# Public worktree creation and compose-task share one lineage-gated mutation
# path. A tampered claim must fail before either entry point creates a task
# branch, worktree, tracker snapshot, packet, prompt, heartbeat, capability,
# or process marker.
COMPOSE_FENCE_TEAM=compose-lineage-fence
COMPOSE_FENCE_FEATURE=compose-lineage-feature.md
COMPOSE_FENCE_TASK="$COMPOSE_FENCE_FEATURE#1"
COMPOSE_FENCE_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$COMPOSE_FENCE_TASK")"
COMPOSE_FENCE_WORKSPACE="$PWD/.teamwork/$COMPOSE_FENCE_TEAM"
COMPOSE_FENCE_BRANCH="agent-task/$COMPOSE_FENCE_TEAM/$COMPOSE_FENCE_KEY"
cat > "$COMPOSE_FENCE_FEATURE" <<'EOF'
# Compose lineage fence fixture [Active]

## 1 Refuse worktree effects [Active]

**Assignee:** backend

Invalid immutable lineage may not create task-local Git or runtime state.
EOF
git branch "$COMPOSE_FENCE_TEAM"
prepare_task_claim \
  "$COMPOSE_FENCE_TEAM" "$COMPOSE_FENCE_FEATURE" "$COMPOSE_FENCE_TASK" backend 1
python3 - "$COMPOSE_FENCE_WORKSPACE/claims/$COMPOSE_FENCE_KEY.json" <<'PY'
import json,sys
path=sys.argv[1]
value=json.load(open(path))
value["claimDigest"]="sha256:"+"0"*64
with open(path,"w",encoding="utf-8") as stream:
    json.dump(value,stream,indent=2)
    stream.write("\n")
PY

if "$LAUNCH" worktree "$COMPOSE_FENCE_TEAM" "$COMPOSE_FENCE_FEATURE" \
    backend "$COMPOSE_FENCE_TASK" 1 >compose-fence-worktree.out 2>&1; then
  echo "FAIL: public worktree accepted mutated claim lineage"; FAILURES=$((FAILURES+1))
elif grep -qi 'lineage\|claim' compose-fence-worktree.out; then
  echo "ok: public worktree rejects mutated lineage before Git effects"
else
  echo "FAIL: public worktree lineage refusal had wrong error: $(cat compose-fence-worktree.out)"; FAILURES=$((FAILURES+1))
fi
check "failed public worktree creates no task branch" \
  bash -c '! git show-ref --verify --quiet "$1"' _ "refs/heads/$COMPOSE_FENCE_BRANCH"
check "failed public worktree creates no worktree root" \
  test ! -e "$COMPOSE_FENCE_WORKSPACE/worktrees"
check "failed public worktree publishes no tracker snapshot" \
  test ! -e "$COMPOSE_FENCE_WORKSPACE/tasks.json"

if STARTUP_FACTORY_LLM_RUNTIME=codex "$LAUNCH" compose-task \
    "$COMPOSE_FENCE_TEAM" "$COMPOSE_FENCE_FEATURE" backend "$COMPOSE_FENCE_TASK" 1 \
    >compose-fence-task.out 2>&1; then
  echo "FAIL: compose-task accepted mutated claim lineage"; FAILURES=$((FAILURES+1))
elif grep -qi 'lineage\|claim' compose-fence-task.out; then
  echo "ok: compose-task rejects mutated lineage before worktree creation"
else
  echo "FAIL: compose-task lineage refusal had wrong error: $(cat compose-fence-task.out)"; FAILURES=$((FAILURES+1))
fi
check "failed compose-task creates no task branch" \
  bash -c '! git show-ref --verify --quiet "$1"' _ "refs/heads/$COMPOSE_FENCE_BRANCH"
check "failed compose-task creates no worktree" \
  test ! -e "$COMPOSE_FENCE_WORKSPACE/worktrees/backend#1-$COMPOSE_FENCE_KEY"
check "failed compose-task creates no packet artifacts" \
  test ! -e "$COMPOSE_FENCE_WORKSPACE/artifacts"
check "failed compose-task creates no prompt" \
  test ! -e "$COMPOSE_FENCE_WORKSPACE/prompts/tasks"
check "failed compose-task creates no heartbeat" \
  test ! -e "$COMPOSE_FENCE_WORKSPACE/heartbeats"
check "failed compose-task creates no process marker" \
  test ! -e "$COMPOSE_FENCE_WORKSPACE/pids/tasks"
check "failed compose-task mints no capability" \
  test "$(active_capability_count "$COMPOSE_FENCE_TEAM" task "$COMPOSE_FENCE_TASK")" -eq 0

# An unchanged durable claim is valid for same-generation packet replay, but it
# is not authority to mint the next execution generation. Exercise the shared
# preflight through every public entry point with both live and dead prior
# generations; only restart-task may supply the internal broker-restart flag.
GENERATION_FENCE_TEAM=generation-advance-fence
GENERATION_FENCE_FEATURE=generation-advance-feature.md
GENERATION_FENCE_WORKSPACE="$PWD/.teamwork/$GENERATION_FENCE_TEAM"
cat > "$GENERATION_FENCE_FEATURE" <<'EOF'
# Generation advance fence fixture [Active]

## 1 Live worktree refusal [Active]

**Assignee:** backend

An unchanged claim cannot create the next worktree while attempt one is live.

## 2 Live compose refusal [Active]

**Assignee:** backend

An unchanged claim cannot compose the next packet while attempt one is live.

## 3 Live start refusal [Active]

**Assignee:** backend

An unchanged claim cannot start the next worker while attempt one is live.

## 4 Dead worktree refusal [Active]

**Assignee:** backend

An unchanged claim cannot create the next worktree after attempt one exits.

## 5 Dead compose refusal [Active]

**Assignee:** backend

An unchanged claim cannot compose the next packet after attempt one exits.

## 6 Dead start refusal [Active]

**Assignee:** backend

An unchanged claim cannot start the next worker after attempt one exits.

## 7 Authorized broker restart [Active]

**Assignee:** backend

An exact protected restart grant may advance one unchanged-claim generation.
EOF
git branch "$GENERATION_FENCE_TEAM"

expect_generation_advance_rejected() { # label command...
  local generation_label="$1" generation_output
  shift
  generation_output="$TMP/generation-advance-$generation_label.out"
  if "$@" >"$generation_output" 2>&1; then
    echo "FAIL: $generation_label accepted an unchanged-claim generation advance"
    FAILURES=$((FAILURES+1))
  elif grep -q 'unchanged-claim generation advance requires an authenticated broker restart' \
      "$generation_output"; then
    echo "ok: $generation_label rejects unchanged-claim generation advance"
  else
    echo "FAIL: $generation_label reported the wrong refusal: $(cat "$generation_output")"
    FAILURES=$((FAILURES+1))
  fi
}

exercise_generation_fence() { # liveness entry-point task-number
  local generation_liveness="$1" generation_entry="$2" generation_number="$3"
  local generation_task generation_key generation_instance generation_execution generation_ready
  local generation_capabilities_before
  generation_task="$GENERATION_FENCE_FEATURE#$generation_number"
  generation_key="$(python3 .claude/skills/pm/bin/runtime-state.py key "$generation_task")"
  generation_instance="backend--$generation_key--a1"
  generation_execution="$GENERATION_FENCE_WORKSPACE/executions/$generation_key.json"
  prepare_task_claim \
    "$GENERATION_FENCE_TEAM" "$GENERATION_FENCE_FEATURE" "$generation_task" backend 1
  TEAM_RUNNER=background "$LAUNCH" start-task \
    "$GENERATION_FENCE_TEAM" "$GENERATION_FENCE_FEATURE" backend "$generation_task" 1 \
    >/dev/null
  if [ "$generation_liveness" = live ]; then
    generation_ready="$LIFECYCLE_READY_DIR/$generation_instance.ready"
    check "$generation_entry fence fixture installs its signal handlers" \
      wait_for_witness_ready "$generation_ready"
    require_live_task "$generation_entry fence fixture is live" \
      "$GENERATION_FENCE_TEAM" backend "$generation_task" 1 "$generation_instance"
  else
    check "$generation_entry fence fixture is dead" wait_task_exit \
      "$GENERATION_FENCE_TEAM" backend "$generation_task" 1
  fi
  generation_capabilities_before="$(
    active_capability_count "$GENERATION_FENCE_TEAM" task "$generation_task"
  )"
  case "$generation_entry" in
    worktree)
      expect_generation_advance_rejected "$generation_liveness-worktree" \
        "$LAUNCH" worktree "$GENERATION_FENCE_TEAM" "$GENERATION_FENCE_FEATURE" \
          backend "$generation_task" 2
      ;;
    compose-task)
      expect_generation_advance_rejected "$generation_liveness-compose-task" \
        env STARTUP_FACTORY_LLM_RUNTIME=codex "$LAUNCH" compose-task \
          "$GENERATION_FENCE_TEAM" "$GENERATION_FENCE_FEATURE" backend \
          "$generation_task" 2
      ;;
    start-task)
      expect_generation_advance_rejected "$generation_liveness-start-task" \
        env TEAM_RUNNER=background "$LAUNCH" start-task \
          "$GENERATION_FENCE_TEAM" "$GENERATION_FENCE_FEATURE" backend \
          "$generation_task" 2
      ;;
    *) echo "FAIL: unknown generation fence entry point"; FAILURES=$((FAILURES+1)) ;;
  esac
  check "$generation_liveness $generation_entry preserves attempt-one execution" \
    python3 -c 'import json,sys; raise SystemExit(json.load(open(sys.argv[1]))["attempt"] != 1)' \
      "$generation_execution"
  check "$generation_liveness $generation_entry preserves attempt-one worktree" \
    test -d "$GENERATION_FENCE_WORKSPACE/worktrees/backend#1-$generation_key"
  check "$generation_liveness $generation_entry creates no attempt-two worktree" \
    test ! -e "$GENERATION_FENCE_WORKSPACE/worktrees/backend#2-$generation_key"
  check "$generation_liveness $generation_entry creates no attempt-two packet" \
    test ! -e "$GENERATION_FENCE_WORKSPACE/artifacts/$generation_key/attempt-2"
  check "$generation_liveness $generation_entry mints no replacement capability" \
    test "$(active_capability_count "$GENERATION_FENCE_TEAM" task "$generation_task")" \
      -eq "$generation_capabilities_before"
  if [ "$generation_liveness" = live ]; then
    require_live_task "$generation_entry refusal leaves attempt one live" \
      "$GENERATION_FENCE_TEAM" backend "$generation_task" 1 "$generation_instance"
    "$LAUNCH" stop-task "$GENERATION_FENCE_TEAM" "$generation_task" >/dev/null
  else
    check "$generation_entry refusal preserves dead lifecycle evidence" \
      test "$(record_count "$GENERATION_FENCE_TEAM" "$generation_instance")" -eq 1
  fi
}

GENERATION_LIVE_COMMAND="\"$LIFECYCLE_WITNESS $LIFECYCLE_READY_DIR $LIFECYCLE_SIGNAL_DIR term-exit\""
set_config_line BACKEND_CMD "$GENERATION_LIVE_COMMAND"
for task_command_key in TASK_FAST_CMD TASK_STANDARD_CMD TASK_STRONG_CMD; do
  set_config_line "$task_command_key" "$GENERATION_LIVE_COMMAND"
done
exercise_generation_fence live worktree 1
exercise_generation_fence live compose-task 2
exercise_generation_fence live start-task 3
set_config_line BACKEND_CMD '"true"'
for task_command_key in TASK_FAST_CMD TASK_STANDARD_CMD TASK_STRONG_CMD; do
  set_config_line "$task_command_key" '"true"'
done
exercise_generation_fence dead worktree 4
exercise_generation_fence dead compose-task 5
exercise_generation_fence dead start-task 6
GENERATION_DIRECT_TASK="$GENERATION_FENCE_FEATURE#4"
GENERATION_DIRECT_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$GENERATION_DIRECT_TASK")"
expect_generation_advance_rejected "dead-direct-task-packet" \
  .claude/skills/pm/bin/task-packet.sh \
    "$GENERATION_FENCE_TEAM" "$GENERATION_FENCE_FEATURE" "$GENERATION_DIRECT_TASK" \
    backend 2 \
    "$GENERATION_FENCE_WORKSPACE/worktrees/backend#2-$GENERATION_DIRECT_KEY" \
    "agent-task/$GENERATION_FENCE_TEAM/$GENERATION_DIRECT_KEY"
check "direct task-packet preserves attempt-one execution" \
  python3 -c 'import json,sys; raise SystemExit(json.load(open(sys.argv[1]))["attempt"] != 1)' \
    "$GENERATION_FENCE_WORKSPACE/executions/$GENERATION_DIRECT_KEY.json"
check "direct task-packet creates no attempt-two artifacts" \
  test ! -e "$GENERATION_FENCE_WORKSPACE/artifacts/$GENERATION_DIRECT_KEY/attempt-2"
GENERATION_RESTART_TASK="$GENERATION_FENCE_FEATURE#7"
GENERATION_RESTART_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$GENERATION_RESTART_TASK")"
GENERATION_RESTART_INSTANCE="backend--$GENERATION_RESTART_KEY--a1"
GENERATION_RESTART_CONTROL=control-77777777777777777777777777777777
prepare_task_claim \
  "$GENERATION_FENCE_TEAM" "$GENERATION_FENCE_FEATURE" "$GENERATION_RESTART_TASK" backend 1
TEAM_RUNNER=background "$LAUNCH" start-task \
  "$GENERATION_FENCE_TEAM" "$GENERATION_FENCE_FEATURE" backend \
  "$GENERATION_RESTART_TASK" 1 >/dev/null
check "broker restart fixture attempt exits" wait_task_exit \
  "$GENERATION_FENCE_TEAM" backend "$GENERATION_RESTART_TASK" 1
GENERATION_RESTART_RECORD="$(
  record_for "$GENERATION_FENCE_TEAM" "$GENERATION_RESTART_INSTANCE"
)"
GENERATION_RESTART_CREATED="$(
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["createdAt"])' \
    "$GENERATION_RESTART_RECORD"
)"
python3 .claude/skills/pm/bin/control-grant.py issue \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" \
  --team "$GENERATION_FENCE_TEAM" --feature "$GENERATION_FENCE_FEATURE" \
  --action restart-task --target "$GENERATION_RESTART_TASK" --attempt 1 \
  --generation "$GENERATION_RESTART_CREATED" \
  --control-id "$GENERATION_RESTART_CONTROL" --reason authorized >/dev/null
GENERATION_RESTART_OUTPUT="$(
  TEAM_RUNNER=background STARTUP_FACTORY_CONTROL_BROKER=1 \
    STARTUP_FACTORY_CONTROL_REASON=authorized \
    STARTUP_FACTORY_EXPECTED_LIFECYCLE_CREATED_AT="$GENERATION_RESTART_CREATED" \
    "$LAUNCH" restart-task "$GENERATION_FENCE_TEAM" "$GENERATION_FENCE_FEATURE" \
      "$GENERATION_RESTART_TASK" 1 "$GENERATION_RESTART_CONTROL"
)"
if printf '%s\n' "$GENERATION_RESTART_OUTPUT" | grep -q 'restarted task.*attempt 2'; then
  echo "ok: exact protected broker evidence advances one unchanged-claim generation"
else
  echo "FAIL: exact protected broker restart did not advance: $GENERATION_RESTART_OUTPUT"
  FAILURES=$((FAILURES+1))
fi
check "broker restart publishes attempt-two execution" \
  python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); raise SystemExit(value["attempt"] != 2 or value["claimLineage"]["claimAttempt"] != 1)' \
    "$GENERATION_FENCE_WORKSPACE/executions/$GENERATION_RESTART_KEY.json"
check "broker restart publishes attempt-two packet" \
  test -f "$GENERATION_FENCE_WORKSPACE/artifacts/$GENERATION_RESTART_KEY/attempt-2/task-packet.json"
check "broker restart replacement exits" wait_task_exit \
  "$GENERATION_FENCE_TEAM" backend "$GENERATION_RESTART_TASK" 2
for task_command_key in TASK_FAST_CMD TASK_STANDARD_CMD TASK_STRONG_CMD; do
  set_config_line "$task_command_key" null
done
set_config_line BACKEND_CMD '"sleep 120"'

# -- claim-lineage fences precede worktree retirement, revocation, and restart --
LINEAGE_FENCE_TEAM=lineage-fence
LINEAGE_FENCE_FEATURE=lineage-fence-feature.md
LINEAGE_FENCE_TASK="$LINEAGE_FENCE_FEATURE#1"
LINEAGE_FENCE_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$LINEAGE_FENCE_TASK")"
LINEAGE_FENCE_INSTANCE="backend--$LINEAGE_FENCE_KEY--a1"
LINEAGE_FENCE_WORKSPACE="$PWD/.teamwork/$LINEAGE_FENCE_TEAM"
LINEAGE_FENCE_WORKTREE="$LINEAGE_FENCE_WORKSPACE/worktrees/backend#1-$LINEAGE_FENCE_KEY"
LINEAGE_FENCE_CONTROL=control-88888888888888888888888888888888
cat > "$LINEAGE_FENCE_FEATURE" <<'EOF'
# Lineage fence fixture [Active]

## 1 Refuse mutation before effects [Active]

**Assignee:** backend

track: backend
parallel-safe: true
files: src/lineage-fence.txt
resources: lineage:fence

Invalid immutable lineage must stop every relaunch/restart side effect.
EOF
git branch "$LINEAGE_FENCE_TEAM"
sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="true"|' "$CFG_LIFECYCLE"
prepare_task_claim \
  "$LINEAGE_FENCE_TEAM" "$LINEAGE_FENCE_FEATURE" "$LINEAGE_FENCE_TASK" backend 1
TEAM_RUNNER=background "$LAUNCH" start-task \
  "$LINEAGE_FENCE_TEAM" "$LINEAGE_FENCE_FEATURE" backend "$LINEAGE_FENCE_TASK" 1 >/dev/null
check "lineage-fence fixture attempt exits" wait_task_exit \
  "$LINEAGE_FENCE_TEAM" backend "$LINEAGE_FENCE_TASK" 1
LINEAGE_FENCE_RECORD="$(record_for "$LINEAGE_FENCE_TEAM" "$LINEAGE_FENCE_INSTANCE")"
LINEAGE_FENCE_GENERATION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["createdAt"])' "$LINEAGE_FENCE_RECORD")"
prepare_task_claim \
  "$LINEAGE_FENCE_TEAM" "$LINEAGE_FENCE_FEATURE" "$LINEAGE_FENCE_TASK" backend 2
python3 - "$LINEAGE_FENCE_WORKSPACE/executions/$LINEAGE_FENCE_KEY.json" <<'PY'
import json,sys
path=sys.argv[1]
value=json.load(open(path))
value["lineageDigest"]="sha256:"+"0"*64
with open(path,"w",encoding="utf-8") as stream:
    json.dump(value,stream,indent=2)
    stream.write("\n")
PY
LINEAGE_FENCE_CAPABILITIES_BEFORE="$(
  active_capability_count "$LINEAGE_FENCE_TEAM" task "$LINEAGE_FENCE_TASK"
)"

if TEAM_RUNNER=background "$LAUNCH" start-task \
    "$LINEAGE_FENCE_TEAM" "$LINEAGE_FENCE_FEATURE" backend "$LINEAGE_FENCE_TASK" 2 \
    >lineage-fence-start.out 2>&1; then
  echo "FAIL: start-task accepted mutated claim lineage"; FAILURES=$((FAILURES+1))
elif grep -qi 'lineage\|claim' lineage-fence-start.out; then
  echo "ok: start-task rejects mutated lineage before attempt retirement"
else
  echo "FAIL: start-task lineage refusal had wrong error: $(cat lineage-fence-start.out)"; FAILURES=$((FAILURES+1))
fi
check "failed lineage start preserves prior worktree" test -d "$LINEAGE_FENCE_WORKTREE"
check "failed lineage start creates no replacement worktree" \
  test ! -e "$LINEAGE_FENCE_WORKSPACE/worktrees/backend#2-$LINEAGE_FENCE_KEY"
check "failed lineage start creates no replacement packet" \
  test ! -e "$LINEAGE_FENCE_WORKSPACE/artifacts/$LINEAGE_FENCE_KEY/attempt-2"
check "failed lineage start creates no replacement heartbeat" \
  test ! -e "$LINEAGE_FENCE_WORKSPACE/heartbeats/backend--$LINEAGE_FENCE_KEY--a2"
check "failed lineage start mints no replacement capability" \
  test "$(active_capability_count "$LINEAGE_FENCE_TEAM" task "$LINEAGE_FENCE_TASK")" \
    -eq "$LINEAGE_FENCE_CAPABILITIES_BEFORE"

python3 .claude/skills/pm/bin/control-grant.py issue \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" \
  --team "$LINEAGE_FENCE_TEAM" --feature "$LINEAGE_FENCE_FEATURE" \
  --action restart-task --target "$LINEAGE_FENCE_TASK" --attempt 1 \
  --generation "$LINEAGE_FENCE_GENERATION" --control-id "$LINEAGE_FENCE_CONTROL" \
  --reason authorized >/dev/null
if TEAM_RUNNER=background STARTUP_FACTORY_CONTROL_BROKER=1 \
    STARTUP_FACTORY_CONTROL_REASON=authorized \
    STARTUP_FACTORY_EXPECTED_LIFECYCLE_CREATED_AT="$LINEAGE_FENCE_GENERATION" \
    "$LAUNCH" restart-task "$LINEAGE_FENCE_TEAM" "$LINEAGE_FENCE_FEATURE" \
      "$LINEAGE_FENCE_TASK" 1 "$LINEAGE_FENCE_CONTROL" \
    >lineage-fence-restart.out 2>&1; then
  echo "FAIL: restart-task accepted mutated claim lineage"; FAILURES=$((FAILURES+1))
elif grep -qi 'lineage\|claim' lineage-fence-restart.out; then
  echo "ok: restart-task rejects mutated lineage before destructive effects"
else
  echo "FAIL: restart-task lineage refusal had wrong error: $(cat lineage-fence-restart.out)"; FAILURES=$((FAILURES+1))
fi
check "failed lineage restart does not revoke prior capability" \
  test "$(active_capability_count "$LINEAGE_FENCE_TEAM" task "$LINEAGE_FENCE_TASK")" \
    -eq "$LINEAGE_FENCE_CAPABILITIES_BEFORE"
check "failed lineage restart does not forget lifecycle generation" \
  test "$(record_count "$LINEAGE_FENCE_TEAM" "$LINEAGE_FENCE_INSTANCE")" -eq 1
check "failed lineage restart preserves prior worktree" test -d "$LINEAGE_FENCE_WORKTREE"
check "failed lineage restart creates no replacement worktree" \
  test ! -e "$LINEAGE_FENCE_WORKSPACE/worktrees/backend#2-$LINEAGE_FENCE_KEY"
sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="sleep 120"|' "$CFG_LIFECYCLE"

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
  tmux -S "$TMUX_STOP_SOCKET" new-session -d -s "$TMUX_STOP_SESSION" -n _hub
  printf -v _tmux_python_q '%q' "$(command -v python3)"
  printf -v _tmux_wrapper_q '%q' "$TMUX_GROUP_WRAPPER"
  printf -v _tmux_ignorer_q '%q' "$TERM_IGNORER"
  printf -v _tmux_ready_q '%q' "$TMUX_STOP_READY"
  TMUX_STOP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  TMUX_STOP_TAG="$(printf '%s' "$TMUX_STOP_TOKEN" | python3 -c 'import hashlib,sys; print("sf-" + hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
  tmux_stop_pane_info="$(tmux new-window -d -P -F '#{pane_id}|#{pane_pid}' \
    -t "$TMUX_STOP_SESSION" -n "$TMUX_STOP_INSTANCE" \
    ": sfgen-$TMUX_STOP_TAG; exec $_tmux_python_q $_tmux_wrapper_q $_tmux_ignorer_q $_tmux_ready_q")"
  TMUX_STOP_PANE="${tmux_stop_pane_info%%|*}"
  TMUX_STOP_PANE_PID="${tmux_stop_pane_info#*|}"
  for _i in $(seq 1 100); do [ -s "$TMUX_STOP_READY" ] && break; sleep 0.02; done
  read -r TMUX_STOP_LEADER_PID TMUX_STOP_CHILD_PID < "$TMUX_STOP_READY"
  printf '%s\n' "$TMUX_STOP_TOKEN" | python3 .claude/skills/pm/bin/process-lifecycle.py register \
    --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$TMUX_STOP_TEAM" \
    --category task --instance "$TMUX_STOP_INSTANCE" --kind tmux --pid "$TMUX_STOP_LEADER_PID" \
    --tmux-session "$TMUX_STOP_SESSION" --tmux-window "$TMUX_STOP_INSTANCE" \
    --tmux-pane "$TMUX_STOP_PANE" --tmux-pane-pid "$TMUX_STOP_PANE_PID" \
    --launch-token-stdin >/dev/null
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
  if tmux list-panes -a -F '#{pane_id}' | grep -Fqx "$TMUX_STOP_PANE"; then
    echo "FAIL: tmux stop-task left its verified pane live"; FAILURES=$((FAILURES+1))
  else
    echo "ok: tmux stop-task retires its verified pane"
  fi
  # A restarted tmux server may reuse the exact pane id and window name while
  # the authenticated child group survives.  Stop must still contain that
  # group, but must leave the successor server's unrelated pane intact.
  tmux kill-server
  tmux -S "$TMUX_STOP_SOCKET" new-session -d -s "$TMUX_STOP_SESSION" -n _hub
  TMUX_RESTART_TASK='T-tmux-restarted-server'
  TMUX_RESTART_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$TMUX_RESTART_TASK")"
  TMUX_RESTART_INSTANCE="backend--$TMUX_RESTART_KEY--a1"
  TMUX_RESTART_READY="$TMP/tmux-restart-ready"
  printf -v _tmux_restart_ready_q '%q' "$TMUX_RESTART_READY"
  TMUX_RESTART_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  TMUX_RESTART_TAG="$(printf '%s' "$TMUX_RESTART_TOKEN" | python3 -c 'import hashlib,sys; print("sf-" + hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
  tmux_restart_info="$(tmux new-window -d -P -F '#{pane_id}|#{pane_pid}' \
    -t "$TMUX_STOP_SESSION" -n "$TMUX_RESTART_INSTANCE" \
    ": sfgen-$TMUX_RESTART_TAG; exec $_tmux_python_q $_tmux_wrapper_q $_tmux_ignorer_q $_tmux_restart_ready_q")"
  TMUX_RESTART_PANE="${tmux_restart_info%%|*}"
  TMUX_RESTART_PANE_PID="${tmux_restart_info#*|}"
  for _i in $(seq 1 100); do [ -s "$TMUX_RESTART_READY" ] && break; sleep 0.02; done
  read -r TMUX_RESTART_LEADER_PID TMUX_RESTART_CHILD_PID < "$TMUX_RESTART_READY"
  printf '%s\n' "$TMUX_RESTART_TOKEN" | python3 .claude/skills/pm/bin/process-lifecycle.py register \
    --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$TMUX_STOP_TEAM" \
    --category task --instance "$TMUX_RESTART_INSTANCE" --kind tmux --pid "$TMUX_RESTART_LEADER_PID" \
    --tmux-session "$TMUX_STOP_SESSION" --tmux-window "$TMUX_RESTART_INSTANCE" \
    --tmux-pane "$TMUX_RESTART_PANE" --tmux-pane-pid "$TMUX_RESTART_PANE_PID" \
    --launch-token-stdin >/dev/null
  mkdir -p ".teamwork/$TMUX_STOP_TEAM/pids/tasks"
  printf 'managed\n' > ".teamwork/$TMUX_STOP_TEAM/pids/tasks/$TMUX_RESTART_INSTANCE.pid"
  tmux kill-server
  tmux -S "$TMUX_STOP_SOCKET" new-session -d -s "$TMUX_STOP_SESSION" -n _hub
  TMUX_RESTART_SUCCESSOR="$(tmux new-window -d -P -F '#{pane_id}' \
    -t "$TMUX_STOP_SESSION" -n "$TMUX_RESTART_INSTANCE" "sleep 60")"
  check "tmux restart reuses the recorded pane id" test "$TMUX_RESTART_SUCCESSOR" = "$TMUX_RESTART_PANE"
  "$LAUNCH" stop-task "$TMUX_STOP_TEAM" "$TMUX_RESTART_TASK" >/dev/null
  for _i in $(seq 1 80); do
    if ! kill -0 "$TMUX_RESTART_LEADER_PID" 2>/dev/null \
        && ! kill -0 "$TMUX_RESTART_CHILD_PID" 2>/dev/null; then break; fi
    sleep 0.05
  done
  check "tmux restart stop contains authenticated surviving group" \
    bash -c "! kill -0 '$TMUX_RESTART_LEADER_PID' 2>/dev/null && ! kill -0 '$TMUX_RESTART_CHILD_PID' 2>/dev/null"
  check "tmux restart stop retires exact lifecycle record" \
    test "$(record_count "$TMUX_STOP_TEAM" "$TMUX_RESTART_INSTANCE")" -eq 0
  check "tmux restart stop preserves successor pane" \
    bash -c 'tmux list-panes -a -F "#{pane_id}" | grep -Fqx "$1"' _ "$TMUX_RESTART_SUCCESSOR"
  tmux kill-server 2>/dev/null || true
  if [ "$TMUX_STOP_HAD_PREVIOUS" = x ]; then export TMUX="$TMUX_STOP_PREVIOUS"; else unset TMUX; fi
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

AUTH_READY_DIR="$TMP/lifecycle-auth-ready"
AUTH_SIGNAL_DIR="$TMP/lifecycle-auth-signals"
mkdir -p "$AUTH_READY_DIR" "$AUTH_SIGNAL_DIR"
set_config_line BACKEND_CMD "\"$LIFECYCLE_WITNESS $AUTH_READY_DIR $AUTH_SIGNAL_DIR ignore\""
TEAM_RUNNER=background "$LAUNCH" start lifecycle-auth FEAT-LIFE backend >/dev/null
auth_record="$(record_for lifecycle-auth backend)"
auth_agent_pid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' "$auth_record")"
check "protected lifecycle signal witness becomes ready before tamper" wait_for_witness_ready \
  "$AUTH_READY_DIR/gate:backend.ready"
check "protected lifecycle fixture is live before tamper" kill -0 "$auth_agent_pid"
STARTUP_FACTORY_INSTANCE=auth-victim \
  "$LIFECYCLE_WITNESS" "$AUTH_READY_DIR" "$AUTH_SIGNAL_DIR" ignore &
auth_victim_pid=$!
check "substituted-process signal witness becomes ready before tamper" wait_for_witness_ready \
  "$AUTH_READY_DIR/auth-victim.ready"
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
check "tampered protected record sends no observable signal to original group" \
  signal_witness_stays_quiet "$AUTH_SIGNAL_DIR" 'gate:backend'
check "tampered protected record leaves the original fixture group live" \
  process_group_is_live "$auth_agent_pid"
check "tampered protected record does not signal substituted process" kill -0 "$auth_victim_pid"
check "tampered protected record sends no observable signal to substituted process" \
  signal_witness_stays_quiet "$AUTH_SIGNAL_DIR" auth-victim
kill -KILL -- "-$auth_agent_pid" 2>/dev/null || true
kill -KILL "$auth_victim_pid" 2>/dev/null || true
wait "$auth_agent_pid" 2>/dev/null || true
wait "$auth_victim_pid" 2>/dev/null || true
rm -f "$auth_record"
set_config_line BACKEND_CMD '"sleep 120"'

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
if TEAM_RUNNER=background "$LAUNCH" start lifecycle-identity FEAT-LIFE backend \
    >lifecycle-identity-relaunch.out 2>&1; then
  echo "FAIL: start replaced an identity-mismatched lifecycle generation"; FAILURES=$((FAILURES+1))
elif grep -q 'identity-mismatch\|identity mismatch' lifecycle-identity-relaunch.out; then
  echo "ok: start refuses to replace identity-mismatched lifecycle evidence"
else
  echo "FAIL: identity-mismatched start returned wrong error: $(cat lifecycle-identity-relaunch.out)"; FAILURES=$((FAILURES+1))
fi
check "failed identity-mismatched start leaves the prior process untouched" kill -0 "$identity_agent_pid"
check "failed identity-mismatched start preserves the prior lifecycle record" \
  test "$(record_count lifecycle-identity backend)" -eq 1
kill "$identity_agent_pid" 2>/dev/null || true
wait "$identity_agent_pid" 2>/dev/null || true
rm -f "$identity_record"

sed_i 's|^BACKEND_CMD=.*|BACKEND_CMD="cat {prompt_file} > backend-received.txt"|' "$CFG_LIFECYCLE"

# -- restart-role: one control has exactly one protected replacement generation --
RESTART_ROLE_TEAM=restart-role-replay
RESTART_ROLE_FEATURE=FEAT-RESTART-ROLE
RESTART_ROLE_CONTROL="control-44444444444444444444444444444444"
sed_i 's|^TEAM_LEAD_CMD=.*|TEAM_LEAD_CMD="sleep 30"|' "$CFG_LIFECYCLE"
TEAM_RUNNER=background "$LAUNCH" start "$RESTART_ROLE_TEAM" "$RESTART_ROLE_FEATURE" team-lead >/dev/null
restart_role_original_record="$(record_for "$RESTART_ROLE_TEAM" team-lead)"
restart_role_original_created="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["createdAt"])' "$restart_role_original_record")"
sed_i 's|^TEAM_LEAD_CMD=.*|TEAM_LEAD_CMD="true"|' "$CFG_LIFECYCLE"
python3 .claude/skills/pm/bin/control-grant.py issue \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" \
  --team "$RESTART_ROLE_TEAM" --feature "$RESTART_ROLE_FEATURE" \
  --action restart-role --target team-lead --attempt 0 --generation "$restart_role_original_created" \
  --control-id "$RESTART_ROLE_CONTROL" --reason authorized >/dev/null
restart_role_first="$(TEAM_RUNNER=background STARTUP_FACTORY_CONTROL_BROKER=1 STARTUP_FACTORY_CONTROL_REASON=authorized \
  "$LAUNCH" restart-role "$RESTART_ROLE_TEAM" "$RESTART_ROLE_FEATURE" team-lead \
  "$restart_role_original_created" "$RESTART_ROLE_CONTROL")"
echo "$restart_role_first" | grep -q 'restarted role team-lead' \
  && echo "ok: restart-role launches one authorized replacement" \
  || { echo "FAIL: restart-role did not launch its replacement: $restart_role_first"; FAILURES=$((FAILURES+1)); }
restart_role_policy="$(python3 .claude/skills/pm/bin/restart-policy.py check \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" \
  --team "$RESTART_ROLE_TEAM" --feature "$RESTART_ROLE_FEATURE" \
  --category gate --target team-lead --attempt 0 --generation "$restart_role_original_created" \
  --control-id "$RESTART_ROLE_CONTROL" --reason authorized)"
restart_role_replacement_created="$(printf '%s' "$restart_role_policy" | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["completedGeneration"])')"
check "restart-role replacement has a distinct lifecycle generation" \
  test "$restart_role_replacement_created" != "$restart_role_original_created"
for _i in $(seq 1 40); do
  restart_role_replacement_record="$(record_for "$RESTART_ROLE_TEAM" team-lead 2>/dev/null || true)"
  if [ -n "$restart_role_replacement_record" ] && python3 -c \
      'import json,sys; value=json.load(open(sys.argv[1])); raise SystemExit(value["kind"] != "completed-background")' \
      "$restart_role_replacement_record"; then
    break
  fi
  sleep 0.05
done
check "restart-role short-lived replacement retires process-group authority" \
  python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["kind"] == "completed-background"; assert value["createdAt"] == sys.argv[2]' \
    "$restart_role_replacement_record" "$restart_role_replacement_created"

restart_role_replay="$(TEAM_RUNNER=background STARTUP_FACTORY_CONTROL_BROKER=1 STARTUP_FACTORY_CONTROL_REASON=authorized \
  "$LAUNCH" restart-role "$RESTART_ROLE_TEAM" "$RESTART_ROLE_FEATURE" team-lead \
  "$restart_role_original_created" "$RESTART_ROLE_CONTROL")"
echo "$restart_role_replay" | grep -q 'already completed with protected replacement generation' \
  && echo "ok: restart-role dead-replacement replay converges from protected completion" \
  || { echo "FAIL: restart-role dead-replacement replay did not converge: $restart_role_replay"; FAILURES=$((FAILURES+1)); }
restart_role_replay_policy="$(python3 .claude/skills/pm/bin/restart-policy.py check \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" \
  --team "$RESTART_ROLE_TEAM" --feature "$RESTART_ROLE_FEATURE" \
  --category gate --target team-lead --attempt 0 --generation "$restart_role_original_created" \
  --control-id "$RESTART_ROLE_CONTROL" --reason authorized)"
check "restart-role replay preserves the exact replacement generation" \
  test "$(printf '%s' "$restart_role_replay_policy" | python3 -c 'import json,sys; print(json.load(sys.stdin)["completedGeneration"])')" = "$restart_role_replacement_created"
check "restart-role policy records one spend and the exact completed generation" python3 -c \
  'import json,sys; p=json.loads(sys.argv[1]); assert p["authorizedCount"] == 1; assert p["completedControlId"] == sys.argv[2]; assert p["completedGeneration"] == sys.argv[3]' \
  "$restart_role_policy" "$RESTART_ROLE_CONTROL" "$restart_role_replacement_created"

# The old control receipt must still prevent a third launch after a later queue
# activation reaps the completed, non-authoritative lifecycle evidence.
python3 .claude/skills/pm/bin/process-lifecycle.py forget \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$RESTART_ROLE_TEAM" \
  --category gate --instance team-lead \
  --expected-created-at "$restart_role_replacement_created" >/dev/null
restart_role_absent_replay="$(TEAM_RUNNER=background STARTUP_FACTORY_CONTROL_BROKER=1 STARTUP_FACTORY_CONTROL_REASON=authorized \
  "$LAUNCH" restart-role "$RESTART_ROLE_TEAM" "$RESTART_ROLE_FEATURE" team-lead \
  "$restart_role_original_created" "$RESTART_ROLE_CONTROL")"
echo "$restart_role_absent_replay" | grep -q 'already completed with protected replacement generation' \
  && echo "ok: restart-role replay cannot relaunch after completed replacement record is reaped" \
  || { echo "FAIL: absent-record restart-role replay did not use protected completion: $restart_role_absent_replay"; FAILURES=$((FAILURES+1)); }
check "restart-role completed-control replay remains at-most-once with no lifecycle record" \
  test "$(record_count "$RESTART_ROLE_TEAM" team-lead)" -eq 0

# -- task-scoped stop: exact collision-safe task selection, stale retirement, idempotence --
CROSS_WORKTREE_TEAM=cross-worktree-stop
CROSS_WORKTREE_TASK='T-linked-capability'
CROSS_WORKTREE_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$CROSS_WORKTREE_TASK")"
CROSS_WORKTREE_INSTANCE="backend--$CROSS_WORKTREE_KEY--a1"
CROSS_WORKTREE_PID="$(spawn_lifecycle_sleep)"
register_lifecycle_process \
  "$CROSS_WORKTREE_TEAM" task "$CROSS_WORKTREE_INSTANCE" "$CROSS_WORKTREE_PID"
mkdir -p ".teamwork/$CROSS_WORKTREE_TEAM"
CROSS_WORKTREE_CAPABILITY="$(python3 .claude/skills/pm/bin/outbox_capability.py mint \
  --repo "$PWD" --workspace "$PWD/.teamwork/$CROSS_WORKTREE_TEAM" \
  --team "$CROSS_WORKTREE_TEAM" --feature FEAT-LINKED --role backend \
  --kind task --task "$CROSS_WORKTREE_TASK" --attempt 1 \
  --instance "$CROSS_WORKTREE_INSTANCE")"
CROSS_WORKTREE_CAPABILITY_ID="$(printf '%s' "$CROSS_WORKTREE_CAPABILITY" | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
CROSS_WORKTREE_LAUNCH="$PWD/$LAUNCH"
CROSS_WORKTREE_CHECKOUT="$(cd "$T42_WT" && pwd -P)"
if (cd "$CROSS_WORKTREE_CHECKOUT" && \
    "$CROSS_WORKTREE_LAUNCH" stop-task \
      "$CROSS_WORKTREE_TEAM" "$CROSS_WORKTREE_TASK" >/dev/null); then
  echo "ok: linked-worktree stop authenticates and stops the shared lifecycle generation"
else
  echo "FAIL: linked-worktree stop could not fence the sibling checkout generation"
  FAILURES=$((FAILURES+1))
fi
for _i in $(seq 1 40); do
  kill -0 "$CROSS_WORKTREE_PID" 2>/dev/null || break
  sleep 0.05
done
check "linked-worktree stop terminates the original checkout process" \
  bash -c "! kill -0 '$CROSS_WORKTREE_PID' 2>/dev/null"
check "linked-worktree stop revokes the exact original capability" \
  python3 - "$PWD" "$CROSS_WORKTREE_CAPABILITY_ID" <<'PY'
from pathlib import Path
import subprocess
import sys

repo, capability = sys.argv[1:]
common = Path(subprocess.check_output(
    ["git", "-C", repo, "rev-parse", "--git-common-dir"], text=True
).strip())
if not common.is_absolute():
    common = Path(repo, common)
tombstone = common.resolve() / "startup-factory-broker" / "outbox-revoked" / (
    capability + ".revoked"
)
assert tombstone.read_text(encoding="ascii").strip() == capability
PY

FENCE_LINKED_TEAM=cross-worktree-fence
FENCE_LINKED_TASK='T-linked-fallback'
FENCE_LINKED_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$FENCE_LINKED_TASK")"
FENCE_LINKED_INSTANCE="backend--$FENCE_LINKED_KEY--a1"
FENCE_LINKED_PID="$(spawn_lifecycle_sleep)"
register_lifecycle_process "$FENCE_LINKED_TEAM" task "$FENCE_LINKED_INSTANCE" "$FENCE_LINKED_PID"
mkdir -p ".teamwork/$FENCE_LINKED_TEAM"
FENCE_LINKED_CAPABILITY="$(python3 .claude/skills/pm/bin/outbox_capability.py mint \
  --repo "$PWD" --workspace "$PWD/.teamwork/$FENCE_LINKED_TEAM" \
  --team "$FENCE_LINKED_TEAM" --feature FEAT-LINKED --role backend \
  --kind task --task "$FENCE_LINKED_TASK" --attempt 1 \
  --instance "$FENCE_LINKED_INSTANCE")"
FENCE_LINKED_ID="$(printf '%s' "$FENCE_LINKED_CAPABILITY" | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
if (cd "$CROSS_WORKTREE_CHECKOUT" && \
    "$CROSS_WORKTREE_LAUNCH" fence-task "$FENCE_LINKED_TEAM" "$FENCE_LINKED_TASK" >/dev/null); then
  echo "ok: linked-worktree fallback fence completes under the task lane"
else
  echo "FAIL: linked-worktree fallback fence failed"; FAILURES=$((FAILURES+1))
fi
check "linked-worktree fallback fence revokes original checkout capability" \
  python3 - "$PWD" "$FENCE_LINKED_ID" <<'PY'
from pathlib import Path
import subprocess,sys
repo, capability = sys.argv[1:]
common = Path(subprocess.check_output(["git", "-C", repo, "rev-parse", "--git-common-dir"], text=True).strip())
if not common.is_absolute(): common = Path(repo, common)
assert (common.resolve() / "startup-factory-broker" / "outbox-revoked" / (capability + ".revoked")).read_text().strip() == capability
PY
check "publication-only fallback does not signal the held task process" \
  kill -0 "$FENCE_LINKED_PID"
"$LAUNCH" stop-task "$FENCE_LINKED_TEAM" "$FENCE_LINKED_TASK" >/dev/null

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

# If TERM removes the authenticated group leader while a descendant survives,
# stop must retain the exact record and refuse any PGID-only SIGKILL authority.
STOP_TASK_LEADERLESS_TEAM=stop-task-leaderless
STOP_TASK_LEADERLESS_ID='T-leaderless-stop'
STOP_TASK_LEADERLESS_KEY="$(python3 .claude/skills/pm/bin/runtime-state.py key "$STOP_TASK_LEADERLESS_ID")"
STOP_TASK_LEADERLESS_INSTANCE="backend--$STOP_TASK_LEADERLESS_KEY--a1"
STOP_TASK_LEADERLESS_READY="$TMP/stop-task-leaderless-ready"
STOP_TASK_LEADERLESS_PID="$(/bin/sh -c '"$1" "$2" "$3" </dev/null >/dev/null 2>&1 & printf "%s\n" "$!"' \
  lifecycle-leaderless "$(command -v python3)" "$LEADER_EXIT_CHILD_SURVIVES" "$STOP_TASK_LEADERLESS_READY")"
for _i in $(seq 1 80); do [ -s "$STOP_TASK_LEADERLESS_READY" ] && break; sleep 0.05; done
read -r STOP_TASK_LEADERLESS_PID STOP_TASK_LEADERLESS_CHILD_PID < "$STOP_TASK_LEADERLESS_READY"
register_lifecycle_process "$STOP_TASK_LEADERLESS_TEAM" task \
  "$STOP_TASK_LEADERLESS_INSTANCE" "$STOP_TASK_LEADERLESS_PID"
mkdir -p ".teamwork/$STOP_TASK_LEADERLESS_TEAM/pids/tasks"
printf 'managed\n' > ".teamwork/$STOP_TASK_LEADERLESS_TEAM/pids/tasks/$STOP_TASK_LEADERLESS_INSTANCE.pid"
if "$LAUNCH" stop-task "$STOP_TASK_LEADERLESS_TEAM" "$STOP_TASK_LEADERLESS_ID" \
    >stop-task-leaderless.out 2>&1; then
  echo "FAIL: stop-task accepted leaderless process-group authority"; FAILURES=$((FAILURES+1))
elif grep -q 'identity mismatch' stop-task-leaderless.out; then
  echo "ok: stop-task fails closed after its authenticated group leader exits"
else
  echo "FAIL: leaderless stop returned wrong error: $(cat stop-task-leaderless.out)"; FAILURES=$((FAILURES+1))
fi
check "leaderless stop never SIGKILLs the surviving descendant" kill -0 "$STOP_TASK_LEADERLESS_CHILD_PID"
check "leaderless stop retains protected lifecycle evidence" \
  test "$(record_count "$STOP_TASK_LEADERLESS_TEAM" "$STOP_TASK_LEADERLESS_INSTANCE")" -eq 1
check "leaderless stop retains its task marker" \
  test -e ".teamwork/$STOP_TASK_LEADERLESS_TEAM/pids/tasks/$STOP_TASK_LEADERLESS_INSTANCE.pid"
kill -KILL -- "-$STOP_TASK_LEADERLESS_PID" 2>/dev/null || true
rm -f "$(record_for "$STOP_TASK_LEADERLESS_TEAM" "$STOP_TASK_LEADERLESS_INSTANCE")" \
  ".teamwork/$STOP_TASK_LEADERLESS_TEAM/pids/tasks/$STOP_TASK_LEADERLESS_INSTANCE.pid"

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

# A stop must wait for an in-flight launch's shared team fence before taking
# its protected snapshot.  Registering a process while stop waits models the
# mint/register interval that the old one-time snapshot could miss.
FENCED_TEAM=team-stop-fence
mkdir -p ".teamwork/$FENCED_TEAM"
FENCED_BARRIER="$LIFECYCLE_ROOT/.team-stop-test"
mkdir -m 700 "$FENCED_BARRIER"
python3 .claude/skills/pm/bin/launch-lane-lock.py \
  --root "$LIFECYCLE_ROOT" --repo "$PWD" --team "$FENCED_TEAM" \
  --category team --instance all --mode shared --barrier "$FENCED_BARRIER" \
  >"$TMP/team-fence-holder.out" 2>&1 &
FENCED_HOLDER=$!
for _i in $(seq 1 100); do [ -s "$FENCED_BARRIER/ready" ] && break; sleep 0.02; done
check "test launch holds the protected team fence" test -s "$FENCED_BARRIER/ready"
FENCED_BARRIERS_BEFORE="$(find "$LIFECYCLE_ROOT" -maxdepth 1 -type d -name '.launch-lane.*' | wc -l | tr -d ' ')"
"$LAUNCH" stop "$FENCED_TEAM" >"$TMP/team-stop-fenced.out" 2>&1 &
FENCED_STOP=$!
for _i in $(seq 1 100); do
  FENCED_BARRIERS_NOW="$(find "$LIFECYCLE_ROOT" -maxdepth 1 -type d -name '.launch-lane.*' | wc -l | tr -d ' ')"
  [ "$FENCED_BARRIERS_NOW" -gt "$FENCED_BARRIERS_BEFORE" ] && break
  sleep 0.02
done
check "team stop reaches protected team-fence wait" \
  test "$FENCED_BARRIERS_NOW" -gt "$FENCED_BARRIERS_BEFORE"
check "team stop waits for an in-flight launch before snapshot" kill -0 "$FENCED_STOP"
FENCED_PID="$(spawn_lifecycle_sleep)"
register_lifecycle_process "$FENCED_TEAM" gate backend "$FENCED_PID"
mkdir -m 700 "$FENCED_BARRIER/release"
wait "$FENCED_HOLDER"
if wait "$FENCED_STOP"; then
  echo "ok: team stop completes after the in-flight generation is registered"
else
  echo "FAIL: fenced team stop failed: $(cat "$TMP/team-stop-fenced.out")"; FAILURES=$((FAILURES+1))
fi
check "team stop retires generation registered before its snapshot" \
  test "$(record_count "$FENCED_TEAM" backend)" -eq 0

# A detached release worker shares admission through register + go.  A team
# stop queued while that fence is held must see the resulting release record
# and refuse before touching an unrelated gate.  Generic stop is never a
# substitute for the release supervisor's cancel/reconciliation protocol.
RELEASE_FENCE_TEAM=release-stop-fence
RELEASE_FENCE_GATE_PID="$(spawn_lifecycle_sleep)"
register_lifecycle_process "$RELEASE_FENCE_TEAM" gate backend "$RELEASE_FENCE_GATE_PID"
mkdir -p ".teamwork/$RELEASE_FENCE_TEAM"
python3 .claude/skills/pm/bin/outbox_capability.py mint \
  --repo "$PWD" --workspace "$PWD/.teamwork/$RELEASE_FENCE_TEAM" \
  --team "$RELEASE_FENCE_TEAM" --feature FEAT-RELEASE-STOP --role backend \
  --kind gate --task - --attempt 0 --instance backend >/dev/null
RELEASE_RECORDS_READY="$TMP/release-records-lock-ready"
python3 - "$LIFECYCLE_ROOT/records.lock" "$RELEASE_RECORDS_READY" <<'PY' &
import fcntl, pathlib, sys, time
with open(sys.argv[1], "a+b") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    pathlib.Path(sys.argv[2]).touch()
    time.sleep(30)
PY
RELEASE_RECORDS_HOLDER=$!
for _i in $(seq 1 100); do [ -e "$RELEASE_RECORDS_READY" ] && break; sleep 0.02; done
check "release fixture holds lifecycle registration before go" test -e "$RELEASE_RECORDS_READY"
RELEASE_FENCE_VARS="$(python3 - "$PWD" "$LIFECYCLE_ROOT" "$RELEASE_FENCE_TEAM" "$TMP/release-command-witness" <<'PY'
import hashlib, importlib.util, json, pathlib, subprocess, sys
repo, root, team, witness = sys.argv[1:]
worker = pathlib.Path(repo, ".claude/skills/pm/bin/release-worker.py")
spec = importlib.util.spec_from_file_location("release_fixture_worker", worker)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
command = [sys.executable, "-c", "from pathlib import Path; import time; Path(%r).touch(); time.sleep(5)" % witness]
identity = {"repository": repo, "runId": "run-release-stop-fence", "team": team,
            "featureId": "release-stop-feature", "attempt": 1,
            "commandDigest": module.digest_command(command)}
identity["jobId"] = "release-" + hashlib.sha256(json.dumps(
    identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode()).hexdigest()[:32]
directory = pathlib.Path(root, identity["jobId"])
directory.mkdir(mode=0o700)
result = directory / "result.json"
result.write_text(json.dumps({"schemaVersion": 1, "identity": identity,
                              "state": "launching", "createdAt": "2026-09-24T00:00:00+00:00"},
                             sort_keys=True, separators=(",", ":")) + "\n")
result.chmod(0o600)
with (directory / "worker.log").open("w") as log:
    process = subprocess.Popen([sys.executable, str(worker), "--result", str(result),
        "--log", str(directory / "release.log"), "--timeout", "60",
        "--identity-json", json.dumps(identity, separators=(",", ":")),
        "--lifecycle-root", root, "--repository", repo, "--", *command],
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True)
print(process.pid, identity["jobId"])
PY
)"
read -r RELEASE_FENCE_WORKER_PID RELEASE_FENCE_JOB_ID <<< "$RELEASE_FENCE_VARS"
for _i in $(seq 1 150); do
  RELEASE_FENCE_READY="$(find "$LIFECYCLE_ROOT" -maxdepth 2 -path '*/.release-team-fence.*/ready' -print -quit)"
  [ -n "$RELEASE_FENCE_READY" ] && break
  sleep 0.02
done
if [ -z "$RELEASE_FENCE_READY" ]; then
  echo "release fence fixture worker exited before readiness:" >&2
  sed -n '1,12p' "$LIFECYCLE_ROOT/$RELEASE_FENCE_JOB_ID/worker.log" >&2 || true
fi
check "release worker holds the shared team fence before registration" test -n "$RELEASE_FENCE_READY"
check "release command has not crossed the registration barrier" \
  test ! -e "$TMP/release-command-witness"
RELEASE_STOP_BARRIERS_BEFORE="$TMP/release-stop-barriers-before"
find "$LIFECYCLE_ROOT" -maxdepth 1 -type d -name '.launch-lane.*' -print \
  | sort > "$RELEASE_STOP_BARRIERS_BEFORE"
"$LAUNCH" stop "$RELEASE_FENCE_TEAM" >"$TMP/release-stop-refusal.out" 2>&1 &
RELEASE_FENCE_STOP_PID=$!
for _i in $(seq 1 500); do
  RELEASE_STOP_NEW_BARRIER="$(comm -13 "$RELEASE_STOP_BARRIERS_BEFORE" \
    <(find "$LIFECYCLE_ROOT" -maxdepth 1 -type d -name '.launch-lane.*' -print | sort))"
  [ -n "$RELEASE_STOP_NEW_BARRIER" ] && break
  sleep 0.02
done
check "team stop reaches the exclusive release fence" \
  test -n "$RELEASE_STOP_NEW_BARRIER"
check "team stop queues behind release admission" kill -0 "$RELEASE_FENCE_STOP_PID"
kill "$RELEASE_RECORDS_HOLDER" 2>/dev/null || true
wait "$RELEASE_RECORDS_HOLDER" 2>/dev/null || true
for _i in $(seq 1 150); do
  [ -e "$TMP/release-command-witness" ] && break
  sleep 0.02
done
check "release command begins only after authenticated registration" \
  test -e "$TMP/release-command-witness"
if wait "$RELEASE_FENCE_STOP_PID"; then
  echo "FAIL: generic team stop accepted an active production release"; FAILURES=$((FAILURES+1))
elif grep -q 'protected release job exists' "$TMP/release-stop-refusal.out"; then
  echo "ok: generic team stop refuses an authenticated release before signalling"
else
  echo "FAIL: team stop returned the wrong release error: $(cat "$TMP/release-stop-refusal.out")"; FAILURES=$((FAILURES+1))
fi
check "release refusal leaves unrelated gate process live" kill -0 "$RELEASE_FENCE_GATE_PID"
check "release refusal does not revoke unrelated gate publication" \
  test "$(active_capability_count "$RELEASE_FENCE_TEAM" gate -)" -eq 1
check "release refusal leaves exact release lifecycle evidence" \
  test "$(record_count "$RELEASE_FENCE_TEAM" "$RELEASE_FENCE_JOB_ID")" -eq 1
for _i in $(seq 1 160); do
  RELEASE_FENCE_RESULT_STATE="$(python3 - "$LIFECYCLE_ROOT/$RELEASE_FENCE_JOB_ID/result.json" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1]))["state"])
except (OSError, ValueError, KeyError): print("unavailable")
PY
)"
  [ "$RELEASE_FENCE_RESULT_STATE" = completed ] && break
  sleep 0.05
done
check "release worker reaches a durable terminal result" \
  test "$RELEASE_FENCE_RESULT_STATE" = completed
check "release worker retires its exact lifecycle record" \
  test "$(record_count "$RELEASE_FENCE_TEAM" "$RELEASE_FENCE_JOB_ID")" -eq 0
"$LAUNCH" stop "$RELEASE_FENCE_TEAM" >/dev/null

# -- status + stop --------------------------------------------------------------
# Capture first (grep -q closes the pipe early → SIGPIPE on the writer under pipefail).
status_out="$("$LAUNCH" status test-feature)"
echo "$status_out" | grep -q backend && echo "ok: status lists role" || { echo "FAIL: status"; FAILURES=$((FAILURES+1)); }
health_json="$("$LAUNCH" health --json)"
check "health uses the project snapshot envelope through the real launcher" python3 -c \
  'import json,sys; value=json.loads(sys.argv[1]); assert value["schemaVersion"] == "agent-health-snapshot-v1"; assert value["intervalSeconds"] == 300; assert any(row["team"] == "test-feature" and row["role"] == "backend" for row in value["agents"]); assert "launchToken" not in sys.argv[1] and "auth" not in sys.argv[1]' \
  "$health_json"
health_table="$("$LAUNCH" health)"
echo "$health_table" | grep -q 'self-reported' \
  && echo "ok: health table labels percentage provenance" \
  || { echo "FAIL: health table omits percentage provenance"; FAILURES=$((FAILURES+1)); }
canonical_launch="$PWD/$LAUNCH"
linked_health_json="$(cd "$T42_WT" && "$canonical_launch" health --json)"
check "linked-worktree health resolves the canonical project workspace" python3 -c \
  'import json,sys; canonical=json.loads(sys.argv[1]); linked=json.loads(sys.argv[2]); assert linked["repositoryId"] == canonical["repositoryId"]; assert {(r["team"],r["category"],r["instance"]) for r in linked["agents"]} == {(r["team"],r["category"],r["instance"]) for r in canonical["agents"]}' \
  "$health_json" "$linked_health_json"
"$LAUNCH" stop test-feature
echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
