#!/usr/bin/env bash
# launch-team.sh — start, relaunch, and support a multi-agent team.
# LLM-agnostic: which CLI runs each role comes from config/team.config.md.
#
# Usage:
#   launch-team.sh team          <preset> <team> <featureId>     # launch a preset roster (teams/<preset>.md)
#   launch-team.sh preflight     <team> <featureId>              # verify adapter, workspace, UTC pin
#   launch-team.sh start         <team> <featureId> <role>...
#   launch-team.sh relaunch      <team> <featureId> <role> [preset]
#   launch-team.sh compose       <team> <featureId> <role> [preset]  # write the composed startup prompt, print its path — no spawn (harness mode)
#   launch-team.sh worktree      <team> <role> <taskId> [attempt]
#   launch-team.sh worktree-remove <team> <role> <taskId> [attempt]
#   launch-team.sh validate-board [config-path]                  # validate board config JSON
#   launch-team.sh status        <team>
#   launch-team.sh stop          <team>
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$SKILL_DIR/config/team.config.md"
PM_CONFIG="$SKILL_DIR/config/project-management.config.md"
REPO_ROOT="$(git rev-parse --show-toplevel)"

die() { echo "launch-team: $*" >&2; exit 1; }

read_key() { # read_key KEY -> value with surrounding quotes stripped; empty if null/missing
  local line _t
  line="$(grep -m1 "^$1=" "$CONFIG" || true)"
  line="${line#*=}"
  if [ "${line#\"}" != "$line" ]; then
    line="${line#\"}"; line="${line%%\"*}"
  else
    line="${line%%[[:space:]]#*}"
    _t="${line##*[![:space:]]}"; line="${line%"$_t"}"
  fi
  [ "$line" = "null" ] && line=""
  printf '%s' "$line"
}

read_pm_key() { # read from project-management.config.md; quotes stripped; null -> empty
  local line; line="$(grep -m1 "^$1=" "$PM_CONFIG" || true)"
  line="${line#*=}"; line="${line%\"}"; line="${line#\"}"
  [ "$line" = "null" ] && line=""
  printf '%s' "$line"
}

is_mcp_only() { # is_mcp_only <adapter> -> 0 if configured for MCP-only access
  case "$1" in
    Linear)       [ "$(read_pm_key LINEAR_ACCESS)"  = "mcp"  ] ;;
    Jira)         [ "$(read_pm_key JIRA_ACCESS)"    = "mcp"  ] ;;
    GitHubIssues) [ "$(read_pm_key GITHUB_USE_MCP)" = "true" ] ;;
    *)            return 1 ;;
  esac
}

role_cmd_key() { # backend -> BACKEND_CMD ; principal-architect -> PRINCIPAL_ARCHITECT_CMD
  printf '%s_CMD' "$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')"
}

key_is_null() { # key_is_null KEY -> 0 if the config sets KEY explicitly to null (disabled)
  grep -qE "^$1=null[[:space:]]*(#.*)?$" "$CONFIG"
}

validate_config() { # MAX_ACTIVE_IMPLEMENTERS is a parallel-only knob (spec: throughput levers)
  local exec_mode max_active
  exec_mode="$(read_key EXECUTION)"
  max_active="$(read_key MAX_ACTIVE_IMPLEMENTERS)"
  [ -z "$max_active" ] && return 0
  [ "$exec_mode" = "parallel" ] || die "MAX_ACTIVE_IMPLEMENTERS is set but EXECUTION is '${exec_mode:-sequential}' — the knob only applies under EXECUTION=parallel"
  case "$max_active" in
    ''|*[!0-9]*) die "MAX_ACTIVE_IMPLEMENTERS must be a positive integer, got '$max_active'" ;;
  esac
  [ "$max_active" -ge 1 ] || die "MAX_ACTIVE_IMPLEMENTERS must be >= 1"
}

role_brief() { # role_brief <role> -> path to its brief, in roles/ or teams/roles/; empty if none
  if [ -f "$SKILL_DIR/roles/$1.md" ]; then
    printf '%s' "$SKILL_DIR/roles/$1.md"
  elif [ -f "$SKILL_DIR/teams/roles/$1.md" ]; then
    printf '%s' "$SKILL_DIR/teams/roles/$1.md"
  fi
}

roster_of() { # roster_of <preset> -> space-separated role names from teams/<preset>.md ROSTER= line
  local f="$SKILL_DIR/teams/$1.md"
  [ -f "$f" ] || die "unknown preset: $1 (no teams/$1.md)"
  local line; line="$(grep -m1 '^ROSTER=' "$f" || true)"
  [ -n "$line" ] || die "teams/$1.md has no ROSTER= line"
  printf '%s' "${line#ROSTER=}"
}

validate_board() { # validate_board [config-path] — structural checks on the board config
  local cfg="${1:-$SKILL_DIR/config/statuses.config.json}"
  [ -f "$cfg" ] || die "no board config: $cfg"
  command -v python3 >/dev/null 2>&1 || die "validate-board requires python3"
  python3 - "$cfg" "$SKILL_DIR" <<'PYEOF'
import json, sys, os
cfg_path, skill_dir = sys.argv[1], sys.argv[2]
try:
    with open(cfg_path) as f:
        cfg = json.load(f)
except ValueError as e:
    print("validate-board: invalid JSON: %s" % e, file=sys.stderr); sys.exit(1)

ABSTRACT_ROLES = {"implementer", "reviewer", "coordinator", "finalizer"}
errors = []

def role_exists(name):
    return (name in ABSTRACT_ROLES
            or os.path.isfile(os.path.join(skill_dir, "roles", name + ".md"))
            or os.path.isfile(os.path.join(skill_dir, "teams", "roles", name + ".md")))

def team_exists(name):
    return os.path.isfile(os.path.join(skill_dir, "teams", name + ".md"))

for machine in ("features", "tasks"):
    statuses = cfg.get(machine, {}).get("statuses")
    if not isinstance(statuses, list) or not statuses:
        errors.append("%s: missing or empty 'statuses' list" % machine); continue
    names = [s.get("name") for s in statuses]
    for d in sorted(set(n for n in names if names.count(n) > 1)):
        errors.append("%s: duplicate status name '%s'" % (machine, d))
    by_name = dict((s.get("name"), s) for s in statuses)
    initials = [s for s in statuses if s.get("initial")]
    if len(initials) != 1:
        errors.append("%s: exactly one initial status required, found %d" % (machine, len(initials)))
    if not any(s.get("terminal") for s in statuses):
        errors.append("%s: at least one terminal status required" % machine)
    for s in statuses:
        name = s.get("name") or "<unnamed>"
        trans = s.get("transitions")
        if not isinstance(trans, list):
            errors.append("%s/%s: 'transitions' must be a list" % (machine, name)); trans = []
        for t in trans:
            if t not in by_name:
                errors.append("%s/%s: transition to undefined status '%s'" % (machine, name, t))
        if s.get("terminal") and trans:
            errors.append("%s/%s: terminal status must have empty transitions" % (machine, name))
        if s.get("requiresCommit") and s.get("initial"):
            errors.append("%s/%s: requiresCommit not allowed on the initial status" % (machine, name))
        owner = s.get("owner")
        if not isinstance(owner, dict) or len(owner) != 1 or list(owner)[0] not in ("role", "team"):
            errors.append("%s/%s: owner must be exactly one of {\"role\": ...} or {\"team\": ...}" % (machine, name))
        else:
            kind, val = list(owner.items())[0]
            if kind == "role" and not role_exists(val):
                errors.append("%s/%s: unknown role '%s'" % (machine, name, val))
            if kind == "team" and not team_exists(val):
                errors.append("%s/%s: unknown team preset '%s'" % (machine, name, val))
    if len(initials) == 1:
        seen, stack = set(), [initials[0].get("name")]
        while stack:
            n = stack.pop()
            if n in seen: continue
            seen.add(n)
            t = by_name.get(n, {}).get("transitions")
            for nxt in (t if isinstance(t, list) else []):
                if nxt in by_name: stack.append(nxt)
        for n in by_name:
            if n not in seen:
                errors.append("%s: status '%s' unreachable from the initial status" % (machine, n))

markers = cfg.get("markers")
if markers is not None:
    if not isinstance(markers, dict) or not markers:
        errors.append("markers: must be a non-empty object of marker -> {authorizedRoles: [...]}")
    else:
        for mname, spec in markers.items():
            roles = (spec or {}).get("authorizedRoles") if isinstance(spec, dict) else None
            if not isinstance(roles, list) or not roles:
                errors.append("markers/%s: 'authorizedRoles' must be a non-empty list" % mname)
                continue
            for r in roles:
                if not role_exists(r):
                    errors.append("markers/%s: unknown role '%s'" % (mname, r))

if errors:
    for e in errors: print("validate-board: %s" % e, file=sys.stderr)
    sys.exit(1)
print("board config OK: %s" % cfg_path)
PYEOF
}

preflight() { # preflight <team> <featureId> — fail before five agents do
  local team="$1" fid="$2"
  local dir; dir="$(teamroot "$team")"
  validate_board >/dev/null
  mkdir -p "$dir/preflight" 2>/dev/null || die "preflight: cannot create workspace $dir"
  ( : > "$dir/preflight/.write-test" && rm "$dir/preflight/.write-test" ) \
    || die "preflight: workspace not writable: $dir"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$dir/preflight/utc.txt"
  local _a; _a="$(grep -m1 '^PRODUCT_MANAGEMENT_TOOL=' "$PM_CONFIG" | cut -d= -f2 | tr -d '"' || true)"
  local _adapter="${TRACKER_ADAPTER:-$_a}"
  if is_mcp_only "$_adapter"; then
    die "preflight FAILED — CLI dispatcher requires scriptable tracker access for $_adapter.
  MCP access is harness-mode only; shell dispatch cannot call MCP tools.
  Fix: in config/project-management.config.md set the scriptable option and export credentials:
    Linear:       LINEAR_ACCESS=rest  +  LINEAR_API_KEY
    Jira:         JIRA_ACCESS=rest    +  JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN
    GitHubIssues: GITHUB_USE_MCP=false  (gh CLI is the scriptable path)
  Or use harness mode: launch-team.sh compose <team> <featureId> <role> [preset]"
  fi
  local probe_err
  if probe_err="$("$SKILL_DIR/bin/tracker-ops.sh" export "$fid" /dev/null 2>&1 >/dev/null)"; then
    echo "preflight OK: adapter read verified, workspace writable, UTC pinned"
  elif printf '%s' "$probe_err" | grep -q "no tracker-ops backend" \
       && [ -s "$dir/preflight/tool-prefix.txt" ]; then
    echo "preflight OK: MCP tool prefix on record ($(cat "$dir/preflight/tool-prefix.txt")), workspace writable, UTC pinned (harness prompt composition only; CLI dispatch.sh requires scriptable access)"
  else
    die "preflight FAILED — no agent was launched.
  probe: $probe_err
  Scriptable adapter (REST/CLI/files): fix credentials/config, then verify with:
    bin/tracker-ops.sh export $fid /dev/null
  MCP adapter: run ONE probe agent that loads the tracker tools (deferred tools
  via ToolSearch), performs one read, and writes the exact tool prefix
  (e.g. mcp__linear__) to $dir/preflight/tool-prefix.txt — then relaunch."
  fi
}

teamroot() {
  local root; root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
  printf '%s/%s/%s' "$REPO_ROOT" "$root" "$1"
}

compose_prompt() { # compose_prompt <team> <featureId> <role> [preset] -> prompt file path
  local team="$1" fid="$2" role="$3" preset="${4:-}"
  local dir; dir="$(teamroot "$team")"
  local out="$dir/prompts/$role.md"
  local brief; brief="$(role_brief "$role")"
  [ -n "$brief" ] || die "unknown role: $role (no brief in roles/ or teams/roles/)"
  mkdir -p "$dir/prompts" "$dir/mailbox/$role" "$dir/heartbeats" "$dir/pids"
  {
    echo "# Startup context"
    echo
    echo "- Your role: $role"
    echo "- Team (feature branch): $team"
    echo "- featureId: $fid"
    [ -n "$preset" ] && echo "- Preset team: $preset (teams/$preset.md)"
    echo "- Repository root: $REPO_ROOT"
    echo "- Skill directory: $SKILL_DIR (adapter + PM config live here)"
    echo "- Team workspace: $dir"
    if [ -s "$dir/preflight/utc.txt" ]; then
      echo "- Preflight UTC pin: $(cat "$dir/preflight/utc.txt") — generate every timestamp with: date -u +%Y-%m-%dT%H:%M:%SZ"
    fi
    if [ -s "$dir/preflight/tool-prefix.txt" ]; then
      echo "- Verified tracker tool prefix: $(cat "$dir/preflight/tool-prefix.txt") (preflight-verified — use it verbatim; do not re-derive from adapter docs)"
    fi
    echo
    echo "Begin by running the Mandatory Preparation in $SKILL_DIR/SKILL.md, then act"
    echo "as your role brief and the protocol below instruct. Work autonomously."
    echo
    echo "---"
    cat "$brief"
    if [ -n "$preset" ]; then
      echo
      echo "---"
      cat "$SKILL_DIR/teams/$preset.md"
      echo
      echo "---"
      cat "$SKILL_DIR/teams/_PLAYBOOK.md"
    fi
    echo
    echo "---"
    cat "$SKILL_DIR/reference/orchestration.md"
    echo
    echo "---"
    cat "$CONFIG"
    if [ -f "$SKILL_DIR/config/statuses.config.json" ]; then
      echo
      echo "---"
      echo "# Board config (config/statuses.config.json)"
      cat "$SKILL_DIR/config/statuses.config.json"
    fi
  } > "$out"
  printf '%s' "$out"
}

launch_one() { # launch_one <team> <featureId> <role> [preset]
  local team="$1" fid="$2" role="$3" preset="${4:-}"
  if [ -z "$preset" ]; then
    local _pf; _pf="$(teamroot "$team")/preset.env"
    [ -f "$_pf" ] && { local _l; _l="$(grep -m1 '^PRESET=' "$_pf" || true)"; preset="${_l#PRESET=}"; }
  fi
  [ -n "$(role_brief "$role")" ] || die "unknown role: $role"
  local key; key="$(role_cmd_key "$role")"
  key_is_null "$key" && die "role '$role' is disabled ($key=null); remove it from the roster"
  # Absent key (not explicit null) falls back to TEAM_DEFAULT_CMD so preset rosters
  # don't need a key per role. An explicit null disables and never falls back.
  local cmd_tpl; cmd_tpl="$(read_key "$key")"
  [ -n "$cmd_tpl" ] || cmd_tpl="$(read_key TEAM_DEFAULT_CMD)"
  [ -n "$cmd_tpl" ] || die "no command for role '$role' ($key absent and TEAM_DEFAULT_CMD is null)"
  local prompt; prompt="$(compose_prompt "$team" "$fid" "$role" "$preset")"
  local cmd="${cmd_tpl//\{prompt_file\}/$prompt}"
  local dir; dir="$(teamroot "$team")"

  if [ "${TEAM_RUNNER:-auto}" != "background" ] && command -v tmux >/dev/null 2>&1; then
    tmux has-session -t "team-$team" 2>/dev/null || tmux new-session -d -s "team-$team" -n _hub
    tmux kill-window -t "team-$team:$role" 2>/dev/null || true
    tmux new-window -t "team-$team" -n "$role" \
      "cd '$REPO_ROOT' && { $cmd; rc=\$?; }; echo '[launch-team] $role exited ('\$rc')'; rm -f '$dir/pids/$role.pid'; sleep 86400"
    echo "tmux" > "$dir/pids/$role.pid"
    echo "launched $role in tmux session team-$team"
  else
    if [ -f "$dir/pids/$role.pid" ] && [ "$(cat "$dir/pids/$role.pid")" != "tmux" ] && kill -0 "$(cat "$dir/pids/$role.pid")" 2>/dev/null; then
      kill "$(cat "$dir/pids/$role.pid")" 2>/dev/null || true
    fi
    ( cd "$REPO_ROOT" && exec bash -c "$cmd" >"$dir/pids/$role.log" 2>&1 ) &
    echo $! > "$dir/pids/$role.pid"
    echo "launched $role in background (pid $(cat "$dir/pids/$role.pid"))"
  fi
}

case "${1:-}" in validate-board|'') ;; *) validate_config ;; esac

case "${1:-}" in
  team)
    [ $# -eq 4 ] || die "usage: team <preset> <team> <featureId>"
    preset="$2"; team="$3"; fid="$4"
    [ -f "$SKILL_DIR/teams/$preset.md" ] || die "unknown preset: $preset (no teams/$preset.md)"
    roster="$(roster_of "$preset")"                       # validate before the loop
    [ -n "$roster" ] || die "teams/$preset.md has an empty ROSTER"
    validate_board >/dev/null
    [ "${SKIP_PREFLIGHT:-}" = "1" ] || preflight "$team" "$fid"
    dir="$(teamroot "$team")"
    { printf 'PRESET=%s\n' "$preset"; grep '^PROTOCOL_' "$SKILL_DIR/teams/$preset.md" || true; } > "$dir/preset.env"
    for role in $roster; do
      if key_is_null "$(role_cmd_key "$role")"; then
        echo "skipping $role (disabled: $(role_cmd_key "$role")=null)"; continue
      fi
      launch_one "$team" "$fid" "$role" "$preset"
    done
    ;;
  start)
    [ $# -ge 4 ] || die "usage: start <team> <featureId> <role>..."
    team="$2"; fid="$3"; shift 3
    for role in "$@"; do launch_one "$team" "$fid" "$role"; done
    ;;
  relaunch)
    [ $# -eq 4 ] || [ $# -eq 5 ] || die "usage: relaunch <team> <featureId> <role> [preset]"
    launch_one "$2" "$3" "$4" "${5:-}"
    ;;
  compose)
    # Harness mode: emit the exact same startup prompt `start` would use, without
    # spawning anything, so any harness can spawn the role natively with it.
    [ $# -eq 4 ] || [ $# -eq 5 ] || die "usage: compose <team> <featureId> <role> [preset]"
    prompt="$(compose_prompt "$2" "$3" "$4" "${5:-}")"
    echo "$prompt"
    ;;
  worktree)
    [ $# -ge 4 ] && [ $# -le 5 ] || die "usage: worktree <team> <role> <taskId> [attempt]"
    team="$2"; role="$3"; task="$4"; attempt="${5:-1}"
    case "$attempt" in ''|*[!0-9]*) die "attempt must be a positive integer" ;; esac
    wt="$(teamroot "$team")/worktrees/$role#$attempt-$task"
    [ -d "$wt" ] && { echo "$wt"; exit 0; }
    mkdir -p "$(dirname "$wt")"
    if git -C "$REPO_ROOT" show-ref --verify --quiet "refs/heads/$role-$task"; then
      git -C "$REPO_ROOT" worktree add "$wt" "$role-$task" >/dev/null
    else
      git -C "$REPO_ROOT" worktree add "$wt" -b "$role-$task" "$team" >/dev/null
    fi
    setup="$(read_key WORKTREE_SETUP)"
    if [ -n "$setup" ]; then
      if ! ( cd "$wt" && eval "$setup" ) >/dev/null; then
        git -C "$REPO_ROOT" worktree remove --force "$wt" >/dev/null 2>&1 || true
        git -C "$REPO_ROOT" worktree prune
        die "WORKTREE_SETUP failed in $wt — worktree removed. Fix the command or the environment; never claim validations in an unprovisioned tree."
      fi
    fi
    echo "$wt"
    ;;
  worktree-remove)
    [ $# -ge 4 ] && [ $# -le 5 ] || die "usage: worktree-remove <team> <role> <taskId> [attempt]"
    wt="$(teamroot "$2")/worktrees/$3#${5:-1}-$4"
    git -C "$REPO_ROOT" worktree remove --force "$wt" 2>/dev/null || true
    git -C "$REPO_ROOT" worktree prune
    echo "removed $wt (registration pruned)"
    ;;
  status)
    [ $# -eq 2 ] || die "usage: status <team>"
    dir="$(teamroot "$2")"
    [ -d "$dir" ] || die "no workspace for team '$2'"
    for pf in "$dir"/pids/*.pid; do
      [ -e "$pf" ] || continue
      role="$(basename "$pf" .pid)"
      pid="$(cat "$pf")"
      if [ "$pid" = "tmux" ]; then
        state="tmux:team-$2:$role"
      elif kill -0 "$pid" 2>/dev/null; then
        state="running (pid $pid)"
      else
        state="DEAD"
      fi
      hb="-"; [ -f "$dir/heartbeats/$role" ] && hb="$(cat "$dir/heartbeats/$role")"
      printf '%-22s %-20s %s\n' "$role" "$state" "$hb"
    done
    ;;
  stop)
    [ $# -eq 2 ] || die "usage: stop <team>"
    dir="$(teamroot "$2")"
    tmux kill-session -t "team-$2" 2>/dev/null || true
    for pf in "$dir"/pids/*.pid; do
      [ -e "$pf" ] || continue
      pid="$(cat "$pf")"
      [ "$pid" != "tmux" ] && kill "$pid" 2>/dev/null || true
      rm -f "$pf"
    done
    echo "stopped team $2"
    ;;
  preflight)
    [ $# -eq 3 ] || die "usage: preflight <team> <featureId>"
    preflight "$2" "$3"
    ;;
  validate-board)
    [ $# -le 2 ] || die "usage: validate-board [config-path]"
    validate_board "${2:-}"
    ;;
  *)
    die "usage: launch-team.sh {team|preflight|start|relaunch|compose|worktree|worktree-remove|validate-board|status|stop} ..."
    ;;
esac
