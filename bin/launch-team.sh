#!/usr/bin/env bash
# launch-team.sh — start, relaunch, and support a multi-agent team.
# LLM-agnostic: which CLI runs each role comes from config/team.config.md.
#
# Usage:
#   launch-team.sh start    <team> <featureId> <role>...
#   launch-team.sh relaunch <team> <featureId> <role>
#   launch-team.sh worktree <team> <role> <taskId>
#   launch-team.sh status   <team>
#   launch-team.sh stop     <team>
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$SKILL_DIR/config/team.config.md"
REPO_ROOT="$(git rev-parse --show-toplevel)"

die() { echo "launch-team: $*" >&2; exit 1; }

read_key() { # read_key KEY -> value with surrounding quotes stripped; empty if null/missing
  local line
  line="$(grep -m1 "^$1=" "$CONFIG" || true)"
  line="${line#*=}"
  line="${line%\"}"; line="${line#\"}"
  [ "$line" = "null" ] && line=""
  printf '%s' "$line"
}

role_cmd_key() { # backend -> BACKEND_CMD ; principal-architect -> PRINCIPAL_ARCHITECT_CMD
  printf '%s_CMD' "$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')"
}

teamroot() {
  local root; root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
  printf '%s/%s/%s' "$REPO_ROOT" "$root" "$1"
}

compose_prompt() { # compose_prompt <team> <featureId> <role> -> prompt file path
  local team="$1" fid="$2" role="$3"
  local dir; dir="$(teamroot "$team")"
  local out="$dir/prompts/$role.md"
  mkdir -p "$dir/prompts" "$dir/mailbox/$role" "$dir/heartbeats" "$dir/pids"
  {
    echo "# Startup context"
    echo
    echo "- Your role: $role"
    echo "- Team (feature branch): $team"
    echo "- featureId: $fid"
    echo "- Repository root: $REPO_ROOT"
    echo "- Skill directory: $SKILL_DIR (adapter + PM config live here)"
    echo "- Team workspace: $dir"
    echo
    echo "Begin by running the Mandatory Preparation in $SKILL_DIR/SKILL.md, then act"
    echo "as your role brief and the protocol below instruct. Work autonomously."
    echo
    echo "---"
    cat "$SKILL_DIR/roles/$role.md"
    echo
    echo "---"
    cat "$SKILL_DIR/reference/orchestration.md"
    echo
    echo "---"
    cat "$CONFIG"
  } > "$out"
  printf '%s' "$out"
}

launch_one() { # launch_one <team> <featureId> <role>
  local team="$1" fid="$2" role="$3"
  [ -f "$SKILL_DIR/roles/$role.md" ] || die "unknown role: $role"
  local cmd_tpl; cmd_tpl="$(read_key "$(role_cmd_key "$role")")"
  [ -n "$cmd_tpl" ] || die "no command configured for role '$role' ($(role_cmd_key "$role") is null)"
  local prompt; prompt="$(compose_prompt "$team" "$fid" "$role")"
  local cmd="${cmd_tpl//\{prompt_file\}/$prompt}"
  local dir; dir="$(teamroot "$team")"

  if [ "${TEAM_RUNNER:-auto}" != "background" ] && command -v tmux >/dev/null 2>&1; then
    tmux has-session -t "team-$team" 2>/dev/null || tmux new-session -d -s "team-$team" -n _hub
    tmux kill-window -t "team-$team:$role" 2>/dev/null || true
    tmux new-window -t "team-$team" -n "$role" \
      "cd '$REPO_ROOT' && $cmd; echo '[launch-team] $role exited'; sleep 86400"
    echo "tmux" > "$dir/pids/$role.pid"
    echo "launched $role in tmux session team-$team"
  else
    ( cd "$REPO_ROOT" && exec bash -c "$cmd" >"$dir/pids/$role.log" 2>&1 ) &
    echo $! > "$dir/pids/$role.pid"
    echo "launched $role in background (pid $(cat "$dir/pids/$role.pid"))"
  fi
}

case "${1:-}" in
  start)
    [ $# -ge 4 ] || die "usage: start <team> <featureId> <role>..."
    team="$2"; fid="$3"; shift 3
    for role in "$@"; do launch_one "$team" "$fid" "$role"; done
    ;;
  relaunch)
    [ $# -eq 4 ] || die "usage: relaunch <team> <featureId> <role>"
    launch_one "$2" "$3" "$4"
    ;;
  worktree)
    [ $# -eq 4 ] || die "usage: worktree <team> <role> <taskId>"
    team="$2"; role="$3"; task="$4"
    wt="$(teamroot "$team")/worktrees/$role-$task"
    [ -d "$wt" ] && { echo "$wt"; exit 0; }
    mkdir -p "$(dirname "$wt")"
    git -C "$REPO_ROOT" worktree add "$wt" -b "$role-$task" >/dev/null
    echo "$wt"
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
  *)
    die "usage: launch-team.sh {start|relaunch|worktree|status|stop} ..."
    ;;
esac
