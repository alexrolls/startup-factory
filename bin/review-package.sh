#!/usr/bin/env bash
# Write one task's commit list, stat, and full diff to a reviewer handoff file.
set -euo pipefail
umask 077

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$SKILL_DIR/config/team.config.md"

# The outbox broker supplies its already authenticated canonical interpreter
# explicitly.  This avoids placing an executable shim in a shared temporary
# directory.  Standalone invocations retain the normal command lookup.
sf_python() {
  local pinned="${STARTUP_FACTORY_PINNED_PYTHON:-}"
  if [ -z "$pinned" ]; then
    command python3 "$@"
    return
  fi
  case "$pinned" in /*) ;; *) echo "review-package: pinned Python must be absolute" >&2; return 1 ;; esac
  [ -f "$pinned" ] && [ -x "$pinned" ] && [ ! -L "$pinned" ] \
    || { echo "review-package: pinned Python is unavailable" >&2; return 1; }
  if [ $# -gt 0 ]; then
    case "$1" in
      "$SKILL_DIR"/bin/*.py)
        local script="$1"
        shift
        "$pinned" -I -B -c '
import runpy, sys
script, module_dir = sys.argv[1:3]
sys.argv = [script, *sys.argv[3:]]
sys.path.insert(0, module_dir)
runpy.run_path(script, run_name="__main__")
' "$script" "$SKILL_DIR/bin" "$@"
        return
        ;;
    esac
  fi
  "$pinned" -I -B "$@"
}

read_key() {
  sf_python "$SKILL_DIR/bin/config-value.py" --config "$CONFIG" \
    --label "team config" --prefix review-package value "$1"
}

[ $# -eq 2 ] || { echo "usage: review-package.sh <team> <taskId>" >&2; exit 2; }
team="$1"; task="$2"
repo="$(sf_python "$SKILL_DIR/bin/delivery_profile.py" repo-root --path "$PWD")"
root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
workspace="$(sf_python "$SKILL_DIR/bin/teamwork-path.py" workspace --repo "$repo" --root "$root" --team "$team")"
key="$(sf_python "$SKILL_DIR/bin/runtime-state.py" key "$task")"
execution="$(sf_python "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "executions/$key.json")"
artifact_dir="$(sf_python "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "artifacts/$key")"
[ -f "$execution" ] && [ ! -L "$execution" ] || { echo "review-package: no safe execution record for $task" >&2; exit 1; }
branch="$(sf_python -c 'import json,sys; print(json.load(open(sys.argv[1]))["branch"])' "$execution")"
read -r role attempt worktree <<EOF
$(sf_python -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["role"], d["attempt"], d["worktree"])' "$execution")
EOF
case "$role" in ''|*[!a-z0-9-]*) echo "review-package: unsafe execution role" >&2; exit 1 ;; esac
case "$attempt" in ''|*[!0-9]*) echo "review-package: unsafe execution attempt" >&2; exit 1 ;; esac
[ "$branch" = "agent-task/$team/$key" ] || { echo "review-package: execution branch does not match task/team generation" >&2; exit 1; }
expected_worktree="$(sf_python "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "worktrees/$role#$attempt-$key")"
[ "$(sf_python -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$worktree")" = "$expected_worktree" ] \
  || { echo "review-package: execution worktree is outside its task slot" >&2; exit 1; }
worktree="$expected_worktree"
[ -d "$worktree" ] && [ ! -L "$worktree" ] || { echo "review-package: missing safe worktree $worktree" >&2; exit 1; }
sf_python "$SKILL_DIR/bin/delivery_profile.py" review-package \
  --repo "$repo" --worktree "$worktree" \
  --base-ref "refs/heads/$team" --head-ref "refs/heads/$branch" \
  --task "$task" --output-directory "$artifact_dir"
