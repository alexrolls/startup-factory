#!/usr/bin/env bash
# Generate the immutable, task-local context packet consumed by one fresh worker.
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$SKILL_DIR/config/team.config.md"

read_key() {
  local line value _t
  line="$(grep -m1 "^$1=" "$CONFIG" || true)"
  value="${line#*=}"
  if [ "${value#\"}" != "$value" ]; then value="${value#\"}"; value="${value%%\"*}"
  else value="${value%%[[:space:]]#*}"; _t="${value##*[![:space:]]}"; value="${value%"$_t"}"; fi
  [ "$value" = "null" ] && value=""
  printf '%s' "$value"
}

[ $# -eq 7 ] || {
  echo "usage: task-packet.sh <team> <featureId> <taskId> <role> <attempt> <worktree> <branch>" >&2
  exit 2
}
team="$1"; feature="$2"; task="$3"; role="$4"; attempt="$5"; worktree="$6"; branch="$7"
repo="$(git rev-parse --show-toplevel)"
root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
workspace="$(python3 "$SKILL_DIR/bin/teamwork-path.py" workspace --repo "$repo" --root "$root" --team "$team")"
key="$(python3 "$SKILL_DIR/bin/runtime-state.py" key "$task")"
tasks="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative tasks.json)"
contracts="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative CONTRACTS.md)"
baseline="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative BASELINE.md)"
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "artifacts/$key/attempt-$attempt" >/dev/null
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "executions/$key.json" >/dev/null
mkdir -p "$workspace"
"$SKILL_DIR/bin/tracker-ops.sh" export "$feature" "$tasks" >/dev/null
python3 "$SKILL_DIR/bin/runtime-state.py" packet \
  --workspace "$workspace" --tasks "$tasks" --feature "$feature" --task "$task" \
  --role "$role" --attempt "$attempt" --worktree "$worktree" --branch "$branch" \
  --config "$CONFIG" --contracts "$contracts" --baseline "$baseline" --repo "$repo"
