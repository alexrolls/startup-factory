#!/usr/bin/env bash
# Generate the immutable, task-local context packet consumed by one fresh worker.
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$SKILL_DIR/config/team.config.md"

read_key() {
  python3 "$SKILL_DIR/bin/config-value.py" --config "$CONFIG" \
    --label "team config" --prefix task-packet value "$1"
}

[ $# -eq 7 ] || [ $# -eq 13 ] || {
  echo "usage: task-packet.sh <team> <featureId> <taskId> <role> <attempt> <worktree> <branch> [--restart-control-id <id> --restart-generation <generation> --restart-reason <reason>]" >&2
  exit 2
}
team="$1"; feature="$2"; task="$3"; role="$4"; attempt="$5"; worktree="$6"; branch="$7"
shift 7
restart_control_id=""; restart_generation=""; restart_reason=""
while [ $# -gt 0 ]; do
  case "$1" in
    --restart-control-id)
      [ -z "$restart_control_id" ] && [ $# -ge 2 ] || exit 2
      restart_control_id="$2"; shift 2
      ;;
    --restart-generation)
      [ -z "$restart_generation" ] && [ $# -ge 2 ] || exit 2
      restart_generation="$2"; shift 2
      ;;
    --restart-reason)
      [ -z "$restart_reason" ] && [ $# -ge 2 ] || exit 2
      restart_reason="$2"; shift 2
      ;;
    *) exit 2 ;;
  esac
done
if [ -n "$restart_control_id$restart_generation$restart_reason" ]; then
  [ -n "$restart_control_id" ] && [ -n "$restart_generation" ] && [ -n "$restart_reason" ] || {
    echo "task-packet: incomplete restart evidence" >&2
    exit 2
  }
fi
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
packet_command=(
  python3 "$SKILL_DIR/bin/runtime-state.py" packet
  --workspace "$workspace" --tasks "$tasks" --team "$team" --feature "$feature" --task "$task"
  --role "$role" --attempt "$attempt" --worktree "$worktree" --branch "$branch"
  --config "$CONFIG" --contracts "$contracts" --baseline "$baseline" --repo "$repo"
)
if [ -n "$restart_control_id" ]; then
  packet_command+=(
    --restart-control-id "$restart_control_id"
    --restart-generation "$restart_generation"
    --restart-reason "$restart_reason"
  )
fi
"${packet_command[@]}"
