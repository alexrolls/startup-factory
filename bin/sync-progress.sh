#!/usr/bin/env bash
# Project the tracker snapshot into one editable task progress artifact and one feature digest.
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

[ $# -eq 3 ] || { echo "usage: sync-progress.sh <team> <featureId> <tasks.json>" >&2; exit 2; }
team="$1"; feature="$2"; tasks="$3"
root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
repo="$(git rev-parse --show-toplevel)"
workspace="$(python3 "$SKILL_DIR/bin/teamwork-path.py" workspace --repo "$repo" --root "$root" --team "$team")"
expected_tasks="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative tasks.json)"
[ "$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$tasks")" = "$expected_tasks" ] || {
  echo "sync-progress: tasks snapshot must be the canonical team tasks.json" >&2
  exit 1
}
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative events.ndjson >/dev/null
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative pm >/dev/null
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative pm-projection.json >/dev/null
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative executions >/dev/null
args=(sync --repo "$repo" --workspace "$workspace" --team "$team" --feature "$feature" --tasks "$tasks"
      --tracker-ops "$SKILL_DIR/bin/tracker-ops.sh"
      --ignored-labels-json "${STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON:-[]}")
while IFS= read -r status; do
  args+=(--terminal "$status")
done < <(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [print(s["name"]) for s in d["tasks"]["statuses"] if s.get("terminal")]' "$SKILL_DIR/config/statuses.config.json")
while IFS= read -r status; do
  args+=(--held-status "$status")
done < <(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [print(s["name"]) for s in d["tasks"]["statuses"] if s.get("kind") == "blocked"]' "$SKILL_DIR/config/statuses.config.json")
python3 "$SKILL_DIR/bin/runtime-state.py" "${args[@]}"
