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
worktree_mode="$(read_key TASK_WORKTREE_MODE)"; worktree_mode="${worktree_mode:-linked-worktree}"
base_commit="$(git -C "$repo" rev-parse "$team^{commit}")"
manifest="$(read_key AGENT_RUNTIME_MANIFEST)"
manifest_digest=""
if [ -n "$manifest" ]; then
  manifest_digest="$(python3 - "$manifest" <<'PY'
import hashlib,os,stat,sys
path=sys.argv[1]; fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
try:
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_size > 1024*1024: raise SystemExit("unsafe runtime manifest")
 print("sha256:"+hashlib.sha256(os.read(fd,info.st_size+1)).hexdigest())
finally: os.close(fd)
PY
)"
fi
"$SKILL_DIR/bin/tracker-ops.sh" export "$feature" "$tasks" >/dev/null
python3 "$SKILL_DIR/bin/runtime-state.py" packet \
  --workspace "$workspace" --tasks "$tasks" --feature "$feature" --task "$task" \
  --role "$role" --attempt "$attempt" --worktree "$worktree" --branch "$branch" \
  --config "$CONFIG" --contracts "$contracts" --baseline "$baseline" --repo "$repo" \
  --worktree-mode "$worktree_mode" --base-commit "$base_commit" \
  --runtime-manifest-digest "$manifest_digest"
