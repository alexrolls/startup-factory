#!/usr/bin/env bash
# Write one task's commit list, stat, and full diff to a reviewer handoff file.
set -euo pipefail
umask 077

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

git_unprivileged() {
  local args=(-i "PATH=${PATH:-/usr/bin:/bin}" "GIT_CONFIG_GLOBAL=/dev/null" "GIT_CONFIG_NOSYSTEM=1")
  [ -z "${TMPDIR-}" ] || args+=("TMPDIR=$TMPDIR")
  [ -z "${LANG-}" ] || args+=("LANG=$LANG")
  [ -z "${LC_ALL-}" ] || args+=("LC_ALL=$LC_ALL")
  /usr/bin/env "${args[@]}" git -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"
}

[ $# -eq 2 ] || { echo "usage: review-package.sh <team> <taskId>" >&2; exit 2; }
team="$1"; task="$2"; repo="$(git_unprivileged rev-parse --show-toplevel)"
root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
workspace="$(python3 "$SKILL_DIR/bin/teamwork-path.py" workspace --repo "$repo" --root "$root" --team "$team")"
key="$(python3 "$SKILL_DIR/bin/runtime-state.py" key "$task")"
execution="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "executions/$key.json")"
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "artifacts/$key" >/dev/null
[ -f "$execution" ] && [ ! -L "$execution" ] || { echo "review-package: no safe execution record for $task" >&2; exit 1; }
read -r role attempt worktree mode base branch <<EOF
$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["role"], d["attempt"], d["worktree"], d.get("worktreeMode") or "linked-worktree", d.get("baseCommit") or "-", d["branch"])' "$execution")
EOF
case "$role" in ''|*[!a-z0-9-]*) echo "review-package: unsafe execution role" >&2; exit 1 ;; esac
case "$attempt" in ''|*[!0-9]*) echo "review-package: unsafe execution attempt" >&2; exit 1 ;; esac
[ "$branch" = "agent-task/$team/$key" ] || { echo "review-package: execution branch does not match task/team generation" >&2; exit 1; }
if [ "$mode" = standalone-clone ]; then
  expected_worktree="$(python3 "$SKILL_DIR/bin/standalone_workspace.py" path --repo "$repo" \
    --root "$(read_key BROKER_TASK_CLONE_ROOT)" --team "$team" --role "$role" \
    --attempt "$attempt" --task-key "$key")"
else
  expected_worktree="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "worktrees/$role#$attempt-$key")"
fi
[ "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$worktree")" = "$expected_worktree" ] \
  || { echo "review-package: execution worktree is outside its task slot" >&2; exit 1; }
worktree="$expected_worktree"
[ -d "$worktree" ] && [ ! -L "$worktree" ] || { echo "review-package: missing safe worktree $worktree" >&2; exit 1; }
[ -z "$(git_unprivileged -C "$worktree" status --porcelain -uall)" ] || {
  echo "review-package: $task has uncommitted changes; worker must create task-branch checkpoint commits first" >&2
  exit 1
}
if [ "$mode" = standalone-clone ]; then
  case "$base" in ''|-|*[!0-9a-f]*) echo "review-package: standalone execution has invalid base" >&2; exit 1 ;; esac
  clone_head="$(git_unprivileged -C "$worktree" rev-parse HEAD)"
  bundle="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "artifacts/$key/quarantine-$clone_head.bundle")"
  imported="$(python3 "$SKILL_DIR/bin/standalone_workspace.py" import --repo "$repo" --clone "$worktree" \
    --branch "$branch" --base "$base" --team "$team" --task-key "$key" --attempt "$attempt" --bundle "$bundle")" \
    || { echo "review-package: hostile standalone clone import failed" >&2; exit 1; }
  source_ref="$(printf '%s' "$imported" | python3 -c 'import json,sys; print(json.load(sys.stdin)["quarantineRef"])')"
  head="$(printf '%s' "$imported" | python3 -c 'import json,sys; print(json.load(sys.stdin)["headCommit"])')"
else
  base="$(git_unprivileged -C "$repo" merge-base "$team" "$branch")"
  head="$(git_unprivileged -C "$repo" rev-parse "$branch")"
  source_ref="$branch"
fi
validation_evidence=""
enforced="$(read_key AGENT_SANDBOX_ENFORCED)"; enforced="${enforced:-false}"
case "$enforced" in true|false) ;; *) echo "review-package: AGENT_SANDBOX_ENFORCED must be true or false" >&2; exit 1 ;; esac
if [ "$mode" = standalone-clone ] && [ "$enforced" = true ]; then
  validation_result="$(python3 "$SKILL_DIR/bin/governed-validation.py" \
    --repo "$repo" --workspace "$workspace" --execution "$execution" \
    --team "$team" --task "$task" --task-key "$key" --attempt "$attempt" \
    --base "$base" --head "$head" --source-ref "$source_ref")" \
    || { echo "review-package: protected validation of the imported head failed" >&2; exit 1; }
  validation_evidence="$(printf '%s' "$validation_result" | python3 -c 'import json,sys; print(json.load(sys.stdin)["path"])')"
fi
out="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "artifacts/$key/review-$(git_unprivileged -C "$repo" rev-parse --short "$base")..$(git_unprivileged -C "$repo" rev-parse --short "$head").diff")"
bindings="${out%.diff}.bindings.json"
mkdir -p "$(dirname "$out")"
{
  echo "# Review package: $task"
  echo
  echo "Base: $base"
  echo "Head: $head"
  if [ "$mode" = standalone-clone ]; then echo "Quarantine ref: $source_ref"; fi
  if [ -n "$validation_evidence" ]; then
    echo
    echo "## Governed validation evidence"
    python3 - "$validation_evidence" <<'PY'
import os,stat,sys
path=sys.argv[1]; fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
try:
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size<=0 or info.st_size>1024*1024:
  raise SystemExit("review-package: governed validation evidence is unsafe")
 content=os.read(fd,info.st_size+1)
 if len(content)!=info.st_size: raise SystemExit("review-package: governed validation evidence changed while reading")
 sys.stdout.buffer.write(content)
finally: os.close(fd)
PY
  fi
  echo
  echo "## Commits"
  git_unprivileged -C "$repo" log --oneline "$base..$source_ref"
  echo
  echo "## Files changed"
  git_unprivileged -C "$repo" diff --stat "$base..$source_ref"
  echo
  echo "## Diff"
  git_unprivileged -C "$repo" diff -U10 "$base..$source_ref"
} > "$out"
python3 - "$out" "$bindings" "$base" "$head" "$validation_evidence" <<'PY'
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

package = Path(sys.argv[1])
destination = Path(sys.argv[2])
base, head, evidence = sys.argv[3:]
body = package.read_bytes()
record = {
    "schemaVersion": 1,
    "reviewBaseCommit": base,
    "taskBranchHead": head,
    "reviewPackagePath": str(package),
    "reviewPackageSha256": "sha256:" + hashlib.sha256(body).hexdigest(),
}
if evidence:
    evidence_path = Path(evidence)
    evidence_body = evidence_path.read_bytes()
    record["governedValidationPath"] = str(evidence_path)
    record["governedValidationSha256"] = "sha256:" + hashlib.sha256(evidence_body).hexdigest()
temporary = destination.with_name(f".{destination.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(temporary, flags, 0o600)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        descriptor = -1
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
echo "$out"
