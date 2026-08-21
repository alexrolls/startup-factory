#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW_TMP="$(mktemp -d)"
TMP="$(cd "$RAW_TMP" && pwd -P)"
trap 'rm -rf "$TMP"' EXIT
REPO="$TMP/repo"
SKILL="$REPO/.agent-squad"
CLONES="$TMP/protected-clones"
mkdir -p "$REPO" "$SKILL"
for item in bin config reference roles teams adapters extensions; do cp -R "$ROOT/$item" "$SKILL/$item"; done
cp "$ROOT/SKILL.md" "$SKILL/SKILL.md"

git -C "$REPO" init -q -b main
git -C "$REPO" config user.name Fixture
git -C "$REPO" config user.email fixture@example.invalid
printf 'base\n' > "$REPO/base.txt"
git -C "$REPO" add base.txt .agent-squad
git -C "$REPO" commit -qm base
git -C "$REPO" branch feature-runtime
python3 - "$SKILL/config/team.config.md" "$CLONES" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]); text=path.read_text()
text=text.replace("TASK_WORKTREE_MODE=linked-worktree", "TASK_WORKTREE_MODE=standalone-clone")
text=text.replace("BROKER_TASK_CLONE_ROOT=null", "BROKER_TASK_CLONE_ROOT="+sys.argv[2])
path.write_text(text)
PY

cd "$REPO"
TASK=T-standalone-1
KEY="$(python3 "$SKILL/bin/runtime-state.py" key "$TASK")"
BRANCH="agent-task/feature-runtime/$KEY"
WORKTREE="$($SKILL/bin/launch-team.sh worktree feature-runtime backend "$TASK" 1)"
test "$WORKTREE" = "$CLONES/feature-runtime/backend#1-$KEY"
test -d "$WORKTREE/.git"
test ! -e "$WORKTREE/.git/commondir"
test "$(git -C "$WORKTREE" rev-parse --absolute-git-dir)" != "$(git -C "$REPO" rev-parse --absolute-git-dir)"
printf 'task\n' > "$WORKTREE/task.txt"
git -C "$WORKTREE" add task.txt
git -C "$WORKTREE" commit -qm checkpoint

WORKSPACE="$REPO/.teamwork/feature-runtime"
mkdir -p "$WORKSPACE/executions" "$WORKSPACE/artifacts/$KEY"
BASE="$(git -C "$REPO" rev-parse feature-runtime)"
python3 - "$WORKSPACE/executions/$KEY.json" "$WORKTREE" "$TASK" "$KEY" "$BRANCH" "$BASE" <<'PY'
import json,sys
path,worktree,task,key,branch,base=sys.argv[1:]
json.dump({"schemaVersion":1,"featureId":"feature-runtime","taskId":task,"taskKey":key,
 "attempt":1,"role":"backend","branch":branch,"worktree":worktree,"worktreeMode":"standalone-clone",
 "baseCommit":base,"runtimeManifestDigest":"sha256:"+"a"*64},open(path,"w"))
PY
PACKAGE="$($SKILL/bin/review-package.sh feature-runtime "$TASK")"
grep -q '^Quarantine ref: refs/startup-factory/quarantine/' "$PACKAGE"
HEAD="$(git -C "$WORKTREE" rev-parse HEAD)"
test "$(git -C "$REPO" for-each-ref --points-at "$HEAD" --format='%(refname)' refs/startup-factory/quarantine/)" != ""

CAPABILITY="$(python3 "$SKILL/bin/outbox_capability.py" mint --repo "$REPO" --workspace "$WORKSPACE" \
  --team feature-runtime --feature feature-runtime --role backend --kind task --task "$TASK" --attempt 1 \
  --instance backend-standalone --task-worktree "$WORKTREE" --base-commit "$BASE" \
  --runtime-manifest-digest "sha256:$(printf a%.0s {1..64})")"
printf '[review-request]\nstandalone package ready\n' > "$WORKTREE/review.md"
CAP_ID="$(printf '%s' "$CAPABILITY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
CAP_SECRET="$(printf '%s' "$CAPABILITY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret"])')"
CAP_EXP="$(printf '%s' "$CAPABILITY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["expiresAt"])')"
(
  cd "$WORKTREE"
  STARTUP_FACTORY_EXECUTION_KIND=task STARTUP_FACTORY_TEAM=feature-runtime \
  STARTUP_FACTORY_FEATURE_ID=feature-runtime STARTUP_FACTORY_ROLE=backend \
  STARTUP_FACTORY_TASK_ID="$TASK" STARTUP_FACTORY_ATTEMPT=1 \
  STARTUP_FACTORY_INSTANCE=backend-standalone STARTUP_FACTORY_CANONICAL_REPO="$REPO" \
  STARTUP_FACTORY_CANONICAL_WORKSPACE="$WORKSPACE" STARTUP_FACTORY_TASK_WORKTREE="$WORKTREE" \
  STARTUP_FACTORY_OUTBOX_CAPABILITY_ID="$CAP_ID" STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET="$CAP_SECRET" \
  STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT="$CAP_EXP" \
  "$SKILL/bin/submit-artifact.sh" feature-runtime feature-runtime "$TASK" 1 backend review-request review.md Review >/dev/null
)
test "$(find "$WORKSPACE/outbox/pending" -type f -name '*.json' | wc -l | tr -d ' ')" = 1
echo "standalone launcher/review/outbox flow: PASS"
