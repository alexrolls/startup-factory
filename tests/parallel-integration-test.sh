#!/usr/bin/env bash
# End-to-end parallel branch integration and retry safety using the Markdown tracker.
set -euo pipefail

if sed --version >/dev/null 2>&1; then
  sed_i() { sed -i "$@"; }
else
  sed_i() { sed -i '' "$@"; }
fi

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_STATUS_FIXTURE="$SKILL_DIR/tests/fixtures/statuses.default-profile.json"
TMP="$(mktemp -d)"; TMP="$(cd "$TMP" && pwd -P)"; trap 'rm -rf "$TMP"' EXIT
FAILURES=0
check() { local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok: $desc"; else echo "FAIL: $desc"; FAILURES=$((FAILURES+1)); fi
}
refuse() { local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "FAIL: $desc"; FAILURES=$((FAILURES+1)); else echo "ok: $desc"; fi
}

mint_review_capability() { # role kind task attempt
  python3 .agent-squad/bin/outbox_capability.py mint \
    --repo "$PWD" --workspace "$PWD/.teamwork/feature-integration" \
    --team feature-integration --feature "$FID" --role "$1" --kind "$2" \
    --task "$3" --attempt "$4" --instance "fixture:$2:$1:$RANDOM:$RANDOM"
}

submit_authenticated_review() { # capability-json kind role fixed-task fixed-attempt task attempt marker body target
  local capability="$1" kind="$2" role="$3" fixed_task="$4" fixed_attempt="$5"
  local task="$6" attempt="$7" marker="$8" body="$9" target="${10}"
  local capability_id
  capability_id="$(printf '%s' "$capability" | python3 -c '
import json,sys
value=json.load(sys.stdin)
print(value["id"])
')"
  python3 - "$PWD" "$capability_id" "$role" "$task" "$attempt" "$marker" "$body" "$target" "$FID" <<'PY'
import json, os, secrets, sys
from datetime import datetime, timezone
from pathlib import Path

repo, handle, role, task, attempt, marker, source, target, feature = sys.argv[1:]
workspace = Path(repo) / ".teamwork" / "feature-integration"
pending = workspace / "outbox" / "pending"
bodies = workspace / "outbox" / "bodies"
pending.mkdir(parents=True, exist_ok=True)
bodies.mkdir(parents=True, exist_ok=True)
identifier = secrets.token_hex(16)
content = Path(source).read_bytes()
body = bodies / (identifier + ".md")
body.write_bytes(content)
body.chmod(0o600)
entry = {
    "schemaVersion": 1,
    "id": identifier,
    "team": "feature-integration",
    "featureId": feature,
    "taskId": task,
    "attempt": int(attempt),
    "actor": role,
    "marker": marker,
    "bodyPath": str(body),
    "targetStatus": None if target == "-" else target,
    "phase": "pending",
    "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
}
sys.path.insert(0, str(Path(repo) / ".agent-squad" / "bin"))
from outbox_capability import sign_active_entry
entry["producerCapability"] = sign_active_entry(
    repo, str(workspace), handle, entry, content
)
destination = pending / (identifier + ".json")
destination.write_text(json.dumps(entry, indent=2) + "\n")
destination.chmod(0o600)
PY
  .agent-squad/bin/process-outbox.sh feature-integration "$FID" >/dev/null
}

bind_review() {
  local task="$1" files="$2" key branch base head package package_digest snapshot prefix review_gates
  local execution attempt request_cap lead_cap architecture_cap sceptical_cap security_cap qa_cap
  local request_context lead_context architecture_context sceptical_context security_context qa_context
  key="$(python3 .agent-squad/bin/runtime-state.py key "$task")"
  branch="agent-task/feature-integration/$key"
  base="$(git merge-base feature-integration "$branch")"
  head="$(git rev-parse "$branch")"
  package="$(.agent-squad/bin/review-package.sh feature-integration "$task")"
  package_digest="sha256:$(shasum -a 256 "$package" | awk '{print $1}')"
  snapshot=".teamwork/feature-integration/tasks.json"
  prefix="$TMP/review-$key-$(date +%s)-$$"
  .agent-squad/bin/tracker-ops.sh export "$FID" "$snapshot" >/dev/null
  review_gates="$(PYTHONDONTWRITEBYTECODE=1 python3 - "$snapshot" "$task" "$PWD" "$base" "$head" "$PWD/.agent-squad/bin" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[6])
from delivery_profile import assess_review_diff
from task_metadata import effective_review_gates, parse_task_metadata
snapshot, task_id, repo, base, head = sys.argv[1:6]
task = next(item for item in json.load(open(snapshot))["tasks"] if str(item["taskId"]) == task_id)
decision = assess_review_diff(repo, base, head, task)
metadata = parse_task_metadata(task.get("description"), task.get("title"))
print(",".join(effective_review_gates(metadata, "", decision)))
PY
)"
  printf '[review-request] exact package review\nFiles: %s\n\n- backend\n' "$files" > "$prefix.request"
  printf '[team-lead-approval] exact package approved\nFiles: %s\n\n- team-lead\n' "$files" > "$prefix.lead"
  printf '[architecture-approval] exact package approved\nFiles: %s\n\n- principal-architect\n' "$files" > "$prefix.architecture"
  printf '[sceptical-architecture-approval] exact package approved\nFiles: %s\n\n- sceptical-architect\n' "$files" > "$prefix.sceptical"
  printf '[security-approval] exact package approved\nFiles: %s\n\n- senior-security-engineer\n' "$files" > "$prefix.security"
  printf '[review-approval] exact package approved\nFiles: %s\n\n- qa\n' "$files" > "$prefix.qa"
  .agent-squad/bin/review_evidence.py bind-request \
    "$prefix.request" "$base" "$head" "$package_digest" "$prefix.request.bound" \
    --review-gates "$review_gates"
  execution=".teamwork/feature-integration/executions/$key.json"
  attempt="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["attempt"])' "$execution")"
  request_cap="$(mint_review_capability backend task "$task" "$attempt")"
  submit_authenticated_review "$request_cap" task backend "$task" "$attempt" \
    "$task" "$attempt" review-request "$prefix.request.bound" Review
  .agent-squad/bin/tracker-ops.sh export "$FID" "$snapshot"
  lead_cap="$(mint_review_capability team-lead gate - 0)"
  architecture_cap="$(mint_review_capability principal-architect gate - 0)"
  sceptical_cap="$(mint_review_capability sceptical-architect gate - 0)"
  security_cap="$(mint_review_capability senior-security-engineer gate - 0)"
  qa_cap="$(mint_review_capability qa gate - 0)"
  lead_context="$(printf '%s' "$lead_cap" | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v["id"]+":"+v["instance"])')"
  architecture_context="$(printf '%s' "$architecture_cap" | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v["id"]+":"+v["instance"])')"
  sceptical_context="$(printf '%s' "$sceptical_cap" | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v["id"]+":"+v["instance"])')"
  security_context="$(printf '%s' "$security_cap" | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v["id"]+":"+v["instance"])')"
  qa_context="$(printf '%s' "$qa_cap" | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v["id"]+":"+v["instance"])')"
  .agent-squad/bin/review_evidence.py bind-approval \
    "$prefix.lead" "$snapshot" "$task" "$prefix.lead.bound" \
    team-lead "$lead_context"
  .agent-squad/bin/review_evidence.py bind-approval \
    "$prefix.architecture" "$snapshot" "$task" "$prefix.architecture.bound" \
    principal-architect "$architecture_context"
  .agent-squad/bin/review_evidence.py bind-approval \
    "$prefix.sceptical" "$snapshot" "$task" "$prefix.sceptical.bound" \
    sceptical-architect "$sceptical_context"
  .agent-squad/bin/review_evidence.py bind-approval \
    "$prefix.security" "$snapshot" "$task" "$prefix.security.bound" \
    senior-security-engineer "$security_context"
  .agent-squad/bin/review_evidence.py bind-approval \
    "$prefix.qa" "$snapshot" "$task" "$prefix.qa.bound" \
    qa "$qa_context"
  submit_authenticated_review "$architecture_cap" gate principal-architect - 0 \
    "$task" "$attempt" architecture-approval "$prefix.architecture.bound" -
  submit_authenticated_review "$sceptical_cap" gate sceptical-architect - 0 \
    "$task" "$attempt" sceptical-architecture-approval "$prefix.sceptical.bound" -
  case ",$review_gates," in *,security,*)
    submit_authenticated_review "$security_cap" gate senior-security-engineer - 0 \
      "$task" "$attempt" security-approval "$prefix.security.bound" - ;;
  esac
  case ",$review_gates," in *,qa,*)
    submit_authenticated_review "$qa_cap" gate qa - 0 \
      "$task" "$attempt" review-approval "$prefix.qa.bound" - ;;
  esac
  submit_authenticated_review "$lead_cap" gate team-lead - 0 \
    "$task" "$attempt" team-lead-approval "$prefix.lead.bound" -
  .agent-squad/bin/tracker-ops.sh export "$FID" "$snapshot"
}

cd "$TMP"; git init -q repo && cd repo
git checkout -q -b feature-integration
LIFECYCLE_ROOT="$TMP/protected-lifecycle"
mkdir -m 700 "$LIFECYCLE_ROOT"
PROTECTED_FORGERY_ROOT="$TMP/protected-forgery-lifecycle"
mkdir -m 700 "$PROTECTED_FORGERY_ROOT"
python3 "$SKILL_DIR/bin/process-lifecycle.py" init --root "$LIFECYCLE_ROOT" --repo "$(pwd)" >/dev/null
python3 "$SKILL_DIR/bin/process-lifecycle.py" init --root "$PROTECTED_FORGERY_ROOT" --repo "$(pwd)" >/dev/null
export STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$LIFECYCLE_ROOT"
git config user.email test@example.com; git config user.name Test
mkdir -p .agent-squad/{bin,config,roles,src} .workspace/task-manager
cp "$SKILL_DIR"/bin/*.sh "$SKILL_DIR"/bin/*.py .agent-squad/bin/
cp -R "$SKILL_DIR/src/startup_factory_cli" .agent-squad/src/
cp "$DEFAULT_STATUS_FIXTURE" .agent-squad/config/statuses.config.json
cp "$SKILL_DIR/config/automation.config.json" .agent-squad/config/
cp "$SKILL_DIR/roles/backend.md" .agent-squad/roles/
cat > .gitignore <<'EOF'
.teamwork/
.workspace/
/.startup-factory-retrospective.md
/.startup-factory-retrospective.lock
__pycache__/
EOF
echo base > app.txt
git add .gitignore app.txt .agent-squad
git commit -q -m init
cat > .agent-squad/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Markdown
MARKDOWN_ROOT=.
STATUS_CONFIG=config/statuses.config.json
```
EOF
cat > .agent-squad/config/team.config.md <<'EOF'
```
BACKEND_CMD="true"
TEAM_DEFAULT_CMD="true"
TEAMWORK_ROOT=.teamwork
AGENT_ENV_ALLOWLIST="PATH TMPDIR LANG LC_ALL TERM"
AGENT_SANDBOX_ENFORCED=false
BROKER_LIFECYCLE_ROOT=__LIFECYCLE_ROOT__
TRACKER_WRITERS=all
EXECUTION=parallel
MAX_ACTIVE_IMPLEMENTERS=2
VALIDATE_BUILD=null
VALIDATE_TEST="grep -q task-change app.txt"
VALIDATE_LINT=null
VALIDATE_FORMAT=null
```
EOF
sed_i "s|^BROKER_LIFECYCLE_ROOT=.*|BROKER_LIFECYCLE_ROOT=\"$LIFECYCLE_ROOT\"|" .agent-squad/config/team.config.md
git add .agent-squad/config/project-management.config.md .agent-squad/config/team.config.md
git commit -q -m config
cat > .workspace/task-manager/feature.md <<'EOF'
# Integration fixture [Active]

## 1 Change app [Review]

**Assignee:** backend

parallel-safe: true
files: app.txt

> [review-request] round: 1
> Files: app.txt
>
> - backend

> [team-lead-approval] round: 1
> Files: app.txt
>
> - team-lead

> [architecture-approval] round: 1
> Files: app.txt
>
> - principal-architect

> [sceptical-architecture-approval] round: 1
> Files: app.txt
>
> - sceptical-architect

> [security-approval] round: 1
> Files: app.txt
>
> - senior-security-engineer

## 3 Concurrent brokered change [Review]

**Assignee:** backend

parallel-safe: true
files: third.txt

> [review-request] round: 1
> Files: third.txt
>
> - backend

> [team-lead-approval] round: 1
> Files: third.txt
>
> - team-lead

> [architecture-approval] round: 1
> Files: third.txt
>
> - principal-architect

> [sceptical-architecture-approval] round: 1
> Files: third.txt
>
> - sceptical-architect

> [security-approval] round: 1
> Files: third.txt
>
> - senior-security-engineer
EOF

FID=.workspace/task-manager/feature.md
TID="$FID#1"
LAUNCH=.agent-squad/bin/launch-team.sh
prepare_task_claim() { # team feature task role attempt
  local team="$1" feature="$2" task="$3" role="$4" attempt="$5"
  local workspace snapshot target claim_id
  workspace="$PWD/.teamwork/$team"
  snapshot="$(mktemp "$TMP/claim-snapshot.XXXXXX")"
  .agent-squad/bin/tracker-ops.sh export "$feature" "$snapshot" >/dev/null
  target="$(python3 - "$snapshot" "$task" <<'PY'
import json
import sys

snapshot, task_id = sys.argv[1:]
matches = [
    task for task in json.load(open(snapshot, encoding="utf-8")).get("tasks", [])
    if str(task.get("taskId")) == task_id
]
if len(matches) != 1:
    raise SystemExit("claim fixture task is absent or duplicated")
status = matches[0].get("status")
if not isinstance(status, str) or not status.strip():
    raise SystemExit("claim fixture task has no concrete current status")
print(status)
PY
)"
  claim_id="$(python3 - "$team" "$feature" "$task" "$role" "$attempt" "$target" <<'PY'
import hashlib
import sys

print("dispatch-" + hashlib.sha256("\0".join(sys.argv[1:]).encode()).hexdigest()[:32])
PY
)"
  python3 .agent-squad/bin/runtime-state.py claim \
    --repo "$PWD" --workspace "$workspace" --team "$team" \
    --feature "$feature" --task "$task" --role "$role" --attempt "$attempt" \
    --claim-id "$claim_id" --target "$target" >/dev/null
  printf '[claim]\nclaim-id: %s\nrole: %s\ntarget-status: %s\n\n— dispatcher\n' \
    "$claim_id" "$role" "$target" | \
    .agent-squad/bin/tracker-ops.sh comment "$task" - >/dev/null
  rm -f "$snapshot"
}
write_task_hold() {
  python3 - ".teamwork/feature-integration/task-holds.json" "$FID" "$1" "$2" <<'PY'
import hashlib,json,re,sys
path,feature,task,state=sys.argv[1:]
slug=re.sub(r"[^a-zA-Z0-9]+","-",task).strip("-").lower()[:32] or "task"
key="%s-%s"%(slug,hashlib.sha256(task.encode()).hexdigest()[:10])
json.dump({"schemaVersion":1,"featureId":feature,"tasks":{
    key:{"taskId":task,"taskKey":key,"state":state}
}},open(path,"w"))
PY
}
clear_task_hold() { rm -f .teamwork/feature-integration/task-holds.json; }
clear_protected_task_hold_fixture() {
  python3 - "$LIFECYCLE_ROOT" "$PWD" "$FID" <<'PY'
import hashlib,json,os,stat,sys
from pathlib import Path

root, repository, feature = map(Path, sys.argv[1:])
root = root.resolve(strict=True)
repository = repository.resolve(strict=True)
if stat.S_IMODE(root.lstat().st_mode) != 0o700:
    raise SystemExit("fixture lifecycle root is not private")
material = {
    "repository": str(repository),
    "team": "feature-integration",
    "featureId": str(feature),
}
identity = hashlib.sha256(
    json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
).hexdigest()
path = root / "task-holds" / (identity + ".json")
try:
    info = path.lstat()
except FileNotFoundError:
    raise SystemExit("fixture protected hold record is missing")
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
    raise SystemExit("fixture protected hold record is not a regular file")
path.unlink()
PY
}
prepare_task_claim feature-integration "$FID" "$TID" backend 1
wt="$($LAUNCH worktree feature-integration "$FID" backend "$TID" 1)"
.agent-squad/bin/task-packet.sh feature-integration "$FID" "$TID" backend 1 "$wt" "agent-task/feature-integration/$(python3 .agent-squad/bin/runtime-state.py key "$TID")" >/dev/null
echo task-change > "$wt/app.txt"
git -C "$wt" add app.txt
git -C "$wt" commit -q -m 'task checkpoint'
reviewed_head="$(git -C "$wt" rev-parse HEAD)"
package="$(.agent-squad/bin/review-package.sh feature-integration "$TID")"
check "review package contains task diff" grep -q '^+task-change$' "$package"
refuse "direct tracker review comments cannot authorize integration" \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID" backend 1
bind_review "$TID" app.txt

# Advancing the task branch after review must invalidate the old approvals even
# when the attacker changes only a previously approved filename.
echo post-review-change >> "$wt/app.txt"
git -C "$wt" add app.txt
git -C "$wt" commit -q -m 'unreviewed same-file checkpoint'
refuse "branch movement invalidates exact review approvals" \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID" backend 1
bind_review "$TID" app.txt
reviewed_head="$(git -C "$wt" rev-parse HEAD)"

.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID" backend 1 >/dev/null
check "feature branch receives task change" grep -q '^task-change$' app.txt
check "integration preserves reviewed task head" test "$(git rev-parse "agent-task/feature-integration/$(python3 .agent-squad/bin/runtime-state.py key "$TID")")" = "$reviewed_head"
check "integration commit has task trailer" git log -1 --format=%B --grep="Task-Id: $TID"
check "tracker reaches terminal status" grep -q '^## 1 Change app \[Ready to deploy\]$' "$FID"
key="$(python3 .agent-squad/bin/runtime-state.py key "$TID")"
check "integration transaction completes" grep -q '"phase": "completed"' ".teamwork/feature-integration/integrations/$key.json"
check "completed task records a project retrospective" \
  grep -q "### \\[task\\] \`$TID\`" .startup-factory-retrospective.md
check "project retrospective is ignored by Git" \
  git check-ignore -q .startup-factory-retrospective.md
check "worktree is removed last" test ! -d "$wt"
before="$(git rev-list --count HEAD)"
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID" backend 1 >/dev/null
after="$(git rev-list --count HEAD)"
check "integration retry creates no duplicate commit" test "$before" -eq "$after"
check "integration retry creates no duplicate tracker comment" test "$(grep -c 'Integrated: commit' "$FID")" -eq 1

# Default-safe broker mode: the credentialless integrator stops after the exact
# merge transaction; the locked dispatcher owns tracker finalization + cleanup.
perl -0pi -e 's/TRACKER_WRITERS=all/TRACKER_WRITERS=broker/' .agent-squad/config/team.config.md
git add .agent-squad/config/team.config.md
git commit -q -m 'use tracker broker'
cat >> "$FID" <<'EOF'

## 2 Brokered change [Review]

**Assignee:** backend

parallel-safe: true
files: second.txt

> [review-request] round: 1
> Files: second.txt
>
> - backend

> [team-lead-approval] round: 1
> Files: second.txt
>
> - team-lead

> [architecture-approval] round: 1
> Files: second.txt
>
> - principal-architect

> [sceptical-architecture-approval] round: 1
> Files: second.txt
>
> - sceptical-architect

> [security-approval] round: 1
> Files: second.txt
>
> - senior-security-engineer
EOF

TID2="$FID#2"
prepare_task_claim feature-integration "$FID" "$TID2" backend 1
wt2="$($LAUNCH worktree feature-integration "$FID" backend "$TID2" 1)"
.agent-squad/bin/task-packet.sh feature-integration "$FID" "$TID2" backend 1 "$wt2" "agent-task/feature-integration/$(python3 .agent-squad/bin/runtime-state.py key "$TID2")" >/dev/null
echo brokered > "$wt2/second.txt"
git -C "$wt2" add second.txt
git -C "$wt2" commit -q -m 'brokered checkpoint'
TID3="$FID#3"
prepare_task_claim feature-integration "$FID" "$TID3" backend 1
wt3="$($LAUNCH worktree feature-integration "$FID" backend "$TID3" 1)"
.agent-squad/bin/task-packet.sh feature-integration "$FID" "$TID3" backend 1 "$wt3" "agent-task/feature-integration/$(python3 .agent-squad/bin/runtime-state.py key "$TID3")" >/dev/null
echo concurrent > "$wt3/third.txt"
git -C "$wt3" add third.txt
git -C "$wt3" commit -q -m 'concurrent checkpoint'
bind_review "$TID2" second.txt
bind_review "$TID3" third.txt
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 1 >/dev/null
key2="$(python3 .agent-squad/bin/runtime-state.py key "$TID2")"
tx2=".teamwork/feature-integration/integrations/$key2.json"
prep2=".teamwork/feature-integration/integrations/.prepared/$key2.json"
head_before_hold="$(git rev-parse HEAD)"

# Direct mutation entrypoints must bind every authority-bearing ambient value
# to the installed config before they touch Git, tracker state, or holds.
refuse "integrator rejects lifecycle authority replacement" \
  env STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$PROTECTED_FORGERY_ROOT" \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 1
refuse "integrator rejects tracker adapter replacement" \
  env TRACKER_ADAPTER=GitHubIssues \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 1
refuse "integrator rejects human-work policy replacement" \
  env STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON='[]' \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 1
refuse "finalizer rejects lifecycle authority replacement" \
  env STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$PROTECTED_FORGERY_ROOT" \
  .agent-squad/bin/finalize-integrations.sh --authorize-prepared \
    feature-integration "$FID" "$prep2"
refuse "finalizer rejects tracker adapter replacement" \
  env TRACKER_ADAPTER=GitHubIssues \
  .agent-squad/bin/finalize-integrations.sh --authorize-prepared \
    feature-integration "$FID" "$prep2"
refuse "finalizer rejects human-work policy replacement" \
  env STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON='[]' \
  .agent-squad/bin/finalize-integrations.sh --authorize-prepared \
    feature-integration "$FID" "$prep2"
check "authority replacement attempts leave the feature branch untouched" \
  test "$(git rev-parse HEAD)" = "$head_before_hold"

# A protected hold wins over an agent-forged workspace projection. Keep the
# tracker in Review to prove this denial is authority-driven, not a status
# side effect, and exercise both the authorization and merge boundaries.
cat > "$TMP/protected-blocked.json" <<EOF
{"featureId":"$FID","tasks":[{"taskId":"$TID2","title":"fixture","description":"fixture","status":"Blocked","statusRaw":"Blocked","assignee":"backend","blockedBy":[],"labels":[],"comments":[],"attachments":[]}]}
EOF
STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$LIFECYCLE_ROOT" \
  python3 .agent-squad/bin/task-hold.py sync \
  --repo "$(pwd)" --workspace "$(pwd)/.teamwork/feature-integration" \
  --tasks "$TMP/protected-blocked.json" --feature "$FID" --team feature-integration \
  --blocked-status Blocked --queued-status Planned \
  --inflight-status Planned --inflight-status Active --inflight-status Review \
  --ignored-labels-json '["human-work"]' >/dev/null
write_task_hold "$TID2" resumed
refuse "protected hold blocks pre-merge authorization despite forged local resume" \
  env STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$LIFECYCLE_ROOT" \
  .agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" "$prep2"
refuse "protected hold blocks the merger despite forged local resume" \
  env STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$LIFECYCLE_ROOT" \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 1
check "protected merge denial leaves the feature branch untouched" test "$(git rev-parse HEAD)" = "$head_before_hold"
clear_task_hold
# The protected record above exists only to exercise this denial boundary. The
# rest of this fixture tests independent local-registry failure modes, so remove
# that one exact authenticated fixture record before continuing.
clear_protected_task_hold_fixture

write_task_hold "$TID2" blocked
refuse "held task cannot receive pre-merge broker authorization" \
  .agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" "$prep2"
check "held authorization attempt cannot move the feature branch" test "$(git rev-parse HEAD)" = "$head_before_hold"

printf '{not-json\n' > .teamwork/feature-integration/task-holds.json
refuse "malformed hold registry blocks pre-merge authorization" \
  .agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" "$prep2"
python3 - .teamwork/feature-integration/task-holds-target.json "$FID" <<'PY'
import json,sys
json.dump({"schemaVersion":1,"featureId":sys.argv[2],"tasks":{}},open(sys.argv[1],"w"))
PY
clear_task_hold
ln -s "$(pwd)/.teamwork/feature-integration/task-holds-target.json" \
  .teamwork/feature-integration/task-holds.json
refuse "symlink hold registry blocks pre-merge authorization" \
  .agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" "$prep2"
clear_task_hold
python3 - .teamwork/feature-integration/task-holds.json <<'PY'
import json,sys
json.dump({"schemaVersion":1,"featureId":"other-feature","tasks":{}},open(sys.argv[1],"w"))
PY
refuse "cross-feature hold registry blocks pre-merge authorization" \
  .agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" "$prep2"
clear_task_hold
rm -f .teamwork/feature-integration/task-holds-target.json
.agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" \
  "$prep2" >/dev/null

# Direct/standalone integration has no PM supervisor environment. The broker's
# safe default must still treat human-work as a hard automation reservation.
perl -0pi -e 's/(## 2 Brokered change \[Review\]\n\n\*\*Assignee:\*\* backend\n)/$1\n**Labels:** human-work\n/' "$FID"
refuse "standalone merger defaults human-work to reserved" \
  env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON -u STARTUP_FACTORY_LIFECYCLE_STATE_ROOT \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 1
check "human-work merge fence leaves the feature branch untouched" test "$(git rev-parse HEAD)" = "$head_before_hold"
perl -0pi -e 's/\n\*\*Labels:\*\* human-work\n//' "$FID"

# Registry state is re-read by the actual merger, not only by the earlier
# authorization broker. No resume-review exception exists for integration.
write_task_hold "$TID2" resume-review-pending
refuse "resume-review hold blocks an already-authorized merge" \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 1
check "held merge leaves the feature branch untouched" test "$(git rev-parse HEAD)" = "$head_before_hold"
clear_task_hold

# A just-moved tracker status can precede the next dispatcher registry sync.
# The merger must therefore export PM state itself and fail closed on semantic
# Blocked even while task-holds.json is absent.
perl -0pi -e 's/## 2 Brokered change \[Review\]/## 2 Brokered change [Blocked]/' "$FID"
refuse "fresh tracker fence blocks merge before the registry catches up" \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 1
check "authoritative Blocked fence leaves the feature branch untouched" test "$(git rev-parse HEAD)" = "$head_before_hold"
perl -0pi -e 's/## 2 Brokered change \[Blocked\]/## 2 Brokered change [Review]/' "$FID"
perl -0pi -e 's/## 2 Brokered change \[Review\]/## 2 Brokered change [Planned]/' "$FID"
refuse "manual Blocked-to-Planned drift cannot bypass the semantic review fence" \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 1
check "non-review status drift leaves the feature branch untouched" test "$(git rev-parse HEAD)" = "$head_before_hold"
perl -0pi -e 's/## 2 Brokered change \[Planned\]/## 2 Brokered change [Review]/' "$FID"
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 1 >/dev/null
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID3" backend 1 >/dev/null
key3="$(python3 .agent-squad/bin/runtime-state.py key "$TID3")"
tx3=".teamwork/feature-integration/integrations/$key3.json"
.agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" \
  ".teamwork/feature-integration/integrations/.prepared/$key3.json" >/dev/null
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID3" backend 1 >/dev/null
check "broker mode records awaiting-tracker transaction" grep -q '"phase": "awaiting-tracker"' "$tx2"
check "broker mode does not move tracker from credentialless integrator" grep -q '^## 2 Brokered change \[Review\]$' "$FID"
check "broker mode retains worktree until tracker finalization" test -d "$wt2"
check "transaction binds exact reviewed task head" grep -q '"taskBranchHead": "[0-9a-f]\{40\}"' "$tx2"
check "transaction binds review package digest" grep -q '"reviewPackageSha256": "sha256:[0-9a-f]\{64\}"' "$tx2"
check "transaction binds current approval evidence" grep -q '"approvalEvidenceDigest": "sha256:[0-9a-f]\{64\}"' "$tx2"
check "parallel transaction separates integration parent from review base" python3 - "$tx3" <<'PY'
import json, sys
value=json.load(open(sys.argv[1]))
raise SystemExit(0 if value['baseCommit'] != value['reviewBaseCommit'] else 1)
PY

# A transaction cannot bless an arbitrary merge tree merely by naming the
# reviewed commit as parent two. Rebuild the same two-parent commit with one
# injected file, move the temporary feature ref to it, and prove validation
# rejects the tree before any tracker mutation.
real_feature_head="$(git rev-parse feature-integration)"
real_tx3="$tx3.real"
mv "$tx3" "$real_tx3"
forged_index="$TMP/forged-integration.index"
rm -f "$forged_index"
GIT_INDEX_FILE="$forged_index" git read-tree "$real_feature_head^{tree}"
injected_blob="$(printf 'unreviewed injection\n' | git hash-object -w --stdin)"
GIT_INDEX_FILE="$forged_index" git update-index --add --cacheinfo 100644 "$injected_blob" unreviewed-injected.txt
forged_tree="$(GIT_INDEX_FILE="$forged_index" git write-tree)"
python3 - "$real_tx3" "$TMP/forged-message" <<'PY'
import json,subprocess,sys
transaction=json.load(open(sys.argv[1]))
with open(sys.argv[2],"w") as handle:
    handle.write(subprocess.check_output(
        ["git","show","-s","--format=%B",transaction["commit"]],text=True
    ))
PY
forged_commit="$(git commit-tree "$forged_tree" \
  -p "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["baseCommit"])' "$real_tx3")" \
  -p "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["taskBranchHead"])' "$real_tx3")" \
  < "$TMP/forged-message")"
python3 - "$real_tx3" "$tx3" "$forged_commit" <<'PY'
import hashlib,json,sys
source,target,commit=sys.argv[1:]
data=json.load(open(source)); data["commit"]=commit
material={name:data[name] for name in (
    "team","featureId","taskId","attempt","executionDigest","baseCommit",
    "reviewBaseCommit","taskBranchHead","commit","reviewPackageSha256",
    "approvalEvidenceDigest",
)}
canonical=json.dumps(material,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
data["transactionId"]="integration-"+hashlib.sha256(canonical).hexdigest()[:32]
json.dump(data,open(target,"w"),indent=2); open(target,"a").write("\n")
PY
git update-ref refs/heads/feature-integration "$forged_commit" "$real_feature_head"
refuse "broker rejects a two-parent integration commit with an injected tree" \
  .agent-squad/bin/finalize-integrations.sh --validate-only feature-integration "$FID" "$tx3"
git update-ref refs/heads/feature-integration "$real_feature_head" "$forged_commit"
rm -f "$tx3"
mv "$real_tx3" "$tx3"
check "injected-tree rejection leaves tracker in review" grep -q '^## 3 Concurrent brokered change \[Review\]$' "$FID"

# The same protected hold remains authoritative after a merge transaction was
# created. Forging the local projection to resumed cannot authorize tracker
# finalization or cleanup.
STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$LIFECYCLE_ROOT" \
  python3 .agent-squad/bin/task-hold.py sync \
  --repo "$(pwd)" --workspace "$(pwd)/.teamwork/feature-integration" \
  --tasks "$TMP/protected-blocked.json" --feature "$FID" --team feature-integration \
  --blocked-status Blocked --queued-status Planned \
  --inflight-status Planned --inflight-status Active --inflight-status Review \
  --ignored-labels-json '["human-work"]' >/dev/null
write_task_hold "$TID2" resumed
refuse "protected hold blocks finalization despite forged local resume" \
  env STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$LIFECYCLE_ROOT" \
  .agent-squad/bin/finalize-integrations.sh feature-integration "$FID" "$tx2"
check "protected finalization denial preserves awaiting tracker" grep -q '"phase": "awaiting-tracker"' "$tx2"
check "protected finalization denial preserves the task worktree" test -d "$wt2"
clear_task_hold
clear_protected_task_hold_fixture

perl -0pi -e 's/(## 2 Brokered change \[Review\]\n\n\*\*Assignee:\*\* backend\n)/$1\n**Labels:** human-work\n/' "$FID"
refuse "standalone finalizer defaults human-work to reserved" \
  env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON -u STARTUP_FACTORY_LIFECYCLE_STATE_ROOT \
  .agent-squad/bin/finalize-integrations.sh feature-integration "$FID" "$tx2"
check "human-work finalization fence preserves awaiting tracker" grep -q '"phase": "awaiting-tracker"' "$tx2"
perl -0pi -e 's/\n\*\*Labels:\*\* human-work\n//' "$FID"

write_task_hold "$TID2" manual-takeover
refuse "manual-takeover hold blocks tracker finalization of an existing merge" \
  .agent-squad/bin/finalize-integrations.sh feature-integration "$FID" "$tx2"
check "held finalization leaves tracker state in review" grep -q '^## 2 Brokered change \[Review\]$' "$FID"
check "held finalization preserves awaiting-tracker transaction" grep -q '"phase": "awaiting-tracker"' "$tx2"
check "held finalization preserves the task worktree" test -d "$wt2"
clear_task_hold

# Simulate a PM move in the narrow window after the broker's pass-level export
# but before tracker-ops integrate. The per-write fresh fence must observe the
# second state even though the first authorization snapshot still said Review.
mv .agent-squad/bin/tracker-ops.sh .agent-squad/bin/tracker-ops.sh.real
cat > .agent-squad/bin/tracker-ops.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
real="$(dirname "$0")/tracker-ops.sh.real"
if [ "${1:-}" = export ] && [ ! -e .teamwork/feature-integration/finalizer-race-once ]; then
  "$real" "$@"
  : > .teamwork/feature-integration/finalizer-race-once
  perl -0pi -e 's/## 2 Brokered change \[Review\]/## 2 Brokered change [Blocked]/' "$2"
  exit 0
fi
exec "$real" "$@"
EOF
chmod +x .agent-squad/bin/tracker-ops.sh
refuse "per-write fresh tracker fence catches Blocked after pass authorization" \
  .agent-squad/bin/finalize-integrations.sh feature-integration "$FID" "$tx2"
check "finalizer race fence prevents terminal tracker mutation" grep -q '^## 2 Brokered change \[Blocked\]$' "$FID"
check "finalizer race fence leaves transaction awaiting tracker" grep -q '"phase": "awaiting-tracker"' "$tx2"
mv .agent-squad/bin/tracker-ops.sh.real .agent-squad/bin/tracker-ops.sh
rm -f .teamwork/feature-integration/finalizer-race-once
perl -0pi -e 's/## 2 Brokered change \[Blocked\]/## 2 Brokered change [Review]/' "$FID"

cat >> "$FID" <<'EOF'

> [review-findings] late finding after approval
> Files: second.txt
>
> - reviewer
EOF
if .agent-squad/bin/finalize-integrations.sh feature-integration "$FID" "$tx2"; then
  echo "ok: broker durably supersedes approvals invalidated after the merge"
else
  echo "FAIL: broker durably supersedes approvals invalidated after the merge"
  FAILURES=$((FAILURES+1))
fi
check "late invalidation preserves original transaction in history" \
  bash -c 'test "$(find .teamwork/feature-integration/integrations/history -name "*integration-*.json" | wc -l | tr -d " ")" -ge 1'
check "late invalidation creates an explicit revert commit" \
  git log -1 --format=%B --grep='Integration-Recovery:'
check "late invalidation returns tracker task to queued rework" grep -q '^## 2 Brokered change \[Planned\]$' "$FID"
check "superseded canonical transaction is retired" test ! -e "$tx2"

# Rework proceeds from the preserved history: a new attempt adds a fix, receives
# a new request with fresh core/declared-gate approval after the finding, and integrates normally.
$LAUNCH worktree-remove feature-integration backend "$TID2" 1 >/dev/null
prepare_task_claim feature-integration "$FID" "$TID2" backend 2
wt2="$($LAUNCH worktree feature-integration "$FID" backend "$TID2" 2)"
.agent-squad/bin/task-packet.sh feature-integration "$FID" "$TID2" backend 2 "$wt2" "agent-task/feature-integration/$(python3 .agent-squad/bin/runtime-state.py key "$TID2")" >/dev/null
.agent-squad/bin/tracker-ops.sh state "$TID2" Active >/dev/null
echo fixed-after-late-finding >> "$wt2/second.txt"
git -C "$wt2" add second.txt
git -C "$wt2" commit -q -m 'late-finding rework checkpoint'
# Preserve both histories and resolve the expected modify/delete divergence
# created by the explicit feature-branch revert. No reset/force-update occurs.
if ! git -C "$wt2" merge --no-edit feature-integration >/dev/null 2>&1; then
  git -C "$wt2" add second.txt
  git -C "$wt2" commit -q -m 'resolve rework against preserved revert'
fi
.agent-squad/bin/tracker-ops.sh state "$TID2" Review >/dev/null
bind_review "$TID2" second.txt
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 2 >/dev/null
.agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" \
  ".teamwork/feature-integration/integrations/.prepared/$key2.json" >/dev/null
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID2" backend 2 >/dev/null
check "late-finding rework reaches a new awaiting-tracker transaction" grep -q '"phase": "awaiting-tracker"' "$tx2"

cp "$tx2" "$tx2.backup"
perl -0pi -e 's/"phase": "awaiting-tracker"/"phase": "completed"/' "$tx2"
refuse "broker rejects producer-forged completed phase" \
  .agent-squad/bin/finalize-integrations.sh feature-integration "$FID" "$tx2"
mv "$tx2.backup" "$tx2"

.agent-squad/bin/dispatch.sh feature-integration "$FID" --once --unblock=off >/dev/null
check "dispatcher broker performs terminal tracker move" grep -q '^## 2 Brokered change \[Ready to deploy\]$' "$FID"
check "dispatcher broker finalizes branch reviewed before prior merge" grep -q '^## 3 Concurrent brokered change \[Ready to deploy\]$' "$FID"
check "dispatcher broker completes transaction after cleanup" grep -q '"phase": "completed"' "$tx2"
check "dispatcher broker removes worktree last" test ! -d "$wt2"
check "dispatcher broker removes concurrent worktree" test ! -d "$wt3"
check "dispatcher emits broker-owned integration event" python3 - ".teamwork/feature-integration/events.ndjson" "$TID2" <<'PY'
import json, sys
events=[json.loads(line) for line in open(sys.argv[1])]
matches=[e for e in events if e.get('type') == 'task.integrated' and e.get('taskId') == sys.argv[2]]
raise SystemExit(0 if len(matches) == 1 and matches[0].get('actor') == 'dispatcher' else 1)
PY

comment_count="$(grep -c 'Integrated: commit' "$FID")"
event_count="$(python3 - ".teamwork/feature-integration/events.ndjson" "$TID2" <<'PY'
import json, sys
print(sum(1 for line in open(sys.argv[1]) if (lambda e: e.get('type') == 'task.integrated' and e.get('taskId') == sys.argv[2])(json.loads(line))))
PY
)"
.agent-squad/bin/dispatch.sh feature-integration "$FID" --once --unblock=off >/dev/null
check "broker retry creates no duplicate integration comment" test "$(grep -c 'Integrated: commit' "$FID")" -eq "$comment_count"
check "broker retry creates no duplicate integration event" test "$(python3 - ".teamwork/feature-integration/events.ndjson" "$TID2" <<'PY'
import json, sys
print(sum(1 for line in open(sys.argv[1]) if (lambda e: e.get('type') == 'task.integrated' and e.get('taskId') == sys.argv[2])(json.loads(line))))
PY
)" -eq "$event_count"

cp "$tx2" "$tx2.backup"
perl -0pi -e 's/("reviewPackageSha256": "sha256:)[0-9a-f]{64}/$1 . ("0" x 64)/e' "$tx2"
refuse "broker rejects a forged review package binding" \
  .agent-squad/bin/finalize-integrations.sh --validate-only feature-integration "$FID" "$tx2"
mv "$tx2.backup" "$tx2"
cp "$tx2" "$tx2.backup"
perl -0pi -e 's/("approvalEvidenceDigest": "sha256:)[0-9a-f]{64}/$1 . ("0" x 64)/e' "$tx2"
refuse "broker rejects a forged approval evidence binding" \
  .agent-squad/bin/finalize-integrations.sh --validate-only feature-integration "$FID" "$tx2"
mv "$tx2.backup" "$tx2"

printf 'PROTOCOL_TEAM_LEAD=team-lead\n' > .teamwork/feature-integration/preset.env
refuse "integration refuses a preset missing mandatory review-board mappings" \
  .agent-squad/bin/finalize-integrations.sh --validate-only feature-integration "$FID" "$tx2"
cat >> .teamwork/feature-integration/preset.env <<'EOF'
PROTOCOL_PRINCIPAL_ARCHITECT=principal-architect
PROTOCOL_SCEPTICAL_ARCHITECT=other-sceptical-architect
PROTOCOL_SECURITY_REVIEWER=senior-security-engineer
EOF
refuse "integration binds approval to the mandatory Sceptical Architect identity" \
  .agent-squad/bin/finalize-integrations.sh feature-integration "$FID" "$tx2"
rm .teamwork/feature-integration/preset.env

printf '{"schemaVersion":1,"phase":"awaiting-tracker"}\n' > .teamwork/feature-integration/integrations/forged.json
refuse "broker rejects malformed transaction before tracker writes" \
  .agent-squad/bin/finalize-integrations.sh feature-integration "$FID"
rm .teamwork/feature-integration/integrations/forged.json
ln -s "$(pwd)/$tx2" .teamwork/feature-integration/integrations/symlink.json
refuse "broker rejects symlink transaction" \
  .agent-squad/bin/finalize-integrations.sh feature-integration "$FID"
rm .teamwork/feature-integration/integrations/symlink.json

# SIGKILL recovery: the preparation journal exists before Git mutation. A
# retry recognizes both an interrupted --no-commit merge and a landed merge
# commit whose final transaction write never ran.
cat >> "$FID" <<'EOF'

## 4 Crash during merge [Review]

**Assignee:** backend

parallel-safe: true
files: crash-merge.txt

## 5 Crash after commit [Review]

**Assignee:** backend

parallel-safe: true
files: crash-commit.txt
EOF

TID4="$FID#4"; key4="$(python3 .agent-squad/bin/runtime-state.py key "$TID4")"
prepare_task_claim feature-integration "$FID" "$TID4" backend 1
wt4="$($LAUNCH worktree feature-integration "$FID" backend "$TID4" 1)"
.agent-squad/bin/task-packet.sh feature-integration "$FID" "$TID4" backend 1 "$wt4" \
  "agent-task/feature-integration/$key4" >/dev/null
echo recover-merge > "$wt4/crash-merge.txt"; git -C "$wt4" add crash-merge.txt
git -C "$wt4" commit -q -m 'merge crash fixture'; bind_review "$TID4" crash-merge.txt
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID4" backend 1 >/dev/null
prep4=".teamwork/feature-integration/integrations/.prepared/$key4.json"
.agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" "$prep4" >/dev/null
refuse "SIGKILL lands in the journaled merge window" env INTEGRATION_TEST_CRASH_AT=after-merge \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID4" backend 1
check "crashed merge retains its durable preparation" test -f "$prep4"
check "crashed merge is recognizable through MERGE_HEAD" git rev-parse -q --verify MERGE_HEAD
perl -0pi -e 's/## 4 Crash during merge \[Review\]/## 4 Crash during merge [Blocked]/' "$FID"
refuse "fresh tracker fence catches Blocked after merge and before commit" \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID4" backend 1
refuse "Blocked-after-merge safely clears MERGE_HEAD" git rev-parse -q --verify MERGE_HEAD
check "Blocked-after-merge restores a clean feature checkout" \
  bash -c 'test -z "$(git status --porcelain -uno)"'
perl -0pi -e 's/## 4 Crash during merge \[Blocked\]/## 4 Crash during merge [Review]/' "$FID"

# Prove the aborted merge does not strand unrelated delivery. A sibling uses
# the real integration broker and reaches its merge window immediately. Crash
# it there deliberately, then clean up its fixture without moving feature HEAD,
# so the original task can resume from its still-valid preparation.
cat >> "$FID" <<'EOF'

## 6 Sibling after Blocked abort [Review]

**Assignee:** backend

parallel-safe: true
files: sibling-after-block.txt
EOF
TID6="$FID#6"; key6="$(python3 .agent-squad/bin/runtime-state.py key "$TID6")"
prepare_task_claim feature-integration "$FID" "$TID6" backend 1
wt6="$($LAUNCH worktree feature-integration "$FID" backend "$TID6" 1)"
.agent-squad/bin/task-packet.sh feature-integration "$FID" "$TID6" backend 1 "$wt6" \
  "agent-task/feature-integration/$key6" >/dev/null
echo sibling-after-block > "$wt6/sibling-after-block.txt"
git -C "$wt6" add sibling-after-block.txt
git -C "$wt6" commit -q -m 'sibling after blocked abort fixture'
bind_review "$TID6" sibling-after-block.txt
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID6" backend 1 >/dev/null
prep6=".teamwork/feature-integration/integrations/.prepared/$key6.json"
.agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" "$prep6" >/dev/null
refuse "sibling can enter integration immediately after Blocked abort" env INTEGRATION_TEST_CRASH_AT=after-merge \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID6" backend 1
check "sibling reached the real merge window" git rev-parse -q --verify MERGE_HEAD
git merge --abort >/dev/null
rm -f "$prep6"
$LAUNCH worktree-remove feature-integration backend "$TID6" 1 >/dev/null
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID4" backend 1 >/dev/null
tx4=".teamwork/feature-integration/integrations/$key4.json"
check "retry completes interrupted merge exactly once" grep -q '"phase": "awaiting-tracker"' "$tx4"
refuse "retry leaves no in-progress merge" git rev-parse -q --verify MERGE_HEAD
.agent-squad/bin/finalize-integrations.sh feature-integration "$FID" "$tx4" >/dev/null
printf '[review-findings] legitimate finding after tracker finalization, before release\nFiles: crash-merge.txt\n\n- reviewer\n' \
  | .agent-squad/bin/tracker-ops.sh comment "$TID4" - >/dev/null
check "completed integration can be durably superseded before release" \
  .agent-squad/bin/finalize-integrations.sh feature-integration "$FID" "$tx4"
check "completed-task recovery uses the broker-only queued reopen" \
  grep -q '^## 4 Crash during merge \[Planned\]$' "$FID"
check "completed invalidation retires canonical transaction without erasing history" test ! -e "$tx4"
check "completed invalidation remains available as preserved evidence" \
  bash -c 'find .teamwork/feature-integration/integrations/history -name "*integration-*.json" | grep -q .'

TID5="$FID#5"; key5="$(python3 .agent-squad/bin/runtime-state.py key "$TID5")"
prepare_task_claim feature-integration "$FID" "$TID5" backend 1
wt5="$($LAUNCH worktree feature-integration "$FID" backend "$TID5" 1)"
.agent-squad/bin/task-packet.sh feature-integration "$FID" "$TID5" backend 1 "$wt5" \
  "agent-task/feature-integration/$key5" >/dev/null
echo recover-commit > "$wt5/crash-commit.txt"; git -C "$wt5" add crash-commit.txt
git -C "$wt5" commit -q -m 'commit crash fixture'; bind_review "$TID5" crash-commit.txt
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID5" backend 1 >/dev/null
prep5=".teamwork/feature-integration/integrations/.prepared/$key5.json"
.agent-squad/bin/finalize-integrations.sh --authorize-prepared feature-integration "$FID" "$prep5" >/dev/null
head_before_crash="$(git rev-parse HEAD)"
first_parent_before="$(git rev-list --first-parent --count HEAD)"
refuse "SIGKILL lands after commit but before final transaction" env INTEGRATION_TEST_CRASH_AT=after-commit \
  .agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID5" backend 1
landed_head="$(git rev-parse HEAD)"
check "post-commit crash has one landed bound merge" test "$(git rev-list --first-parent --count HEAD)" -eq $((first_parent_before + 1))
check "post-commit crash preserves exact two-parent intent" test "$(git show -s --format=%P "$landed_head")" = \
  "$head_before_crash $(git rev-parse "agent-task/feature-integration/$key5")"
check "post-commit crash keeps preparation for deterministic recovery" test -f "$prep5"
tx5=".teamwork/feature-integration/integrations/$key5.json"
check "post-commit crash did not fabricate a final transaction" test ! -e "$tx5"
.agent-squad/bin/integrate-task.sh feature-integration "$FID" "$TID5" backend 1 >/dev/null
check "post-commit retry journals the landed merge" grep -q '"phase": "awaiting-tracker"' "$tx5"
check "post-commit retry creates no duplicate commit" test "$(git rev-parse HEAD)" = "$landed_head"
.agent-squad/bin/finalize-integrations.sh feature-integration "$FID" "$tx5" >/dev/null

echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
