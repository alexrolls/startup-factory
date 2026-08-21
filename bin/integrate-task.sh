#!/usr/bin/env bash
# Merge one approved task branch and hand its immutable transaction to the tracker broker.
set -euo pipefail
umask 077

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$SKILL_DIR/config/team.config.md"

die() { echo "integrate-task: $*" >&2; exit 1; }
read_key() {
  local line value _t
  line="$(grep -m1 "^$1=" "$CONFIG" || true)"
  value="${line#*=}"
  if [ "${value#\"}" != "$value" ]; then value="${value#\"}"; value="${value%%\"*}"
  else value="${value%%[[:space:]]#*}"; _t="${value##*[![:space:]]}"; value="${value%"$_t"}"; fi
  [ "$value" = "null" ] && value=""
  printf '%s' "$value"
}

# Broker authorization must use the protected hold authority even when this
# script is invoked directly rather than through the PM supervisor.
if [ -z "${STARTUP_FACTORY_LIFECYCLE_STATE_ROOT:-}" ]; then
  configured_lifecycle_root="$(read_key BROKER_LIFECYCLE_ROOT)"
  if [ -n "$configured_lifecycle_root" ]; then
    export STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$configured_lifecycle_root"
  fi
fi

git_unprivileged() {
  local args=(-i "PATH=${PATH:-/usr/bin:/bin}" "GIT_CONFIG_GLOBAL=/dev/null" "GIT_CONFIG_NOSYSTEM=1")
  [ -z "${TMPDIR-}" ] || args+=("TMPDIR=$TMPDIR")
  [ -z "${LANG-}" ] || args+=("LANG=$LANG")
  [ -z "${LC_ALL-}" ] || args+=("LC_ALL=$LC_ALL")
  /usr/bin/env "${args[@]}" git -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"
}

[ $# -ge 5 ] && [ $# -le 6 ] || {
  die "usage: integrate-task.sh <team> <featureId> <taskId> <role> <attempt> [completion-bodyfile]"
}
team="$1"; feature="$2"; task="$3"; role="$4"; attempt="$5"; supplied_body="${6:-}"
case "$team" in ''|*[!a-zA-Z0-9._-]*) die "unsafe team identifier '$team'" ;; esac
case "$role" in ''|*[!a-z0-9-]*) die "unsafe role identifier '$role'" ;; esac
case "$attempt" in ''|*[!0-9]*) die "attempt must be a positive integer" ;; esac
[ "$attempt" -ge 1 ] || die "attempt must be positive"
python3 - "$feature" "$task" <<'PY'
import sys
for name, value in zip(("featureId", "taskId"), sys.argv[1:]):
    if not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise SystemExit("integrate-task: invalid %s" % name)
PY

repo="$(git_unprivileged rev-parse --show-toplevel)"
root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
workspace="$(python3 "$SKILL_DIR/bin/teamwork-path.py" workspace --repo "$repo" --root "$root" --team "$team")"
preset_file="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative preset.env)"
key="$(python3 "$SKILL_DIR/bin/runtime-state.py" key "$task")"
execution="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "executions/$key.json")"
transaction="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "integrations/$key.json")"
preparations="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "integrations/.prepared")"
preparation="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "integrations/.prepared/$key.json")"
preparation_history="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "integrations/.prepared-history")"
merge_snapshot="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "pm/integration-merge-snapshot.json")"
mkdir -p "$(dirname "$transaction")" "$preparations" "$preparation_history" "$(dirname "$merge_snapshot")"
python3 - "$repo" "$workspace" "$(dirname "$transaction")" "$preparations" "$preparation_history" "$(dirname "$merge_snapshot")" <<'PY'
import os, stat, sys
repo=os.path.realpath(sys.argv[1])
workspace=os.path.realpath(sys.argv[2])
children=[os.path.realpath(value) for value in sys.argv[3:]]
if os.path.commonpath([repo, workspace]) != repo or any(os.path.commonpath([workspace, child]) != workspace for child in children):
    raise SystemExit("integrate-task: workspace/integrations escapes repository")
for raw in sys.argv[2:]:
    if os.path.islink(raw) or not stat.S_ISDIR(os.lstat(raw).st_mode):
        raise SystemExit("integrate-task: workspace/integrations may not be symlinks")
PY

assert_task_not_held() {
  local protected_rc=0
  python3 "$SKILL_DIR/bin/task-hold.py" check \
    --repo "$repo" --workspace "$workspace" --team "$team" --feature "$feature" \
    --task "$task" || protected_rc=$?
  [ "$protected_rc" -eq 0 ] || die "task is held by protected Blocked authority; merge/integration is stopped"
  python3 - "$workspace" "$feature" "$task" <<'PY'
import hashlib,json,os,re,stat,sys
from pathlib import Path
workspace,feature,task=sys.argv[1:]; path=Path(workspace)/"task-holds.json"
def fail(message): raise SystemExit("integrate-task: "+message)
def key(value):
    slug=re.sub(r"[^a-zA-Z0-9]+","-",value).strip("-").lower()[:32] or "task"
    return "%s-%s"%(slug,hashlib.sha256(value.encode()).hexdigest()[:10])
try: before=os.lstat(path)
except FileNotFoundError: raise SystemExit(0)
except OSError as exc: fail("cannot inspect task hold registry: %s"%exc)
if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
    fail("task hold registry must be a non-symlink regular file")
if before.st_size<=0 or before.st_size>64*1024*1024:
    fail("task hold registry must contain 1..67108864 bytes")
fd=None
try:
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); opened=os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):
        fail("task hold registry changed during integration")
    content=b""
    while len(content)<=64*1024*1024:
        block=os.read(fd,min(1024*1024,64*1024*1024+1-len(content)))
        if not block: break
        content+=block
    if len(content)>64*1024*1024: fail("task hold registry exceeds the 64 MiB safety limit")
except OSError as exc: fail("cannot securely read task hold registry: %s"%exc)
finally:
    if fd is not None: os.close(fd)
try: data=json.loads(content.decode("utf-8"))
except (UnicodeError,ValueError) as exc: fail("invalid task hold registry: %s"%exc)
records=data.get("tasks") if isinstance(data,dict) else None
if not isinstance(data,dict) or data.get("schemaVersion")!=1 or data.get("featureId")!=feature or not isinstance(records,dict):
    fail("task hold registry schema/feature scope mismatch")
states={"blocked","resume-review-pending","manual-takeover","resumed"}; seen=set()
for record_key,record in records.items():
    if not isinstance(record_key,str) or not isinstance(record,dict): fail("malformed task hold record")
    record_task=record.get("taskId")
    if not isinstance(record_task,str) or not record_task or record_task in seen:
        fail("task hold registry has a missing or duplicate task identity")
    seen.add(record_task)
    if record_key!=key(record_task) or record.get("taskKey")!=record_key:
        fail("task hold registry task identity/key mismatch")
    if record.get("state") not in states: fail("task hold registry contains an unknown task state")
record=records.get(key(task))
if record is not None and record.get("taskId")!=task: fail("task hold registry entry/task mismatch")
if record is not None and record.get("state") in {"blocked","resume-review-pending","manual-takeover"}:
    fail("task %s is held (%s); merge/integration is stopped"%(task,record.get("state")))
PY
}

assert_tracker_task_review_authorized() {
  [ ! -L "$merge_snapshot" ] || die "fresh merge snapshot path is a symlink"
  [ ! -e "$merge_snapshot" ] || [ -f "$merge_snapshot" ] || die "fresh merge snapshot path is not a regular file"
  if ! env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
    "$SKILL_DIR/bin/tracker-ops.sh" export "$feature" "$merge_snapshot" >/dev/null; then
    die "fresh tracker export unavailable; merge/integration remains stopped"
  fi
  python3 - "$merge_snapshot" "$SKILL_DIR/config/statuses.config.json" "$feature" "$task" <<'PY'
import json,os,stat,sys
snapshot_raw,board_raw,feature,task=sys.argv[1:]
def fail(message): raise SystemExit("integrate-task: "+message)
def read_regular(path,label,limit):
    try: before=os.lstat(path)
    except OSError as exc: fail("%s unavailable: %s"%(label,exc))
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size<=0 or before.st_size>limit:
        fail("%s must be a bounded non-symlink regular file"%label)
    fd=None
    try:
        fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino): fail("%s changed while reading"%label)
        raw=b""
        while len(raw)<=limit:
            part=os.read(fd,min(1024*1024,limit+1-len(raw)))
            if not part: break
            raw+=part
        if len(raw)>limit: fail("%s exceeds its safety limit"%label)
    except OSError as exc: fail("cannot securely read %s: %s"%(label,exc))
    finally:
        if fd is not None: os.close(fd)
    try: return json.loads(raw.decode("utf-8"))
    except (UnicodeError,ValueError) as exc: fail("invalid %s: %s"%(label,exc))
payload=read_regular(snapshot_raw,"fresh tracker snapshot",64*1024*1024)
board=read_regular(board_raw,"status configuration",1024*1024)
if not isinstance(payload,dict) or payload.get("featureId")!=feature:
    fail("fresh tracker snapshot feature scope mismatch")
tasks=payload.get("tasks")
if not isinstance(tasks,list) or any(not isinstance(item,dict) for item in tasks):
    fail("fresh tracker snapshot tasks are malformed")
ids=[str(item.get("taskId") or "") for item in tasks]
if any(not value for value in ids) or len(ids)!=len(set(ids)):
    fail("fresh tracker snapshot task identities are missing or duplicated")
matches=[item for item in tasks if str(item.get("taskId"))==task]
if len(matches)!=1: fail("task is absent or duplicated in the fresh tracker snapshot")
try: ignored_raw=json.loads(os.environ.get("STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON", '["human-work"]'))
except ValueError: fail("ignored-task label policy is not valid JSON")
if not isinstance(ignored_raw,list) or any(not isinstance(item,str) or not item.strip() for item in ignored_raw):
    fail("ignored-task label policy must be a JSON array of non-empty strings")
if len({item.strip().casefold() for item in ignored_raw}) != len(ignored_raw):
    fail("ignored-task label policy contains duplicate labels")
labels=matches[0].get("labels") or []
if not isinstance(labels,list) or any(not isinstance(item,str) for item in labels):
    fail("fresh tracker task labels are malformed")
if {item.strip().casefold() for item in ignored_raw}.intersection(item.strip().casefold() for item in labels):
    fail("task is labeled for human work; merge/integration is stopped")
try:
    review=[item["name"] for item in board["tasks"]["statuses"] if item.get("kind")=="review"]
except (KeyError,TypeError): fail("status configuration has no semantic task statuses")
if len(review)!=1: fail("status configuration must define exactly one semantic review status")
if matches[0].get("status")!=review[0]:
    fail("task %s is no longer in semantic review in the authoritative tracker; merge/integration is stopped"%task)
PY
}

# Do not even prepare new integration intent for a task already stopped by the
# PM authority. The same check is repeated at every later mutation boundary.
assert_task_not_held

# Rebuild the immutable execution identity rather than trusting arbitrary fields
# copied from the producer-owned transaction.
execution_fields="$(python3 - "$execution" "$workspace" "$team" "$feature" "$task" "$role" "$attempt" "$key" <<'PY'
import hashlib, json, os, re, stat, sys
from pathlib import Path

path_raw, workspace_raw, team, feature, task, role, attempt_raw, key = sys.argv[1:]
path, workspace, attempt = Path(path_raw), Path(workspace_raw), int(attempt_raw)
try: mode=path.lstat().st_mode
except OSError as exc: raise SystemExit("integrate-task: no execution record for %s: %s" % (task, exc))
if path.is_symlink() or not stat.S_ISREG(mode):
    raise SystemExit("integrate-task: execution record must be a non-symlink regular file")
try: path.resolve().relative_to(workspace.resolve())
except (OSError, ValueError): raise SystemExit("integrate-task: execution record escapes team workspace")
try: execution=json.loads(path.read_text())
except (OSError, ValueError) as exc: raise SystemExit("integrate-task: invalid execution record: %s" % exc)
worktree_mode = execution.get("worktreeMode") or "linked-worktree"
expected_worktree = (
    execution.get("worktree")
    if worktree_mode == "standalone-clone"
    else str(workspace / "worktrees" / ("%s#%s-%s" % (role, attempt, key)))
)
if worktree_mode not in {"linked-worktree", "standalone-clone"}:
    raise SystemExit("integrate-task: execution record has unknown worktree mode")
expected = {
    "schemaVersion": 1,
    "featureId": feature,
    "taskId": task,
    "taskKey": key,
    "attempt": attempt,
    "role": role,
    "branch": "agent-task/" + team + "/" + key,
    "worktree": expected_worktree,
    "packetPath": str(workspace / "artifacts" / key / ("attempt-%s" % attempt) / "task-packet.md"),
    "packetJsonPath": str(workspace / "artifacts" / key / ("attempt-%s" % attempt) / "task-packet.json"),
    "reportPath": str(workspace / "artifacts" / key / ("attempt-%s" % attempt) / "task-report.md"),
}
for name, value in expected.items():
    if execution.get(name) != value:
        raise SystemExit("integrate-task: execution record %s does not match invocation" % name)
canonical=json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
print(expected["branch"])
print(expected["worktree"])
print("sha256:" + hashlib.sha256(canonical).hexdigest())
PY
)"
branch="$(printf '%s\n' "$execution_fields" | sed -n '1p')"
worktree="$(printf '%s\n' "$execution_fields" | sed -n '2p')"
execution_digest="$(printf '%s\n' "$execution_fields" | sed -n '3p')"
expected_worktree="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "worktrees/$role#$attempt-$key")"
worktree_mode="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("worktreeMode") or "linked-worktree")' "$execution")"
if [ "$worktree_mode" = standalone-clone ]; then
  expected_worktree="$(python3 "$SKILL_DIR/bin/standalone_workspace.py" path --repo "$repo" \
    --root "$(read_key BROKER_TASK_CLONE_ROOT)" --team "$team" --role "$role" \
    --attempt "$attempt" --task-key "$key")"
fi
[ "$worktree" = "$expected_worktree" ] || die "execution worktree does not match its canonical task slot"
worktree="$expected_worktree"

if [ -e "$transaction" ]; then
  [ -f "$transaction" ] && [ ! -L "$transaction" ] \
    || die "existing transaction must be a non-symlink regular file"
  validated="$("$SKILL_DIR/bin/finalize-integrations.sh" --validate-only "$team" "$feature" "$transaction")"
  phase="$(printf '%s\n' "$validated" | sed -n '8p')"
  commit="$(printf '%s\n' "$validated" | sed -n '4p')"
  if [ -f "$preparation" ] && [ ! -L "$preparation" ]; then
    prep_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["preparationId"])' "$preparation")"
    [ ! -e "$preparation_history/$prep_id.json" ] || die "prepared history collision for $prep_id"
    mv "$preparation" "$preparation_history/$prep_id.json"
  fi
  if [ "$phase" = "completed" ]; then
    echo "$task already integrated at $commit"
    exit 0
  fi
  if [ "$(read_key TRACKER_WRITERS)" = "all" ]; then
    "$SKILL_DIR/bin/finalize-integrations.sh" "$team" "$feature" "$transaction"
  else
    echo "$task already merged at $commit; awaiting credentialed tracker broker"
  fi
  exit 0
fi

run_validation() {
  local where="$1" changed_file="$2" command value
  value="$(read_key VALIDATE_SCRIPT)"
  if [ -n "$value" ]; then
    local changed_files=() item
    while IFS= read -r item; do [ -z "$item" ] || changed_files+=("$item"); done < "$changed_file"
    ( cd "$where" && "$value" "${changed_files[@]}" ) || return $?
    return
  fi
  for command in VALIDATE_BUILD VALIDATE_TEST VALIDATE_LINT VALIDATE_FORMAT; do
    value="$(read_key "$command")"
    [ -z "$value" ] || ( cd "$where" && eval "$value" ) || return $?
  done
}

load_preparation() {
  python3 - "$preparation" "$workspace" "$team" "$feature" "$task" "$key" "$role" "$attempt" \
    "$branch" "$worktree" "$execution_digest" <<'PY'
import hashlib, json, os, re, stat, sys
from datetime import datetime
from pathlib import Path

(raw, workspace_raw, team, feature, task, key, role, attempt_raw, branch,
 worktree_raw, execution_digest) = sys.argv[1:]
path, workspace, attempt = Path(raw), Path(workspace_raw), int(attempt_raw)
try: mode = path.lstat().st_mode
except OSError as exc: raise SystemExit("integrate-task: prepared transaction unavailable: %s" % exc)
if path.is_symlink() or not stat.S_ISREG(mode) or path.stat().st_size > 1024 * 1024:
    raise SystemExit("integrate-task: prepared transaction must be a bounded non-symlink regular file")
try: path.resolve().relative_to(workspace.resolve())
except (OSError, ValueError): raise SystemExit("integrate-task: prepared transaction escapes workspace")
try: data = json.loads(path.read_text())
except (OSError, ValueError) as exc: raise SystemExit("integrate-task: invalid prepared transaction: %s" % exc)
required={
    "schemaVersion", "preparationId", "team", "featureId", "taskId", "taskKey", "role", "attempt",
    "branch", "worktree", "phase", "baseCommit", "reviewBaseCommit", "taskBranchHead",
    "executionDigest", "reviewPackagePath", "reviewPackageSha256", "approvalEvidenceDigest",
    "createdAt", "authorizedAt", "authorizationSnapshotSha256",
}
if not isinstance(data, dict) or set(data) != required or data.get("schemaVersion") != 1:
    raise SystemExit("integrate-task: prepared transaction schema/fields mismatch")
expected={"team":team,"featureId":feature,"taskId":task,"taskKey":key,"role":role,"attempt":attempt,
          "branch":branch,"worktree":worktree_raw,"executionDigest":execution_digest}
for name,value in expected.items():
    if data.get(name) != value: raise SystemExit("integrate-task: prepared transaction %s mismatch" % name)
if data.get("phase") not in {"awaiting-authorization", "authorized"}:
    raise SystemExit("integrate-task: invalid prepared transaction phase")
hex40=re.compile(r"[0-9a-f]{40}")
digest=re.compile(r"sha256:[0-9a-f]{64}")
for name in ("baseCommit","reviewBaseCommit","taskBranchHead"):
    if not isinstance(data.get(name),str) or not hex40.fullmatch(data[name]):
        raise SystemExit("integrate-task: prepared transaction has invalid %s" % name)
for name in ("reviewPackageSha256","approvalEvidenceDigest"):
    if not isinstance(data.get(name),str) or not digest.fullmatch(data[name]):
        raise SystemExit("integrate-task: prepared transaction has invalid %s" % name)
material={name:data[name] for name in (
    "team","featureId","taskId","attempt","executionDigest","baseCommit","reviewBaseCommit",
    "taskBranchHead","reviewPackageSha256","approvalEvidenceDigest")}
canonical=json.dumps(material,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
expected_id="integration-prep-"+hashlib.sha256(canonical).hexdigest()[:32]
if data.get("preparationId") != expected_id:
    raise SystemExit("integrate-task: prepared transaction id mismatch")
package=Path(str(data.get("reviewPackagePath")))
try: package.resolve().relative_to(workspace.resolve())
except (OSError,ValueError): raise SystemExit("integrate-task: prepared review package escapes workspace")
if package.is_symlink() or not package.is_file():
    raise SystemExit("integrate-task: prepared review package is unsafe")
actual="sha256:"+hashlib.sha256(package.read_bytes()).hexdigest()
if actual != data["reviewPackageSha256"]:
    raise SystemExit("integrate-task: prepared review package changed")
if data["phase"] == "awaiting-authorization":
    if data["authorizedAt"] is not None or data["authorizationSnapshotSha256"] is not None:
        raise SystemExit("integrate-task: unauthorized preparation carries authorization fields")
else:
    if not isinstance(data["authorizedAt"],str) or not digest.fullmatch(str(data["authorizationSnapshotSha256"])):
        raise SystemExit("integrate-task: authorized preparation lacks broker evidence")
for name in ("preparationId","phase","baseCommit","reviewBaseCommit","taskBranchHead","reviewPackagePath",
             "reviewPackageSha256","approvalEvidenceDigest","authorizedAt","authorizationSnapshotSha256"):
    value=data[name]
    print("" if value is None else value)
PY
}

reset_preparation_authorization() {
  python3 - "$preparation" <<'PY'
import json, os, stat, sys
from datetime import datetime, timezone
path=sys.argv[1]
mode=os.lstat(path).st_mode
if os.path.islink(path) or not stat.S_ISREG(mode): raise SystemExit("integrate-task: preparation changed type")
data=json.load(open(path))
if data.get("phase") != "authorized": raise SystemExit("integrate-task: preparation is not authorized")
data["phase"]="awaiting-authorization"; data["authorizedAt"]=None; data["authorizationSnapshotSha256"]=None
temp=path+".tmp.%s"%os.getpid()
fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w") as handle:
    json.dump(data,handle,indent=2,ensure_ascii=False); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
os.replace(temp,path)
directory=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(directory); os.close(directory)
PY
}

[ "$(git_unprivileged -C "$repo" branch --show-current)" = "$team" ] \
  || die "repository checkout must be on feature branch '$team'"
[ -d "$worktree" ] && [ ! -L "$worktree" ] || die "missing or unsafe task worktree $worktree"
[ "$(git_unprivileged -C "$worktree" branch --show-current)" = "$branch" ] \
  || die "task worktree is not on execution branch '$branch'"
[ -z "$(git_unprivileged -C "$worktree" status --porcelain -uall)" ] \
  || die "task worktree is dirty; checkpoint commits are required before integration"
merge_ref="$branch"
if [ "$worktree_mode" = standalone-clone ]; then
  recorded_base="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("baseCommit") or "")' "$execution")"
  clone_head="$(git_unprivileged -C "$worktree" rev-parse HEAD)"
  quarantine_bundle="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "artifacts/$key/quarantine-$clone_head.bundle")"
  imported="$(python3 "$SKILL_DIR/bin/standalone_workspace.py" import --repo "$repo" --clone "$worktree" \
    --branch "$branch" --base "$recorded_base" --team "$team" --task-key "$key" \
    --attempt "$attempt" --bundle "$quarantine_bundle")" \
    || die "standalone task could not be imported through the quarantine boundary"
  merge_ref="$(printf '%s' "$imported" | python3 -c 'import json,sys; print(json.load(sys.stdin)["quarantineRef"])')"
  [ "$(git_unprivileged -C "$repo" rev-parse "$merge_ref")" = "$clone_head" ] \
    || die "standalone quarantine ref does not bind the exact clone head"
  [ "$(git_unprivileged -C "$repo" merge-base "$recorded_base" "$merge_ref")" = "$recorded_base" ] \
    || die "quarantine import does not descend from the execution base"
fi
changed_file_list="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "artifacts/$key/integration-files.txt")"
mkdir -p "$(dirname "$changed_file_list")"
if [ ! -e "$preparation" ]; then
  ahead="$(git_unprivileged -C "$repo" rev-list --count "$team..$merge_ref")"
  [ "$ahead" -gt 0 ] || die "task branch $branch has no checkpoint commits to integrate"
  base_commit="$(git_unprivileged -C "$repo" rev-parse "$team")"
  task_branch_head="$(git_unprivileged -C "$repo" rev-parse "$merge_ref")"
  review_base_commit="$(git_unprivileged -C "$repo" merge-base "$team" "$merge_ref")"
  git_unprivileged -C "$repo" diff --name-only "$review_base_commit..$task_branch_head" > "$changed_file_list"
  [ -s "$changed_file_list" ] || die "task branch has no changed files"
  run_validation "$worktree" "$changed_file_list"
  package="$("$SKILL_DIR/bin/review-package.sh" "$team" "$task")"
  [ -f "$package" ] && [ ! -L "$package" ] || die "review package must be a non-symlink regular file"
  package_head="$(sed -n 's/^Head: //p' "$package")"
  [ "$package_head" = "$task_branch_head" ] || die "review package does not bind the current task branch head"
  review_package_digest="$(python3 - "$package" <<'PY'
import hashlib, pathlib, sys
print("sha256:" + hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
  tasks_snapshot="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative tasks.json)"
  [ -f "$tasks_snapshot" ] && [ ! -L "$tasks_snapshot" ] \
    || die "missing safe tracker snapshot; dispatcher must export current approvals first"
  approval_evidence_digest="$("$SKILL_DIR/bin/finalize-integrations.sh" --evidence \
    "$tasks_snapshot" "$task" "$review_base_commit" "$task_branch_head" "$review_package_digest" "$preset_file")"
  [ -z "$(git_unprivileged -C "$repo" status --porcelain -uall)" ] || die "feature-branch checkout is dirty"

  assert_task_not_held
  python3 - "$preparation" "$team" "$feature" "$task" "$key" "$role" "$attempt" "$branch" "$worktree" \
    "$base_commit" "$review_base_commit" "$task_branch_head" "$execution_digest" "$package" \
    "$review_package_digest" "$approval_evidence_digest" <<'PY'
import hashlib, json, os, sys
from datetime import datetime, timezone
(path,team,feature,task,key,role,attempt,branch,worktree,base,review_base,head,execution,
 package,package_digest,approval_digest)=sys.argv[1:]
material={"team":team,"featureId":feature,"taskId":task,"attempt":int(attempt),"executionDigest":execution,
          "baseCommit":base,"reviewBaseCommit":review_base,"taskBranchHead":head,
          "reviewPackageSha256":package_digest,"approvalEvidenceDigest":approval_digest}
canonical=json.dumps(material,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
value={"schemaVersion":1,"preparationId":"integration-prep-"+hashlib.sha256(canonical).hexdigest()[:32],
       "team":team,"featureId":feature,"taskId":task,"taskKey":key,"role":role,"attempt":int(attempt),
       "branch":branch,"worktree":worktree,"phase":"awaiting-authorization","baseCommit":base,
       "reviewBaseCommit":review_base,"taskBranchHead":head,"executionDigest":execution,
       "reviewPackagePath":package,"reviewPackageSha256":package_digest,"approvalEvidenceDigest":approval_digest,
       "createdAt":datetime.now(timezone.utc).isoformat(timespec="seconds"),"authorizedAt":None,
       "authorizationSnapshotSha256":None}
temp=path+".tmp.%s"%os.getpid(); fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w") as handle:
    json.dump(value,handle,indent=2,ensure_ascii=False); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
os.replace(temp,path)
directory=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(directory); os.close(directory)
PY
  if [ "${INTEGRATION_TEST_CRASH_AT:-}" = "after-prepare" ]; then kill -KILL "$$"; fi
fi

prepared="$(load_preparation)"
preparation_id="$(printf '%s\n' "$prepared" | sed -n '1p')"
preparation_phase="$(printf '%s\n' "$prepared" | sed -n '2p')"
base_commit="$(printf '%s\n' "$prepared" | sed -n '3p')"
review_base_commit="$(printf '%s\n' "$prepared" | sed -n '4p')"
task_branch_head="$(printf '%s\n' "$prepared" | sed -n '5p')"
package="$(printf '%s\n' "$prepared" | sed -n '6p')"
review_package_digest="$(printf '%s\n' "$prepared" | sed -n '7p')"
approval_evidence_digest="$(printf '%s\n' "$prepared" | sed -n '8p')"
authorized_at="$(printf '%s\n' "$prepared" | sed -n '9p')"
authorization_snapshot_digest="$(printf '%s\n' "$prepared" | sed -n '10p')"
[ "$(git_unprivileged -C "$repo" rev-parse "$merge_ref")" = "$task_branch_head" ] \
  || die "task branch moved after integration was prepared"
git_unprivileged -C "$repo" diff --name-only "$review_base_commit..$task_branch_head" > "$changed_file_list"
[ -s "$changed_file_list" ] || die "prepared task branch has no changed files"

if [ "$preparation_phase" = "awaiting-authorization" ]; then
  if [ "$(read_key TRACKER_WRITERS)" = "all" ]; then
    "$SKILL_DIR/bin/finalize-integrations.sh" --authorize-prepared "$team" "$feature" "$preparation"
    prepared="$(load_preparation)"
    preparation_phase="$(printf '%s\n' "$prepared" | sed -n '2p')"
    authorized_at="$(printf '%s\n' "$prepared" | sed -n '9p')"
    authorization_snapshot_digest="$(printf '%s\n' "$prepared" | sed -n '10p')"
  else
    echo "$task integration prepared; awaiting fresh credentialed broker authorization"
    exit 0
  fi
fi
[ "$preparation_phase" = "authorized" ] || die "integration preparation is not broker-authorized"

authorization_current() {
  python3 - "$authorized_at" <<'PY'
import sys
from datetime import datetime, timezone
try: value=datetime.fromisoformat(sys.argv[1].replace("Z","+00:00"))
except ValueError: raise SystemExit(1)
age=(datetime.now(timezone.utc)-value).total_seconds()
raise SystemExit(0 if -5 <= age <= 300 else 1)
PY
}

head_now="$(git_unprivileged -C "$repo" rev-parse HEAD)"
commit=""
if [ "$head_now" != "$base_commit" ]; then
  parents="$(git_unprivileged -C "$repo" show -s --format=%P "$head_now")"
  if [ "$parents" = "$base_commit $task_branch_head" ]; then
    commit="$head_now"
  else
    die "feature branch moved after integration preparation; refusing any reset or duplicate merge"
  fi
else
  merge_head="$(git_unprivileged -C "$repo" rev-parse -q --verify MERGE_HEAD 2>/dev/null || true)"
  if [ -n "$merge_head" ]; then
    [ "$merge_head" = "$task_branch_head" ] || die "an unrelated merge is in progress"
  else
    [ -z "$(git_unprivileged -C "$repo" status --porcelain -uall)" ] || die "feature-branch checkout is dirty"
    assert_task_not_held
    assert_tracker_task_review_authorized
    if ! git_unprivileged -C "$repo" merge --no-ff --no-commit "$merge_ref"; then
      git_unprivileged -C "$repo" merge --abort >/dev/null 2>&1 || true
      die "merge conflict; return the task branch to the worker"
    fi
    if [ "${INTEGRATION_TEST_CRASH_AT:-}" = "after-merge" ]; then kill -KILL "$$"; fi
  fi
  if ! run_validation "$repo" "$changed_file_list"; then
    git_unprivileged -C "$repo" merge --abort >/dev/null 2>&1 || true
    die "feature-branch validation failed; merge aborted"
  fi
  if ! authorization_current; then
    git_unprivileged -C "$repo" merge --abort >/dev/null 2>&1 || true
    reset_preparation_authorization
    die "broker authorization expired before commit; merge safely aborted for fresh authorization"
  fi
  if ! assert_task_not_held || ! assert_tracker_task_review_authorized; then
    git_unprivileged -C "$repo" merge --abort >/dev/null 2>&1 \
      || die "task became held/Blocked and the in-progress merge could not be safely aborted"
    die "task became held/Blocked during integration validation; merge safely aborted before commit"
  fi
trailers="$(printf '%s\n' \
  "Feature-Id: $feature" \
  "Task-Id: $task" \
  "Task-Role: $role" \
  "Task-Attempt: $attempt" \
  "Task-Branch: $branch" \
  "Task-Branch-Head: $task_branch_head" \
  "Review-Base-Commit: $review_base_commit" \
  "Task-Execution: $execution_digest" \
  "Review-Package-SHA256: $review_package_digest" \
  "Approval-Evidence-SHA256: $approval_evidence_digest" \
  "Integration-Preparation: $preparation_id" \
  "Authorization-Snapshot-SHA256: $authorization_snapshot_digest")"
  git_unprivileged -C "$repo" commit -m "integrate: $task" -m "$trailers"
  commit="$(git_unprivileged -C "$repo" rev-parse HEAD)"
  if [ "${INTEGRATION_TEST_CRASH_AT:-}" = "after-commit" ]; then kill -KILL "$$"; fi
fi
parents="$(git_unprivileged -C "$repo" show -s --format=%P "$commit")"
[ "$parents" = "$base_commit $task_branch_head" ] \
  || die "integration commit parents do not preserve exact base + reviewed head"
commit_message="$(git_unprivileged -C "$repo" show -s --format=%B "$commit")"
printf '%s\n' "$commit_message" | grep -Fqx "Integration-Preparation: $preparation_id" \
  || die "recovered integration commit lacks its exact prepared-transaction binding"
printf '%s\n' "$commit_message" | grep -Fqx "Authorization-Snapshot-SHA256: $authorization_snapshot_digest" \
  || die "recovered integration commit lacks its fresh broker authorization binding"

# If a hold landed immediately after the commit, preserve the landed commit as
# recoverable Git state but stop before publishing completion evidence or the
# integration transaction. A later unblocked retry recognizes the exact commit.
assert_task_not_held
assert_tracker_task_review_authorized
body="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "artifacts/$key/integration-completion.md")"
body_temp="$body.tmp.$$"
if [ -n "$supplied_body" ]; then
  [ -f "$supplied_body" ] && [ ! -L "$supplied_body" ] \
    || die "completion body source must be a non-symlink regular file"
  [ "$(wc -c < "$supplied_body")" -le 65536 ] || die "completion body exceeds 64 KiB"
  cp "$supplied_body" "$body_temp"
else
  {
    echo "Task branch: $branch"
    echo "Reviewed task head: $task_branch_head"
    echo "Integration commit: $commit"
    echo "Review package: $package"
    echo "Review package digest: $review_package_digest"
    echo "Approval evidence digest: $approval_evidence_digest"
    echo "Independent feature-branch validation completed."
  } > "$body_temp"
fi
chmod 600 "$body_temp"
[ ! -L "$body" ] || die "completion body destination is a symlink"
mv "$body_temp" "$body"
completion_body_digest="$(python3 - "$body" <<'PY'
import hashlib, pathlib, sys
print("sha256:" + hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"

transaction_id="$(python3 - "$team" "$feature" "$task" "$attempt" "$execution_digest" "$base_commit" "$review_base_commit" "$task_branch_head" "$commit" "$review_package_digest" "$approval_evidence_digest" <<'PY'
import hashlib, json, sys
team, feature, task, attempt, execution, base, review_base, head, commit, package, approvals = sys.argv[1:]
material={
    "team": team, "featureId": feature, "taskId": task, "attempt": int(attempt),
    "executionDigest": execution, "baseCommit": base, "reviewBaseCommit": review_base, "taskBranchHead": head,
    "commit": commit, "reviewPackageSha256": package, "approvalEvidenceDigest": approvals,
}
canonical=json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
print("integration-" + hashlib.sha256(canonical).hexdigest()[:32])
PY
)"

assert_task_not_held
assert_tracker_task_review_authorized
python3 - "$transaction" "$transaction_id" "$team" "$feature" "$task" "$key" "$role" "$attempt" \
  "$branch" "$worktree" "$base_commit" "$task_branch_head" "$commit" "$execution_digest" \
  "$review_base_commit" "$package" "$review_package_digest" "$approval_evidence_digest" "$body" "$completion_body_digest" <<'PY'
import json, os, sys
from datetime import datetime, timezone
(
    path, txid, team, feature, task, key, role, attempt, branch, worktree, base, branch_head,
    commit, execution_digest, review_base, package, package_digest, approval_digest, body, body_digest,
) = sys.argv[1:]
value = {
    "schemaVersion": 2,
    "transactionId": txid,
    "team": team,
    "featureId": feature,
    "taskId": task,
    "taskKey": key,
    "role": role,
    "attempt": int(attempt),
    "branch": branch,
    "worktree": worktree,
    "phase": "awaiting-tracker",
    "baseCommit": base,
    "reviewBaseCommit": review_base,
    "taskBranchHead": branch_head,
    "commit": commit,
    "executionDigest": execution_digest,
    "reviewPackagePath": package,
    "reviewPackageSha256": package_digest,
    "approvalEvidenceDigest": approval_digest,
    "completionBodyPath": body,
    "completionBodySha256": body_digest,
    "updatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
}
temp=path+".tmp.%s" % os.getpid()
fd=os.open(temp, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as handle:
    json.dump(value, handle, indent=2, ensure_ascii=False)
    handle.write("\n")
    handle.flush(); os.fsync(handle.fileno())
os.replace(temp, path)
PY

assert_task_not_held
assert_tracker_task_review_authorized
[ -f "$preparation" ] && [ ! -L "$preparation" ] || die "prepared authorization disappeared before handoff"
[ ! -e "$preparation_history/$preparation_id.json" ] || die "prepared history collision for $preparation_id"
mv "$preparation" "$preparation_history/$preparation_id.json"

if [ "$(read_key TRACKER_WRITERS)" = "all" ]; then
  "$SKILL_DIR/bin/finalize-integrations.sh" "$team" "$feature" "$transaction"
  echo "$task integrated at $commit"
else
  echo "$task merged at $commit; awaiting credentialed tracker broker"
fi
