#!/usr/bin/env bash
# Finalize integration transactions through the credentialed deterministic broker.
set -euo pipefail
umask 077

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$SKILL_DIR/config/team.config.md"

die() { echo "finalize-integrations: $*" >&2; exit 1; }
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

usage() {
  die "usage: finalize-integrations.sh <team> <featureId> [transaction.json]
       finalize-integrations.sh --validate-only <team> <featureId> <transaction.json>
       finalize-integrations.sh --authorize-prepared <team> <featureId> <prepared.json>
       finalize-integrations.sh --evidence <tasks.json> <taskId> <baseCommit> <headCommit> <packageSha256>"
}

# Keep approval eligibility identical in the integrator and broker. Every
# approval is bound to the exact request, base, head, and review-package digest.
approval_evidence() {
  [ $# -eq 5 ] || usage
  python3 "$SKILL_DIR/bin/review_evidence.py" validate \
    "$1" "$2" "$3" "$4" "$5" "$SKILL_DIR/config/statuses.config.json"
}

if [ "${1:-}" = "--evidence" ]; then
  [ $# -eq 6 ] || usage
  approval_evidence "$2" "$3" "$4" "$5" "$6"
  exit 0
fi

validate_only=no
authorize_prepared=no
if [ "${1:-}" = "--validate-only" ]; then
  validate_only=yes
  shift
elif [ "${1:-}" = "--authorize-prepared" ]; then
  authorize_prepared=yes
  shift
fi
[ $# -ge 2 ] && [ $# -le 3 ] || usage
team="$1"; feature="$2"; only="${3:-}"
[ "$authorize_prepared" = "no" ] || [ -n "$only" ] || usage
case "$team" in ''|*[!a-zA-Z0-9._-]*) die "unsafe team identifier '$team'" ;; esac
[ "${#team}" -le 63 ] || die "team identifier is longer than 63 characters"
python3 - "$feature" <<'PY'
import sys
value=sys.argv[1]
if not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
    raise SystemExit("finalize-integrations: invalid featureId")
PY

repo="$(git_unprivileged rev-parse --show-toplevel)"
root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
workspace="$(python3 "$SKILL_DIR/bin/teamwork-path.py" workspace --repo "$repo" --root "$root" --team "$team")"
integrations="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative integrations)"
mkdir -p "$integrations"
python3 - "$repo" "$workspace" "$integrations" <<'PY'
import os, sys
repo, workspace, integrations = map(os.path.realpath, sys.argv[1:])
if os.path.commonpath([repo, workspace]) != repo:
    raise SystemExit("finalize-integrations: workspace escapes repository")
for raw in sys.argv[2:]:
    if os.path.islink(raw):
        raise SystemExit("finalize-integrations: workspace/integrations may not be symlinks")
if os.path.commonpath([workspace, integrations]) != workspace:
    raise SystemExit("finalize-integrations: integrations directory escapes workspace")
PY
locks="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative integrations/.locks)"
pm_dir="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative pm)"
events_file="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative events.ndjson)"
preset_file="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative preset.env)"
mkdir -p "$locks" "$pm_dir"
python3 - "$workspace" "$locks" "$pm_dir" <<'PY'
import os, stat, sys
workspace=os.path.realpath(sys.argv[1])
for raw in sys.argv[2:]:
    try: mode=os.lstat(raw).st_mode
    except OSError as exc: raise SystemExit("finalize-integrations: unsafe broker directory: %s" % exc)
    if os.path.islink(raw) or not stat.S_ISDIR(mode):
        raise SystemExit("finalize-integrations: broker lock/snapshot directories may not be symlinks")
    if os.path.commonpath([workspace, os.path.realpath(raw)]) != workspace:
        raise SystemExit("finalize-integrations: broker directory escapes workspace")
PY

# A task hold is authorization state, not an advisory flag. Every mutating
# broker boundary re-reads this single canonical registry. Missing means no
# holds have ever been recorded; every malformed, redirected, or mismatched
# registry fails closed.
assert_task_not_held() {
  local protected_rc=0
  python3 "$SKILL_DIR/bin/task-hold.py" check \
    --repo "$repo" --workspace "$workspace" --team "$team" --feature "$feature" \
    --task "$1" || protected_rc=$?
  [ "$protected_rc" -eq 0 ] || die "task $1 is held by protected Blocked authority; integration/finalization is stopped"
  python3 - "$workspace" "$feature" "$1" <<'PY'
import hashlib,json,os,re,stat,sys
from pathlib import Path
workspace,feature,task=sys.argv[1:]
path=Path(workspace)/"task-holds.json"
def fail(message): raise SystemExit("finalize-integrations: "+message)
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
        fail("task hold registry changed during authorization")
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
    fail("task %s is held (%s); integration/finalization is stopped"%(task,record.get("state")))
PY
}

assert_tracker_task_review_authorized() {
  local task="$1" fresh="$pm_dir/integration-write-snapshot.json"
  [ ! -L "$fresh" ] || die "fresh integration-write snapshot path is a symlink"
  [ ! -e "$fresh" ] || [ -f "$fresh" ] || die "fresh integration-write snapshot path is not a regular file"
  if ! env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
    "$SKILL_DIR/bin/tracker-ops.sh" export "$feature" "$fresh" >/dev/null; then
    die "fresh tracker export unavailable; tracker integration remains stopped"
  fi
  python3 - "$fresh" "$SKILL_DIR/config/statuses.config.json" "$feature" "$task" <<'PY'
import json,os,stat,sys
snapshot_raw,board_raw,feature,task=sys.argv[1:]
def fail(message): raise SystemExit("finalize-integrations: "+message)
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
    fail("task is labeled for human work; tracker integration is stopped")
try: review=[item["name"] for item in board["tasks"]["statuses"] if item.get("kind")=="review"]
except (KeyError,TypeError): fail("status configuration has no semantic task statuses")
if len(review)!=1: fail("status configuration must define exactly one semantic review status")
if matches[0].get("status")!=review[0]:
    fail("task %s is no longer in semantic review; tracker integration is stopped"%task)
PY
}

authorize_preparation() {
  local entry="$1" snapshot task
  task="$(python3 - "$entry" <<'PY'
import json,os,stat,sys
path=sys.argv[1]
try: mode=os.lstat(path).st_mode
except OSError as exc: raise SystemExit("finalize-integrations: prepared transaction unavailable: %s"%exc)
if os.path.islink(path) or not stat.S_ISREG(mode):
    raise SystemExit("finalize-integrations: prepared transaction must be a non-symlink regular file")
try: data=json.load(open(path))
except (OSError,ValueError) as exc: raise SystemExit("finalize-integrations: invalid prepared transaction: %s"%exc)
task=data.get("taskId") if isinstance(data,dict) else None
if not isinstance(task,str) or not task: raise SystemExit("finalize-integrations: prepared transaction lacks taskId")
print(task)
PY
)"
  assert_task_not_held "$task"
  snapshot="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative pm/integration-authorization-snapshot.json)"
  [ ! -L "$snapshot" ] || die "authorization snapshot path is a symlink"
  "$SKILL_DIR/bin/tracker-ops.sh" export "$feature" "$snapshot" >/dev/null
  python3 - "$entry" "$snapshot" "$repo" "$workspace" "$team" "$feature" \
    "$SKILL_DIR/config/statuses.config.json" "$SKILL_DIR/bin/review_evidence.py" <<'PY'
import hashlib, json, os, re, stat, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

entry_raw,snapshot_raw,repo_raw,workspace_raw,team,feature,board_raw,review_module_raw=sys.argv[1:]
entry,snapshot,repo,workspace=Path(entry_raw),Path(snapshot_raw),Path(repo_raw).resolve(),Path(workspace_raw).resolve()
sys.dont_write_bytecode=True; sys.path.insert(0,str(Path(review_module_raw).resolve().parent))
from review_evidence import EvidenceError, validate as validate_review_evidence
def fail(message): raise SystemExit("finalize-integrations: prepared authorization: "+message)
def regular(path,label,maximum=8*1024*1024):
    try: mode=path.lstat().st_mode
    except OSError as exc: fail("%s unavailable: %s"%(label,exc))
    if path.is_symlink() or not stat.S_ISREG(mode) or path.stat().st_size>maximum: fail("unsafe %s"%label)
def assert_unheld(task):
    path=workspace/"task-holds.json"
    try: before=path.lstat()
    except FileNotFoundError: return
    except OSError as exc: fail("cannot inspect task hold registry: %s"%exc)
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size<=0 or before.st_size>64*1024*1024:
        fail("unsafe task hold registry")
    fd=None
    try:
        fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); opened=os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):
            fail("task hold registry changed during prepared authorization")
        raw=b""
        while len(raw)<=64*1024*1024:
            part=os.read(fd,min(1024*1024,64*1024*1024+1-len(raw)))
            if not part: break
            raw+=part
        if len(raw)>64*1024*1024: fail("task hold registry exceeds safety limit")
    except OSError as exc: fail("cannot securely read task hold registry: %s"%exc)
    finally:
        if fd is not None: os.close(fd)
    try: registry=json.loads(raw.decode("utf-8"))
    except (UnicodeError,ValueError) as exc: fail("invalid task hold registry: %s"%exc)
    records=registry.get("tasks") if isinstance(registry,dict) else None
    if not isinstance(registry,dict) or registry.get("schemaVersion")!=1 or registry.get("featureId")!=feature or not isinstance(records,dict):
        fail("task hold registry schema/feature scope mismatch")
    def hold_key(value):
        slug=re.sub(r"[^a-zA-Z0-9]+","-",value).strip("-").lower()[:32] or "task"
        return "%s-%s"%(slug,hashlib.sha256(value.encode()).hexdigest()[:10])
    states={"blocked","resume-review-pending","manual-takeover","resumed"}; seen=set()
    for record_key,record in records.items():
        if not isinstance(record_key,str) or not isinstance(record,dict): fail("malformed task hold record")
        record_task=record.get("taskId")
        if not isinstance(record_task,str) or not record_task or record_task in seen: fail("invalid task hold identity")
        seen.add(record_task)
        if record_key!=hold_key(record_task) or record.get("taskKey")!=record_key: fail("task hold identity/key mismatch")
        if record.get("state") not in states: fail("unknown task hold state")
    record=records.get(hold_key(task))
    if record is not None and record.get("taskId")!=task: fail("task hold entry/task mismatch")
    if record is not None and record.get("state") in {"blocked","resume-review-pending","manual-takeover"}:
        fail("task %s is held (%s)"%(task,record.get("state")))
regular(entry,"prepared transaction",1024*1024); regular(snapshot,"fresh tracker snapshot",8*1024*1024)
prepared_dir=(workspace/"integrations"/".prepared").resolve()
if entry.resolve().parent != prepared_dir: fail("prepared transaction escapes its broker queue")
try: data=json.loads(entry.read_text()); payload=json.loads(snapshot.read_text()); board=json.loads(Path(board_raw).read_text())
except (OSError,ValueError) as exc: fail("invalid JSON: %s"%exc)
required={"schemaVersion","preparationId","team","featureId","taskId","taskKey","role","attempt","branch",
          "worktree","phase","baseCommit","reviewBaseCommit","taskBranchHead","executionDigest","reviewPackagePath",
          "reviewPackageSha256","approvalEvidenceDigest","createdAt","authorizedAt","authorizationSnapshotSha256"}
if not isinstance(data,dict) or set(data)!=required or data.get("schemaVersion")!=1: fail("schema/fields mismatch")
if data.get("team")!=team or data.get("featureId")!=feature: fail("team/feature mismatch")
if data.get("phase") not in {"awaiting-authorization","authorized"}: fail("invalid phase")
material={name:data[name] for name in ("team","featureId","taskId","attempt","executionDigest","baseCommit",
    "reviewBaseCommit","taskBranchHead","reviewPackageSha256","approvalEvidenceDigest")}
canonical=json.dumps(material,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
if data.get("preparationId") != "integration-prep-"+hashlib.sha256(canonical).hexdigest()[:32]: fail("id mismatch")
env={name:os.environ[name] for name in ("PATH","TMPDIR","LANG","LC_ALL") if name in os.environ}
env.setdefault("PATH","/usr/bin:/bin"); env.update({"GIT_CONFIG_GLOBAL":os.devnull,"GIT_CONFIG_NOSYSTEM":"1"})
def git(*args):
    result=subprocess.run(["git","-c","core.hooksPath=/dev/null","-c","core.fsmonitor=false",*args],cwd=repo,text=True,capture_output=True,env=env)
    if result.returncode: fail("Git check failed: "+(result.stderr.strip() or result.stdout.strip()))
    return result.stdout.strip()
if git("rev-parse","refs/heads/"+team) != data["baseCommit"]: fail("feature branch moved after preparation")
if git("rev-parse","refs/heads/"+data["branch"]) != data["taskBranchHead"]: fail("task branch moved after preparation")
if git("merge-base",data["baseCommit"],data["taskBranchHead"]) != data["reviewBaseCommit"]: fail("review base mismatch")
package=Path(str(data["reviewPackagePath"]))
try: package.resolve().relative_to(workspace)
except (OSError,ValueError): fail("review package escapes workspace")
regular(package,"review package")
if "sha256:"+hashlib.sha256(package.read_bytes()).hexdigest()!=data["reviewPackageSha256"]: fail("review package changed")
tracked=next((item for item in payload.get("tasks") or [] if str(item.get("taskId"))==data["taskId"]),None)
if not tracked: fail("task absent from fresh tracker snapshot")
review_statuses={item.get("name") for item in board.get("tasks",{}).get("statuses",[]) if item.get("kind")=="review"}
if tracked.get("status") not in review_statuses: fail("task is no longer in review")
try:
    evidence=validate_review_evidence(payload,data["taskId"],base=data["reviewBaseCommit"],head=data["taskBranchHead"],
                                      package=data["reviewPackageSha256"],review_statuses=review_statuses)
except EvidenceError as exc: fail("fresh review evidence rejected: %s"%exc)
if evidence != data["approvalEvidenceDigest"]: fail("fresh approval evidence differs from prepared evidence")
comments=tracked.get("comments") or []; marker_re=re.compile(r"^\s*\[([\w-]+)\]"); positions={}
for index,comment in enumerate(comments):
    match=marker_re.match(str(comment.get("body") or ""))
    if match: positions[match.group(1)]=index
def files(body,marker):
    match=re.search(r"(?mi)^\s*Files:\s*([^\n]+)$",body)
    if not match: fail("[%s] lacks Files evidence"%marker)
    return {part.strip().strip("`") for part in match.group(1).split(",") if part.strip()}
raw=subprocess.run(["git","-c","core.hooksPath=/dev/null","-c","core.fsmonitor=false","diff","--name-only","-z",
                    data["reviewBaseCommit"]+".."+data["taskBranchHead"]],cwd=repo,capture_output=True,env=env,check=True).stdout
actual={item.decode("utf-8","surrogateescape") for item in raw.split(b"\0") if item}
for marker in ("review-request","review-approval","architecture-approval","sceptical-architecture-approval"):
    if files(str(comments[positions[marker]].get("body") or ""),marker)!=actual: fail("[%s] Files evidence mismatch"%marker)
snapshot_digest="sha256:"+hashlib.sha256(snapshot.read_bytes()).hexdigest()
# This second read is intentionally adjacent to the authorization journal
# write; the earlier shell check only fences the tracker export.
assert_unheld(data["taskId"])
data["phase"]="authorized"; data["authorizedAt"]=datetime.now(timezone.utc).isoformat(timespec="seconds")
data["authorizationSnapshotSha256"]=snapshot_digest
temp=str(entry)+".tmp.%s"%os.getpid(); fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w") as handle:
    json.dump(data,handle,indent=2,ensure_ascii=False); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
os.replace(temp,entry)
directory=os.open(entry.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(directory); os.close(directory)
print("authorized "+data["preparationId"])
PY
}

late_invalidation() {
  python3 - "$1" "$2" <<'PY'
import json,re,sys
transaction,snapshot=map(lambda value: json.load(open(value)),sys.argv[1:])
if transaction.get("phase") not in {"awaiting-tracker", "completed"}: raise SystemExit(1)
task=next((item for item in snapshot.get("tasks") or [] if str(item.get("taskId"))==transaction.get("taskId")),None)
if not task: raise SystemExit(1)
positions={}
for index,comment in enumerate(task.get("comments") or []):
    match=re.match(r"^\s*\[([\w-]+)\]",str(comment.get("body") or ""))
    if match: positions[match.group(1)]=index
request=positions.get("review-request",-1); findings=positions.get("review-findings",-1)
raise SystemExit(0 if request >= 0 and findings > request else 1)
PY
}

run_recovery_validation() {
  local changed="$1" value command
  value="$(read_key VALIDATE_SCRIPT)"
  if [ -n "$value" ]; then
    local changed_files=() item
    while IFS= read -r item; do [ -z "$item" ] || changed_files+=("$item"); done < "$changed"
    ( cd "$repo" && "$value" "${changed_files[@]}" ) || return $?
    return
  fi
  for command in VALIDATE_BUILD VALIDATE_TEST VALIDATE_LINT VALIDATE_FORMAT; do
    value="$(read_key "$command")"
    [ -z "$value" ] || ( cd "$repo" && eval "$value" ) || return $?
  done
}

supersede_one() {
  local entry="$1" snapshot="$2" fields task role attempt commit worktree body txid phase key
  fields="$(validate_unheld_entry "$entry")"
  task="$(printf '%s\n' "$fields" | sed -n '1p')"; role="$(printf '%s\n' "$fields" | sed -n '2p')"
  attempt="$(printf '%s\n' "$fields" | sed -n '3p')"; commit="$(printf '%s\n' "$fields" | sed -n '4p')"
  worktree="$(printf '%s\n' "$fields" | sed -n '5p')"; body="$(printf '%s\n' "$fields" | sed -n '6p')"
  txid="$(printf '%s\n' "$fields" | sed -n '7p')"; phase="$(printf '%s\n' "$fields" | sed -n '8p')"
  case "$phase" in
    awaiting-tracker|completed) ;;
    *) die "late invalidation recovery only applies to merged integrations" ;;
  esac
  key="$(basename "$entry" .json)"
  local recovery_dir history_dir recovery changed recovery_fields recovery_id pre_head revert_commit recovery_snapshot
  recovery_dir="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative integrations/.recoveries)"
  history_dir="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative integrations/history)"
  mkdir -p "$recovery_dir" "$history_dir"
  recovery="$recovery_dir/$key.json"
  pre_head="$(git_unprivileged -C "$repo" rev-parse "$team")"
  if [ ! -e "$recovery" ]; then
    assert_task_not_held "$task"
    python3 - "$entry" "$snapshot" "$recovery" "$team" "$feature" "$task" "$txid" "$commit" "$pre_head" <<'PY'
import hashlib,json,os,re,sys
from datetime import datetime,timezone
tx_raw,snapshot_raw,path,team,feature,task,txid,commit,pre_head=sys.argv[1:]
tx_bytes=open(tx_raw,"rb").read(); snap_bytes=open(snapshot_raw,"rb").read(); snapshot=json.loads(snap_bytes)
tracked=next((item for item in snapshot.get("tasks") or [] if str(item.get("taskId"))==task),None)
if not tracked: raise SystemExit("finalize-integrations: invalidation task absent from fresh snapshot")
positions={}
for index,item in enumerate(tracked.get("comments") or []):
    match=re.match(r"^\s*\[([\w-]+)\]",str(item.get("body") or ""))
    if match: positions[match.group(1)]=index
if positions.get("review-findings",-1) <= positions.get("review-request",-1):
    raise SystemExit("finalize-integrations: invalidation evidence is not later than the approved request")
snapshot_digest="sha256:"+hashlib.sha256(snap_bytes).hexdigest(); tx_digest="sha256:"+hashlib.sha256(tx_bytes).hexdigest()
material={"transactionId":txid,"transactionSha256":tx_digest,"invalidationSnapshotSha256":snapshot_digest,
          "preRevertHead":pre_head,"integrationCommit":commit}
canonical=json.dumps(material,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
value={"schemaVersion":1,"recoveryId":"integration-recovery-"+hashlib.sha256(canonical).hexdigest()[:32],
       "team":team,"featureId":feature,"taskId":task,"transactionId":txid,"transactionSha256":tx_digest,
       "integrationCommit":commit,"preRevertHead":pre_head,"phase":"revert-prepared","revertCommit":None,
       "invalidationSnapshotSha256":snapshot_digest,"invalidationTask":tracked,
       "createdAt":datetime.now(timezone.utc).isoformat(timespec="seconds"),"updatedAt":datetime.now(timezone.utc).isoformat(timespec="seconds")}
temp=path+".tmp.%s"%os.getpid(); fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w") as handle:
    json.dump(value,handle,indent=2,ensure_ascii=False); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
os.replace(temp,path); directory=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(directory); os.close(directory)
PY
    if [ "${INTEGRATION_TEST_CRASH_AT:-}" = "after-recovery-prepare" ]; then kill -KILL "$$"; fi
  fi
  recovery_fields="$(python3 - "$recovery" "$entry" "$team" "$feature" "$task" "$txid" "$commit" <<'PY'
import hashlib,json,os,stat,sys
path,tx_raw,team,feature,task,txid,commit=sys.argv[1:]
mode=os.lstat(path).st_mode
if os.path.islink(path) or not stat.S_ISREG(mode): raise SystemExit("finalize-integrations: unsafe recovery journal")
data=json.load(open(path)); required={"schemaVersion","recoveryId","team","featureId","taskId","transactionId",
"transactionSha256","integrationCommit","preRevertHead","phase","revertCommit","invalidationSnapshotSha256",
"invalidationTask","createdAt","updatedAt"}
if set(data)!=required or data.get("schemaVersion")!=1: raise SystemExit("finalize-integrations: recovery schema mismatch")
expected={"team":team,"featureId":feature,"taskId":task,"transactionId":txid,"integrationCommit":commit}
if any(data.get(k)!=v for k,v in expected.items()): raise SystemExit("finalize-integrations: recovery identity mismatch")
if data.get("transactionSha256")!="sha256:"+hashlib.sha256(open(tx_raw,"rb").read()).hexdigest():
    raise SystemExit("finalize-integrations: transaction changed after recovery preparation")
if data.get("phase") not in {"revert-prepared","reverted"}: raise SystemExit("finalize-integrations: invalid recovery phase")
print(data["recoveryId"]); print(data["preRevertHead"]); print(data.get("revertCommit") or "")
PY
)"
  recovery_id="$(printf '%s\n' "$recovery_fields" | sed -n '1p')"
  pre_head="$(printf '%s\n' "$recovery_fields" | sed -n '2p')"
  revert_commit="$(printf '%s\n' "$recovery_fields" | sed -n '3p')"
  [ "$(git_unprivileged -C "$repo" branch --show-current)" = "$team" ] || die "recovery checkout is not on '$team'"
  if [ -z "$revert_commit" ]; then
    # A crash may have landed the revert commit before its journal phase update.
    revert_commit="$(git_unprivileged -C "$repo" log "$team" --format='%H' --grep="^Integration-Recovery: $recovery_id$" -n 1)"
  fi
  if [ -z "$revert_commit" ]; then
    assert_task_not_held "$task"
    [ "$(git_unprivileged -C "$repo" rev-parse HEAD)" = "$pre_head" ] \
      || die "feature branch moved during late-invalidation recovery; manual rebase/recovery required"
    [ -z "$(git_unprivileged -C "$repo" status --porcelain -uall)" ] || die "feature checkout is dirty before recovery"
    if ! git_unprivileged -C "$repo" revert --no-commit -m 1 "$commit"; then
      git_unprivileged -C "$repo" revert --abort >/dev/null 2>&1 || true
      die "late-invalidation revert conflicts; preserved recovery journal requires human resolution"
    fi
    changed="$recovery_dir/$key.changed-files"
    git_unprivileged -C "$repo" diff --name-only HEAD > "$changed"
    if ! run_recovery_validation "$changed"; then
      git_unprivileged -C "$repo" revert --abort >/dev/null 2>&1 || true
      die "late-invalidation revert failed project validation; recovery journal preserved"
    fi
    if ! assert_task_not_held "$task"; then
      git_unprivileged -C "$repo" revert --abort >/dev/null 2>&1 || true
      die "task hold appeared during late-invalidation validation; revert aborted"
    fi
    git_unprivileged -C "$repo" commit -m "revert: late findings for $task" -m "Task-Id: $task
Supersedes-Integration: $txid
Integration-Recovery: $recovery_id"
    revert_commit="$(git_unprivileged -C "$repo" rev-parse HEAD)"
    if [ "${INTEGRATION_TEST_CRASH_AT:-}" = "after-revert-commit" ]; then kill -KILL "$$"; fi
  fi
  git_unprivileged -C "$repo" merge-base --is-ancestor "$revert_commit" "$team" \
    || die "recorded recovery commit is not on the feature branch"
  assert_task_not_held "$task"
  python3 - "$recovery" "$recovery_id" "$revert_commit" <<'PY'
import json,os,sys
from datetime import datetime,timezone
path,recovery_id,revert=sys.argv[1:]; data=json.load(open(path))
if data.get("recoveryId")!=recovery_id: raise SystemExit("finalize-integrations: recovery id changed")
if data.get("revertCommit") not in (None,revert): raise SystemExit("finalize-integrations: recovery commit changed")
data["phase"]="reverted"; data["revertCommit"]=revert; data["updatedAt"]=datetime.now(timezone.utc).isoformat(timespec="seconds")
temp=path+".tmp.%s"%os.getpid(); fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w") as handle:
    json.dump(data,handle,indent=2,ensure_ascii=False); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
os.replace(temp,path)
PY
  recovery_snapshot="$pm_dir/integration-recovery-snapshot.json"
  "$SKILL_DIR/bin/tracker-ops.sh" export "$feature" "$recovery_snapshot" >/dev/null
  working_status="$(python3 - "$SKILL_DIR/config/statuses.config.json" <<'PY'
import json,sys
values=[item["name"] for item in json.load(open(sys.argv[1]))["tasks"]["statuses"] if item.get("kind")=="working"]
if len(values)!=1: raise SystemExit("finalize-integrations: expected one working task status")
print(values[0])
PY
)"
  assert_task_not_held "$task"
  if [ "$phase" = "completed" ]; then
    STARTUP_FACTORY_INTEGRATION_BROKER=1 "$SKILL_DIR/bin/tracker-ops.sh" task-reopen "$task" "$working_status"
  else
    "$SKILL_DIR/bin/tracker-ops.sh" state "$task" "$working_status"
  fi
  if ! python3 - "$recovery_snapshot" "$task" "$recovery_id" <<'PY'
import json,sys
payload=json.load(open(sys.argv[1])); task=next((i for i in payload.get("tasks") or [] if str(i.get("taskId"))==sys.argv[2]),{})
token="Recovery-Id: "+sys.argv[3]
raise SystemExit(0 if any(token in str(c.get("body") or "") for c in task.get("comments") or []) else 1)
PY
  then
    assert_task_not_held "$task"
    printf '[integration-superseded]\nRecovery-Id: %s\nOriginal integration: %s\nRevert commit: %s\nLate review findings invalidated the merge. History is preserved; rework and a new review are required.\n\n— dispatcher\n' \
      "$recovery_id" "$commit" "$revert_commit" | "$SKILL_DIR/bin/tracker-ops.sh" comment "$task" -
  fi
  assert_task_not_held "$task"
  python3 - "$recovery" "$recovery_id" <<'PY'
import json,os,sys
from datetime import datetime,timezone
path,rid=sys.argv[1:]; data=json.load(open(path))
if data.get("recoveryId")!=rid or data.get("phase")!="reverted": raise SystemExit("finalize-integrations: recovery phase changed")
data["phase"]="superseded"; data["updatedAt"]=datetime.now(timezone.utc).isoformat(timespec="seconds")
temp=path+".tmp.%s"%os.getpid(); fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w") as handle:
    json.dump(data,handle,indent=2,ensure_ascii=False); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
os.replace(temp,path)
PY
  archive="$history_dir/$key-$txid.json"
  [ ! -e "$archive" ] || die "integration history collision for $txid"
  mv "$entry" "$archive"
  mv "$recovery" "$history_dir/$key-$recovery_id.json"
  echo "$task integration $txid superseded by preserved revert $revert_commit; rework may proceed"
}

if [ "$authorize_prepared" = "yes" ]; then
  authorize_preparation "$only"
  exit 0
fi

# The dispatch lease makes this the credentialed pre-commit authorization
# broker. Preparations are intentionally outside the final transaction glob.
prepared_dir="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative integrations/.prepared)"
if [ -d "$prepared_dir" ] && [ ! -L "$prepared_dir" ]; then
  for prepared_entry in "$prepared_dir"/*.json; do
    [ -e "$prepared_entry" ] || [ -L "$prepared_entry" ] || continue
    authorize_preparation "$prepared_entry"
  done
fi

if [ -n "$only" ]; then
  set -- "$only"
else
  set -- "$integrations"/*.json
fi

# Validate structural, Git, execution, package, and (when supplied) tracker
# evidence bindings. Output is a stable line protocol consumed below.
validate_entry() {
  local entry="$1" snapshot="${2:-}"
  python3 - "$entry" "$repo" "$workspace" "$team" "$feature" "$snapshot" "$SKILL_DIR/config/statuses.config.json" "$SKILL_DIR/bin/review_evidence.py" <<'PY'
import hashlib, json, os, re, stat, subprocess, sys
from pathlib import Path

entry_raw, repo_raw, workspace_raw, team, feature, snapshot_raw, board_raw, review_module_raw = sys.argv[1:]
repo, workspace = Path(repo_raw).resolve(), Path(workspace_raw).resolve()
entry = Path(entry_raw)
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(review_module_raw).resolve().parent))
from review_evidence import EvidenceError, validate as validate_review_evidence
GIT_ENV = {name: os.environ[name] for name in ("PATH", "TMPDIR", "LANG", "LC_ALL") if name in os.environ}
GIT_ENV.setdefault("PATH", "/usr/bin:/bin")
GIT_ENV.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})

def git_command(argv):
    if argv and argv[0] == "git":
        return ("git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *argv[1:])
    return argv

def fail(message):
    raise SystemExit("finalize-integrations: " + message)

def regular(path, label, maximum=65536):
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        fail("%s is unavailable: %s" % (label, exc))
    if not stat.S_ISREG(mode) or path.is_symlink():
        fail("%s must be a non-symlink regular file" % label)
    if path.stat().st_size > maximum:
        fail("%s exceeds %d bytes" % (label, maximum))

def contained(path, base, label):
    try:
        path.resolve().relative_to(base.resolve())
    except (OSError, ValueError):
        fail("%s escapes the team workspace" % label)

def run(*argv, input_text=None):
    command = git_command(argv)
    result = subprocess.run(
        command, cwd=repo, text=True, input=input_text, capture_output=True,
        env=GIT_ENV if argv and argv[0] == "git" else None,
    )
    if result.returncode:
        fail("command failed (%s): %s" % (" ".join(argv), result.stderr.strip() or result.stdout.strip()))
    return result.stdout

def safe_key(value):
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()[:32] or "task"
    return "%s-%s" % (slug, hashlib.sha256(value.encode()).hexdigest()[:10])

regular(entry, "transaction")
integration_dir = (workspace / "integrations").resolve()
if entry.resolve().parent != integration_dir:
    fail("transaction escapes integrations directory")
try:
    data = json.loads(entry.read_text())
except (OSError, ValueError) as exc:
    fail("invalid transaction JSON: %s" % exc)
if not isinstance(data, dict) or data.get("schemaVersion") != 2:
    fail("unsupported integration transaction schema")
required = {
    "schemaVersion", "transactionId", "team", "featureId", "taskId", "taskKey", "role",
    "attempt", "branch", "worktree", "phase", "baseCommit", "reviewBaseCommit", "taskBranchHead", "commit",
    "executionDigest", "reviewPackagePath", "reviewPackageSha256", "approvalEvidenceDigest",
    "completionBodyPath", "completionBodySha256", "updatedAt",
}
unknown, missing = set(data) - required, required - set(data)
if unknown or missing:
    fail("transaction fields mismatch (missing=%s unknown=%s)" % (sorted(missing), sorted(unknown)))
if data["team"] != team or data["featureId"] != feature:
    fail("transaction team/feature does not match this broker invocation")
for name in ("featureId", "taskId"):
    value = data.get(name)
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        fail("invalid %s" % name)
role = data.get("role")
if not isinstance(role, str) or not re.fullmatch(r"[a-z0-9-]{2,80}", role):
    fail("invalid role")
if type(data.get("attempt")) is not int or data["attempt"] < 1:
    fail("attempt must be a positive integer")
if data.get("phase") not in {"awaiting-tracker", "tracker-finalized", "event-emitted", "completed"}:
    fail("invalid transaction phase")
task, attempt = data["taskId"], data["attempt"]
key = safe_key(task)
if data.get("taskKey") != key or entry.name != key + ".json":
    fail("transaction filename/task key binding mismatch")
expected_branch = "agent-task/" + team + "/" + key
expected_worktree = workspace / "worktrees" / ("%s#%s-%s" % (role, attempt, key))
if data.get("branch") != expected_branch or Path(str(data.get("worktree"))) != expected_worktree:
    fail("transaction branch/worktree binding mismatch")

execution_path = workspace / "executions" / (key + ".json")
regular(execution_path, "execution record")
contained(execution_path, workspace, "execution record")
try:
    execution = json.loads(execution_path.read_text())
except (OSError, ValueError) as exc:
    fail("invalid execution record: %s" % exc)
expected_exec = {
    "schemaVersion": 1,
    "featureId": feature,
    "taskId": task,
    "taskKey": key,
    "attempt": attempt,
    "role": role,
    "branch": expected_branch,
    "worktree": str(expected_worktree),
    "packetPath": str(workspace / "artifacts" / key / ("attempt-%s" % attempt) / "task-packet.md"),
    "packetJsonPath": str(workspace / "artifacts" / key / ("attempt-%s" % attempt) / "task-packet.json"),
    "reportPath": str(workspace / "artifacts" / key / ("attempt-%s" % attempt) / "task-report.md"),
}
for name, value in expected_exec.items():
    if execution.get(name) != value:
        fail("execution record %s does not match transaction identity" % name)
canonical_exec = json.dumps(expected_exec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
execution_digest = "sha256:" + hashlib.sha256(canonical_exec).hexdigest()
if data.get("executionDigest") != execution_digest:
    fail("execution digest mismatch")

hex_re = re.compile(r"[0-9a-f]{40,64}")
for name in ("baseCommit", "reviewBaseCommit", "taskBranchHead", "commit"):
    if not isinstance(data.get(name), str) or not hex_re.fullmatch(data[name]):
        fail("invalid %s" % name)
    resolved = run("git", "rev-parse", "--verify", data[name] + "^{commit}").strip()
    if resolved != data[name]:
        fail("%s is not the repository's canonical full commit id" % name)
branch_head = run("git", "rev-parse", "--verify", "refs/heads/" + expected_branch).strip()
if branch_head != data["taskBranchHead"]:
    fail("task branch moved after review/integration")
parents = run("git", "show", "-s", "--format=%P", data["commit"]).strip().split()
if parents != [data["baseCommit"], data["taskBranchHead"]]:
    fail("integration commit parents do not bind base + reviewed task head")
review_base = run("git", "merge-base", data["baseCommit"], data["taskBranchHead"]).strip()
if review_base != data["reviewBaseCommit"]:
    fail("review base is not the exact merge-base of integration parent + task head")
if subprocess.run(
    git_command(("git", "merge-base", "--is-ancestor", data["commit"], team)),
    cwd=repo, env=GIT_ENV,
).returncode:
    fail("integration commit is not on the feature branch")

review_path = Path(str(data.get("reviewPackagePath")))
base_short = run("git", "rev-parse", "--short", data["reviewBaseCommit"]).strip()
head_short = run("git", "rev-parse", "--short", data["taskBranchHead"]).strip()
expected_review_path = workspace / "artifacts" / key / ("review-%s..%s.diff" % (base_short, head_short))
if review_path != expected_review_path:
    fail("review package path is not the exact generated package for base/head")
regular(review_path, "review package", maximum=8 * 1024 * 1024)
contained(review_path, workspace, "review package")
expected_package = "\n".join([
    "# Review package: %s" % task,
    "",
    "Base: %s" % data["reviewBaseCommit"],
    "Head: %s" % data["taskBranchHead"],
    "",
    "## Commits",
    run("git", "log", "--oneline", "%s..%s" % (data["reviewBaseCommit"], data["taskBranchHead"])).rstrip("\n"),
    "",
    "## Files changed",
    run("git", "diff", "--stat", "%s..%s" % (data["reviewBaseCommit"], data["taskBranchHead"])).rstrip("\n"),
    "",
    "## Diff",
    run("git", "diff", "-U10", "%s..%s" % (data["reviewBaseCommit"], data["taskBranchHead"])).rstrip("\n"),
]) + "\n"
actual_package = review_path.read_bytes()
if actual_package != expected_package.encode():
    fail("review package does not exactly reproduce the reviewed Git diff")
review_digest = "sha256:" + hashlib.sha256(actual_package).hexdigest()
if data.get("reviewPackageSha256") != review_digest:
    fail("review package digest mismatch")

body_path = Path(str(data.get("completionBodyPath")))
expected_body = workspace / "artifacts" / key / "integration-completion.md"
if body_path != expected_body:
    fail("completion body path mismatch")
regular(body_path, "completion body")
contained(body_path, workspace, "completion body")
body_digest = "sha256:" + hashlib.sha256(body_path.read_bytes()).hexdigest()
if data.get("completionBodySha256") != body_digest:
    fail("completion body digest mismatch")

message = run("git", "show", "-s", "--format=%B", data["commit"])
parsed = run("git", "interpret-trailers", "--parse", input_text=message)
trailers = {}
for line in parsed.splitlines():
    if ":" not in line:
        continue
    name, value = line.split(":", 1)
    trailers.setdefault(name.strip(), []).append(value.strip())
expected_trailers = {
    "Feature-Id": feature,
    "Task-Id": task,
    "Task-Role": role,
    "Task-Attempt": str(attempt),
    "Task-Branch": expected_branch,
    "Task-Branch-Head": data["taskBranchHead"],
    "Review-Base-Commit": data["reviewBaseCommit"],
    "Task-Execution": execution_digest,
    "Review-Package-SHA256": review_digest,
    "Approval-Evidence-SHA256": data["approvalEvidenceDigest"],
}

# The prepared intent is deterministic from immutable integration material and
# must still exist as broker evidence. This makes the pre-commit authorization
# independently enforceable instead of trusting producer-authored extra trailers.
prep_material = {
    "team": team,
    "featureId": feature,
    "taskId": task,
    "attempt": attempt,
    "executionDigest": execution_digest,
    "baseCommit": data["baseCommit"],
    "reviewBaseCommit": data["reviewBaseCommit"],
    "taskBranchHead": data["taskBranchHead"],
    "reviewPackageSha256": review_digest,
    "approvalEvidenceDigest": data["approvalEvidenceDigest"],
}
prep_canonical = json.dumps(prep_material, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
preparation_id = "integration-prep-" + hashlib.sha256(prep_canonical).hexdigest()[:32]
preparation_path = workspace / "integrations" / ".prepared-history" / (preparation_id + ".json")
regular(preparation_path, "prepared authorization", maximum=1024 * 1024)
contained(preparation_path, workspace, "prepared authorization")
try:
    preparation = json.loads(preparation_path.read_text())
except (OSError, ValueError) as exc:
    fail("invalid prepared authorization: %s" % exc)
required_preparation = {
    "schemaVersion", "preparationId", "team", "featureId", "taskId", "taskKey", "role", "attempt",
    "branch", "worktree", "phase", "baseCommit", "reviewBaseCommit", "taskBranchHead",
    "executionDigest", "reviewPackagePath", "reviewPackageSha256", "approvalEvidenceDigest",
    "createdAt", "authorizedAt", "authorizationSnapshotSha256",
}
if not isinstance(preparation, dict) or set(preparation) != required_preparation:
    fail("prepared authorization fields mismatch")
for name, value in {
    "schemaVersion": 1, "preparationId": preparation_id, "team": team, "featureId": feature,
    "taskId": task, "taskKey": key, "role": role, "attempt": attempt, "branch": expected_branch,
    "worktree": str(expected_worktree), "phase": "authorized", "baseCommit": data["baseCommit"],
    "reviewBaseCommit": data["reviewBaseCommit"], "taskBranchHead": data["taskBranchHead"],
    "executionDigest": execution_digest, "reviewPackagePath": str(review_path),
    "reviewPackageSha256": review_digest, "approvalEvidenceDigest": data["approvalEvidenceDigest"],
}.items():
    if preparation.get(name) != value:
        fail("prepared authorization %s mismatch" % name)
if not isinstance(preparation.get("authorizedAt"), str) or not re.fullmatch(
    r"sha256:[0-9a-f]{64}", str(preparation.get("authorizationSnapshotSha256"))
):
    fail("prepared authorization lacks fresh broker evidence")
expected_trailers.update({
    "Integration-Preparation": preparation_id,
    "Authorization-Snapshot-SHA256": preparation["authorizationSnapshotSha256"],
})
for name, value in expected_trailers.items():
    if trailers.get(name) != [value]:
        fail("integration commit has missing/duplicate/mismatched %s trailer" % name)

tx_material = {
    "team": team,
    "featureId": feature,
    "taskId": task,
    "attempt": attempt,
    "executionDigest": execution_digest,
    "baseCommit": data["baseCommit"],
    "reviewBaseCommit": data["reviewBaseCommit"],
    "taskBranchHead": data["taskBranchHead"],
    "commit": data["commit"],
    "reviewPackageSha256": review_digest,
    "approvalEvidenceDigest": data["approvalEvidenceDigest"],
}
tx_canonical = json.dumps(tx_material, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
expected_txid = "integration-" + hashlib.sha256(tx_canonical).hexdigest()[:32]
if data.get("transactionId") != expected_txid:
    fail("transaction id does not match immutable integration material")

if snapshot_raw:
    try:
        payload = json.load(open(snapshot_raw))
    except (OSError, ValueError) as exc:
        fail("invalid fresh tracker snapshot: %s" % exc)
    tracked = next((item for item in payload.get("tasks") or [] if str(item.get("taskId")) == task), None)
    if not tracked:
        fail("task is absent from fresh tracker snapshot")
    try:
        board = json.load(open(board_raw))
    except (OSError, ValueError) as exc:
        fail("invalid board config: %s" % exc)
    review_statuses = {item.get("name") for item in board.get("tasks", {}).get("statuses", []) if item.get("kind") == "review"}
    terminal_statuses = {item.get("name") for item in board.get("tasks", {}).get("statuses", []) if item.get("terminal") and item.get("requiresCommit")}
    if tracked.get("status") not in review_statuses | terminal_statuses:
        fail("fresh tracker task is neither in review nor commit-requiring terminal state")
    comments = tracked.get("comments") or []
    marker_re = re.compile(r"^\s*\[([\w-]+)\]")
    positions = {}
    for index, comment in enumerate(comments):
        match = marker_re.match(str(comment.get("body") or ""))
        if match:
            positions[match.group(1)] = index
    request = positions.get("review-request", -1)
    review = positions.get("review-approval", -1)
    architecture = positions.get("architecture-approval", -1)
    sceptical = positions.get("sceptical-architecture-approval", -1)
    findings = positions.get("review-findings", -1)
    if request < 0 or review <= request or architecture <= request or sceptical <= request or findings > request:
        fail("fresh tracker state is no longer independently triple-approved")
    try:
        evidence_digest = validate_review_evidence(
            payload,
            task,
            base=data["reviewBaseCommit"],
            head=data["taskBranchHead"],
            package=review_digest,
        )
    except EvidenceError as exc:
        fail("review approval binding failed: %s" % exc)
    if data.get("approvalEvidenceDigest") != evidence_digest:
        fail("current approval evidence differs from the integrated evidence")

    integration_token = "Integrated: commit %s." % data["commit"]
    has_integration_comment = any(integration_token in str(item.get("body") or "") for item in comments)
    event_path = workspace / "events.ndjson"
    has_integration_event = False
    if event_path.exists():
        regular(event_path, "durable event log", maximum=64 * 1024 * 1024)
        contained(event_path, workspace, "durable event log")
        for line in event_path.read_text().splitlines():
            try: event = json.loads(line)
            except ValueError: fail("malformed durable event log")
            if (
                event.get("type") == "task.integrated"
                and event.get("taskId") == task
                and event.get("attempt") == attempt
                and event.get("actor") == "dispatcher"
                and event.get("stage") == "integrated"
                and event.get("summary") == "tracker finalized for integration transaction %s" % data["transactionId"]
                and event.get("artifact") == str(body_path)
            ):
                has_integration_event = True
    if data["phase"] == "completed":
        if tracked.get("status") not in terminal_statuses or not has_integration_comment:
            fail("completed transaction lacks exact terminal tracker evidence")
        if not has_integration_event:
            fail("completed transaction lacks its broker-owned durable event")

    # The existing protocol exposes Files: lists on the request and approvals.
    # Bind the request and all three approvals to the exact reviewed Git file set.
    def file_list(body, marker):
        match = re.search(r"(?mi)^\s*Files:\s*([^\n]+)$", body)
        if not match:
            fail("[%s] is missing its Files: evidence" % marker)
        values = {part.strip().strip("`") for part in match.group(1).split(",") if part.strip()}
        if not values:
            fail("[%s] has an empty Files: evidence" % marker)
        return values
    actual_raw = subprocess.run(
        git_command(("git", "diff", "--name-only", "-z", "%s..%s" % (data["reviewBaseCommit"], data["taskBranchHead"]))),
        cwd=repo, capture_output=True, env=GIT_ENV,
    )
    if actual_raw.returncode:
        fail("cannot calculate exact reviewed file set")
    actual_files = {item.decode("utf-8", "surrogateescape") for item in actual_raw.stdout.split(b"\0") if item}
    for marker, index in (
        ("review-request", request),
        ("review-approval", review),
        ("architecture-approval", architecture),
        ("sceptical-architecture-approval", sceptical),
    ):
        if file_list(str(comments[index].get("body") or ""), marker) != actual_files:
            fail("[%s] Files: evidence does not equal the exact reviewed Git file set" % marker)

    preset = workspace / "preset.env"
    if preset.is_file() and not preset.is_symlink():
        preset_text = preset.read_text()
        for protocol_name, marker_name, marker_index in (
            ("REVIEWER", "review-approval", review),
            ("PRINCIPAL_ARCHITECT", "architecture-approval", architecture),
            ("SCEPTICAL_ARCHITECT", "sceptical-architecture-approval", sceptical),
        ):
            match = re.search(r"^PROTOCOL_%s=(.+)$" % protocol_name, preset_text, re.M)
            if not match:
                continue
            signer_match = re.search(
                r"(?:\u2014|-)\s*([\w-]+)(?:\s*\((?:posted by[^)]*|as [^)]+)\))?\s*$",
                str(comments[marker_index].get("body") or "").strip(),
            )
            if not signer_match or signer_match.group(1) != match.group(1).strip():
                fail("current %s signer does not match preset protocol gate" % marker_name)

worktree = Path(data["worktree"])
if worktree.exists():
    if worktree.is_symlink() or not worktree.is_dir():
        fail("task worktree path is not a real directory")
    observed_root = Path(run("git", "-C", str(worktree), "rev-parse", "--show-toplevel").strip()).resolve()
    if observed_root != worktree.resolve():
        fail("task worktree Git identity mismatch")
    observed_branch = run("git", "-C", str(worktree), "branch", "--show-current").strip()
    if observed_branch != expected_branch:
        fail("task worktree is no longer on its execution branch")
    if run("git", "-C", str(worktree), "status", "--porcelain", "-uall"):
        fail("task worktree became dirty after integration")
    if snapshot_raw and data["phase"] == "completed":
        fail("completed transaction still has a task worktree")
elif snapshot_raw and data["phase"] == "completed":
    listing = run("git", "worktree", "list", "--porcelain")
    if any(line == "worktree %s" % worktree for line in listing.splitlines()):
        fail("completed transaction still has a registered task worktree")

for value in (
    task, role, str(attempt), data["commit"], str(worktree), str(body_path), data["transactionId"],
    data["phase"], data["taskBranchHead"], review_digest, data["approvalEvidenceDigest"], execution_digest,
):
    print(value)
PY
}

validate_unheld_entry() {
  local fields task
  fields="$(validate_entry "$@")"
  task="$(printf '%s\n' "$fields" | sed -n '1p')"
  assert_task_not_held "$task"
  printf '%s\n' "$fields"
}

advance_phase() {
  local entry="$1" txid="$2" expected="$3" next="$4"
  python3 - "$entry" "$txid" "$expected" "$next" <<'PY'
import json, os, stat, sys
from datetime import datetime, timezone
path, txid, expected, next_phase = sys.argv[1:]
mode=os.lstat(path).st_mode
if os.path.islink(path) or not stat.S_ISREG(mode):
    raise SystemExit("finalize-integrations: transaction changed into a non-regular file")
data=json.load(open(path))
if data.get("transactionId") != txid or data.get("phase") != expected:
    raise SystemExit("finalize-integrations: transaction changed during finalization")
data["phase"]=next_phase
data["updatedAt"]=datetime.now(timezone.utc).isoformat(timespec="seconds")
temp=path+".tmp.%s" % os.getpid()
fd=os.open(temp, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as handle:
    json.dump(data, handle, indent=2, ensure_ascii=False)
    handle.write("\n")
    handle.flush(); os.fsync(handle.fileno())
os.replace(temp, path)
PY
}

event_exists() {
  python3 - "$events_file" "$1" "$2" "$3" "$4" <<'PY'
import json, pathlib, sys
path, txid, task, attempt, artifact = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
if not path.exists(): raise SystemExit(1)
for line in path.read_text().splitlines():
    try: event=json.loads(line)
    except ValueError: raise SystemExit("finalize-integrations: malformed durable event log")
    if (
        event.get("type") == "task.integrated" and event.get("taskId") == task
        and event.get("attempt") == attempt and event.get("actor") == "dispatcher"
        and event.get("stage") == "integrated"
        and event.get("summary") == "tracker finalized for integration transaction %s" % txid
        and event.get("artifact") == artifact
    ):
        raise SystemExit(0)
raise SystemExit(1)
PY
}

worktree_registered() {
  python3 - "$repo" "$1" <<'PY'
import os, subprocess, sys
repo, wanted=sys.argv[1:]
env={name:os.environ[name] for name in ("PATH","TMPDIR","LANG","LC_ALL") if name in os.environ}
env.setdefault("PATH","/usr/bin:/bin")
env.update({"GIT_CONFIG_GLOBAL":os.devnull,"GIT_CONFIG_NOSYSTEM":"1"})
out=subprocess.check_output(
    ["git","-c","core.hooksPath=/dev/null","-c","core.fsmonitor=false","worktree","list","--porcelain"],
    cwd=repo,text=True,env=env,
)
paths=[line[len("worktree "):] for line in out.splitlines() if line.startswith("worktree ")]
raise SystemExit(0 if wanted in paths else 1)
PY
}

finalize_one() {
  local entry="$1" snapshot="$2" fields task role attempt commit worktree body txid phase
  fields="$(validate_unheld_entry "$entry" "$snapshot")"
  task="$(printf '%s\n' "$fields" | sed -n '1p')"
  role="$(printf '%s\n' "$fields" | sed -n '2p')"
  attempt="$(printf '%s\n' "$fields" | sed -n '3p')"
  commit="$(printf '%s\n' "$fields" | sed -n '4p')"
  worktree="$(printf '%s\n' "$fields" | sed -n '5p')"
  body="$(printf '%s\n' "$fields" | sed -n '6p')"
  txid="$(printf '%s\n' "$fields" | sed -n '7p')"
  phase="$(printf '%s\n' "$fields" | sed -n '8p')"
  if [ "$phase" = "completed" ]; then
    echo "$task integration already finalized at $commit"
    return 0
  fi

  local lock="$integrations/.locks/$(basename "$entry").lock" owner entries
  if ! mkdir "$lock" 2>/dev/null; then
    owner="$(cat "$lock/owner.pid" 2>/dev/null || true)"
    entries="$(find "$lock" -mindepth 1 -maxdepth 1 -print 2>/dev/null || true)"
    if [ -n "$owner" ] && case "$owner" in *[!0-9]*) false ;; *) ! kill -0 "$owner" 2>/dev/null ;; esac \
       && [ "$entries" = "$lock/owner.pid" ]; then
      rm -f "$lock/owner.pid"; rmdir "$lock"; mkdir "$lock"
    else
      die "transaction lock is live or malformed: $lock"
    fi
  fi
  printf '%s\n' "$$" > "$lock/owner.pid"

  # Revalidate after taking the transaction lock; the producer is untrusted.
  fields="$(validate_unheld_entry "$entry" "$snapshot")"
  phase="$(printf '%s\n' "$fields" | sed -n '8p')"
  if [ "$phase" != "completed" ]; then
    assert_task_not_held "$task"
    assert_tracker_task_review_authorized "$task"
    "$SKILL_DIR/bin/tracker-ops.sh" integrate "$task" "$commit" "$body"
  fi
  if [ "$phase" = "awaiting-tracker" ]; then
    assert_task_not_held "$task"
    advance_phase "$entry" "$txid" awaiting-tracker tracker-finalized
    phase=tracker-finalized
  fi
  if [ "$phase" != "completed" ]; then
    if ! event_exists "$txid" "$task" "$attempt" "$body"; then
      assert_task_not_held "$task"
      python3 "$SKILL_DIR/bin/runtime-state.py" emit --workspace "$workspace" --team "$team" \
        --feature "$feature" --task "$task" --attempt "$attempt" --actor dispatcher \
        --type task.integrated --stage integrated \
        --summary "tracker finalized for integration transaction $txid" --artifact "$body" >/dev/null
    fi
    if [ "$phase" = "tracker-finalized" ]; then
      assert_task_not_held "$task"
      advance_phase "$entry" "$txid" tracker-finalized event-emitted
      phase=event-emitted
    fi
  fi
  if [ "$phase" = "event-emitted" ]; then
    assert_task_not_held "$task"
    if [ -e "$worktree" ]; then
      [ -z "$(git_unprivileged -C "$worktree" status --porcelain -uall)" ] \
        || die "task worktree became dirty before cleanup: $worktree"
      git_unprivileged -C "$repo" worktree remove "$worktree"
    fi
    git_unprivileged -C "$repo" worktree prune
    [ ! -e "$worktree" ] || die "task worktree still exists after cleanup: $worktree"
    if worktree_registered "$worktree"; then
      die "task worktree is still registered after cleanup: $worktree"
    fi
    assert_task_not_held "$task"
    advance_phase "$entry" "$txid" event-emitted completed
    phase=completed
  fi
  rm -f "$lock/owner.pid"; rmdir "$lock"
  echo "$task integration finalized at $commit"
}

entries=()
for entry in "$@"; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  entries+=("$entry")
done
[ "${#entries[@]}" -gt 0 ] || exit 0

if [ "$validate_only" = "yes" ]; then
  [ "${#entries[@]}" -eq 1 ] || die "--validate-only requires exactly one transaction"
  validate_unheld_entry "${entries[0]}"
  exit 0
fi

# A fresh export is the authorization fence. Prevalidate every record before
# allowing any tracker write so one forged record blocks the whole pass.
snapshot="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative pm/integration-broker-snapshot.json)"
[ ! -L "$snapshot" ] || die "broker snapshot path is a symlink"
[ ! -e "$snapshot" ] || [ -f "$snapshot" ] || die "broker snapshot path is not a regular file"
"$SKILL_DIR/bin/tracker-ops.sh" export "$feature" "$snapshot" >/dev/null
for entry in "${entries[@]}"; do validate_unheld_entry "$entry" >/dev/null; done
authorized_entries=()
for entry in "${entries[@]}"; do
  if late_invalidation "$entry" "$snapshot"; then
    supersede_one "$entry" "$snapshot"
  else
    validate_unheld_entry "$entry" "$snapshot" >/dev/null
    authorized_entries+=("$entry")
  fi
done
for entry in "${authorized_entries[@]-}"; do
  [ -n "$entry" ] || continue
  finalize_one "$entry" "$snapshot"
done
