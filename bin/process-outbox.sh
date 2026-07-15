#!/usr/bin/env bash
# Publish queued artifacts idempotently; tracker state remains the durable source of truth.
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

# The PM supervisor pins this authority in the process environment. Direct
# broker invocations must consume the same configured root instead of silently
# falling back to the agent-writable workspace registry.
if [ -z "${STARTUP_FACTORY_LIFECYCLE_STATE_ROOT:-}" ]; then
  configured_lifecycle_root="$(read_key BROKER_LIFECYCLE_ROOT)"
  if [ -n "$configured_lifecycle_root" ]; then
    export STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$configured_lifecycle_root"
  fi
fi

[ $# -ge 2 ] && [ $# -le 3 ] || { echo "usage: process-outbox.sh <team> <featureId> [entry.json]" >&2; exit 2; }
team="$1"; feature="$2"; only="${3:-}"
repo="$(git rev-parse --show-toplevel)"
root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
workspace="$(python3 "$SKILL_DIR/bin/teamwork-path.py" workspace --repo "$repo" --root "$root" --team "$team")"
pending="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/pending)"
bodies="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/bodies)"
staged="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/staged)"
authority="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/authoritative)"
done="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/done)"
failed="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/failed)"
locks="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/locks)"
preset_file="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative preset.env)"
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative events.ndjson >/dev/null
mkdir -p "$pending" "$bodies" "$staged" "$authority" "$done" "$failed" "$locks"

current_snapshot=""
cleanup_snapshot() {
  if [ -n "$current_snapshot" ] && [ -f "$current_snapshot" ] && [ ! -L "$current_snapshot" ]; then
    rm -f -- "$current_snapshot"
  fi
  current_snapshot=""
}
trap cleanup_snapshot EXIT

reject_entry() {
  local entry="$1" rejected entry_dir pending_dir
  entry_dir="$(cd "$(dirname "$entry")" 2>/dev/null && pwd -P || true)"
  pending_dir="$(cd "$pending" && pwd -P)"
  if [ "$entry_dir" = "$pending_dir" ] && [ -f "$entry" ] && [ ! -L "$entry" ]; then
    rejected="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "outbox/failed/$(basename "$entry").rejected.$(date -u +%s).$$")"
    mv -- "$entry" "$rejected"
  fi
}

# A write authorization is deliberately short lived. Every call performs a new,
# exhaustive feature export and validates the exact feature/task/team execution
# scope. Call this immediately before each tracker comment or state mutation.
refresh_authority() {
  local entry="$1" validation_output=""
  cleanup_snapshot
  current_snapshot="$(mktemp "$authority/snapshot.XXXXXXXX")"
  if ! "$SKILL_DIR/bin/tracker-ops.sh" export "$feature" "$current_snapshot" >/dev/null; then
    cleanup_snapshot
    # An unavailable authoritative source says nothing about the queued
    # artifact's validity. Keep it pending and stop this broker pass so a later
    # scheduler tick can retry after the adapter recovers.
    return 75
  fi
  local hold_fields hold_task hold_marker hold_rc=0
  hold_fields="$(python3 - "$entry" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
print(str(value.get("taskId") or ""))
print(str(value.get("marker") or ""))
PY
)" || { cleanup_snapshot; return 1; }
  hold_task="$(printf '%s\n' "$hold_fields" | sed -n '1p')"
  hold_marker="$(printf '%s\n' "$hold_fields" | sed -n '2p')"
  python3 "$SKILL_DIR/bin/task-hold.py" check \
    --repo "$repo" --workspace "$workspace" --team "$team" --feature "$feature" \
    --task "$hold_task" --marker "$hold_marker" || hold_rc=$?
  if [ "$hold_rc" -ne 0 ]; then
    cleanup_snapshot
    return 1
  fi
  if ! validation_output="$(python3 - "$entry" "$workspace" "$team" "$feature" \
      "$SKILL_DIR/config/statuses.config.json" "$SKILL_DIR/config/project-management.config.md" \
      "$preset_file" "$pending" "$bodies" "$staged" "$current_snapshot" "$repo" "$SKILL_DIR" <<'PY'
import hashlib, json, os, re, stat, sys
from pathlib import Path

(entry, workspace, expected_team, expected_feature, board_path, pm_path,
 preset, pending, bodies, staged, snapshot_path, repository, skill_dir) = sys.argv[1:]

def fail(message):
    print("process-outbox: " + message, file=sys.stderr)
    raise SystemExit(1)

def regular_file(path, root, label):
    try:
        real = os.path.realpath(path)
        if os.path.commonpath([os.path.realpath(root), real]) != os.path.realpath(root):
            fail("%s must be inside its broker directory" % label)
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            fail("%s must be a non-symlink regular file" % label)
        if info.st_size <= 0 or info.st_size > 65536:
            fail("%s must contain 1..65536 bytes" % label)
        return Path(path), info
    except (OSError, ValueError) as exc:
        fail("invalid %s: %s" % (label, exc))

def read_json_regular(path, label):
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            fail("%s must be a non-symlink regular file" % label)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            return json.loads(os.read(descriptor, 2 * 1024 * 1024).decode())
        finally:
            os.close(descriptor)
    except (OSError, UnicodeError, ValueError) as exc:
        fail("invalid %s: %s" % (label, exc))

def safe_task_key(value):
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()[:32] or "task"
    return "%s-%s" % (slug, hashlib.sha256(value.encode()).hexdigest()[:10])

def task_hold_state(task_id):
    """Read the one canonical registry and reject any ambiguous authority state."""
    path = Path(workspace) / "task-holds.json"
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        fail("cannot inspect task hold registry: %s" % exc)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail("task hold registry must be a non-symlink regular file")
    if before.st_size <= 0 or before.st_size > 64 * 1024 * 1024:
        fail("task hold registry must contain 1..67108864 bytes")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            fail("task hold registry changed while authorizing the artifact")
        content = b""
        while len(content) <= 64 * 1024 * 1024:
            block = os.read(descriptor, min(1024 * 1024, 64 * 1024 * 1024 + 1 - len(content)))
            if not block:
                break
            content += block
        if len(content) > 64 * 1024 * 1024:
            fail("task hold registry exceeds the 64 MiB safety limit")
    except OSError as exc:
        fail("cannot securely read task hold registry: %s" % exc)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        registry = json.loads(content.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        fail("invalid task hold registry: %s" % exc)
    records = registry.get("tasks") if isinstance(registry, dict) else None
    if (
        not isinstance(registry, dict)
        or registry.get("schemaVersion") != 1
        or registry.get("featureId") != expected_feature
        or not isinstance(records, dict)
    ):
        fail("task hold registry schema/feature scope mismatch")
    known_states = {"blocked", "resume-review-pending", "manual-takeover", "resumed"}
    seen = set()
    for key, record in records.items():
        if not isinstance(key, str) or not isinstance(record, dict):
            fail("task hold registry contains a malformed task record")
        record_task = record.get("taskId")
        if not isinstance(record_task, str) or not record_task or record_task in seen:
            fail("task hold registry contains a missing or duplicate task identity")
        seen.add(record_task)
        if key != safe_task_key(record_task) or record.get("taskKey") != key:
            fail("task hold registry task identity/key mismatch")
        if record.get("state") not in known_states:
            fail("task hold registry contains an unknown task state")
    record = records.get(safe_task_key(task_id))
    if record is not None and record.get("taskId") != task_id:
        fail("task hold registry entry does not match the artifact task")
    return None if record is None else record.get("state")

try:
    entry_real = os.path.realpath(entry)
    if os.path.commonpath([os.path.realpath(pending), entry_real]) != os.path.realpath(pending):
        fail("entry escapes pending directory")
except ValueError:
    fail("entry escapes pending directory")
data = read_json_regular(entry, "entry")
if data.get("schemaVersion") != 1:
    fail("unsupported entry schema")
if data.get("team") != expected_team or data.get("featureId") != expected_feature:
    fail("entry team/feature does not match this dispatcher")
if data.get("phase") not in {"pending", "commented", "transitioned", "published"}:
    fail("invalid entry phase")
for key, pattern in {
    "id": r"[A-Za-z0-9._:-]{8,128}",
    "actor": r"[a-z0-9-]{2,80}",
    "marker": r"[a-z0-9-]{2,80}",
}.items():
    if not re.fullmatch(pattern, str(data.get(key) or "")):
        fail("invalid %s" % key)
try:
    attempt = int(data.get("attempt"))
    if attempt < 1 or isinstance(data.get("attempt"), bool):
        fail("attempt must be positive")
except (TypeError, ValueError):
    fail("attempt must be an integer")
for key in ("taskId", "featureId"):
    value = str(data.get(key) or "")
    if not value or any(ord(char) < 32 for char in value):
        fail("invalid %s" % key)
hold_state = task_hold_state(str(data["taskId"]))

# The broker, not the producer, assigns the tracker delivery identity and stages
# the bytes. Once assigned, every related field is mandatory and digest-bound.
delivery = data.get("deliveryId")
broker_fields = (data.get("stagedBodyPath"), data.get("stagedBodySha256"), data.get("brokerAssignedAt"))
if delivery is None:
    if any(value is not None for value in broker_fields) or data.get("publishBodyPath") is not None:
        fail("partial broker-owned delivery metadata")
elif not re.fullmatch(r"delivery-[0-9a-f]{32}", str(delivery)):
    fail("invalid broker-owned delivery id")
elif any(value is None for value in broker_fields):
    fail("incomplete broker-owned delivery metadata")

if delivery is None:
    effective, _ = regular_file(str(data.get("bodyPath") or ""), bodies, "producer body")
    producer_digest = "sha256:" + hashlib.sha256(effective.read_bytes()).hexdigest()
else:
    staged_body, _ = regular_file(str(data["stagedBodyPath"]), staged, "staged body")
    staged_digest = "sha256:" + hashlib.sha256(staged_body.read_bytes()).hexdigest()
    if staged_digest != data.get("stagedBodySha256"):
        fail("staged body digest mismatch")
    producer_digest = staged_digest
    effective = staged_body
    publish = data.get("publishBodyPath")
    if publish is not None:
        publish_body, _ = regular_file(str(publish), staged, "publish body")
        publish_digest = "sha256:" + hashlib.sha256(publish_body.read_bytes()).hexdigest()
        if publish_digest != data.get("publishBodySha256"):
            fail("publish body digest mismatch")
        effective = publish_body

text = effective.read_text(errors="replace")
if not text.startswith("[%s]" % data["marker"]):
    fail("body marker does not match entry")
secret_patterns = (
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{20,}\b",
    r"(?i)\b(?:password|secret|api[_-]?key|authorization)\s*[:=]\s*\S{8,}",
)
if any(re.search(pattern, text) for pattern in secret_patterns):
    fail("body appears to contain a credential/secret; keep it out of tracker and artifacts")

board = read_json_regular(board_path, "status board")
statuses = {status["name"]: status for status in board["tasks"]["statuses"]}
target = data.get("targetStatus")
if target is not None:
    if target not in statuses:
        fail("unknown target status")
    if statuses[target].get("kind") == "blocked":
        fail("outbox cannot request semantic Blocked; dependency propagation is dispatcher-only")
    if statuses[target].get("terminal"):
        fail("outbox cannot request a terminal transition; use the integrator transaction")
expected_kind = {"review-request": "review", "review-findings": "working"}.get(data["marker"])
if expected_kind and (target is None or statuses[target].get("kind") != expected_kind):
    fail("marker requests a status with the wrong semantic kind")
if data["marker"] in {"production-approval", "deployment"}:
    fail("production authority never enters through an agent outbox")

snapshot = read_json_regular(snapshot_path, "authoritative feature export")
if str(snapshot.get("featureId")) != expected_feature:
    fail("authoritative export featureId does not exactly match the dispatcher feature")
try:
    pm_text = Path(pm_path).read_text()
except OSError as exc:
    fail("cannot read project-management scope: %s" % exc)
configured = re.search(r"(?m)^PRODUCT_MANAGEMENT_TOOL=([^\s#]+)", pm_text)
configured_adapter = (os.environ.get("TRACKER_ADAPTER") or (configured.group(1).strip('"') if configured else ""))
if not configured_adapter or snapshot.get("adapter") != configured_adapter:
    fail("authoritative export adapter does not match configured tracker scope")
tasks = snapshot.get("tasks")
if not isinstance(tasks, list):
    fail("authoritative export has no tasks list")
task_ids = [str(item.get("taskId")) for item in tasks if isinstance(item, dict)]
if len(task_ids) != len(tasks) or len(task_ids) != len(set(task_ids)):
    fail("authoritative export has malformed or duplicate task identities")
matches = [item for item in tasks if str(item.get("taskId")) == str(data["taskId"])]
if len(matches) != 1:
    fail("task is absent from the authoritative feature/team scope")
authoritative_task = matches[0]
blocked_statuses = [
    name for name, spec in statuses.items() if spec.get("kind") == "blocked"
]
if len(blocked_statuses) != 1:
    fail("status board must define exactly one semantic blocked task status")
if authoritative_task.get("status") == blocked_statuses[0]:
    fail("task is authoritatively Blocked; every agent publication is stopped")
raw_ignored = os.environ.get("STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON")
try:
    ignored_labels = json.loads(raw_ignored if raw_ignored is not None else '["human-work"]')
except ValueError:
    fail("STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON is not valid JSON")
if not isinstance(ignored_labels, list) or any(
    not isinstance(label, str) or not label.strip() for label in ignored_labels
):
    fail("automation ignoredTaskLabels policy must be an array of non-empty strings")
ignored = {label.strip().casefold() for label in ignored_labels}
if len(ignored) != len(ignored_labels):
    fail("automation ignoredTaskLabels policy contains duplicate labels")
labels = authoritative_task.get("labels") or []
if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
    fail("authoritative task labels are malformed")
if ignored.intersection(label.strip().casefold() for label in labels):
    fail("task is labeled for human work; every agent publication is stopped")

protocol = {}
if os.path.isfile(preset) and not os.path.islink(preset):
    for line in open(preset):
        match = re.match(r"PROTOCOL_([A-Z_]+)=(.+)$", line.strip())
        if match:
            protocol[match.group(1)] = match.group(2)
marker_spec = (board.get("markers") or {}).get(data["marker"])
verified_capability = None
if data.get("producerCapability") is not None:
    sys.path.insert(0, os.path.join(skill_dir, "bin"))
    try:
        from outbox_capability import CapabilityError, verify_entry
        verified_capability = verify_entry(repository, workspace, data, producer_digest)
    except (CapabilityError, OSError, ValueError) as exc:
        fail("verified launched-role capability rejected: %s" % exc)

gate_owned = marker_spec is not None or data["marker"] in {"handoff", "escalation"}
if gate_owned:
    if verified_capability is None:
        fail("verified launched-role capability is required for protocol gate markers")
    if verified_capability.get("executionKind") != "gate":
        fail("protocol gate marker requires a gate-role capability, not a task capability")
    # Actor strings in producer JSON and tracker text are non-authoritative.
    # The effective principal comes only from the verified broker record.
    effective_actor = verified_capability["role"]
else:
    effective_actor = str(data["actor"])

roles = {effective_actor}
for name, concrete in protocol.items():
    if concrete == effective_actor:
        roles.add(name.lower().replace("_", "-"))

if marker_spec:
    if not roles.intersection(marker_spec.get("authorizedRoles") or []):
        fail("actor is not authorized for marker [%s]" % data["marker"])
    if data["marker"] in {"product-approval", "product-pushback"}:
        product_role = protocol.get("PRODUCT_MANAGER")
        if product_role and product_role != "null":
            if effective_actor != product_role:
                fail("configured product-manager exclusively owns the feature product verdict")
        elif "team-lead" not in roles:
            fail("team-lead fallback is allowed only when no product-manager role exists")
elif data["marker"] in {"handoff", "escalation"}:
    if "team-lead" not in roles:
        fail("actor is not the configured team-lead")
else:
    # Task-mode artifacts are bound to the canonical execution record. A
    # pre-claim design note is the sole exception: it is a comment-only planning
    # artifact and grants neither state movement nor approval authority.
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", str(data["taskId"])).strip("-").lower()[:32] or "task"
    key = slug + "-" + hashlib.sha256(str(data["taskId"]).encode()).hexdigest()[:10]
    execution_path = os.path.join(workspace, "executions", key + ".json")
    if os.path.lexists(execution_path):
        execution = read_json_regular(execution_path, "canonical execution record")
    elif data["marker"] == "design-note":
        if target is not None:
            fail("a pre-claim design note may comment only; it cannot move task state")
        execution = None
    else:
        fail("canonical execution record is absent for task-mode artifact")
    if execution is not None:
        expected = {
            "featureId": expected_feature,
            "taskId": str(data["taskId"]),
            "attempt": attempt,
            "role": effective_actor,
        }
        for name, value in expected.items():
            if execution.get(name) != value:
                fail("producer %s does not match the canonical task execution" % name)

# Blocked and manual-takeover stop every agent publication. During the narrow
# human-resume review barrier, only authenticated, comment-only gate verdicts
# needed to resolve that barrier may pass; ordinary work/review artifacts and
# every state transition remain stopped.
if hold_state in {"blocked", "manual-takeover"}:
    fail("task is held (%s); agent artifact publication is stopped" % hold_state)
if hold_state == "resume-review-pending":
    allowed = {
        "resume-review",
        "resume-plan",
        "design-approved",
        "design-pushback",
        "sceptical-design-approved",
        "sceptical-design-pushback",
    }
    if data["marker"] not in allowed or target is not None:
        fail("resume-review-pending permits only comment-only resume barrier gate markers")
    if (
        not gate_owned
        or verified_capability is None
        or verified_capability.get("executionKind") != "gate"
    ):
        fail("resume barrier marker requires an authenticated gate-role capability")
PY
  )"; then
    [ -z "$validation_output" ] || printf '%s\n' "$validation_output" >&2
    cleanup_snapshot
    return 1
  fi
  return 0
}

stop_for_authority_outage() {
  local owner_file="${1:-}" lock="${2:-}"
  cleanup_snapshot
  if [ -n "$owner_file" ]; then rm -f -- "$owner_file"; fi
  if [ -n "$lock" ]; then rmdir -- "$lock" 2>/dev/null || true; fi
  echo "process-outbox: authoritative feature export unavailable; entry remains pending" >&2
  exit 1
}

broker_stage() {
  python3 - "$1" "$bodies" "$staged" <<'PY'
import hashlib, json, os, secrets, stat, sys
from datetime import datetime, timezone
from pathlib import Path

entry, bodies, staged = map(Path, sys.argv[1:])

def fail(message):
    raise SystemExit("process-outbox: " + message)

def contained(path, root):
    try:
        return os.path.commonpath([os.path.realpath(root), os.path.realpath(path)]) == os.path.realpath(root)
    except ValueError:
        return False

try:
    data = json.loads(entry.read_text())
except (OSError, ValueError) as exc:
    fail("invalid entry while assigning delivery: %s" % exc)
existing = data.get("deliveryId")
if existing is not None:
    required = (data.get("stagedBodyPath"), data.get("stagedBodySha256"), data.get("brokerAssignedAt"))
    if not all(required):
        fail("incomplete existing broker delivery")
    path = Path(data["stagedBodyPath"])
    if not contained(path, staged) or path.is_symlink() or not path.is_file():
        fail("existing staged body is unsafe")
    actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != data.get("stagedBodySha256"):
        fail("existing staged body digest mismatch")
    print(existing)
    raise SystemExit(0)

source = Path(str(data.get("bodyPath") or ""))
if not contained(source, bodies):
    fail("producer body escapes outbox/bodies")
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(source, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 65536:
            fail("producer body must be a 1..65536 byte regular file")
        content = b""
        while len(content) <= 65536:
            block = os.read(descriptor, 65537 - len(content))
            if not block:
                break
            content += block
        if len(content) > 65536:
            fail("producer body exceeds 64 KiB")
    finally:
        os.close(descriptor)
except OSError as exc:
    fail("cannot securely read producer body: %s" % exc)

delivery = "delivery-" + secrets.token_hex(16)
target = staged / (delivery + ".source.md")
staged.mkdir(parents=True, exist_ok=True)
write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(target, write_flags, 0o400)
try:
    with os.fdopen(descriptor, "wb") as handle:
        descriptor = -1
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
finally:
    if descriptor >= 0:
        os.close(descriptor)
digest = "sha256:" + hashlib.sha256(content).hexdigest()
data.update({
    "deliveryId": delivery,
    "brokerSchemaVersion": 1,
    "brokerAssignedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "stagedBodyPath": str(target),
    "stagedBodySha256": digest,
})
temporary = entry.with_name(".%s.tmp.%s.%s" % (entry.name, os.getpid(), secrets.token_hex(8)))
fd = os.open(temporary, write_flags, 0o600)
try:
    with os.fdopen(fd, "w") as handle:
        fd = -1
        json.dump(data, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, entry)
finally:
    if fd >= 0:
        os.close(fd)
    try: temporary.unlink()
    except FileNotFoundError: pass
print(delivery)
PY
}

commit_publish_body() {
  # commit_publish_body <entry> <candidate-or--> <binding-json>
  python3 - "$1" "$2" "$3" "$staged" <<'PY'
import hashlib, json, os, secrets, sys
from pathlib import Path

entry, candidate_arg, binding_arg, staged = sys.argv[1:]
entry, staged = Path(entry), Path(staged)
data = json.loads(entry.read_text())
delivery = data["deliveryId"]
source = Path(data["stagedBodyPath"])
candidate = source if candidate_arg == "-" else Path(candidate_arg)
if candidate.is_symlink() or not candidate.is_file():
    raise SystemExit("process-outbox: candidate publish body is unsafe")
try:
    if os.path.commonpath([os.path.realpath(staged), os.path.realpath(candidate)]) != os.path.realpath(staged):
        raise SystemExit("process-outbox: candidate publish body escapes broker staging")
except ValueError:
    raise SystemExit("process-outbox: candidate publish body escapes broker staging")
content = candidate.read_bytes()
if not content or len(content) > 65536:
    raise SystemExit("process-outbox: candidate publish body must contain 1..65536 bytes")
digest = "sha256:" + hashlib.sha256(content).hexdigest()
destination = staged / (delivery + ".publish.md")
if data.get("publishBodyPath"):
    current = Path(data["publishBodyPath"])
    if current != destination or current.is_symlink() or not current.is_file():
        raise SystemExit("process-outbox: stored publish body path is unsafe")
    if current.read_bytes() != content or data.get("publishBodySha256") != digest:
        raise SystemExit("process-outbox: review binding changed after delivery assignment; manual reconciliation required")
    if candidate != source and candidate != current:
        candidate.unlink()
    print(current)
    raise SystemExit(0)
if candidate == source:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o400)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0: os.close(descriptor)
else:
    os.chmod(candidate, 0o400)
    os.replace(candidate, destination)
data["publishBodyPath"] = str(destination)
data["publishBodySha256"] = digest
if binding_arg != "-":
    data["reviewBinding"] = json.loads(binding_arg)
temporary = entry.with_name(".%s.tmp.%s.%s" % (entry.name, os.getpid(), secrets.token_hex(8)))
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(temporary, flags, 0o600)
try:
    with os.fdopen(fd, "w") as handle:
        fd = -1
        json.dump(data, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, entry)
finally:
    if fd >= 0: os.close(fd)
    try: temporary.unlink()
    except FileNotFoundError: pass
print(destination)
PY
}

prepare_publish_body() {
  local entry="$1" marker="$2" task="$3" delivery="$4" staged_body="$5"
  local candidate package binding base head package_digest
  candidate="$staged/$delivery.candidate.$$.md"
  rm -f -- "$candidate"
  case "$marker" in
    review-request)
      if ! package="$("$SKILL_DIR/bin/review-package.sh" "$team" "$task")"; then return 1; fi
      if ! binding="$(python3 - "$package" <<'PY'
import hashlib, re, sys
from pathlib import Path
path=Path(sys.argv[1]); body=path.read_bytes(); text=body.decode(errors='replace')
base=re.search(r'(?m)^Base: ([0-9a-f]{40})$', text)
head=re.search(r'(?m)^Head: ([0-9a-f]{40})$', text)
if not base or not head: raise SystemExit('process-outbox: review package omitted exact Base/Head commits')
print(base.group(1), head.group(1), 'sha256:'+hashlib.sha256(body).hexdigest())
PY
)"; then return 1; fi
      read -r base head package_digest <<EOF
$binding
EOF
      "$SKILL_DIR/bin/review_evidence.py" bind-request "$staged_body" "$base" "$head" "$package_digest" "$candidate" || return 1
      if ! binding="$(python3 - "$base" "$head" "$package_digest" <<'PY'
import json,sys
print(json.dumps({'kind':'review-request','base':sys.argv[1],'head':sys.argv[2],'package':sys.argv[3]}, separators=(',',':')))
PY
)"; then return 1; fi
      ;;
    review-approval|architecture-approval|sceptical-architecture-approval)
      "$SKILL_DIR/bin/review_evidence.py" bind-approval "$staged_body" "$current_snapshot" "$task" "$candidate" || return 1
      if ! binding="$(python3 - "$marker" <<'PY'
import json,sys
print(json.dumps({'kind':sys.argv[1]}, separators=(',',':')))
PY
)"; then return 1; fi
      ;;
    *)
      candidate="-"
      binding="-"
      ;;
  esac
  commit_publish_body "$entry" "$candidate" "$binding" >/dev/null || return 1
}

if [ -n "$only" ]; then
  set -- "$only"
else
  set -- "$pending"/*.json
fi

for entry in "$@"; do
  [ -f "$entry" ] || continue
  authority_status=0
  refresh_authority "$entry" || authority_status=$?
  if [ "$authority_status" -eq 75 ]; then
    stop_for_authority_outage
  elif [ "$authority_status" -ne 0 ]; then
    reject_entry "$entry"
    if [ -n "$only" ]; then exit 1; fi
    continue
  fi
  cleanup_snapshot

  fields="$(python3 - "$entry" <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
for key in ('id','taskId','attempt','actor','marker','targetStatus','phase'):
    value=d.get(key)
    print('' if value is None else value)
PY
)"
  id="$(printf '%s\n' "$fields" | sed -n '1p')"
  task="$(printf '%s\n' "$fields" | sed -n '2p')"
  attempt="$(printf '%s\n' "$fields" | sed -n '3p')"
  actor="$(printf '%s\n' "$fields" | sed -n '4p')"
  marker="$(printf '%s\n' "$fields" | sed -n '5p')"
  target="$(printf '%s\n' "$fields" | sed -n '6p')"
  phase="$(printf '%s\n' "$fields" | sed -n '7p')"
  lock="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "outbox/locks/$id.lock")"
  owner_file="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "outbox/locks/$id.lock/owner")"
  [ ! -L "$lock" ] || { echo "process-outbox: lock must not be a symlink" >&2; exit 1; }
  if ! mkdir "$lock" 2>/dev/null; then
    owner="$(cat "$owner_file" 2>/dev/null || true)"
    if [ -z "$owner" ] || kill -0 "$owner" 2>/dev/null; then
      continue
    fi
    rm -f "$owner_file"
    rmdir "$lock" 2>/dev/null || continue
    mkdir "$lock" 2>/dev/null || continue
  fi
  printf '%s\n' "$$" > "$owner_file"
  if [ ! -f "$entry" ]; then
    rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true
    continue
  fi

  # The entry may have waited for its lock while the PM agent established a
  # hold. Re-export and re-read the canonical hold registry at the last useful
  # boundary before broker-owned staging writes begin.
  authority_status=0
  refresh_authority "$entry" || authority_status=$?
  if [ "$authority_status" -eq 75 ]; then
    stop_for_authority_outage "$owner_file" "$lock"
  elif [ "$authority_status" -ne 0 ]; then
    cleanup_snapshot
    rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true
    reject_entry "$entry"
    if [ -n "$only" ]; then exit 1; fi
    continue
  fi
  if ! delivery="$(broker_stage "$entry")"; then
    rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true
    reject_entry "$entry"
    if [ -n "$only" ]; then exit 1; fi
    continue
  fi
  staged_body="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stagedBodyPath"])' "$entry")"

  if [ "$phase" = "pending" ]; then
    # Author once, then export and author/compare once more immediately before
    # the write. A task move, new request, branch-head change, or package change
    # during preparation changes the candidate bytes and fails closed rather
    # than letting an already-assigned delivery identity drift.
    publish_ok=yes
    authority_status=0
    refresh_authority "$entry" || authority_status=$?
    if [ "$authority_status" -eq 75 ]; then
      stop_for_authority_outage "$owner_file" "$lock"
    elif [ "$authority_status" -ne 0 ]; then
      publish_ok=no
    fi
    [ "$publish_ok" = yes ] && prepare_publish_body "$entry" "$marker" "$task" "$delivery" "$staged_body" || publish_ok=no
    if [ "$publish_ok" = yes ]; then
      cleanup_snapshot
      authority_status=0
      refresh_authority "$entry" || authority_status=$?
      if [ "$authority_status" -eq 75 ]; then
        stop_for_authority_outage "$owner_file" "$lock"
      elif [ "$authority_status" -ne 0 ]; then
        publish_ok=no
      fi
    fi
    [ "$publish_ok" = yes ] && prepare_publish_body "$entry" "$marker" "$task" "$delivery" "$staged_body" || publish_ok=no
    if [ "$publish_ok" = yes ]; then
      # Body preparation can run validation tooling and build a review package;
      # do not let an intervening Blocked move race the actual publication.
      cleanup_snapshot
      authority_status=0
      refresh_authority "$entry" || authority_status=$?
      if [ "$authority_status" -eq 75 ]; then
        stop_for_authority_outage "$owner_file" "$lock"
      elif [ "$authority_status" -ne 0 ]; then
        publish_ok=no
      fi
    fi
    # Rebind/compare once more against that last fresh snapshot. The final
    # authority refresh is not useful unless the exact publish bytes are also
    # proven unchanged before comment-once.
    [ "$publish_ok" = yes ] && prepare_publish_body "$entry" "$marker" "$task" "$delivery" "$staged_body" || publish_ok=no
    if [ "$publish_ok" != yes ]; then
      cleanup_snapshot
      rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true
      reject_entry "$entry"
      if [ -n "$only" ]; then exit 1; fi
      continue
    fi
    body="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["publishBodyPath"])' "$entry")"
    "$SKILL_DIR/bin/tracker-ops.sh" comment-once "$task" "$delivery" "$body"
    cleanup_snapshot
    python3 - "$entry" <<'PY'
import json, os, sys
p=sys.argv[1]; d=json.load(open(p)); d['phase']='commented'
t=p+'.tmp'; open(t,'w').write(json.dumps(d, indent=2)+'\n'); os.replace(t,p)
PY
    phase=commented
  fi
  if [ "$phase" = "commented" ] && [ -n "$target" ]; then
    authority_status=0
    refresh_authority "$entry" || authority_status=$?
    if [ "$authority_status" -eq 75 ]; then
      stop_for_authority_outage "$owner_file" "$lock"
    elif [ "$authority_status" -ne 0 ]; then
      cleanup_snapshot
      rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true
      reject_entry "$entry"
      if [ -n "$only" ]; then exit 1; fi
      continue
    fi
    "$SKILL_DIR/bin/tracker-ops.sh" state "$task" "$target"
    cleanup_snapshot
    python3 - "$entry" <<'PY'
import json, os, sys
p=sys.argv[1]; d=json.load(open(p)); d['phase']='transitioned'
t=p+'.tmp'; open(t,'w').write(json.dumps(d, indent=2)+'\n'); os.replace(t,p)
PY
    phase=transitioned
  fi
  if [ "$phase" != "published" ]; then
    # The event is part of durable artifact publication too. A hold appearing
    # after a tracker write stops this pass before any further agent evidence is
    # emitted; the tracker operation itself remains idempotent on a later retry.
    authority_status=0
    refresh_authority "$entry" || authority_status=$?
    if [ "$authority_status" -eq 75 ]; then
      stop_for_authority_outage "$owner_file" "$lock"
    elif [ "$authority_status" -ne 0 ]; then
      cleanup_snapshot
      rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true
      reject_entry "$entry"
      if [ -n "$only" ]; then exit 1; fi
      continue
    fi
    body="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("publishBodyPath") or d["stagedBodyPath"])' "$entry")"
    python3 "$SKILL_DIR/bin/runtime-state.py" emit --workspace "$workspace" --team "$team" \
      --feature "$feature" --task "$task" --attempt "$attempt" --actor "$actor" \
      --type artifact.published --stage "${target:-artifact-published}" \
      --summary "[$marker] published to tracker" --artifact "$body" >/dev/null
    python3 - "$entry" <<'PY'
import json, os, sys
p=sys.argv[1]; d=json.load(open(p)); d['phase']='published'
t=p+'.tmp'; open(t,'w').write(json.dumps(d, indent=2)+'\n'); os.replace(t,p)
PY
  fi
  # Workspace receipts are not authorization. Bind the exact successful
  # tracker publication into the protected external broker ledger first.
  python3 "$SKILL_DIR/bin/broker_evidence.py" \
    --repo "$repo" --workspace "$workspace" --entry "$entry" >/dev/null
  destination="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "outbox/done/$id.json")"
  [ ! -f "$entry" ] || mv "$entry" "$destination"
  rm -f "$owner_file"
  rmdir "$lock" 2>/dev/null || true
  echo "published [$marker] for $task ($delivery)"
done
cleanup_snapshot
