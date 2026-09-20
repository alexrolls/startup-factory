#!/usr/bin/env bash
# Publish queued artifacts idempotently; tracker state remains the durable source of truth.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH

script_directory="${BASH_SOURCE[0]%/*}"
[ "$script_directory" != "${BASH_SOURCE[0]}" ] || script_directory=.
SKILL_DIR="$(cd "$script_directory/.." && pwd -P)"
CONFIG="$SKILL_DIR/config/team.config.md"
DEFAULT_PM_CONFIG="$SKILL_DIR/config/project-management.config.md"
DEFAULT_AUTOMATION_CONFIG="$SKILL_DIR/config/automation.config.json"
ambient_pm_config_set="${STARTUP_FACTORY_PM_CONFIG+x}"
ambient_pm_config="${STARTUP_FACTORY_PM_CONFIG:-}"
ambient_automation_config_set="${STARTUP_FACTORY_AUTOMATION_CONFIG+x}"
ambient_automation_config="${STARTUP_FACTORY_AUTOMATION_CONFIG:-}"
ambient_ignored_labels_set="${STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON+x}"
ambient_ignored_labels="${STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON:-}"
ambient_tracker_adapter_set="${TRACKER_ADAPTER+x}"
ambient_tracker_adapter="${TRACKER_ADAPTER:-}"

# A caller-controlled environment cannot select the HMAC/hold authority.  The
# configured lifecycle root is the sole binding for this standalone broker; a
# supervisor may repeat it in the environment, but may not replace it.  The
# canonical path and its complete ownership/mode chain are checked below, once
# the trusted Python boundary is established.
ambient_lifecycle_root="${STARTUP_FACTORY_LIFECYCLE_STATE_ROOT:-}"
unset STARTUP_FACTORY_LIFECYCLE_STATE_ROOT
BROKER_LIFECYCLE_VALIDATED=no

# Every Python process in this authority-bearing broker starts from one pinned,
# canonical Python >=3.10 under an isolated, no-bytecode, fixed environment.
# Discovery accepts only standard host toolchain roots and never a repository
# or temporary PATH entry. Caller-provided interpreter overrides are ignored:
# they are not authenticated authority. The file identity is checked again
# before every authority-bearing launch.
canonical_executable() {
  local candidate="$1" target directory count=0
  case "$candidate" in /*) ;; *) return 1 ;; esac
  while [ -L "$candidate" ]; do
    count=$((count + 1)); [ "$count" -le 32 ] || return 1
    target="$(/usr/bin/readlink "$candidate")" || return 1
    case "$target" in
      /*) candidate="$target" ;;
      *) candidate="$(/usr/bin/dirname "$candidate")/$target" ;;
    esac
  done
  directory="$(cd -P -- "$(/usr/bin/dirname "$candidate")" 2>/dev/null && pwd -P)" \
    || return 1
  printf '%s/%s\n' "$directory" "$(/usr/bin/basename "$candidate")"
}

python_file_identity() {
  local output
  if output="$(/usr/bin/stat -f '%d:%i:%p:%u:%g:%z:%m:%c' "$1" 2>/dev/null)"; then
    printf '%s\n' "$output"
  elif output="$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%s:%Y:%Z' "$1" 2>/dev/null)"; then
    printf '%s\n' "$output"
  else
    return 1
  fi
}

select_broker_python() {
  local candidate canonical identity
  local candidates=(/opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3)
  for candidate in "${candidates[@]}"; do
    canonical="$(canonical_executable "$candidate" 2>/dev/null || true)"
    [ -n "$canonical" ] && [ -f "$canonical" ] && [ -x "$canonical" ] || continue
    case "$canonical" in
      "$SKILL_DIR"/*|/tmp/*|/private/tmp/*) continue ;;
    esac
    case "$canonical" in
      /usr/*|/opt/homebrew/Cellar/*|/opt/hostedtoolcache/*|/Library/Frameworks/Python.framework/*) ;;
      *) continue ;;
    esac
    identity="$(python_file_identity "$canonical" 2>/dev/null || true)"
    [ -n "$identity" ] || continue
    if /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/tmp LANG=C LC_ALL=C \
      "$canonical" -I -B -c '
import os, stat, sys
path = sys.argv[1]
info = os.stat(path)
valid = (
    sys.version_info >= (3, 10)
    and os.path.realpath(sys.executable) == path
    and stat.S_ISREG(info.st_mode)
    and not info.st_mode & 0o022
    and info.st_uid in {0, os.geteuid()}
)
raise SystemExit(0 if valid else 1)
' "$canonical"; then
      printf '%s\t%s\n' "$canonical" "$identity"
      return 0
    fi
  done
  return 1
}

broker_python_selection="$(select_broker_python)" || {
  echo "process-outbox: trusted canonical Python >=3.10 is unavailable in an approved host toolchain root" >&2
  exit 1
}
BROKER_PYTHON="${broker_python_selection%%$'\t'*}"
BROKER_PYTHON_IDENTITY="${broker_python_selection#*$'\t'}"

verify_broker_python_identity() {
  local observed
  [ -f "$BROKER_PYTHON" ] && [ -x "$BROKER_PYTHON" ] && [ ! -L "$BROKER_PYTHON" ] \
    || { echo "process-outbox: trusted broker Python disappeared or changed type" >&2; return 1; }
  observed="$(python_file_identity "$BROKER_PYTHON")" \
    || { echo "process-outbox: cannot inspect trusted broker Python" >&2; return 1; }
  [ "$observed" = "$BROKER_PYTHON_IDENTITY" ] \
    || { echo "process-outbox: trusted broker Python identity changed" >&2; return 1; }
}

broker_python() {
  local environment=(-i
    "PATH=/usr/bin:/bin"
    "TMPDIR=/tmp"
    "LANG=C"
    "LC_ALL=C"
    "AWS_EC2_METADATA_DISABLED=true"
    "PYTHONDONTWRITEBYTECODE=1")
  verify_broker_python_identity || return 1
  if [ "$BROKER_LIFECYCLE_VALIDATED" = yes ]; then
    environment+=("STARTUP_FACTORY_LIFECYCLE_STATE_ROOT=$STARTUP_FACTORY_LIFECYCLE_STATE_ROOT")
  fi
  if [ $# -gt 0 ]; then
    case "$1" in
      "$SKILL_DIR"/bin/*.py)
        local script="$1"
        shift
        /usr/bin/env "${environment[@]}" "$BROKER_PYTHON" -I -B -c '
import runpy, sys
script, module_dir = sys.argv[1:3]
sys.argv = [script, *sys.argv[3:]]
sys.path.insert(0, module_dir)
runpy.run_path(script, run_name="__main__")
' "$script" "$SKILL_DIR/bin" "$@"
        return
        ;;
    esac
  fi
  /usr/bin/env "${environment[@]}" "$BROKER_PYTHON" -I -B "$@"
}

# Keep the existing inline-program call sites readable while preventing the
# shell from consulting ambient PATH for any of them.
python3() { broker_python "$@"; }

read_key() {
  python3 "$SKILL_DIR/bin/config-value.py" --config "$CONFIG" \
    --label "team config" --prefix process-outbox value "$1"
}

configured_lifecycle_root="$(python3 "$SKILL_DIR/bin/config-value.py" \
  --config "$CONFIG" --label "team config" --prefix process-outbox \
  value BROKER_LIFECYCLE_ROOT)" || exit 1
[ -n "$configured_lifecycle_root" ] || {
  echo "process-outbox: BROKER_LIFECYCLE_ROOT is required for broker authority" >&2
  exit 1
}

repo="$(python3 "$SKILL_DIR/bin/delivery_profile.py" repo-root --path "$PWD")"
validated_lifecycle_root="$(broker_python - \
  "$configured_lifecycle_root" "$ambient_lifecycle_root" "$repo" "$SKILL_DIR" <<'PY'
import os, stat, sys
from pathlib import Path

configured_raw, ambient_raw, repository_raw, skill_raw = sys.argv[1:]
configured = Path(configured_raw)
repository = Path(repository_raw)
skill = Path(skill_raw)

def fail(message):
    raise SystemExit("process-outbox: " + message)

if not configured.is_absolute() or Path(os.path.normpath(str(configured))) != configured:
    fail("BROKER_LIFECYCLE_ROOT must be an absolute normalized path")
for shared in (Path("/tmp"), Path("/private/tmp")):
    try:
        configured.relative_to(shared)
    except ValueError:
        pass
    else:
        fail("configured lifecycle root must not live below a shared temporary directory")
try:
    resolved = configured.resolve(strict=True)
except OSError as exc:
    fail("configured lifecycle root is unavailable: %s" % exc)
if resolved != configured:
    fail("configured lifecycle root and every parent must be non-symlink paths")
current = Path(configured.anchor)
for part in configured.parts[1:]:
    current /= part
    try:
        info = current.lstat()
    except OSError as exc:
        fail("cannot inspect lifecycle path component %s: %s" % (current, exc))
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("lifecycle path components must be non-symlink directories: %s" % current)
    if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o022:
        fail("lifecycle path components must be broker/root-owned and not group/world-writable: %s" % current)
if stat.S_IMODE(configured.lstat().st_mode) != 0o700:
    fail("configured lifecycle root must have mode 0700")
for boundary, label in ((Path(repository).resolve(strict=True), "repository"),
                        (Path(skill).resolve(strict=True), "installed skill")):
    try:
        common = Path(os.path.commonpath((str(configured), str(boundary))))
    except ValueError:
        continue
    if common in {configured, boundary}:
        fail("configured lifecycle root must be disjoint from the %s" % label)
if ambient_raw:
    ambient = Path(ambient_raw)
    if not ambient.is_absolute() or Path(os.path.normpath(str(ambient))) != ambient:
        fail("STARTUP_FACTORY_LIFECYCLE_STATE_ROOT must repeat the configured canonical root")
    try:
        ambient_resolved = ambient.resolve(strict=True)
    except OSError as exc:
        fail("environment lifecycle root is unavailable: %s" % exc)
    if ambient_resolved != configured:
        fail("STARTUP_FACTORY_LIFECYCLE_STATE_ROOT does not match BROKER_LIFECYCLE_ROOT")
print(configured)
PY
)" || exit 1
export STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$validated_lifecycle_root"
BROKER_LIFECYCLE_VALIDATED=yes

policy_args=(policy-source --default-config "$DEFAULT_PM_CONFIG" --repo "$repo" --skill "$SKILL_DIR" --label "project-management config")
[ -z "$ambient_pm_config_set" ] || policy_args+=(--ambient "$ambient_pm_config")
PM_CONFIG="$(broker_python "$SKILL_DIR/bin/authority_config.py" "${policy_args[@]}")" \
  || { echo "process-outbox: project-management policy source is unavailable" >&2; exit 1; }

policy_args=(policy-source --default-config "$DEFAULT_AUTOMATION_CONFIG" --repo "$repo" --skill "$SKILL_DIR" --label "automation config")
[ -z "$ambient_automation_config_set" ] || policy_args+=(--ambient "$ambient_automation_config")
AUTOMATION_CONFIG="$(broker_python "$SKILL_DIR/bin/authority_config.py" "${policy_args[@]}")" \
  || { echo "process-outbox: automation policy source is unavailable" >&2; exit 1; }

policy_args=(tracker-adapter --pm-config "$PM_CONFIG")
[ -z "$ambient_tracker_adapter_set" ] || policy_args+=(--ambient "$ambient_tracker_adapter")
BROKER_TRACKER_ADAPTER="$(broker_python "$SKILL_DIR/bin/authority_config.py" "${policy_args[@]}")" \
  || { echo "process-outbox: configured tracker adapter authority is unavailable" >&2; exit 1; }

policy_args=(ignored-labels --automation-config "$AUTOMATION_CONFIG")
[ -z "$ambient_ignored_labels_set" ] || policy_args+=(--ambient "$ambient_ignored_labels")
BROKER_IGNORED_TASK_LABELS_JSON="$(
  broker_python "$SKILL_DIR/bin/authority_config.py" "${policy_args[@]}"
)" || { echo "process-outbox: configured human-work label policy is unavailable" >&2; exit 1; }

# Snapshot the non-secret broker tool policy from the authenticated automation
# source. Caller values above were accepted only as exact protected sources or
# exact-repeat assertions. trustedPath canonicalizes root-owned OS aliases.
broker_policy="$(broker_python - "$AUTOMATION_CONFIG" "$SKILL_DIR" <<'PY'
import json, os, stat, sys
from pathlib import Path

config_path, skill = map(Path, sys.argv[1:])

def fail(message):
    raise SystemExit("process-outbox: " + message)

def object_from_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("automation config contains duplicate JSON key")
        result[key] = value
    return result

try:
    info = config_path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        fail("automation config must be a bounded non-symlink regular file")
    config = json.loads(config_path.read_text(), object_pairs_hook=object_from_pairs)
except (OSError, UnicodeError, ValueError) as exc:
    fail("cannot read automation config: %s" % exc)
if not isinstance(config, dict) or config.get("schemaVersion") != 1:
    fail("automation config has an unsupported schema")

trusted = config.get("trustedPath", "/usr/bin:/bin")
entries = trusted.split(":") if isinstance(trusted, str) else []
if not trusted or any(not item.startswith("/") or item in {"/", ".", ".."} for item in entries):
    fail("trustedPath must contain only non-root absolute directory entries")
canonical = []
skill = skill.resolve(strict=True)
for item in entries:
    directory = Path(item)
    current = Path(directory.anchor)
    for part in directory.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            fail("trustedPath directory is unavailable: %s: %s" % (directory, exc))
        if stat.S_ISLNK(metadata.st_mode):
            if metadata.st_uid != 0:
                fail("trustedPath symlink components must be root-owned: %s" % directory)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            fail("trustedPath entry is not a directory: %s" % directory)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            fail("trustedPath components must be root-owned and not group/world-writable: %s" % directory)
    try:
        resolved = directory.resolve(strict=True)
    except OSError as exc:
        fail("trustedPath directory is unavailable: %s: %s" % (directory, exc))
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current /= part
        metadata = current.lstat()
        if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022):
            fail("trustedPath canonical chain is writable or unsafe: %s" % resolved)
    try:
        resolved.relative_to(skill)
    except ValueError:
        pass
    else:
        fail("trustedPath must live outside the installed skill")
    if resolved not in canonical:
        canonical.append(resolved)

print(":".join(str(path) for path in canonical))
PY
)" || exit 1
BROKER_TOOL_PATH="$broker_policy"
[ -n "$BROKER_TOOL_PATH" ] && [ -n "$BROKER_IGNORED_TASK_LABELS_JSON" ] || {
  echo "process-outbox: configured broker policy is incomplete" >&2
  exit 1
}

broker_child() {
  verify_broker_python_identity || return 1
  /usr/bin/env \
    -u BASH_ENV -u ENV -u CDPATH -u GLOBIGNORE \
    -u PYTHONHOME -u PYTHONPATH -u PYTHONSTARTUP -u PYTHONINSPECT \
    -u PYTHONUSERBASE -u PYTHONBREAKPOINT \
    -u LD_PRELOAD -u DYLD_INSERT_LIBRARIES -u DYLD_LIBRARY_PATH \
    -u STARTUP_FACTORY_BROKER_PYTHON -u STARTUP_FACTORY_PINNED_PYTHON \
    -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON -u TRACKER_ADAPTER \
    "PATH=$BROKER_TOOL_PATH" \
    "STARTUP_FACTORY_PINNED_PYTHON=$BROKER_PYTHON" \
    "PYTHONNOUSERSITE=1" \
    "PYTHONSAFEPATH=1" \
    "PYTHONDONTWRITEBYTECODE=1" \
    "$@"
}

# Tracker adapters need their own credentials, but never lifecycle/HMAC state
# or caller-selected policy.  They discover the configured adapter from the
# installed project-management config and tools only from trustedPath.
broker_tracker() {
  broker_child /usr/bin/env \
    -u STARTUP_FACTORY_LIFECYCLE_STATE_ROOT \
    -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
    -u STARTUP_FACTORY_BROKER_PYTHON \
    -u STARTUP_FACTORY_RELEASE_EXECUTOR \
    -u STARTUP_FACTORY_PM_SUPERVISOR \
    -u STARTUP_FACTORY_INTEGRATION_BROKER \
    -u STARTUP_FACTORY_AUTOMATION_CONFIG -u STARTUP_FACTORY_PM_CONFIG \
    -u TRACKER_ADAPTER \
    "TRACKER_PROJECT_ROOT=$repo" \
    "STARTUP_FACTORY_AUTOMATION_CONFIG=$AUTOMATION_CONFIG" \
    "STARTUP_FACTORY_PM_CONFIG=$PM_CONFIG" \
    "STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON=$BROKER_IGNORED_TASK_LABELS_JSON" \
    "TRACKER_ADAPTER=$BROKER_TRACKER_ADAPTER" \
    "$@"
}

broker_tracker_effect() { # entry operation args...
  local effect_entry="$1" digest effect_delivery
  shift
  digest="$(python3 - "$effect_entry" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
capability=value.get("producerCapability")
print(capability.get("bodySha256", "") if isinstance(capability, dict) else "")
PY
)" || return 1
  effect_delivery="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deliveryId"])' "$effect_entry")" \
    || return 1
  # One broker-wide lock spans the final exact-capability/hold check and the
  # tracker child. Mint, revoke, task hold, and external effect therefore have
  # one fail-closed order for signed and manual queue entries alike.
  broker_tracker "$BROKER_PYTHON" -I -B "$SKILL_DIR/bin/outbox_capability.py" \
    locked-tracker-effect --repo "$repo" --workspace "$workspace" \
    --lifecycle-root "$STARTUP_FACTORY_LIFECYCLE_STATE_ROOT" \
    --entry "$effect_entry" --delivery-id "$effect_delivery" \
    --body-digest "${digest:--}" -- "$@"
}

[ $# -ge 2 ] && [ $# -le 3 ] || { echo "usage: process-outbox.sh <team> <featureId> [entry.json]" >&2; exit 2; }
team="$1"; feature="$2"; only="${3:-}"
root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
workspace="$(python3 "$SKILL_DIR/bin/teamwork-path.py" workspace --repo "$repo" --root "$root" --team "$team")"
pending="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/pending)"
bodies="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/bodies)"
staged="$(python3 "$SKILL_DIR/bin/outbox_capability.py" delivery-root \
  --repo "$repo" --workspace "$workspace" --team "$team" --feature "$feature")" \
  || { echo "process-outbox: protected delivery storage is unavailable" >&2; exit 1; }
authority="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/authoritative)"
done="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/done)"
failed="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/failed)"
locks="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/locks)"
preset_file="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative preset.env)"
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative events.ndjson >/dev/null
mkdir -p "$pending" "$bodies" "$authority" "$done" "$failed" "$locks"

trusted_policy_file=""
trusted_policy_digest=""
team_context_required=no
if [ -e "$preset_file" ] || [ -L "$preset_file" ]; then
  team_context_required=yes
else
  team_context_probe_rc=0
  python3 "$SKILL_DIR/bin/team-context.py" probe \
    --repo "$repo" --workspace "$workspace" --team "$team" --feature "$feature" >/dev/null \
    || team_context_probe_rc=$?
  case "$team_context_probe_rc" in
    0) team_context_required=yes ;;
    3) ;;
    *) echo "process-outbox: could not inspect protected team preset authority" >&2; exit 1 ;;
  esac
fi
if [ "$team_context_required" = yes ]; then
  team_context="$(python3 "$SKILL_DIR/bin/team-context.py" verify \
    --repo "$repo" --workspace "$workspace" --team "$team" --feature "$feature" \
    --skill "$SKILL_DIR")" \
    || { echo "process-outbox: protected team preset authority is unavailable" >&2; exit 1; }
  trusted_preset="$(printf '%s' "$team_context" | python3 -c 'import json,sys; print(json.load(sys.stdin)["preset"])')" \
    || { echo "process-outbox: protected team preset authority is malformed" >&2; exit 1; }
  if [ "$trusted_preset" = - ]; then
    trusted_policy_file="$preset_file"
    trusted_policy_digest="$(printf '%s' "$team_context" | python3 -c 'import json,sys; print(json.load(sys.stdin)["projectionSha256"])')"
  else
    trusted_policy_file="$SKILL_DIR/teams/$trusted_preset.md"
    trusted_policy_digest="$(printf '%s' "$team_context" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sourceSha256"])')"
  fi
fi

current_snapshot=""
authorized_actor=""
authorized_reviewer_context=""
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
  if ! broker_tracker "$SKILL_DIR/bin/tracker-ops.sh" export "$feature" "$current_snapshot" >/dev/null; then
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
      "$SKILL_DIR/config/statuses.config.json" "$BROKER_TRACKER_ADAPTER" \
      "$trusted_policy_file" "$trusted_policy_digest" "$pending" "$bodies" "$staged" "$current_snapshot" "$repo" "$SKILL_DIR" \
      "$BROKER_IGNORED_TASK_LABELS_JSON" <<'PY'
import hashlib, json, os, re, stat, sys
from pathlib import Path

(entry, workspace, expected_team, expected_feature, board_path, configured_adapter,
 policy_file, policy_digest, pending, bodies, staged, snapshot_path, repository,
 skill_dir, ignored_labels_json) = sys.argv[1:]
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(skill_dir, "bin"))
sys.path.insert(0, os.path.join(skill_dir, "src"))
from outbox_capability import CapabilityError, producer_envelope
from startup_factory_cli.secret_safety import contains_secret_like, redact_secret_like

def fail(message):
    print("process-outbox: " + redact_secret_like(message), file=sys.stderr)
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
            def unique_object(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        fail("%s contains duplicate JSON key" % label)
                    value[key] = item
                return value
            return json.loads(
                os.read(descriptor, 2 * 1024 * 1024).decode(),
                object_pairs_hook=unique_object,
            )
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
    entry_lexical = os.path.abspath(entry)
    entry_real = os.path.realpath(entry)
    allowed_parents = {os.path.realpath(pending), os.path.realpath(staged)}
    if entry_lexical != entry_real or os.path.dirname(entry_real) not in allowed_parents:
        fail("entry escapes its exact producer/protected delivery directory")
except ValueError:
    fail("entry escapes its exact producer/protected delivery directory")
data = read_json_regular(entry, "entry")
try:
    producer_envelope(data)
except CapabilityError as exc:
    fail("invalid closed producer/broker schema: %s" % exc)
if data.get("team") != expected_team or data.get("featureId") != expected_feature:
    fail("entry team/feature does not match this dispatcher")
if data.get("phase") != "pending":
    fail("producer phase is immutable and must remain pending")
if data.get("brokerSchemaVersion") is not None and data.get("brokerPhase") not in {
    "pending", "commented", "transitioned", "published"
}:
    fail("invalid protected broker phase")
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
if contains_secret_like(text):
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
expected_kind = {"review-request": "review", "review-findings": "queued"}.get(data["marker"])
if expected_kind and (target is None or statuses[target].get("kind") != expected_kind):
    fail("marker requests a status with the wrong semantic kind")
if data["marker"] in {"production-approval", "deployment"}:
    fail("production authority never enters through an agent outbox")

snapshot = read_json_regular(snapshot_path, "authoritative feature export")
if str(snapshot.get("featureId")) != expected_feature:
    fail("authoritative export featureId does not exactly match the dispatcher feature")
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
try:
    ignored_labels = json.loads(ignored_labels_json)
except ValueError:
    fail("configured ignoredTaskLabels policy is not valid JSON")
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
if policy_file:
    if os.path.islink(policy_file) or not os.path.isfile(policy_file) or os.path.getsize(policy_file) > 1024 * 1024:
        fail("trusted team policy must be a bounded non-symlink regular file")
    policy_bytes = open(policy_file, "rb").read()
    observed_policy_digest = "sha256:" + hashlib.sha256(policy_bytes).hexdigest()
    if observed_policy_digest != policy_digest:
        fail("trusted team policy changed after broker verification")
    for line in policy_bytes.decode("utf-8").splitlines():
        match = re.match(r"PROTOCOL_([A-Z_]+)=(.+)$", line.strip())
        if match:
            name, concrete = match.groups()
            if name in protocol:
                fail("team preset contains duplicate PROTOCOL_%s" % name)
            protocol[name] = concrete
else:
    # Direct/manual teams use three always-on core reviewers and retain an
    # independently mapped security specialist for declared security gates.
    protocol.update({
        "TEAM_LEAD": "team-lead",
        "PRINCIPAL_ARCHITECT": "principal-architect",
        "SCEPTICAL_ARCHITECT": "sceptical-architect",
        "SECURITY_REVIEWER": "senior-security-engineer",
    })
required_review_board = (
    "TEAM_LEAD",
    "PRINCIPAL_ARCHITECT",
    "SCEPTICAL_ARCHITECT",
)
review_board_roles = []
for protocol_name in required_review_board:
    concrete = protocol.get(protocol_name)
    if not concrete or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", concrete):
        fail("team preset must define one valid mandatory PROTOCOL_%s" % protocol_name)
    review_board_roles.append(concrete)
if len(set(review_board_roles)) != len(review_board_roles):
    fail("team preset core review board must use three distinct concrete agents")
security_reviewer = protocol.get("SECURITY_REVIEWER")
if not security_reviewer or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", security_reviewer):
    fail("team preset must define one valid on-demand PROTOCOL_SECURITY_REVIEWER")
if security_reviewer in set(review_board_roles):
    fail("team preset security reviewer must be distinct from the core review board")
marker_spec = (board.get("markers") or {}).get(data["marker"])
verified_capability = None
if data.get("producerCapability") is not None:
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.path.join(skill_dir, "bin"))
    try:
        from outbox_capability import CapabilityError, verify_entry
        verified_capability = verify_entry(repository, workspace, data, producer_digest)
    except (CapabilityError, OSError, ValueError) as exc:
        fail("verified launched-role capability rejected: %s" % exc)

gate_owned = marker_spec is not None or data["marker"] in {"handoff", "escalation"}
if data["marker"] == "review-request":
    if verified_capability is None:
        fail("verified launched-role capability is required for [review-request]")
    if verified_capability.get("executionKind") != "task":
        fail("[review-request] requires a task-role capability")
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

mandatory_review_marker_owner = {
    "team-lead-approval": "TEAM_LEAD",
    "architecture-approval": "PRINCIPAL_ARCHITECT",
    "sceptical-architecture-approval": "SCEPTICAL_ARCHITECT",
    "security-approval": "SECURITY_REVIEWER",
}
owner_protocol = mandatory_review_marker_owner.get(data["marker"])
if owner_protocol and effective_actor != protocol[owner_protocol]:
    fail(
        "actor is not the configured %s for marker [%s]"
        % (owner_protocol, data["marker"])
    )

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
context = "-"
if verified_capability is not None:
    context = str(data["producerCapability"]["id"]) + ":" + str(verified_capability["instance"])
print(effective_actor + "\t" + context)
PY
  )"; then
    [ -z "$validation_output" ] || printf '%s\n' "$validation_output" >&2
    cleanup_snapshot
    return 1
  fi
  authorized_actor="${validation_output%%	*}"
  authorized_reviewer_context="${validation_output#*	}"
  case "$authorized_actor" in
    ''|*[!a-z0-9-]*)
      echo "process-outbox: authority check did not return one valid effective actor" >&2
      cleanup_snapshot
      return 1
      ;;
  esac
  if [ "$authorized_reviewer_context" != - ]; then
    if ! python3 - "$authorized_reviewer_context" <<'PY'
import re,sys
value=sys.argv[1]
raise SystemExit(0 if len(value)<=256 and re.fullmatch(r"cap-[0-9a-f]{32}:[^\s]+",value) else 1)
PY
    then
      echo "process-outbox: authority check returned an invalid verified reviewer context" >&2
      cleanup_snapshot
      return 1
    fi
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
  python3 - "$1" "$pending" "$bodies" "$staged" "$repo" "$workspace" "$SKILL_DIR/bin" <<'PY'
import hashlib, json, os, stat, sys
from datetime import datetime, timezone
from pathlib import Path

entry, pending, bodies, staged, repository, workspace = map(Path, sys.argv[1:7])
sys.path.insert(0, sys.argv[7])
from outbox_capability import (
    CapabilityError, OUTBOX_CAPABILITY_FIELD, OUTBOX_PRODUCER_FIELDS,
    _canonical, _fsync_directory, _read_protected, _verify_entry,
    _write_exclusive, authority_lock, producer_envelope, strict_json,
)

def fail(message):
    raise SystemExit("process-outbox: " + message)

def canonical_child(path, root):
    try:
        lexical = Path(os.path.abspath(path))
        resolved = path.resolve(strict=True)
        root_resolved = root.resolve(strict=True)
        if lexical != resolved or resolved.parent != root_resolved:
            fail("path escapes its exact broker directory")
        return resolved
    except (OSError, ValueError) as exc:
        fail("cannot resolve broker path: %s" % exc)

def secure_read(path, label, maximum):
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            fail("%s must be a non-symlink regular file" % label)
        if before.st_size <= 0 or before.st_size > maximum:
            fail("%s has an invalid size" % label)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                fail("%s changed before secure open" % label)
            chunks = []
            size = 0
            while size <= maximum:
                block = os.read(fd, min(65536, maximum + 1 - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
            value = b"".join(chunks)
            after = os.fstat(fd)
            if len(value) != opened.st_size or (after.st_dev, after.st_ino, after.st_size) != (
                opened.st_dev, opened.st_ino, opened.st_size
            ):
                fail("%s changed while it was read" % label)
            return value
        finally:
            os.close(fd)
    except OSError as exc:
        fail("cannot securely read %s: %s" % (label, exc))

def signed_package(value):
    envelope = producer_envelope(value)
    package = dict(envelope)
    if value.get(OUTBOX_CAPABILITY_FIELD) is not None:
        package[OUTBOX_CAPABILITY_FIELD] = value[OUTBOX_CAPABILITY_FIELD]
    return _canonical(package) + b"\n"

def write_or_verify(path, content, label):
    if path.exists() or path.is_symlink():
        if secure_read(path, label, max(len(content), 1)) != content:
            fail("%s identity changed" % label)
        if stat.S_IMODE(path.lstat().st_mode) != 0o400:
            fail("%s must be immutable owner-read-only storage" % label)
        return
    _write_exclusive(path, content, 0o400)

try:
    canonical_entry = canonical_child(entry, pending)
    entry_raw = secure_read(canonical_entry, "producer entry", 1024 * 1024)
    data = strict_json(entry_raw, "producer entry")
    if not isinstance(data, dict) or set(data) not in {
        frozenset(OUTBOX_PRODUCER_FIELDS),
        frozenset(OUTBOX_PRODUCER_FIELDS | {OUTBOX_CAPABILITY_FIELD}),
    }:
        fail("producer entry contains broker-owned or unknown fields")
    envelope = producer_envelope(data)
    source = canonical_child(Path(str(envelope["bodyPath"])), bodies)
    if source.name != str(envelope["id"]) + ".md":
        fail("producer body identity does not match its entry")
    content = secure_read(source, "producer body", 65536)
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    canonical_package = signed_package(data)
    source_digest = "sha256:" + hashlib.sha256(canonical_package).hexdigest()
    record_key = hashlib.sha256(
        _canonical({
            "schemaVersion": 1,
            "workspace": str(workspace),
            "producerEntrySha256": source_digest,
            "producerBodySha256": digest,
        })
    ).hexdigest()
    record_path = staged / (record_key + ".entry.json")
    delivery = "delivery-" + record_key[:32]
    protected_entry = staged / (delivery + ".producer.json")
    target = staged / (delivery + ".source.md")
    with authority_lock(repository):
        verified_capability = None
        if isinstance(data.get("producerCapability"), dict):
            verified_capability = _verify_entry(
                str(repository), str(workspace), data, digest,
                require_active=True, authority_locked=True,
            )
        if record_path.exists() or record_path.is_symlink():
            existing = strict_json(
                _read_protected(record_path, "protected broker delivery", 2 * 1024 * 1024),
                "protected broker delivery",
            )
            producer_envelope(existing)
            if (
                existing.get("deliveryId") != delivery
                or existing.get("sourceEntryPath") != str(protected_entry)
                or existing.get("sourceEntrySha256") != source_digest
                or existing.get("stagedBodySha256") != digest
                or signed_package(existing) != canonical_package
            ):
                fail("protected broker delivery binding changed")
            # An admitted package may finish its first durable broker pass after
            # its producer exits.  Once that protected delivery is published,
            # however, a fenced generation cannot consume the admission again:
            # copied or reserialized pending aliases fail closed instead of
            # turning a recovery receipt into durable replay authority.
            if (
                verified_capability is not None
                and verified_capability.get("admissionRecovery") is True
                and existing.get("brokerPhase") == "published"
            ):
                fail("fenced producer package was already consumed")
            if secure_read(
                canonical_child(protected_entry, staged),
                "protected producer entry",
                1024 * 1024,
            ) != canonical_package:
                fail("protected producer entry digest mismatch")
            staged_body = Path(str(existing.get("stagedBodyPath") or ""))
            if canonical_child(staged_body, staged) != staged_body:
                fail("protected staged body is unsafe")
            if "sha256:" + hashlib.sha256(secure_read(staged_body, "staged body", 65536)).hexdigest() != digest:
                fail("protected staged body digest mismatch")
            print(json.dumps({"deliveryId": existing["deliveryId"], "entryPath": str(record_path)}, separators=(",", ":")))
            raise SystemExit(0)

        write_or_verify(protected_entry, canonical_package, "protected producer entry")
        write_or_verify(target, content, "protected producer body")
        protected = dict(data)
        protected.setdefault("producerCapability", None)
        protected.update({
            "brokerSchemaVersion": 1,
            "deliveryId": delivery,
            "brokerAssignedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sourceEntryPath": str(protected_entry),
            "sourceEntrySha256": source_digest,
            "stagedBodyPath": str(target),
            "stagedBodySha256": digest,
            "publishBodyPath": None,
            "publishBodySha256": None,
            "reviewBinding": None,
            "brokerPhase": "pending",
        })
        producer_envelope(protected)
        _write_exclusive(record_path, _canonical(protected) + b"\n")
        _fsync_directory(staged)
    print(json.dumps({"deliveryId": delivery, "entryPath": str(record_path)}, separators=(",", ":")))
except (CapabilityError, OSError, ValueError) as exc:
    fail("protected delivery assignment failed: %s" % exc)
PY
}

commit_publish_body() {
  # commit_publish_body <entry> <candidate-or--> <binding-json>
  python3 - "$1" "$2" "$3" "$staged" "$repo" "$SKILL_DIR/bin" <<'PY'
import hashlib, json, os, stat, sys
from pathlib import Path

entry, candidate_arg, binding_arg, staged, repository = sys.argv[1:6]
sys.path.insert(0, sys.argv[6])
from outbox_capability import (
    _canonical, _fsync_directory, _read_protected, _replace_owner_only,
    _write_exclusive, authority_lock, producer_envelope, strict_json,
)
entry, staged = Path(entry), Path(staged)

def protected_file(path, label, maximum=65536):
    try:
        lexical = Path(os.path.abspath(path))
        resolved = path.resolve(strict=True)
        if lexical != resolved or resolved.parent != staged.resolve(strict=True):
            raise SystemExit("process-outbox: %s escapes protected delivery storage" % label)
        before = resolved.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise SystemExit("process-outbox: %s is unsafe" % label)
        fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            content = b""
            while len(content) <= maximum:
                block = os.read(fd, maximum + 1 - len(content))
                if not block:
                    break
                content += block
            after = os.fstat(fd)
            if len(content) != opened.st_size or (opened.st_dev, opened.st_ino, opened.st_size) != (after.st_dev, after.st_ino, after.st_size):
                raise SystemExit("process-outbox: %s changed during secure read" % label)
            return resolved, content
        finally:
            os.close(fd)
    except OSError as exc:
        raise SystemExit("process-outbox: cannot securely read %s: %s" % (label, exc))

with authority_lock(repository):
    data = strict_json(
        _read_protected(entry, "protected broker delivery", 2 * 1024 * 1024),
        "protected broker delivery",
    )
    producer_envelope(data)
    delivery = data["deliveryId"]
    source, _source_content = protected_file(Path(data["stagedBodyPath"]), "staged body")
    candidate = source if candidate_arg == "-" else Path(candidate_arg)
    candidate, content = protected_file(candidate, "candidate publish body")
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    destination = staged / (delivery + ".publish.md")
    if data.get("publishBodyPath"):
        current, current_content = protected_file(Path(data["publishBodyPath"]), "stored publish body")
        if current != destination or current_content != content or data.get("publishBodySha256") != digest:
            raise SystemExit("process-outbox: review binding changed after delivery assignment; manual reconciliation required")
        print(current)
        raise SystemExit(0)
    _write_exclusive(destination, content, 0o400)
    data["publishBodyPath"] = str(destination)
    data["publishBodySha256"] = digest
    if binding_arg != "-":
        try:
            data["reviewBinding"] = strict_json(binding_arg, "review binding")
        except Exception as exc:
            raise SystemExit("process-outbox: invalid review binding") from exc
    _replace_owner_only(entry, _canonical(data) + b"\n")
    _fsync_directory(staged)
    print(destination)
PY
}

advance_delivery() { # protected-entry expected-phase next-phase
  python3 - "$1" "$2" "$3" "$repo" "$SKILL_DIR/bin" <<'PY'
import sys
from pathlib import Path

entry, expected, target, repository = sys.argv[1:5]
sys.path.insert(0, sys.argv[5])
from outbox_capability import (
    _canonical, _fsync_directory, _read_protected, _replace_owner_only,
    authority_lock, producer_envelope, strict_json,
)

allowed = {("pending", "commented"), ("commented", "transitioned"),
           ("commented", "published"), ("transitioned", "published")}
if (expected, target) not in allowed:
    raise SystemExit("process-outbox: invalid broker progression")
path = Path(entry)
with authority_lock(repository):
    data = strict_json(
        _read_protected(path, "protected broker delivery", 2 * 1024 * 1024),
        "protected broker delivery",
    )
    producer_envelope(data)
    if data.get("brokerPhase") != expected:
        raise SystemExit("process-outbox: broker delivery phase changed")
    data["brokerPhase"] = target
    _replace_owner_only(path, _canonical(data) + b"\n")
    _fsync_directory(path.parent)
PY
}

prepare_publish_body() {
  local entry="$1" marker="$2" task="$3" delivery="$4" staged_body="$5"
  local verified_actor="$6" reviewer_context="$7"
  local candidate package binding base head package_digest review_gates
  candidate="$staged/$delivery.candidate.$$.md"
  rm -f -- "$candidate"
  case "$marker" in
    review-request)
      if ! package="$(broker_child "$SKILL_DIR/bin/review-package.sh" "$team" "$task")"; then return 1; fi
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
      review_gates="$(python3 - "$current_snapshot" "$task" "$SKILL_DIR/bin" "$trusted_policy_file" "$trusted_policy_digest" "$repo" "$base" "$head" "$staged_body" <<'PY'
import hashlib, json, os, sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[3])
from delivery_profile import DeliveryProfileError, _git as safe_git, assess_review_diff
from review_evidence import EvidenceError, required_files_evidence
from task_metadata import effective_review_gates, parse_task_metadata
snapshot = json.load(open(sys.argv[1]))
task = next((item for item in snapshot.get("tasks") or [] if str(item.get("taskId")) == sys.argv[2]), None)
if task is None:
    raise SystemExit("process-outbox: review task disappeared from the authoritative snapshot")
preset = sys.argv[4]
expected_digest = sys.argv[5]
repo, base, head, staged_body = sys.argv[6:10]
preset_text = ""
if preset:
    if not os.path.lexists(preset):
        raise SystemExit("process-outbox: trusted team policy disappeared")
    if os.path.islink(preset) or not os.path.isfile(preset) or os.path.getsize(preset) > 1024 * 1024:
        raise SystemExit("process-outbox: trusted team policy must be a bounded non-symlink regular file")
    policy_bytes = open(preset, "rb").read()
    if "sha256:" + hashlib.sha256(policy_bytes).hexdigest() != expected_digest:
        raise SystemExit("process-outbox: trusted team policy changed after broker verification")
    preset_text = policy_bytes.decode("utf-8")
decision = assess_review_diff(repo, base, head, task)
try:
    declared_files = required_files_evidence(
        open(staged_body, encoding="utf-8").read(), "review-request"
    )
    raw_files = safe_git(
        os.path.realpath(repo),
        "diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv",
        "--ignore-submodules=none",
        base, head, "--", max_output_bytes=8 * 1024 * 1024,
        timeout_seconds=30.0,
    )
    exact_files = {
        value.decode("utf-8", "strict")
        for value in raw_files.split(b"\0")
        if value
    }
except (DeliveryProfileError, EvidenceError, OSError, UnicodeError) as exc:
    raise SystemExit("process-outbox: review request file evidence is unusable: %s" % exc)
if declared_files != exact_files:
    raise SystemExit(
        "process-outbox: review request Files evidence does not equal the exact committed diff"
    )
try:
    task_metadata = parse_task_metadata(task.get("description"), task.get("title"))
except ValueError:
    # The exact-diff assessor already elevated malformed metadata.  Preserve
    # any trustworthy preset gates while forcing QA+Security from the profile.
    task_metadata = parse_task_metadata("", task.get("title"))
print(",".join(effective_review_gates(
    task_metadata,
    preset_text,
    decision,
)))
PY
)" || return 1
      broker_python "$SKILL_DIR/bin/review_evidence.py" bind-request \
        "$staged_body" "$base" "$head" "$package_digest" "$candidate" \
        --review-gates "$review_gates" || return 1
      if ! binding="$(python3 - "$base" "$head" "$package_digest" <<'PY'
import json,sys
print(json.dumps({'kind':'review-request','base':sys.argv[1],'head':sys.argv[2],'package':sys.argv[3]}, separators=(',',':')))
PY
)"; then return 1; fi
      ;;
    review-approval|team-lead-approval|architecture-approval|sceptical-architecture-approval|security-approval)
      [ "$reviewer_context" != - ] \
        || { echo "process-outbox: approval lacks a verified reviewer context" >&2; return 1; }
      # The supervisor signature already covers the exact request/head/package
      # fields.  The broker may validate and add verified provenance, but must
      # never synthesize or replace those producer-authored bindings.
      broker_python "$SKILL_DIR/bin/review_evidence.py" finalize-approval \
        "$staged_body" "$current_snapshot" "$task" "$candidate" \
        "$verified_actor" "$reviewer_context" || return 1
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
  source_entry="$entry"
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
  if ! staged_assignment="$(broker_stage "$source_entry")"; then
    rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true
    reject_entry "$source_entry"
    if [ -n "$only" ]; then exit 1; fi
    continue
  fi
  delivery="$(printf '%s' "$staged_assignment" | python3 -c 'import json,sys; print(json.load(sys.stdin)["deliveryId"])')" \
    || { rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true; reject_entry "$source_entry"; [ -z "$only" ] || exit 1; continue; }
  entry="$(printf '%s' "$staged_assignment" | python3 -c 'import json,sys; print(json.load(sys.stdin)["entryPath"])')" \
    || { rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true; reject_entry "$source_entry"; [ -z "$only" ] || exit 1; continue; }
  staged_body="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stagedBodyPath"])' "$entry")"
  phase="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["brokerPhase"])' "$entry")"

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
    [ "$publish_ok" = yes ] && prepare_publish_body "$entry" "$marker" "$task" "$delivery" "$staged_body" "$authorized_actor" "$authorized_reviewer_context" || publish_ok=no
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
    [ "$publish_ok" = yes ] && prepare_publish_body "$entry" "$marker" "$task" "$delivery" "$staged_body" "$authorized_actor" "$authorized_reviewer_context" || publish_ok=no
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
    [ "$publish_ok" = yes ] && prepare_publish_body "$entry" "$marker" "$task" "$delivery" "$staged_body" "$authorized_actor" "$authorized_reviewer_context" || publish_ok=no
    if [ "$publish_ok" != yes ]; then
      cleanup_snapshot
      rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true
      reject_entry "$source_entry"
      if [ -n "$only" ]; then exit 1; fi
      continue
    fi
    case "$marker" in
      review-request|review-approval|team-lead-approval|architecture-approval|sceptical-architecture-approval|security-approval)
        # A governed review comment is inert without its protected receipt.
        # Prove that the external HMAC authority is available before creating
        # any tracker-side artifact; the exact receipt is written after the
        # idempotent comment succeeds.
        python3 "$SKILL_DIR/bin/broker_evidence.py" \
          --repo "$repo" --workspace "$workspace" --preflight-review >/dev/null \
          || publish_ok=no
        ;;
    esac
    if [ "$publish_ok" != yes ]; then
      cleanup_snapshot
      rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true
      reject_entry "$source_entry"
      if [ -n "$only" ]; then exit 1; fi
      continue
    fi
    # Re-prove hold/status/package authority at the last boundary before the
    # serialized tracker effect. The capability is reverified again under the
    # broker authority lock by broker_tracker_effect.
    cleanup_snapshot
    authority_status=0
    refresh_authority "$entry" || authority_status=$?
    if [ "$authority_status" -eq 75 ]; then
      stop_for_authority_outage "$owner_file" "$lock"
    elif [ "$authority_status" -ne 0 ]; then
      rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true
      reject_entry "$source_entry"
      if [ -n "$only" ]; then exit 1; fi
      continue
    fi
    prepare_publish_body "$entry" "$marker" "$task" "$delivery" "$staged_body" "$authorized_actor" "$authorized_reviewer_context" \
      || { rm -f "$owner_file"; rmdir "$lock" 2>/dev/null || true; reject_entry "$source_entry"; [ -z "$only" ] || exit 1; continue; }
    body="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["publishBodyPath"])' "$entry")"
    broker_tracker_effect "$entry" comment-once "$task" "$delivery" "$body"
    cleanup_snapshot
    advance_delivery "$entry" pending commented
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
      reject_entry "$source_entry"
      if [ -n "$only" ]; then exit 1; fi
      continue
    fi
    broker_tracker_effect "$entry" state "$task" "$target"
    cleanup_snapshot
    advance_delivery "$entry" commented transitioned
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
      reject_entry "$source_entry"
      if [ -n "$only" ]; then exit 1; fi
      continue
    fi
    body="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("publishBodyPath") or d["stagedBodyPath"])' "$entry")"
    python3 "$SKILL_DIR/bin/runtime-state.py" emit --workspace "$workspace" --team "$team" \
      --feature "$feature" --task "$task" --attempt "$attempt" --actor "$authorized_actor" \
      --type artifact.published --stage "${target:-artifact-published}" \
      --summary "[$marker] published to tracker" --artifact "$body" >/dev/null
    advance_delivery "$entry" "$phase" published
  fi
  # Workspace receipts are not authorization. Bind the exact successful
  # tracker publication into the protected external broker ledger first.
  python3 "$SKILL_DIR/bin/broker_evidence.py" \
    --repo "$repo" --workspace "$workspace" --entry "$entry" >/dev/null
  destination="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "outbox/done/$id.json")"
  cp "$entry" "$destination"
  rm -f -- "$source_entry"
  rm -f "$owner_file"
  rmdir "$lock" 2>/dev/null || true
  echo "published [$marker] for $task ($delivery)"
done
cleanup_snapshot
