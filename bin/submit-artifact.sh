#!/usr/bin/env bash
# Put one structured agent artifact in the durable outbox; the dispatcher publishes it.
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

[ $# -eq 8 ] || {
  echo "usage: submit-artifact.sh <team> <featureId> <taskId> <attempt> <actor> <marker> <bodyfile> <target-status|->" >&2
  exit 2
}
team="$1"; feature="$2"; task="$3"; attempt="$4"; actor="$5"; marker="$6"; source="$7"; target="$8"
case "$team" in ''|*[!a-zA-Z0-9._-]*) echo "submit-artifact: unsafe team identifier" >&2; exit 1 ;; esac
case "$actor" in ''|*[!a-z0-9-]*) echo "submit-artifact: unsafe actor" >&2; exit 1 ;; esac
case "$marker" in ''|*[!a-z0-9-]*) echo "submit-artifact: unsafe marker" >&2; exit 1 ;; esac
case "$attempt" in ''|*[!0-9]*) echo "submit-artifact: attempt must be a positive integer" >&2; exit 1 ;; esac
[ "$attempt" -ge 1 ] || { echo "submit-artifact: attempt must be positive" >&2; exit 1; }
[ -f "$source" ] && [ ! -L "$source" ] && [ -s "$source" ] || { echo "submit-artifact: body must be a non-symlink regular file: $source" >&2; exit 1; }
[ "$(wc -c < "$source")" -le 65536 ] || { echo "submit-artifact: body exceeds 64 KiB" >&2; exit 1; }
first="$(sed -n '1p' "$source")"
case "$first" in
  "[$marker]"*) ;;
  *) echo "submit-artifact: body must begin with [$marker]" >&2; exit 1 ;;
esac

# When invoked by a launched role, bind the producer-supplied identity to the
# launcher's fixed runtime context. The broker repeats this check against its
# protected execution record; this early check makes accidental or opportunistic
# cross-task/role submissions fail before any outbox state is created.
launched=no
if [ -n "${STARTUP_FACTORY_EXECUTION_KIND:-}${STARTUP_FACTORY_TEAM:-}${STARTUP_FACTORY_FEATURE_ID:-}${STARTUP_FACTORY_ROLE:-}" ]; then
  launched=yes
  for name in STARTUP_FACTORY_EXECUTION_KIND STARTUP_FACTORY_TEAM STARTUP_FACTORY_FEATURE_ID STARTUP_FACTORY_ROLE STARTUP_FACTORY_TASK_ID STARTUP_FACTORY_ATTEMPT; do
    [ -n "${!name:-}" ] || { echo "submit-artifact: incomplete fixed runtime identity ($name is absent)" >&2; exit 1; }
  done
  [ "$team" = "$STARTUP_FACTORY_TEAM" ] \
    || { echo "submit-artifact: team does not match fixed runtime identity" >&2; exit 1; }
  [ "$feature" = "$STARTUP_FACTORY_FEATURE_ID" ] \
    || { echo "submit-artifact: feature does not match fixed runtime identity" >&2; exit 1; }
  [ "$actor" = "$STARTUP_FACTORY_ROLE" ] \
    || { echo "submit-artifact: actor does not match fixed runtime identity" >&2; exit 1; }
  case "$STARTUP_FACTORY_EXECUTION_KIND" in
    task)
      [ "$task" = "$STARTUP_FACTORY_TASK_ID" ] \
        || { echo "submit-artifact: task does not match fixed runtime identity" >&2; exit 1; }
      [ "$attempt" = "$STARTUP_FACTORY_ATTEMPT" ] \
        || { echo "submit-artifact: attempt does not match fixed runtime identity" >&2; exit 1; }
      ;;
    gate)
      [ "$STARTUP_FACTORY_TASK_ID" = "-" ] && [ "$STARTUP_FACTORY_ATTEMPT" = "0" ] \
        || { echo "submit-artifact: malformed fixed gate identity" >&2; exit 1; }
      ;;
    *) echo "submit-artifact: unknown fixed execution kind" >&2; exit 1 ;;
  esac
  for name in STARTUP_FACTORY_INSTANCE STARTUP_FACTORY_CANONICAL_REPO STARTUP_FACTORY_CANONICAL_WORKSPACE \
      STARTUP_FACTORY_OUTBOX_CAPABILITY_ID STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET \
      STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT; do
    [ -n "${!name:-}" ] || { echo "submit-artifact: incomplete launched-role capability ($name is absent)" >&2; exit 1; }
  done
elif [ -n "${STARTUP_FACTORY_OUTBOX_CAPABILITY_ID:-}${STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET:-}${STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT:-}" ]; then
  echo "submit-artifact: an outbox capability is invalid without the complete fixed runtime identity" >&2
  exit 1
fi

current_repo="$(git rev-parse --show-toplevel)"
if [ "$launched" = yes ]; then
  repo="$STARTUP_FACTORY_CANONICAL_REPO"
else
  repo="$current_repo"
fi
root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
workspace="$(python3 "$SKILL_DIR/bin/teamwork-path.py" workspace --repo "$repo" --root "$root" --team "$team")"
if [ "$launched" = yes ]; then
  [ "$workspace" = "$STARTUP_FACTORY_CANONICAL_WORKSPACE" ] \
    || { echo "submit-artifact: launcher-fixed canonical workspace does not match team configuration" >&2; exit 1; }
  worktree_mode="$(read_key TASK_WORKTREE_MODE)"; worktree_mode="${worktree_mode:-linked-worktree}"
  fixed_task_worktree="${STARTUP_FACTORY_TASK_WORKTREE:-}"
  python3 - "$current_repo" "$repo" "$worktree_mode" "$STARTUP_FACTORY_EXECUTION_KIND" "$fixed_task_worktree" <<'PY'
import os, subprocess, sys

current, canonical, mode, kind, fixed_task = sys.argv[1:]

def fail(message):
    raise SystemExit("submit-artifact: " + message)

def top(path):
    try:
        raw = subprocess.run(
            ["git", "-C", path, "rev-parse", "--show-toplevel"], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        fail("runtime working copy is not a Git worktree")
    return os.path.realpath(raw)

def common(path):
    try:
        raw = subprocess.run(
            ["git", "-C", path, "rev-parse", "--git-common-dir"], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        fail("cannot resolve runtime Git common directory")
    if not os.path.isabs(raw):
        raw = os.path.join(top(path), raw)
    return os.path.realpath(raw)

if not os.path.isabs(canonical) or os.path.abspath(canonical) != os.path.realpath(canonical):
    fail("canonical repository must be an absolute non-symlink path")
if top(canonical) != os.path.realpath(canonical):
    fail("canonical repository does not equal its Git toplevel")
if mode == "standalone-clone" and kind == "task":
    if not fixed_task or not os.path.isabs(fixed_task):
        fail("standalone task worktree binding is absent")
    if top(current) != os.path.realpath(fixed_task) or current != os.path.realpath(fixed_task):
        fail("runtime clone does not match the launcher-fixed standalone task path")
    if not os.path.isdir(os.path.join(current, ".git")) or os.path.islink(os.path.join(current, ".git")):
        fail("runtime clone lacks an independent Git directory")
elif common(current) != common(canonical):
    fail("runtime worktree is not linked to the launcher-fixed canonical repository")
PY
fi
id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
pending="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/pending)"
bodies="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/bodies)"
done="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative outbox/done)"
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative events.ndjson >/dev/null
mkdir -p "$pending" "$bodies" "$done"
body="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "outbox/bodies/$id.md")"
# Copy through no-follow descriptors into a new file. The later credentialed
# broker creates a second, broker-owned immutable stage and assigns deliveryId.
python3 - "$source" "$body" <<'PY'
import os, stat, sys
source, destination = sys.argv[1:]
read_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
try:
    source_fd = os.open(source, read_flags)
    try:
        info = os.fstat(source_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 65536:
            raise SystemExit("submit-artifact: body must be a 1..65536 byte regular file")
        content = b""
        while len(content) <= 65536:
            block = os.read(source_fd, 65537 - len(content))
            if not block:
                break
            content += block
        if len(content) > 65536:
            raise SystemExit("submit-artifact: body exceeds 64 KiB")
    finally:
        os.close(source_fd)
    destination_fd = os.open(destination, write_flags, 0o600)
    try:
        with os.fdopen(destination_fd, "wb") as handle:
            destination_fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
except OSError as exc:
    raise SystemExit("submit-artifact: secure body staging failed: %s" % exc)
PY
entry="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative "outbox/pending/$id.json")"
python3 - "$entry" "$id" "$team" "$feature" "$task" "$attempt" "$actor" "$marker" "$body" "$target" "$SKILL_DIR" <<'PY'
import json, os, sys
from datetime import datetime, timezone
path, ident, team, feature, task, attempt, actor, marker, body, target, skill_dir = sys.argv[1:]
temp = path + '.tmp'
data = {
    # id is an unprivileged submission identity used only for the local
    # queue/lock. process-outbox assigns the authoritative deliveryId.
    'schemaVersion': 1, 'id': ident, 'team': team, 'featureId': feature,
    'taskId': task, 'attempt': int(attempt), 'actor': actor, 'marker': marker,
    'bodyPath': body, 'targetStatus': None if target == '-' else target,
    'phase': 'pending', 'createdAt': datetime.now(timezone.utc).isoformat(timespec='seconds')
}
capability_values = {
    'id': os.environ.get('STARTUP_FACTORY_OUTBOX_CAPABILITY_ID', ''),
    'secret': os.environ.get('STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET', ''),
    'instance': os.environ.get('STARTUP_FACTORY_INSTANCE', ''),
    'expires': os.environ.get('STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT', ''),
}
if any(capability_values.values()):
    if not all(capability_values.values()):
        raise SystemExit('submit-artifact: incomplete producer capability while signing entry')
    sys.path.insert(0, os.path.join(skill_dir, 'bin'))
    from outbox_capability import CapabilityError, sign_entry
    try:
        data['producerCapability'] = sign_entry(
            data, open(body, 'rb').read(), capability_values['id'],
            capability_values['secret'], capability_values['instance'],
            int(capability_values['expires']),
        )
    except (CapabilityError, OSError, ValueError) as exc:
        raise SystemExit('submit-artifact: cannot sign producer entry: %s' % exc)
with open(temp, 'w') as handle:
    json.dump(data, handle, indent=2)
    handle.write('\n')
os.replace(temp, path)
PY
python3 "$SKILL_DIR/bin/runtime-state.py" emit --workspace "$workspace" --team "$team" \
  --feature "$feature" --task "$task" --attempt "$attempt" --actor "$actor" \
  --type artifact.ready --stage artifact-ready --summary "[$marker] queued for tracker publication" --artifact "$body" >/dev/null

if [ "$(read_key TRACKER_WRITERS)" = "all" ]; then
  ( cd "$repo" && "$SKILL_DIR/bin/process-outbox.sh" "$team" "$feature" "$entry" )
else
  echo "$entry"
fi
