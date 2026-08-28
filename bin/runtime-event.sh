#!/usr/bin/env bash
# Append one durable execution event and immediately reflect task progress in the tracker.
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

[ $# -ge 7 ] && [ $# -le 9 ] || {
  echo "usage: runtime-event.sh <team> <featureId> <taskId|-> <attempt> <actor> <type> <stage> [summary] [artifact]" >&2
  exit 2
}

team="$1"; feature="$2"; task="$3"; attempt="$4"; actor="$5"; type="$6"; stage="$7"
summary="${8:-}"; artifact="${9:-}"

# A launched role receives an immutable runtime identity and canonical routing
# context from launch-team.sh.  Bind caller-supplied event identity to that
# context before creating any journal state.  Standalone broker/dispatcher calls
# have no fixed runtime identity and continue to resolve from their current repo.
launched=no
if [ -n "${STARTUP_FACTORY_EXECUTION_KIND:-}${STARTUP_FACTORY_TEAM:-}${STARTUP_FACTORY_FEATURE_ID:-}${STARTUP_FACTORY_ROLE:-}" ]; then
  launched=yes
  for name in STARTUP_FACTORY_EXECUTION_KIND STARTUP_FACTORY_TEAM STARTUP_FACTORY_FEATURE_ID STARTUP_FACTORY_ROLE STARTUP_FACTORY_TASK_ID STARTUP_FACTORY_ATTEMPT; do
    [ -n "${!name:-}" ] || { echo "runtime-event: incomplete fixed runtime identity ($name is absent)" >&2; exit 1; }
  done
  [ "$team" = "$STARTUP_FACTORY_TEAM" ] \
    || { echo "runtime-event: team does not match fixed runtime identity" >&2; exit 1; }
  [ "$feature" = "$STARTUP_FACTORY_FEATURE_ID" ] \
    || { echo "runtime-event: feature does not match fixed runtime identity" >&2; exit 1; }
  [ "$actor" = "$STARTUP_FACTORY_ROLE" ] \
    || { echo "runtime-event: actor does not match fixed runtime identity" >&2; exit 1; }
  case "$STARTUP_FACTORY_EXECUTION_KIND" in
    task)
      [ "$task" = "$STARTUP_FACTORY_TASK_ID" ] \
        || { echo "runtime-event: task does not match fixed runtime identity" >&2; exit 1; }
      [ "$attempt" = "$STARTUP_FACTORY_ATTEMPT" ] \
        || { echo "runtime-event: attempt does not match fixed runtime identity" >&2; exit 1; }
      ;;
    gate)
      [ "$STARTUP_FACTORY_TASK_ID" = "-" ] && [ "$STARTUP_FACTORY_ATTEMPT" = "0" ] \
        || { echo "runtime-event: malformed fixed gate identity" >&2; exit 1; }
      ;;
    *) echo "runtime-event: unknown fixed execution kind" >&2; exit 1 ;;
  esac
  for name in STARTUP_FACTORY_INSTANCE STARTUP_FACTORY_CANONICAL_REPO STARTUP_FACTORY_CANONICAL_WORKSPACE; do
    [ -n "${!name:-}" ] || { echo "runtime-event: incomplete launched-role routing context ($name is absent)" >&2; exit 1; }
  done
fi

root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
current_repo="$(git rev-parse --show-toplevel)"
if [ "$launched" = yes ]; then
  repo="$STARTUP_FACTORY_CANONICAL_REPO"
else
  repo="$current_repo"
fi
workspace="$(python3 "$SKILL_DIR/bin/teamwork-path.py" workspace --repo "$repo" --root "$root" --team "$team")"
if [ "$launched" = yes ]; then
  [ "$workspace" = "$STARTUP_FACTORY_CANONICAL_WORKSPACE" ] \
    || { echo "runtime-event: launcher-fixed canonical workspace does not match team configuration" >&2; exit 1; }
  # Accept the canonical checkout itself or one of its linked task worktrees,
  # but never a copied environment from a different Git repository.  Keep this
  # check aligned with submit-artifact.sh's canonical-routing boundary.
  python3 - "$current_repo" "$repo" <<'PY'
import os
import subprocess
import sys

current, canonical = sys.argv[1:]


def fail(message):
    raise SystemExit("runtime-event: " + message)


def top(path):
    try:
        raw = subprocess.run(
            ["git", "-C", path, "rev-parse", "--show-toplevel"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        fail("runtime working copy is not a Git worktree")
    return os.path.realpath(raw)


def common(path):
    try:
        raw = subprocess.run(
            ["git", "-C", path, "rev-parse", "--git-common-dir"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
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
if common(current) != common(canonical):
    fail("runtime worktree is not linked to the launcher-fixed canonical repository")
PY
fi
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative events.ndjson >/dev/null
python3 "$SKILL_DIR/bin/teamwork-path.py" child --repo "$repo" --workspace "$workspace" --relative pm >/dev/null
heartbeat=""
heartbeat_state=""
if [ "$launched" = yes ]; then
  heartbeat="$(python3 "$SKILL_DIR/bin/teamwork-path.py" child \
    --repo "$repo" --workspace "$workspace" --relative "heartbeats/$STARTUP_FACTORY_INSTANCE")"
  # Preflight the bounded semantic payload before accepting the event.  The
  # post-append writer below can then fail only on an actual filesystem error,
  # rather than accepting a journal entry whose supplied state cannot refresh
  # the heartbeat.
  heartbeat_state="$(python3 - "$STARTUP_FACTORY_TASK_ID" "$STARTUP_FACTORY_ATTEMPT" "$stage" <<'PY'
import sys

task, attempt, stage = sys.argv[1:]
if not task or len(task) > 1024 or any(char in task for char in "\r\n|"):
    raise SystemExit("runtime-event: fixed task identity is unsafe for heartbeat transport")
if not attempt.isdigit() or len(attempt) > 12:
    raise SystemExit("runtime-event: fixed attempt identity is unsafe for heartbeat transport")
state = " ".join(stage.split())
if not state:
    raise SystemExit("runtime-event: heartbeat state must not be empty")
print(state[:160])
PY
)"
fi

args=(emit --workspace "$workspace" --team "$team" --feature "$feature" --task "$task"
      --attempt "$attempt" --actor "$actor" --type "$type" --stage "$stage"
      --summary "$summary")
[ "$(read_key TRACKER_WRITERS)" != "all" ] || args+=(--tracker-ops "$SKILL_DIR/bin/tracker-ops.sh")
[ -z "$artifact" ] || args+=(--artifact "$artifact")
python3 "$SKILL_DIR/bin/runtime-state.py" "${args[@]}"
if [ -n "$heartbeat" ]; then
  python3 - "$heartbeat" "$STARTUP_FACTORY_TASK_ID" "$STARTUP_FACTORY_ATTEMPT" "$heartbeat_state" <<'PY'
from datetime import datetime, timezone
import os
from pathlib import Path
import sys

path = Path(sys.argv[1])
task, attempt, stage = sys.argv[2:]

if not task or len(task) > 1024 or any(char in task for char in "\r\n|"):
    raise SystemExit("runtime-event: fixed task identity is unsafe for heartbeat transport")
if not attempt.isdigit() or len(attempt) > 12:
    raise SystemExit("runtime-event: fixed attempt identity is unsafe for heartbeat transport")
state = stage
timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
body = f"{timestamp} | {task} | {state}; attempt={attempt}\n"
if len(body.encode("utf-8")) > 2048:
    raise SystemExit("runtime-event: heartbeat exceeds the 2 KiB transport limit")

path.parent.mkdir(parents=True, exist_ok=True)
temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = -1
try:
    descriptor = os.open(temporary, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        descriptor = -1
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
fi
