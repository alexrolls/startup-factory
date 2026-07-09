#!/usr/bin/env bash
# dispatch.sh — one deterministic read-and-act pass (or a loop of them).
# Zero LLM per cycle. Logic spec: reference/dispatch.md.
#
# Usage:
#   dispatch.sh <team> <featureId> --once [--dry-run] [--unblock=auto|suggest|off]
#   dispatch.sh <team> <featureId> --watch [--unblock=...]
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$SKILL_DIR/config/team.config.md"
PM_CONFIG="$SKILL_DIR/config/project-management.config.md"

die() { echo "dispatch: $*" >&2; exit 1; }

read_key() { # from team.config.md; quotes stripped; null -> empty
  local line; line="$(grep -m1 "^$1=" "$CONFIG" || true)"
  line="${line#*=}"; line="${line%\"}"; line="${line#\"}"
  [ "$line" = "null" ] && line=""
  printf '%s' "$line"
}

teamroot() {
  local root; root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
  printf '%s/%s/%s' "$(git rev-parse --show-toplevel)" "$root" "$1"
}

role_live() { # role_live <team> <role> -> 0 if a live instance exists
  local pf; pf="$(teamroot "$1")/pids/$2.pid"
  [ -f "$pf" ] || return 1
  local pid; pid="$(cat "$pf")"
  if [ "$pid" = "tmux" ]; then
    tmux list-windows -t "team-$1" -F '#{window_name}' 2>/dev/null | grep -qx "$2"
  else
    kill -0 "$pid" 2>/dev/null
  fi
}

next_mailbox_file() { # next_mailbox_file <mailbox-dir> -> path with next free NNN
  local mb="$1" max=0 n f
  mkdir -p "$mb"
  for f in "$mb"/[0-9][0-9][0-9]-*.md; do
    [ -e "$f" ] || continue
    n="${f##*/}"; n="${n%%-*}"; n=$((10#$n))
    [ "$n" -gt "$max" ] && max=$n
  done
  printf '%s/%03d-dispatcher.md' "$mb" $((max + 1))
}

adapter_default_unblock() {
  local a; a="$(grep -m1 '^PRODUCT_MANAGEMENT_TOOL=' "$PM_CONFIG" | cut -d= -f2 | tr -d '"' || true)"
  case "${TRACKER_ADAPTER:-$a}" in Linear|Jira) echo auto ;; *) echo suggest ;; esac
}

dispatch_once() { # dispatch_once <team> <featureId> <dry:yes|no> <unblock>
  local team="$1" fid="$2" dry="$3" unblock="$4"
  local dir; dir="$(teamroot "$team")"
  mkdir -p "$dir"
  "$SKILL_DIR/bin/tracker-ops.sh" export "$fid" "$dir/tasks.json" >/dev/null
  local stuck; stuck="$(read_key STUCK_AFTER_MINUTES)"; stuck="${stuck:-15}"
  local plan
  plan="$(python3 - "$SKILL_DIR" "$dir" "$stuck" 3<&- <<'PYEOF'
import json, os, sys, time
skill, workdir, stuck_min = sys.argv[1], sys.argv[2], int(sys.argv[3])
board = json.load(open(os.path.join(skill, 'config', 'statuses.config.json')))
terminal = {s['name'] for s in board['tasks']['statuses'] if s.get('terminal')}
tasks = json.load(open(os.path.join(workdir, 'tasks.json')))['tasks']
by_id = {str(t['taskId']): t for t in tasks}

def last(t, *names):  # index of the last comment starting with any [name]
    idx = -1
    for i, c in enumerate(t.get('comments') or []):
        b = (c.get('body') or '').lstrip()
        if any(b.startswith('[%s]' % n) for n in names):
            idx = i
    return idx

def blockers_terminal(t):
    bb = t.get('blockedBy') or []
    return all(by_id.get(str(b), {}).get('status') in terminal for b in bb)

acts = []
for t in tasks:  # 1. auto-unblock candidates
    if t.get('status') == 'Blocked' and (t.get('blockedBy') or []) and blockers_terminal(t):
        acts.append(('unblock', str(t['taskId']), ''))

design_q = [str(t['taskId']) for t in tasks
            if last(t, 'design-note') > last(t, 'design-approved', 'design-pushback')]
review_q, arch_q, merge_q = [], [], []
for t in tasks:
    if t.get('status') != 'Review':
        continue
    tid, req = str(t['taskId']), last(t, 'review-request')
    ra, aa = last(t, 'review-approval'), last(t, 'architecture-approval')
    if ra > req and aa > req:
        merge_q.append(tid)
    else:
        if ra <= req: review_q.append(tid)
        if aa <= req: arch_q.append(tid)

if design_q or arch_q:
    acts.append(('launch', 'principal-architect',
                 'Dispatch queue — design gates: %s; architecture reviews: %s. '
                 'Drain every item, post per-[task] markers, exit.'
                 % (', '.join(design_q) or 'none', ', '.join(arch_q) or 'none')))
if review_q:
    acts.append(('launch', 'reviewer',
                 'Dispatch queue — [Review]: %s. Drain every item, post per-[task] verdicts, exit.'
                 % ', '.join(review_q)))
if merge_q:
    acts.append(('launch', 'integrator',
                 'Dispatch queue — dual-approved, integrate in dependency order: %s. '
                 'Per-[task] atomic commit+move, then exit.' % ', '.join(merge_q)))

planned = [str(t['taskId']) for t in tasks
           if t.get('status') == 'Planned' and not t.get('assignee') and blockers_terminal(t)]
stale = []
hb = os.path.join(workdir, 'heartbeats')
if os.path.isdir(hb):
    now = time.time()
    stale = [f for f in os.listdir(hb)
             if now - os.path.getmtime(os.path.join(hb, f)) > stuck_min * 60]
if planned or stale:
    acts.append(('launch', 'team-lead',
                 'Lead-actionable — dispatchable [Planned]: %s; stale heartbeats: %s. '
                 'One supervision pass, then exit.'
                 % (', '.join(planned) or 'none', ', '.join(stale) or 'none')))

for a in acts:
    print('\t'.join(a))
PYEOF
)"
  if [ -z "$plan" ]; then echo "dispatch: nothing actionable"; return 0; fi
  local action arg detail
  while IFS="$(printf '\t')" read -r action arg detail; do
    case "$action" in
      unblock)
        case "$unblock" in
          off)     echo "plan: unblock $arg — suppressed (--unblock=off)" ;;
          suggest) echo "plan: unblock $arg — SUGGESTED (confirm and move via the team-lead; see reference/dispatch.md)" ;;
          auto)
            echo "plan: unblock $arg (all blockers terminal)"
            if [ "$dry" != "yes" ]; then
              "$SKILL_DIR/bin/tracker-ops.sh" state "$arg" Active
              printf 'Auto-unblocked by dispatcher: every blocking [task] reached the terminal status.\n\n— dispatcher (on behalf of team-lead)\n' \
                | "$SKILL_DIR/bin/tracker-ops.sh" comment "$arg" -
            fi ;;
          *) die "unknown --unblock mode '$unblock'" ;;
        esac ;;
      launch)
        if role_live "$team" "$arg"; then
          echo "plan: launch $arg — skipped (live instance)"
        else
          echo "plan: launch $arg ($detail)"
          if [ "$dry" != "yes" ]; then
            local mf; mf="$(next_mailbox_file "$dir/mailbox/$arg")"
            printf 'From: dispatcher\nRe: %s\n---\n%s\n' "$fid" "$detail" > "$mf"
            "$SKILL_DIR/bin/launch-team.sh" start "$team" "$fid" "$arg"
          fi
        fi ;;
    esac
  done <<EOF
$plan
EOF
}

[ $# -ge 3 ] || die "usage: dispatch.sh <team> <featureId> --once|--watch [--dry-run] [--unblock=auto|suggest|off]"
TEAM="$1"; FID="$2"; MODE="$3"; shift 3
DRY=no; UNBLOCK="$(adapter_default_unblock)"
for opt in "$@"; do
  case "$opt" in
    --dry-run) DRY=yes ;;
    --unblock=*) UNBLOCK="${opt#*=}" ;;
    *) die "unknown option $opt" ;;
  esac
done
case "$MODE" in
  --once) dispatch_once "$TEAM" "$FID" "$DRY" "$UNBLOCK" ;;
  --watch)
    [ "$DRY" = "no" ] || die "--watch does not combine with --dry-run"
    INTERVAL="$(read_key POLL_INTERVAL_SECONDS)"; INTERVAL="${INTERVAL:-120}"
    echo "dispatch: watching (every ${INTERVAL}s) — this shell is the loop owner; keep it alive (tmux/nohup)"
    while true; do
      dispatch_once "$TEAM" "$FID" no "$UNBLOCK" || echo "dispatch: pass failed — retrying next interval" >&2
      sleep "$INTERVAL"
    done ;;
  *) die "mode must be --once or --watch" ;;
esac
