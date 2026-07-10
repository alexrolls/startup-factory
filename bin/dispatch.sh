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

role_cmd_key() { # backend -> BACKEND_CMD ; principal-architect -> PRINCIPAL_ARCHITECT_CMD
  printf '%s_CMD' "$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')"
}

key_is_null() { # key_is_null KEY -> 0 if the config sets KEY explicitly to null
  grep -qE "^$1=null[[:space:]]*(#.*)?$" "$CONFIG"
}

read_key() { # from team.config.md; quotes stripped; null -> empty; inline # stripped on unquoted
  local line _t; line="$(grep -m1 "^$1=" "$CONFIG" || true)"
  line="${line#*=}"
  if [ "${line#\"}" != "$line" ]; then
    line="${line#\"}"; line="${line%%\"*}"
  else
    line="${line%%[[:space:]]#*}"
    _t="${line##*[![:space:]]}"; line="${line%"$_t"}"
  fi
  [ "$line" = "null" ] && line=""
  printf '%s' "$line"
}

read_pm_key() { # read from project-management.config.md; quotes stripped; null -> empty; inline # stripped
  local line _t; line="$(grep -m1 "^$1=" "$PM_CONFIG" || true)"
  line="${line#*=}"
  if [ "${line#\"}" != "$line" ]; then
    line="${line#\"}"; line="${line%%\"*}"
  else
    line="${line%%[[:space:]]#*}"
    _t="${line##*[![:space:]]}"; line="${line%"$_t"}"
  fi
  [ "$line" = "null" ] && line=""
  printf '%s' "$line"
}

is_mcp_only() { # is_mcp_only <adapter> -> 0 if configured for MCP-only access
  case "$1" in
    Linear)       [ "$(read_pm_key LINEAR_ACCESS)"  = "mcp"  ] ;;
    Jira)         [ "$(read_pm_key JIRA_ACCESS)"    = "mcp"  ] ;;
    GitHubIssues) [ "$(read_pm_key GITHUB_USE_MCP)" = "true" ] ;;
    *)            return 1 ;;
  esac
}

resolve_role() { # resolve_role <team> <protocol-role> -> concrete role (or same if no mapping)
  local pf; pf="$(teamroot "$1")/preset.env"
  [ -f "$pf" ] || { printf '%s' "$2"; return; }
  local key; key="PROTOCOL_$(printf '%s' "$2" | tr 'a-z-' 'A-Z_')"
  local val; val="$(grep -m1 "^$key=" "$pf" | cut -d= -f2 || true)"
  printf '%s' "${val:-$2}"
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
  local a; a="$(grep -m1 '^PRODUCT_MANAGEMENT_TOOL=' "$PM_CONFIG" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
  local effective="${TRACKER_ADAPTER:-$a}"
  [ -n "$effective" ] || die "cannot determine tracker adapter (PRODUCT_MANAGEMENT_TOOL in config/project-management.config.md or TRACKER_ADAPTER env)"
  case "$effective" in Linear|Jira) echo auto ;; *) echo suggest ;; esac
}

dispatch_once() { # dispatch_once <team> <featureId> <dry:yes|no> <unblock>
  local team="$1" fid="$2" dry="$3" unblock="$4"
  local dir; dir="$(teamroot "$team")"
  local _a; _a="$(grep -m1 '^PRODUCT_MANAGEMENT_TOOL=' "$PM_CONFIG" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
  local adapter="${TRACKER_ADAPTER:-$_a}"
  if is_mcp_only "$adapter"; then
    die "dispatch requires scriptable tracker access — $adapter is configured for MCP-only.
  Set the scriptable option in config/project-management.config.md or use harness mode."
  fi
  mkdir -p "$dir"
  "$SKILL_DIR/bin/tracker-ops.sh" export "$fid" "$dir/tasks.json" >/dev/null
  local stuck; stuck="$(read_key STUCK_AFTER_MINUTES)"; stuck="${stuck:-15}"
  local plan
  plan="$(python3 - "$SKILL_DIR" "$dir" "$stuck" 3<&- <<'PYEOF'
import json, os, re as _re, sys, time
skill, workdir, stuck_min = sys.argv[1], sys.argv[2], int(sys.argv[3])
board = json.load(open(os.path.join(skill, 'config', 'statuses.config.json')))
terminal = {s['name'] for s in board['tasks']['statuses'] if s.get('terminal')}
blocked_transitions = next(
    (set(s['transitions']) for s in board['tasks']['statuses'] if s['name'] == 'Blocked'),
    set())
tasks = json.load(open(os.path.join(workdir, 'tasks.json')))['tasks']
by_id = {str(t['taskId']): t for t in tasks}

preset_env = os.path.join(workdir, 'preset.env')
protocol_reviewer = None
if os.path.exists(preset_env):
    with open(preset_env) as _f:
        for _ln in _f:
            _m = _re.match(r'^PROTOCOL_REVIEWER=(.+)$', _ln.strip())
            if _m: protocol_reviewer = _m.group(1); break

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

def last_resume_status(t):  # latest 'resume-status: <value>' line across all comment bodies
    result = None
    for c in (t.get('comments') or []):
        for line in (c.get('body') or '').splitlines():
            if line.startswith('resume-status: '):
                result = line[len('resume-status: '):].strip()
    return result

acts = []
no_rs_blocks = []
for t in tasks:  # 1. auto-unblock candidates
    if t.get('status') == 'Blocked' and (t.get('blockedBy') or []) and blockers_terminal(t):
        tid = str(t['taskId'])
        rs = last_resume_status(t)
        if rs is not None and rs in blocked_transitions:
            acts.append(('unblock', tid, rs))
        else:
            if rs is not None:
                print("dispatch: warning — %s has invalid resume-status '%s' "
                      "(not a legal transition from Blocked; legal: %s)"
                      % (tid, rs, ', '.join(sorted(blocked_transitions))), file=sys.stderr)
            no_rs_blocks.append(tid)
            acts.append(('unblock-no-rs', tid, rs or ''))

# warn on unknown blockedBy references
for t in tasks:
    tid = str(t['taskId'])
    for b in (t.get('blockedBy') or []):
        if str(b) not in by_id:
            print("dispatch: warning — %s blockedBy references unknown [task] '%s' "
                  "(never auto-unblocked; check the tracker relation)" % (tid, b),
                  file=sys.stderr)

design_q = [str(t['taskId']) for t in tasks
            if last(t, 'design-note') > last(t, 'design-approved', 'design-pushback')]
review_q, arch_q, merge_q, anomalies = [], [], [], []
for t in tasks:
    if t.get('status') != 'Review':
        continue
    tid, req = str(t['taskId']), last(t, 'review-request')
    if req == -1:
        anomalies.append(tid)
        continue
    ra, aa = last(t, 'review-approval'), last(t, 'architecture-approval')
    if ra > req and aa > req:
        if protocol_reviewer:
            ra_body = ((t.get('comments') or [])[ra]).get('body') or ''
            sig = _re.search(r'—\s*([\w-]+)(?:\s*\((?:posted by[^)]*|as [^)]+)\))?\s*$', ra_body.strip())
            signer = sig.group(1) if sig else None
            if signer == protocol_reviewer:
                merge_q.append(tid)
            else:
                anomalies.append(tid)
                print("dispatch: warning — %s [review-approval] signed by '%s', expected preset "
                      "final gate '%s' — routing to team-lead" % (tid, signer, protocol_reviewer),
                      file=sys.stderr)
        else:
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
if planned or stale or anomalies or no_rs_blocks:
    detail = ('Lead-actionable — dispatchable [Planned]: %s; stale heartbeats: %s'
              % (', '.join(planned) or 'none', ', '.join(stale) or 'none'))
    if anomalies:
        detail += '; anomalous [Review] without [review-request]: %s' % ', '.join(anomalies)
    if no_rs_blocks:
        detail += ('; blocked/terminal-but-no-resume-status (add resume-status: <Status>'
                   ' to the block comment): %s' % ', '.join(no_rs_blocks))
    acts.append(('launch', 'team-lead', detail + '. One supervision pass, then exit.'))

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
            echo "plan: unblock $arg → [$detail] (all blockers terminal)"
            if [ "$dry" != "yes" ]; then
              "$SKILL_DIR/bin/tracker-ops.sh" state "$arg" "$detail"
              printf 'Auto-unblocked by dispatcher: every blocking [task] reached the terminal status. Resuming to [%s].\n\n— dispatcher (on behalf of team-lead)\n' "$detail" \
                | "$SKILL_DIR/bin/tracker-ops.sh" comment "$arg" -
            fi ;;
          *) die "unknown --unblock mode '$unblock'" ;;
        esac ;;
      unblock-no-rs)
        echo "plan: unblock $arg — NO RESUME STATUS (lead must resume; add 'resume-status: <Status>' to the block comment)" ;;
      launch)
        local concrete; concrete="$(resolve_role "$team" "$arg")"
        local _ck; _ck="$(role_cmd_key "$concrete")"
        if key_is_null "$_ck"; then
          echo "plan: launch $arg (→$concrete) — skipped (${_ck}=null; the team-lead routes this queue)"
        elif role_live "$team" "$concrete"; then
          echo "plan: launch $arg (→$concrete) — skipped (live instance)"
        else
          echo "plan: launch $arg (→$concrete) ($detail)"
          if [ "$dry" != "yes" ]; then
            local mf; mf="$(next_mailbox_file "$dir/mailbox/$concrete")"
            printf 'From: dispatcher\nRe: %s\n---\n%s\n' "$fid" "$detail" > "$mf"
            "$SKILL_DIR/bin/launch-team.sh" start "$team" "$fid" "$concrete"
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
