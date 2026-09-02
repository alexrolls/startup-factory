#!/usr/bin/env bash
# dispatch.sh — one deterministic read-and-act pass (or a loop of them).
# Zero LLM per cycle. Logic spec: reference/dispatch.md.
#
# Usage:
#   dispatch.sh <team> <featureId> --once [--dry-run] [--task <taskId>]
#   dispatch.sh <team> <featureId> --watch
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$SKILL_DIR/config/team.config.md"
PM_CONFIG="$SKILL_DIR/config/project-management.config.md"
REPO_ROOT="$(git rev-parse --show-toplevel)"

STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON="$(python3 - \
  "$SKILL_DIR/config/automation.config.json" \
  "${STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON-}" <<'PY'
import json,sys
config_path,override=sys.argv[1:]
if override:
    try: value=json.loads(override)
    except ValueError: raise SystemExit("dispatch: ignored-label policy override is invalid JSON")
else:
    value=json.load(open(config_path)).get("ignoredTaskLabels", ["human-work"])
if not isinstance(value,list) or any(not isinstance(item,str) or not item.strip() or item!=item.strip() for item in value):
    raise SystemExit("dispatch: ignored-label policy must be a JSON array of canonical strings")
canonical=[item.casefold() for item in value]
if len(canonical)!=len(set(canonical)):
    raise SystemExit("dispatch: ignored-label policy contains a case-insensitive duplicate")
print(json.dumps(value,separators=(",",":")))
PY
)"
export STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON

die() { echo "dispatch: $*" >&2; exit 1; }

validate_team_id() {
  case "$1" in
    ''|*[!a-zA-Z0-9._-]*) die "unsafe team/feature-branch identifier '$1'" ;;
  esac
  [ "${#1}" -le 63 ] || die "team/feature-branch identifier is longer than 63 characters"
}

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

trusted_team_preset() { # team feature -> protected preset identity, or empty for a manual team
  local dir pf context probe_rc=0
  dir="$(teamroot "$1")" || return $?
  pf="$(team_path "$dir" preset.env)" || return $?
  if [ ! -f "$pf" ]; then
    python3 "$SKILL_DIR/bin/team-context.py" probe \
      --repo "$REPO_ROOT" --workspace "$dir" --team "$1" --feature "$2" >/dev/null \
      || probe_rc=$?
    [ "$probe_rc" -eq 3 ] && return 0
    [ "$probe_rc" -eq 0 ] || return "$probe_rc"
  fi
  context="$(python3 "$SKILL_DIR/bin/team-context.py" verify \
    --repo "$REPO_ROOT" --workspace "$dir" --team "$1" --feature "$2" \
    --skill "$SKILL_DIR")" || return $?
  python3 -c 'import json,sys; value=json.load(sys.stdin)["preset"]; print("" if value=="-" else value,end="")' <<< "$context"
}

resolve_role() { # resolve_role <team> <feature> <protocol-role> -> concrete role
  local preset
  preset="$(trusted_team_preset "$1" "$2")" || return $?
  [ -n "$preset" ] || { printf '%s' "$3"; return; }
  python3 - "$SKILL_DIR/teams" "$preset" "$3" <<'PY'
import re,stat,sys
from pathlib import Path

teams_dir, preset, protocol_role = map(Path, sys.argv[1:])

def assignments(text):
    values = {}
    for line in text.splitlines():
        if "=" not in line: continue
        key, value = line.split("=", 1)
        if key in values: raise SystemExit(f"dispatch: team preset repeats {key}")
        values[key] = value.strip()
    return values

source_path = Path(teams_dir) / f"{preset}.md"
source_info = source_path.lstat()
if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISREG(source_info.st_mode):
    raise SystemExit("dispatch: protected team preset is unsafe")
source = assignments(source_path.read_text(encoding="utf-8"))
key = "PROTOCOL_" + str(protocol_role).upper().replace("-", "_")
expected = source.get(key)
if expected is None:
    print(protocol_role, end="")
else:
    print(expected, end="")
PY
}

teamroot() {
  validate_team_id "$1"
  local root; root="$(read_key TEAMWORK_ROOT)"; root="${root:-.teamwork}"
  python3 "$SKILL_DIR/bin/teamwork-path.py" workspace \
    --repo "$REPO_ROOT" --root "$root" --team "$1"
}

team_path() { # team_path <absolute-workspace> <relative-path>
  python3 "$SKILL_DIR/bin/teamwork-path.py" child \
    --repo "$REPO_ROOT" --workspace "$1" --relative "$2"
}

role_live() { # role_live <team> <role> -> 0 if a live instance exists
  local rc
  if "$SKILL_DIR/bin/launch-team.sh" live-role "$1" "$2" >/dev/null; then
    return 0
  else
    rc=$?
  fi
  [ "$rc" -eq 3 ] && return 1
  die "protected lifecycle lookup failed for role $2 (workspace PID markers are never authority)"
}

task_live() { # task_live <team> <role> <taskId> <attempt>
  local rc
  if "$SKILL_DIR/bin/launch-team.sh" live-task "$1" "$2" "$3" "$4" >/dev/null; then
    return 0
  else
    rc=$?
  fi
  [ "$rc" -eq 3 ] && return 1
  die "protected lifecycle lookup failed for task $3 (workspace PID markers are never authority)"
}

task_any_live() { # task_any_live <team> <taskId> -> any role/attempt process for task
  local rc
  if "$SKILL_DIR/bin/launch-team.sh" live-task-any "$1" "$2" >/dev/null; then
    return 0
  else
    rc=$?
  fi
  [ "$rc" -eq 3 ] && return 1
  die "protected lifecycle lookup failed for task $2 (workspace PID markers are never authority)"
}

stop_task_or_quarantine() { # <team> <workspace> <taskId>
  local stop_team="$1" stop_workspace="$2" stop_task="$3"
  if "$SKILL_DIR/bin/launch-team.sh" stop-task "$stop_team" "$stop_task"; then
    return 0
  fi
  echo "dispatch: task $stop_task could not be fully signaled; revoking publication authority and continuing isolated work" >&2
  python3 "$SKILL_DIR/bin/outbox_capability.py" revoke-task \
    --repo "$REPO_ROOT" --workspace "$stop_workspace" --team "$stop_team" --task "$stop_task" >/dev/null \
    || die "task $stop_task stop failed and publication authority could not be revoked"
}

process_worker_controls() { # team feature workspace tasks-snapshot
  local control_team="$1" control_feature="$2" control_workspace="$3" control_tasks="$4"
  local pending lifecycle_root entries
  pending="$(team_path "$control_workspace" control-outbox/pending)"
  [ -d "$pending" ] || return 0
  entries="$(find "$pending" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null || true)"
  [ -n "$entries" ] || return 0
  lifecycle_root="${STARTUP_FACTORY_LIFECYCLE_STATE_ROOT:-$(read_key BROKER_LIFECYCLE_ROOT)}"
  [ -n "$lifecycle_root" ] \
    || die "authenticated worker-control request is pending but protected lifecycle supervision is disabled"
  python3 "$SKILL_DIR/bin/worker-control.py" reconcile \
    --repo "$REPO_ROOT" --workspace "$control_workspace" --team "$control_team" \
    --feature "$control_feature" --tasks "$control_tasks" \
    --launcher "$SKILL_DIR/bin/launch-team.sh" --lifecycle-root "$lifecycle_root" \
    || die "worker-control reconciliation failed"
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

recover_team_lead_if_stalled() { # team feature workspace lifecycle-root health-json dry
  local control_team="$1" control_feature="$2" control_workspace="$3" lifecycle_root="$4" health_json="$5" dry="$6"
  local lead_role row verdict generation control_id output
  lead_role="$(resolve_role "$control_team" "$control_feature" team-lead)" || die "could not resolve protected Team Lead mapping"
  row="$(python3 - "$health_json" "$lead_role" <<'PY'
import json,sys
rows=json.loads(sys.argv[1]); role=sys.argv[2]
matches=[item for item in rows if item.get("category")=="gate" and item.get("instance")==role]
if len(matches)>1: raise SystemExit("dispatch: duplicate protected Team Lead lifecycle identity")
if matches:
    item=matches[0]
    print(str(item.get("verdict") or "")+"\t"+str(item.get("createdAt") or ""))
PY
  )" || die "could not inspect authenticated Team Lead health"
  [ -n "$row" ] || return 0
  IFS=$'\t' read -r verdict generation <<< "$row"
  # Gate roles are one-shot queue consumers. A normal exited generation is
  # desired idle state and is relaunched only by a concrete dispatch-plan queue
  # action. Automatic restart authority is reserved for a live, wedged Team
  # Lead; the ordinary start path then observes it as live and cannot bypass a
  # suppressed restart policy decision.
  case "$verdict" in stalled:*) ;; *) return 0 ;; esac
  [ -n "$generation" ] || die "stalled Team Lead health lacks a lifecycle generation"
  control_id="control-$(python3 -c 'import hashlib,sys; print(hashlib.sha256("\0".join(sys.argv[1:]).encode()).hexdigest()[:32])' "$control_team" "$control_feature" "$lead_role" "$generation" automatic-lead-recovery)"
  echo "plan: recover stalled Team Lead $lead_role ($verdict)"
  [ "$dry" != yes ] || return 0
  python3 "$SKILL_DIR/bin/control-grant.py" issue \
    --root "$lifecycle_root" --repo "$REPO_ROOT" \
    --team "$control_team" --feature "$control_feature" --action restart-role --target "$lead_role" \
    --attempt 0 --generation "$generation" --control-id "$control_id" --reason automatic \
    >/dev/null || die "could not issue protected Team Lead recovery grant"
  if output="$(STARTUP_FACTORY_CONTROL_BROKER=1 STARTUP_FACTORY_CONTROL_REASON=automatic \
      "$SKILL_DIR/bin/launch-team.sh" restart-role "$control_team" "$control_feature" \
      "$lead_role" "$generation" "$control_id" 2>&1)"; then
    printf '%s\n' "$output"
    TEAM_LEAD_RECOVERED=yes
    return 0
  fi
  # A stalled role is not a trustworthy recipient for its own recovery
  # escalation. Keep this in the dispatcher/operator log; do not create a
  # mailbox item that can be silently stranded behind the wedged generation.
  echo "dispatch: automatic Team Lead recovery was suppressed: $output" >&2
  echo "dispatch: inspect protected lifecycle/restart-policy records; human intervention is required" >&2
}

working_feature_status() {
  python3 - "$SKILL_DIR/config/statuses.config.json" <<'PY'
import json,sys
board=json.load(open(sys.argv[1]))
matches=[str(item.get("name")) for item in board.get("features",{}).get("statuses",[]) if item.get("kind")=="working"]
if len(matches) != 1:
    raise SystemExit("dispatch: feature status kind 'working' must resolve to exactly one status")
print(matches[0])
PY
}

task_status_names() {
  python3 - "$SKILL_DIR/config/statuses.config.json" <<'PY'
import json,sys
board=json.load(open(sys.argv[1]))
by_kind={}
for item in board.get("tasks",{}).get("statuses",[]):
    kind=item.get("kind")
    if kind:
        by_kind.setdefault(kind,[]).append(str(item.get("name")))
for kind in ("queued","blocked","working","review"):
    values=by_kind.get(kind,[])
    if len(values)!=1:
        raise SystemExit("dispatch: task status kind %r must resolve exactly once" % kind)
    print(values[0])
PY
}

claim_id_for() { # team feature task role attempt target -> deterministic bounded id
  python3 - "$@" <<'PY'
import hashlib,sys
team,feature,task,role,attempt,target=sys.argv[1:]
print("dispatch-" + hashlib.sha256("\0".join(
    (team,feature,task,role,attempt,target)
).encode()).hexdigest()[:32])
PY
}

dispatch_once() { # dispatch_once <team> <featureId> <dry:yes|no> [target-task]
  local team="$1" fid="$2" dry="$3" target_task="${4:-}"
  local dir lock tasks_file; dir="$(teamroot "$team")"
  lock="$(team_path "$dir" dispatch.lock)"
  tasks_file="$(team_path "$dir" tasks.json)"
  # The planner reads these children directly; validate their entire lexical
  # path before it can observe a forged cross-team/external symlink.
  team_path "$dir" preset.env >/dev/null
  team_path "$dir" product-acceptance-request.json >/dev/null
  team_path "$dir" heartbeats >/dev/null
  team_path "$dir" executions >/dev/null
  team_path "$dir" claims >/dev/null
  local _a; _a="$(grep -m1 '^PRODUCT_MANAGEMENT_TOOL=' "$PM_CONFIG" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
  local adapter="${TRACKER_ADAPTER:-$_a}"
  if is_mcp_only "$adapter"; then
    die "dispatch requires scriptable tracker access — $adapter is configured for MCP-only.
  Set the scriptable option in config/project-management.config.md or use harness mode."
  fi
  mkdir -p "$dir"
  if ! mkdir "$lock" 2>/dev/null; then
    local owner="" entries
    [ -f "$lock/owner.pid" ] && owner="$(cat "$lock/owner.pid" 2>/dev/null || true)"
    entries="$(find "$lock" -mindepth 1 -maxdepth 1 -print 2>/dev/null || true)"
    if [ -n "$owner" ] && case "$owner" in *[!0-9]*) false ;; *) ! kill -0 "$owner" 2>/dev/null ;; esac \
       && [ "$entries" = "$lock/owner.pid" ]; then
      rm -f "$lock/owner.pid"
      rmdir "$lock"
      mkdir "$lock" || { echo "dispatch: lost stale-lock recovery race; skipping"; return 0; }
    else
      echo "dispatch: another pass owns $lock; skipping"
      return 0
    fi
  fi
  printf '%s\n' "$$" > "$lock/owner.pid"
  trap 'rm -f "$lock/owner.pid"; rmdir "$lock" 2>/dev/null || true' RETURN
  local status_fields queued_status blocked_status working_status review_status
  status_fields="$(task_status_names)"
  queued_status="$(printf '%s\n' "$status_fields" | sed -n '1p')"
  blocked_status="$(printf '%s\n' "$status_fields" | sed -n '2p')"
  working_status="$(printf '%s\n' "$status_fields" | sed -n '3p')"
  review_status="$(printf '%s\n' "$status_fields" | sed -n '4p')"

  # Holds must observe the complete authoritative feature, including work that
  # is reserved from autonomous claiming with an ignored label.
  env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
    "$SKILL_DIR/bin/tracker-ops.sh" export "$fid" "$tasks_file" >/dev/null
  if [ "$dry" != "yes" ]; then
    local hold_result hold_actions hold_action hold_task hold_graph changed=no
    hold_result="$(python3 "$SKILL_DIR/bin/task-hold.py" sync \
      --repo "$REPO_ROOT" --workspace "$dir" --tasks "$tasks_file" --feature "$fid" --team "$team" \
      --blocked-status "$blocked_status" --queued-status "$queued_status" \
      --inflight-status "$queued_status" --inflight-status "$working_status" --inflight-status "$review_status" \
      --ignored-labels-json "${STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON:-[]}")"
    hold_actions="$(python3 - "$hold_result" <<'PY'
import json,sys
value=json.loads(sys.argv[1])
for task in value.get("stopTasks",[]):
    print("stop\t%s\t" % task)
for item in value.get("blockDependents",[]):
    print("block\t%s\t%s" % (item["taskId"],item["graphDigest"]))
PY
)"
    while IFS="$(printf '\t')" read -r hold_action hold_task hold_graph; do
      [ -n "$hold_action" ] || continue
      case "$hold_action" in
        stop)
          echo "dispatch: stopping task-scoped workers for human-held $hold_task"
          stop_task_or_quarantine "$team" "$dir" "$hold_task"
          ;;
        block)
          # The team-lead verdict is advisory until the broker re-exports the
          # exact graph and authenticated marker immediately before mutation.
          env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
            "$SKILL_DIR/bin/tracker-ops.sh" export "$fid" "$tasks_file" >/dev/null
          python3 "$SKILL_DIR/bin/task-hold.py" validate-dependent \
            --repo "$REPO_ROOT" --workspace "$dir" --tasks "$tasks_file" --feature "$fid" --team "$team" \
            --task "$hold_task" --graph-digest "$hold_graph" \
            --blocked-status "$blocked_status" \
            --inflight-status "$queued_status" --inflight-status "$working_status" --inflight-status "$review_status" \
            --ignored-labels-json "$STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON" >/dev/null
          echo "dispatch: lead-confirmed dependency prevents $hold_task; moving it to [$blocked_status]"
          env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
            "$SKILL_DIR/bin/tracker-ops.sh" state "$hold_task" "$blocked_status"
          # Make the durable hold visible to every broker before attempting to
          # signal the worker. Even if process termination later fails closed,
          # no publication or integration can pass this registry/status fence.
          env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
            "$SKILL_DIR/bin/tracker-ops.sh" export "$fid" "$tasks_file" >/dev/null
          python3 "$SKILL_DIR/bin/task-hold.py" sync \
            --repo "$REPO_ROOT" --workspace "$dir" --tasks "$tasks_file" --feature "$fid" --team "$team" \
            --blocked-status "$blocked_status" --queued-status "$queued_status" \
            --inflight-status "$queued_status" --inflight-status "$working_status" --inflight-status "$review_status" \
            --ignored-labels-json "${STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON:-[]}" >/dev/null
          stop_task_or_quarantine "$team" "$dir" "$hold_task"
          changed=yes
          ;;
        *) die "task-hold returned unknown action '$hold_action'" ;;
      esac
    done <<EOF
$hold_actions
EOF
    if [ "$changed" = "yes" ]; then
      env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
        "$SKILL_DIR/bin/tracker-ops.sh" export "$fid" "$tasks_file" >/dev/null
      python3 "$SKILL_DIR/bin/task-hold.py" sync \
        --repo "$REPO_ROOT" --workspace "$dir" --tasks "$tasks_file" --feature "$fid" --team "$team" \
        --blocked-status "$blocked_status" --queued-status "$queued_status" \
        --inflight-status "$queued_status" --inflight-status "$working_status" --inflight-status "$review_status" \
        --ignored-labels-json "${STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON:-[]}" >/dev/null
    fi

    # Only after task-scoped stops and durable holds are established may the
    # credentialed brokers publish artifacts or finalize integration evidence.
    "$SKILL_DIR/bin/finalize-integrations.sh" "$team" "$fid"
    "$SKILL_DIR/bin/process-outbox.sh" "$team" "$fid"
    env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
      "$SKILL_DIR/bin/tracker-ops.sh" export "$fid" "$tasks_file" >/dev/null

    # Close the observation race created by broker/finalizer work. If a human
    # moved a task to Blocked or reserved it with an ignored label during this
    # pass, establish the hold and stop that exact task before planning returns.
    hold_result="$(python3 "$SKILL_DIR/bin/task-hold.py" sync \
      --repo "$REPO_ROOT" --workspace "$dir" --tasks "$tasks_file" --feature "$fid" --team "$team" \
      --blocked-status "$blocked_status" --queued-status "$queued_status" \
      --inflight-status "$queued_status" --inflight-status "$working_status" --inflight-status "$review_status" \
      --ignored-labels-json "${STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON:-[]}")"
    while IFS= read -r hold_task; do
      [ -n "$hold_task" ] || continue
      echo "dispatch: final authority fence stopping task-scoped workers for $hold_task"
      stop_task_or_quarantine "$team" "$dir" "$hold_task"
    done <<EOF
$(python3 -c 'import json,sys; [print(item) for item in json.loads(sys.argv[1]).get("stopTasks", [])]' "$hold_result")
EOF
    process_worker_controls "$team" "$fid" "$dir" "$tasks_file"
  fi
  if [ "$dry" != "yes" ]; then
    "$SKILL_DIR/bin/sync-progress.sh" "$team" "$fid" "$tasks_file"
  fi
  local stuck; stuck="$(read_key STUCK_AFTER_MINUTES)"; stuck="${stuck:-15}"
  local execution max_active plan health_json lifecycle_root trusted_preset
  execution="$(read_key EXECUTION)"; execution="${execution:-sequential}"
  max_active="$(read_key MAX_ACTIVE_IMPLEMENTERS)"
  trusted_preset="$(trusted_team_preset "$team" "$fid")" \
    || die "could not verify protected team preset authority"
  health_json="[]"
  lifecycle_root="${STARTUP_FACTORY_LIFECYCLE_STATE_ROOT:-$(read_key BROKER_LIFECYCLE_ROOT)}"
  if [ -n "$lifecycle_root" ]; then
    health_json="$("$SKILL_DIR/bin/launch-team.sh" status "$team" --json | python3 -c 'import json,sys; print(json.dumps([json.loads(line) for line in sys.stdin if line.strip()],separators=(",",":")))')" \
      || die "could not build authenticated worker-health snapshot"
    TEAM_LEAD_RECOVERED=no
    recover_team_lead_if_stalled "$team" "$fid" "$dir" "$lifecycle_root" "$health_json" "$dry"
    if [ "$TEAM_LEAD_RECOVERED" = yes ]; then
      health_json="$("$SKILL_DIR/bin/launch-team.sh" status "$team" --json | python3 -c 'import json,sys; print(json.dumps([json.loads(line) for line in sys.stdin if line.strip()],separators=(",",":")))')" \
        || die "could not refresh authenticated worker-health after Team Lead recovery"
    fi
  fi
  local planner_args=(--skill "$SKILL_DIR" --workdir "$dir" --team "$team" --feature "$fid" --stuck-minutes "$stuck" --execution "$execution")
  [ -z "$trusted_preset" ] || planner_args+=(--preset "$trusted_preset")
  planner_args+=(--health-json "$health_json")
  [ -z "$max_active" ] || planner_args+=(--max-active "$max_active")
  [ -z "$target_task" ] || planner_args+=(--task "$target_task")
  planner_args+=(--ignored-labels-json "${STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON:-[]}")
  plan="$(python3 "$SKILL_DIR/bin/dispatch-plan.py" "${planner_args[@]}")"
  if [ -z "$plan" ]; then echo "dispatch: nothing actionable"; return 0; fi
  local action arg detail extra
  while IFS="$(printf '\t')" read -r action arg detail extra; do
    case "$action" in
      blocked-hold)
        echo "plan: keep $arg [Blocked] — human-held; Startup Factory cannot move it outbound" ;;
      launch)
        local concrete; concrete="$(resolve_role "$team" "$fid" "$arg")" || die "could not resolve protected role mapping"
        local _ck; _ck="$(role_cmd_key "$concrete")"
        if key_is_null "$_ck"; then
          echo "plan: launch $arg (→$concrete) — skipped (${_ck}=null; the team-lead routes this queue)"
        elif role_live "$team" "$concrete"; then
          echo "plan: launch $arg (→$concrete) — skipped (live instance)"
        else
          echo "plan: launch $arg (→$concrete) ($detail)"
          if [ "$dry" != "yes" ]; then
            if [ -n "$extra" ]; then
              local packages="" task_id package
              local _old_ifs="$IFS"; IFS='|'
              for task_id in $extra; do
                package="$("$SKILL_DIR/bin/review-package.sh" "$team" "$task_id" 2>/dev/null || true)"
                [ -z "$package" ] || packages="$packages $task_id=$package"
              done
              IFS="$_old_ifs"
              [ -z "$packages" ] || detail="$detail Review packages:$packages"
            fi
            local mailbox mf
            mailbox="$(team_path "$dir" "mailbox/$concrete")"
            mf="$(next_mailbox_file "$mailbox")"
            printf 'From: dispatcher\nRe: %s\n---\n%s\n' "$fid" "$detail" > "$mf"
            "$SKILL_DIR/bin/launch-team.sh" start "$team" "$fid" "$concrete"
          fi
        fi ;;
      claim-task)
        local claim_role; claim_role="$(resolve_role "$team" "$fid" "$arg")" || die "could not resolve protected claim role"
        if task_live "$team" "$claim_role" "$detail" "$extra"; then
          echo "plan: claim $detail for $claim_role - skipped (live task instance)"
        else
          echo "plan: claim $detail for $claim_role (attempt $extra)"
          if [ "$dry" != "yes" ]; then
            local claim_id claim_target
            claim_target="$(python3 - "$SKILL_DIR/config/statuses.config.json" <<'PY'
import json,sys
board=json.load(open(sys.argv[1]))
matches=[str(s.get("name")) for s in board["tasks"]["statuses"] if s.get("kind")=="working"]
if len(matches)!=1: raise SystemExit("dispatch: task working status must resolve exactly once")
print(matches[0])
PY
            )"
            claim_id="$(claim_id_for "$team" "$fid" "$detail" "$claim_role" "$extra" "$claim_target")"
            env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
              "$SKILL_DIR/bin/tracker-ops.sh" export "$fid" "$tasks_file" >/dev/null
            python3 - "$tasks_file" "$detail" "$queued_status" \
              "${STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON:-[]}" <<'PY'
import json,sys
path,task_id,queued,ignored_raw=sys.argv[1:]
payload=json.load(open(path)); tasks=payload.get("tasks")
if not isinstance(tasks,list): raise SystemExit("dispatch: fresh claim snapshot is malformed")
matches=[item for item in tasks if isinstance(item,dict) and str(item.get("taskId"))==task_id]
if len(matches)!=1: raise SystemExit("dispatch: claim task is absent or duplicated in fresh snapshot")
task=matches[0]
if task.get("status")!=queued: raise SystemExit("dispatch: claim task is no longer queued")
try: ignored=json.loads(ignored_raw)
except ValueError: raise SystemExit("dispatch: ignored-label policy is invalid JSON")
if not isinstance(ignored,list) or any(not isinstance(item,str) or not item.strip() for item in ignored):
    raise SystemExit("dispatch: ignored-label policy must be a JSON string array")
labels=task.get("labels") or []
if not isinstance(labels,list) or any(not isinstance(item,str) for item in labels):
    raise SystemExit("dispatch: fresh claim task labels are malformed")
if {item.strip().casefold() for item in ignored}.intersection(item.strip().casefold() for item in labels):
    raise SystemExit("dispatch: claim task became human-owned; no claim or launch")
PY
            local claim_authority_args=(authorize-claim --repo "$REPO_ROOT" \
              --workspace "$dir" --team "$team" --feature "$fid" --tasks "$tasks_file" \
              --task "$detail" --queued-status "$queued_status" --blocked-status "$blocked_status")
            while IFS= read -r terminal_status; do
              claim_authority_args+=(--terminal-status "$terminal_status")
            done < <(python3 - "$SKILL_DIR/config/statuses.config.json" <<'PY'
import json,sys
board=json.load(open(sys.argv[1]))
for status in board["tasks"]["statuses"]:
    if status.get("terminal"): print(status["name"])
PY
)
            python3 "$SKILL_DIR/bin/task-hold.py" "${claim_authority_args[@]}" >/dev/null
            "$SKILL_DIR/bin/tracker-ops.sh" claim "$detail" "$claim_role" --to "$claim_target" --claim-id "$claim_id"
            # Persist the local identity only after the tracker claim succeeds;
            # a failed remote claim can never leave a stale local claim record.
            python3 "$SKILL_DIR/bin/runtime-state.py" claim --workspace "$dir" \
              --team "$team" --feature "$fid" --task "$detail" --role "$claim_role" \
              --attempt "$extra" --claim-id "$claim_id" --target "$claim_target" >/dev/null
            # Keep the feature lifecycle deterministic: the first successful
            # task claim also advances a queued feature into its working state.
            "$SKILL_DIR/bin/tracker-ops.sh" feature-state "$fid" "$(working_feature_status)"
            "$SKILL_DIR/bin/runtime-event.sh" "$team" "$fid" "$detail" "$extra" "$claim_role" task.claimed claimed "task claimed by deterministic dispatcher" >/dev/null
            "$SKILL_DIR/bin/launch-team.sh" start-task "$team" "$fid" "$claim_role" "$detail" "$extra"
          fi
        fi ;;
      launch-task)
        local task_role; task_role="$(resolve_role "$team" "$fid" "$arg")" || die "could not resolve protected task role"
        if task_any_live "$team" "$detail"; then
          echo "plan: launch task $detail as $task_role - skipped (another task attempt is live)"
        else
          echo "plan: launch task $detail as $task_role (attempt $extra)"
          if [ "$dry" != "yes" ]; then
            "$SKILL_DIR/bin/launch-team.sh" start-task "$team" "$fid" "$task_role" "$detail" "$extra"
          fi
        fi ;;
      recover-task)
        local recover_role control_id recover_key recover_instance lifecycle_row lifecycle_state lifecycle_generation
        recover_role="$(resolve_role "$team" "$fid" "$arg")" || die "could not resolve protected recovery role"
        if task_any_live "$team" "$detail"; then
          echo "plan: recover task $detail as $recover_role - deferred (live instance; Team Lead authorization required)"
        else
          control_id="control-$(python3 -c 'import hashlib,sys; print(hashlib.sha256("\0".join(sys.argv[1:]).encode()).hexdigest()[:32])' "$team" "$fid" "$detail" "$extra" dead-worker)"
          recover_key="$(python3 "$SKILL_DIR/bin/runtime-state.py" key "$detail")"
          recover_instance="$recover_role--$recover_key--a$extra"
          lifecycle_row="$(python3 "$SKILL_DIR/bin/process-lifecycle.py" list \
            --root "$lifecycle_root" --repo "$REPO_ROOT" --team "$team" | \
            python3 -c 'import json,sys; target=sys.argv[1]; rows=[json.loads(line) for line in sys.stdin if line.strip()]; matches=[r for r in rows if r.get("category")=="task" and r.get("instance")==target];
assert len(matches)<=1, "duplicate lifecycle identities";
print((matches[0]["state"]+"\t"+matches[0]["createdAt"]) if matches else "absent\t-")' "$recover_instance")" \
            || die "could not authenticate dead-worker lifecycle generation"
          IFS=$'\t' read -r lifecycle_state lifecycle_generation <<< "$lifecycle_row"
          if [ "$lifecycle_state" = live ]; then
            echo "plan: recover task $detail as $recover_role - deferred (a replacement became live)"
            continue
          fi
          [ "$lifecycle_state" != identity-mismatch ] \
            || die "automatic recovery refused an identity-mismatched lifecycle record for $detail"
          echo "plan: recover exited task $detail as $recover_role (attempt $extra -> $((extra + 1)))"
          if [ "$dry" != "yes" ]; then
            python3 "$SKILL_DIR/bin/control-grant.py" issue \
              --root "$lifecycle_root" --repo "$REPO_ROOT" \
              --team "$team" --feature "$fid" --action restart-task --target "$detail" \
              --attempt "$extra" --generation "$lifecycle_generation" --control-id "$control_id" --reason automatic \
              >/dev/null || die "could not issue protected automatic-recovery grant"
            if recovery_output="$(STARTUP_FACTORY_CONTROL_BROKER=1 STARTUP_FACTORY_CONTROL_REASON=automatic \
                STARTUP_FACTORY_EXPECTED_LIFECYCLE_CREATED_AT="$lifecycle_generation" \
                "$SKILL_DIR/bin/launch-team.sh" restart-task \
                "$team" "$fid" "$detail" "$extra" "$control_id" 2>&1)"; then
              printf '%s\n' "$recovery_output"
            else
              local lead_mailbox lead_message
              lead_mailbox="$(team_path "$dir" mailbox/team-lead)"
              lead_message="$(next_mailbox_file "$lead_mailbox")"
              {
                echo "From: dispatcher"
                echo "Re: $detail"
                echo "---"
                echo "Automatic dead-worker recovery was suppressed: $recovery_output"
                echo "Inspect protected status and restart policy; authorize a bounded recovery or escalate."
              } > "$lead_message"
              echo "plan: automatic recovery for $detail suppressed; Team Lead review queued" >&2
            fi
          fi
        fi ;;
    esac
  done <<EOF
$plan
EOF
  # Record that a pass completed. Every role exiting is the normal end of a
  # pass, so this marker is the only evidence that separates a board nobody is
  # driving from one that simply finished its work.
  if [ "$dry" = "no" ]; then
    printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      > "$(team_path "$dir" dispatch.last-pass)" 2>/dev/null || true
  fi
}

[ $# -ge 3 ] || die "usage: dispatch.sh <team> <featureId> --once|--watch [--dry-run] [--task <taskId>]"
TEAM="$1"; FID="$2"; MODE="$3"; shift 3
DRY=no
TARGET_TASK=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=yes ;;
    --task)
      [ $# -ge 2 ] || die "--task requires one taskId"
      [ -z "$TARGET_TASK" ] || die "--task may be specified only once"
      TARGET_TASK="$2"
      shift ;;
    --task=*)
      [ -z "$TARGET_TASK" ] || die "--task may be specified only once"
      TARGET_TASK="${1#--task=}"
      [ -n "$TARGET_TASK" ] || die "--task requires one taskId" ;;
    --unblock=auto|--unblock=suggest|--unblock=off)
      echo "dispatch: warning — $1 is deprecated and ignored; [Blocked] exits are human-only" >&2 ;;
    --unblock=*) die "unknown legacy unblock option $1" ;;
    *) die "unknown option $1" ;;
  esac
  shift
done
[ -z "$TARGET_TASK" ] || [ "$DRY" = yes ] \
  || die "--task is a read-only scope preview and requires --dry-run; execute one task with launch-team.sh start-task"
case "$MODE" in
  --once) dispatch_once "$TEAM" "$FID" "$DRY" "$TARGET_TASK" ;;
  --watch)
    [ "$DRY" = "no" ] || die "--watch does not combine with --dry-run"
    [ -z "$TARGET_TASK" ] || die "--watch does not combine with --task"
    INTERVAL="$(read_key POLL_INTERVAL_SECONDS)"; INTERVAL="${INTERVAL:-120}"
    echo "dispatch: watching (every ${INTERVAL}s) — this shell is the loop owner; keep it alive (tmux/nohup)"
    while true; do
      before="$(python3 "$SKILL_DIR/bin/runtime-state.py" count --workspace "$(teamroot "$TEAM")")"
      dispatch_once "$TEAM" "$FID" no || echo "dispatch: pass failed — retrying next interval" >&2
      after="$(python3 "$SKILL_DIR/bin/runtime-state.py" count --workspace "$(teamroot "$TEAM")")"
      [ "$after" != "$before" ] && continue
      python3 "$SKILL_DIR/bin/runtime-state.py" wait --workspace "$(teamroot "$TEAM")" --count "$after" --timeout "$INTERVAL" >/dev/null
    done ;;
  *) die "mode must be --once or --watch" ;;
esac
