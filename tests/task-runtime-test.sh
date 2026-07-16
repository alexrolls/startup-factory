#!/usr/bin/env bash
# Task-scoped runtime test: lean packets, model routing, events, outbox, and PM projection.
set -euo pipefail

if sed --version >/dev/null 2>&1; then
  sed_i() { sed -i "$@"; }
else
  sed_i() { sed -i '' "$@"; }
fi

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; TMP="$(cd "$TMP" && pwd -P)"; trap 'rm -rf "$TMP"' EXIT
FAILURES=0
check() { local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok: $desc"; else echo "FAIL: $desc"; FAILURES=$((FAILURES+1)); fi
}
refuse() { local desc="$1" needle="$2" output rc; shift 2
  set +e
  output="$("$@" 2>&1)"; rc=$?
  set -e
  if [ "$rc" -ne 0 ] && grep -qi -- "$needle" <<<"$output"; then
    echo "ok: $desc"
  else
    echo "FAIL: $desc (rc=$rc, output=$output)"; FAILURES=$((FAILURES+1))
  fi
}

cd "$TMP"; git init -q repo && cd repo
git config user.email test@example.com
git config user.name Test
git commit -q --allow-empty -m init; git checkout -q -b feature-runtime
LIFECYCLE_ROOT="$TMP/protected-lifecycle"
mkdir -m 700 "$LIFECYCLE_ROOT"
PROTECTED_FORGERY_ROOT="$TMP/protected-forgery-lifecycle"
mkdir -m 700 "$PROTECTED_FORGERY_ROOT"
python3 "$SKILL_DIR/bin/process-lifecycle.py" init --root "$LIFECYCLE_ROOT" --repo "$(pwd)" >/dev/null
python3 "$SKILL_DIR/bin/process-lifecycle.py" init --root "$PROTECTED_FORGERY_ROOT" --repo "$(pwd)" >/dev/null
export STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$LIFECYCLE_ROOT"
mkdir -p .agent-squad/{bin,config,roles,reference} feat
cp "$SKILL_DIR"/bin/*.sh "$SKILL_DIR"/bin/*.py .agent-squad/bin/
cp "$SKILL_DIR/config/statuses.config.json" "$SKILL_DIR/config/automation.config.json" \
  "$SKILL_DIR/config/planning.config.md" .agent-squad/config/
cp "$SKILL_DIR/roles/backend.md" "$SKILL_DIR/roles/reviewer.md" \
  "$SKILL_DIR/roles/sceptical-architect.md" "$SKILL_DIR/roles/team-lead.md" \
  "$SKILL_DIR/roles/senior-security-engineer.md" .agent-squad/roles/
cp "$SKILL_DIR/teams/roles/principal-software-architect.md" \
  "$SKILL_DIR/teams/roles/senior-technical-product-manager.md" .agent-squad/roles/
cp "$SKILL_DIR/reference/guardrails.md" "$SKILL_DIR/reference/orchestration.md" \
  "$SKILL_DIR/reference/superpowers-planning.md" .agent-squad/reference/
cat > .agent-squad/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Markdown
MARKDOWN_ROOT=.
STATUS_CONFIG=config/statuses.config.json
```
EOF
cat > .agent-squad/config/team.config.md <<'EOF'
```
BACKEND_CMD="false"
TASK_FAST_CMD="cat {prompt_file} > task-fast-prompt.txt"
TEAM_DEFAULT_CMD="false"
TEAMWORK_ROOT=.teamwork
AGENT_ENV_ALLOWLIST="PATH TMPDIR LANG LC_ALL TERM"
AGENT_SANDBOX_ENFORCED=false
BROKER_LIFECYCLE_ROOT=__LIFECYCLE_ROOT__
TRACKER_WRITERS=lead
EXECUTION=parallel
MAX_ACTIVE_IMPLEMENTERS=2
VALIDATE_BUILD=null
VALIDATE_TEST="true"
VALIDATE_LINT=null
VALIDATE_FORMAT=null
```
EOF
sed_i "s|^BROKER_LIFECYCLE_ROOT=.*|BROKER_LIFECYCLE_ROOT=\"$LIFECYCLE_ROOT\"|" .agent-squad/config/team.config.md
cat > feat/feature.md <<'EOF'
# Runtime fixture [Active]

## 1 Implement endpoint [Planned]

**Assignee:** -

track: backend
parallel-safe: true
files: src/endpoint.py
resources: api:endpoint
model-profile: fast

Implement the endpoint with tests.

> [design-note] round: 1
> Approach approved for the fixture.
>
> - backend

> [design-approved] round: 1
> 1. Endpoint behavior is tested.
>
> - principal-architect

> [sceptical-design-approved] round: 1
> assumptions: fixture scope and rollback are explicit.
>
> - sceptical-architect
EOF

LAUNCH=.agent-squad/bin/launch-team.sh
OPS=.agent-squad/bin/tracker-ops.sh
EVENT=.agent-squad/bin/runtime-event.sh
FID=feat/feature.md
TID="$FID#1"
key="$(python3 .agent-squad/bin/runtime-state.py key "$TID")"

# Every pre-integration entry point shares the same fail-closed workspace-root
# resolver. None may create state when TEAMWORK_ROOT is absolute.
cat > guard-body.md <<'EOF'
[review-request]
Path guard fixture.
EOF
CFG=.agent-squad/config/team.config.md
ABS_ROOT="$TMP/forbidden-teamwork-root"
sed_i "s|^TEAMWORK_ROOT=.*|TEAMWORK_ROOT=$ABS_ROOT|" "$CFG"
refuse "launcher rejects absolute TEAMWORK_ROOT" "TEAMWORK_ROOT" \
  "$LAUNCH" compose abs-root "$FID" backend
refuse "task packet rejects absolute TEAMWORK_ROOT" "TEAMWORK_ROOT" \
  .agent-squad/bin/task-packet.sh abs-root "$FID" "$TID" backend 1 "$(pwd)" agent-task/fixture
refuse "review package rejects absolute TEAMWORK_ROOT" "TEAMWORK_ROOT" \
  .agent-squad/bin/review-package.sh abs-root "$TID"
refuse "runtime event rejects absolute TEAMWORK_ROOT" "TEAMWORK_ROOT" \
  "$EVENT" abs-root "$FID" "$TID" 1 backend task.started implementing fixture
refuse "artifact submit rejects absolute TEAMWORK_ROOT" "TEAMWORK_ROOT" \
  .agent-squad/bin/submit-artifact.sh abs-root "$FID" "$TID" 1 backend review-request guard-body.md Review
refuse "outbox broker rejects absolute TEAMWORK_ROOT" "TEAMWORK_ROOT" \
  .agent-squad/bin/process-outbox.sh abs-root "$FID"
refuse "dispatcher rejects absolute TEAMWORK_ROOT" "TEAMWORK_ROOT" \
  .agent-squad/bin/dispatch.sh abs-root "$FID" --once --dry-run
refuse "progress sync rejects absolute TEAMWORK_ROOT" "TEAMWORK_ROOT" \
  .agent-squad/bin/sync-progress.sh abs-root "$FID" placeholder.json
refuse "integrator rejects absolute TEAMWORK_ROOT" "TEAMWORK_ROOT" \
  .agent-squad/bin/integrate-task.sh abs-root "$FID" "$TID" backend 1
refuse "integration broker rejects absolute TEAMWORK_ROOT" "TEAMWORK_ROOT" \
  .agent-squad/bin/finalize-integrations.sh abs-root "$FID"
check "absolute workspace guard creates no state" test ! -e "$ABS_ROOT"
sed_i 's|^TEAMWORK_ROOT=.*|TEAMWORK_ROOT=.teamwork|' "$CFG"

# Managed children are resolved too, so an attacker cannot pre-place a symlink
# beneath a valid team root and redirect a later mkdir/read/write.
PATH_ESCAPE="$TMP/path-escape"; mkdir -p "$PATH_ESCAPE"
mkdir -p .teamwork/{launch-escape,packet-escape,review-escape,event-escape,submit-escape,broker-escape,dispatch-escape,sync-escape,integrate-escape,finalize-escape}
ln -s "$PATH_ESCAPE" .teamwork/launch-escape/prompts
ln -s "$PATH_ESCAPE" .teamwork/packet-escape/artifacts
ln -s "$PATH_ESCAPE" .teamwork/review-escape/artifacts
ln -s "$PATH_ESCAPE/event.ndjson" .teamwork/event-escape/events.ndjson
ln -s "$PATH_ESCAPE" .teamwork/submit-escape/outbox
ln -s "$PATH_ESCAPE" .teamwork/broker-escape/outbox
ln -s "$PATH_ESCAPE" .teamwork/dispatch-escape/dispatch.lock
ln -s "$PATH_ESCAPE" .teamwork/sync-escape/pm
ln -s "$PATH_ESCAPE" .teamwork/integrate-escape/integrations
ln -s "$PATH_ESCAPE" .teamwork/finalize-escape/integrations
refuse "launcher rejects managed-child symlink escape" "workspace path" \
  "$LAUNCH" compose launch-escape "$FID" backend
refuse "task packet rejects managed-child symlink escape" "workspace path" \
  .agent-squad/bin/task-packet.sh packet-escape "$FID" "$TID" backend 1 "$(pwd)" agent-task/fixture
refuse "review package rejects managed-child symlink escape" "workspace path" \
  .agent-squad/bin/review-package.sh review-escape "$TID"
refuse "runtime event rejects managed-child symlink escape" "workspace path" \
  "$EVENT" event-escape "$FID" "$TID" 1 backend task.started implementing fixture
refuse "artifact submit rejects managed-child symlink escape" "workspace path" \
  .agent-squad/bin/submit-artifact.sh submit-escape "$FID" "$TID" 1 backend review-request guard-body.md Review
refuse "outbox broker rejects managed-child symlink escape" "workspace path" \
  .agent-squad/bin/process-outbox.sh broker-escape "$FID"
refuse "dispatcher rejects managed-child symlink escape" "workspace path" \
  .agent-squad/bin/dispatch.sh dispatch-escape "$FID" --once --dry-run
refuse "progress sync rejects managed-child symlink escape" "workspace path" \
  .agent-squad/bin/sync-progress.sh sync-escape "$FID" .teamwork/sync-escape/tasks.json
refuse "integrator rejects managed-child symlink escape" "workspace path" \
  .agent-squad/bin/integrate-task.sh integrate-escape "$FID" "$TID" backend 1
refuse "integration broker rejects managed-child symlink escape" "workspace path" \
  .agent-squad/bin/finalize-integrations.sh finalize-escape "$FID"
check "managed-child symlink guards write nothing outside workspace" test -z "$(find "$PATH_ESCAPE" -mindepth 1 -print -quit)"

wt="$($LAUNCH worktree feature-runtime backend "$TID" 1)"
check "task worktree uses collision-safe key" test "$(basename "$wt")" = "backend#1-$key"
check "task branch is generation/team namespaced" test "$(git -C "$wt" branch --show-current)" = "agent-task/feature-runtime/$key"
prompt="$($LAUNCH compose-task feature-runtime "$FID" backend "$TID" 1)"
check "lean task prompt exists" test -f "$prompt"
check "lean prompt points to task packet" grep -q 'Task packet:' "$prompt"
check "non-Claude task command is classified as other" grep -q 'LLM runtime family: other' "$prompt"
if grep -q 'Claude Superpowers task method' "$prompt"; then
  echo "FAIL: non-Claude task prompt received Superpowers worker methods"; FAILURES=$((FAILURES+1))
else
  echo "ok: non-Claude task prompt excludes Superpowers worker methods"
fi
claude_prompt="$(STARTUP_FACTORY_LLM_RUNTIME=claude "$LAUNCH" compose-task feature-runtime "$FID" backend "$TID" 1)"
check "Claude task harness receives Superpowers worker methods" \
  grep -q 'Claude Superpowers task method' "$claude_prompt"
PLANNING_CFG=.agent-squad/config/planning.config.md
sed_i 's/^USE_SUPERPOWERS=true$/USE_SUPERPOWERS=false/' "$PLANNING_CFG"
disabled_claude_prompt="$(STARTUP_FACTORY_LLM_RUNTIME=claude "$LAUNCH" compose-task feature-runtime "$FID" backend "$TID" 1)"
if grep -q 'Claude Superpowers task method' "$disabled_claude_prompt"; then
  echo "FAIL: disabled planning left Claude task worker methods enabled"; FAILURES=$((FAILURES+1))
else
  echo "ok: disabled planning removes Claude task worker methods"
fi
sed_i 's/^USE_SUPERPOWERS=false$/USE_SUPERPOWERS=true/' "$PLANNING_CFG"
"$LAUNCH" compose-task feature-runtime "$FID" backend "$TID" 1 >/dev/null
if grep -q 'The Multi-Agent Protocol' "$prompt"; then
  echo "FAIL: lean prompt inlined full protocol"; FAILURES=$((FAILURES+1))
else
  echo "ok: lean prompt excludes full protocol"
fi
packet_json=".teamwork/feature-runtime/artifacts/$key/attempt-1/task-packet.json"
packet_md=".teamwork/feature-runtime/artifacts/$key/attempt-1/task-packet.md"
check "packet records fast model profile" grep -q '"modelProfile": "fast"' "$packet_json"
check "packet requirement excludes Markdown comment history" python3 -c '
import json, sys
d=json.load(open(sys.argv[1]))
assert "[design-note]" not in d["description"]
assert "**Assignee:**" not in d["description"]
' "$packet_json"
packet_checksum="$(cksum "$packet_md")"
printf '[handoff]\nThis arrives after packet creation.\n' | "$OPS" comment "$TID" - >/dev/null
"$LAUNCH" compose-task feature-runtime "$FID" backend "$TID" 1 >/dev/null
check "same attempt reuses immutable packet" test "$(cksum "$packet_md")" = "$packet_checksum"

cat > "$TMP/claude" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cp "$1" claude-task-prompt.txt
EOF
chmod +x "$TMP/claude"
sed_i "s|^TASK_FAST_CMD=.*|TASK_FAST_CMD=\"$TMP/claude {prompt_file}\"|" "$CFG"
TEAM_RUNNER=background "$LAUNCH" start-task feature-runtime "$FID" backend "$TID" 1
for _i in $(seq 1 30); do [ -f "$wt/claude-task-prompt.txt" ] && break; sleep 0.1; done
check "direct Claude task command is classified as Claude" \
  grep -q 'LLM runtime family: claude' "$wt/claude-task-prompt.txt"
check "direct Claude task command receives Superpowers worker methods" \
  grep -q 'Claude Superpowers task method' "$wt/claude-task-prompt.txt"
rm -f "$wt/claude-task-prompt.txt"
sed_i 's|^TASK_FAST_CMD=.*|TASK_FAST_CMD="cat {prompt_file} > task-fast-prompt.txt"|' "$CFG"

TEAM_RUNNER=background "$LAUNCH" start-task feature-runtime "$FID" backend "$TID" 1
for _i in $(seq 1 30); do [ -f "$wt/task-fast-prompt.txt" ] && break; sleep 0.1; done
check "task-specific model command ran" test -f "$wt/task-fast-prompt.txt"
if grep -q 'Claude Superpowers task method' "$wt/task-fast-prompt.txt"; then
  echo "FAIL: non-Claude launched task received Superpowers worker methods"; FAILURES=$((FAILURES+1))
else
  echo "ok: non-Claude launched task excludes Superpowers worker methods"
fi
check "task pid uses task instance directory" test -d .teamwork/feature-runtime/pids/tasks

"$OPS" claim "$TID" backend >/dev/null
"$EVENT" feature-runtime "$FID" "$TID" 1 backend task.started implementing "writing endpoint" >/dev/null
check "event journal records task event" grep -q '"type":"task.started"' .teamwork/feature-runtime/events.ndjson
if grep -q 'agent-squad:progress:start' "$FID"; then
  echo "FAIL: worker wrote tracker directly in scribe mode"; FAILURES=$((FAILURES+1))
else
  echo "ok: scribe mode keeps task event local until dispatcher sync"
fi
"$OPS" export "$FID" .teamwork/feature-runtime/tasks.json >/dev/null
.agent-squad/bin/sync-progress.sh feature-runtime "$FID" .teamwork/feature-runtime/tasks.json >/dev/null
check "dispatcher projects event stage to tracker progress" grep -q '^> stage: implementing$' "$FID"

# The review envelope is generated from the exact committed task branch. Remove
# the task-runner probe and leave one real, clean checkpoint for the package.
rm -f "$wt/task-fast-prompt.txt"
mkdir -p "$wt/src"
printf 'def endpoint():\n    return "ok"\n' > "$wt/src/endpoint.py"
git -C "$wt" add src/endpoint.py
git -C "$wt" commit -q -m 'Implement endpoint fixture'

# A real launched task runs inside a linked worktree, but its fixed canonical
# project/workspace context must route the entry to the integration workspace.
# The per-instance capability is injected only into this launched process.
cat > task-submit-probe.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cat > linked-progress-note.md <<'BODY'
[progress-note]
Submitted from the linked task worktree through canonical routing.
BODY
entry="$("$STARTUP_FACTORY_CANONICAL_REPO/.agent-squad/bin/submit-artifact.sh" \
  "$STARTUP_FACTORY_TEAM" "$STARTUP_FACTORY_FEATURE_ID" "$STARTUP_FACTORY_TASK_ID" \
  "$STARTUP_FACTORY_ATTEMPT" "$STARTUP_FACTORY_ROLE" progress-note linked-progress-note.md -)"
rm -f linked-progress-note.md
printf '%s\n' "$entry" > "$STARTUP_FACTORY_CANONICAL_WORKSPACE/linked-entry.path"
EOF
chmod +x task-submit-probe.sh
sed_i "s|^TASK_FAST_CMD=.*|TASK_FAST_CMD=\"$(pwd)/task-submit-probe.sh {prompt_file}\"|" "$CFG"
rm -f ".teamwork/feature-runtime/pids/tasks/backend--$key--a1.pid" \
  .teamwork/feature-runtime/linked-entry.path
TEAM_RUNNER=background "$LAUNCH" start-task feature-runtime "$FID" backend "$TID" 1 >/dev/null
for _i in $(seq 1 50); do [ -s .teamwork/feature-runtime/linked-entry.path ] && break; sleep 0.1; done
linked_entry="$(cat .teamwork/feature-runtime/linked-entry.path 2>/dev/null || true)"
check "linked task submission lands in canonical outbox" python3 - "$linked_entry" "$(pwd)/.teamwork/feature-runtime/outbox/pending" <<'PY'
import os,sys
entry,pending=sys.argv[1:]
assert os.path.isfile(entry)
assert os.path.commonpath([os.path.realpath(entry), os.path.realpath(pending)]) == os.path.realpath(pending)
PY
check "linked task worktree gets no shadow outbox" test ! -e "$wt/.teamwork"
.agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$linked_entry" >/dev/null
check "broker accepts a legitimate launched-task signature" grep -q 'Submitted from the linked task worktree' "$FID"
sed_i 's|^TASK_FAST_CMD=.*|TASK_FAST_CMD="cat {prompt_file} > task-fast-prompt.txt"|' "$CFG"

cat > review.md <<'EOF'
[review-request]
round: 1
Files: src/endpoint.py, tests/test_endpoint.py
Evidence: focused tests passed

- backend
EOF
pre_review_delivery_count="$(grep -c 'delivery-id:' "$FID" || true)"
entry="$(.agent-squad/bin/submit-artifact.sh feature-runtime "$FID" "$TID" 1 backend review-request review.md Review)"
check "scribe mode leaves a durable outbox entry" test -f "$entry"

# An adapter outage is not evidence that a valid entry is forged. The broker
# must stop and leave the entry pending for the next scheduler pass.
mv .agent-squad/bin/tracker-ops.sh .agent-squad/bin/tracker-ops.sh.real
cat > .agent-squad/bin/tracker-ops.sh <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = export ]; then
  echo "simulated authoritative export outage" >&2
  exit 75
fi
exec "$(dirname "$0")/tracker-ops.sh.real" "$@"
EOF
chmod +x .agent-squad/bin/tracker-ops.sh
refuse "transient authoritative export stops without rejecting valid outbox work" "remains pending" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$entry"
check "transient export leaves valid entry pending" test -f "$entry"
check "transient export does not move valid entry to failed" \
  test -z "$(find .teamwork/feature-runtime/outbox/failed -maxdepth 1 -name "$(basename "$entry").rejected.*" -print -quit)"
mv .agent-squad/bin/tracker-ops.sh.real .agent-squad/bin/tracker-ops.sh

.agent-squad/bin/process-outbox.sh feature-runtime "$FID" >/dev/null & outbox_pid_1=$!
.agent-squad/bin/process-outbox.sh feature-runtime "$FID" >/dev/null & outbox_pid_2=$!
wait "$outbox_pid_1" "$outbox_pid_2"
check "outbox publishes review request" grep -q '\[review-request\]' "$FID"
check "outbox performs requested transition" grep -q '^## 1 Implement endpoint \[Review\]$' "$FID"
done_entry=".teamwork/feature-runtime/outbox/done/$(basename "$entry")"
check "outbox entry moves to done" test -f "$done_entry"
check "concurrent outbox drains keep one tracker comment" test "$(grep -c 'delivery-id:' "$FID")" -eq "$((pre_review_delivery_count + 1))"
check "broker binds request to exact base/head/package" python3 - "$done_entry" <<'PY'
import json,re,sys
d=json.load(open(sys.argv[1])); body=open(d['publishBodyPath']).read()
assert d['deliveryId'].startswith('delivery-') and d['deliveryId'] != d['id']
assert re.search(r'(?m)^Review-Base-Commit: [0-9a-f]{40}$', body)
assert re.search(r'(?m)^Task-Branch-Head: [0-9a-f]{40}$', body)
assert re.search(r'(?m)^Review-Package-SHA256: sha256:[0-9a-f]{64}$', body)
assert d['reviewBinding']['head'] == re.search(r'(?m)^Task-Branch-Head: (\S+)$', body).group(1)
PY
check "broker-owned staged body is read-only" python3 - "$done_entry" <<'PY'
import json,stat,sys
d=json.load(open(sys.argv[1]))
assert stat.S_IMODE(__import__('os').stat(d['stagedBodyPath']).st_mode) == 0o400
PY
mv "$done_entry" "$entry"
python3 - "$entry" <<'PY'
import json, os, sys
p=sys.argv[1]; d=json.load(open(p)); d['phase']='pending'
t=p+'.tmp'; open(t,'w').write(json.dumps(d, indent=2)+'\n'); os.replace(t,p)
PY
.agent-squad/bin/process-outbox.sh feature-runtime "$FID" >/dev/null
check "outbox retry keeps one tracker comment" test "$(grep -c 'delivery-id:' "$FID")" -eq "$((pre_review_delivery_count + 1))"
check "outbox retry keeps target status" grep -q '^## 1 Implement endpoint \[Review\]$' "$FID"

# Gate approvals remain protocol-role owned, but authorization comes from a
# short-lived capability minted for the exact launched role instance. Actor
# strings in raw outbox JSON cannot manufacture a principal.
cat > .teamwork/feature-runtime/preset.env <<'EOF'
PROTOCOL_TEAM_LEAD=team-lead
PROTOCOL_PRINCIPAL_ARCHITECT=principal-software-architect
PROTOCOL_SCEPTICAL_ARCHITECT=sceptical-architect
PROTOCOL_SECURITY_REVIEWER=senior-security-engineer
EOF
cat > gate-submit-probe.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
marker="$1"; source="$2"; output="$3"
target="${4:--}"
entry="$("$STARTUP_FACTORY_CANONICAL_REPO/.agent-squad/bin/submit-artifact.sh" \
  "$STARTUP_FACTORY_TEAM" "$STARTUP_FACTORY_FEATURE_ID" 'feat/feature.md#1' 1 \
  "$STARTUP_FACTORY_ROLE" "$marker" "$source" "$target")"
printf '%s\n' "$entry" > "$STARTUP_FACTORY_CANONICAL_WORKSPACE/$output"
EOF
chmod +x gate-submit-probe.sh

launch_gate_submission() { # role marker body output-file [target] -> entry path
  local role="$1" marker="$2" body_file="$3" output_file="$4" target="${5:--}" key_name
  key_name="$(printf '%s_CMD' "$(printf '%s' "$role" | tr 'a-z-' 'A-Z_')")"
  sed_i "/^${key_name}=/d" "$CFG"
  printf '%s="%s %s %s %s %s {prompt_file}"\n' "$key_name" "$(pwd)/gate-submit-probe.sh" \
    "$marker" "$body_file" "$output_file" "$target" >> "$CFG"
  rm -f ".teamwork/feature-runtime/$output_file" ".teamwork/feature-runtime/pids/$role.pid"
  TEAM_RUNNER=background "$LAUNCH" start feature-runtime "$FID" "$role" >/dev/null
  for _i in $(seq 1 50); do [ -s ".teamwork/feature-runtime/$output_file" ] && break; sleep 0.1; done
  cat ".teamwork/feature-runtime/$output_file"
}

write_task_hold() {
  python3 - ".teamwork/feature-runtime/task-holds.json" "$FID" "$TID" "$key" "$1" <<'PY'
import json,sys
path,feature,task,key,state=sys.argv[1:]
with open(path,"w") as handle:
    json.dump({"schemaVersion":1,"featureId":feature,"tasks":{
        key:{"taskId":task,"taskKey":key,"state":state}
    }},handle)
PY
}

# A Blocked/manual hold stops every agent publication. The only exception is
# the resume-review barrier itself: an authenticated gate may add one of the
# exact comment-only verdicts needed to resolve it, but cannot publish ordinary
# review/work artifacts or move state.
cat > resume-design-approved.md <<'EOF'
[design-approved]
fixture: authenticated resume barrier gate

- principal-software-architect
EOF

# Protected authority must remain decisive even if an agent deletes or forges
# the workspace projection and the fresh tracker status itself is non-Blocked.
# Produce the gate capability under the same external authority first, then
# establish its protected hold and lie locally that the task resumed.
export STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$PROTECTED_FORGERY_ROOT"
protected_gate_entry="$(launch_gate_submission principal-software-architect design-approved resume-design-approved.md protected-gate.path)"
cat > "$TMP/protected-blocked.json" <<EOF
{"featureId":"$FID","tasks":[{"taskId":"$TID","title":"fixture","description":"fixture","status":"Blocked","statusRaw":"Blocked","assignee":"backend","blockedBy":[],"labels":[],"comments":[],"attachments":[]}]}
EOF
python3 .agent-squad/bin/task-hold.py sync \
  --repo "$(pwd)" --workspace "$(pwd)/.teamwork/feature-runtime" \
  --tasks "$TMP/protected-blocked.json" --feature "$FID" --team feature-runtime \
  --blocked-status Blocked --queued-status Planned \
  --inflight-status Planned --inflight-status Active --inflight-status Review \
  --ignored-labels-json '["human-work"]' >/dev/null
write_task_hold resumed
refuse "protected Blocked authority defeats a forged local resumed projection" "is held (blocked)" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$protected_gate_entry"
export STARTUP_FACTORY_LIFECYCLE_STATE_ROOT="$LIFECYCLE_ROOT"
rm -f .teamwork/feature-runtime/task-holds.json

write_task_hold resume-review-pending
resume_gate_entry="$(launch_gate_submission principal-software-architect design-approved resume-design-approved.md resume-gate.path)"
.agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$resume_gate_entry" >/dev/null
check "resume-review hold permits an authenticated comment-only barrier gate" \
  grep -q 'fixture: authenticated resume barrier gate' "$FID"
resume_state_entry="$(launch_gate_submission principal-software-architect design-approved resume-design-approved.md resume-state.path Active)"
refuse "resume-review hold rejects state-moving barrier gates" "comment-only" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$resume_state_entry"

cat > held-architecture.md <<'EOF'
[architecture-approval]
fixture: ordinary gate must remain stopped

- principal-software-architect
EOF
resume_work_entry="$(launch_gate_submission principal-software-architect architecture-approval held-architecture.md resume-work.path)"
refuse "resume-review hold rejects ordinary review gates" "resume-review-pending" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$resume_work_entry"

write_task_hold blocked
blocked_gate_entry="$(launch_gate_submission principal-software-architect design-approved resume-design-approved.md blocked-gate.path)"
refuse "Blocked hold rejects even resume barrier comments" "is held (blocked)" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$blocked_gate_entry"

printf '{not-json\n' > .teamwork/feature-runtime/task-holds.json
malformed_hold_entry="$(launch_gate_submission principal-software-architect design-approved resume-design-approved.md malformed-hold.path)"
refuse "malformed hold registry fails closed" "invalid task hold registry" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$malformed_hold_entry"

python3 - ".teamwork/feature-runtime/task-holds-target.json" "$FID" <<'PY'
import json,sys
json.dump({"schemaVersion":1,"featureId":sys.argv[2],"tasks":{}},open(sys.argv[1],"w"))
PY
rm -f .teamwork/feature-runtime/task-holds.json
ln -s "$(pwd)/.teamwork/feature-runtime/task-holds-target.json" .teamwork/feature-runtime/task-holds.json
symlink_hold_entry="$(launch_gate_submission principal-software-architect design-approved resume-design-approved.md symlink-hold.path)"
refuse "symlink hold registry fails closed" "non-symlink regular file" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$symlink_hold_entry"
rm .teamwork/feature-runtime/task-holds.json

python3 - ".teamwork/feature-runtime/task-holds.json" <<'PY'
import json,sys
json.dump({"schemaVersion":1,"featureId":"other-feature","tasks":{}},open(sys.argv[1],"w"))
PY
mismatched_hold_entry="$(launch_gate_submission principal-software-architect design-approved resume-design-approved.md mismatched-hold.path)"
refuse "cross-feature hold registry fails closed" "feature scope mismatch" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$mismatched_hold_entry"
rm -f .teamwork/feature-runtime/task-holds.json .teamwork/feature-runtime/task-holds-target.json

blocked_target_entry="$(launch_gate_submission principal-software-architect design-approved resume-design-approved.md blocked-target.path Blocked)"
refuse "generic authenticated outbox entry cannot move a task to Blocked" "dispatcher-only" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$blocked_target_entry"

perl -0pi -e 's/## 1 Implement endpoint \[Review\]/## 1 Implement endpoint [Blocked]/' "$FID"
blocked_source_entry="$(launch_gate_submission principal-software-architect design-approved resume-design-approved.md blocked-source.path)"
refuse "authoritative Blocked stops comment-only publication before hold sync" "authoritatively Blocked" \
  env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$blocked_source_entry"
perl -0pi -e 's/## 1 Implement endpoint \[Blocked\]/## 1 Implement endpoint [Review]/' "$FID"

perl -0pi -e 's/(\*\*Assignee:\*\* backend\n)/$1\n**Labels:** human-work\n/' "$FID"
human_label_entry="$(launch_gate_submission principal-software-architect design-approved resume-design-approved.md human-label.path)"
refuse "standalone outbox uses configured human-work fallback without dispatcher env" "labeled for human work" \
  env -u STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON -u STARTUP_FACTORY_LIFECYCLE_STATE_ROOT \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$human_label_entry"
perl -0pi -e 's/\n\*\*Labels:\*\* human-work\n//' "$FID"

cat > architecture-verdict.md <<'EOF'
[architecture-approval]
Architecture matches the approved checklist.

- principal-software-architect
EOF
unsigned_architecture_entry="$(.agent-squad/bin/submit-artifact.sh feature-runtime "$FID" "$TID" 1 principal-software-architect architecture-approval architecture-verdict.md -)"
refuse "raw forged principal marker has no gate authority" "capability is required" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$unsigned_architecture_entry"

tampered_signature_entry="$(launch_gate_submission principal-software-architect architecture-approval architecture-verdict.md tampered-signature.path)"
python3 - "$tampered_signature_entry" <<'PY'
import json,os,sys
p=sys.argv[1]; d=json.load(open(p)); signature=d['producerCapability']['signature']
d['producerCapability']['signature']=signature[:-1]+('0' if signature[-1] != '0' else '1')
t=p+'.tmp'; open(t,'w').write(json.dumps(d,indent=2)+'\n'); os.replace(t,p)
PY
refuse "broker rejects a tampered gate capability signature" "signature mismatch" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$tampered_signature_entry"

cross_role_entry="$(launch_gate_submission principal-software-architect architecture-approval architecture-verdict.md cross-role.path)"
python3 - "$cross_role_entry" <<'PY'
import json,os,sys
p=sys.argv[1]; d=json.load(open(p)); d['actor']='senior-technical-product-manager'
t=p+'.tmp'; open(t,'w').write(json.dumps(d,indent=2)+'\n'); os.replace(t,p)
PY
refuse "broker rejects a cross-role gate capability" "claimed actor does not match" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$cross_role_entry"

missing_sceptical_mapping_entry="$(launch_gate_submission principal-software-architect architecture-approval architecture-verdict.md missing-sceptical-mapping.path)"
sed_i '/^PROTOCOL_SCEPTICAL_ARCHITECT=/d' .teamwork/feature-runtime/preset.env
refuse "broker rejects a preset that omits the mandatory Sceptical Architect" "must define one valid mandatory PROTOCOL_SCEPTICAL_ARCHITECT" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$missing_sceptical_mapping_entry"
printf 'PROTOCOL_SCEPTICAL_ARCHITECT=sceptical-architect\n' >> .teamwork/feature-runtime/preset.env

architecture_entry="$(launch_gate_submission principal-software-architect architecture-approval architecture-verdict.md architecture.path)"
.agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$architecture_entry" >/dev/null
cat > sceptical-architecture-verdict.md <<'EOF'
[sceptical-architecture-approval]
Independent challenge found no unresolved material risk.

- sceptical-architect
EOF
sceptical_entry="$(launch_gate_submission sceptical-architect sceptical-architecture-approval sceptical-architecture-verdict.md sceptical.path)"
.agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$sceptical_entry" >/dev/null
cat > security-verdict.md <<'EOF'
[security-approval]
Threat model, authorization boundaries, and abuse cases reviewed.

- senior-security-engineer
EOF
security_entry="$(launch_gate_submission senior-security-engineer security-approval security-verdict.md security.path)"
.agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$security_entry" >/dev/null
cat > team-lead-verdict.md <<'EOF'
[team-lead-approval]
Specification, tests, maintainability, and operational readiness reviewed.

- team-lead
EOF
team_lead_entry="$(launch_gate_submission team-lead team-lead-approval team-lead-verdict.md team-lead.path)"
.agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$team_lead_entry" >/dev/null
"$OPS" export "$FID" .teamwork/feature-runtime/approval-snapshot.json >/dev/null
check "gate approvals bind the latest request digest/head/package" python3 - .teamwork/feature-runtime/approval-snapshot.json <<'PY'
import hashlib,json,re,sys
payload=json.load(open(sys.argv[1])); task=payload['tasks'][0]
comments=[str(c.get('body') or '') for c in task['comments']]
request=next(body for body in reversed(comments) if body.startswith('[review-request]'))
expected='sha256:'+hashlib.sha256(request.encode()).hexdigest()
for marker in (
    '[team-lead-approval]',
    '[architecture-approval]',
    '[sceptical-architecture-approval]',
    '[security-approval]',
):
    body=next(body for body in reversed(comments) if body.startswith(marker))
    assert re.search(r'(?m)^Review-Request-SHA256: '+re.escape(expected)+r'$', body)
    assert re.search(r'(?m)^Task-Branch-Head: [0-9a-f]{40}$', body)
    assert re.search(r'(?m)^Review-Package-SHA256: sha256:[0-9a-f]{64}$', body)
PY

# Product verdict ownership is conditional: the configured product-manager owns
# it exclusively, with team-lead fallback only when that role is absent.
cat > .teamwork/feature-runtime/preset.env <<'EOF'
PROTOCOL_TEAM_LEAD=team-lead
PROTOCOL_PRINCIPAL_ARCHITECT=principal-software-architect
PROTOCOL_SCEPTICAL_ARCHITECT=sceptical-architect
PROTOCOL_SECURITY_REVIEWER=senior-security-engineer
PROTOCOL_PRODUCT_MANAGER=senior-technical-product-manager
EOF
cat > product-verdict.md <<'EOF'
[product-approval]
scope: feature
fixture: broker-role-ownership
EOF
unsigned_product_entry="$(.agent-squad/bin/submit-artifact.sh feature-runtime "$FID" "$TID" 1 senior-technical-product-manager product-approval product-verdict.md -)"
refuse "raw forged product marker has no gate authority" "capability is required" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$unsigned_product_entry"
lead_product_entry="$(launch_gate_submission team-lead product-approval product-verdict.md lead-product.path)"
refuse "configured product-manager excludes team-lead product verdict" "product-manager exclusively owns" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$lead_product_entry"
product_entry="$(launch_gate_submission senior-technical-product-manager product-approval product-verdict.md product.path)"
.agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$product_entry" >/dev/null
check "configured product-manager can publish product verdict" grep -q 'fixture: broker-role-ownership' "$FID"
sed_i '/^PROTOCOL_PRODUCT_MANAGER=/d' .teamwork/feature-runtime/preset.env
cat > fallback-verdict.md <<'EOF'
[product-pushback]
reason: fallback ownership fixture
EOF
fallback_entry="$(launch_gate_submission team-lead product-pushback fallback-verdict.md fallback.path)"
.agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$fallback_entry" >/dev/null
check "team-lead product fallback works only without product role" grep -q 'fallback ownership fixture' "$FID"
accepted_delivery_count="$(grep -c 'delivery-id:' "$FID")"

pending=".teamwork/feature-runtime/outbox/pending"
bodies=".teamwork/feature-runtime/outbox/bodies"
make_forged_entry() {
  local ident="$1" body="$2" target="$3"
  python3 - "$pending/$ident.json" "$ident" "$body" "$target" "$FID" "$TID" <<'PY'
import json, sys
path, ident, body, target, feature, task = sys.argv[1:]
with open(path, "w") as handle:
    json.dump({
        "schemaVersion": 1, "id": ident, "team": "feature-runtime",
        "featureId": feature, "taskId": task, "attempt": 1,
        "actor": "backend", "marker": "review-request",
        "bodyPath": body, "targetStatus": target, "phase": "pending",
    }, handle)
PY
}

make_forged_entry forged-path-1234 /etc/hosts Review
refuse "outbox rejects body path escape" "body must be" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$pending/forged-path-1234.json"

cat > "$bodies/forged-terminal.md" <<'EOF'
[review-request]
An agent must not complete its own task through the outbox.
EOF
make_forged_entry forged-terminal-1234 "$(pwd)/$bodies/forged-terminal.md" "Ready to deploy"
refuse "outbox rejects terminal transition" "terminal transition" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$pending/forged-terminal-1234.json"

cat > "$bodies/forged-secret.md" <<'EOF'
[review-request]
api_key=supersecretvalue
EOF
make_forged_entry forged-secret-1234 "$(pwd)/$bodies/forged-secret.md" Review
refuse "outbox rejects credential-like content" "credential/secret" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$pending/forged-secret-1234.json"

cat > feat/other.md <<'EOF'
# Other feature [Active]

## 1 Foreign task [Active]

**Assignee:** backend
EOF
cat > "$bodies/forged-cross-feature.md" <<'EOF'
[review-request]
This task belongs to another feature.
EOF
make_forged_entry forged-cross-1234 "$(pwd)/$bodies/forged-cross-feature.md" Review
python3 - "$pending/forged-cross-1234.json" <<'PY'
import json,os,sys
p=sys.argv[1]; d=json.load(open(p)); d['taskId']='feat/other.md#1'
t=p+'.tmp'; open(t,'w').write(json.dumps(d)+'\n'); os.replace(t,p)
PY
refuse "outbox rejects a cross-feature task" "absent from the authoritative feature/team scope" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$pending/forged-cross-1234.json"

cat > "$bodies/forged-actor.md" <<'EOF'
[review-request]
An unrelated role cannot borrow this task execution.
EOF
make_forged_entry forged-actor-1234 "$(pwd)/$bodies/forged-actor.md" Review
python3 - "$pending/forged-actor-1234.json" <<'PY'
import json,os,sys
p=sys.argv[1]; d=json.load(open(p)); d['actor']='frontend'
t=p+'.tmp'; open(t,'w').write(json.dumps(d)+'\n'); os.replace(t,p)
PY
refuse "outbox rejects an actor forged against task execution" "producer role does not match" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$pending/forged-actor-1234.json"

cat > "$bodies/forged-preclaim-design.md" <<'EOF'
[design-note]
A planning comment cannot claim or move the task by itself.
EOF
make_forged_entry forged-design-1234 "$(pwd)/$bodies/forged-preclaim-design.md" Active
python3 - "$pending/forged-design-1234.json" <<'PY'
import json,os,sys
p=sys.argv[1]; d=json.load(open(p)); d['marker']='design-note'
t=p+'.tmp'; open(t,'w').write(json.dumps(d)+'\n'); os.replace(t,p)
PY
execution=".teamwork/feature-runtime/executions/$key.json"
mv "$execution" "$execution.saved"
refuse "pre-claim design note cannot move task state" "comment only" \
  .agent-squad/bin/process-outbox.sh feature-runtime "$FID" "$pending/forged-design-1234.json"
mv "$execution.saved" "$execution"

refuse "submitter rejects fixed runtime actor forgery" "actor does not match fixed runtime identity" \
  env STARTUP_FACTORY_EXECUTION_KIND=task STARTUP_FACTORY_TEAM=feature-runtime \
    STARTUP_FACTORY_FEATURE_ID="$FID" STARTUP_FACTORY_ROLE=backend STARTUP_FACTORY_TASK_ID="$TID" \
    STARTUP_FACTORY_ATTEMPT=1 .agent-squad/bin/submit-artifact.sh \
    feature-runtime "$FID" "$TID" 1 frontend review-request review.md Review
check "rejected outbox entries do not mutate task state" grep -q '^## 1 Implement endpoint \[Review\]$' "$FID"
check "rejected outbox entries do not add tracker comments" test "$(grep -c 'delivery-id:' "$FID")" -eq "$accepted_delivery_count"

# The test probe is intentionally a one-shot process. Remove its stale
# background-runner pid record before exercising dispatcher relaunch behavior.
rm -f ".teamwork/feature-runtime/pids/tasks/backend--$key--a1.pid"
rm -f "$wt/task-fast-prompt.txt"
cat > findings.md <<'EOF'
[review-findings]
round: 1
1. Add the missing edge-case assertion.

- reviewer
EOF
"$OPS" comment "$TID" findings.md >/dev/null
"$OPS" state "$TID" Planned >/dev/null
dispatch_output="$(TEAM_RUNNER=background .agent-squad/bin/dispatch.sh feature-runtime "$FID" --once --unblock=off 2>&1)"
attempt2_wt=".teamwork/feature-runtime/worktrees/backend#2-$key"
for _i in $(seq 1 30); do [ -f "$attempt2_wt/task-fast-prompt.txt" ] && break; sleep 0.1; done
[ -f "$attempt2_wt/task-fast-prompt.txt" ] || printf '%s\n' "$dispatch_output" >&2
check "review findings launch a fresh attempt" grep -q '"attempt": 2' ".teamwork/feature-runtime/executions/$key.json"
check "fresh rework packet includes findings" grep -q '\[review-findings\]' ".teamwork/feature-runtime/artifacts/$key/attempt-2/task-packet.md"
check "clean prior worktree is retired" test ! -d "$wt"

"$OPS" export "$FID" .teamwork/feature-runtime/tasks.json >/dev/null
.agent-squad/bin/sync-progress.sh feature-runtime "$FID" .teamwork/feature-runtime/tasks.json >/dev/null
check "sync creates one feature digest" test "$(grep -c 'agent-squad:digest:start' "$FID")" -eq 1
check "sync projection is durable" test -f .teamwork/feature-runtime/pm-projection.json

echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
