#!/usr/bin/env bash
# tracker-ops smoke test: exercises the Markdown backend end-to-end (offline)
# plus the adapter-agnostic argument/board validation.
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok: $desc"; else echo "FAIL: $desc"; FAILURES=$((FAILURES+1)); fi
}
refuse() { # refuse <desc> <needle> <cmd...>
  local desc="$1" needle="$2" out; shift 2
  if out="$("$@" 2>&1)"; then
    echo "FAIL: $desc (accepted)"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$out" | grep -q "$needle"; then
    echo "ok: $desc"
  else
    echo "FAIL: $desc (wrong message: $out)"; FAILURES=$((FAILURES+1))
  fi
}

# -- project-owned custom backend delegation -----------------------------------
CUSTOM_SKILL="$TMP/custom-skill"
mkdir -p "$CUSTOM_SKILL/bin" "$CUSTOM_SKILL/config" "$CUSTOM_SKILL/extensions/tracker-backends"
cp "$SKILL_DIR/bin/tracker-ops.sh" "$CUSTOM_SKILL/bin/"
cp "$SKILL_DIR/bin/ticket_content_security.py" "$CUSTOM_SKILL/bin/"
cp "$SKILL_DIR/config/statuses.config.json" "$CUSTOM_SKILL/config/"
cat > "$CUSTOM_SKILL/config/project-management.config.md" <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Acme
STATUS_CONFIG=config/statuses.config.json
```
EOF
cat > "$CUSTOM_SKILL/extensions/tracker-backends/Acme.py" <<'PY'
import json
import os


class Backend:
    def __init__(self, context):
        self.context = context

    def current_status(self, task_id):
        return os.environ.get('ACME_STATUS', 'Planned')

    def current_labels(self, task_id):
        return json.loads(os.environ.get('ACME_LABELS', '[]'))

    def current_feature_status(self, feature_id):
        return 'Planned'

    def _mutation(self, name):
        path = os.environ.get('CUSTOM_MUTATION_OUT')
        if path:
            with open(path, 'a') as handle:
                handle.write(name + '\n')

    def set_state(self, task_id, target): self._mutation('set_state')
    def set_assignee(self, task_id, role): self._mutation('set_assignee')
    def set_feature_state(self, feature_id, target): self._mutation('set_feature_state')

    def comment(self, task_id, body):
        with open(os.environ['CUSTOM_BACKEND_OUT'], 'w') as handle:
            handle.write('root=%s\n' % self.context['skill_dir'])
            handle.write('adapter=%s\n' % self.context['adapter'])
            handle.write('task=%s\n' % task_id)
            handle.write('body=%s\n' % body)
        return 'custom-comment-id'

    def comment_exists(self, task_id, token): return False
    def integration_comment_exists(self, task_id, commit): return False
    def update_comment(self, task_id, comment_id, body): self._mutation('update_comment')
    def upsert_progress(self, task_id, body): self._mutation('upsert_progress')
    def upsert_digest(self, feature_id, body): self._mutation('upsert_digest')
    def upsert_deployment(self, feature_id, body): self._mutation('upsert_deployment')
    def export(self, feature_id): return []
    def scan(self, statuses): return []
PY
CUSTOM_OPS="$CUSTOM_SKILL/bin/tracker-ops.sh"
printf 'custom body\n' | CUSTOM_BACKEND_OUT="$TMP/custom-backend.out" \
  "$CUSTOM_OPS" comment ACME-1 -
check "custom backend receives the absolute skill root" \
  grep -qx "root=$CUSTOM_SKILL" "$TMP/custom-backend.out"
check "custom backend receives the selected adapter" \
  grep -qx 'adapter=Acme' "$TMP/custom-backend.out"
check "custom backend receives the task primitive" \
  grep -qx 'task=ACME-1' "$TMP/custom-backend.out"
check "custom backend receives the core-validated body" \
  grep -qx 'body=custom body' "$TMP/custom-backend.out"
OUTBOUND_SECRET='sk-proj-abcdefghijklmnopqrstuvwxyz012345'
printf 'api_key=%s\n' "$OUTBOUND_SECRET" | CUSTOM_BACKEND_OUT="$TMP/custom-backend.out" \
  "$CUSTOM_OPS" comment ACME-1 - >/dev/null
check "custom backend never receives a raw credential" \
  bash -c "! grep -Fq '$OUTBOUND_SECRET' '$TMP/custom-backend.out'"
check "custom backend receives the redacted comment" \
  grep -Fq '[REDACTED POTENTIAL SECRET]' "$TMP/custom-backend.out"

ln -s Acme.py "$CUSTOM_SKILL/extensions/tracker-backends/AcmeLink.py"
cat > "$CUSTOM_SKILL/config/project-management.config.md" <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=AcmeLink
STATUS_CONFIG=config/statuses.config.json
```
EOF
refuse "symlinked custom backend is refused" "contains a symlink" \
  "$CUSTOM_OPS" scan "$TMP/unused.json" --status Planned

cat > "$CUSTOM_SKILL/extensions/tracker-backends/Incomplete.py" <<'PY'
class Backend:
    def __init__(self, context):
        self.context = context
PY
refuse "incomplete custom backend contract is refused" "missing methods" \
  env TRACKER_ADAPTER=Incomplete "$CUSTOM_OPS" scan "$TMP/unused.json" --status Planned

refuse "custom backend cannot bypass human-only Blocked exit" "human-only" \
  env TRACKER_ADAPTER=Acme ACME_STATUS=Blocked CUSTOM_MUTATION_OUT="$TMP/custom-mutations" \
    "$CUSTOM_OPS" state ACME-1 Planned
refuse "custom backend cannot bypass human-work claim fence" "labeled for human work" \
  env TRACKER_ADAPTER=Acme ACME_STATUS=Planned ACME_LABELS='["human-work"]' \
    STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON='["human-work"]' \
    CUSTOM_MUTATION_OUT="$TMP/custom-mutations" \
    "$CUSTOM_OPS" claim ACME-1 backend
check "refused custom operations never reach mutation primitives" \
  test ! -e "$TMP/custom-mutations"

# -- fixture: a skill copy configured for the Markdown adapter ------------------
cd "$TMP"
mkdir -p skill/config skill/bin
cp "$SKILL_DIR/bin/tracker-ops.sh" skill/bin/
cp "$SKILL_DIR/bin/ticket_content_security.py" skill/bin/
cp "$SKILL_DIR/config/statuses.config.json" skill/config/
cat > skill/config/project-management.config.md <<'EOF'
```
PRODUCT_MANAGEMENT_TOOL=Markdown
MARKDOWN_ROOT=.
STATUS_CONFIG=config/statuses.config.json
```
EOF
OPS="skill/bin/tracker-ops.sh"

mkdir -p feat
cat > feat/feature.md <<'EOF'
# Payments revamp [Planned]

**Purpose:** Test fixture.

## 1 Add form [Planned]

**Assignee:** —
**Labels:** human-work, needs-review

Build the form.

- Field A

## 2 Wire endpoint [Planned]

**Assignee:** —
**BlockedBy:** 1

Call the endpoint.
EOF
T="feat/feature.md"

# -- generated PM surfaces: one task progress block + one feature digest -------
printf '[progress]\ncredential: %s\n' "$OUTBOUND_SECRET" | "$OPS" upsert-progress "$T#2" - >/dev/null
check "progress projection never stores a raw credential" bash -c "! grep -Fq '$OUTBOUND_SECRET' '$T'"
check "progress projection stores a redaction marker" grep -Fq '[REDACTED POTENTIAL SECRET]' "$T"
printf '[progress]\nstage: planned\nsummary: queued\n' | "$OPS" upsert-progress "$T#2" -
printf '[progress]\nstage: ready\nsummary: design approved\n' | "$OPS" upsert-progress "$T#2" -
check "progress upsert keeps one managed block" test "$(grep -c 'agent-squad:progress:start' "$T")" -eq 1
check "progress upsert replaces old content" grep -q '^> stage: ready$' "$T"
if grep -q '^> stage: planned$' "$T"; then echo "FAIL: stale progress retained"; FAILURES=$((FAILURES+1)); else echo "ok: stale progress removed"; fi
printf '[digest]\ncredential: %s\n' "$OUTBOUND_SECRET" | "$OPS" upsert-digest "$T" - >/dev/null
check "digest projection never stores a raw credential" bash -c "! grep -Fq '$OUTBOUND_SECRET' '$T'"
check "digest projection stores a redaction marker" grep -Fq '[REDACTED POTENTIAL SECRET]' "$T"
printf '[digest]\nT#1 - planned\n' | "$OPS" upsert-digest "$T" -
printf '[digest]\nT#1 - active\n' | "$OPS" upsert-digest "$T" -
check "digest upsert keeps one managed block" test "$(grep -c 'agent-squad:digest:start' "$T")" -eq 1
check "digest upsert replaces old content" grep -q '^> T#1 - active$' "$T"

# -- claim: assignee + initial→Active + claim comment ---------------------------
"$OPS" claim "$T#1" backend
check "claim sets status"        grep -q '^## 1 Add form \[Active\]$' "$T"
check "claim sets assignee"      grep -q '^\*\*Assignee:\*\* backend$' "$T"
check "claim leaves a comment"   grep -q '\[claim\]' "$T"
check "claim records the role"   grep -q 'role: backend' "$T"
check "claim records a claim id" grep -q 'claim-id: ' "$T"
check "claim retry is idempotent" bash -c "'$OPS' claim '$T#1' backend && [ \"\$(grep -c 'claim-id: ' '$T')\" -eq 1 ]"
check "sibling task untouched"   grep -q '^## 2 Wire endpoint \[Planned\]$' "$T"

# -- comment: body from stdin, marker extracted, quoting-proof ------------------
printf '[design-note] Approach: "quote" & $dollar.\nSecond line.\n' | "$OPS" comment "$T#1" -
check "comment marker extracted"  grep -q '> \[design-note\] (....-..-..): Approach: "quote" & $dollar\.' "$T"
check "comment multiline quoted"  grep -q '^> Second line\.$' "$T"
printf '[security-test] api_key=%s\n' "$OUTBOUND_SECRET" | "$OPS" comment "$T#1" - >/dev/null
check "comment never stores a raw credential" bash -c "! grep -Fq '$OUTBOUND_SECRET' '$T'"
check "comment stores a redaction marker" grep -Fq '[REDACTED POTENTIAL SECRET]' "$T"

# -- comment: body from a file ---------------------------------------------------
printf 'From a file.\n' > body.txt
"$OPS" comment "$T#1" body.txt
check "comment from file"         grep -q '> note (....-..-..): From a file\.' "$T"

cat > product-body.txt <<'EOF'
[product-approval]
scope: feature
feature-id: feat/feature.md
anchor-task-id: feat/feature.md#1
commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
integration-evidence-digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
acceptance-criteria: passed
summary: exact round-trip fixture

— product-manager (team-lead only when no product role exists)
EOF
"$OPS" comment "$T#1" product-body.txt
check "structured product envelope stays byte-exact in Markdown" python3 - "$OPS" "$T" <<'PY'
import json,subprocess,sys,tempfile
ops,feature=sys.argv[1:]
with tempfile.NamedTemporaryFile() as out:
    subprocess.run([ops,'export',feature,out.name],check=True,stdout=subprocess.DEVNULL)
    payload=json.load(open(out.name))
comments=next(task for task in payload['tasks'] if task['taskId']==feature+'#1')['comments']
comment=next(comment for comment in comments if comment['body'].startswith('[product-approval]'))
assert comment['body']==open('product-body.txt').read().rstrip('\n')
assert str(comment['revision']).startswith('markdown-offset:')
assert str(comment['revision']).split(':',1)[1].isdigit()
PY

# -- comment-once: uncertain delivery retries stay idempotent ------------------
printf '[review-request]\nFiles: a.py\n' > delivery.txt
"$OPS" comment-once "$T#1" delivery-123 delivery.txt
"$OPS" comment-once "$T#1" delivery-123 delivery.txt
check "comment-once retry keeps one delivery" test "$(grep -c 'delivery-id: delivery-123' "$T")" -eq 1
refuse "secret-bearing delivery identifier is refused" "unsafe content detected in outbound comment-delivery-id" \
  "$OPS" comment-once "$T#1" "$OUTBOUND_SECRET" delivery.txt

# -- record-denial: guardrail DENY becomes idempotent ticket-level evidence -----
printf 'deploy.apply argv: terraform destroy -auto-approve (production)\n' > denied.txt
"$OPS" record-denial "$T#1" --actor deep-infra/devops --reason "infrastructure destroy is forbidden" denied.txt
check "denial marker recorded literally"   grep -q '^> \[DENIED ACTION\]$' "$T"
check "denial records the actor"           grep -q '^> actor: deep-infra/devops$' "$T"
check "denial records the attempt"         grep -q 'terraform destroy -auto-approve' "$T"
check "denial records the reason"          grep -q '^> Denial reason: infrastructure destroy is forbidden$' "$T"
check "denial states prevention"           grep -q 'was blocked by the fail-closed policy gate and was not executed' "$T"
check "denial carries an id"               grep -q '^> denial-id: denial-' "$T"
check "denial retry is idempotent" bash -c \
  "'$OPS' record-denial '$T#1' --actor deep-infra/devops --reason 'infrastructure destroy is forbidden' denied.txt \
   && [ \"\$(grep -c 'denial-id: ' '$T')\" -eq 1 ]"
printf 'attempted request included password=%s\n' "$OUTBOUND_SECRET" | "$OPS" record-denial "$T#1" \
  --actor policy-gate --reason "credential exposure is forbidden" --denial-id denial-secret-0001 - >/dev/null
check "denial evidence never stores a raw credential" bash -c "! grep -Fq '$OUTBOUND_SECRET' '$T'"
check "denial evidence stores a redaction marker" grep -Fq '[REDACTED POTENTIAL SECRET]' "$T"
printf 'curl 169.254.169.254 \x01\x02with control bytes\n' | "$OPS" record-denial "$T#1" \
  --actor full-stack/backend --reason "metadata credential access is forbidden" --denial-id denial-ctrl-0001 -
check "denial strips control bytes" bash -c "grep -q 'curl 169.254.169.254 *with control bytes' '$T' && ! grep -q \$'\x01' '$T'"
refuse "denial without actor refused"   "requires --actor and --reason" bash -c "printf 'x\n' | '$OPS' record-denial '$T#1' --reason r -"
refuse "denial without reason refused"  "requires --actor and --reason" bash -c "printf 'x\n' | '$OPS' record-denial '$T#1' --actor a -"
refuse "denial with empty body refused" "empty comment body"            bash -c "printf '' | '$OPS' record-denial '$T#1' --actor a --reason r -"
refuse "denial with bad id refused"     "invalid denial id"             bash -c "printf 'x\n' | '$OPS' record-denial '$T#1' --actor a --reason r --denial-id 'no spaces!' -"

# -- state: legal generic status names only --------------------------------------
"$OPS" state "$T#1" Review
"$OPS" state "$T#1" Review
check "state moves the task"      grep -q '^## 1 Add form \[Review\]$' "$T"
check "state retry is idempotent" grep -q '^## 1 Add form \[Review\]$' "$T"

# -- Blocked is enterable by the team but only a human may move it outbound ---
check "Blocked board authority is directional and human-owned" python3 - "skill/config/statuses.config.json" <<'PY'
import json,sys
board=json.load(open(sys.argv[1]))
statuses={item['name']:item for item in board['tasks']['statuses']}
assert 'Blocked' in statuses['Planned']['transitions']
blocked=statuses['Blocked']
assert blocked['owner'] == {'role': 'human'}
assert blocked['transitions'] == ['Planned', 'Active', 'Review']
assert blocked['transitionAuthority']['enter']['roles'] == ['team-lead', 'pm-agent']
assert blocked['transitionAuthority']['exit'] == {'roles': ['human'], 'automation': False}
PY
cat > held.md <<'EOF'
# Directional authority [Active]

## 1 Queued [Planned]

**Assignee:** —

## 2 Working [Active]

**Assignee:** backend

## 3 Reviewing [Review]

**Assignee:** reviewer

## 4 Already held [Blocked]

**Assignee:** backend
EOF
"$OPS" state held.md#1 Blocked
"$OPS" state held.md#2 Blocked
"$OPS" state held.md#3 Blocked
check "Planned may enter Blocked" grep -q '^## 1 Queued \[Blocked\]$' held.md
check "Active may enter Blocked"  grep -q '^## 2 Working \[Blocked\]$' held.md
check "Review may enter Blocked"  grep -q '^## 3 Reviewing \[Blocked\]$' held.md
"$OPS" state held.md#4 Blocked >/dev/null
refuse "broker refuses Blocked to Planned" "outbound \[Blocked\].*human-only" \
  "$OPS" state held.md#1 Planned
refuse "broker refuses Blocked to Active" "outbound \[Blocked\].*human-only" \
  "$OPS" state held.md#2 Active
refuse "broker refuses Blocked to Review" "outbound \[Blocked\].*human-only" \
  "$OPS" state held.md#3 Review
refuse "claim cannot release Blocked" "outbound \[Blocked\].*human-only" \
  "$OPS" claim held.md#4 backend --to Active --claim-id claim-human-hold
refuse "integration cannot release Blocked" "outbound \[Blocked\].*human-only" \
  "$OPS" integrate held.md#4 abc1234
refuse "integration broker cannot release Blocked" "outbound \[Blocked\].*human-only" \
  env STARTUP_FACTORY_INTEGRATION_BROKER=1 "$OPS" task-reopen held.md#4 Planned
check "all refused outbound transitions preserve Blocked" \
  test "$(grep -c '\[Blocked\]$' held.md)" -eq 4

cat > secure-fields.md <<'EOF'
# Secure structural fields [Planned]

## 1 Reject credential routing [Planned]

**Assignee:** —
EOF
refuse "secret-bearing assignee role is refused before mutation" "unsafe content detected in outbound assignee-role" \
  "$OPS" claim secure-fields.md#1 "$OUTBOUND_SECRET"
check "refused assignee role leaves task and assignee unchanged" bash -c \
  "grep -q '^## 1 Reject credential routing \[Planned\]$' secure-fields.md && grep -q '^\\*\\*Assignee:\\*\\* —$' secure-fields.md"

# -- integrate: terminal move + hash citation + extra body -----------------------
printf 'VALIDATE_TEST green. Merged: a.py\napi_key=%s\n' "$OUTBOUND_SECRET" | "$OPS" integrate "$T#1" abc1234 -
check "integrate terminal status" grep -q '^## 1 Add form \[Ready to deploy\]$' "$T"
check "integrate cites the hash"  grep -q 'Integrated: commit abc1234\.' "$T"
check "integrate appends body"    grep -q 'VALIDATE_TEST green\. Merged: a\.py' "$T"
check "integration comment never stores a raw credential" bash -c "! grep -Fq '$OUTBOUND_SECRET' '$T'"
check "integration comment stores a redaction marker" grep -Fq '[REDACTED POTENTIAL SECRET]' "$T"
check "integrate signed"          grep -q -- '— integrator' "$T"
printf 'VALIDATE_TEST green. Merged: a.py\n' | "$OPS" integrate "$T#1" abc1234 -
check "integrate retry is idempotent" test "$(grep -c 'Integrated: commit abc1234\.' "$T")" -eq 1

# -- export: JSON snapshot with generic statuses ----------------------------------
"$OPS" export "$T" tasks.json
check "export writes JSON" python3 -c "
import json
d = json.load(open('tasks.json'))
assert d['adapter'] == 'Markdown' and len(d['tasks']) == 2
byid = {t['taskId']: t for t in d['tasks']}
assert byid['$T#1']['status'] == 'Ready to deploy'
assert byid['$T#2']['status'] == 'Planned'
assert byid['$T#1']['assignee'] == 'backend'
assert byid['$T#2']['assignee'] is None
assert byid['$T#1']['labels'] == ['human-work', 'needs-review']
assert '[design-note]' not in byid['$T#1']['description']
assert '**Assignee:**' not in byid['$T#1']['description']
assert '**Labels:**' not in byid['$T#1']['description']
assert any('design-note' in c['body'] for c in byid['$T#1']['comments'])
assert any(c['body'].startswith('[progress]') for c in byid['$T#2']['comments'])
assert byid['$T#2']['blockedBy'] == ['$T#1'], byid['$T#2'].get('blockedBy')
assert byid['$T#1']['blockedBy'] == []
"

STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON='["human-work"]' "$OPS" export "$T" filtered-tasks.json
check "ignored label filters autonomous feature export" python3 -c "
import json
d=json.load(open('filtered-tasks.json'))
assert [task['taskId'] for task in d['tasks']] == ['$T#2']
"
refuse "malformed ignored-label policy fails closed" "must be a JSON list" \
  env STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON='{}' "$OPS" export "$T" filtered-tasks.json

# -- board scan: generic statuses, parent grouping, routing inputs ---------------
mkdir -p blocked
cat > blocked/feature.md <<'EOF'
# Operations guard [Active]

## 1 Investigate dependency [Blocked]

**Assignee:** —

team-preset: deep-infra

> [note] (2026-07-14): automation: enabled
EOF
"$OPS" scan scan.json --status Planned --status Blocked
check "scan writes versioned normalized JSON" python3 -c "
import json
d=json.load(open('scan.json'))
assert d['schemaVersion'] == 1 and d['adapter'] == 'Markdown'
assert d['statuses'] == ['Planned', 'Blocked']
assert len(d['items']) == 2, d['items']
by_status={x['status']:x for x in d['items']}
assert by_status['Planned']['taskId'].endswith('feat/feature.md#2')
assert by_status['Blocked']['featureId'].endswith('blocked/feature.md')
assert by_status['Blocked']['routingHints']['labels'] == []
assert by_status['Blocked']['revision']
assert d['orphans'] == []
"

# -- feature projection and state use their own configured state machine --------
printf '[deployment]\ncredential: %s\n' "$OUTBOUND_SECRET" | "$OPS" upsert-deployment "$T" - >/dev/null
check "deployment projection never stores a raw credential" bash -c "! grep -Fq '$OUTBOUND_SECRET' '$T'"
check "deployment projection stores a redaction marker" grep -Fq '[REDACTED POTENTIAL SECRET]' "$T"
printf '[deployment]\nstate: verifying\n' | "$OPS" upsert-deployment "$T" -
printf '[deployment]\nstate: succeeded\n' | "$OPS" upsert-deployment "$T" -
check "deployment upsert keeps one managed block" test "$(grep -c 'agent-squad:deployment:start' "$T")" -eq 1
check "deployment upsert replaces old content" grep -q '^> state: succeeded$' "$T"
"$OPS" feature-state "$T" Active
refuse "terminal feature transition requires release executor" "reserved for the isolated release executor" \
  "$OPS" feature-state "$T" Resolved
STARTUP_FACTORY_RELEASE_EXECUTOR=1 "$OPS" feature-state "$T" Resolved
check "feature-state follows configured transitions" grep -q '^# Payments revamp \[Resolved\]$' "$T"
refuse "illegal feature transition refused" "illegal \[feature\] transition" "$OPS" feature-state "$T" Active
refuse "ordinary callers cannot reopen terminal features" "reserved for the deterministic PM supervisor" \
  "$OPS" feature-reopen "$T" Planned
STARTUP_FACTORY_PM_SUPERVISOR=1 "$OPS" feature-reopen "$T" Planned
check "PM supervisor deliberately reopens terminal feature to queued" grep -q '^# Payments revamp \[Planned\]$' "$T"
refuse "feature reopen refuses a non-terminal source" "requires a terminal source" \
  env STARTUP_FACTORY_PM_SUPERVISOR=1 "$OPS" feature-reopen "$T" Active

refuse "ordinary callers cannot reopen integrated tasks" "reserved for the deterministic integration broker" \
  "$OPS" task-reopen "$T#1" Planned
STARTUP_FACTORY_INTEGRATION_BROKER=1 "$OPS" task-reopen "$T#1" Planned
check "integration broker deliberately returns terminal task to queued rework" grep -q '^## 1 Add form \[Planned\]$' "$T"
"$OPS" state "$T#1" Active >/dev/null
"$OPS" state "$T#1" Review >/dev/null
refuse "task reopen refuses a non-terminal source" "requires a commit-requiring terminal source" \
  env STARTUP_FACTORY_INTEGRATION_BROKER=1 "$OPS" task-reopen "$T#1" Planned

# -- conditional claims reject stale snapshots and preserve the existing owner --
refuse "stale conditional claim refused" "claim conflict" "$OPS" claim "$T#1" frontend --expected Planned --claim-id claim-stale-1234
check "stale claim did not change assignee" grep -q '^\*\*Assignee:\*\* backend$' "$T"

# -- comment size warning: >50 lines still posts but warns ----------------------
long="$(python3 -c "print('\n'.join('line %d' % i for i in range(60)))")"
out="$(printf '%s\n' "$long" | "$OPS" comment "$T#2" - 2>&1)"
printf '%s' "$out" | grep -q "exceeds the 50-line budget" \
  && echo "ok: oversize comment warns" || { echo "FAIL: no size warning"; FAILURES=$((FAILURES+1)); }
check "oversize comment still posted" grep -q 'line 59' "$T"

# -- fail-loud: every bad input is refused with a clear message -------------------
refuse "unknown status refused"       "unknown \[task\] status" "$OPS" state "$T#2" Nonesuch
refuse "missing task refused"         "no task 9"               "$OPS" state "$T#9" Review
refuse "bad hash refused"             "does not look like"      "$OPS" integrate "$T#2" nothash
refuse "taskId without # refused"     "feature-file"            "$OPS" state "just-a-number" Review
refuse "unknown op refused"           "usage:"                  "$OPS" frobnicate x y
refuse "empty comment body refused"   "empty comment body"      bash -c "printf '' | '$OPS' comment '$T#2' -"
refuse "missing feature file refused" "cannot read"             "$OPS" export nope/feature.md out.json
refuse "path escaping MARKDOWN_ROOT refused" "escapes MARKDOWN_ROOT" "$OPS" export ../escape.md out.json
ln -s feat linked-feat
ln -s feat/feature.md linked-feature.md
refuse "symlinked Markdown directory refused" "symlinked component" "$OPS" export linked-feat/feature.md out.json
refuse "symlinked Markdown feature refused" "symlinked component" "$OPS" export linked-feature.md out.json
refuse "unmapped adapter refused"     "no tracker-ops backend"  env TRACKER_ADAPTER=Nonesuch "$OPS" state "$T#2" Review
refuse "Markdown update-comment refused"  "append-only"  bash -c "printf 'x\n' | '$OPS' update-comment '$T#2' some-id -"
refuse "update-comment arg check"         "usage:"       "$OPS" update-comment onlyone

# -- malformed normalized sources fail closed rather than yielding ambiguity --
mkdir -p malformed
cat > malformed/duplicate-progress.md <<'EOF'
# Malformed progress [Planned]

## 1 Duplicate projection [Planned]

**Assignee:** —

<!-- agent-squad:progress:start -->
> [progress]
> first
<!-- agent-squad:progress:end -->

<!-- agent-squad:progress:start -->
> [progress]
> second
<!-- agent-squad:progress:end -->
EOF
refuse "duplicate managed progress export refused" "duplicate managed progress" \
  "$OPS" export malformed/duplicate-progress.md malformed/out.json
refuse "duplicate managed progress upsert refused" "managed progress block is duplicated" \
  bash -c "printf '[progress]\nnew\n' | '$OPS' upsert-progress malformed/duplicate-progress.md#1 -"

cat > malformed/duplicate-task.md <<'EOF'
# Duplicate task ids [Planned]

## 1 First [Planned]

**Assignee:** —

## 1 Second [Planned]

**Assignee:** —
EOF
refuse "duplicate normalized task identity refused" "duplicate task identity" \
  "$OPS" export malformed/duplicate-task.md malformed/out.json

cat > malformed/unknown-status.md <<'EOF'
# Unknown status [Planned]

## 1 Cannot map [Mystery]

**Assignee:** —
EOF
refuse "unmapped generic export status refused" "unmapped/unknown generic status" \
  "$OPS" export malformed/unknown-status.md malformed/out.json

# -- remote adapter pagination contracts run fully offline with mocked clients --
check "remote adapters exhaust paginated reads" python3 "$SKILL_DIR/tests/tracker-adapter-pagination-test.py"

echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
