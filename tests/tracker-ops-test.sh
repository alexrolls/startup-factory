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

# -- fixture: a skill copy configured for the Markdown adapter ------------------
cd "$TMP"
mkdir -p skill/config skill/bin
cp "$SKILL_DIR/bin/tracker-ops.sh" skill/bin/
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

Build the form.

- Field A

## 2 Wire endpoint [Planned]

**Assignee:** —
**BlockedBy:** 1

Call the endpoint.
EOF
T="feat/feature.md"

# -- generated PM surfaces: one task progress block + one feature digest -------
printf '[progress]\nstage: planned\nsummary: queued\n' | "$OPS" upsert-progress "$T#2" -
printf '[progress]\nstage: ready\nsummary: design approved\n' | "$OPS" upsert-progress "$T#2" -
check "progress upsert keeps one managed block" test "$(grep -c 'agent-squad:progress:start' "$T")" -eq 1
check "progress upsert replaces old content" grep -q '^> stage: ready$' "$T"
if grep -q '^> stage: planned$' "$T"; then echo "FAIL: stale progress retained"; FAILURES=$((FAILURES+1)); else echo "ok: stale progress removed"; fi
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

# -- comment: body from a file ---------------------------------------------------
printf 'From a file.\n' > body.txt
"$OPS" comment "$T#1" body.txt
check "comment from file"         grep -q '> note (....-..-..): From a file\.' "$T"

# -- comment-once: uncertain delivery retries stay idempotent ------------------
printf '[review-request]\nFiles: a.py\n' > delivery.txt
"$OPS" comment-once "$T#1" delivery-123 delivery.txt
"$OPS" comment-once "$T#1" delivery-123 delivery.txt
check "comment-once retry keeps one delivery" test "$(grep -c 'delivery-id: delivery-123' "$T")" -eq 1

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

# -- integrate: terminal move + hash citation + extra body -----------------------
printf 'VALIDATE_TEST green. Merged: a.py\n' | "$OPS" integrate "$T#1" abc1234 -
check "integrate terminal status" grep -q '^## 1 Add form \[Ready to deploy\]$' "$T"
check "integrate cites the hash"  grep -q 'Integrated: commit abc1234\.' "$T"
check "integrate appends body"    grep -q 'VALIDATE_TEST green\. Merged: a\.py' "$T"
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
assert '[design-note]' not in byid['$T#1']['description']
assert '**Assignee:**' not in byid['$T#1']['description']
assert any('design-note' in c['body'] for c in byid['$T#1']['comments'])
assert any(c['body'].startswith('[progress]') for c in byid['$T#2']['comments'])
assert byid['$T#2']['blockedBy'] == ['$T#1'], byid['$T#2'].get('blockedBy')
assert byid['$T#1']['blockedBy'] == []
"

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
refuse "unmapped adapter refused"     "no tracker-ops backend"  env TRACKER_ADAPTER=Nonesuch "$OPS" state "$T#2" Review
refuse "Markdown update-comment refused"  "append-only"  bash -c "printf 'x\n' | '$OPS' update-comment '$T#2' some-id -"
refuse "update-comment arg check"         "usage:"       "$OPS" update-comment onlyone

echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
