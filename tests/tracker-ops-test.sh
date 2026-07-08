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
MARKDOWN_ROOT=.workspace/task-manager
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

Call the endpoint.
EOF
T="feat/feature.md"

# -- claim: assignee + initial→Active + claim comment ---------------------------
"$OPS" claim "$T#1" backend
check "claim sets status"        grep -q '^## 1 Add form \[Active\]$' "$T"
check "claim sets assignee"      grep -q '^\*\*Assignee:\*\* backend$' "$T"
check "claim leaves a comment"   grep -q 'Claimed — moving to \[Active\]' "$T"
check "claim comment signed"     grep -q -- '— backend' "$T"
check "sibling task untouched"   grep -q '^## 2 Wire endpoint \[Planned\]$' "$T"

# -- comment: body from stdin, marker extracted, quoting-proof ------------------
printf '[design-note] Approach: "quote" & $dollar.\nSecond line.\n' | "$OPS" comment "$T#1" -
check "comment marker extracted"  grep -q '> \[design-note\] (....-..-..): Approach: "quote" & $dollar\.' "$T"
check "comment multiline quoted"  grep -q '^> Second line\.$' "$T"

# -- comment: body from a file ---------------------------------------------------
printf 'From a file.\n' > body.txt
"$OPS" comment "$T#1" body.txt
check "comment from file"         grep -q '> note (....-..-..): From a file\.' "$T"

# -- state: legal generic status names only --------------------------------------
"$OPS" state "$T#1" Review
check "state moves the task"      grep -q '^## 1 Add form \[Review\]$' "$T"

# -- integrate: terminal move + hash citation + extra body -----------------------
printf 'VALIDATE_TEST green. Merged: a.py\n' | "$OPS" integrate "$T#1" abc1234 -
check "integrate terminal status" grep -q '^## 1 Add form \[Ready to deploy\]$' "$T"
check "integrate cites the hash"  grep -q 'Integrated: commit abc1234\.' "$T"
check "integrate appends body"    grep -q 'VALIDATE_TEST green\. Merged: a\.py' "$T"
check "integrate signed"          grep -q -- '— integrator' "$T"

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
assert any('design-note' in c['body'] for c in byid['$T#1']['comments'])
"

# -- fail-loud: every bad input is refused with a clear message -------------------
refuse "unknown status refused"       "unknown \[task\] status" "$OPS" state "$T#2" Nonesuch
refuse "missing task refused"         "no task 9"               "$OPS" state "$T#9" Review
refuse "bad hash refused"             "does not look like"      "$OPS" integrate "$T#2" nothash
refuse "taskId without # refused"     "feature-file"            "$OPS" state "just-a-number" Review
refuse "unknown op refused"           "usage:"                  "$OPS" frobnicate x y
refuse "empty comment body refused"   "empty comment body"      bash -c "printf '' | '$OPS' comment '$T#2' -"
refuse "missing feature file refused" "cannot read"             "$OPS" export nope/feature.md out.json
refuse "unmapped adapter refused"     "no tracker-ops backend"  env TRACKER_ADAPTER=Nonesuch "$OPS" state "$T#2" Review

echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
