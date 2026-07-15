#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE="$ROOT/bin/release-feature.py"
TMP="$(mktemp -d /private/tmp/startup-factory-deployment.XXXXXX)"
cleanup() {
  if [ "${KEEP_DEPLOYMENT_TMP:-0}" = "1" ]; then
    echo "kept deployment fixture: $TMP" >&2
    return
  fi
  chmod -R u+w "$TMP" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
FAILURES=0

check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok: $desc"; else echo "FAIL: $desc"; FAILURES=$((FAILURES+1)); fi
}

refuse() {
  local desc="$1" needle="$2" out; shift 2
  if out="$($@ 2>&1)"; then
    echo "FAIL: $desc (accepted)"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$out" | grep -q "$needle"; then
    echo "ok: $desc"
  else
    echo "FAIL: $desc ($out)"; FAILURES=$((FAILURES+1))
  fi
}

FAKE="$TMP/fake-release"
cat > "$FAKE" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mode="$1"; shift
artifact="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
case "$mode" in
  plan)
    plan="$1"; commit="$2"; environment="$3"; target="$4"; source_digest="$5"
    [ -z "${FAKE_SECRET+x}" ] || { echo "planning hook received production credential" >&2; exit 70; }
    [ "${FAKE_PLAN_FAIL:-0}" != "1" ] || exit 75
    [ ! -e untracked-only.txt ] || { echo "plan saw untracked repository bytes" >&2; exit 76; }
    python3 - "$plan" "$commit" "$environment" "$target" "$source_digest" <<'PY'
import json,sys
json.dump({
  "schemaVersion":1,
  "environment":sys.argv[3],
  "commit":sys.argv[2],
  "target":{"id":sys.argv[4]},
  "sourceArchiveDigest":sys.argv[5],
  "artifactDigest":"sha256:"+"a"*64,
  "changes":[{
    "action":"UPDATE","resourceClass":"application","resourceId":"api",
    "destructive":False,"reversible":True,"publicExposure":False,
    "dataEffect":"none","estimatedCostDelta":0,
    "secretValueAccess":False,"privilegeEscalation":False,"disablesSafeguard":False
  }],
  "rollback":{"automaticSafe":True,"previousArtifactDigest":"sha256:"+"b"*64}
},open(sys.argv[1],"w"))
PY
    printf 'plan\n' >> "$FAKE_LOG"
    ;;
  status)
    release_id="$1"
    if [ "${FAKE_REOPEN_BEFORE_APPLY:-0}" = "1" ] && [ ! -f "$FAKE_STATE.reopened" ]; then
      python3 - "$FAKE_REOPEN_FEATURE_PATH" <<'PY'
import pathlib,sys
path=pathlib.Path(sys.argv[1]); text=path.read_text()
path.write_text(text.replace('## 1 Ship immutable artifact [Ready to deploy]',
                             '## 1 Ship immutable artifact [Planned]',1))
PY
      printf 'reopened\n' > "$FAKE_STATE.reopened"
    fi
    state="not-applied"; [ ! -f "$FAKE_STATE" ] || state="$(cat "$FAKE_STATE")"
    case "$state" in
      applied-new) printf '{"state":"applied","artifactDigest":"%s","releaseId":"%s"}\n' "$artifact" "$release_id" ;;
      applied-old) printf '{"state":"applied","artifactDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","releaseId":"%s"}\n' "$release_id" ;;
      *) printf '{"state":"not-applied","currentArtifactDigest":"sha256:%064d"}\n' 0 | sed 's/0/b/g' ;;
    esac
    printf 'status:%s\n' "$state" >> "$FAKE_LOG"
    ;;
  apply)
    printf 'applied-new\n' > "$FAKE_STATE"
    printf 'apply\n' >> "$FAKE_LOG"
    ;;
  verify)
    printf 'secret=%s\n' "${FAKE_SECRET:-missing}" >&2
    printf 'verify\n' >> "$FAKE_LOG"
    if [ "${FAKE_VERIFY_FAIL:-0}" = "1" ]; then
      printf '{"healthy":false,"artifactDigest":"%s"}\n' "$artifact"
    else
      printf '{"healthy":true,"artifactDigest":"%s"}\n' "$artifact"
    fi
    ;;
  rollback)
    printf 'applied-old\n' > "$FAKE_STATE"
    printf 'rollback\n' >> "$FAKE_LOG"
    ;;
  approve)
    manifest="$1"
    [ "${APPROVE:-0}" = "1" ] || exit 4
    python3 - "$manifest" <<'PY'
import hashlib,json,sys
m=json.load(open(sys.argv[1]))
digest="sha256:"+hashlib.sha256(json.dumps(m,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
json.dump({
  "schemaVersion":1,"approved":True,"manifestDigest":digest,"nonce":m["nonce"],
  "approver":{"id":"release-manager@example.test"},"approvalId":"approval-fixture-0001",
  "approvedAt":m["createdAt"],"expiresAt":m["expiresAt"],
},sys.stdout)
PY
    ;;
  attest)
    feature_digest="$1"; team="$2"; commit="$3"; source_digest="$4"; evidence="$5"; product="$6"
    python3 - "$feature_digest" "$team" "$commit" "$source_digest" "$evidence" "$product" <<'PY'
import json,sys
from datetime import datetime,timedelta,timezone
feature_digest,team,commit,source_digest,evidence,product=sys.argv[1:]
issued=datetime.now(timezone.utc)
json.dump({
  "schemaVersion":1,"trusted":True,"featureIdDigest":feature_digest,"team":team,"commit":commit,
  "sourceArchiveDigest":source_digest,
  "integrationEvidenceDigest":evidence,"productAcceptanceDigest":product,
  "roleIsolation":True,"approvalAuthenticity":True,
  "planningIsolation":True,
  "isolationProvider":"fixture-os-sandbox","attestationId":"delivery-fixture-"+commit[:16],
  "planningIsolationProvider":"fixture-planning-sandbox",
  "issuedAt":issued.isoformat(timespec="seconds"),
  "expiresAt":(issued+timedelta(minutes=10)).isoformat(timespec="seconds"),
},sys.stdout)
PY
    printf 'attest\n' >> "$FAKE_LOG"
    ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$FAKE"

CREDENTIALS="$TMP/release.env"
printf 'FAKE_SECRET=super-sensitive-value\n' > "$CREDENTIALS"
chmod 600 "$CREDENTIALS"

CONFIG="$TMP/deployment.json"
STATE_ROOT="$TMP/release-state"
mkdir -m 700 "$STATE_ROOT"
python3 - "$CONFIG" "$FAKE" "$CREDENTIALS" "$STATE_ROOT" "$ROOT" <<'PY'
import hashlib,json,pathlib,sys
path,hook,credentials,state_root,root=sys.argv[1:]
def digest(path):
  return "sha256:"+hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
trusted={name:digest(pathlib.Path(root)/rel) for name,rel in {
  "release-feature.py":"bin/release-feature.py",
  "policy-check.py":"bin/policy-check.py",
  "tracker-ops.sh":"bin/tracker-ops.sh",
  "finalize-integrations.sh":"bin/finalize-integrations.sh",
  "task-hold.py":"bin/task-hold.py",
  "outbox_capability.py":"bin/outbox_capability.py",
  "broker_evidence.py":"bin/broker_evidence.py",
  "runtime-state.py":"bin/runtime-state.py",
  "task_metadata.py":"bin/task_metadata.py",
  "product_acceptance.py":"bin/product_acceptance.py",
  "statuses.config.json":"config/statuses.config.json",
  "guardrails.config.json":"config/guardrails.config.json",
  "team.config.md":"config/team.config.md",
  "project-management.config.md":"config/project-management.config.md",
  "teamwork-path.py":"bin/teamwork-path.py",
  "review_evidence.py":"bin/review_evidence.py",
}.items()}
json.dump({
  "schemaVersion":1,
  "enabled":True,
  "mode":"automatic",
  "environment":"production",
  "trustedBaseRef":"main",
  "target":{"id":"prod-fixture"},
  "stateRoot":state_root,
  "approvalTtlSeconds":900,
  "deliveryAttestationTtlSeconds":900,
  "planningIsolation":{
    "enforced":True,"provider":"fixture-planning-sandbox","separateIdentity":True,
    "credentialPathsUnmounted":True,"statePathsUnmounted":True,"productionEgress":False
  },
  "gitLfsPolicy":"reject-pointers",
  "maxSourceArchiveBytes":10485760,
  "maxSourceBytes":10485760,
  "maxSourceFiles":10000,
  "trustedPath":"/usr/bin:/bin",
  "credentialEnvFile":credentials,
  "credentialEnvironmentAllowlist":["FAKE_SECRET"],
  "planningEnvironmentAllowlist":["PATH","TMPDIR","LANG","FAKE_LOG","FAKE_PLAN_FAIL"],
  "trackerEnvironmentAllowlist":["PATH","TMPDIR","LANG","TRACKER_ADAPTER"],
  "environmentAllowlist":["PATH","TMPDIR","LANG","FAKE_STATE","FAKE_LOG","FAKE_VERIFY_FAIL","FAKE_REOPEN_BEFORE_APPLY","FAKE_REOPEN_FEATURE_PATH"],
  "trustedCodeDigests":trusted,
  "trustedHookDigests":{name:digest(hook) for name in ["plan","apply","status","verify","rollback","verifyDelivery"]},
  "hooks":{
    "plan":[hook,"plan","{plan_file}","{commit}","{environment}","{target_id}","{source_archive_digest}"],
    "apply":[hook,"apply","{release_id}","{artifact_digest}","{authorization_expires_at}"],
    "status":[hook,"status","{release_id}"],
    "verify":[hook,"verify","{release_id}","{artifact_digest}"],
    "rollback":[hook,"rollback","{release_id}","{plan_file}"],
    "verifyDelivery":[hook,"attest","{feature_id_digest}","{team}","{commit}","{source_archive_digest}","{integration_evidence_digest}","{product_acceptance_digest}"],
    "verifyApproval":None
  },
  "timeoutsSeconds":{"plan":30,"apply":30,"status":30,"verify":30,"rollback":30,"verifyDelivery":30,"verifyApproval":30}
},open(path,"w"))
PY

make_fixture() {
  local repo="$1" team="$2"
  mkdir -p "$repo"
  git -C "$repo" init -q -b "$team"
  git -C "$repo" config user.email test@example.com
  git -C "$repo" config user.name Test
  printf '.workspace/\n.teamwork/\n' > "$repo/.gitignore"
  printf 'release fixture\n' > "$repo/app.txt"
  git -C "$repo" add .gitignore app.txt
  git -C "$repo" commit -qm init
  git -C "$repo" branch main
  mkdir -p "$repo/.workspace/task-manager/feat" "$repo/.teamwork/$team/integrations"
  cat > "$repo/.workspace/task-manager/feat/feature.md" <<'EOF'
# Production delivery [Active]

## 1 Ship immutable artifact [Review]

**Assignee:** backend

parallel-safe: true
files: app.txt

> [review-request] round: 1
> Files: app.txt
>
> - backend

> [review-approval] round: 1
> Files: app.txt
>
> - reviewer

> [architecture-approval] round: 1
> Files: app.txt
>
> - principal-architect
EOF
  local fid="$repo/.workspace/task-manager/feat/feature.md"
  local tid="$fid#1" key branch wt
  key="$(python3 "$ROOT/bin/runtime-state.py" key "$tid")"
  branch="agent-task/$team/$key"
  wt="$(cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/launch-team.sh" worktree "$team" backend "$tid" 1 | tail -1)"
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/task-packet.sh" "$team" "$fid" "$tid" backend 1 "$wt" "$branch" >/dev/null)
  printf 'release fixture integrated\n' > "$wt/app.txt"
  git -C "$wt" add app.txt
  git -C "$wt" commit -qm 'task checkpoint'
  local package base head package_digest snapshot request_template request_body
  local review_template review_body architecture_template architecture_body sceptical_template sceptical_body
  package="$(cd "$repo" && "$ROOT/bin/review-package.sh" "$team" "$tid")"
  base="$(sed -n 's/^Base: //p' "$package")"
  head="$(sed -n 's/^Head: //p' "$package")"
  package_digest="$(python3 - "$package" <<'PY'
import hashlib,pathlib,sys
print('sha256:'+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
  snapshot="$repo/.teamwork/$team/tasks.json"
  request_template="$TMP/$key-review-request-template.md"
  request_body="$TMP/$key-review-request.md"
  review_template="$TMP/$key-review-template.md"
  review_body="$TMP/$key-review.md"
  architecture_template="$TMP/$key-architecture-template.md"
  architecture_body="$TMP/$key-architecture.md"
  sceptical_template="$TMP/$key-sceptical-template.md"
  sceptical_body="$TMP/$key-sceptical.md"
  printf '[review-request] round: 2\nFiles: app.txt\n\n— backend\n' > "$request_template"
  python3 "$ROOT/bin/review_evidence.py" bind-request \
    "$request_template" "$base" "$head" "$package_digest" "$request_body"
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" comment "$tid" "$request_body" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" export "$fid" "$snapshot" >/dev/null)
  printf '[review-approval] round: 2\nFiles: app.txt\n\n— reviewer\n' > "$review_template"
  printf '[architecture-approval] round: 2\nFiles: app.txt\n\n— principal-architect\n' > "$architecture_template"
  printf '[sceptical-architecture-approval] round: 2\nFiles: app.txt\n\n— sceptical-architect\n' > "$sceptical_template"
  python3 "$ROOT/bin/review_evidence.py" bind-approval \
    "$review_template" "$snapshot" "$tid" "$review_body"
  python3 "$ROOT/bin/review_evidence.py" bind-approval \
    "$architecture_template" "$snapshot" "$tid" "$architecture_body"
  python3 "$ROOT/bin/review_evidence.py" bind-approval \
    "$sceptical_template" "$snapshot" "$tid" "$sceptical_body"
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" comment "$tid" "$review_body" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" comment "$tid" "$architecture_body" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" comment "$tid" "$sceptical_body" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" export "$fid" "$snapshot" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/integrate-task.sh" "$team" "$fid" "$tid" backend 1 >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/finalize-integrations.sh" --authorize-prepared "$team" "$fid" \
    "$repo/.teamwork/$team/integrations/.prepared/$key.json" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/integrate-task.sh" "$team" "$fid" "$tid" backend 1 >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/finalize-integrations.sh" "$team" "$fid" >/dev/null)
}

integrate_generation_two() {
  local repo="$1" prior_team="$2" team="$3"
  local fid="$repo/.workspace/task-manager/feat/feature.md"
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    STARTUP_FACTORY_PM_SUPERVISOR=1 "$ROOT/bin/tracker-ops.sh" feature-reopen "$fid" Planned >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" feature-state "$fid" Active >/dev/null)
  git -C "$repo" switch -q -c "$team" "$prior_team"
  cat >> "$fid" <<'EOF'

## 2 Deliver generation two [Review]

**Assignee:** backend

parallel-safe: true
files: generation-2.txt

> [review-request] round: 1
> Files: generation-2.txt
>
> - backend

> [review-approval] round: 1
> Files: generation-2.txt
>
> - reviewer

> [architecture-approval] round: 1
> Files: generation-2.txt
>
> - principal-architect
EOF
  local tid="$fid#2" key branch wt package base head package_digest snapshot
  local request_template request_body review_template review_body architecture_template architecture_body sceptical_template sceptical_body
  key="$(python3 "$ROOT/bin/runtime-state.py" key "$tid")"
  branch="agent-task/$team/$key"
  wt="$(cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/launch-team.sh" worktree "$team" backend "$tid" 1 | tail -1)"
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/task-packet.sh" "$team" "$fid" "$tid" backend 1 "$wt" "$branch" >/dev/null)
  printf 'generation two\n' > "$wt/generation-2.txt"
  git -C "$wt" add generation-2.txt
  git -C "$wt" commit -qm 'generation two checkpoint'
  package="$(cd "$repo" && "$ROOT/bin/review-package.sh" "$team" "$tid")"
  base="$(sed -n 's/^Base: //p' "$package")"
  head="$(sed -n 's/^Head: //p' "$package")"
  package_digest="$(python3 - "$package" <<'PY'
import hashlib,pathlib,sys
print('sha256:'+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
  snapshot="$repo/.teamwork/$team/tasks.json"
  request_template="$TMP/$key-generation-request-template.md"
  request_body="$TMP/$key-generation-request.md"
  review_template="$TMP/$key-generation-review-template.md"
  review_body="$TMP/$key-generation-review.md"
  architecture_template="$TMP/$key-generation-architecture-template.md"
  architecture_body="$TMP/$key-generation-architecture.md"
  sceptical_template="$TMP/$key-generation-sceptical-template.md"
  sceptical_body="$TMP/$key-generation-sceptical.md"
  printf '[review-request] round: 2\nFiles: generation-2.txt\n\n— backend\n' > "$request_template"
  python3 "$ROOT/bin/review_evidence.py" bind-request \
    "$request_template" "$base" "$head" "$package_digest" "$request_body"
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" comment "$tid" "$request_body" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" export "$fid" "$snapshot" >/dev/null)
  printf '[review-approval] round: 2\nFiles: generation-2.txt\n\n— reviewer\n' > "$review_template"
  printf '[architecture-approval] round: 2\nFiles: generation-2.txt\n\n— principal-architect\n' > "$architecture_template"
  printf '[sceptical-architecture-approval] round: 2\nFiles: generation-2.txt\n\n— sceptical-architect\n' > "$sceptical_template"
  python3 "$ROOT/bin/review_evidence.py" bind-approval \
    "$review_template" "$snapshot" "$tid" "$review_body"
  python3 "$ROOT/bin/review_evidence.py" bind-approval \
    "$architecture_template" "$snapshot" "$tid" "$architecture_body"
  python3 "$ROOT/bin/review_evidence.py" bind-approval \
    "$sceptical_template" "$snapshot" "$tid" "$sceptical_body"
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" comment "$tid" "$review_body" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" comment "$tid" "$architecture_body" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" comment "$tid" "$sceptical_body" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" export "$fid" "$snapshot" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/integrate-task.sh" "$team" "$fid" "$tid" backend 1 >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/finalize-integrations.sh" --authorize-prepared "$team" "$fid" \
    "$repo/.teamwork/$team/integrations/.prepared/$key.json" >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/integrate-task.sh" "$team" "$fid" "$tid" backend 1 >/dev/null)
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/finalize-integrations.sh" "$team" "$fid" >/dev/null)
}

prime_product_approval() {
  local repo="$1" team="$2" config="$3" state="$4" log="$5"
  local fid="$repo/.workspace/task-manager/feat/feature.md" out="$TMP/product-prime-$team.out" rc
  local approval_body="$TMP/product-prime-$team-approval.md" anchor
  set +e
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
      FAKE_STATE="$state" FAKE_LOG="$log" FAKE_VERIFY_FAIL=0 APPROVE=0 \
      "$RELEASE" --repository "$repo" --workspace "$repo/.teamwork/$team" \
      --team "$team" --feature "$fid" --config "$config" >"$out" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 4 ] || { echo "product prime failed for $team (rc=$rc): $(cat "$out")" >&2; return 1; }
  grep -q 'awaiting authorization:.*product' "$out" || {
    echo "product prime did not stop at the product gate for $team: $(cat "$out")" >&2; return 1;
  }
  anchor="$(python3 - "$fid" "$repo/.teamwork/$team/product-acceptance-request.json" "$approval_body" <<'PY'
import json,sys
feature,request_path,body_path=sys.argv[1:]
request=json.load(open(request_path))
assert request['featureId']==feature
open(body_path,'w').write(request['canonicalBody']+'\n')
print(request['anchorTaskId'])
PY
)"
  (cd "$repo" && env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$repo" \
    "$ROOT/bin/tracker-ops.sh" comment "$anchor" "$approval_body" >/dev/null)
}

SUCCESS_REPO="$TMP/success"
SUCCESS_TEAM="factory-success"
make_fixture "$SUCCESS_REPO" "$SUCCESS_TEAM"
SUCCESS_FID="$SUCCESS_REPO/.workspace/task-manager/feat/feature.md"
SUCCESS_STATE="$TMP/success.state"
SUCCESS_LOG="$TMP/success.log"
printf 'must never reach release planning\n' > "$SUCCESS_REPO/untracked-only.txt"
mkdir -p "$SUCCESS_REPO/.teamwork/$SUCCESS_TEAM/deployments/forged"
printf '{"schemaVersion":1,"phase":"succeeded"}\n' > "$SUCCESS_REPO/.teamwork/$SUCCESS_TEAM/deployments/forged/transaction.json"

prime_product_approval "$SUCCESS_REPO" "$SUCCESS_TEAM" "$CONFIG" "$SUCCESS_STATE" "$SUCCESS_LOG"
check "missing feature-level product approval is a retryable wait" grep -q '^> state: awaiting-product-approval$' "$SUCCESS_FID"
check "product gate stops before planning or apply" bash -c "[ ! -f '$SUCCESS_LOG' ] || { ! grep -qE '^(plan|apply)$' '$SUCCESS_LOG'; }"

# The protected base ref may advance while product approval is pending. Its
# moving tip stays out of stable evidence. The chain base must remain in the
# protected history, but an unrelated advance does not rewrite the reviewed
# feature chain or invalidate its approval.
SUCCESS_MAIN_TREE="$(git -C "$SUCCESS_REPO" rev-parse 'main^{tree}')"
SUCCESS_MAIN_NEXT="$(printf 'advance protected base\n' | git -C "$SUCCESS_REPO" commit-tree "$SUCCESS_MAIN_TREE" -p main)"
git -C "$SUCCESS_REPO" update-ref refs/heads/main "$SUCCESS_MAIN_NEXT"

env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$SUCCESS_REPO" \
    FAKE_STATE="$SUCCESS_STATE" FAKE_LOG="$SUCCESS_LOG" FAKE_VERIFY_FAIL=0 \
    "$RELEASE" --repository "$SUCCESS_REPO" --workspace "$SUCCESS_REPO/.teamwork/$SUCCESS_TEAM" \
    --team "$SUCCESS_TEAM" --feature "$SUCCESS_FID" --config "$CONFIG" >/dev/null

check "automatic release executes plan/apply/status/verify" bash -c "grep -q '^plan$' '$SUCCESS_LOG' && grep -q '^apply$' '$SUCCESS_LOG' && grep -q '^verify$' '$SUCCESS_LOG'"
check "legitimate protected-base advance preserves reviewed release evidence" \
  test "$(git -C "$SUCCESS_REPO" rev-parse main)" = "$SUCCESS_MAIN_NEXT"
check "successful release moves feature to terminal status" grep -q '^# Production delivery \[Resolved\]$' "$SUCCESS_FID"
check "successful release projects deployment state" grep -q '^> state: succeeded$' "$SUCCESS_FID"
TXN="$(find "$STATE_ROOT" -path '*/transaction.json' -print -quit)"
check "successful transaction is durable and source-bound" python3 -c "import json; d=json.load(open('$TXN')); assert d['phase']=='succeeded' and d['artifactDigest'].startswith('sha256:') and d['sourceArchiveDigest'].startswith('sha256:') and d['productAcceptanceDigest'].startswith('sha256:') and d['productAcceptanceConsumedAt']"
check "automatic release requires a source-bound role-isolation attestation" python3 -c "import json; t=json.load(open('$TXN')); d=json.load(open('$(dirname "$TXN")/delivery-attestation.json')); assert t['deliveryAttestationDigest'].startswith('sha256:') and t['deliveryAttestationId'].startswith('delivery-fixture-') and d['sourceArchiveDigest']==t['sourceArchiveDigest']"
check "release plan sees only exact committed source" bash -c "[ ! -e '$(dirname "$TXN")/source/untracked-only.txt' ] && python3 -c \"import json; t=json.load(open('$TXN')); p=json.load(open('$(dirname "$TXN")/plan.json')); m=json.load(open('$(dirname "$TXN")/approval-manifest.json')); assert p['sourceArchiveDigest']==t['sourceArchiveDigest']==m['sourceArchiveDigest']\""
check "trusted helpers execute from protected pinned copies" bash -c "test -x '$STATE_ROOT/trusted-code/'*/bin/tracker-ops.sh && test -x '$STATE_ROOT/trusted-code/'*/bin/finalize-integrations.sh"
check "release state is outside the agent workspace" bash -c "case '$TXN' in '$SUCCESS_REPO'/*) exit 1;; *) exit 0;; esac"
check "forged agent-workspace transaction cannot skip apply" grep -q '^apply$' "$SUCCESS_LOG"
check "release logs redact credential values" bash -c "grep -R -q 'REDACTED' '$(dirname "$TXN")/logs' && ! grep -R -q 'super-sensitive-value' '$(dirname "$TXN")/logs'"

env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$SUCCESS_REPO" \
    FAKE_STATE="$SUCCESS_STATE" FAKE_LOG="$SUCCESS_LOG" FAKE_VERIFY_FAIL=0 \
    "$RELEASE" --repository "$SUCCESS_REPO" --workspace "$SUCCESS_REPO/.teamwork/$SUCCESS_TEAM" \
    --team "$SUCCESS_TEAM" --feature "$SUCCESS_FID" --config "$CONFIG" >/dev/null
check "retry is idempotent and never reapplies" test "$(grep -c '^apply$' "$SUCCESS_LOG")" -eq 1
check "retry keeps one deployment projection" test "$(grep -c 'agent-squad:deployment:start' "$SUCCESS_FID")" -eq 1

python3 - "$TXN" "$(dirname "$TXN")/delivery-attestation.json" <<'PY'
import hashlib,json,sys
from datetime import datetime,timedelta,timezone
transaction_path,proof_path=sys.argv[1:]
proof=json.load(open(proof_path))
issued=datetime.now(timezone.utc)-timedelta(minutes=20)
proof['issuedAt']=issued.isoformat(timespec='seconds')
proof['expiresAt']=(issued+timedelta(minutes=10)).isoformat(timespec='seconds')
json.dump(proof,open(proof_path,'w'))
digest='sha256:'+hashlib.sha256(json.dumps(proof,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
transaction=json.load(open(transaction_path)); transaction['deliveryAttestationDigest']=digest
json.dump(transaction,open(transaction_path,'w'))
PY
env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$SUCCESS_REPO" \
    FAKE_STATE="$SUCCESS_STATE" FAKE_LOG="$SUCCESS_LOG" FAKE_VERIFY_FAIL=0 \
    "$RELEASE" --repository "$SUCCESS_REPO" --workspace "$SUCCESS_REPO/.teamwork/$SUCCESS_TEAM" \
    --team "$SUCCESS_TEAM" --feature "$SUCCESS_FID" --config "$CONFIG" >/dev/null
check "expired historical attestation cannot strand post-apply recovery" test "$(grep -c '^apply$' "$SUCCESS_LOG")" -eq 1

# A second delivery generation keeps the same repository/release group but uses
# a fresh team workspace and branch. Its transaction chain starts at the exact
# previously verified commit, while the protected predecessor manifest carries
# unchanged terminal task evidence that is absent from the new workspace.
GEN2_TEAM="factory-success-g2"
mv "$SUCCESS_REPO/untracked-only.txt" "$TMP/success-untracked-only.txt"
integrate_generation_two "$SUCCESS_REPO" "$SUCCESS_TEAM" "$GEN2_TEAM"
check "generation two keeps prior integration evidence untouched" \
  test -f "$SUCCESS_REPO/.teamwork/$SUCCESS_TEAM/integrations/$(python3 "$ROOT/bin/runtime-state.py" key "$SUCCESS_FID#1").json"
check "generation two uses a fresh integration workspace" \
  test ! -e "$SUCCESS_REPO/.teamwork/$GEN2_TEAM/integrations/$(python3 "$ROOT/bin/runtime-state.py" key "$SUCCESS_FID#1").json"
printf 'not-applied\n' > "$SUCCESS_STATE"
prime_product_approval "$SUCCESS_REPO" "$GEN2_TEAM" "$CONFIG" "$SUCCESS_STATE" "$SUCCESS_LOG"
env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$SUCCESS_REPO" \
    FAKE_STATE="$SUCCESS_STATE" FAKE_LOG="$SUCCESS_LOG" FAKE_VERIFY_FAIL=0 \
    "$RELEASE" --repository "$SUCCESS_REPO" --workspace "$SUCCESS_REPO/.teamwork/$GEN2_TEAM" \
    --team "$GEN2_TEAM" --feature "$SUCCESS_FID" --config "$CONFIG" >/dev/null
GEN2_TXN="$(find "$STATE_ROOT" -path '*/transaction.json' -exec grep -q "$GEN2_TEAM" {} \; -print -quit)"
check "generation two reaches verified production success" python3 - "$GEN2_TXN" <<'PY'
import json,sys
t=json.load(open(sys.argv[1])); assert t['phase']=='succeeded' and t['team']=='factory-success-g2'
PY
check "generation two evidence binds the prior verified release and inherited task" \
  python3 - "$(dirname "$GEN2_TXN")/integration-evidence.json" "$SUCCESS_FID#1" "$SUCCESS_FID#2" <<'PY'
import json,sys
e=json.load(open(sys.argv[1]))
assert e['chainTrust']['kind']=='prior-verified-release'
assert e['inheritedTasks']==[sys.argv[2]]
assert [item['taskId'] for item in e['transactions']]==[sys.argv[3]]
assert e['inheritedEvidence'][0]['taskId']==sys.argv[2]
PY
check "generation two performs an independent production apply" test "$(grep -c '^apply$' "$SUCCESS_LOG")" -eq 2

REFRESH_REPO="$TMP/attestation-refresh"
REFRESH_TEAM="factory-attestation-refresh"
make_fixture "$REFRESH_REPO" "$REFRESH_TEAM"
REFRESH_FID="$REFRESH_REPO/.workspace/task-manager/feat/feature.md"
REFRESH_STATE="$TMP/attestation-refresh.state"
REFRESH_LOG="$TMP/attestation-refresh.log"
prime_product_approval "$REFRESH_REPO" "$REFRESH_TEAM" "$CONFIG" "$REFRESH_STATE" "$REFRESH_LOG"
set +e
env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$REFRESH_REPO" \
    FAKE_STATE="$REFRESH_STATE" FAKE_LOG="$REFRESH_LOG" FAKE_VERIFY_FAIL=0 FAKE_PLAN_FAIL=1 \
    "$RELEASE" --repository "$REFRESH_REPO" --workspace "$REFRESH_REPO/.teamwork/$REFRESH_TEAM" \
    --team "$REFRESH_TEAM" --feature "$REFRESH_FID" --config "$CONFIG" >/dev/null 2>&1
refresh_fail_rc=$?
set -e
check "pre-apply refresh fixture records attestation before plan failure" test "$refresh_fail_rc" -ne 0
REFRESH_TXN="$(find "$STATE_ROOT" -path '*/transaction.json' -exec grep -q "$REFRESH_TEAM" {} \; -print -quit)"
python3 - "$REFRESH_TXN" "$(dirname "$REFRESH_TXN")/delivery-attestation.json" <<'PY'
import hashlib,json,sys
from datetime import datetime,timedelta,timezone
transaction_path,proof_path=sys.argv[1:]
proof=json.load(open(proof_path))
issued=datetime.now(timezone.utc)-timedelta(minutes=20)
proof['issuedAt']=issued.isoformat(timespec='seconds')
proof['expiresAt']=(issued+timedelta(minutes=10)).isoformat(timespec='seconds')
json.dump(proof,open(proof_path,'w'))
digest='sha256:'+hashlib.sha256(json.dumps(proof,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
transaction=json.load(open(transaction_path)); transaction['deliveryAttestationDigest']=digest
json.dump(transaction,open(transaction_path,'w'))
PY
env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$REFRESH_REPO" \
    FAKE_STATE="$REFRESH_STATE" FAKE_LOG="$REFRESH_LOG" FAKE_VERIFY_FAIL=0 FAKE_PLAN_FAIL=0 \
    "$RELEASE" --repository "$REFRESH_REPO" --workspace "$REFRESH_REPO/.teamwork/$REFRESH_TEAM" \
    --team "$REFRESH_TEAM" --feature "$REFRESH_FID" --config "$CONFIG" >/dev/null
check "expired pre-apply attestation is refreshed before production" test "$(grep -c '^attest$' "$REFRESH_LOG")" -eq 2
check "attestation refresh invalidates and safely rebuilds the release plan" python3 -c "import json; d=json.load(open('$REFRESH_TXN')); assert d['phase']=='succeeded' and d['productAcceptanceConsumedAt']"

FENCE_REPO="$TMP/preapply-fence"
FENCE_TEAM="factory-preapply-fence"
make_fixture "$FENCE_REPO" "$FENCE_TEAM"
FENCE_FID="$FENCE_REPO/.workspace/task-manager/feat/feature.md"
FENCE_STATE="$TMP/preapply-fence.state"
FENCE_LOG="$TMP/preapply-fence.log"
prime_product_approval "$FENCE_REPO" "$FENCE_TEAM" "$CONFIG" "$FENCE_STATE" "$FENCE_LOG"
refuse "pre-apply fence rejects a task reopened after planning" "not every \[task\] is in the commit-requiring terminal status" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$FENCE_REPO" \
      FAKE_STATE="$FENCE_STATE" FAKE_LOG="$FENCE_LOG" FAKE_VERIFY_FAIL=0 FAKE_REOPEN_BEFORE_APPLY=1 \
      FAKE_REOPEN_FEATURE_PATH="$FENCE_FID" \
      "$RELEASE" --repository "$FENCE_REPO" --workspace "$FENCE_REPO/.teamwork/$FENCE_TEAM" \
      --team "$FENCE_TEAM" --feature "$FENCE_FID" --config "$CONFIG"
check "pre-apply tracker/evidence fence prevents apply" bash -c "[ ! -f '$FENCE_LOG' ] || ! grep -q '^apply$' '$FENCE_LOG'"

PUSH_REPO="$TMP/product-pushback"
PUSH_TEAM="factory-product-pushback"
make_fixture "$PUSH_REPO" "$PUSH_TEAM"
PUSH_FID="$PUSH_REPO/.workspace/task-manager/feat/feature.md"
PUSH_STATE="$TMP/product-pushback.state"
PUSH_LOG="$TMP/product-pushback.log"
prime_product_approval "$PUSH_REPO" "$PUSH_TEAM" "$CONFIG" "$PUSH_STATE" "$PUSH_LOG"
cat >> "$PUSH_FID" <<'EOF'

> [product-pushback]
> reason: end-to-end acceptance criterion regressed
EOF
set +e
env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$PUSH_REPO" \
    FAKE_STATE="$PUSH_STATE" FAKE_LOG="$PUSH_LOG" FAKE_VERIFY_FAIL=0 \
    "$RELEASE" --repository "$PUSH_REPO" --workspace "$PUSH_REPO/.teamwork/$PUSH_TEAM" \
    --team "$PUSH_TEAM" --feature "$PUSH_FID" --config "$CONFIG" > "$TMP/product-pushback.out" 2>&1
pushback_rc=$?
set -e
check "later product pushback is a retryable authorization wait" test "$pushback_rc" -eq 4
check "product pushback blocks before plan/apply" bash -c "[ ! -f '$PUSH_LOG' ] || ! grep -qE '^(plan|apply)$' '$PUSH_LOG'"
check "product pushback wait is visible in tracker" grep -q '^> state: awaiting-product-approval$' "$PUSH_FID"

FAIL_REPO="$TMP/failure"
FAIL_TEAM="factory-failure"
make_fixture "$FAIL_REPO" "$FAIL_TEAM"
FAIL_FID="$FAIL_REPO/.workspace/task-manager/feat/feature.md"
FAIL_STATE="$TMP/failure.state"
FAIL_LOG="$TMP/failure.log"
prime_product_approval "$FAIL_REPO" "$FAIL_TEAM" "$CONFIG" "$FAIL_STATE" "$FAIL_LOG"
refuse "failed independent verification never reports success" "production verification failed" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$FAIL_REPO" \
      FAKE_STATE="$FAIL_STATE" FAKE_LOG="$FAIL_LOG" FAKE_VERIFY_FAIL=1 \
      "$RELEASE" --repository "$FAIL_REPO" --workspace "$FAIL_REPO/.teamwork/$FAIL_TEAM" \
      --team "$FAIL_TEAM" --feature "$FAIL_FID" --config "$CONFIG"
FAIL_TXN="$(find "$STATE_ROOT" -path '*/transaction.json' -exec grep -q 'factory-failure' {} \; -print -quit)"
check "health failure uses only predeclared safe rollback" bash -c "[ \"\$(grep -c '^apply$' '$FAIL_LOG')\" -eq 1 ] && [ \"\$(grep -c '^rollback$' '$FAIL_LOG')\" -eq 1 ]"
check "rolled-back transaction is terminal and explicit" python3 -c "import json; assert json.load(open('$FAIL_TXN'))['phase']=='rolled-back'"
check "rollback never marks feature resolved" grep -q '^# Production delivery \[Active\]$' "$FAIL_FID"
check "rollback state is projected to tracker" grep -q '^> state: rolled-back$' "$FAIL_FID"

APPROVAL_REPO="$TMP/approval"
APPROVAL_TEAM="factory-approval"
make_fixture "$APPROVAL_REPO" "$APPROVAL_TEAM"
APPROVAL_FID="$APPROVAL_REPO/.workspace/task-manager/feat/feature.md"
APPROVAL_STATE="$TMP/approval.state"
APPROVAL_LOG="$TMP/approval.log"
APPROVAL_CONFIG="$TMP/deployment-approval.json"
python3 - "$CONFIG" "$APPROVAL_CONFIG" "$FAKE" <<'PY'
import hashlib,json,pathlib,sys
source,target,hook=sys.argv[1:]
d=json.load(open(source)); d["mode"]="approval-required"
d["hooks"]["verifyApproval"]=[hook,"approve","{manifest_file}"]
d["trustedHookDigests"]["verifyApproval"]="sha256:"+hashlib.sha256(pathlib.Path(hook).read_bytes()).hexdigest()
d["planningEnvironmentAllowlist"].append("APPROVE")
json.dump(d,open(target,"w"))
PY
prime_product_approval "$APPROVAL_REPO" "$APPROVAL_TEAM" "$APPROVAL_CONFIG" "$APPROVAL_STATE" "$APPROVAL_LOG"
set +e
env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$APPROVAL_REPO" \
    FAKE_STATE="$APPROVAL_STATE" FAKE_LOG="$APPROVAL_LOG" FAKE_VERIFY_FAIL=0 APPROVE=0 \
    "$RELEASE" --repository "$APPROVAL_REPO" --workspace "$APPROVAL_REPO/.teamwork/$APPROVAL_TEAM" \
    --team "$APPROVAL_TEAM" --feature "$APPROVAL_FID" --config "$APPROVAL_CONFIG" > "$TMP/approval-wait.out" 2>&1
approval_wait_rc=$?
set -e
check "missing external approval is a retryable wait" test "$approval_wait_rc" -eq 4
check "approval wait is visible in tracker" grep -q '^> state: awaiting-approval$' "$APPROVAL_FID"
check "approval wait never applies" bash -c "! grep -q '^apply$' '$APPROVAL_LOG'"

env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$APPROVAL_REPO" \
    FAKE_STATE="$APPROVAL_STATE" FAKE_LOG="$APPROVAL_LOG" FAKE_VERIFY_FAIL=0 APPROVE=1 \
    "$RELEASE" --repository "$APPROVAL_REPO" --workspace "$APPROVAL_REPO/.teamwork/$APPROVAL_TEAM" \
    --team "$APPROVAL_TEAM" --feature "$APPROVAL_FID" --config "$APPROVAL_CONFIG" >/dev/null
APPROVAL_TXN="$(find "$STATE_ROOT" -path '*/transaction.json' -exec grep -q 'factory-approval' {} \; -print -quit)"
check "exact expiring approval is consumed once" python3 -c "import json; d=json.load(open('$APPROVAL_TXN')); assert d['phase']=='succeeded' and d['approvalConsumedAt'] and d['approvalProofDigest'].startswith('sha256:')"
APPROVAL_MANIFEST="$(dirname "$APPROVAL_TXN")/approval-manifest.json"
check "approval binds target product acceptance nonce expiry and hook argv" python3 -c "import json; d=json.load(open('$APPROVAL_MANIFEST')); assert d['target']['id']=='prod-fixture' and d['productAcceptanceDigest'].startswith('sha256:') and len(d['nonce'])==64 and d['expiresAt'] and d['hookBindings']['apply']['argv']"

BAD_TRUST="$TMP/deployment-bad-trust.json"
python3 - "$CONFIG" "$BAD_TRUST" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d["trustedCodeDigests"]["release-feature.py"]="sha256:"+"0"*64
json.dump(d,open(sys.argv[2],"w"))
PY
refuse "modified release executor is rejected by external trust pins" "digest does not match" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$APPROVAL_REPO" \
      FAKE_STATE="$APPROVAL_STATE" FAKE_LOG="$APPROVAL_LOG" FAKE_VERIFY_FAIL=0 \
      "$RELEASE" --repository "$APPROVAL_REPO" --workspace "$APPROVAL_REPO/.teamwork/$APPROVAL_TEAM" \
      --team "$APPROVAL_TEAM" --feature "$APPROVAL_FID" --config "$BAD_TRUST"

ALT_WORKSPACE="$APPROVAL_REPO/.teamwork/not-the-team"
mkdir -p "$ALT_WORKSPACE"
refuse "release refuses a caller-selected noncanonical integration workspace" "canonical configured TEAMWORK_ROOT/team" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$APPROVAL_REPO" \
      "$RELEASE" --repository "$APPROVAL_REPO" --workspace "$ALT_WORKSPACE" \
      --team "$APPROVAL_TEAM" --feature "$APPROVAL_FID" --config "$APPROVAL_CONFIG"

NO_ATTEST="$TMP/deployment-no-attestor.json"
python3 - "$CONFIG" "$NO_ATTEST" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d['hooks']['verifyDelivery']=None; d['trustedHookDigests'].pop('verifyDelivery',None)
json.dump(d,open(sys.argv[2],'w'))
PY
refuse "automatic production refuses an un-attested agent team" "needs a protected verifyDelivery" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$APPROVAL_REPO" \
      "$RELEASE" --repository "$APPROVAL_REPO" --workspace "$APPROVAL_REPO/.teamwork/$APPROVAL_TEAM" \
      --team "$APPROVAL_TEAM" --feature "$APPROVAL_FID" --config "$NO_ATTEST"

NO_PLAN_ISOLATION="$TMP/deployment-no-planning-isolation.json"
python3 - "$CONFIG" "$NO_PLAN_ISOLATION" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d.pop('planningIsolation',None)
json.dump(d,open(sys.argv[2],'w'))
PY
refuse "production refuses source planning without a protected isolation contract" "planningIsolation must contain exactly" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$APPROVAL_REPO" \
      "$RELEASE" --repository "$APPROVAL_REPO" --workspace "$APPROVAL_REPO/.teamwork/$APPROVAL_TEAM" \
      --team "$APPROVAL_TEAM" --feature "$APPROVAL_FID" --config "$NO_PLAN_ISOLATION"

NO_PROVIDER_DEADLINE="$TMP/deployment-no-provider-deadline.json"
python3 - "$CONFIG" "$NO_PROVIDER_DEADLINE" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d['hooks']['apply']=[token for token in d['hooks']['apply'] if token != '{authorization_expires_at}']
json.dump(d,open(sys.argv[2],'w'))
PY
refuse "production apply must enforce authorization expiry provider-side" "apply hook must receive" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$APPROVAL_REPO" \
      "$RELEASE" --repository "$APPROVAL_REPO" --workspace "$APPROVAL_REPO/.teamwork/$APPROVAL_TEAM" \
      --team "$APPROVAL_TEAM" --feature "$APPROVAL_FID" --config "$NO_PROVIDER_DEADLINE"

INTERPRETER_CONFIG="$TMP/deployment-interpreter.json"
python3 - "$CONFIG" "$INTERPRETER_CONFIG" <<'PY'
import hashlib,json,pathlib,sys
d=json.load(open(sys.argv[1])); shell='/bin/bash'
d['hooks']['verifyDelivery']=[shell,d['hooks']['verifyDelivery'][0],'attest','{feature_id_digest}','{team}','{commit}','{source_archive_digest}','{integration_evidence_digest}','{product_acceptance_digest}']
d['trustedHookDigests']['verifyDelivery']='sha256:'+hashlib.sha256(pathlib.Path(shell).read_bytes()).hexdigest()
json.dump(d,open(sys.argv[2],'w'))
PY
INTERPRETER_REPO="$TMP/interpreter"
INTERPRETER_TEAM="factory-interpreter"
make_fixture "$INTERPRETER_REPO" "$INTERPRETER_TEAM"
INTERPRETER_FID="$INTERPRETER_REPO/.workspace/task-manager/feat/feature.md"
prime_product_approval "$INTERPRETER_REPO" "$INTERPRETER_TEAM" "$INTERPRETER_CONFIG" "$TMP/interpreter.state" "$TMP/interpreter.log"
refuse "production hooks cannot use a generic interpreter with an unpinned script" "dedicated pinned executable/wrapper" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$INTERPRETER_REPO" \
      "$RELEASE" --repository "$INTERPRETER_REPO" --workspace "$INTERPRETER_REPO/.teamwork/$INTERPRETER_TEAM" \
      --team "$INTERPRETER_TEAM" --feature "$INTERPRETER_FID" --config "$INTERPRETER_CONFIG"

CHAIN_REPO="$TMP/chain-gap"
CHAIN_TEAM="factory-chain-gap"
make_fixture "$CHAIN_REPO" "$CHAIN_TEAM"
CHAIN_FID="$CHAIN_REPO/.workspace/task-manager/feat/feature.md"
printf 'unreviewed branch mutation\n' > "$CHAIN_REPO/unreviewed.txt"
git -C "$CHAIN_REPO" add unreviewed.txt
git -C "$CHAIN_REPO" commit -qm 'unreviewed direct feature commit'
refuse "release requires feature HEAD to equal the final reviewed integration commit" "feature HEAD is not the final reviewed integration commit" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$CHAIN_REPO" \
      FAKE_STATE="$TMP/chain.state" FAKE_LOG="$TMP/chain.log" FAKE_VERIFY_FAIL=0 \
      "$RELEASE" --repository "$CHAIN_REPO" --workspace "$CHAIN_REPO/.teamwork/$CHAIN_TEAM" \
      --team "$CHAIN_TEAM" --feature "$CHAIN_FID" --config "$CONFIG"

REBIND_REPO="$TMP/rebind"
REBIND_TEAM="factory-rebind"
make_fixture "$REBIND_REPO" "$REBIND_TEAM"
REBIND_FID="$REBIND_REPO/.workspace/task-manager/feat/feature.md"
REBIND_CONFIG="$TMP/deployment-rebind.json"
cp "$APPROVAL_CONFIG" "$REBIND_CONFIG"
prime_product_approval "$REBIND_REPO" "$REBIND_TEAM" "$REBIND_CONFIG" "$TMP/rebind.state" "$TMP/rebind.log"
set +e
env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$REBIND_REPO" \
    FAKE_STATE="$TMP/rebind.state" FAKE_LOG="$TMP/rebind.log" FAKE_VERIFY_FAIL=0 APPROVE=0 \
    "$RELEASE" --repository "$REBIND_REPO" --workspace "$REBIND_REPO/.teamwork/$REBIND_TEAM" \
    --team "$REBIND_TEAM" --feature "$REBIND_FID" --config "$REBIND_CONFIG" >/dev/null 2>&1
rebind_wait_rc=$?
set -e
check "rebind fixture reaches approval wait" test "$rebind_wait_rc" -eq 4
python3 - "$REBIND_CONFIG" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d['hooks']['apply'].append('changed-after-approval'); json.dump(d,open(p,'w'))
PY
refuse "post-approval deployment config changes invalidate the transaction" "bound to different release inputs" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$REBIND_REPO" \
      FAKE_STATE="$TMP/rebind.state" FAKE_LOG="$TMP/rebind.log" FAKE_VERIFY_FAIL=0 APPROVE=1 \
      "$RELEASE" --repository "$REBIND_REPO" --workspace "$REBIND_REPO/.teamwork/$REBIND_TEAM" \
      --team "$REBIND_TEAM" --feature "$REBIND_FID" --config "$REBIND_CONFIG"

DISABLED="$TMP/disabled.json"
python3 - "$CONFIG" "$DISABLED" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d['enabled']=False
json.dump(d,open(sys.argv[2],'w'))
PY
set +e
env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$FAIL_REPO" \
    "$RELEASE" --repository "$FAIL_REPO" --workspace "$FAIL_REPO/.teamwork/$FAIL_TEAM" \
    --team "$FAIL_TEAM" --feature "$FAIL_FID" --config "$DISABLED" > "$TMP/disabled.out" 2>&1
disabled_rc=$?
set -e
check "deployment defaults can stop safely without side effects" test "$disabled_rc" -eq 4

STRING_DISABLED="$TMP/string-disabled.json"
python3 - "$CONFIG" "$STRING_DISABLED" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d['enabled']='false'
json.dump(d,open(sys.argv[2],'w'))
PY
refuse "string false cannot enable production delivery" "enabled must be true or false" \
  env TRACKER_ADAPTER=Markdown TRACKER_PROJECT_ROOT="$FAIL_REPO" \
      "$RELEASE" --repository "$FAIL_REPO" --workspace "$FAIL_REPO/.teamwork/$FAIL_TEAM" \
      --team "$FAIL_TEAM" --feature "$FAIL_FID" --config "$STRING_DISABLED"

echo "---"
[ "$FAILURES" -eq 0 ] && echo "ALL PASS" || { echo "$FAILURES FAILURE(S)"; exit 1; }
