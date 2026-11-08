#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=full
SHARD=""
LIST=false
HELP=false
MODE_SET=false

usage() {
  cat <<'EOF'
Usage: tests/run-all.sh [--full|--smoke] [--shard NAME] [--list]

Run the complete offline suite by default, or its smoke subset. --shard selects
one independent group: dispatch, launcher, parallel-integration, task-runtime,
deployment, or core. --list prints the selected repository-relative test paths
without executing them. Every executed test reports elapsed seconds and status.
EOF
}

argument_error() {
  echo "run-all.sh: $*" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --full|--smoke)
      [ "$MODE_SET" = false ] || argument_error "specify --full or --smoke only once"
      MODE="${1#--}"
      MODE_SET=true
      shift
      ;;
    --shard)
      [ -z "$SHARD" ] || argument_error "specify --shard only once"
      [ "$#" -ge 2 ] || argument_error "--shard requires a name"
      SHARD="$2"
      [ -n "$SHARD" ] || argument_error "--shard requires a name"
      shift 2
      ;;
    --list)
      [ "$LIST" = false ] || argument_error "specify --list only once"
      LIST=true
      shift
      ;;
    -h|--help)
      [ "$HELP" = false ] || argument_error "specify --help only once"
      HELP=true
      shift
      ;;
    *) argument_error "unknown option: $1" ;;
  esac
done

SHARDS=(dispatch launcher parallel-integration task-runtime deployment core)
if [ -n "$SHARD" ]; then
  case " ${SHARDS[*]} " in
    *" $SHARD "*) ;;
    *) argument_error "unknown shard: $SHARD" ;;
  esac
fi
if [ "$HELP" = true ]; then
  usage
  exit 0
fi

# The sole inventory: runner | repository-relative path | minimum mode | shard.
# Full includes every row; smoke includes only rows marked smoke. Every row has
# exactly one shard, including the optional Node test in core.
TEST_INVENTORY=(
  "python|tests/test-runner-test.py|smoke|core"
  "python|tests/authority-bootstrap-test.py|smoke|core"
  "python|tests/machine-setup-test.py|smoke|core"
  "python|tests/machine-login-test.py|smoke|core"
  "python|tests/config-values-test.py|smoke|core"
  "python|tests/authority-config-test.py|smoke|core"
  "python|tests/beta-readiness-test.py|smoke|core"
  "python|tests/ticket-content-security-test.py|smoke|core"
  "python|tests/agent-health-test.py|smoke|core"
  "python|tests/pm-agent-health-test.py|smoke|core"
  "python|tests/heartbeat-status-test.py|smoke|core"
  "python|tests/integration-pack-test.py|smoke|core"
  "python|tests/claim-lineage-runtime-test.py|smoke|core"
  "python|tests/lineage-migration-test.py|smoke|core"
  "python|tests/worker-control-test.py|smoke|core"
  "python|tests/protected-control-policy-test.py|smoke|core"
  "python|tests/team-context-test.py|smoke|core"
  "python|tests/team-policy-test.py|smoke|core"
  "python|tests/process-lifecycle-generation-test.py|smoke|core"
  "python|tests/launch-lane-lock-test.py|smoke|core"
  "python|tests/launch-barrier-test.py|smoke|core"
  "python|tests/release-worker-test.py|smoke|core"
  "python|tests/safe-turbo-readiness-test.py|smoke|core"
  "python|tests/retrospective-test.py|smoke|core"
  "python|tests/product-acceptance-test.py|smoke|core"
  "python|tests/superpowers-planning-test.py|smoke|core"
  "python|tests/review-evidence-test.py|smoke|core"
  "python|tests/broker-evidence-test.py|smoke|core"
  "python|tests/recovery-validation-test.py|smoke|core"
  "python|tests/published-artifact-parsing-test.py|smoke|core"
  "python|tests/delivery-profile-test.py|smoke|core"
  "python|tests/evidence-provider-test.py|smoke|core"
  "python|tests/live-probe-evidence-test.py|smoke|core"
  "python|tests/review-worktree-test.py|smoke|core"
  "python|tests/environment-caveats-test.py|smoke|core"
  "python|tests/release-lifecycle-test.py|full|core"
  "python|tests/tracker-adapter-pagination-test.py|smoke|core"
  "python|tests/task-hold-test.py|smoke|core"
  "python|tests/outbox-capability-supersede-test.py|smoke|core"
  "python|tests/publication-supervisor-test.py|smoke|core"
  "python|tests/board-status-test.py|smoke|core"
  "python|tests/tracker-change-token-test.py|smoke|core"
  "python|tests/custom-tracker-release-snapshot-test.py|full|core"
  "shell|tests/update-installed-skill-test.sh|smoke|core"
  "shell|tests/tracker-ops-test.sh|smoke|core"
  "shell|tests/task-routing-test.sh|smoke|core"
  "shell|tests/task-runtime-test.sh|full|task-runtime"
  "shell|tests/parallel-integration-test.sh|full|parallel-integration"
  "shell|tests/dispatch-test.sh|full|dispatch"
  "shell|tests/launcher-test.sh|full|launcher"
  "shell|tests/safety-policy-test.sh|smoke|core"
  "shell|tests/pm-monitor-test.sh|full|core"
  "shell|tests/deployment-test.sh|full|deployment"
  "node|extensions/evidence-providers/playwright/provider.test.mjs|full|core"
)

validate_inventory() {
  local entry runner test scope shard extra previous seen_shards=" "
  local seen_tests=()
  for entry in "${TEST_INVENTORY[@]}"; do
    IFS='|' read -r runner test scope shard extra <<< "$entry"
    [ "$entry" = "$runner|$test|$scope|$shard" ] \
      || argument_error "invalid test inventory row: $entry"
    case "$runner" in python|shell|node) ;; *) argument_error "invalid test runner: $runner" ;; esac
    case "$scope" in smoke|full) ;; *) argument_error "invalid test mode: $scope" ;; esac
    case " ${SHARDS[*]} " in
      *" $shard "*) ;;
      *) argument_error "invalid inventory shard: $shard" ;;
    esac
    case "$test" in
      tests/*|extensions/*) ;;
      *) argument_error "invalid test path: $test" ;;
    esac
    case "/$test/" in
      *"/../"*|*"/./"*|*"//"*) argument_error "invalid test path: $test" ;;
    esac
    # The default expansion keeps empty arrays compatible with macOS Bash 3.2
    # under nounset. No test may execute twice, even under different runners.
    for previous in "${seen_tests[@]-}"; do
      [ "$previous" != "$test" ] || argument_error "duplicate inventory test: $test"
    done
    seen_tests+=("$test")
    seen_shards="$seen_shards$shard "
  done
  for shard in "${SHARDS[@]}"; do
    case "$seen_shards" in
      *" $shard "*) ;;
      *) argument_error "inventory has no tests for shard: $shard" ;;
    esac
  done
}
validate_inventory

SELECTED_TESTS=()
for entry in "${TEST_INVENTORY[@]}"; do
  IFS='|' read -r runner test scope shard <<< "$entry"
  [ "$MODE" != smoke ] || [ "$scope" = smoke ] || continue
  [ -z "$SHARD" ] || [ "$shard" = "$SHARD" ] || continue
  SELECTED_TESTS+=("$entry")
done
[ "${#SELECTED_TESTS[@]}" -gt 0 ] \
  || argument_error "no tests selected for $MODE mode and shard $SHARD"

if [ "$LIST" = true ]; then
  for entry in "${SELECTED_TESTS[@]}"; do
    IFS='|' read -r runner test scope shard <<< "$entry"
    printf '%s\n' "$test"
  done
  exit 0
fi

SUMMARY_FILE="${GITHUB_STEP_SUMMARY:-}"
if [ -n "$SUMMARY_FILE" ]; then
  if ! printf '### Runtime tests: %s%s\n\n| Test | Seconds | Exit | Result |\n| --- | ---: | ---: | --- |\n' \
    "$MODE" "${SHARD:+ / $SHARD}" >> "$SUMMARY_FILE"; then
    echo "run-all.sh: could not initialize the optional CI summary" >&2
    SUMMARY_FILE=""
  fi
fi

FAILURES=()
run_test() {
  local runner="$1" test="$2" started="$SECONDS" status=0 outcome=passed elapsed
  echo "==> ${test#tests/}"
  if [ ! -f "$ROOT/$test" ]; then
    status=127
    outcome=missing
    echo "FAIL: $test is missing"
  elif [ "$runner" = node ] && ! command -v node >/dev/null 2>&1; then
    outcome=skipped
    echo "SKIP: node is not installed; provider test remains optional"
  else
    case "$runner" in
      python)
        if python3 "$ROOT/$test"; then :; else status=$?; fi
        ;;
      shell)
        if TEAM_RUNNER=background bash "$ROOT/$test"; then :; else status=$?; fi
        ;;
      node)
        if node --test "$ROOT/$test"; then :; else status=$?; fi
        ;;
    esac
    if [ "$status" -ne 0 ]; then
      outcome=failed
      echo "FAIL: $test exited with status $status"
    fi
  fi
  elapsed=$((SECONDS - started))
  printf 'TEST_RESULT test=%s elapsed_seconds=%s exit_status=%s outcome=%s\n' \
    "$test" "$elapsed" "$status" "$outcome"
  if [ -n "$SUMMARY_FILE" ]; then
    printf '| `%s` | %s | %s | %s |\n' "$test" "$elapsed" "$status" "$outcome" \
      >> "$SUMMARY_FILE" || echo "run-all.sh: could not append to the optional CI summary" >&2
  fi
  if [ "$status" -ne 0 ]; then
    FAILURES+=("$test ($outcome, exit $status)")
  fi
  return 0
}

echo "Running $MODE test suite${SHARD:+ (shard: $SHARD)}"
for entry in "${SELECTED_TESTS[@]}"; do
  IFS='|' read -r runner test scope shard <<< "$entry"
  run_test "$runner" "$test"
done

echo "---"
if [ "${#FAILURES[@]}" -ne 0 ]; then
  echo "${#FAILURES[@]} TEST(S) FAILED:"
  for failure in "${FAILURES[@]}"; do
    echo "  - $failure"
  done
  exit 1
fi
echo "ALL TESTS PASS"
