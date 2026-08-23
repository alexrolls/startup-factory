#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=full
case "${1:-}" in
  "")
    ;;
  --full)
    ;;
  --smoke)
    MODE=smoke
    ;;
  -h|--help)
    cat <<'EOF'
Usage: tests/run-all.sh [--full|--smoke]

Run the full offline test suite by default. Use --smoke for a fast verification
of core security, planning, routing, acceptance, and updater behavior.
EOF
    exit 0
    ;;
  *)
    echo "run-all.sh: unknown option: $1" >&2
    echo "Usage: tests/run-all.sh [--full|--smoke]" >&2
    exit 2
    ;;
esac
[ "$#" -le 1 ] || {
  echo "run-all.sh: expected at most one option" >&2
  echo "Usage: tests/run-all.sh [--full|--smoke]" >&2
  exit 2
}

FULL_PYTHON_TESTS=(
  outbox-ingress-test.py
  standalone-workspace-test.py
  ticket-content-security-test.py
  execution-graph-test.py
  beads-protected-runtime-test.py
  beads-protected-runtime-hostile-test.py
  retrospective-test.py
  product-acceptance-test.py
  superpowers-planning-test.py
  review-evidence-test.py
  delivery-profile-test.py
  evidence-provider-test.py
  release-lifecycle-test.py
  tracker-adapter-pagination-test.py
  task-hold-test.py
  custom-tracker-release-snapshot-test.py
)
FULL_SHELL_TESTS=(
  standalone-launcher-test.sh
  runtime-boundary-linux-opt-in.sh
  update-installed-skill-test.sh
  tracker-ops-test.sh
  task-routing-test.sh
  task-runtime-test.sh
  parallel-integration-test.sh
  dispatch-test.sh
  launcher-test.sh
  safety-policy-test.sh
  pm-monitor-test.sh
  deployment-test.sh
)
SMOKE_PYTHON_TESTS=(
  ticket-content-security-test.py
  retrospective-test.py
  product-acceptance-test.py
  superpowers-planning-test.py
  review-evidence-test.py
  delivery-profile-test.py
  evidence-provider-test.py
  tracker-adapter-pagination-test.py
  beads-protected-runtime-test.py
  beads-protected-runtime-hostile-test.py
  task-hold-test.py
)
SMOKE_SHELL_TESTS=(
  update-installed-skill-test.sh
  tracker-ops-test.sh
  task-routing-test.sh
  safety-policy-test.sh
)

if [ "$MODE" = smoke ]; then
  PYTHON_TESTS=("${SMOKE_PYTHON_TESTS[@]}")
  SHELL_TESTS=("${SMOKE_SHELL_TESTS[@]}")
else
  PYTHON_TESTS=("${FULL_PYTHON_TESTS[@]}")
  SHELL_TESTS=("${FULL_SHELL_TESTS[@]}")
fi

FAILURES=()
run_test() {
  local runner="$1"
  local test="$2"
  local status

  echo "==> $test"
  if [ ! -f "$ROOT/tests/$test" ]; then
    echo "FAIL: $test is missing"
    FAILURES+=("$test (missing)")
    return
  fi

  if [ "$runner" = python ]; then
    if python3 "$ROOT/tests/$test"; then
      return
    else
      status=$?
    fi
  else
    if TEAM_RUNNER=background bash "$ROOT/tests/$test"; then
      return
    else
      status=$?
    fi
  fi

  echo "FAIL: $test exited with status $status"
  FAILURES+=("$test (exit $status)")
}

run_optional_node_test() {
  local test="$1"
  local status

  echo "==> $test"
  if ! command -v node >/dev/null 2>&1; then
    echo "SKIP: node is not installed; provider test remains optional"
    return
  fi
  if [ ! -f "$ROOT/$test" ]; then
    echo "FAIL: $test is missing"
    FAILURES+=("$test (missing)")
    return
  fi
  if node --test "$ROOT/$test"; then
    return
  else
    status=$?
  fi
  echo "FAIL: $test exited with status $status"
  FAILURES+=("$test (exit $status)")
}

echo "Running $MODE test suite"
for test in "${PYTHON_TESTS[@]}"; do
  run_test python "$test"
done
for test in "${SHELL_TESTS[@]}"; do
  run_test shell "$test"
done
if [ "$MODE" = full ]; then
  run_optional_node_test "extensions/evidence-providers/playwright/provider.test.mjs"
fi

echo "---"
if [ "${#FAILURES[@]}" -ne 0 ]; then
  echo "${#FAILURES[@]} TEST(S) FAILED:"
  for failure in "${FAILURES[@]}"; do
    echo "  - $failure"
  done
  exit 1
fi
echo "ALL TESTS PASS"
