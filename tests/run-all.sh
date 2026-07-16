#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "==> product-acceptance-test.py"
python3 "$ROOT/tests/product-acceptance-test.py"
echo "==> superpowers-planning-test.py"
python3 "$ROOT/tests/superpowers-planning-test.py"
echo "==> review-evidence-test.py"
python3 "$ROOT/tests/review-evidence-test.py"
echo "==> release-lifecycle-test.py"
python3 "$ROOT/tests/release-lifecycle-test.py"
echo "==> tracker-adapter-pagination-test.py"
python3 "$ROOT/tests/tracker-adapter-pagination-test.py"
echo "==> task-hold-test.py"
python3 "$ROOT/tests/task-hold-test.py"
echo "==> custom-tracker-release-snapshot-test.py"
python3 "$ROOT/tests/custom-tracker-release-snapshot-test.py"
for test in update-installed-skill-test.sh tracker-ops-test.sh task-routing-test.sh task-runtime-test.sh parallel-integration-test.sh dispatch-test.sh launcher-test.sh safety-policy-test.sh pm-monitor-test.sh deployment-test.sh; do
  [ -f "$ROOT/tests/$test" ] || continue
  echo "==> $test"
  TEAM_RUNNER=background bash "$ROOT/tests/$test"
done

echo "---"
echo "ALL TESTS PASS"
