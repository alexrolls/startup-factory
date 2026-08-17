#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "bin"))
from task_metadata import effective_review_gates, parse_task_metadata, required_review_gates

spec = importlib.util.spec_from_file_location("runtime_state", root / "bin" / "runtime-state.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
planner_spec = importlib.util.spec_from_file_location(
    "dispatch_plan", root / "bin" / "dispatch-plan.py"
)
planner = importlib.util.module_from_spec(planner_spec)
planner_spec.loader.exec_module(planner)


def profile(title, description=""):
    task = {"title": title, "description": description}
    return runtime.model_profile(task, parse_task_metadata(description, title))


for title in (
    "Add authentication middleware",
    "Fix the concurrency race",
    "Review cryptography key rotation",
):
    assert profile(title) == "strong", title

assert profile("Fix README typo") == "fast"
assert profile("Update documentation") == "fast"
assert profile("Update contributor guide", "files: docs/contributing.md") == "fast"
assert profile("Update component guide", "files: docs/component.mdx") == "standard"
assert profile(
    "Add regression test",
    "parallel-safe: true\nfiles: tests/test_widget.py",
) == "fast"
assert profile(
    "Rename local constant",
    "parallel-safe: true\nfiles: src/constants.py",
) == "fast"
assert profile(
    "Implement endpoint",
    "parallel-safe: true\nfiles: src/endpoint.py",
) == "standard"
assert profile("Update authentication docs", "files: docs/auth.md") == "strong"
assert profile("Implement auth", "model-profile: fast") == "strong"
assert profile("Implement endpoint", "model-profile: fast") == "standard"
assert profile("Fix README typo", "model-profile: standard") == "standard"

parsed = parse_task_metadata(
    "track: frontend\nparallel-safe: yes\nfiles: a.ts, b.ts\n"
    "resources: api:widget\nmodel-profile: strong\ndelivery-profile: standard\nwork-kind: defect"
    "\nreview-gates: security, qa"
)
assert parsed == {
    "parallelSafe": True,
    "files": ["a.ts", "b.ts"],
    "resources": ["api:widget"],
    "track": "frontend",
    "modelProfile": "strong",
    "deliveryProfile": "standard",
    "workKind": "defect",
    "reviewGates": ["qa", "security"],
}
assert planner.metadata(
    {
        "title": "Any",
        "description": (
            "track: frontend\nparallel-safe: yes\nfiles: a.ts, b.ts\n"
            "resources: api:widget\nmodel-profile: strong\ndelivery-profile: standard\nwork-kind: defect"
            "\nreview-gates: security, qa"
        ),
    }
) == parsed
assert parse_task_metadata("", "Browser component")["track"] == "frontend"
assert parse_task_metadata("", "Database worker")["track"] == "backend"
assert parse_task_metadata("track: llm", "Evaluate retrieval quality")["track"] == "llm"
try:
    parse_task_metadata("work-kind: maybe", "Ambiguous work")
except ValueError as exc:
    assert "work-kind" in str(exc)
else:
    raise AssertionError("invalid work-kind must fail closed")
try:
    parse_task_metadata("delivery-profile: turbo", "Ambiguous profile")
except ValueError as exc:
    assert "delivery-profile" in str(exc)
else:
    raise AssertionError("invalid delivery-profile must fail closed")
try:
    parse_task_metadata(
        "delivery-profile: standard\ndelivery-profile: micro",
        "Conflicting profile",
    )
except ValueError as exc:
    assert "more than once" in str(exc)
else:
    raise AssertionError("duplicate delivery-profile must fail closed")
try:
    parse_task_metadata("review-gates: qa, operability", "Unsupported gate")
except ValueError as exc:
    assert "review-gates" in str(exc)
else:
    raise AssertionError("unsupported review gate must fail closed")
try:
    parse_task_metadata("review-gates: qa, qa", "Duplicate gate")
except ValueError as exc:
    assert "duplicates" in str(exc)
else:
    raise AssertionError("duplicate review gate must fail closed")
assert required_review_gates("REQUIRED_REVIEW_GATES=null\n") == []
assert required_review_gates("REQUIRED_REVIEW_GATES=security\n") == ["security"]
assert effective_review_gates(
    parse_task_metadata("review-gates: qa"),
    "REQUIRED_REVIEW_GATES=security\n",
) == ["qa", "security"]
print("ALL PASS")
PY
