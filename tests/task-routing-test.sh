#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "bin"))
from task_metadata import parse_task_metadata

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
assert profile("Implement auth", "model-profile: fast") == "fast"

parsed = parse_task_metadata(
    "track: frontend\nparallel-safe: yes\nfiles: a.ts, b.ts\n"
    "resources: api:widget\nmodel-profile: strong"
)
assert parsed == {
    "parallelSafe": True,
    "files": ["a.ts", "b.ts"],
    "resources": ["api:widget"],
    "track": "frontend",
    "modelProfile": "strong",
}
assert planner.metadata(
    {
        "title": "Any",
        "description": (
            "track: frontend\nparallel-safe: yes\nfiles: a.ts, b.ts\n"
            "resources: api:widget\nmodel-profile: strong"
        ),
    }
) == parsed
assert parse_task_metadata("", "Browser component")["track"] == "frontend"
assert parse_task_metadata("", "Database worker")["track"] == "backend"
assert parse_task_metadata("track: llm", "Evaluate retrieval quality")["track"] == "llm"
print("ALL PASS")
PY
