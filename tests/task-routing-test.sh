#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "bin"))
from delivery_profile import assess_task
from review_evidence import bind_request
from task_metadata import (
    effective_review_gates,
    parse_task_metadata,
    profile_forced_review_gates,
    required_review_gates,
)

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


def decision(title, description=""):
    task = {"title": title, "description": description}
    return assess_task(task)


for title in (
    "Add authentication middleware",
    "Fix the concurrency race",
    "Review cryptography key rotation",
):
    assert profile(title) == "strong", title

for title in ("Fix README typo", "Update documentation"):
    undeclared = decision(title)
    assert undeclared["effectiveProfile"] == "high-risk"
    assert "files-not-declared" in undeclared["reasons"]
    assert undeclared["deliveryPolicy"] == {
        "modelProfileFloor": "strong",
        "implementationConcurrency": "exclusive",
    }
    assert undeclared["authority"]["profileForcedReviewGates"] == ["qa", "security"]
    assert profile(title) == "strong"
for title, path in (
    ("Render the author card", "src/author.py"),
    ("Add a React hook", "src/useTheme.ts"),
    ("Update design tokens", "src/designTokens.ts"),
    ("Display the release date", "src/releaseDate.ts"),
    ("Render workshop sessions", "src/workshopSessionCard.ts"),
    ("Publish the author profile", "src/publishAuthorProfile.ts"),
):
    assert profile(title, "files: " + path) == "standard", (title, path)
for title in (
    "Harden csrfProtection",
    "Rotate refreshToken credentials",
    "Update dependency graph",
    "Run database migration",
    "Deploy to production",
    "Release v2.0",
    "Publish package to PyPI",
    "Verify webhook signature",
    "Prevent command injection",
    "Change administrator privileges",
    "Update entitlement enforcement",
    "Deploy an AWS serverless function",
):
    assert profile(title, "files: src/handler.ts") == "strong", title
assert profile("Update contributor guide", "files: docs/contributing.md") == "fast"
assert profile("Update component guide", "files: docs/component.mdx") == "standard"
assert profile(
    "Add regression test",
    "parallel-safe: true\nfiles: tests/test_widget.py",
) == "standard"
assert profile(
    "Rename local constant",
    "parallel-safe: true\nfiles: src/constants.py",
) == "standard"
assert profile(
    "Implement endpoint",
    "parallel-safe: true\nfiles: src/endpoint.py",
) == "standard"
assert profile("Update authentication docs", "files: docs/auth.md") == "strong"
assert profile("Implement auth", "model-profile: fast") == "strong"
assert profile(
    "Implement endpoint",
    "files: src/endpoint.py\nmodel-profile: fast",
) == "standard"
assert profile("Fix README typo", "model-profile: standard") == "strong"
assert profile(
    "Fix README typo",
    "files: README.md\nmodel-profile: standard",
) == "standard"

micro = decision("Update contributor guide", "files: docs/contributing.md")
standard = decision("Implement endpoint", "files: src/endpoint.py")
high = decision(
    "Change production authentication",
    "parallel-safe: true\nfiles: src/auth.py\ndelivery-profile: micro",
)
assert [micro["effectiveProfile"], standard["effectiveProfile"], high["effectiveProfile"]] == [
    "micro",
    "standard",
    "high-risk",
]
assert high["deliveryPolicy"]["modelProfileFloor"] == "strong"
assert high["deliveryPolicy"]["implementationConcurrency"] == "exclusive"
assert set(high["deliveryPolicy"]) == {"modelProfileFloor", "implementationConcurrency"}
assert high["authority"]["profileMayReduceCoreReviewModel"] is False
assert high["authority"]["distinctCoreReviewDecisionsRequired"] == 3
assert profile_forced_review_gates(high) == ["qa", "security"]
assert profile_forced_review_gates({"effectiveProfile": "invalid"}) == ["qa", "security"]
assert planner.delivery_profile_decision(
    {"title": "Implement endpoint", "description": "files: src/endpoint.py"}
) == standard
assert planner.implementation_parallel_safe(
    {
        "title": "Implement endpoint",
        "description": "parallel-safe: true\nfiles: src/endpoint.py",
    }
)
assert not planner.implementation_parallel_safe(
    {
        "title": "Change production authentication",
        "description": "parallel-safe: true\nfiles: src/auth.py",
    }
)

with tempfile.TemporaryDirectory() as temporary:
    exact_repo = Path(temporary)
    subprocess.run(["git", "init", "-q", str(exact_repo)], check=True)
    subprocess.run(
        ["git", "-C", str(exact_repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(exact_repo), "config", "user.name", "Test"],
        check=True,
    )
    (exact_repo / "README.md").write_text("base\n")
    subprocess.run(["git", "-C", str(exact_repo), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(exact_repo), "commit", "-qm", "base"], check=True)
    exact_base = subprocess.check_output(
        ["git", "-C", str(exact_repo), "rev-parse", "HEAD"], text=True
    ).strip()
    (exact_repo / "src").mkdir()
    (exact_repo / "src" / "auth.py").write_text("enabled = True\n")
    subprocess.run(["git", "-C", str(exact_repo), "add", "src/auth.py"], check=True)
    subprocess.run(["git", "-C", str(exact_repo), "commit", "-qm", "auth"], check=True)
    exact_head = subprocess.check_output(
        ["git", "-C", str(exact_repo), "rev-parse", "HEAD"], text=True
    ).strip()
    request = bind_request(
        "[review-request]\nFiles: src/auth.py\n",
        exact_base,
        exact_head,
        "sha256:" + "0" * 64,
    )
    exact_task = {
        "title": "Refresh guide",
        "description": "delivery-profile: micro",
        "comments": [{"body": request}],
    }
    exact, bound_gates, binding_valid = planner.review_delivery_profile_decision(
        exact_task, 0, exact_repo
    )
    assert binding_valid
    assert bound_gates == []
    assert exact["effectiveProfile"] == "high-risk"
    assert effective_review_gates(
        parse_task_metadata(exact_task["description"], exact_task["title"]),
        "",
        exact,
    ) == ["qa", "security"]
    review_task = {**exact_task, "status": "Review"}
    assert runtime.derive_stage(review_task, set(), "", exact_repo)[0] == "review-anomaly"
    assert runtime.derive_stage(review_task, set())[0] == "review-anomaly"

invalid, _, binding_valid = planner.review_delivery_profile_decision(
    {**exact_task, "comments": [{"body": "[review-request]\n"}]}, 0, exact_repo
)
assert not binding_valid
assert invalid["effectiveProfile"] == "high-risk"

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
assert parse_task_metadata("delivery-profile: high-risk")["deliveryProfile"] == "high-risk"
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
for malformed in (
    "model-profile: strongg",
    "model-profile:",
    "delivery-profile:",
    "review-gates:",
):
    try:
        parse_task_metadata(malformed, "Malformed metadata")
    except ValueError:
        pass
    else:
        raise AssertionError("recognized malformed/empty metadata must fail closed: " + malformed)
    assert decision("Malformed metadata", malformed)["effectiveProfile"] == "high-risk"
assert parse_task_metadata(
    "This prose contains model-profile: but is not metadata.\nfiles: README.md"
)["modelProfile"] is None
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
    parse_task_metadata(
        "files: src/auth.py\nfiles: docs/guide.md",
        "Conflicting scope",
    )
except ValueError as exc:
    assert "files" in str(exc)
else:
    raise AssertionError("duplicate files declarations must fail closed")
assert decision(
    "Conflicting scope",
    "files: src/auth.py\nfiles: docs/guide.md",
)["effectiveProfile"] == "high-risk"
try:
    parse_task_metadata(
        "review-gates: security\nreview-gates: qa",
        "Conflicting authority",
    )
except ValueError as exc:
    assert "review-gates" in str(exc)
else:
    raise AssertionError("duplicate authority metadata must fail closed")
assert decision(
    "Conflicting authority",
    "review-gates: security\nreview-gates: qa",
)["effectiveProfile"] == "high-risk"
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
assert effective_review_gates(
    parse_task_metadata("files: src/auth.py"),
    "REQUIRED_REVIEW_GATES=null\n",
    decision("Authentication change", "files: src/auth.py"),
) == ["qa", "security"]
print("ALL PASS")
PY
