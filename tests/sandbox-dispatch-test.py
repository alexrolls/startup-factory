#!/usr/bin/env python3
"""Real planner routes design/review queues into concrete sandbox assignments."""
from __future__ import annotations
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = runpy.run_path(str(ROOT / "tests/sandbox-artifacts-test.py"), run_name="dispatch_git_fixture")


class SandboxDispatchTest(unittest.TestCase):
    for _method in ("setUp", "fixture_git"):
        locals()[_method] = FIXTURE["ArtifactTests"].__dict__[_method]

    def test_design_and_code_review_keep_exact_task_ids_in_json_job_assignments(self):
        (self.repo / "hello.txt").write_text("review candidate\n")
        self.fixture_git("add", "hello.txt")
        self.fixture_git("commit", "-q", "-m", "review candidate")
        head = self.fixture_git("rev-parse", "HEAD").strip().decode()
        workspace = self.repo / ".teamwork/team-one"
        workspace.mkdir(parents=True, mode=0o700)
        board = json.loads((ROOT / "config/statuses.config.json").read_text())
        kinds = {row.get("kind"): row["name"] for row in board["tasks"]["statuses"]}
        design, review = "FEATURE-1#design|one", "FEATURE-1#review|two"
        payload = {"featureId": "FEATURE-1", "tasks": [
            {"taskId": design, "title": "Design decision", "status": kinds["working"], "assignee": "backend",
             "labels": [], "description": "files: hello.txt", "blockedBy": [],
             "comments": [{"body": "[design-note]\nProposed bounded design — backend"}]},
            {"taskId": review, "title": "Code review", "status": kinds["review"], "assignee": "backend",
             "labels": [], "description": "files: hello.txt", "blockedBy": [],
             "comments": [{"body": "[review-request]\nFiles: hello.txt\nReview-Base-Commit: " + self.base +
                "\nTask-Branch-Head: " + head + "\nReview-Package-SHA256: sha256:" + "a" * 64 + "\nReview-Gates: none\n"}]},
        ]}
        (workspace / "tasks.json").write_text(json.dumps(payload))
        result = subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "bin/dispatch-plan.py"),
            "--skill", str(ROOT), "--workdir", str(workspace), "--team", "team-one", "--feature", "FEATURE-1",
            "--stuck-minutes", "15", "--execution", "sequential", "--sandbox-jobs"],
            cwd=self.repo, env={"PATH": "/usr/bin:/bin"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("\t") for line in result.stdout.decode().splitlines()]
        architecture = next(row for row in rows if row[:2] == ["launch", "principal-architect"])
        sceptical = next(row for row in rows if row[:2] == ["launch", "sceptical-architect"])
        self.assertEqual(json.loads(architecture[3]), [design, review])
        self.assertEqual(json.loads(sceptical[3]), [design, review])
        self.assertTrue(all(task != "-" for task in json.loads(architecture[3])))


if __name__ == "__main__": unittest.main()
