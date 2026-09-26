"""The release workflow must fail closed on unprotected GitHub environments."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "packaging" / "check_release_environment.py"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def protected_environment(name: str = "release") -> dict:
    return {
        "name": name,
        "can_admins_bypass": False,
        "protection_rules": [
            {"type": "branch_policy", "id": 42},
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {"type": "User", "reviewer": {"id": 17, "login": "reviewer"}}
                ],
            },
        ],
    }


def check(payload: bytes, name: str = "release") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--name", name],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class ReleaseEnvironmentGateTests(unittest.TestCase):
    def test_independent_user_and_team_reviewers_are_accepted(self) -> None:
        for name, canonical in (("release", "Release"), ("pypi", "PyPI")):
            with self.subTest(name=name, canonical=canonical):
                payload = protected_environment(canonical)
                payload["protection_rules"][1]["reviewers"].append(
                    {"type": "Team", "reviewer": {"id": 18, "slug": "releasers"}}
                )
                result = check(json.dumps(payload).encode(), name)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_or_empty_reviewer_rule_fails_closed(self) -> None:
        for rules in (
            [],
            [{"type": "branch_policy", "id": 42}],
            [{"type": "required_reviewers", "prevent_self_review": True, "reviewers": []}],
        ):
            with self.subTest(rules=rules):
                payload = protected_environment()
                payload["protection_rules"] = rules
                self.assertEqual(check(json.dumps(payload).encode()).returncode, 1)

    def test_wrong_name_and_self_review_fail_closed(self) -> None:
        payload = protected_environment("pypi")
        self.assertEqual(check(json.dumps(payload).encode(), "release").returncode, 1)
        payload = protected_environment()
        payload["protection_rules"][1]["prevent_self_review"] = False
        self.assertEqual(check(json.dumps(payload).encode()).returncode, 1)

    def test_administrator_bypass_must_be_explicitly_disabled(self) -> None:
        for value in (True, None, 0, "false"):
            with self.subTest(value=value):
                payload = protected_environment()
                payload["can_admins_bypass"] = value
                self.assertEqual(check(json.dumps(payload).encode()).returncode, 1)
        payload = protected_environment()
        del payload["can_admins_bypass"]
        self.assertEqual(check(json.dumps(payload).encode()).returncode, 1)

    def test_malformed_reviewers_fail_closed(self) -> None:
        for entry in (
            {"type": "Bot", "reviewer": {"id": 17, "login": "bot"}},
            {"type": "User", "reviewer": {"id": True, "login": "reviewer"}},
            {"type": "User", "reviewer": {"id": 17, "login": ""}},
            {"type": "Team", "reviewer": {"id": 17, "login": "not-a-slug"}},
        ):
            with self.subTest(entry=entry):
                payload = protected_environment()
                payload["protection_rules"][1]["reviewers"] = [entry]
                self.assertEqual(check(json.dumps(payload).encode()).returncode, 1)

    def test_ambiguous_and_oversized_api_responses_fail_closed(self) -> None:
        self.assertEqual(check(b'{"name":"release","name":"pypi"}').returncode, 1)
        self.assertEqual(check(b"{" + b" " * 1_000_001).returncode, 1)
        self.assertEqual(check(b"not json").returncode, 1)

    def test_workflow_checks_both_environments_before_release_work(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("group: release-main", workflow)
        self.assertNotIn("group: release-${{ inputs.release_commit }}", workflow)
        authorize = workflow.split("  authorize:\n", 1)[1].split("\n  build:\n", 1)[0]
        publish = workflow.split("  publish:\n", 1)[1].split("\n  verify-uvx:\n", 1)[0]
        for section in (authorize, publish):
            self.assertIn("      actions: read", section)
            self.assertIn("for name in release pypi; do", section)
            self.assertIn("gh api \"repos/$GH_REPO/environments/$name\"", section)
            self.assertIn("candidate/packaging/check_release_environment.py", section)
        self.assertLess(
            authorize.index("Require live independent release environment reviewers"),
            authorize.index("Extract only bounded regular secret-free evidence blobs"),
        )
        self.assertLess(
            publish.index("Reconfirm live independent reviewers before publication"),
            publish.index("pypa/gh-action-pypi-publish"),
        )


if __name__ == "__main__":
    unittest.main()
