#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from team_policy import TeamPolicyError, load_team_policy


class TeamPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name).resolve() / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.workspace = self.repo / ".teamwork" / "policy-team"
        self.workspace.mkdir(parents=True)
        self.team = "policy-team"
        self.feature = "FEATURE-1"

    def issue(self, preset: str) -> None:
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "bin" / "team-context.py"),
                "issue",
                "--repo",
                str(self.repo),
                "--workspace",
                str(self.workspace),
                "--team",
                self.team,
                "--feature",
                self.feature,
                "--preset",
                preset,
                "--skill",
                str(ROOT),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    def test_no_projection_preserves_direct_manual_defaults(self) -> None:
        policy = load_team_policy(
            self.repo, self.workspace, self.team, self.feature, ROOT
        )
        self.assertIsNone(policy.preset)
        self.assertEqual("", policy.text)

    def test_projection_without_protected_authority_is_rejected(self) -> None:
        (self.workspace / "preset.env").write_text(
            "PROTOCOL_TEAM_LEAD=attacker-controlled-reviewer\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(TeamPolicyError, "without protected context"):
            load_team_policy(self.repo, self.workspace, self.team, self.feature, ROOT)

    def test_named_preset_uses_protected_source_and_rejects_projection_tamper(self) -> None:
        source = (ROOT / "teams" / "full-stack.md").read_text(encoding="utf-8")
        projection = [
            line
            for line in source.splitlines()
            if line.startswith(
                ("REVIEW_MODE=", "REQUIRED_REVIEW_GATES=", "PROTOCOL_")
            )
        ]
        path = self.workspace / "preset.env"
        path.write_text(
            "PRESET=full-stack\n" + "\n".join(projection) + "\n",
            encoding="utf-8",
        )
        self.issue("full-stack")
        policy = load_team_policy(
            self.repo, self.workspace, self.team, self.feature, ROOT
        )
        self.assertEqual("full-stack", policy.preset)
        self.assertEqual(source, policy.text)

        original_projection = path.read_text(encoding="utf-8")
        path.unlink()
        with self.assertRaisesRegex(TeamPolicyError, "verification failed"):
            load_team_policy(self.repo, self.workspace, self.team, self.feature, ROOT)
        path.write_text(original_projection, encoding="utf-8")

        path.write_text(path.read_text().replace("team-lead", "forged-team-lead", 1))
        with self.assertRaisesRegex(TeamPolicyError, "verification failed"):
            load_team_policy(self.repo, self.workspace, self.team, self.feature, ROOT)

    def test_authenticated_manual_projection_is_allowed_but_not_mutable(self) -> None:
        path = self.workspace / "preset.env"
        projection = "PROTOCOL_TEAM_LEAD=custom-team-lead\n"
        path.write_text(projection, encoding="utf-8")
        self.issue("-")
        policy = load_team_policy(
            self.repo, self.workspace, self.team, self.feature, ROOT
        )
        self.assertEqual("-", policy.preset)
        self.assertEqual(projection, policy.text)

        path.write_text("PROTOCOL_TEAM_LEAD=attacker\n", encoding="utf-8")
        with self.assertRaisesRegex(TeamPolicyError, "verification failed"):
            load_team_policy(self.repo, self.workspace, self.team, self.feature, ROOT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
