#!/usr/bin/env python3
"""Tests for protected team preset selection and source binding."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "bin" / "team-context.py"


class TeamContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.repository = self.base / "repo"
        self.repository.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.repository, check=True)
        self.team = "context-team"
        self.feature = "FEATURE-1"
        self.workspace = self.repository / ".teamwork" / self.team
        self.workspace.mkdir(parents=True)
        self.skill = self.base / "protected-skill"
        (self.skill / "teams").mkdir(parents=True)
        self.preset = "test-preset"
        self.source = self.skill / "teams" / f"{self.preset}.md"
        self.source.write_text(
            "# Test preset\n"
            "ROSTER=team-lead sceptical-architect integrator\n"
            "REVIEW_MODE=parallel\n"
            "REQUIRED_REVIEW_GATES=null\n"
            "PROTOCOL_TEAM_LEAD=team-lead\n"
            "PROTOCOL_SCEPTICAL_ARCHITECT=sceptical-architect\n"
            "PROTOCOL_INTEGRATOR=integrator\n",
            encoding="utf-8",
        )
        self.projection = self.workspace / "preset.env"
        self.write_exact_projection()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_exact_projection(self) -> None:
        policies = [
            line
            for line in self.source.read_text(encoding="utf-8").splitlines()
            if line.startswith(("REVIEW_MODE=", "REQUIRED_REVIEW_GATES=", "PROTOCOL_"))
        ]
        self.projection.write_text(
            f"PRESET={self.preset}\n" + "\n".join(policies) + "\n",
            encoding="utf-8",
        )

    def command(
        self, operation: str, *, preset: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable,
            str(HELPER),
            operation,
            "--repo",
            str(self.repository),
            "--workspace",
            str(self.workspace),
            "--team",
            self.team,
            "--feature",
            self.feature,
            "--skill",
            str(self.skill),
        ]
        if operation == "issue":
            arguments.extend(("--preset", preset or self.preset))
        elif preset is not None:
            arguments.extend(("--expected-preset", preset))
        return subprocess.run(arguments, text=True, capture_output=True, check=False)

    def issue(self, *, preset: str | None = None) -> dict[str, object]:
        result = self.command("issue", preset=preset)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def receipt(self) -> Path:
        receipts = self.repository / ".git" / "startup-factory-broker" / "team-contexts"
        matches = list(receipts.glob("*.json"))
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_exact_source_bound_projection_verifies(self) -> None:
        issued = self.issue()
        result = self.command("verify", preset=self.preset)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), issued)

    def test_writable_projection_cannot_change_review_or_control_authority(self) -> None:
        self.issue()
        self.projection.write_text(
            self.projection.read_text(encoding="utf-8")
            .replace("REVIEW_MODE=parallel", "REVIEW_MODE=sequential")
            .replace("PROTOCOL_TEAM_LEAD=team-lead", "PROTOCOL_TEAM_LEAD=principal-architect"),
            encoding="utf-8",
        )
        result = self.command("verify", preset=self.preset)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("projection changed after broker selection", result.stderr)
        self.assertIn("PROTOCOL_TEAM_LEAD=team-lead", self.source.read_text(encoding="utf-8"))

    def test_receipt_tamper_fails_authentication(self) -> None:
        self.issue()
        receipt = self.receipt()
        value = json.loads(receipt.read_text(encoding="utf-8"))
        value["payload"]["preset"] = "forged-preset"
        receipt.write_text(json.dumps(value) + "\n", encoding="utf-8")
        result = self.command("verify", preset=self.preset)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("receipt authentication failed", result.stderr)

    def test_protected_preset_source_drift_invalidates_receipt(self) -> None:
        self.issue()
        # Even non-policy source drift invalidates the broker's selected preset.
        self.source.write_text(
            self.source.read_text(encoding="utf-8") + "\nChanged after selection.\n",
            encoding="utf-8",
        )
        result = self.command("verify", preset=self.preset)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("protected team preset changed after broker selection", result.stderr)

    def test_issue_rejects_projection_that_does_not_match_source(self) -> None:
        self.projection.write_text(
            self.projection.read_text(encoding="utf-8").replace(
                "REVIEW_MODE=parallel", "REVIEW_MODE=sequential"
            ),
            encoding="utf-8",
        )
        result = self.command("issue")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("does not match the protected preset", result.stderr)

    def test_manual_projection_is_bound_to_exact_issued_bytes(self) -> None:
        self.projection.write_text(
            "PROTOCOL_TEAM_LEAD=team-lead\nPROTOCOL_INTEGRATOR=integrator\n",
            encoding="utf-8",
        )
        self.issue(preset="-")
        result = self.command("verify", preset="-")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.projection.write_text(
            "PROTOCOL_TEAM_LEAD=principal-architect\nPROTOCOL_INTEGRATOR=integrator\n",
            encoding="utf-8",
        )
        result = self.command("verify", preset="-")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("projection changed after broker selection", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
