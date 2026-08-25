#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GRANT = ROOT / "bin" / "control-grant.py"
POLICY = ROOT / "bin" / "restart-policy.py"


class ProtectedControlPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name).resolve()
        self.repo = base / "repo"
        self.root = base / "lifecycle"
        self.repo.mkdir()
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        key = self.root / "record-auth.key"
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)
        self.common = [
            "--root", str(self.root),
            "--repo", str(self.repo),
            "--team", "turbo-team",
            "--feature", "ENG-42",
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(self, program: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(program), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_grant_is_authenticated_and_exactly_operation_bound(self) -> None:
        operation = [
            *self.common,
            "--action", "restart-task",
            "--target", "ENG-42#7",
            "--attempt", "2",
            "--generation", "2026-08-26T10:00:00Z",
            "--control-id", "control-" + "1" * 32,
            "--reason", "authorized",
        ]
        self.assertEqual(self.invoke(GRANT, "issue", *operation).returncode, 0)
        self.assertEqual(self.invoke(GRANT, "verify", *operation).returncode, 0)
        changed = list(operation)
        changed[changed.index("ENG-42#7")] = "ENG-42#8"
        rejected = self.invoke(GRANT, "verify", *changed)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("does not match", rejected.stderr)

        changed_attempt = list(operation)
        changed_attempt[changed_attempt.index("2")] = "3"
        rejected = self.invoke(GRANT, "verify", *changed_attempt)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("does not match", rejected.stderr)

        grant_path = next((self.root / "control-grants").glob("*.json"))
        grant_path.write_text(grant_path.read_text().replace("ENG-42#7", "ENG-42#9"))
        tampered = self.invoke(GRANT, "verify", *operation)
        self.assertNotEqual(tampered.returncode, 0)
        self.assertIn("authentication failed", tampered.stderr)

    def test_restart_cap_is_protected_and_retry_is_idempotent(self) -> None:
        first = [
            *self.common,
            "--category", "task",
            "--target", "ENG-42#7",
            "--attempt", "2",
            "--generation", "2026-08-26T10:00:00Z",
            "--control-id", "control-" + "2" * 32,
            "--reason", "automatic",
            "--maximum", "1",
            "--backoff-seconds", "0",
        ]
        accepted = self.invoke(POLICY, "authorize", *first)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        replay = self.invoke(POLICY, "authorize", *first)
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertIn('"replayed":true', replay.stdout)

        second = list(first)
        second[second.index("control-" + "2" * 32)] = "control-" + "3" * 32
        refused = self.invoke(POLICY, "authorize", *second)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("circuit breaker is open", refused.stderr)

        cross_attempt = list(second)
        cross_attempt[cross_attempt.index("2")] = "3"
        refused = self.invoke(POLICY, "authorize", *cross_attempt)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("circuit breaker is open", refused.stderr)

        # The attempt is part of the protected operation binding, so neither a
        # grant nor a policy receipt can be replayed against another attempt.
        wrong_attempt = list(first[:-4])
        wrong_attempt[wrong_attempt.index("2")] = "3"
        refused = self.invoke(POLICY, "check", *wrong_attempt)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("does not match", refused.stderr)

        policy_path = next((self.root / "restart-policies").glob("*.json"))
        policy_path.write_text(policy_path.read_text().replace('"automaticCount":1', '"automaticCount":0'))
        tampered = self.invoke(POLICY, "check", *first[:-4])
        self.assertNotEqual(tampered.returncode, 0)
        self.assertIn("authentication failed", tampered.stderr)

    def test_restart_completion_durably_binds_one_replacement_generation(self) -> None:
        control = [
            *self.common,
            "--category", "gate",
            "--target", "team-lead",
            "--attempt", "0",
            "--generation", "2026-08-26T10:00:00.000001Z",
            "--control-id", "control-" + "4" * 32,
            "--reason", "authorized",
        ]
        authorized = self.invoke(
            POLICY,
            "authorize",
            *control,
            "--maximum", "2",
            "--backoff-seconds", "0",
        )
        self.assertEqual(authorized.returncode, 0, authorized.stderr)

        replacement = "2026-08-26T10:00:01.000002Z"
        completed = self.invoke(
            POLICY,
            "complete",
            *control,
            "--replacement-generation", replacement,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["completedControlId"], "control-" + "4" * 32)
        self.assertEqual(payload["completedGeneration"], replacement)
        self.assertFalse(payload["replayed"])

        replay = self.invoke(
            POLICY,
            "complete",
            *control,
            "--replacement-generation", replacement,
        )
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertTrue(json.loads(replay.stdout)["replayed"])

        changed = self.invoke(
            POLICY,
            "complete",
            *control,
            "--replacement-generation", "2026-08-26T10:00:02.000003Z",
        )
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("completion changed meaning", changed.stderr)

        checked = self.invoke(POLICY, "check", *control)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["completedGeneration"], replacement)


if __name__ == "__main__":
    unittest.main(verbosity=2)
