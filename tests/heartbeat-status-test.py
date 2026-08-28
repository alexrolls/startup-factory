#!/usr/bin/env python3
"""Deterministic tests for protected worker heartbeat verdicts."""

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "heartbeat_status", ROOT / "bin" / "heartbeat-status.py"
)
assert SPEC and SPEC.loader
heartbeat_status = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(heartbeat_status)


def at(hour: int, minute: int, second: int = 0) -> datetime:
    return datetime(2026, 8, 24, hour, minute, second, tzinfo=timezone.utc)


class HeartbeatStatusTest(unittest.TestCase):
    def setUp(self):
        self.record = {
            "state": "live",
            "category": "task",
            "instance": "backend--task-key--a2",
            "createdAt": "2026-08-24T18:00:00Z",
        }
        self.ttl = timedelta(minutes=15)

    def classify(self, heartbeat, now, **expectations):
        return heartbeat_status.classify(
            self.record, heartbeat, now, self.ttl, **expectations
        )

    def test_fresh_heartbeat_is_active_with_explicit_deadline(self):
        result = self.classify(
            "2026-08-24T18:10:00Z | TASK-1 | implementing | 2026-08-24T18:20:00Z",
            at(18, 12),
        )
        self.assertEqual("active", result["verdict"])
        self.assertEqual("2026-08-24T18:20:00Z", result["nextActionBy"])

    def test_deadline_cannot_extend_past_the_configured_ttl(self):
        result = self.classify(
            "2026-08-24T18:00:00Z | TASK-1 | implementing | 2026-08-24T20:00:00Z",
            at(18, 16),
        )
        self.assertEqual("stalled:no-progress", result["verdict"])
        self.assertEqual("2026-08-24T18:15:00Z", result["nextActionBy"])

    def test_stale_idle_and_gate_wait_are_distinct(self):
        idle = self.classify(
            "2026-08-24T18:00:00Z | - | idle, no assignment", at(18, 20)
        )
        waiting = self.classify(
            "2026-08-24T18:00:00Z | TASK-2 | waiting on review gate", at(18, 20)
        )
        self.assertEqual("stalled:idle-no-assignment", idle["verdict"])
        self.assertEqual("stalled:waiting-on-gate", waiting["verdict"])

    def test_missing_heartbeat_has_a_bounded_starting_window(self):
        self.assertEqual("starting", self.classify(None, at(18, 10))["verdict"])
        self.assertEqual(
            "stalled:no-heartbeat", self.classify(None, at(18, 20))["verdict"]
        )

    def test_explicit_start_grace_is_independent_of_progress_ttl(self):
        grace = timedelta(seconds=60)
        self.assertEqual(
            "starting", self.classify(None, at(18, 0, 30), start_grace=grace)["verdict"]
        )
        self.assertEqual(
            "stalled:no-heartbeat",
            self.classify(None, at(18, 1, 1), start_grace=grace)["verdict"],
        )

    def test_launcher_starting_heartbeat_uses_its_short_deadline(self):
        heartbeat = (
            "2026-08-24T18:00:00Z | TASK-1 | starting | "
            "2026-08-24T18:01:00Z"
        )
        self.assertEqual("starting", self.classify(heartbeat, at(18, 0, 30))["verdict"])
        self.assertEqual(
            "stalled:no-heartbeat", self.classify(heartbeat, at(18, 1, 1))["verdict"]
        )

    def test_starting_with_semantic_metadata_remains_starting(self):
        result = self.classify(
            "2026-08-24T18:00:00Z | TASK-1 | starting; attempt=2; progress=0 | "
            "2026-08-24T18:01:00Z",
            at(18, 0, 30),
            expected_task="TASK-1",
            expected_role="backend",
            expected_attempt=2,
        )
        self.assertEqual("starting", result["verdict"])
        self.assertEqual("starting", result["activity"])
        self.assertEqual(0, result["progressPercent"])

    def test_malformed_deadline_is_visible(self):
        result = self.classify(
            "2026-08-24T18:10:00Z | TASK-1 | implementing | someday", at(18, 12)
        )
        self.assertEqual("stalled:malformed-heartbeat", result["verdict"])
        self.assertIn("ISO-8601", result["detail"])

    def test_future_timestamp_is_never_treated_as_active(self):
        result = self.classify(
            "2026-08-24T19:00:00Z | TASK-1 | implementing | 2026-08-24T19:10:00Z",
            at(18, 12),
        )
        self.assertEqual("stalled:future-heartbeat", result["verdict"])

    def test_small_positive_clock_skew_is_accepted(self):
        result = self.classify(
            "2026-08-24T18:12:30Z | TASK-1 | implementing", at(18, 12)
        )
        self.assertEqual("active", result["verdict"])

    def test_heartbeat_before_lifecycle_creation_is_rejected_as_replay(self):
        result = self.classify(
            "2026-08-24T17:50:00Z | TASK-1 | implementing", at(18, 1)
        )
        self.assertEqual("stalled:replayed-heartbeat", result["verdict"])

    def test_within_skew_pre_generation_progress_is_never_displayed(self):
        result = self.classify(
            "2026-08-24T17:59:30Z | TASK-1 | implementing; attempt=2; progress=40",
            at(18, 0),
            expected_task="TASK-1",
            expected_role="backend",
            expected_attempt=2,
        )
        self.assertEqual("active", result["verdict"])
        self.assertIsNone(result["progressPercent"])

    def test_expected_task_binds_the_agent_written_target(self):
        heartbeat = "2026-08-24T18:10:00Z | TASK-1 | implementing"
        matching = self.classify(
            heartbeat, at(18, 12), expected_task="TASK-1"
        )
        mismatched = self.classify(
            heartbeat, at(18, 12), expected_task="TASK-2"
        )
        self.assertEqual("active", matching["verdict"])
        self.assertEqual("stalled:binding-mismatch", mismatched["verdict"])

    def test_expected_identity_binds_protected_role_attempt_and_instance(self):
        heartbeat = "2026-08-24T18:10:00Z | TASK-1 | implementing"
        matching = self.classify(
            heartbeat,
            at(18, 12),
            expected_role="backend",
            expected_attempt=2,
            expected_instance="backend--task-key--a2",
        )
        self.assertEqual("active", matching["verdict"])
        for expectation in (
            {"expected_role": "frontend"},
            {"expected_attempt": 3},
            {"expected_instance": "backend--task-key--a3"},
        ):
            with self.subTest(expectation=expectation):
                result = self.classify(heartbeat, at(18, 12), **expectation)
                self.assertEqual("stalled:binding-mismatch", result["verdict"])

    def test_progress_boundaries_are_exposed_for_the_current_attempt(self):
        for percent in (0, 100):
            with self.subTest(percent=percent):
                result = self.classify(
                    "2026-08-24T18:10:00Z | TASK-1 | "
                    f"implementing; attempt=2; progress={percent}",
                    at(18, 12),
                    expected_task="TASK-1",
                    expected_role="backend",
                    expected_attempt=2,
                )
                self.assertEqual("active", result["verdict"])
                self.assertEqual(percent, result["progressPercent"])
                self.assertEqual("2026-08-24T18:10:00Z", result["observedAt"])

    def test_progress_is_presentation_only_when_metadata_is_invalid(self):
        for state in (
            "implementing; attempt=2; progress=-1",
            "implementing; attempt=2; progress=101",
            "implementing; attempt=2; progress=1.5",
            "implementing; attempt=2; progress=40; progress=41",
            "implementing; attempt=1; progress=40",
        ):
            with self.subTest(state=state):
                result = self.classify(
                    f"2026-08-24T18:10:00Z | TASK-1 | {state}",
                    at(18, 12),
                    expected_task="TASK-1",
                    expected_role="backend",
                    expected_attempt=2,
                )
                self.assertEqual("active", result["verdict"])
                self.assertIsNone(result["progressPercent"])

    def test_progress_freshness_rejects_stale_and_future_values(self):
        stale = self.classify(
            "2026-08-24T18:06:59Z | TASK-1 | implementing; attempt=2; progress=40",
            at(18, 12),
            expected_task="TASK-1",
            expected_role="backend",
            expected_attempt=2,
        )
        future = self.classify(
            "2026-08-24T18:12:30Z | TASK-1 | implementing; attempt=2; progress=40",
            at(18, 12),
            expected_task="TASK-1",
            expected_role="backend",
            expected_attempt=2,
        )
        self.assertEqual("active", stale["verdict"])
        self.assertEqual("active", future["verdict"])
        self.assertIsNone(stale["progressPercent"])
        self.assertIsNone(future["progressPercent"])

    def test_gate_role_binding_uses_the_protected_gate_instance(self):
        self.record.update(
            {"category": "gate", "instance": "team-lead"}
        )
        result = self.classify(
            "2026-08-24T18:10:00Z | - | idle, no assignment",
            at(18, 12),
            expected_role="team-lead",
            expected_instance="team-lead",
        )
        self.assertEqual("active", result["verdict"])

    def test_cli_applies_all_expected_identity_bindings(self):
        with tempfile.TemporaryDirectory() as temp:
            heartbeat = Path(temp) / "heartbeat"
            heartbeat.write_text(
                "2026-08-24T18:10:00Z | TASK-1 | implementing\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "bin" / "heartbeat-status.py"),
                    "--heartbeat",
                    str(heartbeat),
                    "--stuck-minutes",
                    "15",
                    "--now",
                    "2026-08-24T18:12:00Z",
                    "--expected-task",
                    "TASK-1",
                    "--expected-role",
                    "backend",
                    "--expected-attempt",
                    "2",
                    "--expected-instance",
                    "backend--task-key--a2",
                ],
                input=json.dumps(self.record),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("active", json.loads(completed.stdout)["verdict"])

    def test_symlink_heartbeat_is_never_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.write_text(
                "2026-08-24T18:10:00Z | TASK-1 | implementing", encoding="utf-8"
            )
            link = root / "heartbeat"
            link.symlink_to(target)
            with self.assertRaises(heartbeat_status.HeartbeatError):
                heartbeat_status.read_heartbeat(link)


if __name__ == "__main__":
    unittest.main()
