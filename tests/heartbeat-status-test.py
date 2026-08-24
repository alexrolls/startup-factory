#!/usr/bin/env python3
"""Deterministic tests for worker heartbeat verdicts."""

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "heartbeat_status", ROOT / "bin" / "heartbeat-status.py"
)
assert SPEC and SPEC.loader
heartbeat_status = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(heartbeat_status)


def at(minute: int) -> datetime:
    return datetime(2026, 8, 24, 18, minute, tzinfo=timezone.utc)


class HeartbeatStatusTest(unittest.TestCase):
    def setUp(self):
        self.record = {
            "state": "live",
            "createdAt": "2026-08-24T18:00:00Z",
        }
        self.ttl = timedelta(minutes=15)

    def classify(self, heartbeat, now):
        return heartbeat_status.classify(self.record, heartbeat, now, self.ttl)

    def test_fresh_heartbeat_is_active_with_explicit_deadline(self):
        result = self.classify(
            "2026-08-24T18:10:00Z | TASK-1 | implementing | 2026-08-24T18:20:00Z",
            at(12),
        )
        self.assertEqual("active", result["verdict"])
        self.assertEqual("2026-08-24T18:20:00Z", result["nextActionBy"])

    def test_deadline_cannot_extend_past_the_configured_ttl(self):
        result = self.classify(
            "2026-08-24T18:00:00Z | TASK-1 | implementing | 2026-08-24T20:00:00Z",
            at(16),
        )
        self.assertEqual("stalled:no-progress", result["verdict"])
        self.assertEqual("2026-08-24T18:15:00Z", result["nextActionBy"])

    def test_stale_idle_and_gate_wait_are_distinct(self):
        idle = self.classify(
            "2026-08-24T18:00:00Z | - | idle, no assignment",
            at(20),
        )
        waiting = self.classify(
            "2026-08-24T18:00:00Z | TASK-2 | waiting on review gate",
            at(20),
        )
        self.assertEqual("stalled:idle-no-assignment", idle["verdict"])
        self.assertEqual("stalled:waiting-on-gate", waiting["verdict"])

    def test_missing_heartbeat_has_a_bounded_starting_window(self):
        self.assertEqual("starting", self.classify(None, at(10))["verdict"])
        self.assertEqual(
            "stalled:no-heartbeat", self.classify(None, at(20))["verdict"]
        )

    def test_malformed_deadline_is_visible(self):
        result = self.classify(
            "2026-08-24T18:10:00Z | TASK-1 | implementing | someday",
            at(12),
        )
        self.assertEqual("stalled:malformed-heartbeat", result["verdict"])

    def test_symlink_heartbeat_is_never_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.write_text("2026-08-24T18:10:00Z | TASK-1 | implementing")
            link = root / "heartbeat"
            link.symlink_to(target)
            with self.assertRaises(heartbeat_status.HeartbeatError):
                heartbeat_status.read_heartbeat(link)


if __name__ == "__main__":
    unittest.main()
