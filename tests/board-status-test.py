#!/usr/bin/env python3
"""Black-box tests for board-level idle and stall reporting.

Every role reaching `exited` is the normal end of a dispatch pass, so per-role
health cannot separate a board that finished from one nobody is driving.  These
tests pin that distinction.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "bin" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


board_status = load("startup_factory_board_status", "board-status.py")

NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
BOARD = json.loads((ROOT / "config" / "statuses.config.json").read_text(encoding="utf-8"))


def counts(queued: int = 0, working: int = 0, review: int = 0, blocked: int = 0) -> dict:
    return {"queued": queued, "working": working, "review": review, "blocked": blocked}


class SummarizeTest(unittest.TestCase):
    def summarize(self, **changes):
        arguments = {
            "counts": counts(),
            "pending": 0,
            "last_pass": NOW,
            "live_agents": 0,
            "now": NOW,
        }
        arguments.update(changes)
        return board_status.summarize(**arguments)

    def test_live_agents_mean_the_board_is_working(self) -> None:
        summary = self.summarize(counts=counts(queued=2), live_agents=1)
        self.assertEqual(summary["verdict"], "WORKING")

    def test_no_work_and_no_agents_is_drained_not_stalled(self) -> None:
        """The normal, healthy end of a run must not raise an alarm."""
        summary = self.summarize(last_pass=NOW - timedelta(hours=3))
        self.assertEqual(summary["verdict"], "DRAINED")

    def test_outstanding_work_with_no_agents_and_a_stale_pass_is_stalled(self) -> None:
        summary = self.summarize(
            counts=counts(queued=2),
            pending=4,
            last_pass=NOW - timedelta(minutes=31),
        )
        self.assertEqual(summary["verdict"], "STALLED")
        self.assertEqual(summary["outstanding"], 2)
        self.assertEqual(summary["undrainedArtifacts"], 4)
        self.assertEqual(summary["secondsSinceLastPass"], 31 * 60)

    def test_outstanding_work_with_a_recent_pass_is_idle_not_stalled(self) -> None:
        summary = self.summarize(
            counts=counts(queued=2), last_pass=NOW - timedelta(minutes=2)
        )
        self.assertEqual(summary["verdict"], "IDLE")

    def test_undrained_artifacts_alone_can_stall_a_board(self) -> None:
        """Verdicts waiting to publish are outstanding work even with no tasks."""
        summary = self.summarize(pending=3, last_pass=NOW - timedelta(minutes=45))
        self.assertEqual(summary["verdict"], "STALLED")

    def test_a_board_that_never_dispatched_is_stalled_when_work_waits(self) -> None:
        summary = self.summarize(counts=counts(review=1), last_pass=None)
        self.assertEqual(summary["verdict"], "STALLED")
        self.assertIsNone(summary["lastPassAt"])
        self.assertIsNone(summary["secondsSinceLastPass"])

    def test_review_work_counts_as_outstanding(self) -> None:
        summary = self.summarize(
            counts=counts(review=2), last_pass=NOW - timedelta(minutes=40)
        )
        self.assertEqual(summary["outstanding"], 2)
        self.assertEqual(summary["verdict"], "STALLED")

    def test_blocked_work_alone_does_not_stall_a_board(self) -> None:
        """Blocked tasks are waiting on a human, not on dispatch."""
        summary = self.summarize(
            counts=counts(blocked=5), last_pass=NOW - timedelta(hours=2)
        )
        self.assertEqual(summary["verdict"], "DRAINED")

    def test_a_clock_skewed_pass_never_reports_negative_age(self) -> None:
        summary = self.summarize(
            counts=counts(queued=1), last_pass=NOW + timedelta(minutes=5)
        )
        self.assertEqual(summary["secondsSinceLastPass"], 0)

    def test_the_summary_stays_presentation_only(self) -> None:
        self.assertIs(self.summarize()["presentationOnly"], True)

    def test_the_idle_threshold_is_configurable(self) -> None:
        """A pass age between the custom and default thresholds must flip."""
        arguments = {"counts": counts(queued=1), "last_pass": NOW - timedelta(minutes=8)}
        self.assertEqual(self.summarize(**arguments)["verdict"], "IDLE")
        self.assertEqual(
            self.summarize(idle_minutes=5, **arguments)["verdict"], "STALLED"
        )

    def test_the_configured_threshold_is_reported_back(self) -> None:
        self.assertEqual(self.summarize(idle_minutes=5)["idleMinutes"], 5)

    def test_a_zero_idle_threshold_is_refused(self) -> None:
        with self.assertRaises(board_status.BoardStatusError):
            self.summarize(idle_minutes=0)

    def test_the_threshold_is_inclusive_at_its_exact_boundary(self) -> None:
        """Pins >= rather than >, so the boundary cannot drift unnoticed."""
        arguments = {"counts": counts(queued=1)}
        self.assertEqual(
            self.summarize(last_pass=NOW - timedelta(minutes=15), **arguments)["verdict"],
            "STALLED",
        )
        self.assertEqual(
            self.summarize(
                last_pass=NOW - timedelta(seconds=15 * 60 - 1), **arguments
            )["verdict"],
            "IDLE",
        )


class BoardLineTest(unittest.TestCase):
    def test_the_operator_line_names_work_artifacts_and_pass_age(self) -> None:
        summary = board_status.summarize(
            counts=counts(queued=2),
            pending=4,
            last_pass=NOW - timedelta(minutes=31),
            live_agents=0,
            now=NOW,
        )
        self.assertEqual(
            board_status.board_line(summary),
            "STALLED — 2 queued tasks, 4 undrained artifacts, last pass 31m ago",
        )

    def test_singulars_read_correctly(self) -> None:
        summary = board_status.summarize(
            counts=counts(queued=1),
            pending=1,
            last_pass=NOW - timedelta(minutes=31),
            live_agents=0,
            now=NOW,
        )
        self.assertIn("1 queued task,", board_status.board_line(summary))
        self.assertIn("1 undrained artifact,", board_status.board_line(summary))

    def test_a_board_with_no_recorded_pass_says_so(self) -> None:
        summary = board_status.summarize(
            counts=counts(queued=1), pending=0, last_pass=None, live_agents=0, now=NOW
        )
        self.assertIn("no dispatch pass recorded", board_status.board_line(summary))


class CollectTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_tasks(self, statuses: list[str]) -> None:
        (self.workspace / "tasks.json").write_text(
            json.dumps(
                {
                    "tasks": [
                        {"taskId": "TASK-%d" % index, "status": status}
                        for index, status in enumerate(statuses, start=1)
                    ]
                }
            ),
            encoding="utf-8",
        )

    def collect(self, **changes):
        arguments = {
            "workspace": self.workspace,
            "board": BOARD,
            "live_agents": 0,
            "now": NOW,
        }
        arguments.update(changes)
        return board_status.collect(**arguments)

    def test_an_empty_workspace_is_drained_not_an_error(self) -> None:
        self.assertEqual(self.collect()["verdict"], "DRAINED")

    def test_counts_come_from_the_configured_status_names(self) -> None:
        self.write_tasks(["Planned", "Planned", "Review", "Active", "Blocked"])
        summary = self.collect()
        self.assertEqual(summary["queued"], 2)
        self.assertEqual(summary["review"], 1)
        self.assertEqual(summary["working"], 1)
        self.assertEqual(summary["blocked"], 1)

    def test_pending_artifacts_are_counted_from_the_outbox(self) -> None:
        pending = self.workspace / "outbox" / "pending"
        pending.mkdir(parents=True)
        for index in range(3):
            (pending / ("entry-%d.json" % index)).write_text("{}", encoding="utf-8")
        (pending / ".hidden").write_text("{}", encoding="utf-8")
        self.assertEqual(self.collect()["undrainedArtifacts"], 3)

    def test_the_dispatch_marker_is_read_when_present(self) -> None:
        (self.workspace / "dispatch.last-pass").write_text(
            "2026-09-02T11:29:00Z\n", encoding="utf-8"
        )
        self.write_tasks(["Planned"])
        summary = self.collect()
        self.assertEqual(summary["secondsSinceLastPass"], 31 * 60)
        self.assertEqual(summary["verdict"], "STALLED")

    def test_a_malformed_dispatch_marker_is_refused_not_guessed(self) -> None:
        (self.workspace / "dispatch.last-pass").write_text("yesterday\n", encoding="utf-8")
        with self.assertRaises(board_status.BoardStatusError):
            self.collect()

    def test_a_malformed_snapshot_is_refused_not_guessed(self) -> None:
        (self.workspace / "tasks.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(board_status.BoardStatusError):
            self.collect()


if __name__ == "__main__":
    unittest.main(verbosity=2)
