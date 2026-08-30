#!/usr/bin/env python3
"""Deterministic tests for the project-scoped agent health view."""

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "agent_health", ROOT / "bin" / "agent-health.py"
)
assert SPEC and SPEC.loader
agent_health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent_health)


NOW = datetime(2026, 8, 24, 18, 12, tzinfo=timezone.utc)
REPOSITORY_ID = "a" * 64
TASK_ID = "TASK-1"
TASK_KEY = "task-1-" + __import__("hashlib").sha256(TASK_ID.encode()).hexdigest()[:10]


def lifecycle_record(**changes):
    record = {
        "schemaVersion": 3,
        "repositoryId": REPOSITORY_ID,
        "team": "feature-a",
        "category": "task",
        "instance": f"backend--{TASK_KEY}--a2",
        "kind": "background",
        "pid": 1234,
        "processIdentity": "test",
        "createdAt": "2026-08-24T18:02:00Z",
        "tmuxSession": None,
        "tmuxWindow": None,
        "tmuxPane": None,
        "processGroupId": 1234,
        "sessionId": 1234,
        "tmuxPanePid": None,
        "state": "live",
    }
    record.update(changes)
    return record


def envelope(*records):
    return {
        "schemaVersion": "project-lifecycle-list-v1",
        "repositoryId": REPOSITORY_ID,
        "records": list(records),
        "legacyOmitted": 0,
        "warnings": [],
    }


class AgentHealthTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.workspace = self.repo / ".teamwork" / "feature-a"
        (self.workspace / "executions").mkdir(parents=True)
        (self.workspace / "heartbeats").mkdir()
        (self.workspace / "executions" / f"{TASK_KEY}.json").write_text(
            json.dumps(
                {
                    "taskId": TASK_ID,
                    "taskKey": TASK_KEY,
                    "role": "backend",
                    "attempt": 2,
                }
            ),
            encoding="utf-8",
        )
        self.heartbeat = self.workspace / "heartbeats" / f"backend--{TASK_KEY}--a2"

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self, record=None):
        return agent_health.build_snapshot(
            envelope(record or lifecycle_record()),
            repo=self.repo,
            teamwork_root=".teamwork",
            now=NOW,
            stuck_minutes=15,
            start_grace_seconds=60,
        )

    def test_fresh_percentage_and_elapsed_share_one_json_row(self):
        self.heartbeat.write_text(
            "2026-08-24T18:10:00Z | TASK-1 | implementing; attempt=2; progress=42\n",
            encoding="utf-8",
        )
        snapshot = self.snapshot()
        self.assertEqual("agent-health-snapshot-v1", snapshot["schemaVersion"])
        self.assertEqual(REPOSITORY_ID, snapshot["repositoryId"])
        self.assertEqual(300, snapshot["intervalSeconds"])
        self.assertIs(True, snapshot["presentationOnly"])
        self.assertEqual(1, len(snapshot["agents"]))
        row = snapshot["agents"][0]
        self.assertEqual("feature-a", row["team"])
        self.assertEqual("backend", row["role"])
        self.assertEqual(TASK_ID, row["taskId"])
        self.assertEqual(2, row["attempt"])
        self.assertEqual(42, row["progressPercent"])
        self.assertEqual("self-reported", row["progressSource"])
        self.assertEqual(600, row["elapsedSeconds"])
        self.assertEqual("active", row["verdict"])

    def test_stale_replayed_or_restarted_progress_falls_back_to_elapsed(self):
        cases = (
            "2026-08-24T18:06:59Z | TASK-1 | implementing; attempt=2; progress=40",
            "2026-08-24T18:10:00Z | TASK-1 | implementing; attempt=1; progress=40",
            "2026-08-24T18:10:00Z | TASK-OTHER | implementing; attempt=2; progress=40",
            "2026-08-24T18:10:00Z | TASK-1 | implementing; attempt=2; progress=101",
        )
        for heartbeat in cases:
            with self.subTest(heartbeat=heartbeat):
                self.heartbeat.write_text(heartbeat + "\n", encoding="utf-8")
                row = self.snapshot()["agents"][0]
                self.assertIsNone(row["progressPercent"])
                self.assertEqual(600, row["elapsedSeconds"])

    def test_future_progress_is_hidden_even_when_liveness_accepts_clock_skew(self):
        self.heartbeat.write_text(
            "2026-08-24T18:12:30Z | TASK-1 | implementing; attempt=2; progress=40\n",
            encoding="utf-8",
        )
        row = self.snapshot()["agents"][0]
        self.assertEqual("active", row["verdict"])
        self.assertIsNone(row["progressPercent"])

    def test_missing_execution_binding_never_fabricates_assignment_or_progress(self):
        (self.repo / ".teamwork" / "feature-a" / "executions" / f"{TASK_KEY}.json").unlink()
        self.heartbeat.write_text(
            "2026-08-24T18:10:00Z | TASK-1 | implementing; attempt=2; progress=80\n",
            encoding="utf-8",
        )
        snapshot = self.snapshot()
        row = snapshot["agents"][0]
        self.assertIsNone(row["taskId"])
        self.assertIsNone(row["progressPercent"])
        self.assertIn("binding", row["verdict"])
        self.assertTrue(snapshot["warnings"])

    def test_table_is_rendered_from_the_same_snapshot(self):
        self.heartbeat.write_text(
            "2026-08-24T18:10:00Z | TASK-1 | implementing; attempt=2; progress=42\n",
            encoding="utf-8",
        )
        table = agent_health.render_table(self.snapshot())
        self.assertIn("feature-a", table)
        self.assertIn("backend", table)
        self.assertIn("TASK-1", table)
        self.assertIn("42%", table)
        self.assertIn("self-reported", table)

    def test_elapsed_is_rendered_when_percentage_is_unavailable(self):
        self.heartbeat.write_text(
            "2026-08-24T18:10:00Z | TASK-1 | implementing; attempt=2\n",
            encoding="utf-8",
        )
        table = agent_health.render_table(self.snapshot())
        self.assertIn("10m", table)

    def test_exited_agent_does_not_accumulate_time_in_progress(self):
        snapshot = self.snapshot(lifecycle_record(state="dead"))
        row = snapshot["agents"][0]
        self.assertIsNone(row["elapsedSeconds"])
        self.assertIsNone(row["progressSource"])
        self.assertIsNone(row["nextActionBy"])
        self.assertIn("-", agent_health.render_table(snapshot))

    def test_identity_mismatch_never_renders_time_in_progress(self):
        snapshot = self.snapshot(lifecycle_record(state="identity-mismatch"))
        row = snapshot["agents"][0]
        self.assertEqual("identity-mismatch", row["verdict"])
        self.assertIsNone(row["elapsedSeconds"])
        self.assertIsNone(row["progressPercent"])
        self.assertIsNone(row["nextActionBy"])
        self.assertIn("identity-mismatch", agent_health.render_table(snapshot))

    def test_stalled_agent_json_uses_null_for_missing_deadline(self):
        self.heartbeat.write_text("not-a-valid-heartbeat\n", encoding="utf-8")
        snapshot = self.snapshot()
        row = snapshot["agents"][0]
        self.assertTrue(row["verdict"].startswith("stalled:"))
        self.assertIsNone(row["nextActionBy"])

    def test_dead_agent_bypasses_hostile_team_workspace(self):
        outside = self.repo / "outside-dead-workspace"
        outside.mkdir()
        self.workspace.rename(self.repo / "workspace-before-dead-swap")
        self.workspace.symlink_to(outside, target_is_directory=True)

        with mock.patch.object(
            agent_health,
            "execution_binding",
            side_effect=AssertionError("terminal agent must not read execution state"),
        ), mock.patch.object(
            agent_health,
            "heartbeat_value",
            side_effect=AssertionError("terminal agent must not read heartbeat state"),
        ):
            snapshot = self.snapshot(lifecycle_record(state="dead"))

        row = snapshot["agents"][0]
        self.assertEqual("exited", row["verdict"])
        self.assertEqual("backend", row["role"])
        self.assertIsNone(row["taskId"])
        self.assertIsNone(row["progressPercent"])
        self.assertIsNone(row["progressSource"])
        self.assertIsNone(row["elapsedSeconds"])
        self.assertIn("exited", agent_health.render_table(snapshot))

    def test_identity_mismatch_agent_bypasses_hostile_team_workspace(self):
        outside = self.repo / "outside-identity-workspace"
        outside.mkdir()
        self.workspace.rename(self.repo / "workspace-before-identity-swap")
        self.workspace.symlink_to(outside, target_is_directory=True)

        with mock.patch.object(
            agent_health,
            "execution_binding",
            side_effect=AssertionError("terminal agent must not read execution state"),
        ), mock.patch.object(
            agent_health,
            "heartbeat_value",
            side_effect=AssertionError("terminal agent must not read heartbeat state"),
        ):
            snapshot = self.snapshot(lifecycle_record(state="identity-mismatch"))

        row = snapshot["agents"][0]
        self.assertEqual("identity-mismatch", row["verdict"])
        self.assertEqual("backend", row["role"])
        self.assertIsNone(row["taskId"])
        self.assertIsNone(row["progressPercent"])
        self.assertIsNone(row["progressSource"])
        self.assertIsNone(row["elapsedSeconds"])
        self.assertIn("identity-mismatch", agent_health.render_table(snapshot))

    def test_symlinked_heartbeat_directory_fails_closed(self):
        outside = self.repo / "outside-heartbeats"
        outside.mkdir()
        (outside / self.heartbeat.name).write_text(
            "2026-08-24T18:10:00Z | TASK-1 | implementing; attempt=2; progress=90\n",
            encoding="utf-8",
        )
        self.heartbeat.parent.rmdir()
        self.heartbeat.parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(agent_health.AgentHealthError):
            self.snapshot()

    def test_execution_lookup_never_scans_large_fanout(self):
        for index in range(1000):
            (self.workspace / "executions" / f"decoy-{index}.json").write_text(
                "{}\n", encoding="utf-8"
            )
        self.heartbeat.write_text(
            "2026-08-24T18:10:00Z | TASK-1 | implementing; attempt=2; progress=42\n",
            encoding="utf-8",
        )
        with mock.patch.object(
            Path, "iterdir", side_effect=AssertionError("execution lookup must not scan")
        ):
            row = self.snapshot()["agents"][0]
        self.assertEqual(TASK_ID, row["taskId"])
        self.assertEqual(42, row["progressPercent"])

    def test_execution_ancestor_swap_after_policy_validation_fails_closed(self):
        outside = self.repo / "outside-executions"
        outside.mkdir()
        (outside / f"{TASK_KEY}.json").write_text(
            json.dumps(
                {
                    "taskId": TASK_ID,
                    "taskKey": TASK_KEY,
                    "role": "backend",
                    "attempt": 2,
                }
            ),
            encoding="utf-8",
        )
        original_child = agent_health.teamwork_path.child

        def swap_after_validation(repo, workspace, relative):
            resolved = original_child(repo, workspace, relative)
            if relative == f"executions/{TASK_KEY}.json":
                executions = self.workspace / "executions"
                executions.rename(self.workspace / "executions-before-swap")
                executions.symlink_to(outside, target_is_directory=True)
            return resolved

        with mock.patch.object(
            agent_health.teamwork_path, "child", side_effect=swap_after_validation
        ):
            with self.assertRaises(agent_health.AgentHealthError):
                self.snapshot()

    def test_heartbeat_ancestor_swap_after_policy_validation_fails_closed(self):
        outside = self.repo / "outside-heartbeats-after-validation"
        outside.mkdir()
        (outside / self.heartbeat.name).write_text(
            "2026-08-24T18:10:00Z | TASK-1 | implementing; attempt=2; progress=90\n",
            encoding="utf-8",
        )
        original_child = agent_health.teamwork_path.child

        def swap_after_validation(repo, workspace, relative):
            resolved = original_child(repo, workspace, relative)
            if relative == f"heartbeats/{self.heartbeat.name}":
                heartbeats = self.workspace / "heartbeats"
                heartbeats.rename(self.workspace / "heartbeats-before-swap")
                heartbeats.symlink_to(outside, target_is_directory=True)
            return resolved

        with mock.patch.object(
            agent_health.teamwork_path, "child", side_effect=swap_after_validation
        ):
            with self.assertRaises(agent_health.AgentHealthError):
                self.snapshot()

    def test_release_lifecycle_process_is_omitted_as_a_non_agent(self):
        snapshot = self.snapshot(
            lifecycle_record(category="release", instance="release-worker")
        )
        self.assertEqual([], snapshot["agents"])
        self.assertEqual(1, snapshot["nonAgentProcessesOmitted"])
        warning = " ".join(snapshot["warnings"]).casefold()
        self.assertIn("non-agent release process", warning)
        self.assertNotIn("release-worker", warning)

    def test_watch_emits_immediately_then_on_monotonic_deadlines(self):
        clock = [0.0]
        emitted = []

        def monotonic():
            return clock[0]

        def sleep(seconds):
            clock[0] += seconds

        def emit():
            emitted.append(clock[0])

        agent_health.watch(
            emit,
            interval_seconds=300,
            monotonic=monotonic,
            sleep=sleep,
            maximum_snapshots=3,
        )
        self.assertEqual([0.0, 300.0, 600.0], emitted)

    def test_watch_skips_missed_deadlines_after_collection_overrun(self):
        clock = [0.0]
        emitted = []

        def monotonic():
            return clock[0]

        def sleep(seconds):
            clock[0] += seconds

        def emit():
            emitted.append(clock[0])
            if len(emitted) == 1:
                clock[0] += 650

        agent_health.watch(
            emit,
            interval_seconds=300,
            monotonic=monotonic,
            sleep=sleep,
            maximum_snapshots=3,
        )
        self.assertEqual([0.0, 900.0, 1200.0], emitted)

    def test_unmanaged_snapshot_is_empty_and_explicit(self):
        snapshot = agent_health.unmanaged_snapshot(REPOSITORY_ID, NOW)
        self.assertEqual([], snapshot["agents"])
        self.assertIn("unmanaged", " ".join(snapshot["warnings"]).casefold())

    def test_linked_worktree_uses_the_primary_teamwork_host(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            primary = root / "primary"
            linked = root / "linked"
            primary.mkdir()
            subprocess.run(["git", "init", "-q", str(primary)], check=True)
            subprocess.run(
                ["git", "-C", str(primary), "config", "user.email", "health@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(primary), "config", "user.name", "Health Test"],
                check=True,
            )
            (primary / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(primary), "add", "README.md"], check=True)
            subprocess.run(
                ["git", "-C", str(primary), "commit", "-q", "-m", "fixture"], check=True
            )
            subprocess.run(
                ["git", "-C", str(primary), "worktree", "add", "-q", str(linked)],
                check=True,
            )
            workspace = primary / ".teamwork" / "feature-a"
            (workspace / "executions").mkdir(parents=True)
            (workspace / "heartbeats").mkdir()
            (workspace / "executions" / f"{TASK_KEY}.json").write_text(
                json.dumps(
                    {
                        "taskId": TASK_ID,
                        "taskKey": TASK_KEY,
                        "role": "backend",
                        "attempt": 2,
                    }
                ),
                encoding="utf-8",
            )
            (workspace / "heartbeats" / f"backend--{TASK_KEY}--a2").write_text(
                "2026-08-24T18:10:00Z | TASK-1 | implementing; attempt=2; progress=35\n",
                encoding="utf-8",
            )
            host = agent_health.canonical_teamwork_host(linked)
            self.assertEqual(primary.resolve(), host)
            snapshot = agent_health.build_snapshot(
                envelope(lifecycle_record()),
                repo=linked,
                teamwork_host=host,
                teamwork_root=".teamwork",
                now=NOW,
                stuck_minutes=15,
                start_grace_seconds=60,
            )
            self.assertEqual(35, snapshot["agents"][0]["progressPercent"])


if __name__ == "__main__":
    unittest.main()
