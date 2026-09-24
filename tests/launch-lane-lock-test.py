#!/usr/bin/env python3
"""Concurrency regression tests for the protected launcher-lane lock."""

from __future__ import annotations

import os
import fcntl
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
LANE_LOCK = ROOT / "bin" / "launch-lane-lock.py"


class LaunchLaneLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        subprocess.run(
            ["git", "-C", str(self.repo), "init", "--quiet"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "-c",
                "user.name=Launch Lane Test",
                "-c",
                "user.email=launch-lane@example.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "fixture",
            ],
            check=True,
            capture_output=True,
        )
        self.lifecycle_root = self.base / "lifecycle"
        self.lifecycle_root.mkdir(mode=0o700)
        self.lifecycle_root.chmod(0o700)
        self.processes: list[subprocess.Popen[str]] = []
        self.orphan_pids: set[int] = set()

    def tearDown(self) -> None:
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            if process.stderr is not None:
                process.stderr.close()
            if process.stdout is not None:
                process.stdout.close()
        for pid in self.orphan_pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.temporary.cleanup()

    def barrier(self, name: str) -> Path:
        path = self.lifecycle_root / name
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        return path

    def holder_command(
        self,
        barrier: Path,
        *,
        team: str = "concurrency-team",
        category: str = "task",
        instance: str = "backend--task--a1",
        mode: str = "exclusive",
        repo: Path | None = None,
    ) -> list[str]:
        return [
            sys.executable,
            str(LANE_LOCK),
            "--root",
            str(self.lifecycle_root),
            "--repo",
            str(repo or self.repo),
            "--team",
            team,
            "--category",
            category,
            "--instance",
            instance,
            "--mode",
            mode,
            "--barrier",
            str(barrier),
        ]

    def spawn_holder(
        self,
        barrier: Path,
        *,
        team: str = "concurrency-team",
        category: str = "task",
        instance: str = "backend--task--a1",
        mode: str = "exclusive",
        repo: Path | None = None,
    ) -> subprocess.Popen[str]:
        process = subprocess.Popen(
            self.holder_command(
                barrier,
                team=team,
                category=category,
                instance=instance,
                mode=mode,
                repo=repo,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.processes.append(process)
        return process

    def wait_ready(
        self,
        barrier: Path,
        process: subprocess.Popen[str] | None = None,
        *,
        timeout: float = 5.0,
    ) -> int:
        ready = barrier / "ready"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if ready.is_file():
                return int(ready.read_text(encoding="ascii").strip())
            if process is not None and process.poll() is not None:
                stderr = process.stderr.read() if process.stderr is not None else ""
                self.fail(
                    f"launch-lane holder exited before acknowledgement: {stderr}"
                )
            time.sleep(0.01)
        self.fail("timed out waiting for launch-lane acknowledgement")

    def assert_blocked(
        self,
        barrier: Path,
        process: subprocess.Popen[str],
        *,
        duration: float = 0.25,
    ) -> None:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            self.assertFalse(
                (barrier / "ready").exists(),
                "same-lane waiter acquired before the holder released",
            )
            if process.poll() is not None:
                stderr = process.stderr.read() if process.stderr is not None else ""
                self.fail(f"blocked launch-lane holder exited early: {stderr}")
            time.sleep(0.01)

    def release(self, barrier: Path, process: subprocess.Popen[str]) -> None:
        (barrier / "release").mkdir(mode=0o700)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.fail("launch-lane holder did not observe release")
        stderr = process.stderr.read() if process.stderr is not None else ""
        self.assertEqual(process.returncode, 0, stderr)

    def wait_team_admission_held(self, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            paths = list(self.lifecycle_root.glob("launch-admission-*.lock"))
            if len(paths) == 1:
                with paths[0].open("rb") as handle:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        return
                    else:
                        fcntl.flock(handle, fcntl.LOCK_UN)
            time.sleep(0.01)
        self.fail("queued team stop never closed reader admission")

    def spawn_broker(self, barrier: Path) -> tuple[subprocess.Popen[str], int]:
        # The intermediary is the holder's observed parent. Killing only this
        # broker exercises the helper's orphan-release path without signalling
        # the helper itself.
        broker_code = r"""
import subprocess
import sys
import time

error_path = sys.argv[1]
command = sys.argv[2:]
with open(error_path, "wb") as error:
    child = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=error,
    )
    print(child.pid, flush=True)
    while True:
        time.sleep(60)
"""
        broker = subprocess.Popen(
            [
                sys.executable,
                "-c",
                broker_code,
                str(barrier / "holder-error"),
                *self.holder_command(barrier),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.processes.append(broker)
        assert broker.stdout is not None
        line = broker.stdout.readline().strip()
        if not line:
            stderr = broker.stderr.read() if broker.stderr is not None else ""
            self.fail(f"broker failed to publish holder pid: {stderr}")
        holder_pid = int(line)
        self.orphan_pids.add(holder_pid)
        return broker, holder_pid

    def test_same_lane_waits_until_current_holder_releases(self) -> None:
        first_barrier = self.barrier("same-first")
        first = self.spawn_holder(first_barrier)
        self.assertEqual(self.wait_ready(first_barrier, first), first.pid)

        second_barrier = self.barrier("same-second")
        second = self.spawn_holder(second_barrier)
        self.assert_blocked(second_barrier, second)

        self.release(first_barrier, first)
        self.assertEqual(self.wait_ready(second_barrier, second), second.pid)
        self.release(second_barrier, second)

    def test_team_shared_launches_overlap_but_stop_waits_for_all(self) -> None:
        first_barrier = self.barrier("team-launch-one")
        first = self.spawn_holder(first_barrier, category="team", instance="all", mode="shared")
        self.assertEqual(self.wait_ready(first_barrier, first), first.pid)

        second_barrier = self.barrier("team-launch-two")
        second = self.spawn_holder(second_barrier, category="team", instance="all", mode="shared")
        self.assertEqual(self.wait_ready(second_barrier, second), second.pid)

        stop_barrier = self.barrier("team-stop")
        stop = self.spawn_holder(stop_barrier, category="team", instance="all")
        self.assert_blocked(stop_barrier, stop)
        self.release(first_barrier, first)
        self.assert_blocked(stop_barrier, stop)
        self.release(second_barrier, second)
        self.assertEqual(self.wait_ready(stop_barrier, stop), stop.pid)

        later_barrier = self.barrier("team-later-launch")
        later = self.spawn_holder(later_barrier, category="team", instance="all", mode="shared")
        self.assert_blocked(later_barrier, later)
        self.release(stop_barrier, stop)
        self.assertEqual(self.wait_ready(later_barrier, later), later.pid)
        self.release(later_barrier, later)

    def test_team_stop_contends_longer_than_ten_seconds_without_abandoning(self) -> None:
        launch_barrier = self.barrier("long-team-launch")
        launch = self.spawn_holder(launch_barrier, category="team", instance="all", mode="shared")
        self.assertEqual(self.wait_ready(launch_barrier, launch), launch.pid)

        stop_barrier = self.barrier("long-team-stop")
        stop = self.spawn_holder(stop_barrier, category="team", instance="all")
        self.assert_blocked(stop_barrier, stop, duration=10.25)
        self.release(launch_barrier, launch)
        self.assertEqual(self.wait_ready(stop_barrier, stop), stop.pid)
        self.release(stop_barrier, stop)

    def test_queued_team_stop_precedes_later_shared_launch(self) -> None:
        launch_barrier = self.barrier("queued-writer-first-reader")
        launch = self.spawn_holder(launch_barrier, category="team", instance="all", mode="shared")
        self.assertEqual(self.wait_ready(launch_barrier, launch), launch.pid)

        stop_barrier = self.barrier("queued-writer-stop")
        stop = self.spawn_holder(stop_barrier, category="team", instance="all")
        self.wait_team_admission_held()
        self.assert_blocked(stop_barrier, stop)

        later_barrier = self.barrier("queued-writer-later-reader")
        later = self.spawn_holder(later_barrier, category="team", instance="all", mode="shared")
        self.assert_blocked(later_barrier, later)

        self.release(launch_barrier, launch)
        self.assertEqual(self.wait_ready(stop_barrier, stop), stop.pid)
        self.assert_blocked(later_barrier, later)
        self.release(stop_barrier, stop)
        self.assertEqual(self.wait_ready(later_barrier, later), later.pid)
        self.release(later_barrier, later)

    def test_distinct_instance_and_category_lanes_can_overlap(self) -> None:
        first_barrier = self.barrier("distinct-first")
        first = self.spawn_holder(first_barrier)
        self.assertEqual(self.wait_ready(first_barrier, first), first.pid)

        instance_barrier = self.barrier("distinct-instance")
        different_instance = self.spawn_holder(
            instance_barrier, instance="frontend--task--a1"
        )
        self.assertEqual(
            self.wait_ready(instance_barrier, different_instance),
            different_instance.pid,
        )

        category_barrier = self.barrier("distinct-category")
        different_category = self.spawn_holder(category_barrier, category="gate")
        self.assertEqual(
            self.wait_ready(category_barrier, different_category),
            different_category.pid,
        )
        self.assertIsNone(first.poll(), "different lane displaced current holder")

        self.release(category_barrier, different_category)
        self.release(instance_barrier, different_instance)
        self.release(first_barrier, first)

    def test_stable_task_key_serializes_roles_and_attempts_only_for_that_task(self) -> None:
        task_key = "task-key-4d84c7"
        first_barrier = self.barrier("task-attempt-one")
        first = self.spawn_holder(first_barrier, instance=task_key)
        self.assertEqual(self.wait_ready(first_barrier, first), first.pid)

        # Launchers for another role/attempt pass the stable task key rather
        # than their role--task--attempt lifecycle instance, so they must wait.
        successor_barrier = self.barrier("task-attempt-two")
        successor = self.spawn_holder(successor_barrier, instance=task_key)
        self.assert_blocked(successor_barrier, successor)

        # A different task remains an independent publication/lifecycle lane.
        sibling_barrier = self.barrier("sibling-task")
        sibling = self.spawn_holder(sibling_barrier, instance="task-key-927ac1")
        self.assertEqual(self.wait_ready(sibling_barrier, sibling), sibling.pid)

        self.release(first_barrier, first)
        self.assertEqual(
            self.wait_ready(successor_barrier, successor), successor.pid
        )
        self.release(successor_barrier, successor)
        self.release(sibling_barrier, sibling)

    def test_linked_worktrees_share_the_same_lifecycle_lane(self) -> None:
        linked = self.base / "linked"
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "worktree",
                "add",
                "--quiet",
                "--detach",
                str(linked),
            ],
            check=True,
            capture_output=True,
        )

        first_barrier = self.barrier("main-worktree")
        first = self.spawn_holder(first_barrier, repo=self.repo)
        self.assertEqual(self.wait_ready(first_barrier, first), first.pid)

        linked_barrier = self.barrier("linked-worktree")
        linked_holder = self.spawn_holder(linked_barrier, repo=linked)
        self.assert_blocked(linked_barrier, linked_holder)

        self.release(first_barrier, first)
        self.assertEqual(
            self.wait_ready(linked_barrier, linked_holder), linked_holder.pid
        )
        self.release(linked_barrier, linked_holder)

    def test_broker_death_releases_lane_for_waiting_launcher(self) -> None:
        abandoned_barrier = self.barrier("abandoned")
        broker, holder_pid = self.spawn_broker(abandoned_barrier)
        self.assertEqual(self.wait_ready(abandoned_barrier), holder_pid)

        waiting_barrier = self.barrier("after-parent-death")
        waiting = self.spawn_holder(waiting_barrier)
        self.assert_blocked(waiting_barrier, waiting)

        broker.kill()
        broker.wait(timeout=5)
        self.assertEqual(self.wait_ready(waiting_barrier, waiting), waiting.pid)
        self.release(waiting_barrier, waiting)

        # Acquiring the same kernel lock proves the orphan closed its holder
        # descriptor.  Some container PID 1 implementations leave the exited
        # grandchild visible as a zombie, so kill(0) is not a portable exit
        # oracle here.

    def test_role_control_holds_exact_gate_lane_through_replacement(self) -> None:
        source = (ROOT / "bin" / "launch-team.sh").read_text(encoding="utf-8")
        launch = source.split("launch_one() {", 1)[1].split("retire_attempt_worktree() {", 1)[0]
        retire = source.split("retire_role() {", 1)[1].split("restart_role() {", 1)[0]
        restart = source.split("restart_role() {", 1)[1].split("\ncase \"${1:-}\" in", 1)[0]
        exact = '[ "$LAUNCH_LANE_LOCK_TEAM" = "$team" ]'
        self.assertIn(exact, launch)
        self.assertIn('[ "$LAUNCH_LANE_LOCK_CATEGORY" = gate ]', launch)
        self.assertIn('[ "$LAUNCH_LANE_LOCK_INSTANCE" = "$role" ]', launch)
        self.assertIn(exact, retire)
        self.assertIn('[ "$LAUNCH_LANE_LOCK_CATEGORY" = gate ]', retire)
        self.assertIn('[ "$LAUNCH_LANE_LOCK_INSTANCE" = "$role" ]', retire)
        self.assertLess(
            retire.index('acquire_launch_lane_lock "$team" gate "$role"'),
            retire.index('record="$(python3 "$SKILL_DIR/bin/process-lifecycle.py" list'),
        )
        self.assertLess(
            restart.index('acquire_launch_lane_lock "$team" gate "$role"'),
            restart.index('record="$(python3 "$SKILL_DIR/bin/process-lifecycle.py" list'),
        )
        self.assertLess(
            restart.index('retire_role "$team"'),
            restart.index('launch_one "$team"'),
        )
        self.assertLess(
            restart.index('launch_one "$team"'),
            restart.rindex('release_launch_lane_lock'),
        )

    def test_failed_team_release_exits_without_waiting_or_signalling_pid(self) -> None:
        source = (ROOT / "bin" / "launch-team.sh").read_text(encoding="utf-8")
        self.assertIn("trap 'release_team_fence || exit 1' EXIT", source)
        release = source.split("release_team_fence() {", 1)[1].split(
            "create_launch_barrier() {", 1
        )[0]
        failure = release.split('if ! mkdir -m 700 "$directory/release"', 1)[1].split(
            "  fi", 1
        )[0]
        self.assertIn("return 1", failure)
        self.assertNotIn('wait "$holder"', failure)
        self.assertNotIn("/bin/kill", failure)


if __name__ == "__main__":
    unittest.main(verbosity=2)
