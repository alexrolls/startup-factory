#!/usr/bin/env python3
"""Regression tests for exact-generation release guardian retirement."""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "bin" / "release-worker.py"
PM_AGENT = ROOT / "bin" / "pm-agent.py"
LIFECYCLE = ROOT / "bin" / "process-lifecycle.py"
LANE_LOCK = ROOT / "bin" / "launch-lane-lock.py"
SPEC = importlib.util.spec_from_file_location("release_worker", WORKER)
assert SPEC is not None and SPEC.loader is not None
release_worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_worker)


def load_pm_agent(name: str):
    spec = importlib.util.spec_from_file_location(name, PM_AGENT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.repository = self.base / "repository"
        self.repository.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.repository, check=True)
        self.lifecycle_root = self.base / "lifecycle"
        self.lifecycle_root.mkdir(mode=0o700)
        self.fixture_groups: set[int] = set()

    def tearDown(self) -> None:
        for process_group in self.fixture_groups:
            try:
                os.killpg(process_group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.temporary.cleanup()

    def identity(self, command: list[str], attempt: int = 1) -> dict:
        value = {
            "repository": str(self.repository),
            "runId": "run-guardian-regression",
            "team": "release-test-team",
            "featureId": "guardian-release-feature",
            "attempt": attempt,
            "commandDigest": release_worker.digest_command(command),
        }
        value["jobId"] = "release-" + hashlib.sha256(
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()[:32]
        return value

    def create_job(self, command: list[str], attempt: int = 1) -> tuple[dict, Path]:
        identity = self.identity(command, attempt)
        directory = self.lifecycle_root / identity["jobId"]
        directory.mkdir(mode=0o700)
        result = directory / "result.json"
        result.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "identity": identity,
                    "state": "launching",
                    "createdAt": "2026-09-21T00:00:00+00:00",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        result.chmod(0o600)
        return identity, directory

    def run_worker(
        self, command: list[str], attempt: int = 1
    ) -> tuple[subprocess.CompletedProcess[str], dict, Path]:
        identity, directory = self.create_job(command, attempt)
        completed = subprocess.run(
            self.worker_arguments(identity, directory, command),
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        result = json.loads((directory / "result.json").read_text(encoding="utf-8"))
        return completed, result, directory

    def worker_arguments(
        self, identity: dict, directory: Path, command: list[str]
    ) -> list[str]:
        return [
            sys.executable,
            str(WORKER),
            "--result", str(directory / "result.json"),
            "--log", str(directory / "release.log"),
            "--timeout", "60",
            "--identity-json", json.dumps(identity, separators=(",", ":")),
            "--lifecycle-root", str(self.lifecycle_root),
            "--repository", str(self.repository),
            "--",
            *command,
        ]

    def inspect_lifecycle(self, identity: dict) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(LIFECYCLE),
                "inspect",
                "--root", str(self.lifecycle_root),
                "--repo", str(self.repository),
                "--team", identity["team"],
                "--category", "release",
                "--instance", identity["jobId"],
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def lifecycle_records(self) -> list[Path]:
        records = self.lifecycle_root / "records"
        return [] if not records.exists() else list(records.glob("*.json"))

    @staticmethod
    def process_exists(pid: int) -> bool:
        stat_path = Path("/proc") / str(pid) / "stat"
        try:
            # A container PID 1 may leave an orphaned fixture zombie around;
            # zombies have no execution authority and are not live descendants.
            if stat_path.read_text(encoding="ascii").split()[2] == "Z":
                return False
        except (FileNotFoundError, IndexError, OSError, UnicodeError):
            pass
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def wait_process_gone(self, pid: int, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.process_exists(pid):
                return
            time.sleep(0.02)
        self.fail("process %s remained live" % pid)

    def spawn_registered_guardian(
        self, command: list[str], attempt: int
    ) -> tuple[subprocess.Popen, int, int, dict, dict, object]:
        identity = self.identity(command, attempt)
        log = open(os.devnull, "w", encoding="utf-8")
        guardian, control, status = release_worker.spawn_guardian(command, log)
        self.fixture_groups.add(guardian.pid)
        registered = release_worker.lifecycle_command(
            "register",
            lifecycle_root=self.lifecycle_root,
            repository=self.repository,
            identity=identity,
            pid=guardian.pid,
            check=False,
        )
        generation = release_worker.parse_lifecycle_generation(
            registered, identity, guardian.pid
        )
        return guardian, control, status, identity, generation, log

    def test_containment_fork_failure_retains_pre_registration_liveness_tether(
        self,
    ) -> None:
        injected_source = """
import os
def fail_containment_fork():
    raise OSError("simulated containment fork exhaustion")
os.fork = fail_containment_fork
""" + release_worker.GUARDIAN_SOURCE
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        log = open(os.devnull, "w", encoding="utf-8")
        guardian: subprocess.Popen | None = None
        control = status = -1
        try:
            with mock.patch.object(
                release_worker, "GUARDIAN_SOURCE", injected_source
            ):
                guardian, control, status = release_worker.spawn_guardian(command, log)
            self.fixture_groups.add(guardian.pid)

            # Status EOF proves the injected fork failure branch is now waiting
            # on the still-open worker control pipe rather than merely not yet
            # having reached it.
            deadline = time.monotonic() + 5
            while True:
                try:
                    self.assertEqual(os.read(status, 1), b"")
                    break
                except BlockingIOError:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
            self.assertIsNone(guardian.poll())

            os.close(control)
            control = -1
            guardian.wait(timeout=5)
            self.assertFalse(self.process_exists(guardian.pid))
            self.fixture_groups.discard(guardian.pid)
        finally:
            if control >= 0:
                os.close(control)
            if status >= 0:
                os.close(status)
            if guardian is not None and guardian.poll() is None:
                os.killpg(guardian.pid, signal.SIGKILL)
                guardian.wait(timeout=5)
                self.fixture_groups.discard(guardian.pid)
            log.close()

    def test_exit_zero_retires_term_resistant_descendant(self) -> None:
        child_pid_path = self.base / "descendant.pid"
        child_code = (
            "import pathlib,signal,sys,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "pathlib.Path(sys.argv[1]).write_text(str(__import__('os').getpid()));"
            "time.sleep(60)"
        )
        command_code = (
            "import pathlib,subprocess,sys,time;"
            "p=subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]]);"
            "deadline=time.monotonic()+5;"
            "\nwhile not pathlib.Path(sys.argv[1]).exists():\n"
            "  assert time.monotonic()<deadline\n"
            "  time.sleep(.01)\n"
        )
        command = [sys.executable, "-c", command_code, str(child_pid_path), child_code]

        completed, result, _ = self.run_worker(command)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["exitCode"], 0)
        self.assertNotIn("launchToken", json.dumps(result))
        descendant_pid = int(child_pid_path.read_text(encoding="utf-8"))
        self.wait_process_gone(descendant_pid)
        self.assertEqual(self.lifecycle_records(), [])

    def test_nonzero_command_status_is_reported_after_exact_retirement(self) -> None:
        command = [sys.executable, "-c", "raise SystemExit(7)"]

        completed, result, _ = self.run_worker(command, attempt=2)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["exitCode"], 7)
        self.assertEqual(self.lifecycle_records(), [])

    def test_hard_crash_after_register_leaves_durable_pid_for_restart(self) -> None:
        sentinel = self.base / "must-not-launch-after-register-crash"
        command = [
            sys.executable,
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ran')",
            str(sentinel),
        ]
        identity, directory = self.create_job(command, attempt=10)
        arguments = self.worker_arguments(identity, directory, command)[1:]
        harness = """
import importlib.util
import os
import signal
import sys
from unittest import mock

spec = importlib.util.spec_from_file_location("crashing_release_worker", %r)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
real_lifecycle_command = module.lifecycle_command

def crash_after_register(action, **kwargs):
    result = real_lifecycle_command(action, **kwargs)
    if action == "register" and result.returncode == 0:
        os.kill(os.getpid(), signal.SIGKILL)
    return result

with mock.patch.object(module, "lifecycle_command", side_effect=crash_after_register), \
     mock.patch.object(sys, "argv", sys.argv[1:]):
    module.main()
""" % str(WORKER)

        crashed = subprocess.run(
            [sys.executable, "-c", harness, *arguments],
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

        self.assertNotEqual(crashed.returncode, 0)
        result = json.loads((directory / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["state"], "running")
        self.assertIs(type(result.get("releasePid")), int)
        self.assertNotIn("releaseMayHaveStartedAt", result)
        inspected = self.inspect_lifecycle(identity)
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        record = json.loads(inspected.stdout)
        self.assertEqual(record["pid"], result["releasePid"])
        self.assertEqual(record["kind"], "background")
        self.assertFalse(sentinel.exists())

        guardian_pid = result["releasePid"]
        self.fixture_groups.add(guardian_pid)
        self.wait_process_gone(guardian_pid)
        restarted = load_pm_agent("pm_after_release_registration_crash")
        persisted = restarted.read_release_job_result(directory, identity)
        with mock.patch.object(restarted, "result_age_seconds", return_value=999):
            recovered = restarted.recover_stale_release_job(
                {}, self.repository, self.lifecycle_root, identity, directory, persisted
            )

        self.assertEqual(recovered["state"], "cancelled")
        self.assertEqual(recovered["releasePid"], guardian_pid)
        self.assertFalse(sentinel.exists())
        self.assertEqual(self.inspect_lifecycle(identity).returncode, 3)
        self.fixture_groups.discard(guardian_pid)

    def test_recovered_terminal_pid_survives_forget_crash_and_restart(self) -> None:
        class SimulatedCrash(RuntimeError):
            pass

        command = [sys.executable, "-c", "raise SystemExit(0)"]
        identity, directory = self.create_job(command, attempt=11)
        log = open(os.devnull, "w", encoding="utf-8")
        guardian, control, status = release_worker.spawn_guardian(command, log)
        self.fixture_groups.add(guardian.pid)
        try:
            registered = release_worker.lifecycle_command(
                "register",
                lifecycle_root=self.lifecycle_root,
                repository=self.repository,
                identity=identity,
                pid=guardian.pid,
                check=False,
            )
            generation = release_worker.parse_lifecycle_generation(
                registered, identity, guardian.pid
            )
            release_worker.terminate_release_generation(
                guardian,
                lifecycle_root=self.lifecycle_root,
                repository=self.repository,
                identity=identity,
                generation=generation,
                graceful=False,
            )
            self.fixture_groups.discard(guardian.pid)
            release_worker.atomic_json(
                directory / "result.json",
                {
                    "schemaVersion": 1,
                    "identity": identity,
                    "state": "running",
                    "workerPid": os.getpid(),
                    "startedAt": "2026-09-21T00:00:00+00:00",
                    "heartbeatAt": "2026-09-21T00:00:00+00:00",
                    "releasePid": guardian.pid,
                    "releaseMayHaveStartedAt": "2026-09-21T00:00:01+00:00",
                },
            )

            first_monitor = load_pm_agent("pm_before_terminal_forget_crash")
            running = first_monitor.read_release_job_result(directory, identity)
            with mock.patch.object(
                first_monitor, "result_age_seconds", return_value=999
            ), mock.patch.object(
                first_monitor,
                "forget_release_generation",
                side_effect=SimulatedCrash("crash before exact forget"),
            ):
                with self.assertRaisesRegex(SimulatedCrash, "exact forget"):
                    first_monitor.recover_stale_release_job(
                        {}, self.repository, self.lifecycle_root,
                        identity, directory, running
                    )

            persisted = json.loads(
                (directory / "result.json").read_text(encoding="utf-8")
            )
            self.assertEqual(persisted["state"], "completed")
            self.assertEqual(persisted["releasePid"], guardian.pid)
            retained = self.inspect_lifecycle(identity)
            self.assertEqual(retained.returncode, 0, retained.stderr)
            self.assertEqual(json.loads(retained.stdout)["pid"], guardian.pid)

            restarted = load_pm_agent("pm_after_terminal_forget_crash")
            entry = {
                "runId": identity["runId"],
                "team": identity["team"],
                "featureId": identity["featureId"],
                "releaseJob": {
                    "schemaVersion": 1,
                    "identity": identity,
                    "startedAt": "2026-09-21T00:00:00+00:00",
                },
            }
            with mock.patch.object(
                restarted, "release_job_directory", return_value=directory
            ):
                attached = restarted.active_release_job(
                    entry, self.repository, self.lifecycle_root
                )
            self.assertIsNotNone(attached)
            assert attached is not None
            self.assertEqual(attached[2]["releasePid"], guardian.pid)
            self.assertEqual(self.inspect_lifecycle(identity).returncode, 3)
        finally:
            os.close(control)
            os.close(status)
            log.close()

    def test_ambiguous_terminal_publish_is_redurable_before_forget(self) -> None:
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        identity, directory = self.create_job(command, attempt=12)
        log = open(os.devnull, "w", encoding="utf-8")
        guardian, control, status = release_worker.spawn_guardian(command, log)
        self.fixture_groups.add(guardian.pid)
        try:
            registered = release_worker.lifecycle_command(
                "register",
                lifecycle_root=self.lifecycle_root,
                repository=self.repository,
                identity=identity,
                pid=guardian.pid,
                check=False,
            )
            generation = release_worker.parse_lifecycle_generation(
                registered, identity, guardian.pid
            )
            release_worker.terminate_release_generation(
                guardian,
                lifecycle_root=self.lifecycle_root,
                repository=self.repository,
                identity=identity,
                generation=generation,
                graceful=False,
            )
            self.fixture_groups.discard(guardian.pid)
            terminal = {
                "schemaVersion": 1,
                "identity": identity,
                "state": "completed",
                "exitCode": 0,
                "completedAt": "2026-09-21T00:00:02+00:00",
                "releasePid": guardian.pid,
            }

            # Simulate the ambiguous publication boundary: rename committed the
            # terminal result to the visible path, but its first parent fsync
            # failed.  The completed lifecycle tombstone must remain retained.
            publishing = load_pm_agent("pm_ambiguous_terminal_publish")
            real_fsync = os.fsync
            publication_syncs: list[str] = []

            def fail_publication_parent(descriptor: int) -> None:
                kind = (
                    "directory"
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode)
                    else "file"
                )
                publication_syncs.append(kind)
                if kind == "directory":
                    raise OSError("simulated ambiguous parent fsync failure")
                real_fsync(descriptor)

            with mock.patch.object(
                publishing.os, "fsync", side_effect=fail_publication_parent
            ):
                with self.assertRaisesRegex(
                    publishing.MonitorError, "cannot protect release job state"
                ):
                    publishing.atomic_private_json(
                        directory / "result.json", terminal
                    )

            self.assertEqual(publication_syncs, ["file", "directory"])
            self.assertEqual(
                json.loads(
                    (directory / "result.json").read_text(encoding="utf-8")
                ),
                terminal,
            )
            retained = self.inspect_lifecycle(identity)
            self.assertEqual(retained.returncode, 0, retained.stderr)
            self.assertEqual(
                json.loads(retained.stdout)["kind"], "completed-background"
            )

            entry = {
                "runId": identity["runId"],
                "team": identity["team"],
                "featureId": identity["featureId"],
                "releaseJob": {
                    "schemaVersion": 1,
                    "identity": identity,
                    "startedAt": "2026-09-21T00:00:00+00:00",
                },
            }

            # If restart cannot re-establish the directory durability, it must
            # fail closed without issuing exact forget.
            failed_restart = load_pm_agent("pm_failed_terminal_redurability")
            failed_syncs: list[str] = []

            def fail_recovery_parent(descriptor: int) -> None:
                kind = (
                    "directory"
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode)
                    else "file"
                )
                failed_syncs.append(kind)
                if kind == "directory":
                    raise OSError("simulated recovery parent fsync failure")
                real_fsync(descriptor)

            with mock.patch.object(
                failed_restart, "release_job_directory", return_value=directory
            ), mock.patch.object(
                failed_restart.os, "fsync", side_effect=fail_recovery_parent
            ):
                with self.assertRaisesRegex(
                    failed_restart.MonitorError,
                    "cannot protect release job state",
                ):
                    failed_restart.active_release_job(
                        entry, self.repository, self.lifecycle_root
                    )

            self.assertEqual(failed_syncs, ["file", "directory"])
            retained = self.inspect_lifecycle(identity)
            self.assertEqual(retained.returncode, 0, retained.stderr)
            self.assertEqual(
                json.loads(retained.stdout)["kind"], "completed-background"
            )

            # A later restart must fsync the exact result inode and job
            # directory before it is allowed to forget the retained tombstone.
            restarted = load_pm_agent("pm_successful_terminal_redurability")
            recovery_events: list[str] = []
            original_forget = restarted.forget_release_generation

            def record_recovery_sync(descriptor: int) -> None:
                recovery_events.append(
                    "directory"
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode)
                    else "file"
                )
                real_fsync(descriptor)

            def record_forget(*args, **kwargs) -> None:
                recovery_events.append("forget")
                original_forget(*args, **kwargs)

            with mock.patch.object(
                restarted, "release_job_directory", return_value=directory
            ), mock.patch.object(
                restarted.os, "fsync", side_effect=record_recovery_sync
            ), mock.patch.object(
                restarted,
                "forget_release_generation",
                side_effect=record_forget,
            ):
                attached = restarted.active_release_job(
                    entry, self.repository, self.lifecycle_root
                )

            self.assertIsNotNone(attached)
            assert attached is not None
            self.assertEqual(attached[2], terminal)
            self.assertEqual(recovery_events, ["file", "directory", "forget"])
            self.assertEqual(self.inspect_lifecycle(identity).returncode, 3)
        finally:
            os.close(control)
            os.close(status)
            log.close()

    def test_crash_between_terminate_and_terminal_retains_tombstone(self) -> None:
        class SimulatedCrash(RuntimeError):
            pass

        command = [sys.executable, "-c", "raise SystemExit(0)"]
        identity, directory = self.create_job(command, attempt=8)
        arguments = self.worker_arguments(identity, directory, command)[1:]
        write_json = release_worker.atomic_json

        def crash_before_terminal(path: Path, value: dict) -> None:
            if value.get("state") in {"completed", "cancelled"}:
                raise SimulatedCrash("crash before durable terminal result")
            write_json(path, value)

        with mock.patch.object(sys, "argv", arguments), mock.patch.object(
            release_worker, "atomic_json", side_effect=crash_before_terminal
        ):
            with self.assertRaisesRegex(SimulatedCrash, "durable terminal"):
                release_worker.main()

        result = json.loads((directory / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["state"], "running")
        self.assertNotIn("exitCode", result)
        inspected = self.inspect_lifecycle(identity)
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        record = json.loads(inspected.stdout)
        self.assertEqual(record["kind"], "completed-background")
        self.assertEqual(record["pid"], result["releasePid"])
        self.assertEqual(len(self.lifecycle_records()), 1)

    def test_forget_failure_after_terminal_never_rewrites_nonterminal(self) -> None:
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        identity, directory = self.create_job(command, attempt=9)
        arguments = self.worker_arguments(identity, directory, command)[1:]

        with mock.patch.object(sys, "argv", arguments), mock.patch.object(
            release_worker,
            "forget_release_generation",
            side_effect=RuntimeError("simulated forget failure"),
        ):
            exit_status = release_worker.main()

        self.assertEqual(exit_status, 125)
        result = json.loads((directory / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["exitCode"], 0)
        inspected = self.inspect_lifecycle(identity)
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        record = json.loads(inspected.stdout)
        self.assertEqual(record["kind"], "completed-background")
        self.assertEqual(record["pid"], result["releasePid"])
        self.assertEqual(len(self.lifecycle_records()), 1)

    def test_team_stop_fence_blocks_release_admission_before_register_and_go(self) -> None:
        barrier = self.lifecycle_root / "stop-fence"
        barrier.mkdir(mode=0o700)
        exclusive = subprocess.Popen(
            [
                sys.executable, str(LANE_LOCK),
                "--root", str(self.lifecycle_root), "--repo", str(self.repository),
                "--team", "release-test-team", "--category", "team",
                "--instance", "all", "--mode", "exclusive",
                "--barrier", str(barrier),
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        witness = self.base / "release-witness"
        command = [sys.executable, "-c", "from pathlib import Path; Path(%r).write_text('ran')" % str(witness)]
        identity, directory = self.create_job(command, attempt=12)
        worker: subprocess.Popen[str] | None = None
        try:
            deadline = time.monotonic() + 5
            while not (barrier / "ready").exists() and time.monotonic() < deadline:
                self.assertIsNone(exclusive.poll(), "exclusive team fence exited early")
                time.sleep(0.01)
            self.assertTrue((barrier / "ready").exists())
            worker = subprocess.Popen(
                self.worker_arguments(identity, directory, command),
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                result = json.loads((directory / "result.json").read_text())
                if result["state"] == "running":
                    break
                time.sleep(0.01)
            self.assertEqual(result["state"], "running")
            time.sleep(0.2)
            self.assertIsNone(worker.poll(), "release worker escaped team stop fence")
            self.assertEqual(self.lifecycle_records(), [])
            self.assertNotIn("releaseMayHaveStartedAt", result)
            self.assertFalse(witness.exists())
            (barrier / "release").mkdir(mode=0o700)
            self.assertEqual(exclusive.wait(timeout=5), 0)
            stdout, stderr = worker.communicate(timeout=15)
            self.assertEqual(worker.returncode, 0, stderr or stdout)
            self.assertEqual(witness.read_text(), "ran")
        finally:
            if worker is not None and worker.poll() is None:
                worker.kill()
                worker.wait(timeout=5)
            if exclusive.poll() is None:
                exclusive.kill()
                exclusive.wait(timeout=5)
            if exclusive.stderr is not None:
                exclusive.stderr.close()
            if worker is not None:
                if worker.stdout is not None:
                    worker.stdout.close()
                if worker.stderr is not None:
                    worker.stderr.close()

    def test_missing_team_fence_helper_never_spawns_guardian(self) -> None:
        witness = self.base / "unfenced-witness"
        command = [sys.executable, "-c", "from pathlib import Path; Path(%r).touch()" % str(witness)]
        identity, directory = self.create_job(command, attempt=13)
        arguments = self.worker_arguments(identity, directory, command)[1:]
        with mock.patch.object(sys, "argv", arguments), mock.patch.object(
            release_worker, "TEAM_FENCE_HELPER", self.base / "missing-helper.py"
        ), mock.patch.object(
            release_worker, "spawn_guardian", side_effect=AssertionError("guardian spawned")
        ):
            self.assertEqual(release_worker.main(), 0)
        result = json.loads((directory / "result.json").read_text())
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["exitCode"], 125)
        self.assertIn("team fence", result["workerError"])
        self.assertNotIn("releasePid", result)
        self.assertFalse(witness.exists())

    def test_terminal_result_is_immutable_across_worker_and_monitor_writers(
        self,
    ) -> None:
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        identity, directory = self.create_job(command, attempt=14)
        path = directory / "result.json"
        terminal = {
            "schemaVersion": 1,
            "identity": identity,
            "state": "completed",
            "exitCode": 125,
            "completedAt": "2026-09-21T00:00:03+00:00",
            "workerError": "recovered stale release",
        }
        monitor = load_pm_agent("pm_terminal_result_fence")
        monitor.atomic_private_json(path, terminal)
        winning_bytes = path.read_bytes()

        stale_running = {
            "schemaVersion": 1,
            "identity": identity,
            "state": "running",
            "workerPid": os.getpid(),
            "startedAt": "2026-09-21T00:00:00+00:00",
            "heartbeatAt": "2026-09-21T00:00:04+00:00",
        }
        with self.assertRaises(release_worker.TerminalResultAlreadyPublished):
            release_worker.atomic_json(path, stale_running)
        self.assertEqual(path.read_bytes(), winning_bytes)

        conflicting_terminal = dict(terminal, exitCode=0)
        with self.assertRaisesRegex(
            monitor.MonitorError, "existing terminal release job result"
        ):
            monitor.atomic_private_json(path, conflicting_terminal)
        self.assertEqual(path.read_bytes(), winning_bytes)

    def test_result_writer_lock_contention_fails_closed_within_bound(self) -> None:
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        identity, directory = self.create_job(command, attempt=16)
        path = directory / "result.json"
        original_bytes = path.read_bytes()
        running = {
            "schemaVersion": 1,
            "identity": identity,
            "state": "running",
            "workerPid": os.getpid(),
            "startedAt": "2026-09-21T00:00:00+00:00",
            "heartbeatAt": "2026-09-21T00:00:01+00:00",
        }
        terminal = {
            "schemaVersion": 1,
            "identity": identity,
            "state": "completed",
            "exitCode": 125,
            "completedAt": "2026-09-21T00:00:02+00:00",
        }
        monitor = load_pm_agent("pm_result_lock_timeout")
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            fcntl.flock(directory_fd, fcntl.LOCK_EX)
            with mock.patch.object(
                release_worker, "RELEASE_RESULT_LOCK_TIMEOUT_SECONDS", 0.05
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "timed out acquiring.*writer fence"
                ):
                    release_worker.atomic_json(path, running)
            with mock.patch.object(
                monitor, "RELEASE_RESULT_LOCK_TIMEOUT_SECONDS", 0.05
            ):
                with self.assertRaisesRegex(
                    monitor.MonitorError, "timed out acquiring.*writer fence"
                ):
                    monitor.atomic_private_json(path, terminal)
        finally:
            fcntl.flock(directory_fd, fcntl.LOCK_UN)
            os.close(directory_fd)
        self.assertEqual(path.read_bytes(), original_bytes)

    def test_sigstop_pm_recovery_sigcont_cannot_roll_back_terminal_result(
        self,
    ) -> None:
        launches = self.base / "release-launches"
        command = [
            sys.executable,
            "-c",
            (
                "import pathlib,sys,time;"
                "p=pathlib.Path(sys.argv[1]);"
                "h=p.open('a',encoding='utf-8');"
                "h.write('run\\n');h.flush();h.close();"
                "time.sleep(60)"
            ),
            str(launches),
        ]
        identity, directory = self.create_job(command, attempt=15)
        worker = subprocess.Popen(
            self.worker_arguments(identity, directory, command),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stopped = False
        guardian_pid: int | None = None
        try:
            path = directory / "result.json"
            deadline = time.monotonic() + 10
            running: dict | None = None
            while time.monotonic() < deadline:
                try:
                    candidate = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    time.sleep(0.01)
                    continue
                if (
                    candidate.get("releaseMayHaveStartedAt")
                    and launches.exists()
                ):
                    running = candidate
                    break
                if worker.poll() is not None:
                    stdout, stderr = worker.communicate()
                    self.fail(
                        "release worker exited before SIGSTOP: %s %s"
                        % (stdout, stderr)
                    )
                time.sleep(0.01)
            self.assertIsNotNone(running, "release command did not cross launch barrier")
            assert running is not None
            guardian_pid = running["releasePid"]
            self.fixture_groups.add(guardian_pid)

            # Taking the same stable directory lock before SIGSTOP proves the
            # worker cannot be frozen while holding the writer fence.  This
            # makes the real inter-process recovery ordering deterministic.
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                fcntl.flock(directory_fd, fcntl.LOCK_EX)
                os.kill(worker.pid, signal.SIGSTOP)
                waited, wait_status = os.waitpid(worker.pid, os.WUNTRACED)
                self.assertEqual(waited, worker.pid)
                self.assertTrue(os.WIFSTOPPED(wait_status))
                stopped = True
            finally:
                fcntl.flock(directory_fd, fcntl.LOCK_UN)
                os.close(directory_fd)

            monitor = load_pm_agent("pm_sigstop_terminal_result_recovery")
            persisted = monitor.read_release_job_result(directory, identity)
            with mock.patch.object(
                monitor, "result_age_seconds", return_value=999
            ), mock.patch.object(
                monitor, "RELEASE_ORPHAN_TERM_GRACE_SECONDS", 0.05
            ):
                recovered = monitor.recover_stale_release_job(
                    {}, self.repository, self.lifecycle_root,
                    identity, directory, persisted
                )

            terminal_bytes = path.read_bytes()
            terminal_value = json.loads(terminal_bytes)
            self.assertEqual(recovered, terminal_value)
            self.assertEqual(terminal_value["state"], "completed")
            self.assertEqual(terminal_value["exitCode"], 125)
            self.assertEqual(self.inspect_lifecycle(identity).returncode, 3)
            self.fixture_groups.discard(guardian_pid)

            os.kill(worker.pid, signal.SIGCONT)
            stopped = False
            stdout, stderr = worker.communicate(timeout=10)
            self.assertEqual(worker.returncode, 125, (stdout, stderr))
            self.assertEqual(path.read_bytes(), terminal_bytes)
            self.assertEqual(json.loads(path.read_bytes()), terminal_value)
            self.assertEqual(
                launches.read_text(encoding="utf-8").splitlines(), ["run"]
            )
            self.assertEqual(self.lifecycle_records(), [])
        finally:
            if stopped and worker.poll() is None:
                os.kill(worker.pid, signal.SIGCONT)
            if worker.poll() is None:
                worker.kill()
                worker.wait(timeout=5)
            if guardian_pid is not None and self.process_exists(guardian_pid):
                try:
                    os.killpg(guardian_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.fixture_groups.discard(guardian_pid)

    def test_terminal_state_writer_fsyncs_file_and_parent_directory(self) -> None:
        path = self.base / "durable-result.json"
        with mock.patch.object(os, "fsync", wraps=os.fsync) as synced:
            release_worker.atomic_json(path, {"state": "completed"})

        self.assertEqual(synced.call_count, 2)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {
            "state": "completed"
        })
        self.assertEqual(list(self.base.glob(".durable-result.json.tmp.*")), [])

    def test_cancellation_before_launch_never_runs_command(self) -> None:
        sentinel = self.base / "must-not-run"
        command = [
            sys.executable,
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ran')",
            str(sentinel),
        ]
        identity, directory = self.create_job(command, attempt=3)
        cancel = directory / "cancel.json"
        cancel.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "identity": identity,
                    "requestedAt": "2026-09-21T00:00:01+00:00",
                    "reason": "run-paused",
                },
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        cancel.chmod(0o600)

        completed = subprocess.run(
            self.worker_arguments(identity, directory, command),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        result = json.loads((directory / "result.json").read_text(encoding="utf-8"))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(result["exitCode"], 130)
        self.assertFalse(sentinel.exists())
        self.assertEqual(self.lifecycle_records(), [])

    def test_registered_pre_go_cancellation_retires_guardian_without_exec(self) -> None:
        sentinel = self.base / "registered-cancel-must-not-run"
        command = [
            sys.executable,
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ran')",
            str(sentinel),
        ]
        guardian, control, status, identity, generation, log = (
            self.spawn_registered_guardian(command, attempt=6)
        )
        try:
            os.write(control, b"cancel\n")
            os.close(control)
            control = -1
            release_worker.terminate_release_generation(
                guardian,
                lifecycle_root=self.lifecycle_root,
                repository=self.repository,
                identity=identity,
                generation=generation,
                graceful=False,
            )
            release_worker.forget_release_generation(
                lifecycle_root=self.lifecycle_root,
                repository=self.repository,
                identity=identity,
                generation=generation,
            )
            self.fixture_groups.discard(guardian.pid)
            self.assertFalse(sentinel.exists())
            self.assertEqual(self.lifecycle_records(), [])
        finally:
            if control >= 0:
                os.close(control)
            os.close(status)
            log.close()

    def test_timeout_cleanup_terms_then_kills_exact_generation(self) -> None:
        command_pid_path = self.base / "timeout-command.pid"
        command = [
            sys.executable,
            "-c",
            (
                "import os,pathlib,signal,sys,time;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));"
                "time.sleep(60)"
            ),
            str(command_pid_path),
        ]
        guardian, control, status, identity, generation, log = (
            self.spawn_registered_guardian(command, attempt=7)
        )
        try:
            os.write(control, b"go\n")
            os.close(control)
            control = -1
            deadline = time.monotonic() + 5
            while not command_pid_path.exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            command_pid = int(command_pid_path.read_text(encoding="utf-8"))
            release_worker.terminate_release_generation(
                guardian,
                lifecycle_root=self.lifecycle_root,
                repository=self.repository,
                identity=identity,
                generation=generation,
                graceful=True,
                grace_seconds=0.05,
            )
            release_worker.forget_release_generation(
                lifecycle_root=self.lifecycle_root,
                repository=self.repository,
                identity=identity,
                generation=generation,
            )
            self.fixture_groups.discard(guardian.pid)
            self.wait_process_gone(command_pid)
            self.assertEqual(self.lifecycle_records(), [])
        finally:
            if control >= 0:
                os.close(control)
            os.close(status)
            log.close()

    def test_guardian_status_parser_rejects_open_or_malformed_schema(self) -> None:
        valid = b'{"commandPid":123,"returnCode":0,"schemaVersion":1}\n'
        self.assertEqual(release_worker.parse_guardian_status(valid)["returnCode"], 0)
        invalid = (
            b"",
            b"{}\n",
            b'{"schemaVersion":1,"commandPid":123,"returnCode":0,"extra":1}\n',
            b'{"schemaVersion":1,"schemaVersion":1,"commandPid":123,"returnCode":0}\n',
            valid + valid,
            b"x" * (release_worker.GUARDIAN_STATUS_LIMIT + 1),
        )
        for raw in invalid:
            with self.subTest(raw=raw[:80]):
                with self.assertRaises(RuntimeError):
                    release_worker.parse_guardian_status(raw)

    def test_wrong_generation_does_not_signal_guardian(self) -> None:
        command = [sys.executable, "-c", "import time; time.sleep(60)"]
        guardian, control, status, identity, generation, log = (
            self.spawn_registered_guardian(command, attempt=4)
        )
        wrong = dict(generation)
        first = "0" if generation["launchToken"][0] != "0" else "1"
        wrong["launchToken"] = first + generation["launchToken"][1:]
        try:
            with self.assertRaisesRegex(RuntimeError, "termination failed"):
                release_worker.terminate_release_generation(
                    guardian,
                    lifecycle_root=self.lifecycle_root,
                    repository=self.repository,
                    identity=identity,
                    generation=wrong,
                    graceful=False,
                )
            self.assertIsNone(guardian.poll())
            self.assertEqual(len(self.lifecycle_records()), 1)
            release_worker.terminate_release_generation(
                guardian,
                lifecycle_root=self.lifecycle_root,
                repository=self.repository,
                identity=identity,
                generation=generation,
                graceful=False,
            )
            release_worker.forget_release_generation(
                lifecycle_root=self.lifecycle_root,
                repository=self.repository,
                identity=identity,
                generation=generation,
            )
            self.fixture_groups.discard(guardian.pid)
        finally:
            os.close(control)
            os.close(status)
            log.close()

    def test_lost_guardian_containment_kills_command_without_pgid_fallback(self) -> None:
        command_pid_path = self.base / "lost-guardian-command.pid"
        command = [
            sys.executable,
            "-c",
            (
                "import os,pathlib,signal,sys,time;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));"
                "time.sleep(60)"
            ),
            str(command_pid_path),
        ]
        guardian, control, status, identity, generation, log = (
            self.spawn_registered_guardian(command, attempt=5)
        )
        try:
            os.write(control, b"go\n")
            os.close(control)
            control = -1
            deadline = time.monotonic() + 5
            while not command_pid_path.exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            command_pid = int(command_pid_path.read_text(encoding="utf-8"))
            os.kill(guardian.pid, signal.SIGKILL)
            guardian.wait(timeout=5)
            self.wait_process_gone(command_pid)

            with self.assertRaisesRegex(RuntimeError, "termination failed"):
                release_worker.terminate_release_generation(
                    guardian,
                    lifecycle_root=self.lifecycle_root,
                    repository=self.repository,
                    identity=identity,
                    generation=generation,
                    graceful=False,
                )
            self.assertEqual(len(self.lifecycle_records()), 1)
            self.fixture_groups.discard(guardian.pid)
        finally:
            if control >= 0:
                os.close(control)
            os.close(status)
            log.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
