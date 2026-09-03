#!/usr/bin/env python3
"""Deterministic tests for unattended project health publication."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import inspect
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pm_agent", ROOT / "bin" / "pm-agent.py")
assert SPEC and SPEC.loader
pm_agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pm_agent)

AGENT_SPEC = importlib.util.spec_from_file_location(
    "pm_agent_health_collector", ROOT / "bin" / "agent-health.py"
)
assert AGENT_SPEC and AGENT_SPEC.loader
agent_health = importlib.util.module_from_spec(AGENT_SPEC)
AGENT_SPEC.loader.exec_module(agent_health)

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
REPOSITORY_ID = "a" * 64


def snapshot(**changes):
    value = {
        "schemaVersion": "agent-health-snapshot-v1",
        "generatedAt": "2026-08-29T12:00:00Z",
        "repositoryId": REPOSITORY_ID,
        "intervalSeconds": 300,
        "presentationOnly": True,
        "nonAgentProcessesOmitted": 0,
        "agents": [],
        "boards": [],
        "warnings": [],
    }
    value.update(changes)
    return value


def managed_record(*, category, instance, state, pid):
    return {
        "schemaVersion": 3,
        "repositoryId": REPOSITORY_ID,
        "team": "feature-a",
        "category": category,
        "instance": instance,
        "kind": "background",
        "pid": pid,
        "processIdentity": state,
        "createdAt": "2026-08-29T11:50:00Z",
        "tmuxSession": None,
        "tmuxWindow": None,
        "tmuxPane": None,
        "processGroupId": pid,
        "sessionId": pid,
        "tmuxPanePid": None,
        "state": state,
    }


class HealthPublisherTest(unittest.TestCase):
    def test_health_interval_is_independent_strict_and_defaults_to_five_minutes(self):
        self.assertEqual(300, pm_agent.healthcheck_interval_seconds({}))
        self.assertEqual(
            420,
            pm_agent.healthcheck_interval_seconds({"healthcheckIntervalMinutes": 7}),
        )
        for value in (True, 3.5, 0, 1441, "5"):
            with self.subTest(value=value), self.assertRaises(pm_agent.MonitorError):
                pm_agent.healthcheck_interval_seconds(
                    {"healthcheckIntervalMinutes": value}
                )

    def test_health_child_environment_omits_credentials_and_injection_controls(self):
        source = {
            "PATH": "/host/bin",
            "TMPDIR": "/private/tmp/test",
            "LANG": "C.UTF-8",
            "LINEAR_API_KEY": "secret",
            "GITHUB_TOKEN": "secret",
            "STARTUP_FACTORY_TRACKER_OPS": "/tmp/forged",
            "HOME": "/home/operator",
            "PYTHONPATH": "/tmp/inject",
            "LD_PRELOAD": "/tmp/inject.so",
        }
        self.assertEqual(
            {
                "PATH": pm_agent.ACTIVE_TRUSTED_PATH,
                "TMPDIR": "/private/tmp/test",
                "LANG": "C.UTF-8",
                "PYTHONNOUSERSITE": "1",
                "PYTHONSAFEPATH": "1",
            },
            pm_agent.health_child_environment(source),
        )

    def test_snapshot_validation_is_exact_current_and_project_bound(self):
        raw = json.dumps(snapshot(), separators=(",", ":")).encode() + b"\n"
        self.assertEqual(
            snapshot(),
            pm_agent.validate_health_snapshot(
                raw,
                repository_id=REPOSITORY_ID,
                interval_seconds=300,
                started_at=NOW - timedelta(seconds=1),
                finished_at=NOW + timedelta(seconds=1),
            ),
        )
        invalid = (
            b'{"schemaVersion":"agent-health-snapshot-v1","schemaVersion":"agent-health-snapshot-v1"}',
            raw + b"{}",
            raw.replace(b'"nonAgentProcessesOmitted":0', b'"nonAgentProcessesOmitted":NaN'),
            json.dumps(snapshot(repositoryId="b" * 64)).encode(),
            json.dumps(snapshot(intervalSeconds=180)).encode(),
            json.dumps(snapshot(presentationOnly=False)).encode(),
            json.dumps(snapshot(generatedAt="2026-08-29T11:00:00Z")).encode(),
        )
        for value in invalid:
            with self.subTest(value=value[:60]), self.assertRaises(pm_agent.MonitorError):
                pm_agent.validate_health_snapshot(
                    value,
                    repository_id=REPOSITORY_ID,
                    interval_seconds=300,
                    started_at=NOW - timedelta(seconds=1),
                    finished_at=NOW + timedelta(seconds=1),
                )

    def test_actual_exited_and_stalled_rows_publish_end_to_end(self):
        with tempfile.TemporaryDirectory() as temp:
            primary = Path(temp).resolve()
            heartbeat_dir = primary / ".teamwork" / "feature-a" / "heartbeats"
            heartbeat_dir.mkdir(parents=True)
            (heartbeat_dir / "team-lead").write_text(
                "not-a-valid-heartbeat\n", encoding="utf-8"
            )
            envelope = {
                "schemaVersion": "project-lifecycle-list-v1",
                "repositoryId": REPOSITORY_ID,
                "records": [
                    managed_record(
                        category="task",
                        instance="backend--task-key--a1",
                        state="dead",
                        pid=100,
                    ),
                    managed_record(
                        category="gate",
                        instance="team-lead",
                        state="live",
                        pid=101,
                    ),
                ],
                "legacyOmitted": 0,
                "warnings": [],
            }
            collected = agent_health.build_snapshot(
                envelope,
                repo=primary,
                teamwork_root=".teamwork",
                now=NOW,
                stuck_minutes=15,
                start_grace_seconds=60,
            )
            self.assertEqual(
                [None, None], [row["nextActionBy"] for row in collected["agents"]]
            )
            validated = pm_agent.validate_health_snapshot(
                json.dumps(collected).encode(),
                repository_id=REPOSITORY_ID,
                interval_seconds=300,
                started_at=NOW - timedelta(seconds=1),
                finished_at=NOW + timedelta(seconds=1),
            )
            self.assertTrue(pm_agent.atomic_health_snapshot(primary, validated))
            cached = json.loads(
                (primary / ".teamwork" / "pm-agent" / "agent-health.json").read_bytes()
            )
            self.assertEqual(
                {"exited", "stalled:malformed-heartbeat"},
                {row["verdict"] for row in cached["agents"]},
            )

    def test_atomic_publication_preserves_old_bytes_on_replace_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            primary = Path(temp).resolve()
            cache = primary / ".teamwork" / "pm-agent" / "agent-health.json"
            cache.parent.mkdir(parents=True)
            old = b'{"generatedAt":"old"}\n'
            cache.write_bytes(old)
            cache.chmod(0o600)
            with mock.patch.object(pm_agent.os, "replace", side_effect=OSError("boom")):
                with self.assertRaises(pm_agent.MonitorError):
                    pm_agent.atomic_health_snapshot(primary, snapshot())
            self.assertEqual(old, cache.read_bytes())
            self.assertEqual([], list(cache.parent.glob(".agent-health.json.tmp.*")))

    def test_post_replace_directory_fsync_failure_is_committed_with_warning(self):
        with tempfile.TemporaryDirectory() as temp:
            primary = Path(temp).resolve()
            real_fsync = pm_agent.os.fsync
            calls = 0

            def fsync(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("directory durability unavailable")
                return real_fsync(descriptor)

            with (
                mock.patch.object(pm_agent.os, "fsync", side_effect=fsync),
                self.assertWarnsRegex(RuntimeWarning, "committed.*durability"),
            ):
                self.assertTrue(pm_agent.atomic_health_snapshot(primary, snapshot()))
            cache = primary / ".teamwork" / "pm-agent" / "agent-health.json"
            self.assertEqual(snapshot(), json.loads(cache.read_bytes()))

    def test_atomic_publication_rejects_symlinked_managed_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            primary = Path(temp) / "primary"
            outside = Path(temp) / "outside"
            primary.mkdir()
            outside.mkdir()
            (primary / ".teamwork").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(pm_agent.MonitorError):
                pm_agent.atomic_health_snapshot(primary, snapshot())
            self.assertEqual([], list(outside.iterdir()))

    def test_dual_clock_is_immediate_independent_and_skips_missed_slots(self):
        clock = [0.0]
        calls = []

        def monotonic():
            return clock[0]

        def sleep(seconds):
            clock[0] += seconds

        def scan():
            calls.append(("scan", clock[0]))
            if len(calls) == 3:
                clock[0] += 500

        def health():
            calls.append(("health", clock[0]))

        pm_agent.watch_supervisor(
            scan,
            health,
            scan_interval_seconds=180,
            health_interval_seconds=300,
            monotonic=monotonic,
            sleep=sleep,
            maximum_callbacks=6,
        )
        self.assertEqual(
            [
                ("health", 0.0),
                ("scan", 0.0),
                ("scan", 180.0),
                ("health", 680.0),
                ("scan", 720.0),
                ("health", 900.0),
            ],
            calls,
        )

    def test_dual_clock_isolates_health_and_scan_failures(self):
        clock = [0.0]
        attempts = []
        errors = []

        def monotonic():
            return clock[0]

        def sleep(seconds):
            clock[0] += seconds

        def scan():
            attempts.append(("scan", clock[0]))
            if len([item for item in attempts if item[0] == "scan"]) == 1:
                raise pm_agent.MonitorError("scan failed")

        def health():
            attempts.append(("health", clock[0]))
            if len([item for item in attempts if item[0] == "health"]) == 1:
                raise pm_agent.MonitorError("health failed")

        pm_agent.watch_supervisor(
            scan,
            health,
            scan_interval_seconds=180,
            health_interval_seconds=300,
            monotonic=monotonic,
            sleep=sleep,
            maximum_callbacks=4,
            on_error=lambda label, exc: errors.append((label, str(exc))),
        )
        self.assertEqual(
            [("health", 0.0), ("scan", 0.0), ("scan", 180.0), ("health", 300.0)],
            attempts,
        )
        self.assertEqual([("health", "health failed"), ("scan", "scan failed")], errors)

    def test_one_shot_bypasses_tracker_and_board_pass(self):
        config = {"healthcheckIntervalMinutes": 5, "enabled": False}
        project = Path("/project")
        with (
            mock.patch.object(
                pm_agent,
                "bootstrap_automation",
                return_value=(config, Path("/protected/config.json"), project, Path("/python")),
            ),
            mock.patch.object(
                pm_agent,
                "health_runtime_context",
                return_value=(Path("/primary"), Path("/lifecycle"), ".teamwork", 15, 60),
            ),
            mock.patch.object(pm_agent, "collect_and_publish_health") as publish,
            mock.patch.object(pm_agent, "one_pass") as board_pass,
            mock.patch.object(pm_agent, "validate_pm_automation") as tracker_validation,
        ):
            self.assertEqual(0, pm_agent.one_healthcheck())
        publish.assert_called_once()
        board_pass.assert_not_called()
        tracker_validation.assert_not_called()

    def test_collection_uses_fixed_isolated_command_and_current_interval(self):
        captured = {}

        def run(argv, **kwargs):
            captured["argv"] = argv
            captured["env"] = kwargs["env"]
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(snapshot(intervalSeconds=420)).encode(),
                b"",
            )

        with (
            mock.patch.dict(
                os.environ,
                {"LINEAR_API_KEY": "secret", "STARTUP_FACTORY_TRACKER_OPS": "/forged"},
                clear=False,
            ),
            mock.patch.object(pm_agent, "run_bounded_health_child", side_effect=run),
            mock.patch.object(pm_agent, "utc_now", side_effect=[NOW, NOW]),
        ):
            value = pm_agent.collect_health_snapshot(
                primary=Path("/project"),
                lifecycle_root=Path("/protected/lifecycle"),
                teamwork_root=".teamwork",
                stuck_minutes=15,
                start_grace_seconds=60,
                repository_id=REPOSITORY_ID,
                interval_seconds=420,
            )
        self.assertEqual(420, value["intervalSeconds"])
        self.assertEqual(["-I", "-S", "-E", "-s"], captured["argv"][1:5])
        self.assertEqual(
            [
                "--repo",
                "/project",
                "--teamwork-root",
                ".teamwork",
                "--lifecycle-root",
                "/protected/lifecycle",
                "--stuck-minutes",
                "15",
                "--start-grace-seconds",
                "60",
                "--interval-seconds",
                "420",
                "--json",
            ],
            captured["argv"][6:],
        )
        self.assertNotIn("LINEAR_API_KEY", captured["env"])
        self.assertNotIn("STARTUP_FACTORY_TRACKER_OPS", captured["env"])

    def test_collection_failure_preserves_existing_snapshot_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as temp:
            primary = Path(temp).resolve()
            cache = primary / ".teamwork" / "pm-agent" / "agent-health.json"
            cache.parent.mkdir(parents=True)
            old = b'{"generatedAt":"2026-08-29T11:59:00Z","opaque":"old"}\n'
            cache.write_bytes(old)
            cache.chmod(0o600)
            context = (primary, Path("/lifecycle"), ".teamwork", 15, 60)
            with (
                mock.patch.object(
                    pm_agent,
                    "canonical_project_context",
                    return_value=(primary, REPOSITORY_ID),
                ),
                mock.patch.object(
                    pm_agent,
                    "collect_health_snapshot",
                    side_effect=pm_agent.MonitorError("invalid collector output"),
                ),
                self.assertRaises(pm_agent.MonitorError),
            ):
                pm_agent.collect_and_publish_health({}, primary, context)
            self.assertEqual(old, cache.read_bytes())

    def test_newer_or_future_generation_never_regresses(self):
        with tempfile.TemporaryDirectory() as temp:
            primary = Path(temp).resolve()
            newer = snapshot(generatedAt="2099-01-01T00:00:00Z")
            older = snapshot(generatedAt="2026-08-29T12:00:00Z")
            self.assertTrue(pm_agent.atomic_health_snapshot(primary, newer))
            cache = primary / ".teamwork" / "pm-agent" / "agent-health.json"
            first = cache.read_bytes()
            self.assertFalse(pm_agent.atomic_health_snapshot(primary, older))
            self.assertEqual(first, cache.read_bytes())

    def test_concurrent_readers_never_observe_partial_json(self):
        with tempfile.TemporaryDirectory() as temp:
            primary = Path(temp).resolve()
            pm_agent.atomic_health_snapshot(primary, snapshot())
            cache = primary / ".teamwork" / "pm-agent" / "agent-health.json"
            errors = []
            stop = threading.Event()

            def reader():
                while not stop.is_set():
                    try:
                        value = json.loads(cache.read_bytes())
                        self.assertEqual("agent-health-snapshot-v1", value["schemaVersion"])
                    except Exception as exc:  # pragma: no cover - captured for the main thread
                        errors.append(exc)
                        stop.set()

            thread = threading.Thread(target=reader)
            thread.start()
            try:
                for index in range(1, 30):
                    pm_agent.atomic_health_snapshot(
                        primary,
                        snapshot(generatedAt=f"2026-08-29T12:00:{index:02d}Z"),
                    )
            finally:
                stop.set()
                thread.join(timeout=5)
            self.assertEqual([], errors)

    def test_existing_symlink_target_is_refused_not_replaced(self):
        with tempfile.TemporaryDirectory() as temp:
            primary = Path(temp) / "primary"
            outside = Path(temp) / "outside.json"
            cache_dir = primary / ".teamwork" / "pm-agent"
            cache_dir.mkdir(parents=True)
            outside.write_text("outside\n", encoding="utf-8")
            (cache_dir / "agent-health.json").symlink_to(outside)
            with self.assertRaises(pm_agent.MonitorError):
                pm_agent.atomic_health_snapshot(primary, snapshot())
            self.assertEqual("outside\n", outside.read_text(encoding="utf-8"))

    def test_fifo_cache_is_rejected_promptly_and_does_not_delay_watch_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            primary = Path(temp).resolve()
            cache = primary / ".teamwork" / "pm-agent" / "agent-health.json"
            cache.parent.mkdir(parents=True)
            os.mkfifo(cache, mode=0o600)
            scans = []
            errors = []
            durations = []

            def run_watch():
                started = time.monotonic()
                pm_agent.watch_supervisor(
                    lambda: scans.append("scan"),
                    lambda: pm_agent.atomic_health_snapshot(primary, snapshot()),
                    scan_interval_seconds=180,
                    health_interval_seconds=300,
                    maximum_callbacks=2,
                    on_error=lambda label, exc: errors.append((label, str(exc))),
                )
                durations.append(time.monotonic() - started)

            thread = threading.Thread(target=run_watch, daemon=True)
            thread.start()
            thread.join(timeout=0.5)
            completed_promptly = not thread.is_alive()
            if thread.is_alive():
                # Wake a blocking pre-fix FIFO open so the regression can fail
                # without leaking a stuck test thread.
                descriptor = os.open(cache, os.O_RDWR | os.O_NONBLOCK)
                os.close(descriptor)
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive(), "health publication stayed blocked on a FIFO")
            self.assertTrue(completed_promptly, "health publication did not reject the FIFO promptly")
            self.assertLess(durations[0], 0.5)
            self.assertEqual(["scan"], scans)
            self.assertEqual("health", errors[0][0])
            self.assertIn("regular file", errors[0][1])
            self.assertTrue(stat.S_ISFIFO(os.lstat(cache).st_mode))

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets unavailable")
    def test_socket_cache_is_rejected_without_target_mutation(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            primary = Path(temp).resolve()
            cache = primary / ".teamwork" / "pm-agent" / "agent-health.json"
            cache.parent.mkdir(parents=True)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                try:
                    listener.bind(os.path.relpath(cache, Path.cwd()))
                except PermissionError as exc:
                    self.skipTest(f"Unix socket bind denied by test sandbox: {exc}")
                with self.assertRaises(pm_agent.MonitorError):
                    pm_agent.atomic_health_snapshot(primary, snapshot())
                self.assertTrue(stat.S_ISSOCK(os.lstat(cache).st_mode))
            finally:
                listener.close()

    def test_held_directory_descriptor_defeats_post_open_ancestor_swap(self):
        with tempfile.TemporaryDirectory() as temp:
            primary = Path(temp).resolve()
            outside = primary / "outside"
            outside.mkdir()
            with pm_agent.health_publication_lock(primary) as directory:
                original = primary / ".teamwork"
                held = primary / ".teamwork-held"
                original.rename(held)
                original.symlink_to(outside, target_is_directory=True)
                self.assertTrue(pm_agent._atomic_health_snapshot_at(directory, snapshot()))
            self.assertTrue((held / "pm-agent" / "agent-health.json").is_file())
            self.assertEqual([], list(outside.iterdir()))

    def test_health_child_enforces_stdout_stderr_and_time_bounds(self):
        base = [sys.executable, "-I", "-S", "-E", "-s", "-c"]
        with (
            mock.patch.object(pm_agent, "MAX_HEALTH_STDOUT_BYTES", 32),
            self.assertRaisesRegex(pm_agent.MonitorError, "stdout exceeded"),
        ):
            pm_agent.run_bounded_health_child(
                base + ["print('x' * 1000)"], cwd=ROOT, env=pm_agent.health_child_environment({})
            )
        with (
            mock.patch.object(pm_agent, "MAX_HEALTH_STDERR_BYTES", 32),
            self.assertRaisesRegex(pm_agent.MonitorError, "stderr exceeded"),
        ):
            pm_agent.run_bounded_health_child(
                base + ["import sys; print('x' * 1000, file=sys.stderr)"],
                cwd=ROOT,
                env=pm_agent.health_child_environment({}),
            )
        with self.assertRaisesRegex(pm_agent.MonitorError, "operation deadline"):
            pm_agent.run_bounded_health_child(
                base + ["import time; time.sleep(2)"],
                cwd=ROOT,
                env=pm_agent.health_child_environment({}),
                timeout_seconds=0.05,
            )

    def test_health_child_cleanup_kills_term_ignoring_group_descendant(self):
        descendant_code = (
            "import os,signal,time;"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            "print(os.getpid(), flush=True);"
            "time.sleep(60)"
        )
        leader_code = (
            "import subprocess,sys,time;"
            f"child=subprocess.Popen({[sys.executable, '-I', '-S', '-E', '-s', '-c', descendant_code]!r},"
            "stdout=subprocess.PIPE,text=True);"
            "print(child.stdout.readline().strip(), flush=True);"
            "time.sleep(60)"
        )
        leader = subprocess.Popen(
            [sys.executable, "-I", "-S", "-E", "-s", "-c", leader_code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        assert leader.stdout is not None
        descendant_pid = int(leader.stdout.readline().strip())

        def pid_exists(pid):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return False
            return True

        started = time.monotonic()
        try:
            with (
                mock.patch.object(pm_agent, "COMMAND_KILL_GRACE_SECONDS", 0.1),
                mock.patch.object(
                    pm_agent,
                    "HEALTH_CHILD_KILL_GRACE_SECONDS",
                    1.0,
                    create=True,
                ),
            ):
                pm_agent._stop_health_child(leader)
            self.assertLess(time.monotonic() - started, 2)
            deadline = time.monotonic() + 1
            while pid_exists(descendant_pid) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(pid_exists(descendant_pid), "descendant survived group cleanup")
            self.assertIsNotNone(leader.poll())
        finally:
            try:
                os.killpg(leader.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                leader.wait(timeout=1)
            except subprocess.TimeoutExpired:
                leader.kill()
                leader.wait(timeout=1)
            if leader.stdout is not None:
                leader.stdout.close()
            if leader.stderr is not None:
                leader.stderr.close()

    def test_protected_install_rejects_missing_symlinked_or_writable_helper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            project = root / "project"
            install = root / "install" / "bin"
            project.mkdir()
            install.mkdir(parents=True)
            required = (
                "release-worker.py",
                "process-lifecycle.py",
                "agent-health.py",
                "heartbeat-status.py",
                "teamwork-path.py",
            )
            for name in required:
                (install / name).write_text("# fixture\n", encoding="utf-8")
                (install / name).chmod(0o600)
            with mock.patch.object(pm_agent, "RELEASE_WORKER", install / "release-worker.py"):
                pm_agent.validate_supervisor_install(project)
                (install / "agent-health.py").unlink()
                with self.assertRaises(pm_agent.MonitorError):
                    pm_agent.validate_supervisor_install(project)
                (install / "agent-health.py").symlink_to(install / "heartbeat-status.py")
                with self.assertRaises(pm_agent.MonitorError):
                    pm_agent.validate_supervisor_install(project)
                (install / "agent-health.py").unlink()
                (install / "agent-health.py").write_text("# fixture\n", encoding="utf-8")
                (install / "agent-health.py").chmod(0o666)
                with self.assertRaises(pm_agent.MonitorError):
                    pm_agent.validate_supervisor_install(project)

    def test_real_healthcheck_cli_targets_primary_and_ignores_disabled_tracker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            install = root / "protected-install"
            bin_dir = install / "bin"
            config_dir = install / "config"
            bin_dir.mkdir(parents=True)
            config_dir.mkdir()
            for name in (
                "pm-agent.py",
                "release-worker.py",
                "process-lifecycle.py",
                "agent-health.py",
                "board-status.py",
                "heartbeat-status.py",
                "teamwork-path.py",
            ):
                shutil.copy2(ROOT / "bin" / name, bin_dir / name)
            primary = root / "primary"
            linked = root / "linked"
            primary.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main", str(primary)], check=True)
            subprocess.run(["git", "-C", str(primary), "config", "user.email", "health@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(primary), "config", "user.name", "Health Test"], check=True)
            (primary / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(primary), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(primary), "commit", "-q", "-m", "fixture"], check=True)
            subprocess.run(["git", "-C", str(primary), "worktree", "add", "-q", str(linked)], check=True)
            lifecycle = root / "lifecycle"
            lifecycle.mkdir(mode=0o700)
            team_config = config_dir / "team.config.md"
            team_config.write_text(
                "TEAMWORK_ROOT=.teamwork\n"
                "STUCK_AFTER_MINUTES=15\n"
                "START_GRACE_SECONDS=60\n"
                f'BROKER_LIFECYCLE_ROOT="{lifecycle}"\n',
                encoding="utf-8",
            )
            team_config.chmod(0o600)
            automation = root / "automation.json"
            automation.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "enabled": False,
                        "trustedPath": "/usr/bin:/bin",
                        "healthcheckIntervalMinutes": 5,
                    }
                ),
                encoding="utf-8",
            )
            automation.chmod(0o600)
            environment = {
                "PATH": "/usr/bin:/bin",
                "STARTUP_FACTORY_PROJECT_ROOT": str(linked),
                "STARTUP_FACTORY_AUTOMATION_CONFIG": str(automation),
                "LINEAR_API_KEY": "must-not-reach-health-child",
            }
            result = subprocess.run(
                [sys.executable, str(bin_dir / "pm-agent.py"), "--healthcheck"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            cache = primary / ".teamwork" / "pm-agent" / "agent-health.json"
            value = json.loads(cache.read_text(encoding="utf-8"))
            self.assertTrue(value["presentationOnly"])
            self.assertEqual(300, value["intervalSeconds"])
            self.assertFalse((linked / ".teamwork" / "pm-agent" / "agent-health.json").exists())

    def test_workflow_pass_has_no_health_cache_authority_read(self):
        self.assertNotIn("agent-health.json", inspect.getsource(pm_agent.one_pass))
        self.assertNotIn("snapshot[", inspect.getsource(pm_agent.one_healthcheck))


if __name__ == "__main__":
    unittest.main()
