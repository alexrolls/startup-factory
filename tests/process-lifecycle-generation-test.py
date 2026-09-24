#!/usr/bin/env python3
"""Regression tests for generation-bound lifecycle mutation."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
LIFECYCLE = ROOT / "bin" / "process-lifecycle.py"


class ProcessLifecycleGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        self.lifecycle_root = self.base / "protected-lifecycle"
        self.lifecycle_root.mkdir(mode=0o700)
        self.processes: list[subprocess.Popen[str]] = []

    def tearDown(self) -> None:
        for process in self.processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        self.temporary.cleanup()

    def command(
        self,
        operation: str,
        *arguments: str,
        input_text: str | None = None,
        repo: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(LIFECYCLE),
                operation,
                "--root",
                str(self.lifecycle_root),
                "--repo",
                str(repo or self.repo),
                *arguments,
            ],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

    def spawn_session_leader(self) -> subprocess.Popen[str]:
        process = subprocess.Popen(
            [sys.executable, "-c", "import os,time; os.setsid(); time.sleep(60)"],
            text=True,
        )
        self.processes.append(process)
        # Registration retries while setsid() wins the scheduling race.
        return process

    def spawn_leader_with_surviving_child(
        self,
    ) -> tuple[subprocess.Popen[str], int]:
        code = """
import os, signal, subprocess, sys, time
os.setsid()
child = subprocess.Popen([
    sys.executable,
    "-c",
    "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
])
print(child.pid, flush=True)
time.sleep(60)
"""
        process = subprocess.Popen(
            [sys.executable, "-c", code],
            text=True,
            stdout=subprocess.PIPE,
        )
        self.processes.append(process)
        self.assertIsNotNone(process.stdout)
        assert process.stdout is not None
        child_pid = int(process.stdout.readline().strip())
        process.stdout.close()
        self.addCleanup(self.kill_group, process.pid)
        return process, child_pid

    @staticmethod
    def kill_group(process_group_id: int) -> None:
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def register(
        self,
        process: subprocess.Popen[str],
        *,
        repo: Path | None = None,
        category: str = "task",
        instance: str = "backend--task--a1",
    ) -> dict[str, object]:
        result = self.command(
            "register",
            "--team",
            "replacement-team",
            "--category",
            category,
            "--instance",
            instance,
            "--kind",
            "background",
            "--pid",
            str(process.pid),
            repo=repo,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_tmux_registration_binds_preissued_generation_from_stdin(self) -> None:
        process = self.spawn_session_leader()
        identity = (
            "--team", "replacement-team", "--category", "task",
            "--instance", "backend--task--a1", "--kind", "tmux",
            "--pid", str(process.pid), "--tmux-session", "team-replacement-team",
            "--tmux-window", "backend--task--a1", "--tmux-pane", "%1",
            "--tmux-pane-pid", str(process.pid), "--launch-token-stdin",
        )
        malformed = self.command("register", *identity, input_text="0" * 63 + "\n")
        self.assertNotEqual(malformed.returncode, 0)
        self.assertIn("malformed", malformed.stderr)
        self.assertEqual(self.record_paths(), [])

        token = "a" * 64
        issued = self.command("register", *identity, input_text=token + "\n")
        self.assertEqual(issued.returncode, 0, issued.stderr)
        self.assertEqual(json.loads(issued.stdout)["launchToken"], token)
        self.assertEqual(
            json.loads(self.record_paths()[0].read_text(encoding="utf-8"))["launchToken"],
            token,
        )

    def test_background_registration_refuses_preissued_token(self) -> None:
        process = self.spawn_session_leader()
        issued = self.command(
            "register", "--team", "replacement-team", "--category", "task",
            "--instance", "backend--task--a1", "--kind", "background",
            "--pid", str(process.pid), "--launch-token-stdin",
            input_text="a" * 64 + "\n",
        )
        self.assertNotEqual(issued.returncode, 0)
        self.assertIn("only for tmux", issued.stderr)
        self.assertEqual(self.record_paths(), [])

    def ensure_lock(self) -> Path:
        initialized = self.command("init")
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        path = self.lifecycle_root / "records.lock"
        self.assertTrue(path.is_file())
        return path

    def stop_process(self, process: subprocess.Popen[str]) -> None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)

    def assert_generation_refused(
        self, result: subprocess.CompletedProcess[str]
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("generation changed", result.stderr)

    def record_paths(self) -> list[Path]:
        return list((self.lifecycle_root / "records").glob("*.json"))

    def project_list(self, repo: Path | None = None) -> dict[str, object]:
        result = self.command("project-list", repo=repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def add_legacy_copy(self, record: dict[str, object]) -> Path:
        legacy = dict(record)
        legacy["schemaVersion"] = 2
        legacy.pop("repositoryId")
        legacy.pop("auth")
        key = (self.lifecycle_root / "record-auth.key").read_bytes()
        encoded = json.dumps(
            legacy, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        legacy["auth"] = hmac.new(key, encoded, hashlib.sha256).hexdigest()
        filename = hashlib.sha256(
            str(record["team"]).encode("utf-8")
            + b"\0"
            + str(record["category"]).encode("ascii")
            + b"\0"
            + str(record["instance"]).encode("utf-8")
        ).hexdigest()
        path = self.lifecycle_root / "records" / f"{filename}.json"
        path.write_text(
            json.dumps(legacy, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def resign_record(self, mutate: dict[str, object]) -> None:
        paths = self.record_paths()
        self.assertEqual(len(paths), 1)
        path = paths[0]
        record = json.loads(path.read_text(encoding="utf-8"))
        record.update(mutate)
        record.pop("auth")
        key = (self.lifecycle_root / "record-auth.key").read_bytes()
        encoded = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        record["auth"] = hmac.new(key, encoded, hashlib.sha256).hexdigest()
        path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def test_stale_generation_cannot_signal_or_forget_replacement(self) -> None:
        original_process = self.spawn_session_leader()
        original = self.register(original_process)
        self.stop_process(original_process)

        # Reuse the exact logical identity with a new process generation.
        replacement_process = self.spawn_session_leader()
        replacement = self.register(replacement_process)
        self.assertNotEqual(original["launchToken"], replacement["launchToken"])
        self.assertNotEqual(original["createdAt"], replacement["createdAt"])

        common = (
            "--team",
            "replacement-team",
            "--category",
            "task",
            "--instance",
            "backend--task--a1",
        )
        stale_token = str(original["launchToken"]) + "\n"

        result = self.command(
            "signal",
            *common,
            "--expect-token-stdin",
            "--signal",
            "TERM",
            input_text=stale_token,
        )
        self.assert_generation_refused(result)
        self.assertIsNone(
            replacement_process.poll(), "stale token signalled replacement process"
        )

        result = self.command(
            "forget", *common, "--expect-token-stdin", input_text=stale_token
        )
        self.assert_generation_refused(result)
        self.assertEqual(len(self.record_paths()), 1)
        self.assertIsNone(replacement_process.poll())

        result = self.command(
            "forget",
            *common,
            "--expected-created-at",
            str(original["createdAt"]),
        )
        self.assert_generation_refused(result)
        self.assertEqual(len(self.record_paths()), 1)
        self.assertIsNone(replacement_process.poll())

        # Generation checks must still preserve a dead replacement record; a
        # live-process refusal alone would not protect this case.
        self.stop_process(replacement_process)
        time.sleep(0.02)
        result = self.command(
            "complete",
            *common,
            "--expect-token-stdin",
            input_text=stale_token,
        )
        self.assert_generation_refused(result)
        self.assertEqual(len(self.record_paths()), 1)

        result = self.command(
            "complete",
            *common,
            "--expected-created-at",
            str(original["createdAt"]),
        )
        self.assert_generation_refused(result)
        self.assertEqual(len(self.record_paths()), 1)

        result = self.command(
            "forget", *common, "--expect-token-stdin", input_text=stale_token
        )
        self.assert_generation_refused(result)
        self.assertEqual(len(self.record_paths()), 1)

        result = self.command(
            "forget",
            *common,
            "--expected-created-at",
            str(original["createdAt"]),
        )
        self.assert_generation_refused(result)
        self.assertEqual(len(self.record_paths()), 1)

        result = self.command(
            "forget",
            *common,
            "--expected-created-at",
            str(replacement["createdAt"]),
            "--expect-token-stdin",
            input_text=str(replacement["launchToken"]) + "\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.record_paths(), [])

    def test_paused_failed_launch_cleanup_cannot_signal_successor(self) -> None:
        """Cleanup retained before a pause never adopts successor authority."""

        failed_process = self.spawn_session_leader()
        failed = self.register(
            failed_process, category="gate", instance="principal-architect"
        )
        self.stop_process(failed_process)

        # This replacement is the deterministic pause boundary: A has failed,
        # cleanup retained A's exact identities, and B becomes current before
        # that cleanup resumes.
        successor_process = self.spawn_session_leader()
        successor = self.register(
            successor_process, category="gate", instance="principal-architect"
        )
        self.assertNotEqual(failed["createdAt"], successor["createdAt"])
        self.assertNotEqual(failed["launchToken"], successor["launchToken"])

        resumed_cleanup = self.command(
            "signal",
            "--team",
            "replacement-team",
            "--category",
            "gate",
            "--instance",
            "principal-architect",
            "--expected-created-at",
            str(failed["createdAt"]),
            "--expect-token-stdin",
            "--signal",
            "TERM",
            input_text=str(failed["launchToken"]) + "\n",
        )
        self.assert_generation_refused(resumed_cleanup)
        self.assertIsNone(
            successor_process.poll(),
            "paused failed-launch cleanup signalled the successor generation",
        )
        persisted = json.loads(self.record_paths()[0].read_text(encoding="utf-8"))
        self.assertEqual(persisted["createdAt"], successor["createdAt"])
        self.assertEqual(persisted["launchToken"], successor["launchToken"])

    def test_missing_leader_identity_never_revives_group_authority(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "process_lifecycle_under_test", LIFECYCLE
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        assert spec is not None and spec.loader is not None
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        record = {
            "schemaVersion": 3,
            "kind": "background",
            "pid": 4242,
            "processGroupId": 4242,
            "sessionId": 4242,
            "processIdentity": "linux:original-boot:1",
        }

        with (
            mock.patch.object(lifecycle, "process_identity", return_value=None),
            mock.patch.object(lifecycle, "group_exists", return_value=True),
            mock.patch.object(lifecycle.os, "killpg") as killpg,
        ):
            self.assertEqual(lifecycle.record_state(record), "identity-mismatch")
            with self.assertRaisesRegex(
                lifecycle.LifecycleError, "protected leader identity changed"
            ):
                lifecycle.safe_signal_group(record, signal.SIGTERM)
            killpg.assert_not_called()

    def test_identity_mismatch_cannot_be_probed_scanned_or_replaced(self) -> None:
        original_process, child_pid = self.spawn_leader_with_surviving_child()
        original = self.register(original_process)
        os.kill(original_process.pid, signal.SIGTERM)
        original_process.wait(timeout=5)
        os.kill(child_pid, 0)

        common = (
            "--team",
            "replacement-team",
            "--category",
            "task",
            "--instance",
            "backend--task--a1",
        )
        probed = self.command(
            "probe",
            *common,
            "--expected-created-at",
            str(original["createdAt"]),
            "--expect-token-stdin",
            input_text=str(original["launchToken"]) + "\n",
        )
        self.assertNotEqual(probed.returncode, 0)
        self.assertIn("identity mismatch", probed.stderr)

        scanned = self.command(
            "any-live", "--team", "replacement-team", "--category", "task"
        )
        self.assertNotEqual(scanned.returncode, 0)
        self.assertIn("identity mismatch", scanned.stderr)

        replacement_process = self.spawn_session_leader()
        replacement = self.command(
            "register",
            *common,
            "--kind",
            "background",
            "--pid",
            str(replacement_process.pid),
        )
        self.assertNotEqual(replacement.returncode, 0)
        self.assertIn("identity mismatch", replacement.stderr)
        persisted = json.loads(self.record_paths()[0].read_text(encoding="utf-8"))
        self.assertEqual(persisted["createdAt"], original["createdAt"])
        self.assertEqual(persisted["launchToken"], original["launchToken"])
        self.assertIsNone(replacement_process.poll())
        os.kill(child_pid, 0)

    def test_completed_background_generation_keeps_evidence_without_signal_authority(
        self,
    ) -> None:
        process = self.spawn_session_leader()
        record = self.register(process)
        common = (
            "--team",
            "replacement-team",
            "--category",
            "task",
            "--instance",
            "backend--task--a1",
        )
        live_completion = self.command(
            "complete",
            *common,
            "--expected-created-at",
            str(record["createdAt"]),
            "--expect-token-stdin",
            input_text=str(record["launchToken"]) + "\n",
        )
        self.assertNotEqual(live_completion.returncode, 0)
        self.assertIn("live lifecycle generation", live_completion.stderr)
        self.assertIsNone(process.poll())

        self.stop_process(process)
        completed = self.command(
            "complete",
            *common,
            "--expected-created-at",
            str(record["createdAt"]),
            "--expect-token-stdin",
            input_text=str(record["launchToken"]) + "\n",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        listing = self.command("list", "--team", "replacement-team")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        rows = [json.loads(line) for line in listing.stdout.splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "dead")
        self.assertEqual(rows[0]["kind"], "completed-background")

        signalled = self.command(
            "signal",
            *common,
            "--expect-token-stdin",
            input_text=str(record["launchToken"]) + "\n",
        )
        self.assertNotEqual(signalled.returncode, 0)
        self.assertIn("unsupported process kind", signalled.stderr)

    def test_release_inspection_returns_live_dead_and_completed_exact_record(
        self,
    ) -> None:
        process = self.spawn_session_leader()
        record = self.register(
            process, category="release", instance="production-release"
        )
        common = (
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "production-release",
        )

        live = self.command("inspect", *common)
        self.assertEqual(live.returncode, 0, live.stderr)
        live_record = json.loads(live.stdout)
        self.assertEqual(live_record["launchToken"], record["launchToken"])
        self.assertEqual(live_record["auth"], record["auth"])
        self.assertEqual(live_record["kind"], "background")

        self.stop_process(process)
        dead = self.command("inspect", *common)
        self.assertEqual(dead.returncode, 0, dead.stderr)
        dead_record = json.loads(dead.stdout)
        self.assertEqual(dead_record, live_record)

        completed = self.command(
            "complete",
            *common,
            "--expected-created-at",
            str(record["createdAt"]),
            "--expect-token-stdin",
            input_text=str(record["launchToken"]) + "\n",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        inspected_completed = self.command("inspect", *common)
        self.assertEqual(inspected_completed.returncode, 0, inspected_completed.stderr)
        completed_record = json.loads(inspected_completed.stdout)
        self.assertEqual(completed_record["kind"], "completed-background")
        self.assertEqual(completed_record["launchToken"], record["launchToken"])
        self.assertEqual(completed_record["createdAt"], record["createdAt"])

        listing = self.command("list", "--team", "replacement-team")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        listed = json.loads(listing.stdout)
        self.assertNotIn("launchToken", listed)
        self.assertNotIn("auth", listed)
        project = self.project_list()
        self.assertNotIn("launchToken", project["records"][0])
        self.assertNotIn("auth", project["records"][0])

    def test_release_inspection_returns_not_live_when_absent(self) -> None:
        absent = self.command(
            "inspect",
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "missing-release",
        )
        self.assertEqual(absent.returncode, 3, absent.stderr)
        self.assertEqual(absent.stdout, "")

    def test_release_inspection_rejects_tampered_record(self) -> None:
        process = self.spawn_session_leader()
        record = self.register(
            process, category="release", instance="production-release"
        )
        path = self.record_paths()[0]
        record["launchToken"] = "0" * 64
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        path.chmod(0o600)

        inspected = self.command(
            "inspect",
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "production-release",
        )
        self.assertNotEqual(inspected.returncode, 0)
        self.assertIn("authentication failed", inspected.stderr)

    def test_release_inspection_rejects_legacy_ambiguity_and_unbound_legacy(
        self,
    ) -> None:
        process = self.spawn_session_leader()
        record = self.register(
            process, category="release", instance="production-release"
        )
        legacy_path = self.add_legacy_copy(record)
        common = (
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "production-release",
        )

        ambiguous = self.command("inspect", *common)
        self.assertNotEqual(ambiguous.returncode, 0)
        self.assertIn("ambiguous", ambiguous.stderr)

        for path in self.record_paths():
            if path != legacy_path:
                path.unlink()
        unbound = self.command("inspect", *common)
        self.assertNotEqual(unbound.returncode, 0)
        self.assertIn("repository-bound", unbound.stderr)

    def test_release_inspection_is_project_bound(self) -> None:
        other_repo = self.base / "other-repo"
        other_repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=other_repo, check=True)
        process = self.spawn_session_leader()
        self.register(process, category="release", instance="production-release")

        wrong_project = self.command(
            "inspect",
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "production-release",
            repo=other_repo,
        )
        self.assertEqual(wrong_project.returncode, 3, wrong_project.stderr)
        self.assertEqual(wrong_project.stdout, "")

    def test_release_inspection_rejects_non_release_category(self) -> None:
        process = self.spawn_session_leader()
        record = self.register(process)
        inspected = self.command(
            "inspect",
            "--team",
            "replacement-team",
            "--category",
            "task",
            "--instance",
            "backend--task--a1",
        )
        self.assertNotEqual(inspected.returncode, 0)
        self.assertIn("invalid choice", inspected.stderr)
        self.assertIsNone(process.poll())
        persisted = json.loads(self.record_paths()[0].read_text(encoding="utf-8"))
        self.assertEqual(persisted["launchToken"], record["launchToken"])

    def test_atomic_release_termination_tombstones_exact_generation(self) -> None:
        process = self.spawn_session_leader()
        record = self.register(
            process, category="release", instance="production-release"
        )
        common = (
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "production-release",
            "--expected-created-at",
            str(record["createdAt"]),
            "--expect-token-stdin",
        )
        token = str(record["launchToken"]) + "\n"

        terminated = self.command("terminate", *common, input_text=token)
        self.assertEqual(terminated.returncode, 0, terminated.stderr)
        process.wait(timeout=5)

        listing = self.command("list", "--team", "replacement-team")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        rows = [json.loads(line) for line in listing.stdout.splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "completed-background")
        self.assertEqual(rows[0]["state"], "dead")
        self.assertEqual(rows[0]["createdAt"], record["createdAt"])

        signalled = self.command(
            "signal",
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "production-release",
            "--expected-created-at",
            str(record["createdAt"]),
            "--expect-token-stdin",
            input_text=token,
        )
        self.assertNotEqual(signalled.returncode, 0)
        self.assertIn("unsupported process kind", signalled.stderr)

        repeated = self.command("terminate", *common, input_text=token)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)

    def test_atomic_release_termination_rejects_stale_generation(self) -> None:
        original_process = self.spawn_session_leader()
        original = self.register(
            original_process, category="release", instance="production-release"
        )
        self.stop_process(original_process)
        replacement_process = self.spawn_session_leader()
        replacement = self.register(
            replacement_process, category="release", instance="production-release"
        )
        common = (
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "production-release",
            "--expect-token-stdin",
        )

        wrong_token = self.command(
            "terminate",
            *common,
            "--expected-created-at",
            str(replacement["createdAt"]),
            input_text=str(original["launchToken"]) + "\n",
        )
        self.assert_generation_refused(wrong_token)
        self.assertIsNone(replacement_process.poll())

        wrong_created = self.command(
            "terminate",
            *common,
            "--expected-created-at",
            str(original["createdAt"]),
            input_text=str(replacement["launchToken"]) + "\n",
        )
        self.assert_generation_refused(wrong_created)
        self.assertIsNone(replacement_process.poll())
        persisted = json.loads(self.record_paths()[0].read_text(encoding="utf-8"))
        self.assertEqual(persisted["createdAt"], replacement["createdAt"])
        self.assertEqual(persisted["launchToken"], replacement["launchToken"])

    def test_atomic_release_termination_rejects_missing_leader(self) -> None:
        process, child_pid = self.spawn_leader_with_surviving_child()
        record = self.register(
            process, category="release", instance="production-release"
        )
        os.kill(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
        os.kill(child_pid, 0)

        terminated = self.command(
            "terminate",
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "production-release",
            "--expected-created-at",
            str(record["createdAt"]),
            "--expect-token-stdin",
            input_text=str(record["launchToken"]) + "\n",
        )
        self.assertNotEqual(terminated.returncode, 0)
        self.assertIn("protected leader identity changed", terminated.stderr)
        os.kill(child_pid, 0)
        persisted = json.loads(self.record_paths()[0].read_text(encoding="utf-8"))
        self.assertEqual(persisted["kind"], "background")
        self.assertEqual(persisted["createdAt"], record["createdAt"])

    def test_atomic_release_termination_rejects_mismatched_leader(self) -> None:
        process = self.spawn_session_leader()
        record = self.register(
            process, category="release", instance="production-release"
        )
        self.resign_record({"processIdentity": "forged-generation-identity"})

        terminated = self.command(
            "terminate",
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "production-release",
            "--expected-created-at",
            str(record["createdAt"]),
            "--expect-token-stdin",
            input_text=str(record["launchToken"]) + "\n",
        )
        self.assertNotEqual(terminated.returncode, 0)
        self.assertIn("protected leader identity changed", terminated.stderr)
        self.assertIsNone(process.poll())
        persisted = json.loads(self.record_paths()[0].read_text(encoding="utf-8"))
        self.assertEqual(persisted["kind"], "background")

    def test_atomic_termination_is_release_only_and_requires_exact_generation(
        self,
    ) -> None:
        process = self.spawn_session_leader()
        record = self.register(process)
        common = (
            "--team",
            "replacement-team",
            "--category",
            "task",
            "--instance",
            "backend--task--a1",
        )
        wrong_category = self.command(
            "terminate",
            *common,
            "--expected-created-at",
            str(record["createdAt"]),
            "--expect-token-stdin",
            input_text=str(record["launchToken"]) + "\n",
        )
        self.assertNotEqual(wrong_category.returncode, 0)
        self.assertIsNone(process.poll())

        missing_token = self.command(
            "terminate",
            "--team",
            "replacement-team",
            "--category",
            "release",
            "--instance",
            "missing-release",
            "--expected-created-at",
            str(record["createdAt"]),
        )
        self.assertNotEqual(missing_token.returncode, 0)
        self.assertIn("--expect-token-stdin", missing_token.stderr)

    def test_lifecycle_lock_serializes_competing_commands(self) -> None:
        lock = self.ensure_lock()
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                """
import fcntl, os, sys
descriptor = os.open(sys.argv[1], os.O_RDWR)
fcntl.flock(descriptor, fcntl.LOCK_EX)
print("locked", flush=True)
sys.stdin.read(1)
fcntl.flock(descriptor, fcntl.LOCK_UN)
os.close(descriptor)
""",
                str(lock),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        blocked: subprocess.Popen[str] | None = None
        try:
            self.assertIsNotNone(holder.stdout)
            assert holder.stdout is not None
            self.assertEqual(holder.stdout.readline().strip(), "locked")
            holder.stdout.close()
            blocked = subprocess.Popen(
                [
                    sys.executable,
                    str(LIFECYCLE),
                    "project-list",
                    "--root",
                    str(self.lifecycle_root),
                    "--repo",
                    str(self.repo),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.05)
            self.assertIsNone(blocked.poll(), "command bypassed the lifecycle lock")
            self.assertIsNotNone(holder.stdin)
            assert holder.stdin is not None
            holder.stdin.write("x")
            holder.stdin.flush()
            holder.stdin.close()
            self.assertEqual(holder.wait(timeout=5), 0)
            stdout, stderr = blocked.communicate(timeout=5)
            self.assertEqual(blocked.returncode, 0, stderr)
            self.assertIn('"schemaVersion":"project-lifecycle-list-v1"', stdout)
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=5)
            if blocked is not None and blocked.poll() is None:
                blocked.kill()
                blocked.wait(timeout=5)

    def test_lifecycle_lock_rejects_unsafe_mode_and_symlink(self) -> None:
        lock = self.ensure_lock()
        lock.chmod(0o644)
        unsafe_mode = self.command("project-list")
        self.assertNotEqual(unsafe_mode.returncode, 0)
        self.assertIn("unsafe identity or permissions", unsafe_mode.stderr)

        lock.unlink()
        target = self.lifecycle_root / "attacker-selected.lock"
        target.write_text("", encoding="ascii")
        target.chmod(0o600)
        lock.symlink_to(target)
        unsafe_symlink = self.command("project-list")
        self.assertNotEqual(unsafe_symlink.returncode, 0)
        self.assertIn("lifecycle authority lock", unsafe_symlink.stderr)

    def test_lifecycle_lock_rejects_opened_named_inode_mismatch(self) -> None:
        lock = self.ensure_lock()
        displaced = self.lifecycle_root / "displaced-records.lock"
        spec = importlib.util.spec_from_file_location(
            "process_lifecycle_lock_under_test", LIFECYCLE
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        assert spec is not None and spec.loader is not None
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        real_open = lifecycle.os.open
        swapped = False

        def swapping_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            if dir_fd is None:
                descriptor = real_open(path, flags, mode)
            else:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if Path(path) == lock and not swapped:
                swapped = True
                lock.rename(displaced)
                replacement = real_open(
                    lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                os.close(replacement)
            return descriptor

        with mock.patch.object(lifecycle.os, "open", side_effect=swapping_open):
            with self.assertRaisesRegex(
                lifecycle.LifecycleError, "unsafe identity or permissions"
            ):
                with lifecycle.lifecycle_lock(self.lifecycle_root):
                    self.fail("inode-swapped lifecycle lock was accepted")
        self.assertTrue(swapped)

    def test_atomic_writer_retries_short_and_interrupted_writes(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "process_lifecycle_atomic_write_under_test", LIFECYCLE
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        assert spec is not None and spec.loader is not None
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        path = self.base / "atomic-record.json"
        record = {"kind": "completed-background", "payload": "x" * 257}
        expected = lifecycle.canonical(record) + b"\n"
        real_write = os.write
        calls = 0

        def interrupted_short_write(descriptor: int, data: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise InterruptedError
            return real_write(descriptor, data[: max(1, len(data) // 3)])

        with mock.patch.object(
            lifecycle.os, "write", side_effect=interrupted_short_write
        ):
            lifecycle.atomic_write(path, record)

        self.assertGreater(calls, 3)
        self.assertEqual(path.read_bytes(), expected)
        self.assertEqual(list(self.base.glob(".record-*")), [])

    def test_initial_auth_key_retries_short_and_interrupted_writes(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "process_lifecycle_key_write_under_test", LIFECYCLE
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        assert spec is not None and spec.loader is not None
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        expected = bytes(range(32))
        real_write = os.write
        calls = 0

        def interrupted_short_write(descriptor: int, data: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise InterruptedError
            return real_write(descriptor, data[: max(1, len(data) // 3)])

        with (
            mock.patch.object(lifecycle.secrets, "token_bytes", return_value=expected),
            mock.patch.object(
                lifecycle.os, "write", side_effect=interrupted_short_write
            ),
        ):
            _, _, key = lifecycle.initialize(
                str(self.lifecycle_root), str(self.repo)
            )

        self.assertGreater(calls, 3)
        self.assertEqual(key, expected)
        self.assertEqual(
            (self.lifecycle_root / "record-auth.key").read_bytes(), expected
        )

    def test_concurrent_fresh_initializers_share_complete_key(self) -> None:
        reader, writer = os.pipe()
        processes: list[subprocess.Popen[str]] = []
        count = 32
        wrapper = (
            "import os,sys; os.read(int(sys.argv[1]), 1); "
            "os.execv(sys.executable, [sys.executable, *sys.argv[2:]])"
        )
        try:
            for _ in range(count):
                processes.append(
                    subprocess.Popen(
                        [
                            sys.executable,
                            "-c",
                            wrapper,
                            str(reader),
                            str(LIFECYCLE),
                            "init",
                            "--root",
                            str(self.lifecycle_root),
                            "--repo",
                            str(self.repo),
                        ],
                        pass_fds=(reader,),
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                )
            os.close(reader)
            reader = -1
            os.write(writer, b"x" * count)
            os.close(writer)
            writer = -1
            for process in processes:
                stdout, stderr = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stdout.strip(), str(self.lifecycle_root))
            self.assertEqual(
                len((self.lifecycle_root / "record-auth.key").read_bytes()), 32
            )
            self.assertEqual(list(self.lifecycle_root.glob(".record-auth-*")), [])
        finally:
            if reader >= 0:
                os.close(reader)
            if writer >= 0:
                os.close(writer)
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

    def test_crash_during_first_key_write_can_retry(self) -> None:
        crash_script = """
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('lifecycle_crash_test', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
real_write = os.write
def crash_after_partial_write(fd, data):
    real_write(fd, data[:7])
    os._exit(71)
module.os.write = crash_after_partial_write
module.initialize(sys.argv[2], sys.argv[3])
"""
        crashed = subprocess.run(
            [
                sys.executable,
                "-c",
                crash_script,
                str(LIFECYCLE),
                str(self.lifecycle_root),
                str(self.repo),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(crashed.returncode, 71, crashed.stderr)
        self.assertFalse((self.lifecycle_root / "record-auth.key").exists())
        remnants = list(self.lifecycle_root.glob(".record-auth-*"))
        self.assertEqual(len(remnants), 1)
        self.assertEqual(remnants[0].stat().st_mode & 0o777, 0o600)
        retried = self.command("init")
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertEqual(
            len((self.lifecycle_root / "record-auth.key").read_bytes()), 32
        )

    def test_preexisting_partial_key_remains_fail_closed(self) -> None:
        key_path = self.lifecycle_root / "record-auth.key"
        key_path.write_bytes(b"partial")
        key_path.chmod(0o600)
        result = self.command("init")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must contain exactly 32 bytes", result.stderr)
        self.assertEqual(key_path.read_bytes(), b"partial")

    def test_identity_mismatch_cannot_be_marked_completed(self) -> None:
        process = self.spawn_session_leader()
        record = self.register(process)
        self.resign_record({"processIdentity": "forged-generation-identity"})
        completed = self.command(
            "complete",
            "--team",
            "replacement-team",
            "--category",
            "task",
            "--instance",
            "backend--task--a1",
            "--expected-created-at",
            str(record["createdAt"]),
            "--expect-token-stdin",
            input_text=str(record["launchToken"]) + "\n",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("process group exists", completed.stderr)
        self.assertIsNone(process.poll())
        self.assertEqual(len(self.record_paths()), 1)

    def test_same_root_and_team_are_isolated_by_git_project(self) -> None:
        other_repo = self.base / "other-repo"
        other_repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=other_repo, check=True)
        first_process = self.spawn_session_leader()
        second_process = self.spawn_session_leader()

        first = self.register(first_process)
        second = self.register(second_process, repo=other_repo)

        self.assertEqual(first["schemaVersion"], 3)
        self.assertEqual(second["schemaVersion"], 3)
        self.assertNotEqual(first["repositoryId"], second["repositoryId"])
        self.assertEqual(len(self.record_paths()), 2)
        first_exact = self.command("list", "--team", "replacement-team")
        second_exact = self.command(
            "list", "--team", "replacement-team", repo=other_repo
        )
        self.assertEqual(
            [json.loads(row)["pid"] for row in first_exact.stdout.splitlines()],
            [first_process.pid],
        )
        self.assertEqual(
            [json.loads(row)["pid"] for row in second_exact.stdout.splitlines()],
            [second_process.pid],
        )
        first_list = self.project_list()
        second_list = self.project_list(other_repo)
        self.assertEqual(first_list["schemaVersion"], "project-lifecycle-list-v1")
        self.assertEqual(first_list["repositoryId"], first["repositoryId"])
        self.assertEqual(
            [row["pid"] for row in first_list["records"]], [first_process.pid]
        )
        self.assertEqual(
            [row["pid"] for row in second_list["records"]], [second_process.pid]
        )
        for envelope in (first_list, second_list):
            self.assertEqual(envelope["legacyOmitted"], 0)
            self.assertEqual(envelope["warnings"], [])
            self.assertNotIn("auth", envelope["records"][0])
            self.assertNotIn("launchToken", envelope["records"][0])

    def test_linked_worktree_uses_the_same_project_identity(self) -> None:
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Lifecycle Test",
                "-c",
                "user.email=lifecycle@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "fixture",
            ],
            cwd=self.repo,
            check=True,
        )
        linked = self.base / "linked-worktree"
        subprocess.run(
            ["git", "worktree", "add", "-qb", "linked-test", str(linked)],
            cwd=self.repo,
            check=True,
        )
        first_process = self.spawn_session_leader()
        second_process = self.spawn_session_leader()

        first = self.register(first_process, instance="backend--first--a1")
        second = self.register(
            second_process, repo=linked, instance="backend--second--a1"
        )

        self.assertEqual(first["repositoryId"], second["repositoryId"])
        rows = self.project_list(linked)["records"]
        self.assertEqual(
            {row["instance"] for row in rows},
            {"backend--first--a1", "backend--second--a1"},
        )

    def test_project_list_omits_legacy_but_exact_team_lookup_remains_compatible(self) -> None:
        process = self.spawn_session_leader()
        record = self.register(process)
        self.record_paths()[0].unlink()
        self.add_legacy_copy(record)

        listing = self.command("list", "--team", "replacement-team")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        exact_rows = [json.loads(line) for line in listing.stdout.splitlines()]
        self.assertEqual(len(exact_rows), 1)
        self.assertEqual(exact_rows[0]["schemaVersion"], 2)
        envelope = self.project_list()
        self.assertEqual(envelope["records"], [])
        self.assertEqual(envelope["legacyOmitted"], 1)
        self.assertEqual(len(envelope["warnings"]), 1)
        self.assertNotIn("replacement-team", envelope["warnings"][0])
        self.assertNotIn("backend--task--a1", envelope["warnings"][0])

        probe = self.command(
            "probe",
            "--team",
            "replacement-team",
            "--category",
            "task",
            "--instance",
            "backend--task--a1",
        )
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(json.loads(probe.stdout)["schemaVersion"], 2)

    def test_destructive_exact_operations_reject_v3_legacy_ambiguity(self) -> None:
        process = self.spawn_session_leader()
        record = self.register(process)
        self.add_legacy_copy(record)
        common = (
            "--team",
            "replacement-team",
            "--category",
            "task",
            "--instance",
            "backend--task--a1",
        )

        signalled = self.command(
            "signal",
            *common,
            "--expect-token-stdin",
            input_text=str(record["launchToken"]) + "\n",
        )
        self.assertNotEqual(signalled.returncode, 0)
        self.assertIn("ambiguous", signalled.stderr)
        self.assertIsNone(process.poll())
        forgotten = self.command(
            "forget",
            *common,
            "--expect-token-stdin",
            input_text=str(record["launchToken"]) + "\n",
        )
        self.assertNotEqual(forgotten.returncode, 0)
        self.assertIn("ambiguous", forgotten.stderr)
        self.assertEqual(len(self.record_paths()), 2)

    def test_project_list_fails_closed_on_tampered_current_project_record(self) -> None:
        process = self.spawn_session_leader()
        record = self.register(process)
        path = self.record_paths()[0]
        record["repositoryId"] = "0" * 64
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        path.chmod(0o600)

        result = self.command("project-list")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authentication failed", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
