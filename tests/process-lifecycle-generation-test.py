#!/usr/bin/env python3
"""Regression tests for generation-bound lifecycle mutation."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


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

    def register(
        self,
        process: subprocess.Popen[str],
        *,
        repo: Path | None = None,
        instance: str = "backend--task--a1",
    ) -> dict[str, object]:
        result = self.command(
            "register",
            "--team",
            "replacement-team",
            "--category",
            "task",
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
            b"replacement-team\0task\0backend--task--a1"
        ).hexdigest()
        path = self.lifecycle_root / "records" / f"{filename}.json"
        path.write_text(
            json.dumps(legacy, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

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
