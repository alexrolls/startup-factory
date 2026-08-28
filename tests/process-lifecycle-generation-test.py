#!/usr/bin/env python3
"""Regression tests for generation-bound lifecycle mutation."""

from __future__ import annotations

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
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(LIFECYCLE),
                operation,
                "--root",
                str(self.lifecycle_root),
                "--repo",
                str(self.repo),
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

    def register(self, process: subprocess.Popen[str]) -> dict[str, object]:
        result = self.command(
            "register",
            "--team",
            "replacement-team",
            "--category",
            "task",
            "--instance",
            "backend--task--a1",
            "--kind",
            "background",
            "--pid",
            str(process.pid),
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
