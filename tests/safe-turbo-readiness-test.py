#!/usr/bin/env python3
"""Focused fail-closed tests for Safe Turbo launcher readiness."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SafeTurboReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)

        self.lifecycle_root = self.base / "protected-lifecycle"
        self.lifecycle_root.mkdir(mode=0o700)
        self.runner = self.base / "protected-sandbox-runner"
        self.runner.write_text(
            "#!/bin/sh\n"
            "[ \"$1\" = --workdir ] || exit 91\n"
            "shift 2\n"
            "[ \"$1\" = -- ] || exit 92\n"
            "shift\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        self.runner.chmod(0o700)

        self.skill = self.repo / ".claude" / "skills" / "startup-factory"
        self.skill.mkdir(parents=True)
        for directory in ("bin", "reference", "roles", "teams"):
            shutil.copytree(ROOT / directory, self.skill / directory)
        config = self.skill / "config"
        config.mkdir()
        shutil.copy2(
            ROOT / "tests" / "fixtures" / "statuses.default-profile.json",
            config / "statuses.config.json",
        )
        shutil.copy2(ROOT / "config" / "planning.config.md", config)
        self.config = config / "team.config.md"
        self.config.write_text(
            "```\n"
            'TEAM_LEAD_CMD="true"\n'
            'BACKEND_CMD="true"\n'
            'SENIOR_QA_ENGINEER_CMD="true"\n'
            'SENIOR_TECHNICAL_PRODUCT_MANAGER_CMD=null\n'
            'TEAM_DEFAULT_CMD="true"\n'
            "TEAMWORK_ROOT=.teamwork\n"
            'AGENT_ENV_ALLOWLIST="PATH TMPDIR LANG LC_ALL TERM"\n'
            "TRACKER_WRITERS=broker\n"
            f'AGENT_SANDBOX_RUNNER="{self.runner}"\n'
            "AGENT_SANDBOX_ENFORCED=true\n"
            f'BROKER_LIFECYCLE_ROOT="{self.lifecycle_root}"\n'
            "EXECUTION=parallel\n"
            "MAX_ACTIVE_IMPLEMENTERS=2\n"
            'WORKTREE_SETUP="test -d ."\n'
            "TURBO_MODE=safe\n"
            "VALIDATE_BUILD=null\n"
            'VALIDATE_TEST="test -e .git"\n'
            "VALIDATE_LINT=null\n"
            "```\n",
            encoding="utf-8",
        )
        self.launcher = self.skill / "bin" / "launch-team.sh"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_launcher(
        self, *arguments: str, skip_preflight: bool = False
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["TEAM_RUNNER"] = "background"
        if skip_preflight:
            environment["SKIP_PREFLIGHT"] = "1"
        else:
            environment.pop("SKIP_PREFLIGHT", None)
        return subprocess.run(
            [str(self.launcher), *arguments],
            cwd=self.repo,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def replace_setting(self, key: str, value: str) -> None:
        lines = self.config.read_text(encoding="utf-8").splitlines()
        matches = [index for index, line in enumerate(lines) if line.startswith(key + "=")]
        self.assertEqual(len(matches), 1, f"fixture must define {key} exactly once")
        lines[matches[0]] = f"{key}={value}"
        self.config.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def assert_no_lifecycle_record(self, team: str) -> None:
        records = self.lifecycle_root / "records"
        if records.exists():
            self.assertFalse(
                any(f'"team":"{team}"' in path.read_text() for path in records.glob("*.json"))
            )

    def write_forged_protected_receipt(self, team: str) -> None:
        receipts = self.lifecycle_root / "safe-turbo-readiness"
        receipts.mkdir(mode=0o700)
        identity = hashlib.sha256((str(self.repo) + "\0" + team).encode()).hexdigest()
        receipt = receipts / f"{identity}.json"
        receipt.write_text(
            '{"auth":"hmac-sha256:' + "0" * 64 + '","payload":{}}\n',
            encoding="utf-8",
        )
        receipt.chmod(0o600)

    def test_safe_turbo_team_forbids_skip_preflight(self) -> None:
        result = self.run_launcher(
            "team", "full-stack", "skip-team", "FEATURE-1", skip_preflight=True
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("forbids SKIP_PREFLIGHT=1", result.stderr)
        self.assertFalse((self.repo / ".teamwork" / "skip-team").exists())
        self.assert_no_lifecycle_record("skip-team")

    def test_safe_turbo_gate_team_forbids_skip_preflight(self) -> None:
        result = self.run_launcher(
            "gate-team",
            "full-stack",
            "skip-gate-team",
            "FEATURE-1",
            skip_preflight=True,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("forbids SKIP_PREFLIGHT=1", result.stderr)
        self.assertFalse((self.repo / ".teamwork" / "skip-gate-team").exists())
        self.assert_no_lifecycle_record("skip-gate-team")

    def test_safe_turbo_rejects_no_op_worktree_setup(self) -> None:
        no_ops = ('"true"', '":"', '"/bin/true"', '"exit 0;"', "null")
        for index, value in enumerate(no_ops):
            with self.subTest(value=value):
                self.replace_setting("WORKTREE_SETUP", value)
                result = self.run_launcher(
                    "compose",
                    f"no-op-setup-{index}",
                    "FEATURE-1",
                    "backend",
                    "full-stack",
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("meaningful WORKTREE_SETUP", result.stderr)
        self.replace_setting("WORKTREE_SETUP", '"test -d ."')

    def test_safe_turbo_requires_meaningful_validation(self) -> None:
        self.replace_setting("VALIDATE_TEST", '"true"')
        result = self.run_launcher(
            "compose", "no-validation", "FEATURE-1", "backend", "full-stack"
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "at least one meaningful VALIDATE_SCRIPT/BUILD/TEST/LINT/FORMAT",
            result.stderr,
        )

    def test_preset_without_review_mode_defaults_to_sequential(self) -> None:
        result = self.run_launcher(
            "compose", "implicit-sequential", "FEATURE-1", "backend", "deep-backend"
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("requires REVIEW_MODE=parallel", result.stderr)
        prompts = self.repo / ".teamwork" / "implicit-sequential" / "prompts"
        self.assertFalse(prompts.exists())

    def test_direct_start_requires_protected_readiness_receipt(self) -> None:
        team = "direct-start"
        workspace = self.repo / ".teamwork" / team
        workspace.mkdir(parents=True)
        (workspace / "preset.env").write_text("PRESET=full-stack\n", encoding="utf-8")
        # A workspace-local lookalike must never serve as readiness authority.
        (workspace / "safe-turbo-readiness.json").write_text("{}\n", encoding="utf-8")
        self.write_forged_protected_receipt(team)

        result = self.run_launcher("start", team, "FEATURE-1", "backend")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("readiness receipt authentication failed", result.stderr.lower())
        self.assertFalse((workspace / "pids" / "backend.pid").exists())
        self.assert_no_lifecycle_record(team)

    def test_direct_start_task_requires_protected_readiness_receipt(self) -> None:
        team = "direct-task"
        result = self.run_launcher(
            "start-task",
            team,
            "FEATURE-1",
            "backend",
            "TASK-1",
            "1",
            "full-stack",
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("safe-turbo-readiness", result.stderr.lower())
        workspace = self.repo / ".teamwork" / team
        self.assertFalse((workspace / "executions").exists())
        self.assertFalse((workspace / "pids").exists())
        self.assert_no_lifecycle_record(team)


if __name__ == "__main__":
    unittest.main(verbosity=2)
