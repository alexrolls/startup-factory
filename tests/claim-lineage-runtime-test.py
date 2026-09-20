#!/usr/bin/env python3
"""Focused real-filesystem regressions for claimLineage/v1 transactions."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))
SPEC = importlib.util.spec_from_file_location(
    "claim_lineage_runtime", BIN / "runtime-state.py"
)
assert SPEC and SPEC.loader
runtime = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime
SPEC.loader.exec_module(runtime)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class ClaimLineageRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.repository = self.base / "repository"
        self.repository.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(self.repository)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.team = "lineage-team"
        self.feature = "features/runtime.md"
        self.task_id = f"{self.feature}#8"
        self.role = "backend"
        self.workspace = self.repository / ".teamwork" / self.team
        self.workspace.mkdir(parents=True)
        self.key = runtime.safe_key(self.task_id)
        self.claim_path = self.workspace / "claims" / f"{self.key}.json"
        self.execution_path = self.workspace / "executions" / f"{self.key}.json"

    def tearDown(self) -> None:
        os.environ.pop("STARTUP_FACTORY_LIFECYCLE_STATE_ROOT", None)
        self.temporary.cleanup()

    def claim(self, attempt: int, target: str = "Active") -> dict:
        identity = runtime.claim_identity(
            team=self.team,
            feature=self.feature,
            task=self.task_id,
            key=self.key,
            attempt=attempt,
            role=self.role,
            target=target,
        )
        return {
            **identity,
            "claimDigest": runtime.canonical_digest(identity),
            "recordedAt": f"2026-09-20T00:00:{attempt:02d}+00:00",
        }

    def execution(self, attempt: int, lineage_claim: dict, *, legacy: bool = False) -> dict:
        artifact = self.workspace / "artifacts" / self.key / f"attempt-{attempt}"
        value = {
            "schemaVersion": 1,
            "featureId": self.feature,
            "taskId": self.task_id,
            "taskKey": self.key,
            "attempt": attempt,
            "role": self.role,
            "branch": f"agent-task/{self.team}/{self.key}",
            "worktree": str(
                self.workspace
                / "worktrees"
                / f"{self.role}#{attempt}-{self.key}"
            ),
            "packetPath": str(artifact / "task-packet.md"),
            "packetJsonPath": str(artifact / "task-packet.json"),
            "reportPath": str(artifact / "task-report.md"),
            "deliveryProfile": "standard",
            "modelProfile": "strong",
            "updatedAt": "2026-09-20T00:10:00+00:00",
        }
        if not legacy:
            lineage = runtime.lineage_from_claim(lineage_claim)
            value.update(
                claimLineage=lineage,
                lineageDigest=runtime.canonical_digest(lineage),
            )
        return value

    def receipt(self, claim: dict) -> dict:
        return {
            "body": (
                "[claim]\n"
                f"claim-id: {claim['claimId']}\n"
                f"role: {claim['role']}\n"
                f"target-status: {claim['targetStatus']}\n\n"
                "— dispatcher"
            )
        }

    def task(self, status: str, claim: dict, *, comments: list[dict] | None = None) -> dict:
        return {
            "taskId": self.task_id,
            "status": status,
            "revision": "rev-8",
            "assignee": self.role,
            "comments": comments if comments is not None else [self.receipt(claim)],
        }

    def claim_args(self, attempt: int, target: str = "Active") -> SimpleNamespace:
        return SimpleNamespace(
            repo=str(self.repository),
            workspace=str(self.workspace),
            team=self.team,
            feature=self.feature,
            task=self.task_id,
            role=self.role,
            attempt=attempt,
            claim_id=runtime.deterministic_claim_id(
                self.team,
                self.feature,
                self.task_id,
                self.role,
                attempt,
                target,
            ),
            target=target,
        )

    def run_claim(self, attempt: int, target: str = "Active") -> dict:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runtime.cmd_claim(self.claim_args(attempt, target))
        return json.loads(output.getvalue())

    def preflight_args(
        self, attempt: int, tasks_path: Path, target: str = "Active"
    ) -> SimpleNamespace:
        claim_args = self.claim_args(attempt, target)
        return SimpleNamespace(
            **vars(claim_args),
            tasks=str(tasks_path),
            current_status="Planned",
        )

    def resolve(self, task: dict, attempt: int):
        return runtime.resolve_packet_lineage(
            repository=self.repository,
            workspace=self.workspace,
            team=self.team,
            feature=self.feature,
            task=task,
            task_id=self.task_id,
            key=self.key,
            role=self.role,
            attempt=attempt,
        )

    def lineage_args(
        self, attempt: int, tasks_path: Path, *, allow_restart: bool = False
    ) -> SimpleNamespace:
        return SimpleNamespace(
            repo=str(self.repository),
            workspace=str(self.workspace),
            tasks=str(tasks_path),
            team=self.team,
            feature=self.feature,
            task=self.task_id,
            role=self.role,
            attempt=attempt,
            allow_unchanged_lineage_advance=allow_restart,
        )

    def test_packet_config_uses_shared_parser_before_mutation(self) -> None:
        config = self.base / "team.config.md"
        config.write_text(
            'TEAMWORK_ROOT=".teamwork" # canonical quoted value\n'
            "VALIDATE_TEST='python -m pytest'\n",
            encoding="utf-8",
        )
        self.assertEqual(runtime.read_config(config)["TEAMWORK_ROOT"], ".teamwork")
        self.assertEqual(
            runtime.read_config(config)["VALIDATE_TEST"], "python -m pytest"
        )

        config.write_text(
            "TEAMWORK_ROOT=.teamwork\nTEAMWORK_ROOT=other\n",
            encoding="utf-8",
        )
        claim = self.claim(1)
        write_json(self.claim_path, claim)
        tasks_path = self.workspace / "tasks.json"
        write_json(tasks_path, {"tasks": [self.task("Active", claim)]})
        args = SimpleNamespace(
            repo=str(self.repository),
            workspace=str(self.workspace),
            tasks=str(tasks_path),
            team=self.team,
            feature=self.feature,
            task=self.task_id,
            role=self.role,
            attempt=1,
            worktree=str(
                self.workspace
                / "worktrees"
                / f"{self.role}#1-{self.key}"
            ),
            branch=f"agent-task/{self.team}/{self.key}",
            config=str(config),
            contracts=str(self.workspace / "CONTRACTS.md"),
            baseline=str(self.workspace / "BASELINE.md"),
            restart_control_id=None,
            restart_generation=None,
            restart_reason=None,
        )
        with self.assertRaisesRegex(
            SystemExit, "duplicate configuration key TEAMWORK_ROOT"
        ):
            runtime.cmd_packet(args)
        self.assertFalse((self.workspace / "locks").exists())
        self.assertFalse((self.workspace / "artifacts").exists())

    def test_generation_advance_requires_broker_restart_or_new_claim(self) -> None:
        claim1 = self.claim(1)
        write_json(self.claim_path, claim1)
        write_json(self.execution_path, self.execution(1, claim1))
        tasks_path = self.workspace / "tasks.json"
        write_json(tasks_path, {"tasks": [self.task("Active", claim1)]})

        with self.assertRaisesRegex(SystemExit, "authenticated broker restart"):
            runtime.cmd_lineage_check(self.lineage_args(2, tasks_path))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runtime.cmd_lineage_check(
                self.lineage_args(2, tasks_path, allow_restart=True)
            )
        self.assertEqual(
            json.loads(output.getvalue())["previousExecutionAttempt"], 1
        )

        queued_path = self.workspace / "queued.json"
        write_json(queued_path, {"tasks": [self.task("Planned", claim1)]})
        with contextlib.redirect_stdout(io.StringIO()):
            runtime.cmd_claim_preflight(self.preflight_args(2, queued_path))
        claim2 = self.run_claim(2)
        write_json(tasks_path, {"tasks": [self.task("Active", claim2)]})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runtime.cmd_lineage_check(self.lineage_args(2, tasks_path))
        self.assertEqual(
            json.loads(output.getvalue())["claimLineage"]["claimAttempt"], 2
        )

    def test_clean_restart_and_rework_keep_immutable_claim_target(self) -> None:
        claim2 = self.claim(2)
        write_json(self.claim_path, claim2)
        write_json(self.execution_path, self.execution(3, claim2))

        # Current tracker lifecycle is separate from the immutable claim target.
        lineage, _, execution, previous = self.resolve(
            self.task("Review", claim2), 3
        )
        self.assertEqual(previous, 3)
        self.assertEqual(execution["attempt"], 3)
        self.assertEqual(lineage["claimAttempt"], 2)
        self.assertEqual(lineage["targetStatus"], "Active")

        queued = self.task("Planned", claim2)
        tasks_path = self.workspace / "queued.json"
        write_json(tasks_path, {"tasks": [queued]})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runtime.cmd_claim_preflight(self.preflight_args(4, tasks_path))
        self.assertEqual(json.loads(output.getvalue())["mode"], "rework")

        before = self.claim_path.read_bytes()
        with self.assertRaisesRegex(SystemExit, "advance one execution generation"):
            self.run_claim(5)
        self.assertEqual(self.claim_path.read_bytes(), before)
        self.assertFalse((self.claim_path.parent / "history").exists())

        claim4 = self.run_claim(4)
        archived = (
            self.claim_path.parent / "history" / f"{self.key}-a2-rework.json"
        )
        self.assertEqual(archived.read_bytes(), before)
        self.assertNotEqual(os.stat(archived).st_ino, os.stat(self.claim_path).st_ino)
        self.assertEqual(claim4["attempt"], 4)
        next_lineage, _, _, _ = self.resolve(self.task("Active", claim4), 4)
        self.assertEqual(next_lineage["claimAttempt"], 4)

    def test_tracker_receipt_and_lineage_mutation_fail_closed(self) -> None:
        claim = self.claim(2)
        write_json(self.claim_path, claim)
        execution = self.execution(3, claim)
        write_json(self.execution_path, execution)

        stale = self.task(
            "Review",
            claim,
            comments=[{"body": self.receipt(claim)["body"].replace("backend", "frontend")}],
        )
        with self.assertRaisesRegex(SystemExit, "exact tracker-side claim receipt"):
            self.resolve(stale, 3)

        duplicate = self.task(
            "Review", claim, comments=[self.receipt(claim), self.receipt(claim)]
        )
        with self.assertRaisesRegex(SystemExit, "exact tracker-side claim receipt"):
            self.resolve(duplicate, 3)

        execution["claimLineage"]["claimAttempt"] = 1
        write_json(self.execution_path, execution)
        with self.assertRaisesRegex(SystemExit, "lineage"):
            self.resolve(self.task("Review", claim), 3)

    def test_packet_rejection_has_no_artifact_or_lock_effect(self) -> None:
        claim = self.claim(1)
        write_json(self.claim_path, claim)
        bad_task = self.task("Active", claim, comments=[])
        tasks_path = self.workspace / "tasks.json"
        write_json(tasks_path, {"tasks": [bad_task]})
        args = SimpleNamespace(
            repo=str(self.repository),
            workspace=str(self.workspace),
            tasks=str(tasks_path),
            team=self.team,
            feature=self.feature,
            task=self.task_id,
            role=self.role,
            attempt=1,
            worktree=str(
                self.workspace / "worktrees" / f"{self.role}#1-{self.key}"
            ),
            branch=f"agent-task/{self.team}/{self.key}",
            config=str(self.repository / "missing-config"),
            contracts=str(self.repository / "missing-contracts"),
            baseline=str(self.repository / "missing-baseline"),
        )
        with self.assertRaisesRegex(SystemExit, "exact tracker-side claim receipt"):
            runtime.cmd_packet(args)
        self.assertFalse((self.workspace / "artifacts").exists())
        self.assertFalse((self.workspace / "executions").exists())

    def test_direct_packet_cannot_advance_an_unchanged_claim(self) -> None:
        claim1 = self.claim(1)
        write_json(self.claim_path, claim1)
        write_json(self.execution_path, self.execution(1, claim1))
        before_execution = self.execution_path.read_bytes()
        tasks_path = self.workspace / "tasks.json"
        write_json(tasks_path, {"tasks": [self.task("Active", claim1)]})
        args = SimpleNamespace(
            repo=str(self.repository),
            workspace=str(self.workspace),
            tasks=str(tasks_path),
            team=self.team,
            feature=self.feature,
            task=self.task_id,
            role=self.role,
            attempt=2,
            worktree=str(
                self.workspace / "worktrees" / f"{self.role}#2-{self.key}"
            ),
            branch=f"agent-task/{self.team}/{self.key}",
            config=str(self.repository / "missing-config"),
            contracts=str(self.repository / "missing-contracts"),
            baseline=str(self.repository / "missing-baseline"),
        )
        with self.assertRaisesRegex(SystemExit, "authenticated broker restart"):
            runtime.cmd_packet(args)
        self.assertEqual(self.execution_path.read_bytes(), before_execution)
        args.restart_control_id = "control-" + "a" * 32
        args.restart_generation = "forged-generation"
        args.restart_reason = "authorized"
        with self.assertRaisesRegex(
            SystemExit, "configured packet restart authority is invalid"
        ):
            runtime.cmd_packet(args)
        self.assertEqual(self.execution_path.read_bytes(), before_execution)
        self.assertFalse(
            (self.workspace / "artifacts" / self.key / "attempt-2").exists()
        )
        self.assertFalse(
            (
                self.execution_path.parent
                / f".{self.key}.transaction.lock"
            ).exists()
        )

    def test_rework_retained_fd_race_preserves_both_byte_versions(self) -> None:
        claim2 = self.claim(2)
        write_json(self.claim_path, claim2)
        write_json(self.execution_path, self.execution(3, claim2))
        trusted = self.claim_path.read_bytes()
        raced = dict(claim2)
        raced["recordedAt"] = "retained-fd-race"
        raced_raw = (json.dumps(raced, indent=2) + "\n").encode()
        writer = os.open(self.claim_path, os.O_RDWR)
        original_publish = runtime.write_json_no_replace_in_directory
        mutated = False

        def racing_publish(*args, **kwargs):
            nonlocal mutated
            os.lseek(writer, 0, os.SEEK_SET)
            os.ftruncate(writer, 0)
            self.assertEqual(os.write(writer, raced_raw), len(raced_raw))
            mutated = True
            return original_publish(*args, **kwargs)

        runtime.write_json_no_replace_in_directory = racing_publish
        try:
            with self.assertRaisesRegex(SystemExit, "changed during replacement"):
                self.run_claim(4)
        finally:
            runtime.write_json_no_replace_in_directory = original_publish
            os.close(writer)

        archive = self.claim_path.parent / "history" / f"{self.key}-a2-rework.json"
        evacuated = (
            self.claim_path.parent / f".{self.claim_path.name}.rework-a2.evacuated"
        )
        self.assertTrue(mutated)
        self.assertEqual(archive.read_bytes(), trusted)
        self.assertEqual(evacuated.read_bytes(), raced_raw)
        self.assertEqual(json.loads(self.claim_path.read_text())["attempt"], 4)

    def install_hold_authority(self, generation: int) -> Path:
        root = self.base / "protected-lifecycle"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        key_bytes = os.urandom(32)
        key_path = root / "record-auth.key"
        key_path.write_bytes(key_bytes)
        key_path.chmod(0o600)
        scope = {
            "repository": str(self.repository.resolve()),
            "team": self.team,
            "featureId": self.feature,
        }
        registry = {
            "schemaVersion": 1,
            "featureId": self.feature,
            "tasks": {
                self.key: {
                    "taskId": self.task_id,
                    "taskKey": self.key,
                    "state": "resumed",
                    "generation": generation,
                    "holdId": "hold-runtime-1",
                    "resumeVerdict": "unchanged",
                    "clearedAt": "2026-09-20T01:00:00+00:00",
                }
            },
        }
        unsigned = {"schemaVersion": 1, "scope": scope, "registry": registry}
        envelope = {
            **unsigned,
            "auth": "hmac-sha256:"
            + hmac.new(
                key_bytes, runtime.canonical_bytes(unsigned), hashlib.sha256
            ).hexdigest(),
        }
        authority_id = hashlib.sha256(runtime.canonical_bytes(scope)).hexdigest()
        write_json(root / "task-holds" / f"{authority_id}.json", envelope)
        os.environ["STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"] = str(root)
        return root

    def test_authenticated_hold_resume_and_skipped_generation(self) -> None:
        claim4 = self.claim(4)
        write_json(self.claim_path, claim4)
        write_json(self.execution_path, self.execution(4, claim4))
        archive = (
            self.claim_path.parent / "history" / f"{self.key}-a4-hold-1.json"
        )
        archive.parent.mkdir(parents=True)
        os.replace(self.claim_path, archive)

        self.install_hold_authority(generation=2)
        with self.assertRaisesRegex(SystemExit, "hold-archived predecessor claim is missing"):
            self.run_claim(5)
        self.assertFalse(self.claim_path.exists())
        self.assertEqual(json.loads(archive.read_text())["attempt"], 4)

        # Re-sign the protected registry for the actual archived generation.
        root = Path(os.environ["STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"])
        shutil.rmtree(root)
        os.environ.pop("STARTUP_FACTORY_LIFECYCLE_STATE_ROOT", None)
        self.install_hold_authority(generation=1)
        claim5 = self.run_claim(5)
        self.assertEqual(claim5["attempt"], 5)
        self.assertEqual(json.loads(archive.read_text())["attempt"], 4)

    def test_legacy_execution_requires_migration_without_effects(self) -> None:
        claim1 = self.claim(1)
        write_json(self.claim_path, claim1)
        write_json(self.execution_path, self.execution(1, claim1, legacy=True))
        before_claim = self.claim_path.read_bytes()
        before_execution = self.execution_path.read_bytes()
        with self.assertRaisesRegex(SystemExit, "authenticated lineage migration"):
            self.run_claim(2)
        self.assertEqual(self.claim_path.read_bytes(), before_claim)
        self.assertEqual(self.execution_path.read_bytes(), before_execution)
        self.assertFalse((self.claim_path.parent / "history").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
