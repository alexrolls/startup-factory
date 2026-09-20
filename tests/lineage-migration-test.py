#!/usr/bin/env python3
"""Real-path transaction tests for the protected lineageMigration/v1 executor."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "lineage_migration", ROOT / "bin" / "lineage-migration.py"
)
assert SPEC and SPEC.loader
migration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(migration)
WORKER_SPEC = importlib.util.spec_from_file_location(
    "worker_control_for_migration", ROOT / "bin" / "worker-control.py"
)
assert WORKER_SPEC and WORKER_SPEC.loader
worker_control = importlib.util.module_from_spec(WORKER_SPEC)
WORKER_SPEC.loader.exec_module(worker_control)
from outbox_capability import mint, revoke_exact, sign_entry  # noqa: E402


class LineageMigrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.repository = self.base / "repository"
        self.repository.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repository)], check=True)
        subprocess.run(
            ["git", "-C", str(self.repository), "config", "user.email", "test@example.test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.repository), "config", "user.name", "Test"],
            check=True,
        )
        (self.repository / "base.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repository), "add", "base.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repository), "commit", "-qm", "base"], check=True)
        self.workspace = self.repository / ".teamwork" / "migration-team"
        for name in (
            "executions", "claims", "artifacts", "worktrees",
            "lineage-migration-outbox/pending", "lineage-migration-outbox/consumed",
            "outbox/done", "outbox/staged",
        ):
            (self.workspace / name).mkdir(parents=True, exist_ok=True)
        for name in (
            "lineage-migration-outbox", "lineage-migration-outbox/pending",
            "lineage-migration-outbox/consumed",
        ):
            (self.workspace / name).chmod(0o700)
        self.team = "migration-team"
        self.feature = "feature.md"
        (self.workspace / "preset.env").write_text(
            "PRESET=-\n"
            "PROTOCOL_TEAM_LEAD=team-lead\n"
            "PROTOCOL_PRODUCT_MANAGER=senior-technical-product-manager\n"
            "PROTOCOL_PRINCIPAL_ARCHITECT=principal-software-architect\n"
            "PROTOCOL_SCEPTICAL_ARCHITECT=sceptical-architect\n"
            "PROTOCOL_INTEGRATOR=integrator\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                str(ROOT / "bin" / "team-context.py"),
                "issue",
                "--repo",
                str(self.repository),
                "--workspace",
                str(self.workspace),
                "--team",
                self.team,
                "--feature",
                self.feature,
                "--skill",
                str(ROOT),
                "--preset",
                "-",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.target_task = f"{self.feature}#7"
        self.authorization_task = f"{self.feature}#8"
        self.other_task = f"{self.feature}#9"
        self.key = migration.task_key(self.target_task)
        self.role = "senior-full-stack-engineer"
        self.attempt = 34
        self.branch = f"agent-task/{self.team}/{self.key}"
        self.worktree = self.workspace / "worktrees" / f"{self.role}#{self.attempt}-{self.key}"
        subprocess.run(
            ["git", "-C", str(self.repository), "worktree", "add", "-q", "-b", self.branch, str(self.worktree), "HEAD"],
            check=True,
        )
        self.head = subprocess.run(
            ["git", "-C", str(self.worktree), "rev-parse", "HEAD"],
            check=True, text=True, stdout=subprocess.PIPE,
        ).stdout.strip()
        self.packet = self.workspace / "artifacts" / self.key / f"attempt-{self.attempt}" / "task-packet.md"
        self.packet.parent.mkdir(parents=True)
        self.packet.write_text("authenticated packet fixture\n", encoding="utf-8")
        artifact = self.packet.parent
        self.packet_json = artifact / "task-packet.json"
        self.packet_json.write_text('{"fixture":true}\n', encoding="utf-8")
        self.report = artifact / "task-report.md"
        self.report.write_text("# Report\n", encoding="utf-8")
        self.execution = {
            "schemaVersion": 1, "featureId": self.feature,
            "taskId": self.target_task, "taskKey": self.key,
            "attempt": self.attempt, "role": self.role, "branch": self.branch,
            "worktree": str(self.worktree), "packetPath": str(self.packet),
            "packetJsonPath": str(artifact / "task-packet.json"),
            "reportPath": str(artifact / "task-report.md"),
            "modelProfile": "strong", "updatedAt": "2026-09-01T00:00:00Z",
        }
        self.execution_path = self.workspace / "executions" / f"{self.key}.json"
        self.execution_path.write_text(json.dumps(self.execution, indent=2) + "\n", encoding="utf-8")
        claim_attempt = 1
        claim_target = "Active"
        claim_id = "dispatch-" + hashlib.sha256(
            "\0".join(
                (self.team, self.feature, self.target_task, self.role, str(claim_attempt), claim_target)
            ).encode()
        ).hexdigest()[:32]
        claim_identity = {
            "schemaVersion": 1, "team": self.team, "featureId": self.feature,
            "taskId": self.target_task, "taskKey": self.key, "attempt": claim_attempt,
            "role": self.role, "claimId": claim_id, "targetStatus": claim_target,
        }
        self.claim = {
            **claim_identity,
            "claimDigest": migration.digest(migration.canonical(claim_identity)),
            "recordedAt": "2026-08-01T00:00:00Z",
        }
        self.claim_path = self.workspace / "claims" / f"{self.key}.json"
        self.claim_path.write_text(json.dumps(self.claim, indent=2) + "\n", encoding="utf-8")
        self.contract_line = (
            f"{self.authorization_task} exports transaction `lineageMigration/v1` — "
            "test fixture contract"
        )
        (self.workspace / "CONTRACTS.md").write_text(
            "# Contracts\n\n" + self.contract_line + "\n", encoding="utf-8"
        )
        self.tasks = {
            "team": self.team, "featureId": self.feature,
            "tasks": [
                self.task(
                    self.target_task,
                    "Planned",
                    "target-r1",
                    [
                        {
                            "body": (
                                f"[claim]\nclaim-id: {claim_id}\nrole: {self.role}\n"
                                f"target-status: {claim_target}\n\n— dispatcher"
                            )
                        }
                    ],
                ),
                self.task(self.authorization_task, "Ready to deploy", "auth-r1"),
                self.task(self.other_task, "Active", "other-r1"),
            ],
        }
        self.lifecycle_root = self.base / "lifecycle"
        self.lifecycle_root.mkdir(mode=0o700)
        key_path = self.lifecycle_root / "record-auth.key"
        key_path.write_bytes(b"k" * 32)
        key_path.chmod(0o600)
        self.generation = {
            "instance": f"{self.role}--{self.key}--a{self.attempt}",
            "createdAt": "2026-09-01T01:02:03Z", "state": "dead",
            "rowSha256": "sha256:" + "7" * 64,
        }
        self.request = self.make_request()
        self.control_path = (
            self.workspace / "lineage-migration-outbox" / "pending"
            / f"{self.request['id']}.json"
        )
        self.write_request()
        self.roles = {
            "TEAM_LEAD": "team-lead",
            "PRODUCT_MANAGER": "senior-technical-product-manager",
            "PRINCIPAL_ARCHITECT": "principal-software-architect",
            "SCEPTICAL_ARCHITECT": "sceptical-architect",
        }
        self.environment = mock.patch.dict(
            os.environ, {"STARTUP_FACTORY_LINEAGE_MIGRATION_BROKER": "1"}
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    @staticmethod
    def task(task_id: str, status: str, revision: str, comments=None) -> dict:
        return {
            "taskId": task_id, "status": status, "revision": revision,
            "labels": [], "comments": list(comments or []),
        }

    def make_request(self) -> dict:
        contract = migration.registered_contract(self.workspace)
        execution_raw = self.execution_path.read_bytes()
        claim_raw = self.claim_path.read_bytes()
        identity = {
            "repository": str(self.repository), "workspace": str(self.workspace),
            "team": self.team, "featureId": self.feature,
            "taskId": self.target_task, "taskKey": self.key,
            "attempt": self.attempt, "authorizationTaskId": self.authorization_task,
            "execution": migration.digest(execution_raw), "claim": migration.digest(claim_raw),
            "head": self.head,
        }
        control_id = "control-" + hashlib.sha256(migration.canonical(identity)).hexdigest()[:32]
        value = {
            "schemaVersion": 1, "id": control_id, "team": self.team,
            "featureId": self.feature, "taskId": self.target_task,
            "taskKey": self.key, "actor": "team-lead",
            "authorizationTaskId": self.authorization_task,
            "authorizationTaskRevision": "auth-r1",
            "authorizationTaskStatus": "Ready to deploy",
            "contractRegistrySha256": contract["contractRegistrySha256"],
            "contractEntrySha256": contract["contractEntrySha256"],
            "marker": "lineage-migration", "createdAt": int(time.time()),
            "expiresAt": int(time.time()) + 300,
            "observedLifecycleCreatedAt": self.generation["createdAt"],
            "observedTaskRevision": "target-r1", "observedTaskStatus": "Planned",
            "observedExecutionSha256": migration.digest(execution_raw),
            "observedClaimSha256": migration.digest(claim_raw),
            "branch": self.branch, "worktree": str(self.worktree), "head": self.head,
            "packetPath": str(self.packet),
            "packetSha256": migration.digest(self.packet.read_bytes()),
            "packetJsonPath": str(self.packet_json),
            "packetJsonSha256": migration.digest(self.packet_json.read_bytes()),
            "reportPath": str(self.report),
            "reportSha256": migration.digest(self.report.read_bytes()),
        }
        value["controlBodySha256"] = migration.digest(
            migration.canonical(migration.request_body(value))
        )
        value["producerCapability"] = {"fixture": True}
        return value

    def write_request(self) -> None:
        self.control_path.write_bytes(migration.canonical(self.request) + b"\n")
        self.control_path.chmod(0o600)

    def reset_request(self) -> None:
        try:
            self.control_path.unlink()
        except FileNotFoundError:
            pass
        self.request = self.make_request()
        self.control_path = (
            self.workspace / "lineage-migration-outbox" / "pending"
            / f"{self.request['id']}.json"
        )
        self.write_request()

    def patches(self):
        return (
            mock.patch.object(migration, "verify_entry", return_value={"executionKind": "gate", "role": "team-lead"}),
            mock.patch.object(migration, "verify_published_entry", return_value={"executionKind": "gate", "role": "team-lead"}),
            mock.patch.object(migration, "protocol_roles", return_value=self.roles),
            mock.patch.object(migration, "current_verdicts", return_value=[
                {"family": "product", "marker": "product-approval", "round": 4},
                {"family": "principal", "marker": "design-approved", "round": 3},
                {"family": "sceptical", "marker": "sceptical-design-approved", "round": 4},
            ]),
            mock.patch.object(migration, "lifecycle_generation", return_value=self.generation),
        )

    def producer_context(self, actor: str) -> tuple[dict[str, str], dict, object]:
        capability = mint(
            str(self.repository), str(self.workspace), self.team, self.feature,
            actor, "gate", "-", 0, actor,
        )
        environment = {
            "STARTUP_FACTORY_CANONICAL_REPO": str(self.repository),
            "STARTUP_FACTORY_CANONICAL_WORKSPACE": str(self.workspace),
            "STARTUP_FACTORY_TEAM": self.team,
            "STARTUP_FACTORY_FEATURE_ID": self.feature,
            "STARTUP_FACTORY_ROLE": actor,
            "STARTUP_FACTORY_EXECUTION_KIND": "gate",
            "STARTUP_FACTORY_INSTANCE": actor,
            "STARTUP_FACTORY_OUTBOX_TRANSPORT": "/tmp/lineage-migration-test.sock",
        }

        return environment, capability, self.transport_for(capability)

    @staticmethod
    def transport_for(capability: dict):
        def sign_request(_locator, value, body):
            return sign_entry(
                value,
                body,
                capability["id"],
                capability["secret"],
                capability["instance"],
                capability["expiresAt"],
            )

        return mock.patch.object(
            worker_control, "request_signature", side_effect=sign_request
        )

    def migrate(self) -> str:
        patches = list(self.patches())
        for patch in patches: patch.start()
        try:
            return migration.migrate_one(
                self.repository, self.workspace, self.lifecycle_root,
                self.tasks, self.control_path,
            )
        finally:
            for patch in reversed(patches): patch.stop()

    def test_exact_two_field_migration_and_domain_separated_receipt(self) -> None:
        claim_before = self.claim_path.read_bytes()
        tasks_before = json.loads(json.dumps(self.tasks))
        head_before = self.head
        self.assertEqual(self.migrate(), "consumed")
        target = json.loads(self.execution_path.read_text())
        self.assertEqual(set(target) - set(self.execution), {"claimLineage", "lineageDigest"})
        self.assertTrue(all(target[name] == value for name, value in self.execution.items()))
        self.assertEqual(target["claimLineage"]["claimAttempt"], 1)
        receipt = json.loads(next((self.lifecycle_root / "lineage-migrations" / "consumed").iterdir()).read_text())
        self.assertTrue(migration.authenticated(receipt, b"k" * 32))
        self.assertEqual(receipt["domain"], "lineageMigration/v1")
        self.assertEqual(receipt["lifecycle"]["rowSha256"], self.generation["rowSha256"])
        self.assertFalse((self.lifecycle_root / "lineage-migrations" / "prepared" / self.control_path.name).exists())
        self.assertTrue((self.workspace / "lineage-migration-outbox" / "consumed" / self.control_path.name).exists())
        self.assertEqual(self.claim_path.read_bytes(), claim_before)
        self.assertEqual(self.tasks, tasks_before)
        self.assertEqual(
            subprocess.run(
                ["git", "-C", str(self.worktree), "rev-parse", "HEAD"],
                check=True, text=True, stdout=subprocess.PIPE,
            ).stdout.strip(),
            head_before,
        )
        self.assertFalse((self.workspace / "control-outbox").exists())
        self.assertFalse((self.workspace / "pids").exists())

    def test_delivery_profile_is_preserved_as_the_only_optional_legacy_field(self) -> None:
        self.execution["deliveryProfile"] = "standard"
        self.execution_path.write_bytes(migration.canonical(self.execution) + b"\n")
        self.reset_request()

        self.assertEqual(self.migrate(), "consumed")
        target = json.loads(self.execution_path.read_text(encoding="utf-8"))
        self.assertEqual(target["deliveryProfile"], "standard")
        self.assertEqual(
            set(target) - set(self.execution),
            {"claimLineage", "lineageDigest"},
        )

    def test_unexpected_legacy_execution_field_fails_before_prepare(self) -> None:
        self.execution["untrustedExtension"] = True
        self.execution_path.write_bytes(migration.canonical(self.execution) + b"\n")
        self.reset_request()
        before = self.execution_path.read_bytes()

        with self.assertRaisesRegex(
            migration.MigrationError, "exact genuine pre-lineage"
        ):
            self.migrate()
        self.assertEqual(self.execution_path.read_bytes(), before)
        self.assertEqual(
            list(
                (self.lifecycle_root / "lineage-migrations" / "prepared").glob(
                    "*.json"
                )
            ),
            [],
        )

    def assert_capability_change_waits_for_transaction(self, action: str) -> None:
        self.control_path.unlink()
        (self.workspace / "tasks.json").write_text(
            json.dumps(self.tasks) + "\n", encoding="utf-8"
        )
        environment, capability, transport = self.producer_context("team-lead")
        args = argparse.Namespace(
            task=self.target_task,
            authorization_task=self.authorization_task,
            expected_attempt=self.attempt,
            observed_created_at=self.generation["createdAt"],
        )
        with transport, mock.patch.dict(
            os.environ, environment, clear=False
        ), mock.patch("sys.stdout"):
            self.assertEqual(worker_control.migration_request_command(args), 0)
        self.control_path = next(
            (self.workspace / "lineage-migration-outbox" / "pending").iterdir()
        )
        self.request = json.loads(self.control_path.read_text(encoding="utf-8"))

        started = threading.Event()
        finished = threading.Event()
        failures: list[BaseException] = []

        def mutate_capability() -> None:
            started.set()
            try:
                if action == "revoke":
                    revoke_exact(
                        str(self.repository),
                        str(self.workspace),
                        capability["id"],
                    )
                else:
                    mint(
                        str(self.repository),
                        str(self.workspace),
                        self.team,
                        self.feature,
                        "team-lead",
                        "gate",
                        "-",
                        0,
                        "team-lead-successor",
                    )
            except BaseException as exc:  # surfaced deterministically below
                failures.append(exc)
            finally:
                finished.set()

        competitor = threading.Thread(target=mutate_capability, daemon=True)
        original_store = migration.store_receipt
        original_install = migration.install_execution_transaction
        original_consume = migration.consume_control
        phases: list[str] = []

        def roles_after_competitor_starts(*_arguments, **_kwargs):
            competitor.start()
            self.assertTrue(started.wait(1))
            time.sleep(0.05)
            self.assertFalse(finished.is_set())
            return self.roles

        def guarded_store(path, unsigned, key, **kwargs):
            self.assertFalse(finished.is_set())
            phases.append(str(unsigned.get("phase")))
            return original_store(path, unsigned, key, **kwargs)

        def guarded_install(*arguments, **kwargs):
            self.assertFalse(finished.is_set())
            phases.append("apply")
            return original_install(*arguments, **kwargs)

        def guarded_consume(*arguments, **kwargs):
            self.assertFalse(finished.is_set())
            phases.append("retire-control")
            return original_consume(*arguments, **kwargs)

        with mock.patch.object(
            migration, "protocol_roles", side_effect=roles_after_competitor_starts
        ), mock.patch.object(
            migration, "current_verdicts", return_value=[]
        ), mock.patch.object(
            migration, "lifecycle_generation", return_value=self.generation
        ), mock.patch.object(
            migration, "store_receipt", side_effect=guarded_store
        ), mock.patch.object(
            migration, "install_execution_transaction", side_effect=guarded_install
        ), mock.patch.object(
            migration, "consume_control", side_effect=guarded_consume
        ):
            self.assertEqual(
                migration.migrate_one(
                    self.repository,
                    self.workspace,
                    self.lifecycle_root,
                    self.tasks,
                    self.control_path,
                ),
                "consumed",
            )

        competitor.join(3)
        self.assertTrue(finished.is_set())
        self.assertEqual(failures, [])
        self.assertEqual(
            phases,
            ["prepared", "apply", "consumed", "retire-control"],
        )

    def test_revocation_cannot_race_prepare_apply_or_consume(self) -> None:
        self.assert_capability_change_waits_for_transaction("revoke")

    def test_supersession_cannot_race_prepare_apply_or_consume(self) -> None:
        self.assert_capability_change_waits_for_transaction("supersede")

    def test_receipt_and_control_phase_changes_are_directory_durable(self) -> None:
        receipt_directory = self.lifecycle_root / "receipt-order"
        receipt_directory.mkdir(mode=0o700)
        receipt_path = receipt_directory / f"control-{'a' * 32}.json"
        fsync_kinds = []
        real_fsync = os.fsync

        def recording_fsync(descriptor: int) -> None:
            mode = os.fstat(descriptor).st_mode
            fsync_kinds.append("directory" if stat.S_ISDIR(mode) else "file")
            real_fsync(descriptor)

        with mock.patch.object(migration.os, "fsync", side_effect=recording_fsync):
            migration.store_receipt(
                receipt_path,
                {"schemaVersion": 1, "domain": "lineageMigration/v1"},
                b"k" * 32,
            )
        self.assertEqual(fsync_kinds[-2:], ["file", "directory"])

        directory_events = []
        original_directory_fsync = migration.fsync_ref

        def recording_directory(directory) -> None:
            directory_events.append(directory.path)
            original_directory_fsync(directory)

        with mock.patch.object(
            migration, "fsync_ref", side_effect=recording_directory
        ):
            self.assertEqual(self.migrate(), "consumed")
        prepared = self.lifecycle_root / "lineage-migrations" / "prepared"
        consumed_receipts = self.lifecycle_root / "lineage-migrations" / "consumed"
        pending_controls = self.workspace / "lineage-migration-outbox" / "pending"
        consumed_controls = self.workspace / "lineage-migration-outbox" / "consumed"
        rejected_controls = self.workspace / "lineage-migration-outbox" / "rejected"
        expected_tail = [
            prepared,
            consumed_receipts,
            prepared,
            consumed_controls,
            rejected_controls,
            pending_controls,
        ]
        cursor = 0
        for observed in directory_events:
            if cursor < len(expected_tail) and observed == expected_tail[cursor]:
                cursor += 1
        self.assertEqual(cursor, len(expected_tail), directory_events)

    def test_direct_invocation_fails_before_authority_or_execution_mutation(self) -> None:
        before = self.execution_path.read_bytes()
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
            migration.MigrationError, "direct invocation"
        ):
            migration.migrate_one(
                self.repository, self.workspace, self.lifecycle_root,
                self.tasks, self.control_path,
            )
        self.assertEqual(self.execution_path.read_bytes(), before)
        self.assertFalse((self.lifecycle_root / "lineage-migrations").exists())

    def test_prepared_parent_swap_cannot_redirect_protected_receipt(self) -> None:
        before = self.execution_path.read_bytes()
        outside = self.base / "attacker-prepared-receipts"
        outside.mkdir(mode=0o700)
        detached = self.lifecycle_root / "lineage-migrations" / ".prepared-detached"
        original_store = migration.store_receipt
        swapped = False

        def swap_prepared_parent(path, unsigned, key, **kwargs):
            nonlocal swapped
            if path.parent.name == "prepared" and not swapped:
                path.parent.rename(detached)
                path.parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            return original_store(path, unsigned, key, **kwargs)

        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(
                migration, "store_receipt", side_effect=swap_prepared_parent
            ), self.assertRaisesRegex(
                migration.MigrationError, "pathname changed during migration"
            ):
                migration.migrate_one(
                    self.repository,
                    self.workspace,
                    self.lifecycle_root,
                    self.tasks,
                    self.control_path,
                )
        finally:
            for patch in reversed(patches):
                patch.stop()

        self.assertTrue(swapped)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(len(list(detached.glob("*.json"))), 1)
        self.assertEqual(self.execution_path.read_bytes(), before)

    def test_authenticated_team_lead_stages_secret_free_registered_request(self) -> None:
        self.control_path.unlink()
        (self.workspace / "tasks.json").write_text(
            json.dumps(self.tasks) + "\n", encoding="utf-8"
        )
        environment, capability, transport = self.producer_context("team-lead")
        args = argparse.Namespace(
            task=self.target_task, authorization_task=self.authorization_task,
            expected_attempt=self.attempt,
            observed_created_at=self.generation["createdAt"],
        )
        staged_at = int(time.time())
        fsync_kinds = []
        real_fsync = os.fsync

        def recording_fsync(descriptor: int) -> None:
            mode = os.fstat(descriptor).st_mode
            fsync_kinds.append("directory" if stat.S_ISDIR(mode) else "file")
            real_fsync(descriptor)

        with transport, mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "sys.stdout"
        ), mock.patch.object(
            worker_control.time, "time", return_value=staged_at
        ), mock.patch.object(
            worker_control.os, "fsync", side_effect=recording_fsync
        ):
            self.assertEqual(worker_control.migration_request_command(args), 0)
        self.assertEqual(fsync_kinds[-2:], ["file", "directory"])
        staged = list((self.workspace / "lineage-migration-outbox" / "pending").glob("control-*.json"))
        self.assertEqual(len(staged), 1)
        raw = staged[0].read_bytes()
        value = json.loads(raw)
        self.assertEqual(value["authorizationTaskId"], self.authorization_task)
        self.assertEqual(value["authorizationTaskStatus"], "Ready to deploy")
        self.assertEqual(value["packetJsonPath"], str(self.packet_json))
        self.assertNotIn(capability["secret"].encode(), raw)

        # The stable operation ID deliberately excludes renewable TTL fields.
        # A later authenticated retry must reuse the still-live request rather
        # than treating the new timestamp/signature bytes as an ID collision.
        with self.transport_for(capability), mock.patch.dict(
            os.environ, environment, clear=False
        ), mock.patch(
            "sys.stdout"
        ), mock.patch.object(
            worker_control.time, "time", return_value=staged_at + 1
        ):
            self.assertEqual(worker_control.migration_request_command(args), 0)
        self.assertEqual(staged[0].read_bytes(), raw)
        self.assertEqual(
            len(list((self.workspace / "lineage-migration-outbox" / "pending").iterdir())),
            1,
        )
        args.authorization_task = self.other_task
        with mock.patch.dict(os.environ, environment, clear=False), self.assertRaisesRegex(
            worker_control.ControlError, "unique registered"
        ):
            worker_control.migration_request_command(args)

    def test_first_use_and_idempotent_staging_fsync_every_queue_parent(self) -> None:
        self.control_path.unlink()
        queue_root = self.workspace / "lineage-migration-outbox"
        pending = queue_root / "pending"
        consumed = queue_root / "consumed"
        consumed.rmdir()
        pending.rmdir()
        queue_root.rmdir()
        (self.workspace / "tasks.json").write_text(
            json.dumps(self.tasks) + "\n", encoding="utf-8"
        )
        environment, capability, transport = self.producer_context("team-lead")
        args = argparse.Namespace(
            task=self.target_task,
            authorization_task=self.authorization_task,
            expected_attempt=self.attempt,
            observed_created_at=self.generation["createdAt"],
        )
        directory_events = []
        original_fsync = worker_control.os.fsync

        def recording_fsync(descriptor: int) -> None:
            info = os.fstat(descriptor)
            if stat.S_ISDIR(info.st_mode):
                for path in (self.workspace, queue_root, pending, consumed):
                    try:
                        candidate = path.lstat()
                    except FileNotFoundError:
                        continue
                    if (candidate.st_dev, candidate.st_ino) == (
                        info.st_dev,
                        info.st_ino,
                    ):
                        directory_events.append(path)
                        break
            original_fsync(descriptor)

        staged_at = int(time.time())
        with transport, mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "sys.stdout"
        ), mock.patch.object(
            worker_control.time, "time", return_value=staged_at
        ), mock.patch.object(
            worker_control.os, "fsync", side_effect=recording_fsync
        ):
            self.assertEqual(worker_control.migration_request_command(args), 0)
        self.assertEqual(
            directory_events,
            [self.workspace, queue_root, queue_root, pending],
        )
        staged = next(pending.iterdir())
        staged_raw = staged.read_bytes()

        directory_events.clear()
        with self.transport_for(capability), mock.patch.dict(
            os.environ, environment, clear=False
        ), mock.patch(
            "sys.stdout"
        ), mock.patch.object(
            worker_control.time, "time", return_value=staged_at + 1
        ), mock.patch.object(
            worker_control.os, "fsync", side_effect=recording_fsync
        ):
            self.assertEqual(worker_control.migration_request_command(args), 0)
        self.assertEqual(
            directory_events,
            [self.workspace, queue_root, queue_root, pending],
        )
        self.assertEqual(staged.read_bytes(), staged_raw)

    def test_producer_parent_swap_cannot_redirect_signed_request(self) -> None:
        self.control_path.unlink()
        (self.workspace / "tasks.json").write_text(
            json.dumps(self.tasks) + "\n", encoding="utf-8"
        )
        environment, _capability, transport = self.producer_context("team-lead")
        args = argparse.Namespace(
            task=self.target_task,
            authorization_task=self.authorization_task,
            expected_attempt=self.attempt,
            observed_created_at=self.generation["createdAt"],
        )
        queue_root = self.workspace / "lineage-migration-outbox"
        detached = self.workspace / ".detached-lineage-migration-outbox"
        outside = self.base / "attacker-producer-outbox"
        outside.mkdir(mode=0o700)
        (outside / "pending").mkdir(mode=0o700)
        (outside / "consumed").mkdir(mode=0o700)
        original_open = worker_control.os.open
        swapped = False

        def swap_before_create(path, flags, *arguments, **kwargs):
            nonlocal swapped
            name = os.fsdecode(path)
            if (
                not swapped
                and re.fullmatch(r"control-[0-9a-f]{32}[.]json", name)
                and flags & os.O_CREAT
            ):
                queue_root.rename(detached)
                queue_root.symlink_to(outside, target_is_directory=True)
                swapped = True
            return original_open(path, flags, *arguments, **kwargs)

        with transport, mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "sys.stdout"
        ), mock.patch.object(
            worker_control.os, "open", side_effect=swap_before_create
        ), self.assertRaisesRegex(
            worker_control.ControlError, "pathname changed before publication"
        ):
            worker_control.migration_request_command(args)

        self.assertTrue(swapped)
        self.assertEqual(list((outside / "pending").iterdir()), [])
        self.assertEqual(len(list((detached / "pending").iterdir())), 1)

    def test_staging_requires_one_exact_historical_tracker_claim_receipt(self) -> None:
        original_raw = self.claim_path.read_bytes()
        forged_target = "Review"
        forged_id = "dispatch-" + hashlib.sha256(
            "\0".join(
                (
                    self.team,
                    self.feature,
                    self.target_task,
                    self.role,
                    "1",
                    forged_target,
                )
            ).encode()
        ).hexdigest()[:32]
        forged_identity = {
            "schemaVersion": 1,
            "team": self.team,
            "featureId": self.feature,
            "taskId": self.target_task,
            "taskKey": self.key,
            "attempt": 1,
            "role": self.role,
            "claimId": forged_id,
            "targetStatus": forged_target,
        }
        forged_claim = {
            **forged_identity,
            "claimDigest": worker_control.sha256_bytes(
                worker_control.canonical(forged_identity)
            ),
            "recordedAt": self.claim["recordedAt"],
        }
        self.claim_path.write_text(
            json.dumps(forged_claim) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            worker_control.ControlError, "historical tracker receipt"
        ):
            worker_control.legacy_migration_binding(
                self.workspace,
                self.tasks,
                self.team,
                self.feature,
                self.target_task,
            )

        self.claim_path.write_bytes(original_raw)
        self.tasks["tasks"][0]["comments"].append(
            dict(self.tasks["tasks"][0]["comments"][0])
        )
        with self.assertRaisesRegex(
            worker_control.ControlError, "historical tracker receipt"
        ):
            worker_control.legacy_migration_binding(
                self.workspace,
                self.tasks,
                self.team,
                self.feature,
                self.target_task,
            )

    def test_executor_quarantines_consistently_forged_claim_without_receipt(self) -> None:
        before = self.execution_path.read_bytes()
        forged_target = "Review"
        forged_id = "dispatch-" + hashlib.sha256(
            "\0".join(
                (
                    self.team,
                    self.feature,
                    self.target_task,
                    self.role,
                    "1",
                    forged_target,
                )
            ).encode()
        ).hexdigest()[:32]
        forged_identity = {
            "schemaVersion": 1,
            "team": self.team,
            "featureId": self.feature,
            "taskId": self.target_task,
            "taskKey": self.key,
            "attempt": 1,
            "role": self.role,
            "claimId": forged_id,
            "targetStatus": forged_target,
        }
        forged_claim = {
            **forged_identity,
            "claimDigest": migration.digest(migration.canonical(forged_identity)),
            "recordedAt": self.claim["recordedAt"],
        }
        self.claim_path.write_text(
            json.dumps(forged_claim) + "\n", encoding="utf-8"
        )
        self.reset_request()
        request_raw = self.control_path.read_bytes()
        tasks_path = self.workspace / "tasks.json"
        tasks_path.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        reconcile_args = argparse.Namespace(
            repo=str(self.repository),
            workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root),
            team=self.team,
            feature=self.feature,
            tasks=str(tasks_path),
        )
        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            self.assertEqual(migration.reconcile(reconcile_args), 0)
        finally:
            for patch in reversed(patches):
                patch.stop()

        pending = self.workspace / "lineage-migration-outbox" / "pending"
        rejected = self.workspace / "lineage-migration-outbox" / "rejected"
        prepared = self.lifecycle_root / "lineage-migrations" / "prepared"
        self.assertEqual(list(pending.iterdir()), [])
        self.assertIn(request_raw, [path.read_bytes() for path in rejected.glob("*.entry")])
        self.assertEqual(list(prepared.glob("*.json")), [])
        self.assertEqual(self.execution_path.read_bytes(), before)

    def test_producer_authenticates_team_lead_before_staging(self) -> None:
        self.control_path.unlink()
        (self.workspace / "tasks.json").write_text(
            json.dumps(self.tasks) + "\n", encoding="utf-8"
        )
        args = argparse.Namespace(
            task=self.target_task,
            authorization_task=self.authorization_task,
            expected_attempt=self.attempt,
            observed_created_at=self.generation["createdAt"],
        )

        wrong_actor = "principal-software-architect"
        wrong_environment, _wrong_capability, wrong_transport = (
            self.producer_context(wrong_actor)
        )
        pending = self.workspace / "lineage-migration-outbox" / "pending"
        staged_at = int(time.time())
        with wrong_transport, mock.patch.dict(
            os.environ, wrong_environment, clear=False
        ), mock.patch("sys.stdout"), mock.patch.object(
            worker_control.time, "time", return_value=staged_at
        ), self.assertRaisesRegex(
            worker_control.ControlError, "configured Team Lead"
        ):
            worker_control.migration_request_command(args)
        self.assertEqual(list(pending.iterdir()), [])

        lead_environment, _lead_capability, lead_transport = (
            self.producer_context("team-lead")
        )
        with lead_transport, mock.patch.dict(
            os.environ, lead_environment, clear=False
        ), mock.patch("sys.stdout"), mock.patch.object(
            worker_control.time, "time", return_value=staged_at
        ):
            self.assertEqual(worker_control.migration_request_command(args), 0)
        staged = [json.loads(path.read_text()) for path in pending.iterdir()]
        self.assertEqual([value["actor"] for value in staged], ["team-lead"])

        reconcile_args = argparse.Namespace(
            repo=str(self.repository),
            workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root),
            team=self.team,
            feature=self.feature,
            tasks=str(self.workspace / "tasks.json"),
        )
        patches = list(self.patches())
        patches[0] = mock.patch.object(
            migration,
            "verify_entry",
            side_effect=lambda _repository, _workspace, entry, _digest, **_kwargs: {
                "executionKind": "gate",
                "role": entry["actor"],
            },
        )
        for patch in patches:
            patch.start()
        try:
            self.assertEqual(migration.reconcile(reconcile_args), 0)
        finally:
            for patch in reversed(patches):
                patch.stop()
        self.assertEqual(list(pending.iterdir()), [])
        consumed = self.workspace / "lineage-migration-outbox" / "consumed"
        consumed_values = [json.loads(path.read_text()) for path in consumed.iterdir()]
        self.assertEqual([value["actor"] for value in consumed_values], ["team-lead"])

    def test_manual_preset_swap_after_verification_cannot_authorize_non_lead(self) -> None:
        self.control_path.unlink()
        (self.workspace / "tasks.json").write_text(
            json.dumps(self.tasks) + "\n", encoding="utf-8"
        )
        preset_path = self.workspace / "preset.env"
        exact_projection = preset_path.read_bytes()
        attacker = "principal-software-architect"
        attacker_projection = exact_projection.replace(
            b"PROTOCOL_TEAM_LEAD=team-lead\n",
            f"PROTOCOL_TEAM_LEAD={attacker}\n".encode(),
        )
        environment, _capability, transport = self.producer_context(attacker)
        args = argparse.Namespace(
            task=self.target_task,
            authorization_task=self.authorization_task,
            expected_attempt=self.attempt,
            observed_created_at=self.generation["createdAt"],
        )
        before = self.execution_path.read_bytes()
        preset_path.write_bytes(attacker_projection)
        with transport, mock.patch.dict(
            os.environ, environment, clear=False
        ), mock.patch("sys.stdout"), self.assertRaisesRegex(
            worker_control.ControlError,
            "protected team preset authority is unavailable",
        ):
            worker_control.migration_request_command(args)

        self.assertEqual(self.execution_path.read_bytes(), before)
        self.assertEqual(
            list((self.workspace / "lineage-migration-outbox" / "pending").iterdir()),
            [],
        )

    def test_reconcile_durably_rejects_bad_entries_and_continues_safe_work(self) -> None:
        tasks_path = self.workspace / "tasks.json"
        tasks_path.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        pending = self.workspace / "lineage-migration-outbox" / "pending"

        expired = dict(self.request)
        expired["id"] = "control-" + "0" * 32
        expired["createdAt"] = int(time.time()) - 400
        expired["expiresAt"] = int(time.time()) - 100
        expired["controlBodySha256"] = migration.digest(
            migration.canonical(migration.request_body(expired))
        )
        expired_raw = migration.canonical(expired) + b"\n"
        expired_path = pending / f"{expired['id']}.json"
        expired_path.write_bytes(expired_raw)
        expired_path.chmod(0o600)

        malformed_path = pending / ("control-" + "1" * 32 + ".json")
        malformed_raw = b"{not-json\n"
        malformed_path.write_bytes(malformed_raw)
        malformed_path.chmod(0o600)

        args = argparse.Namespace(
            repo=str(self.repository), workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root), team=self.team,
            feature=self.feature, tasks=str(tasks_path),
        )
        directory_events = []
        original_directory_fsync = migration.fsync_ref

        def recording_directory(directory) -> None:
            directory_events.append(directory.path)
            original_directory_fsync(directory)

        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(
                migration, "fsync_ref", side_effect=recording_directory
            ):
                self.assertEqual(migration.reconcile(args), 0)
        finally:
            for patch in reversed(patches):
                patch.stop()

        rejected = self.workspace / "lineage-migration-outbox" / "rejected"
        quarantined = [path.read_bytes() for path in rejected.glob("*.entry")]
        self.assertCountEqual(quarantined, [expired_raw, malformed_raw])
        self.assertEqual(list(pending.iterdir()), [])
        self.assertTrue(
            (
                self.workspace / "lineage-migration-outbox" / "consumed"
                / self.control_path.name
            ).is_file()
        )
        durable_moves = sum(
            1
            for left, right in zip(directory_events, directory_events[1:])
            if left == rejected and right == pending
        )
        # The two rejected inputs and the successfully consumed input all move
        # destination-first out of pending.  The valid request's untrusted
        # source inode remains as a non-authoritative tombstone after its exact
        # inode/byte comparison.
        self.assertEqual(durable_moves, 3, directory_events)

    def test_rejected_parent_swap_cannot_redirect_quarantine(self) -> None:
        tasks_path = self.workspace / "tasks.json"
        tasks_path.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        pending = self.workspace / "lineage-migration-outbox" / "pending"
        malformed = pending / ("control-" + "0" * 32 + ".json")
        malformed_raw = b"{malformed-parent-swap\n"
        malformed.write_bytes(malformed_raw)
        malformed.chmod(0o600)
        rejected = self.workspace / "lineage-migration-outbox" / "rejected"
        outside = self.base / "attacker-rejected"
        outside.mkdir(mode=0o700)
        detached = rejected.with_name(".rejected-detached")
        original_rename = migration.rename_no_replace
        swapped = False

        def swap_rejected_parent(source, destination, label, **kwargs):
            nonlocal swapped
            if label == "quarantine lineage migration pending entry" and not swapped:
                rejected.rename(detached)
                rejected.symlink_to(outside, target_is_directory=True)
                swapped = True
            return original_rename(source, destination, label, **kwargs)

        args = argparse.Namespace(
            repo=str(self.repository), workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root), team=self.team,
            feature=self.feature, tasks=str(tasks_path),
        )
        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(
                migration, "rename_no_replace", side_effect=swap_rejected_parent
            ):
                self.assertEqual(migration.reconcile(args), 0)
        finally:
            for patch in reversed(patches):
                patch.stop()

        self.assertTrue(swapped)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertIn(malformed_raw, [path.read_bytes() for path in detached.iterdir()])

    def test_disappearing_selected_entry_does_not_starve_safe_request(self) -> None:
        tasks_path = self.workspace / "tasks.json"
        tasks_path.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        pending = self.workspace / "lineage-migration-outbox" / "pending"
        vanished = pending / ("control-" + "0" * 32 + ".json")
        vanished.write_bytes(b"{vanish-before-read\n")
        vanished.chmod(0o600)
        original_open = migration.open_bound_bytes_at
        injected = False

        def unlink_before_read(directory, name, label, maximum):
            nonlocal injected
            if name == vanished.name and not injected:
                os.unlink(name, dir_fd=directory.descriptor)
                injected = True
            return original_open(directory, name, label, maximum)

        args = argparse.Namespace(
            repo=str(self.repository), workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root), team=self.team,
            feature=self.feature, tasks=str(tasks_path),
        )
        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(
                migration, "open_bound_bytes_at", side_effect=unlink_before_read
            ):
                self.assertEqual(migration.reconcile(args), 0)
        finally:
            for patch in reversed(patches):
                patch.stop()

        self.assertTrue(injected)
        self.assertFalse(vanished.exists())
        self.assertFalse(self.control_path.exists())
        self.assertIn("claimLineage", json.loads(self.execution_path.read_text()))

    def test_rejected_entry_replacement_is_retained_while_safe_request_runs(self) -> None:
        tasks_path = self.workspace / "tasks.json"
        tasks_path.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        pending = self.workspace / "lineage-migration-outbox" / "pending"
        expired = dict(self.request)
        expired["id"] = "control-" + "0" * 32
        expired["createdAt"] = int(time.time()) - 400
        expired["expiresAt"] = int(time.time()) - 100
        expired["controlBodySha256"] = migration.digest(
            migration.canonical(migration.request_body(expired))
        )
        expired_path = pending / f"{expired['id']}.json"
        expired_path.write_bytes(migration.canonical(expired) + b"\n")
        expired_path.chmod(0o600)
        raced_raw = b"{replacement-after-rejection\n"
        original_reject = migration.reject_pending_entry
        injected = False

        def replace_before_reject(path, *arguments):
            nonlocal injected
            if path == expired_path and not injected:
                replacement = path.with_name(f".{path.name}.replacement")
                replacement.write_bytes(raced_raw)
                os.replace(replacement, path)
                injected = True
            return original_reject(path, *arguments)

        args = argparse.Namespace(
            repo=str(self.repository), workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root), team=self.team,
            feature=self.feature, tasks=str(tasks_path),
        )
        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(
                migration, "reject_pending_entry", side_effect=replace_before_reject
            ):
                self.assertEqual(migration.reconcile(args), 0)
        finally:
            for patch in reversed(patches):
                patch.stop()

        self.assertTrue(injected)
        self.assertEqual(expired_path.read_bytes(), raced_raw)
        self.assertFalse(self.control_path.exists())
        self.assertIn("claimLineage", json.loads(self.execution_path.read_text()))

    def test_rejected_entry_disappearance_does_not_starve_safe_request(self) -> None:
        tasks_path = self.workspace / "tasks.json"
        tasks_path.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        pending = self.workspace / "lineage-migration-outbox" / "pending"
        expired = dict(self.request)
        expired["id"] = "control-" + "0" * 32
        expired["createdAt"] = int(time.time()) - 400
        expired["expiresAt"] = int(time.time()) - 100
        expired["controlBodySha256"] = migration.digest(
            migration.canonical(migration.request_body(expired))
        )
        expired_path = pending / f"{expired['id']}.json"
        expired_path.write_bytes(migration.canonical(expired) + b"\n")
        expired_path.chmod(0o600)
        original_reject = migration.reject_pending_entry
        injected = False

        def unlink_before_reject(path, *arguments):
            nonlocal injected
            if path == expired_path and not injected:
                path.unlink()
                injected = True
            return original_reject(path, *arguments)

        args = argparse.Namespace(
            repo=str(self.repository), workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root), team=self.team,
            feature=self.feature, tasks=str(tasks_path),
        )
        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(
                migration, "reject_pending_entry", side_effect=unlink_before_reject
            ):
                self.assertEqual(migration.reconcile(args), 0)
        finally:
            for patch in reversed(patches):
                patch.stop()

        self.assertTrue(injected)
        self.assertFalse(expired_path.exists())
        self.assertFalse(self.control_path.exists())
        self.assertIn("claimLineage", json.loads(self.execution_path.read_text()))

    def test_expired_stable_id_can_be_restaged_after_bounded_rejection(self) -> None:
        self.control_path.unlink()
        tasks_path = self.workspace / "tasks.json"
        tasks_path.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        environment, capability, transport = self.producer_context("team-lead")
        request_args = argparse.Namespace(
            task=self.target_task, authorization_task=self.authorization_task,
            expected_attempt=self.attempt,
            observed_created_at=self.generation["createdAt"],
        )
        now = int(time.time())
        with transport, mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "sys.stdout"
        ), mock.patch.object(worker_control.time, "time", return_value=now - 400):
            self.assertEqual(worker_control.migration_request_command(request_args), 0)
        pending = self.workspace / "lineage-migration-outbox" / "pending"
        first = next(pending.iterdir())
        first_raw = first.read_bytes()

        reconcile_args = argparse.Namespace(
            repo=str(self.repository), workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root), team=self.team,
            feature=self.feature, tasks=str(tasks_path),
        )
        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            self.assertEqual(migration.reconcile(reconcile_args), 0)
        finally:
            for patch in reversed(patches):
                patch.stop()
        self.assertEqual(list(pending.iterdir()), [])

        with self.transport_for(capability), mock.patch.dict(
            os.environ, environment, clear=False
        ), mock.patch(
            "sys.stdout"
        ), mock.patch.object(worker_control.time, "time", return_value=now):
            self.assertEqual(worker_control.migration_request_command(request_args), 0)
        restaged = next(pending.iterdir())
        self.assertEqual(restaged.name, first.name)
        self.assertNotEqual(restaged.read_bytes(), first_raw)
        self.assertEqual(json.loads(restaged.read_text())["createdAt"], now)

    def test_registered_owner_not_unrelated_approved_task(self) -> None:
        before = self.execution_path.read_bytes()
        self.request["authorizationTaskId"] = self.other_task
        self.request["authorizationTaskRevision"] = "other-r1"
        self.request["controlBodySha256"] = migration.digest(
            migration.canonical(migration.request_body(self.request))
        )
        self.write_request()
        with self.assertRaisesRegex(migration.MigrationError, "registered contract owner"):
            self.migrate()
        self.assertEqual(self.execution_path.read_bytes(), before)

    def test_broker_rejects_helper_bypass_for_nonterminal_authorization(self) -> None:
        """The executor must not trust the producer's signed status assertion."""
        before = self.execution_path.read_bytes()
        self.tasks["tasks"][1]["status"] = "Active"
        self.request["authorizationTaskStatus"] = "Active"
        self.request["controlBodySha256"] = migration.digest(
            migration.canonical(migration.request_body(self.request))
        )
        self.write_request()
        with self.assertRaisesRegex(
            migration.MigrationError, "not an integrated exact package"
        ):
            self.migrate()
        self.assertEqual(self.execution_path.read_bytes(), before)
        self.assertEqual(
            list((self.lifecycle_root / "lineage-migrations" / "prepared").glob("*.json")),
            [],
        )

    def test_reconcile_rejects_arbitrary_snapshot_path(self) -> None:
        canonical_tasks = self.workspace / "tasks.json"
        canonical_tasks.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        forged = self.workspace / "forged-tasks.json"
        forged.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        args = argparse.Namespace(
            repo=str(self.repository), workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root), team=self.team,
            feature=self.feature, tasks=str(forged),
        )
        with self.assertRaisesRegex(migration.MigrationError, "canonical workspace/tasks.json"):
            migration.reconcile(args)

    def test_prepared_target_recovers_after_freshness_drift(self) -> None:
        original_store = migration.store_receipt

        def crash_before_consumed(path, unsigned, key, **kwargs):
            if path.parent.name == "consumed":
                raise migration.MigrationError("simulated crash after target")
            return original_store(path, unsigned, key, **kwargs)

        patches = self.patches()
        for patch in patches: patch.start()
        try:
            with mock.patch.object(migration, "store_receipt", side_effect=crash_before_consumed):
                with self.assertRaisesRegex(migration.MigrationError, "simulated crash"):
                    migration.migrate_one(
                        self.repository, self.workspace, self.lifecycle_root,
                        self.tasks, self.control_path,
                    )
        finally:
            for patch in reversed(patches): patch.stop()
        self.assertIn("claimLineage", json.loads(self.execution_path.read_text()))
        self.tasks["tasks"][1]["revision"] = "auth-later"
        (self.workspace / "CONTRACTS.md").write_text(
            "# later append\n", encoding="utf-8"
        )
        self.assertEqual(self.migrate(), "consumed")

    def test_expired_prepared_exact_old_aborts_and_allows_stable_restaging(self) -> None:
        before = self.execution_path.read_bytes()
        self.control_path.unlink()
        tasks_path = self.workspace / "tasks.json"
        tasks_path.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        environment, capability, transport = self.producer_context("team-lead")
        request_args = argparse.Namespace(
            task=self.target_task,
            authorization_task=self.authorization_task,
            expected_attempt=self.attempt,
            observed_created_at=self.generation["createdAt"],
        )
        staged_at = int(time.time())
        with transport, mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "sys.stdout"
        ), mock.patch.object(worker_control.time, "time", return_value=staged_at):
            self.assertEqual(worker_control.migration_request_command(request_args), 0)
        pending = self.workspace / "lineage-migration-outbox" / "pending"
        self.control_path = next(pending.iterdir())
        self.request = json.loads(self.control_path.read_text())
        request_raw = self.control_path.read_bytes()

        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(
                migration,
                "install_execution_transaction",
                side_effect=migration.MigrationError(
                    "simulated crash before execution transition"
                ),
            ), self.assertRaisesRegex(
                migration.MigrationError, "simulated crash before execution transition"
            ):
                migration.migrate_one(
                    self.repository,
                    self.workspace,
                    self.lifecycle_root,
                    self.tasks,
                    self.control_path,
                )
        finally:
            for patch in reversed(patches):
                patch.stop()

        prepared = self.lifecycle_root / "lineage-migrations" / "prepared"
        self.assertTrue((prepared / self.control_path.name).is_file())
        target_artifact = prepared / f".{self.request['id']}.execution-target"
        backup = prepared / f".{self.request['id']}.execution-backup"
        self.assertFalse(target_artifact.exists())
        self.assertFalse(backup.exists())
        self.assertEqual(self.execution_path.read_bytes(), before)

        reconcile_args = argparse.Namespace(
            repo=str(self.repository),
            workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root),
            team=self.team,
            feature=self.feature,
            tasks=str(tasks_path),
        )
        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(
                migration.time, "time", return_value=self.request["expiresAt"] + 1
            ):
                self.assertEqual(migration.reconcile(reconcile_args), 0)
        finally:
            for patch in reversed(patches):
                patch.stop()

        rejected = self.workspace / "lineage-migration-outbox" / "rejected"
        self.assertIn(request_raw, [path.read_bytes() for path in rejected.glob("*.entry")])
        self.assertEqual(list(pending.iterdir()), [])
        self.assertFalse((prepared / self.control_path.name).exists())
        self.assertFalse(target_artifact.exists())
        self.assertEqual(self.execution_path.read_bytes(), before)

        restaged_at = self.request["expiresAt"] + 1
        with self.transport_for(capability), mock.patch.dict(
            os.environ, environment, clear=False
        ), mock.patch(
            "sys.stdout"
        ), mock.patch.object(worker_control.time, "time", return_value=restaged_at):
            self.assertEqual(worker_control.migration_request_command(request_args), 0)
        restaged = next(pending.iterdir())
        self.assertEqual(restaged.name, self.control_path.name)
        self.assertNotEqual(restaged.read_bytes(), request_raw)
        self.assertEqual(json.loads(restaged.read_text())["createdAt"], restaged_at)

    def test_live_lifecycle_is_rejected_before_prepare_with_open_writer(self) -> None:
        before = self.execution_path.read_bytes()
        writer = os.open(self.execution_path, os.O_RDWR)
        live_generation = {
            **self.generation,
            "state": "live",
            "rowSha256": "sha256:" + "8" * 64,
        }
        patches = list(self.patches())
        patches[-1] = mock.patch.object(
            migration, "lifecycle_generation", return_value=live_generation
        )
        for patch in patches:
            patch.start()
        try:
            with self.assertRaisesRegex(migration.MigrationError, "non-live"):
                migration.migrate_one(
                    self.repository,
                    self.workspace,
                    self.lifecycle_root,
                    self.tasks,
                    self.control_path,
                )
        finally:
            for patch in reversed(patches):
                patch.stop()
            os.close(writer)
        prepared = self.lifecycle_root / "lineage-migrations" / "prepared"
        self.assertEqual(list(prepared.glob("*.json")), [])
        self.assertEqual(self.execution_path.read_bytes(), before)

    def test_lifecycle_drift_is_rejected_inside_commit_boundary(self) -> None:
        before = self.execution_path.read_bytes()
        writer = os.open(self.execution_path, os.O_RDWR)
        live_generation = {
            **self.generation,
            "state": "live",
            "rowSha256": "sha256:" + "9" * 64,
        }
        patches = list(self.patches())
        patches[-1] = mock.patch.object(
            migration,
            "lifecycle_generation",
            side_effect=[self.generation, live_generation],
        )
        for patch in patches:
            patch.start()
        try:
            with self.assertRaisesRegex(migration.MigrationError, "non-live"):
                migration.migrate_one(
                    self.repository,
                    self.workspace,
                    self.lifecycle_root,
                    self.tasks,
                    self.control_path,
                )
        finally:
            for patch in reversed(patches):
                patch.stop()
            os.close(writer)
        prepared = self.lifecycle_root / "lineage-migrations" / "prepared"
        backup = prepared / f".{self.request['id']}.execution-backup"
        self.assertTrue((prepared / self.control_path.name).is_file())
        self.assertFalse(backup.exists())
        self.assertEqual(self.execution_path.read_bytes(), before)

    def test_same_device_preflight_fails_before_prepared_receipt(self) -> None:
        before = self.execution_path.read_bytes()
        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(
                migration,
                "require_same_transaction_device",
                side_effect=migration.MigrationError(
                    "migration execution and protected recovery storage must share one filesystem"
                ),
            ), mock.patch.object(
                migration, "store_receipt", wraps=migration.store_receipt
            ) as receipt_store, self.assertRaisesRegex(
                migration.MigrationError, "share one filesystem"
            ):
                migration.migrate_one(
                    self.repository,
                    self.workspace,
                    self.lifecycle_root,
                    self.tasks,
                    self.control_path,
                )
            receipt_store.assert_not_called()
        finally:
            for patch in reversed(patches):
                patch.stop()
        prepared = self.lifecycle_root / "lineage-migrations" / "prepared"
        self.assertEqual(list(prepared.glob("*.json")), [])
        self.assertEqual(self.execution_path.read_bytes(), before)

    def test_retained_writable_fd_cannot_corrupt_sealed_backup(self) -> None:
        original_store = migration.store_transaction_artifact
        legacy_raw = self.execution_path.read_bytes()
        racing_execution = dict(self.execution)
        racing_execution["updatedAt"] = "non-cooperating-writer"
        racing_raw = migration.canonical(racing_execution) + b"\n"
        injected = False
        writer = os.open(self.execution_path, os.O_RDWR)

        def mutate_after_sealed_copy(
            path: Path, raw: bytes, label: str, **kwargs
        ) -> None:
            nonlocal injected
            result = original_store(path, raw, label, **kwargs)
            if label == "protected legacy execution backup" and not injected:
                injected = True
                os.lseek(writer, 0, os.SEEK_SET)
                os.write(writer, racing_raw)
                os.ftruncate(writer, len(racing_raw))
                os.fsync(writer)
            return result

        try:
            with mock.patch.object(
                migration,
                "store_transaction_artifact",
                side_effect=mutate_after_sealed_copy,
            ), self.assertRaisesRegex(
                migration.MigrationError, "changed before sealed evacuation"
            ):
                self.migrate()
        finally:
            os.close(writer)

        backup = (
            self.lifecycle_root / "lineage-migrations" / "prepared"
            / f".{self.request['id']}.execution-backup"
        )
        self.assertTrue(injected)
        self.assertEqual(self.execution_path.read_bytes(), racing_raw)
        self.assertEqual(backup.read_bytes(), legacy_raw)
        self.assertNotEqual(backup.stat().st_ino, self.execution_path.stat().st_ino)
        self.assertNotIn("claimLineage", json.loads(self.execution_path.read_text()))

    def test_write_at_legacy_unlink_boundary_is_retained_and_recoverable(self) -> None:
        original_rename = migration.rename_no_replace
        legacy_raw = self.execution_path.read_bytes()
        raced_execution = dict(self.execution)
        raced_execution["updatedAt"] = "writer-at-former-unlink-boundary"
        raced_raw = migration.canonical(raced_execution) + b"\n"
        writer = os.open(self.execution_path, os.O_RDWR)
        injected = False

        def mutate_before_evacuation(
            source: Path, destination: Path, label: str, **kwargs
        ) -> None:
            nonlocal injected
            if label == "evacuate legacy execution for migration" and not injected:
                injected = True
                os.lseek(writer, 0, os.SEEK_SET)
                os.write(writer, raced_raw)
                os.ftruncate(writer, len(raced_raw))
                os.fsync(writer)
            original_rename(source, destination, label, **kwargs)

        try:
            with mock.patch.object(
                migration, "rename_no_replace", side_effect=mutate_before_evacuation
            ), self.assertRaisesRegex(
                migration.MigrationError, "changed during sealed evacuation"
            ):
                self.migrate()
        finally:
            os.close(writer)

        prepared = self.lifecycle_root / "lineage-migrations" / "prepared"
        backup = prepared / f".{self.request['id']}.execution-backup"
        tombstones = list(prepared.glob(".*.untrusted-source.*.tombstone"))
        self.assertTrue(injected)
        self.assertFalse(self.execution_path.exists())
        self.assertEqual(backup.read_bytes(), legacy_raw)
        self.assertEqual([path.read_bytes() for path in tombstones], [raced_raw])
        self.assertEqual(
            list((self.lifecycle_root / "lineage-migrations" / "consumed").glob("*.json")),
            [],
        )

        self.assertEqual(self.migrate(), "consumed")
        self.assertIn("claimLineage", json.loads(self.execution_path.read_text()))
        self.assertEqual(tombstones[0].read_bytes(), raced_raw)

    def test_noncooperating_writer_during_no_replace_install_is_preserved(self) -> None:
        original_rename = migration.rename_no_replace
        legacy_raw = self.execution_path.read_bytes()
        racing_execution = dict(self.execution)
        racing_execution["updatedAt"] = "writer-in-empty-name-window"
        racing_raw = migration.canonical(racing_execution) + b"\n"
        injected = False

        def inject_before_projection(
            source: Path, destination: Path, label: str, **kwargs
        ):
            nonlocal injected
            if label == "install migration target projection" and not injected:
                injected = True
                self.execution_path.write_bytes(racing_raw)
            return original_rename(source, destination, label, **kwargs)

        with mock.patch.object(
            migration, "rename_no_replace", side_effect=inject_before_projection
        ), self.assertRaisesRegex(
            migration.MigrationError, "destination already exists"
        ):
            self.migrate()

        backup = (
            self.lifecycle_root / "lineage-migrations" / "prepared"
            / f".{self.request['id']}.execution-backup"
        )
        self.assertTrue(injected)
        self.assertEqual(self.execution_path.read_bytes(), racing_raw)
        self.assertEqual(backup.read_bytes(), legacy_raw)
        self.assertNotIn("claimLineage", json.loads(self.execution_path.read_text()))

    def test_crash_after_atomic_evacuation_recovers_from_protected_bytes(self) -> None:
        original_rename = migration.rename_no_replace
        legacy_raw = self.execution_path.read_bytes()
        crashed = False

        def crash_after_move(
            source: Path, destination: Path, label: str, **kwargs
        ) -> None:
            nonlocal crashed
            original_rename(source, destination, label, **kwargs)
            if label == "install migration target projection" and not crashed:
                crashed = True
                raise migration.MigrationError("simulated crash after atomic evacuation")

        with mock.patch.object(
            migration, "rename_no_replace", side_effect=crash_after_move
        ), self.assertRaisesRegex(
            migration.MigrationError, "simulated crash after atomic evacuation"
        ):
            self.migrate()

        prepared = self.lifecycle_root / "lineage-migrations" / "prepared"
        backup = prepared / f".{self.request['id']}.execution-backup"
        target_artifact = prepared / f".{self.request['id']}.execution-target"
        self.assertIn("claimLineage", json.loads(self.execution_path.read_text()))
        self.assertEqual(backup.read_bytes(), legacy_raw)
        self.assertTrue(target_artifact.is_file())

        self.tasks["tasks"][1]["revision"] = "drift-after-transaction-start"
        (self.workspace / "CONTRACTS.md").write_text("# drift\n", encoding="utf-8")
        self.assertEqual(self.migrate(), "consumed")
        self.assertIn("claimLineage", json.loads(self.execution_path.read_text()))
        self.assertFalse(backup.exists())
        self.assertFalse(target_artifact.exists())

    def test_cross_directory_backup_is_fsynced_destination_then_source(self) -> None:
        execution_directory = self.base / "transaction-executions"
        protected_directory = self.base / "transaction-protected"
        execution_directory.mkdir()
        protected_directory.mkdir()
        execution = execution_directory / "execution.json"
        backup = protected_directory / "execution.backup"
        target_artifact = protected_directory / "execution.target"
        old_raw = b'{"generation":"old"}\n'
        target_raw = b'{"generation":"target"}\n'
        execution.write_bytes(old_raw)
        events = []
        original_rename = migration.rename_no_replace
        original_fsync = migration.fsync_ref

        def recording_rename(
            source: Path, destination: Path, label: str, **kwargs
        ) -> None:
            events.append(("rename", source, destination, label))
            original_rename(source, destination, label, **kwargs)

        def recording_fsync(directory) -> None:
            events.append(("fsync", directory.path))
            original_fsync(directory)

        with mock.patch.object(
            migration, "rename_no_replace", side_effect=recording_rename
        ), mock.patch.object(
            migration, "fsync_ref", side_effect=recording_fsync
        ):
            migration.install_execution_transaction(
                execution, backup, target_artifact, old_raw, target_raw
            )

        move_index = next(
            index
            for index, event in enumerate(events)
            if event[0] == "rename"
            and event[3] == "install migration target projection"
        )
        self.assertEqual(
            events[move_index + 1 : move_index + 3],
            [("fsync", execution_directory), ("fsync", protected_directory)],
        )
        self.assertEqual(backup.read_bytes(), old_raw)
        self.assertEqual(execution.read_bytes(), target_raw)

    def test_post_rename_parent_swap_cannot_precede_durable_retention(self) -> None:
        source_directory = self.base / "rename-source"
        destination_directory = self.base / "rename-destination"
        detached_destination = self.base / "rename-destination-detached"
        outside = self.base / "rename-attacker"
        source_directory.mkdir()
        destination_directory.mkdir()
        outside.mkdir()
        source = source_directory / "source.entry"
        destination = destination_directory / "retained.entry"
        raw = b"retained transaction bytes\n"
        source.write_bytes(raw)
        source_ref = migration.open_directory_ref(source_directory, "rename source")
        destination_ref = migration.open_directory_ref(
            destination_directory, "rename destination"
        )
        original_fsync = migration.fsync_ref
        events = []
        injected = False

        def swap_after_destination_fsync(directory) -> None:
            nonlocal injected
            events.append(directory.path)
            original_fsync(directory)
            if directory is destination_ref and not injected:
                destination_directory.rename(detached_destination)
                destination_directory.symlink_to(outside, target_is_directory=True)
                injected = True

        try:
            with mock.patch.object(
                migration, "fsync_ref", side_effect=swap_after_destination_fsync
            ), self.assertRaisesRegex(
                migration.MigrationError, "rename destination pathname changed"
            ):
                migration.rename_no_replace(
                    source,
                    destination,
                    "retain transaction entry",
                    source_directory=source_ref,
                    destination_directory=destination_ref,
                )
        finally:
            destination_ref.close()
            source_ref.close()

        self.assertTrue(injected)
        self.assertEqual(events[:2], [destination_directory, source_directory])
        self.assertFalse(source.exists())
        self.assertEqual((detached_destination / destination.name).read_bytes(), raw)
        self.assertEqual(list(outside.iterdir()), [])

    def test_sealed_backup_requires_an_independent_inode(self) -> None:
        old_raw = b'{"generation":"old"}\n'
        target_raw = b'{"generation":"target"}\n'

        replay_root = self.base / "same-inode-replay"
        execution_directory = replay_root / "executions"
        protected_directory = replay_root / "protected"
        execution_directory.mkdir(parents=True)
        protected_directory.mkdir()
        execution = execution_directory / "execution.json"
        backup = protected_directory / "execution.backup"
        target_artifact = protected_directory / "execution.target"
        execution.write_bytes(old_raw)
        os.link(execution, backup)
        with self.assertRaisesRegex(migration.MigrationError, "must not share"):
            migration.install_execution_transaction(
                execution, backup, target_artifact, old_raw, target_raw
            )
        self.assertEqual(execution.read_bytes(), old_raw)
        self.assertEqual(backup.read_bytes(), old_raw)

        collision_root = self.base / "distinct-inode-collision"
        collision_execution_directory = collision_root / "executions"
        collision_protected_directory = collision_root / "protected"
        collision_execution_directory.mkdir(parents=True)
        collision_protected_directory.mkdir()
        collision_execution = collision_execution_directory / "execution.json"
        collision_backup = collision_protected_directory / "execution.backup"
        collision_target = collision_protected_directory / "execution.target"
        collision_execution.write_bytes(old_raw)
        collision_backup.write_bytes(old_raw)
        migration.install_execution_transaction(
            collision_execution,
            collision_backup,
            collision_target,
            old_raw,
            target_raw,
        )
        self.assertEqual(collision_execution.read_bytes(), target_raw)
        self.assertEqual(collision_backup.read_bytes(), old_raw)

    def test_consumed_receipt_recovers_crash_before_artifact_retirement(self) -> None:
        original_retire = migration.retire_transaction_artifact
        crashed = False

        def crash_before_retire(
            path: Path, raw: bytes, label: str, **kwargs
        ) -> None:
            nonlocal crashed
            if label == "protected legacy execution backup" and not crashed:
                crashed = True
                raise migration.MigrationError("simulated crash before backup retirement")
            original_retire(path, raw, label, **kwargs)

        with mock.patch.object(
            migration, "retire_transaction_artifact", side_effect=crash_before_retire
        ), self.assertRaisesRegex(
            migration.MigrationError, "simulated crash before backup retirement"
        ):
            self.migrate()

        prepared = self.lifecycle_root / "lineage-migrations" / "prepared"
        consumed = self.lifecycle_root / "lineage-migrations" / "consumed"
        backup = prepared / f".{self.request['id']}.execution-backup"
        target_artifact = prepared / f".{self.request['id']}.execution-target"
        self.assertTrue(next(consumed.glob("*.json")).is_file())
        self.assertTrue(backup.is_file())
        self.assertTrue(target_artifact.is_file())
        self.assertEqual(self.migrate(), "already-consumed")
        self.assertFalse(backup.exists())
        self.assertFalse(target_artifact.exists())
        self.assertFalse(self.control_path.exists())

    def test_consumed_phase_repairs_mutated_projection_from_sealed_target(self) -> None:
        original_store = migration.store_receipt
        corrupted = b'{"attacker":"post-target-check"}\n'
        observed_independent = False

        def mutate_after_consumed_receipt(path, unsigned, key, **kwargs):
            nonlocal observed_independent
            result = original_store(path, unsigned, key, **kwargs)
            if path.parent.name == "consumed":
                target_artifact = (
                    self.lifecycle_root / "lineage-migrations" / "prepared"
                    / f".{self.request['id']}.execution-target"
                )
                observed_independent = (
                    target_artifact.stat().st_ino != self.execution_path.stat().st_ino
                )
                self.execution_path.write_bytes(corrupted)
                self.assertNotEqual(target_artifact.read_bytes(), corrupted)
            return result

        with mock.patch.object(
            migration, "store_receipt", side_effect=mutate_after_consumed_receipt
        ):
            self.assertEqual(self.migrate(), "consumed")

        self.assertTrue(observed_independent)
        target = json.loads(self.execution_path.read_text())
        self.assertIn("claimLineage", target)
        self.assertNotEqual(self.execution_path.read_bytes(), corrupted)
        self.assertFalse(self.control_path.exists())

    def test_consumed_repair_retains_late_written_displaced_inode(self) -> None:
        original_store = migration.store_receipt
        original_rename = migration.rename_no_replace
        corrupted = b'{"attacker":"before-repair"}\n'
        late = b'{"attacker":"at-former-tombstone-unlink"}\n'
        writer = -1
        injected = False

        def corrupt_after_consumed_receipt(path, unsigned, key, **kwargs):
            nonlocal writer
            result = original_store(path, unsigned, key, **kwargs)
            if path.parent.name == "consumed" and writer < 0:
                writer = os.open(self.execution_path, os.O_RDWR)
                os.lseek(writer, 0, os.SEEK_SET)
                os.write(writer, corrupted)
                os.ftruncate(writer, len(corrupted))
                os.fsync(writer)
            return result

        def mutate_displaced_inode(
            source: Path, destination: Path, label: str, **kwargs
        ) -> None:
            nonlocal injected
            if label == "repair consumed migration target projection" and not injected:
                injected = True
                os.lseek(writer, 0, os.SEEK_SET)
                os.write(writer, late)
                os.ftruncate(writer, len(late))
                os.fsync(writer)
            original_rename(source, destination, label, **kwargs)

        try:
            with mock.patch.object(
                migration, "store_receipt", side_effect=corrupt_after_consumed_receipt
            ), mock.patch.object(
                migration, "rename_no_replace", side_effect=mutate_displaced_inode
            ):
                self.assertEqual(self.migrate(), "consumed")
        finally:
            if writer >= 0:
                os.close(writer)

        prepared = self.lifecycle_root / "lineage-migrations" / "prepared"
        tombstones = list(prepared.glob(".*.displaced.*"))
        self.assertTrue(injected)
        self.assertIn("claimLineage", json.loads(self.execution_path.read_text()))
        self.assertEqual([path.read_bytes() for path in tombstones], [late])

    def test_consumed_target_retires_stale_prepared_and_is_idempotent(self) -> None:
        source_bytes = self.control_path.read_bytes()
        self.assertEqual(self.migrate(), "consumed")
        consumed_dir = self.lifecycle_root / "lineage-migrations" / "consumed"
        prepared_dir = self.lifecycle_root / "lineage-migrations" / "prepared"
        receipt = next(consumed_dir.iterdir())
        consumed = json.loads(receipt.read_text())
        prepared = dict(consumed); prepared.pop("auth"); prepared["phase"] = "prepared"
        migration.store_receipt(prepared_dir / receipt.name, prepared, b"k" * 32)
        self.control_path.write_bytes(source_bytes)
        self.tasks["tasks"][1]["revision"] = "irrelevant-later-revision"
        self.assertEqual(self.migrate(), "already-consumed")
        self.assertFalse((prepared_dir / receipt.name).exists())
        self.assertFalse(self.control_path.exists())

    def test_pre_consume_path_replacement_cannot_change_archived_control(self) -> None:
        authenticated_raw = self.control_path.read_bytes()
        raced_raw = b"{raced-pending-pathname\n"
        original_consume = migration.consume_control
        injected = False

        def replace_before_consume(source: Path, *arguments) -> None:
            nonlocal injected
            replacement = source.with_name(f".{source.name}.racer")
            replacement.write_bytes(raced_raw)
            os.replace(replacement, source)
            injected = True
            original_consume(source, *arguments)

        with mock.patch.object(
            migration, "consume_control", side_effect=replace_before_consume
        ):
            self.assertEqual(self.migrate(), "consumed")

        consumed = self.workspace / "lineage-migration-outbox" / "consumed"
        rejected = self.workspace / "lineage-migration-outbox" / "rejected"
        self.assertTrue(injected)
        self.assertEqual((consumed / self.control_path.name).read_bytes(), authenticated_raw)
        self.assertIn(raced_raw, [path.read_bytes() for path in rejected.iterdir()])
        self.assertFalse(self.control_path.exists())

    def test_control_write_after_retirement_compare_is_retained(self) -> None:
        authenticated_raw = self.control_path.read_bytes()
        raced_raw = b'{"attacker":"at-former-control-unlink"}\n'
        original_read = migration.regular_bytes_at
        writer = os.open(self.control_path, os.O_RDWR)
        injected = False

        def mutate_after_comparison(directory, name, label, maximum=1024 * 1024):
            nonlocal injected
            result = original_read(directory, name, label, maximum)
            if label == "retired migration control" and not injected:
                injected = True
                os.lseek(writer, 0, os.SEEK_SET)
                os.write(writer, raced_raw)
                os.ftruncate(writer, len(raced_raw))
                os.fsync(writer)
            return result

        try:
            with mock.patch.object(
                migration, "regular_bytes_at", side_effect=mutate_after_comparison
            ):
                self.assertEqual(self.migrate(), "consumed")
        finally:
            os.close(writer)

        consumed = self.workspace / "lineage-migration-outbox" / "consumed"
        rejected = self.workspace / "lineage-migration-outbox" / "rejected"
        tombstones = list(rejected.glob("retiring-*.tombstone"))
        self.assertTrue(injected)
        self.assertEqual((consumed / self.control_path.name).read_bytes(), authenticated_raw)
        self.assertEqual([path.read_bytes() for path in tombstones], [raced_raw])
        self.assertFalse(self.control_path.exists())

    def test_post_consumed_receipt_unlink_preserves_exact_control_recovery(self) -> None:
        authenticated_raw = self.control_path.read_bytes()
        original_store = migration.store_receipt
        injected = False

        def unlink_after_consumed_receipt(path, unsigned, key, **kwargs):
            nonlocal injected
            result = original_store(path, unsigned, key, **kwargs)
            if path.parent.name == "consumed" and not injected:
                self.control_path.unlink()
                injected = True
            return result

        with mock.patch.object(
            migration, "store_receipt", side_effect=unlink_after_consumed_receipt
        ):
            self.assertEqual(self.migrate(), "consumed")

        consumed = self.workspace / "lineage-migration-outbox" / "consumed"
        self.assertTrue(injected)
        self.assertEqual((consumed / self.control_path.name).read_bytes(), authenticated_raw)
        self.assertFalse(self.control_path.exists())

    def test_transaction_lock_detects_racing_execution_writer(self) -> None:
        lock_path = self.workspace / "executions" / f".{self.key}.transaction.lock"
        held = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(held, fcntl.LOCK_EX)
        errors = []

        def run() -> None:
            try:
                self.migrate()
            except Exception as exc:  # the asserted fail-closed result
                errors.append(exc)

        thread = threading.Thread(target=run)
        thread.start()
        time.sleep(0.1)
        mutated = dict(self.execution); mutated["updatedAt"] = "racing-writer"
        self.execution_path.write_text(json.dumps(mutated) + "\n", encoding="utf-8")
        fcntl.flock(held, fcntl.LOCK_UN); os.close(held)
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertRegex(str(errors[0]), "changed after Team Lead staging")
        self.assertNotIn("claimLineage", json.loads(self.execution_path.read_text()))

    def test_canonical_key_branch_and_mixed_lineage_fail(self) -> None:
        for field, value, message in (
            ("taskKey", "forged-key", "non-canonical task key"),
            ("branch", "agent-task/other/branch", "non-canonical task branch"),
        ):
            with self.subTest(field=field):
                changed = dict(self.request); changed[field] = value
                changed["controlBodySha256"] = migration.digest(
                    migration.canonical(migration.request_body(changed))
                )
                path = self.control_path.with_name("control-" + hashlib.sha256(field.encode()).hexdigest()[:32] + ".json")
                changed["id"] = path.stem
                changed["controlBodySha256"] = migration.digest(
                    migration.canonical(migration.request_body(changed))
                )
                path.write_bytes(migration.canonical(changed) + b"\n")
                patches = self.patches()
                for patch in patches: patch.start()
                try:
                    with self.assertRaisesRegex(migration.MigrationError, message):
                        migration.migrate_one(
                            self.repository, self.workspace, self.lifecycle_root,
                            self.tasks, path,
                        )
                finally:
                    for patch in reversed(patches): patch.stop()

    def test_current_verdicts_use_bound_authorization_task(self) -> None:
        comments = []
        roles = self.roles
        actors = {
            "product-approval": roles["PRODUCT_MANAGER"],
            "design-approved": roles["PRINCIPAL_ARCHITECT"],
            "sceptical-design-approved": roles["SCEPTICAL_ARCHITECT"],
        }
        for index, marker in enumerate(actors, 1):
            delivery = f"delivery-{index:032x}"
            body = f"[{marker}]\nround: {index}\nverdict: approved\n"
            body_path = self.workspace / "outbox" / "staged" / f"{delivery}.publish.md"
            body_path.write_text(body, encoding="utf-8")
            entry = {
                "schemaVersion": 1, "id": f"entry-{index}", "team": self.team,
                "featureId": self.feature, "taskId": self.authorization_task,
                "attempt": 1, "actor": actors[marker], "marker": marker,
                "targetStatus": None, "createdAt": "2026-09-01T00:00:00Z",
                "phase": "published", "deliveryId": delivery,
                "publishBodyPath": str(body_path),
                "publishBodySha256": migration.digest(body.encode()),
                "producerCapability": {},
            }
            (self.workspace / "outbox" / "done" / f"entry-{index}.json").write_text(
                json.dumps(entry), encoding="utf-8"
            )
            comments.append({"body": body.rstrip("\n") + f"\n\ndelivery-id: {delivery}"})
        comments[-1]["body"] = comments[-1]["body"].replace(
            "[sceptical-design-approved]",
            "[sceptical-design-approved] (2026-09-01): ",
            1,
        )
        auth_task = self.task(self.authorization_task, "Active", "auth-r1", comments)
        request = dict(self.request)
        with mock.patch.object(
            migration, "verify_published_entry",
            side_effect=lambda _r, _w, entry, _d, **_kwargs: {
                "executionKind": "gate", "role": entry["actor"]
            },
        ), mock.patch.object(
            migration, "published_receipt_digest",
            return_value={"sha256": "sha256:" + "9" * 64, "publishedDate": "2026-09-01"},
        ):
            verdicts = migration.current_verdicts(
                self.repository, self.workspace, request, auth_task, roles
            )
        self.assertEqual([item["family"] for item in verdicts], ["product", "principal", "sceptical"])
        self.assertTrue(all(item["deliveryId"].startswith("delivery-") for item in verdicts))

    def test_markdown_adapter_date_allows_only_timezone_boundary(self) -> None:
        marker = "sceptical-design-approved"
        delivery = "delivery-" + "a" * 32
        published = f"[{marker}]\nround: 6\nverdict: approved\n"
        for decorated_date in ("2026-08-31", "2026-09-01", "2026-09-02"):
            with self.subTest(accepted=decorated_date):
                tracker = (
                    f"[{marker}] ({decorated_date}): \nround: 6\nverdict: approved"
                    f"\n\ndelivery-id: {delivery}"
                )
                self.assertTrue(
                    migration.markdown_tracker_body_matches(
                        tracker, published, marker, delivery, "2026-09-01"
                    )
                )
        for decorated_date in ("2026-08-30", "2026-09-03", "2026-02-30"):
            with self.subTest(rejected=decorated_date):
                tracker = (
                    f"[{marker}] ({decorated_date}): \nround: 6\nverdict: approved"
                    f"\n\ndelivery-id: {delivery}"
                )
                self.assertFalse(
                    migration.markdown_tracker_body_matches(
                        tracker, published, marker, delivery, "2026-09-01"
                    )
                )

    def test_claim_two_later_execution_preserves_claim_generation(self) -> None:
        claim_target = "Active"
        claim_id = "dispatch-" + hashlib.sha256(
            "\0".join(
                (self.team, self.feature, self.target_task, self.role, "2", claim_target)
            ).encode()
        ).hexdigest()[:32]
        identity = {
            "schemaVersion": 1, "team": self.team, "featureId": self.feature,
            "taskId": self.target_task, "taskKey": self.key, "attempt": 2,
            "role": self.role, "claimId": claim_id, "targetStatus": claim_target,
        }
        self.claim = {
            **identity, "claimDigest": migration.digest(migration.canonical(identity)),
            "recordedAt": "2026-08-02T00:00:00Z",
        }
        self.claim_path.write_text(json.dumps(self.claim) + "\n", encoding="utf-8")
        self.tasks["tasks"][0]["comments"].append(
            {
                "body": (
                    f"[claim]\nclaim-id: {claim_id}\nrole: {self.role}\n"
                    f"target-status: {claim_target}\n\n— dispatcher"
                )
            }
        )
        self.reset_request()
        self.assertEqual(self.migrate(), "consumed")
        target = json.loads(self.execution_path.read_text())
        self.assertEqual(target["attempt"], 34)
        self.assertEqual(target["claimLineage"]["claimAttempt"], 2)

    def test_post_migration_claim_rollover_and_packet_attempt_35(self) -> None:
        claim_one_bytes = self.claim_path.read_bytes()
        claim_one_digest = self.claim["claimDigest"]
        self.assertEqual(self.migrate(), "consumed")

        tasks_path = self.workspace / "tasks.json"
        team_config = self.repository / "team.config.md"
        team_config.write_text("VALIDATE_TEST=null\n", encoding="utf-8")
        target_task = self.tasks["tasks"][0]
        target_task.update(
            title="Continue migrated work",
            description="Task 7 shaped rework fixture",
            blockedBy=[],
        )
        tasks_path.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        next_attempt = 35
        next_claim_id = "dispatch-" + hashlib.sha256(
            "\0".join(
                (
                    self.team,
                    self.feature,
                    self.target_task,
                    self.role,
                    str(next_attempt),
                    "Active",
                )
            ).encode()
        ).hexdigest()[:32]

        def runtime(*arguments: str, environment: dict | None = None) -> dict:
            result = subprocess.run(
                ["python3", str(ROOT / "bin" / "runtime-state.py"), *arguments],
                cwd=self.repository,
                env={**os.environ, **(environment or {})},
                text=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return json.loads(result.stdout)

        next_claim = runtime(
            "claim",
            "--workspace", str(self.workspace),
            "--repo", str(self.repository),
            "--team", self.team,
            "--feature", self.feature,
            "--task", self.target_task,
            "--role", self.role,
            "--attempt", str(next_attempt),
            "--claim-id", next_claim_id,
            "--target", "Active",
        )
        target_task["status"] = "Active"
        target_task["assignee"] = self.role
        target_task["comments"].append(
            {
                "body": (
                    f"[claim]\nclaim-id: {next_claim_id}\nrole: {self.role}\n"
                    "target-status: Active\n\n— dispatcher"
                )
            }
        )
        tasks_path.write_text(json.dumps(self.tasks) + "\n", encoding="utf-8")
        next_worktree = (
            self.workspace / "worktrees"
            / f"{self.role}#{next_attempt}-{self.key}"
        )
        runtime(
            "packet",
            "--workspace", str(self.workspace),
            "--tasks", str(tasks_path),
            "--team", self.team,
            "--feature", self.feature,
            "--task", self.target_task,
            "--role", self.role,
            "--attempt", str(next_attempt),
            "--worktree", str(next_worktree),
            "--branch", self.branch,
            "--config", str(team_config),
            "--contracts", str(self.workspace / "CONTRACTS.md"),
            "--baseline", str(self.workspace / "BASELINE.md"),
            "--repo", str(self.repository),
        )

        target = json.loads(self.execution_path.read_text())
        self.assertEqual(target["attempt"], 35)
        self.assertEqual(target["claimLineage"]["claimAttempt"], 35)
        self.assertEqual(target["claimLineage"]["claimDigest"], next_claim["claimDigest"])
        history = (
            self.workspace / "claims" / "history"
            / f"{self.key}-a1-rework.json"
        )
        self.assertEqual(history.read_bytes(), claim_one_bytes)
        self.assertEqual(json.loads(history.read_text())["claimDigest"], claim_one_digest)

    def test_duplicate_key_json_fails_before_receipt_or_mutation(self) -> None:
        cases = (
            (
                self.execution_path,
                self.execution_path.read_text().rstrip()[:-1]
                + ',"updatedAt":"duplicate"}\n',
                "repeats field updatedAt",
            ),
            (
                self.claim_path,
                self.claim_path.read_text().rstrip()[:-1]
                + ',"claimDigest":"sha256:' + "0" * 64 + '"}\n',
                "repeats field claimDigest",
            ),
        )
        for path, raw, message in cases:
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_text(raw, encoding="utf-8")
                self.reset_request()
                with self.assertRaisesRegex(migration.MigrationError, message):
                    self.migrate()
                self.assertEqual(
                    list((self.lifecycle_root / "lineage-migrations" / "prepared").glob("*.json")),
                    [],
                )
                path.write_bytes(original)

    def test_staged_state_drift_and_symlink_fail_closed(self) -> None:
        original_execution = self.execution_path.read_bytes()
        original_packet = self.packet.read_bytes()
        original_report = self.report.read_bytes()
        cases = []
        cases.append(("tracker status", lambda: self.tasks["tasks"][0].update(status="Active"), "tracker revision/status changed"))
        cases.append(("tracker revision", lambda: self.tasks["tasks"][0].update(revision="target-r2"), "tracker revision/status changed"))
        cases.append(("packet", lambda: self.packet.write_text("changed\n", encoding="utf-8"), "packet changed"))
        cases.append(("report", lambda: self.report.write_text("changed report\n", encoding="utf-8"), "report changed"))
        cases.append(("head", lambda: subprocess.run(
            ["git", "-C", str(self.worktree), "commit", "--allow-empty", "-qm", "later"], check=True
        ), "HEAD changed"))
        for name, mutate, message in cases:
            with self.subTest(name=name):
                mutate()
                with self.assertRaisesRegex(migration.MigrationError, message):
                    self.migrate()
                self.assertNotIn("claimLineage", json.loads(self.execution_path.read_text()))
                self.tasks["tasks"][0].update(status="Planned", revision="target-r1")
                self.packet.write_bytes(original_packet)
                self.report.write_bytes(original_report)
                subprocess.run(["git", "-C", str(self.worktree), "reset", "--hard", "-q", self.head], check=True)
        self.execution_path.unlink()
        os.symlink(self.claim_path, self.execution_path)
        with self.assertRaisesRegex(migration.MigrationError, "non-symlink regular file"):
            self.migrate()
        self.execution_path.unlink(); self.execution_path.write_bytes(original_execution)

    def test_pinned_claims_parent_rejects_temporary_exact_snapshot(self) -> None:
        exact_claim = self.claim_path.read_bytes()
        drifted = dict(self.claim)
        drifted["recordedAt"] = "2026-08-02T00:00:00Z"
        self.claim_path.write_bytes(migration.canonical(drifted) + b"\n")
        claims = self.claim_path.parent
        detached = claims.with_name("claims-current-detached")
        staged = claims.with_name("claims-staged-exact")
        staged.mkdir()
        (staged / self.claim_path.name).write_bytes(exact_claim)
        original_open = migration.open_child_directory_ref
        injected = False

        def swap_during_pin(parent, name, label, **kwargs):
            nonlocal injected
            if name == "claims" and parent.path == self.workspace and not injected:
                claims.rename(detached)
                staged.rename(claims)
                try:
                    result = original_open(parent, name, label, **kwargs)
                finally:
                    claims.rename(staged)
                    detached.rename(claims)
                injected = True
                return result
            return original_open(parent, name, label, **kwargs)

        before = self.execution_path.read_bytes()
        with mock.patch.object(
            migration, "open_child_directory_ref", side_effect=swap_during_pin
        ), self.assertRaisesRegex(
            migration.MigrationError, "claims directory pathname changed"
        ):
            self.migrate()

        self.assertTrue(injected)
        self.assertEqual(self.execution_path.read_bytes(), before)
        self.assertEqual(
            list((self.lifecycle_root / "lineage-migrations" / "prepared").glob("*.json")),
            [],
        )

    def test_registry_and_packet_exact_leaf_swaps_fail_snapshot_revalidation(self) -> None:
        cases = (
            (
                self.workspace / "CONTRACTS.md",
                "lineage migration registry",
                2,
                b"# Contracts\n\nrevoked\n",
                "registry changed after exact state snapshot",
            ),
            (
                self.packet,
                "legacy task packet",
                1,
                b"drifted packet\n",
                "task packet changed after exact state snapshot",
            ),
        )
        for target, label, exact_reads, drifted, message in cases:
            with self.subTest(label=label):
                exact = target.read_bytes()
                target.write_bytes(drifted)
                staged = target.with_name(f".{target.name}.staged-exact")
                current = target.with_name(f".{target.name}.current-drift")
                staged.write_bytes(exact)
                original_read = migration.regular_bytes_at
                reads = 0

                def temporary_exact(
                    directory, name, observed_label, maximum=2 * 1024 * 1024
                ):
                    nonlocal reads
                    selected = directory.path / name == target and observed_label == label
                    if selected and reads == 0:
                        os.replace(target, current)
                        os.replace(staged, target)
                    result = original_read(directory, name, observed_label, maximum)
                    if selected:
                        reads += 1
                        if reads == exact_reads:
                            os.replace(target, staged)
                            os.replace(current, target)
                    return result

                try:
                    with mock.patch.object(
                        migration, "regular_bytes_at", side_effect=temporary_exact
                    ), self.assertRaisesRegex(migration.MigrationError, message):
                        self.migrate()
                finally:
                    if current.exists():
                        if target.exists():
                            target.unlink()
                        os.replace(current, target)
                    target.write_bytes(exact)
                    staged.unlink(missing_ok=True)
                self.assertEqual(reads, exact_reads + 1)
                self.assertNotIn(
                    "claimLineage", json.loads(self.execution_path.read_text())
                )

    def test_real_reconcile_revalidates_retained_tasks_snapshot(self) -> None:
        tasks_path = self.workspace / "tasks.json"
        exact_tasks = json.loads(json.dumps(self.tasks))
        exact_raw = migration.canonical(exact_tasks) + b"\n"
        drifted_tasks = json.loads(json.dumps(self.tasks))
        drifted_tasks["tasks"][1].update(status="Active", revision="auth-r2")
        tasks_path.write_bytes(migration.canonical(drifted_tasks) + b"\n")
        staged = tasks_path.with_name(".tasks.json.staged-exact")
        current = tasks_path.with_name(".tasks.json.current-drift")
        staged.write_bytes(exact_raw)
        original_read = migration.regular_bytes_at
        injected = False

        def stage_only_for_initial_read(
            directory, name, label, maximum=2 * 1024 * 1024
        ):
            nonlocal injected
            if label == "fresh task snapshot" and not injected:
                os.replace(tasks_path, current)
                os.replace(staged, tasks_path)
                try:
                    return original_read(directory, name, label, maximum)
                finally:
                    os.replace(tasks_path, staged)
                    os.replace(current, tasks_path)
                    injected = True
            return original_read(directory, name, label, maximum)

        args = argparse.Namespace(
            repo=str(self.repository),
            workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root),
            team=self.team,
            feature=self.feature,
            tasks=str(tasks_path),
        )
        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(
                migration, "regular_bytes_at", side_effect=stage_only_for_initial_read
            ):
                self.assertEqual(migration.reconcile(args), 0)
        finally:
            for patch in reversed(patches):
                patch.stop()

        self.assertTrue(injected)
        self.assertTrue(self.control_path.exists())
        self.assertNotIn("claimLineage", json.loads(self.execution_path.read_text()))
        self.assertEqual(
            list((self.lifecycle_root / "lineage-migrations" / "prepared").glob("*.json")),
            [],
        )

    def test_worktree_head_is_rechecked_from_retained_directory(self) -> None:
        subprocess.run(
            ["git", "-C", str(self.worktree), "commit", "--allow-empty", "-qm", "drift"],
            check=True,
        )
        drifted_head = subprocess.run(
            ["git", "-C", str(self.worktree), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        original_git = migration.git_value
        calls = 0

        def temporary_staged_head(worktree, *arguments, directory=None):
            nonlocal calls
            if calls == 0:
                subprocess.run(
                    ["git", "-C", str(self.worktree), "reset", "--hard", "-q", self.head],
                    check=True,
                )
            result = original_git(
                worktree, *arguments, directory=directory
            )
            calls += 1
            if calls == 4:
                subprocess.run(
                    [
                        "git", "-C", str(self.worktree), "reset", "--hard", "-q",
                        drifted_head,
                    ],
                    check=True,
                )
            return result

        try:
            with mock.patch.object(
                migration, "git_value", side_effect=temporary_staged_head
            ), self.assertRaisesRegex(
                migration.MigrationError, "worktree HEAD changed"
            ):
                self.migrate()
        finally:
            subprocess.run(
                ["git", "-C", str(self.worktree), "reset", "--hard", "-q", self.head],
                check=True,
            )

        self.assertGreater(calls, 4)
        self.assertNotIn("claimLineage", json.loads(self.execution_path.read_text()))

    def test_execution_lock_replacement_is_detected_before_prepare(self) -> None:
        original_contract = migration.registered_contract
        lock_path = (
            self.workspace / "executions" / f".{self.key}.transaction.lock"
        )
        detached = lock_path.with_name(f".{lock_path.name}.detached")
        injected = False

        def replace_after_lock(*args, **kwargs):
            nonlocal injected
            result = original_contract(*args, **kwargs)
            if not injected:
                lock_path.rename(detached)
                lock_path.write_bytes(b"")
                lock_path.chmod(0o600)
                injected = True
            return result

        with mock.patch.object(
            migration, "registered_contract", side_effect=replace_after_lock
        ), self.assertRaisesRegex(
            migration.MigrationError, "execution transaction lock changed identity"
        ):
            self.migrate()

        self.assertTrue(injected)
        self.assertNotIn("claimLineage", json.loads(self.execution_path.read_text()))
        self.assertEqual(
            list((self.lifecycle_root / "lineage-migrations" / "prepared").glob("*.json")),
            [],
        )

    def test_required_verdict_membership_is_revalidated(self) -> None:
        authorization_task, entries = self.verdict_fixture()
        snapshot = migration.ExactStateSnapshot(self.tasks, [], [])
        try:
            with mock.patch.object(
                migration,
                "verify_published_entry",
                side_effect=lambda _r, _w, entry, _d, **_kwargs: {
                    "executionKind": "gate", "role": entry["actor"]
                },
            ), mock.patch.object(
                migration,
                "published_receipt_digest",
                return_value={
                    "sha256": "sha256:" + "9" * 64,
                    "publishedDate": "2026-09-01",
                },
            ):
                migration.current_verdicts(
                    self.repository,
                    self.workspace,
                    self.request,
                    authorization_task,
                    self.roles,
                    snapshot=snapshot,
                )
            duplicate = self.workspace / "outbox" / "done" / "duplicate-product.json"
            duplicate.write_bytes(entries[0][0].read_bytes())
            with self.assertRaisesRegex(
                migration.MigrationError, "publication membership changed"
            ):
                snapshot.validate()
        finally:
            snapshot.close()

    def test_fifo_and_nonregular_pending_entries_do_not_block_safe_control(self) -> None:
        tasks_path = self.workspace / "tasks.json"
        tasks_path.write_bytes(migration.canonical(self.tasks) + b"\n")
        pending = self.control_path.parent
        fifo = pending / ("control-" + "0" * 32 + ".json")
        nonregular = pending / ("control-" + "1" * 32 + ".json")
        os.mkfifo(fifo, 0o600)
        nonregular.mkdir()
        args = argparse.Namespace(
            repo=str(self.repository), workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root), team=self.team,
            feature=self.feature, tasks=str(tasks_path),
        )
        patches = list(self.patches())
        for patch in patches:
            patch.start()
        try:
            started = time.monotonic()
            self.assertEqual(migration.reconcile(args), 0)
            self.assertLess(time.monotonic() - started, 2.0)
        finally:
            for patch in reversed(patches):
                patch.stop()

        rejected = self.workspace / "lineage-migration-outbox" / "rejected"
        rejected_modes = [
            path.lstat().st_mode for path in rejected.glob("rejected-*.entry")
        ]
        self.assertTrue(any(stat.S_ISFIFO(mode) for mode in rejected_modes))
        self.assertTrue(any(stat.S_ISDIR(mode) for mode in rejected_modes))
        self.assertFalse(self.control_path.exists())
        self.assertIn("claimLineage", json.loads(self.execution_path.read_text()))

    def test_lifecycle_drift_and_expiry_fail_before_prepare(self) -> None:
        before = self.execution_path.read_bytes()
        patches = list(self.patches())
        patches[-1] = mock.patch.object(
            migration, "lifecycle_generation",
            side_effect=migration.MigrationError("protected lifecycle generation changed"),
        )
        for patch in patches: patch.start()
        try:
            with self.assertRaisesRegex(migration.MigrationError, "lifecycle generation changed"):
                migration.migrate_one(
                    self.repository, self.workspace, self.lifecycle_root,
                    self.tasks, self.control_path,
                )
        finally:
            for patch in reversed(patches): patch.stop()
        self.assertEqual(self.execution_path.read_bytes(), before)
        self.request["createdAt"] = int(time.time()) - 400
        self.request["expiresAt"] = int(time.time()) - 100
        self.request["controlBodySha256"] = migration.digest(
            migration.canonical(migration.request_body(self.request))
        )
        self.write_request()
        with self.assertRaisesRegex(migration.MigrationError, "expired"):
            self.migrate()
        self.assertEqual(self.execution_path.read_bytes(), before)

    def test_consumed_receipt_cannot_replay_across_task(self) -> None:
        source = self.control_path.read_bytes()
        self.assertEqual(self.migrate(), "consumed")
        forged = json.loads(source)
        forged["taskId"] = self.other_task
        forged["controlBodySha256"] = migration.digest(
            migration.canonical(migration.request_body(forged))
        )
        self.control_path.write_bytes(migration.canonical(forged) + b"\n")
        with self.assertRaisesRegex(migration.MigrationError, "receipt is cross-bound"):
            self.migrate()

    def verdict_fixture(self):
        comments = []
        entries = []
        specs = (
            ("product-approval", self.roles["PRODUCT_MANAGER"], 4),
            ("design-approved", self.roles["PRINCIPAL_ARCHITECT"], 3),
            ("sceptical-design-approved", self.roles["SCEPTICAL_ARCHITECT"], 4),
        )
        for index, (marker, actor, round_number) in enumerate(specs, 11):
            delivery = f"delivery-{index:032x}"
            body = f"[{marker}]\nround: {round_number}\nverdict: approved\n"
            body_path = self.workspace / "outbox" / "staged" / f"{delivery}.publish.md"
            body_path.write_text(body, encoding="utf-8")
            entry = {
                "schemaVersion": 1, "id": f"entry-{index}", "team": self.team,
                "featureId": self.feature, "taskId": self.authorization_task,
                "attempt": 1, "actor": actor, "marker": marker,
                "targetStatus": None, "createdAt": "2026-09-01T00:00:00Z",
                "phase": "published", "deliveryId": delivery,
                "publishBodyPath": str(body_path),
                "publishBodySha256": migration.digest(body.encode()),
                "producerCapability": {},
            }
            path = self.workspace / "outbox" / "done" / f"entry-{index}.json"
            path.write_text(json.dumps(entry), encoding="utf-8")
            comments.append({"body": body.rstrip("\n") + f"\n\ndelivery-id: {delivery}"})
            entries.append((path, entry, body_path))
        return self.task(self.authorization_task, "Active", "auth-r1", comments), entries

    def test_verdict_lookup_ignores_unrelated_malformed_done_entry(self) -> None:
        auth_task, _ = self.verdict_fixture()
        (self.workspace / "outbox" / "done" / "unrelated.json").write_bytes(
            b"{malformed-unrelated-history\n"
        )
        with mock.patch.object(
            migration,
            "verify_published_entry",
            side_effect=lambda _r, _w, entry, _d, **_kwargs: {
                "executionKind": "gate", "role": entry["actor"]
            },
        ), mock.patch.object(
            migration,
            "published_receipt_digest",
            return_value={
                "sha256": "sha256:" + "9" * 64,
                "publishedDate": "2026-09-01",
            },
        ):
            verdicts = migration.current_verdicts(
                self.repository,
                self.workspace,
                self.request,
                auth_task,
                self.roles,
            )
        self.assertEqual(len(verdicts), 3)

    def test_verdict_lookup_rejects_oversized_done_history_boundedly(self) -> None:
        auth_task, _ = self.verdict_fixture()
        with mock.patch.object(
            migration, "MAX_VERDICT_ENTRIES", 2
        ), self.assertRaisesRegex(
            migration.MigrationError, "bounded lookup limit"
        ):
            migration.current_verdicts(
                self.repository,
                self.workspace,
                self.request,
                auth_task,
                self.roles,
            )

    def test_verdict_publication_fail_closed_matrix(self) -> None:
        auth_task, entries = self.verdict_fixture()
        base_comments = json.loads(json.dumps(auth_task["comments"]))
        cases = []
        cases.append(("missing family", lambda: auth_task["comments"].pop(), "sceptical verdict is absent", None))
        cases.append(("latest pushback", lambda: auth_task["comments"].append({"body": "[design-pushback]\nround: 4\n\ndelivery-id: delivery-" + "f" * 32}), "principal verdict is a pushback", None))
        cases.append(("malformed trailer", lambda: auth_task["comments"].__setitem__(0, {"body": auth_task["comments"][0]["body"].replace("delivery-id:", "Delivery-ID:")}), "malformed broker provenance", None))
        cases.append(("missing evidence", lambda: None, "publication evidence missing", migration.MigrationError("publication evidence missing")))
        cases.append(("forged owner", lambda: None, "wrong authenticated owner", {"executionKind": "gate", "role": "attacker-role"}))
        for name, mutate, message, special in cases:
            with self.subTest(name=name):
                auth_task["comments"] = json.loads(json.dumps(base_comments))
                mutate()
                verify_result = special if isinstance(special, dict) else None
                evidence = special if isinstance(special, Exception) else None
                with mock.patch.object(
                    migration, "verify_published_entry",
                    return_value=verify_result or {"executionKind": "gate", "role": entries[0][1]["actor"]},
                    side_effect=None,
                ) as verifier, mock.patch.object(
                    migration, "published_receipt_digest",
                    side_effect=evidence,
                    return_value={"sha256": "sha256:" + "9" * 64, "publishedDate": "2026-09-01"},
                ):
                    if name != "forged owner":
                        verifier.side_effect = lambda _r, _w, entry, _d, **_kwargs: {
                            "executionKind": "gate", "role": entry["actor"]
                        }
                    with self.assertRaisesRegex(migration.MigrationError, message):
                        migration.current_verdicts(
                            self.repository, self.workspace, self.request,
                            auth_task, self.roles,
                        )

    def test_duplicate_or_malformed_verdict_metadata_and_delivery_fail(self) -> None:
        auth_task, entries = self.verdict_fixture()
        path, entry, body_path = entries[0]
        base_body = body_path.read_text()
        for name, body, message in (
            ("duplicate round", base_body + "round: 99\n", "round/supersession metadata is ambiguous"),
            (
                "duplicate supersession",
                base_body + "supersedes: product-pushback-2\nsupersedes: product-approval-3\n",
                "round/supersession metadata is ambiguous",
            ),
        ):
            with self.subTest(name=name):
                body_path.write_text(body, encoding="utf-8")
                entry["publishBodySha256"] = migration.digest(body.encode())
                path.write_text(json.dumps(entry), encoding="utf-8")
                auth_task["comments"][0]["body"] = body.rstrip("\n") + f"\n\ndelivery-id: {entry['deliveryId']}"
                with mock.patch.object(
                    migration, "verify_published_entry",
                    side_effect=lambda _r, _w, item, _d, **_kwargs: {"executionKind": "gate", "role": item["actor"]},
                ), mock.patch.object(
                    migration, "published_receipt_digest",
                    return_value={"sha256": "sha256:" + "9" * 64, "publishedDate": "2026-09-01"},
                ), self.assertRaisesRegex(migration.MigrationError, message):
                    migration.current_verdicts(
                        self.repository, self.workspace, self.request,
                        auth_task, self.roles,
                    )
                body_path.write_text(base_body, encoding="utf-8")
                entry["publishBodySha256"] = migration.digest(base_body.encode())
                path.write_text(json.dumps(entry), encoding="utf-8")
                auth_task["comments"][0]["body"] = base_body.rstrip("\n") + f"\n\ndelivery-id: {entry['deliveryId']}"
        duplicate = self.workspace / "outbox" / "done" / "duplicate.json"
        duplicate.write_text(json.dumps(entry), encoding="utf-8")
        with self.assertRaisesRegex(migration.MigrationError, "absent or ambiguous"), mock.patch.object(
            migration, "verify_published_entry"
        ), mock.patch.object(migration, "published_receipt_digest"):
            migration.current_verdicts(
                self.repository, self.workspace, self.request, auth_task, self.roles
            )

    def test_current_verdict_requires_exact_supersession_chain(self) -> None:
        auth_task, entries = self.verdict_fixture()
        current = auth_task["comments"][0]
        prior = {
            "body": "[product-pushback]\nround: 3\nverdict: revise\n\n"
            "delivery-id: delivery-" + "e" * 32
        }
        auth_task["comments"].insert(0, prior)
        path, entry, body_path = entries[0]
        body = body_path.read_text().replace(
            "round: 4\n", "round: 4\nsupersedes: product-approval-3\n"
        )
        body_path.write_text(body, encoding="utf-8")
        entry["publishBodySha256"] = migration.digest(body.encode())
        path.write_text(json.dumps(entry), encoding="utf-8")
        current["body"] = body.rstrip("\n") + f"\n\ndelivery-id: {entry['deliveryId']}"
        with mock.patch.object(
            migration, "verify_published_entry",
            side_effect=lambda _r, _w, item, _d, **_kwargs: {
                "executionKind": "gate", "role": item["actor"]
            },
        ), mock.patch.object(
            migration, "published_receipt_digest",
            return_value={"sha256": "sha256:" + "9" * 64, "publishedDate": "2026-09-01"},
        ), self.assertRaisesRegex(
            migration.MigrationError, "does not canonically supersede"
        ):
            migration.current_verdicts(
                self.repository, self.workspace, self.request, auth_task, self.roles
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
