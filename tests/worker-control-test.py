#!/usr/bin/env python3
"""Focused authorization, CAS, and idempotency tests for worker control."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

CONTROL_SPEC = importlib.util.spec_from_file_location(
    "worker_control", ROOT / "bin" / "worker-control.py"
)
assert CONTROL_SPEC and CONTROL_SPEC.loader
worker_control = importlib.util.module_from_spec(CONTROL_SPEC)
CONTROL_SPEC.loader.exec_module(worker_control)

from outbox_capability import mint, sign_entry  # noqa: E402


class WorkerControlTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS exposes temporary roots through /var -> /private/var. Production
        # correctly requires canonical non-symlink paths, so fixtures do too.
        self.root = Path(self.temp.name).resolve()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(self.repository)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.workspace = self.repository / ".teamwork" / "control-team"
        self.workspace.mkdir(parents=True)
        self.lifecycle_root = self.root / "lifecycle"
        self.lifecycle_root.mkdir(mode=0o700)
        self.fixture_skill = self.root / "fixture-skill"
        self.fixture_bin = self.fixture_skill / "bin"
        self.fixture_config = self.fixture_skill / "config"
        self.fixture_bin.mkdir(parents=True)
        self.fixture_config.mkdir()
        self.launcher = self.fixture_bin / "launch-team.sh"
        self.launcher.write_text(
            """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

record = {
    "argv": sys.argv[1:],
    "broker": os.environ.get("STARTUP_FACTORY_CONTROL_BROKER"),
    "controlReason": os.environ.get("STARTUP_FACTORY_CONTROL_REASON"),
    "lifecycleRoot": os.environ.get("STARTUP_FACTORY_LIFECYCLE_STATE_ROOT"),
    "expectedCreatedAt": os.environ.get("STARTUP_FACTORY_EXPECTED_LIFECYCLE_CREATED_AT"),
}
with Path(os.environ["FAKE_LAUNCHER_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True) + "\\n")
print("fake launcher accepted argv")
""",
            encoding="utf-8",
        )
        self.launcher.chmod(0o755)
        self.control_grant = self.fixture_bin / "control-grant.py"
        self.control_grant.write_text(
            """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

with Path(os.environ["FAKE_GRANT_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")
print("fake grant issued")
""",
            encoding="utf-8",
        )
        self.control_grant.chmod(0o755)
        self.task_hold = self.fixture_bin / "task-hold.py"
        self.task_hold.write_text(
            """#!/usr/bin/env python3
import os
raise SystemExit(int(os.environ.get("FAKE_HOLD_EXIT", "0")))
""",
            encoding="utf-8",
        )
        self.task_hold.chmod(0o755)
        (self.fixture_config / "statuses.config.json").write_text(
            json.dumps(
                {
                    "tasks": {
                        "statuses": [
                            {"name": "Active", "kind": "working"},
                            {"name": "Review", "kind": "review"},
                            {"name": "Blocked", "kind": "blocked"},
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        (self.fixture_config / "team.config.md").write_text(
            "STALE_NUDGE_GRACE_SECONDS=120\n", encoding="utf-8"
        )
        source_lines = (ROOT / "teams" / "full-stack.md").read_text(
            encoding="utf-8"
        ).splitlines()
        projection = [
            line
            for line in source_lines
            if line.startswith(
                ("REVIEW_MODE=", "REQUIRED_REVIEW_GATES=", "PROTOCOL_")
            )
        ]
        (self.workspace / "preset.env").write_text(
            "PRESET=full-stack\n" + "\n".join(projection) + "\n",
            encoding="utf-8",
        )
        self.team = "control-team"
        self.feature = "FEATURE-1"
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
                "full-stack",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.task = "TASK-1"
        self.attempt = 2
        self.task_key = self.execution_key(self.task)
        executions = self.workspace / "executions"
        executions.mkdir()
        self.execution_path = executions / f"{self.task_key}.json"
        self.write_execution(self.attempt)
        claims = self.workspace / "claims"
        claims.mkdir()
        self.claim_path = claims / f"{self.task_key}.json"
        self.write_claim(self.attempt)
        self.tasks = {
            "team": self.team,
            "featureId": self.feature,
            "tasks": [
                {
                    "taskId": self.task,
                    "status": "Active",
                    "labels": [],
                    "revision": "task-r1",
                }
            ],
        }
        self.tasks_path = self.workspace / "tasks.json"
        self.tasks_path.write_text(json.dumps(self.tasks), encoding="utf-8")
        self.launcher_log = self.root / "launcher.ndjson"
        self.grant_log = self.root / "grant.ndjson"
        self.environment = {
            "FAKE_LAUNCHER_LOG": str(self.launcher_log),
            "FAKE_GRANT_LOG": str(self.grant_log),
            "FAKE_HOLD_EXIT": "0",
            "STARTUP_FACTORY_IGNORED_TASK_LABELS_JSON": '["human-work"]',
        }
        self.clock = int(time.time())
        nudge = self.request(action="nudge-task", identity_seed="default-nudge")
        self.default_nudge_id = nudge["id"]
        self.complete_nudge(nudge)

    @staticmethod
    def execution_key(task: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", task).strip("-").lower()[:32] or "task"
        return f"{slug}-{hashlib.sha256(task.encode()).hexdigest()[:10]}"

    def write_execution(self, attempt: int) -> None:
        self.execution_path.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "team": self.team,
                    "featureId": self.feature,
                    "taskId": self.task,
                    "taskKey": self.task_key,
                    "role": "backend",
                    "attempt": attempt,
                    "worktree": str(
                        self.workspace
                        / "worktrees"
                        / f"backend#{attempt}-{self.task_key}"
                    ),
                }
            ),
            encoding="utf-8",
        )

    def write_claim(self, attempt: int, *, role: str = "backend") -> None:
        identity = {
            "schemaVersion": 1,
            "team": self.team,
            "featureId": self.feature,
            "taskId": self.task,
            "taskKey": self.task_key,
            "attempt": attempt,
            "role": role,
            "claimId": f"dispatch-{attempt}",
            "targetStatus": "Active",
        }
        self.claim_path.write_text(
            json.dumps(
                {
                    **identity,
                    "claimDigest": worker_control.sha256_bytes(
                        worker_control.canonical(identity)
                    ),
                    "recordedAt": "2026-08-25T12:00:00Z",
                }
            ),
            encoding="utf-8",
        )

    def complete_nudge(self, request: dict, *, age_seconds: int = 121) -> None:
        directory, key = worker_control.result_authority(
            self.lifecycle_root, self.repository
        )
        protected = worker_control.store_protected_result(
            directory, key, request, "completed", "nudged exact task"
        )
        protected["processedAt"] = datetime.fromtimestamp(
            self.clock - age_seconds, timezone.utc
        ).isoformat(timespec="seconds")
        unsigned = dict(protected)
        unsigned.pop("auth")
        protected["auth"] = "hmac-sha256:" + worker_control.hmac.new(
            key, worker_control.canonical(unsigned), hashlib.sha256
        ).hexdigest()
        worker_control.protected_result_path(directory, request["id"]).write_bytes(
            worker_control.canonical(protected) + b"\n"
        )
        done = self.workspace / "control-outbox" / "done"
        done.mkdir(parents=True, exist_ok=True)
        path = done / f"{request['id']}.json"
        path.write_bytes(
            worker_control.canonical(
                {
                    **request,
                    "result": protected["result"],
                    "detail": protected["detail"],
                    "processedAt": protected["processedAt"],
                }
            )
            + b"\n"
        )
        path.chmod(0o600)

    def request(
        self,
        *,
        action: str = "restart-task",
        actor: str = "team-lead",
        capability_role: str | None = None,
        task: str | None = None,
        attempt: int | None = None,
        target_role: str | None = None,
        created_at: int | None = None,
        expires_at: int | None = None,
        identity_seed: str = "valid",
        prior_nudge_id: str | None = None,
    ) -> dict:
        role = capability_role or actor
        now = int(time.time())
        created = now if created_at is None else created_at
        expires = created + 300 if expires_at is None else expires_at
        task_action = action in {"nudge-task", "restart-task"}
        request_task = (self.task if task is None else task) if task_action else "-"
        request_attempt = (
            (self.attempt if attempt is None else attempt) if task_action else 0
        )
        request_target_role = target_role if not task_action else None
        observed = None if action == "nudge-task" else "2026-08-25T12:00:00Z"
        binding = (
            worker_control.bound_task_state(
                self.workspace, self.tasks, self.team, self.feature, request_task
            )
            if task_action
            else None
        )
        nudge_id = None
        if action == "restart-task":
            nudge_id = prior_nudge_id or getattr(self, "default_nudge_id", None)
            if nudge_id is None:
                nudge_id = "control-" + hashlib.sha256(b"missing-nudge").hexdigest()[:32]
        control_id = "control-" + hashlib.sha256(identity_seed.encode()).hexdigest()[:32]
        value = {
            "schemaVersion": 1,
            "id": control_id,
            "team": self.team,
            "featureId": self.feature,
            "taskId": request_task,
            "attempt": request_attempt,
            "actor": actor,
            "marker": "worker-control",
            "targetStatus": None,
            "createdAt": created,
            "expiresAt": expires,
            "action": action,
            "targetRole": request_target_role,
            "observedLifecycleCreatedAt": observed,
            "observedTaskRevision": binding["observedTaskRevision"] if binding else None,
            "observedTaskStatus": binding["observedTaskStatus"] if binding else None,
            "observedExecutionSha256": binding["observedExecutionSha256"] if binding else None,
            "observedClaimSha256": binding["observedClaimSha256"] if binding else None,
            "priorNudgeControlId": nudge_id,
            "reasonCode": "stale-live",
        }
        body = worker_control.canonical(worker_control.control_body(value))
        value["controlBodySha256"] = "sha256:" + hashlib.sha256(body).hexdigest()
        capability = mint(
            str(self.repository),
            str(self.workspace),
            self.team,
            self.feature,
            role,
            "gate",
            "-",
            0,
            role,
        )
        value["producerCapability"] = sign_entry(
            value,
            body,
            capability["id"],
            capability["secret"],
            capability["instance"],
            capability["expiresAt"],
        )
        worker_control.validate_shape(value)
        return value

    def reconcile_one(
        self,
        request: dict,
        tasks: dict | None = None,
        *,
        now: int | None = None,
        nudge_grace_seconds: int = 120,
    ) -> str:
        with mock.patch.dict(os.environ, self.environment, clear=False), mock.patch.object(
            worker_control.time,
            "time",
            return_value=self.clock + 121 if now is None else now,
        ):
            return worker_control.reconcile_one(
                request,
                repository=self.repository,
                workspace=self.workspace,
                tasks=self.tasks if tasks is None else tasks,
                launcher=self.launcher,
                lifecycle_root=self.lifecycle_root,
                lead_role="team-lead",
                preset="full-stack",
                integrator_role="integrator",
                nudge_grace_seconds=nudge_grace_seconds,
            )

    def launcher_records(self) -> list[dict]:
        if not self.launcher_log.exists():
            return []
        return [
            json.loads(line)
            for line in self.launcher_log.read_text(encoding="utf-8").splitlines()
            if line
        ]

    def grant_records(self) -> list[list[str]]:
        if not self.grant_log.exists():
            return []
        return [
            json.loads(line)
            for line in self.grant_log.read_text(encoding="utf-8").splitlines()
            if line
        ]

    def request_command_context(self) -> tuple[argparse.Namespace, dict[str, str]]:
        capability = mint(
            str(self.repository),
            str(self.workspace),
            self.team,
            self.feature,
            "team-lead",
            "gate",
            "-",
            0,
            "team-lead",
        )
        args = argparse.Namespace(
            action="nudge-task",
            task=self.task,
            role=None,
            expected_attempt=self.attempt,
            observed_created_at=None,
            nudge_control_id=None,
            reason_code="artifact-missing",
        )
        environment = {
            "STARTUP_FACTORY_CANONICAL_REPO": str(self.repository),
            "STARTUP_FACTORY_CANONICAL_WORKSPACE": str(self.workspace),
            "STARTUP_FACTORY_TEAM": self.team,
            "STARTUP_FACTORY_FEATURE_ID": self.feature,
            "STARTUP_FACTORY_ROLE": "team-lead",
            "STARTUP_FACTORY_EXECUTION_KIND": "gate",
            "STARTUP_FACTORY_INSTANCE": "team-lead",
            "STARTUP_FACTORY_OUTBOX_CAPABILITY_ID": capability["id"],
            "STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET": capability["secret"],
            "STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT": str(
                capability["expiresAt"]
            ),
        }
        return args, environment

    def write_pending(self, request: dict) -> Path:
        pending = self.workspace / "control-outbox" / "pending"
        pending.mkdir(parents=True, exist_ok=True)
        path = pending / f"{request['id']}.json"
        path.write_bytes(worker_control.canonical(request) + b"\n")
        path.chmod(0o600)
        return path

    def reconcile_args(self) -> argparse.Namespace:
        return argparse.Namespace(
            repo=str(self.repository),
            workspace=str(self.workspace),
            lifecycle_root=str(self.lifecycle_root),
            launcher=str(self.launcher),
            tasks=str(self.tasks_path),
            team=self.team,
            feature=self.feature,
        )

    def test_valid_team_lead_restart_uses_exact_argv_once(self):
        request = self.request()
        detail = self.reconcile_one(request)
        records = self.launcher_records()
        self.assertIn("fake launcher accepted argv", detail)
        self.assertEqual(1, len(records))
        self.assertEqual(
            [
                "restart-task",
                self.team,
                self.feature,
                self.task,
                str(self.attempt),
                request["id"],
                "full-stack",
            ],
            records[0]["argv"],
        )
        self.assertEqual("1", records[0]["broker"])
        self.assertEqual("authorized", records[0]["controlReason"])
        self.assertEqual(str(self.lifecycle_root), records[0]["lifecycleRoot"])
        self.assertEqual(
            request["observedLifecycleCreatedAt"], records[0]["expectedCreatedAt"]
        )
        grants = self.grant_records()
        self.assertEqual(1, len(grants))
        self.assertIn("restart-task", grants[0])
        self.assertIn(self.task, grants[0])
        self.assertEqual(
            str(self.attempt), grants[0][grants[0].index("--attempt") + 1]
        )
        self.assertIn(request["id"], grants[0])

    def test_forged_non_lead_and_expired_requests_are_rejected(self):
        forged = self.request(identity_seed="forged")
        signature = forged["producerCapability"]["signature"]
        forged["producerCapability"]["signature"] = signature[:-1] + (
            "0" if signature[-1] != "0" else "1"
        )
        with self.assertRaisesRegex(worker_control.ControlError, "capability rejected"):
            self.reconcile_one(forged)

        non_lead = self.request(
            actor="principal-architect",
            capability_role="principal-architect",
            identity_seed="non-lead",
        )
        with self.assertRaisesRegex(worker_control.ControlError, "Team Lead gate capability"):
            self.reconcile_one(non_lead)

        now = int(time.time())
        expired = self.request(
            created_at=now - 400,
            expires_at=now - 100,
            identity_seed="expired",
        )
        with self.assertRaisesRegex(worker_control.ControlError, "expired"):
            self.reconcile_one(expired)
        self.assertEqual([], self.launcher_records())

    def test_agent_writable_preset_cannot_promote_another_gate_to_team_lead(self):
        (self.workspace / "preset.env").write_text(
            "\n".join(
                (
                    "PRESET=full-stack",
                    "PROTOCOL_TEAM_LEAD=principal-architect",
                    "PROTOCOL_INTEGRATOR=integrator",
                    "",
                )
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            worker_control.ControlError,
            "protected team preset authority is unavailable",
        ):
            worker_control.parse_preset(
                self.workspace, self.repository, self.team, self.feature
            )

    def test_task_attempt_status_and_hold_compare_and_set_refuse(self):
        stale_attempt = self.request(identity_seed="attempt")
        self.write_execution(self.attempt + 1)
        self.write_claim(self.attempt + 1)
        with self.assertRaisesRegex(worker_control.ControlError, "observedExecutionSha256 is stale"):
            self.reconcile_one(stale_attempt)
        self.write_execution(self.attempt)
        self.write_claim(self.attempt)

        wrong_status = self.request(identity_seed="status")
        review_tasks = json.loads(json.dumps(self.tasks))
        review_tasks["tasks"][0]["status"] = "Review"
        with self.assertRaisesRegex(worker_control.ControlError, "observedTaskStatus is stale"):
            self.reconcile_one(wrong_status, review_tasks)

        held = self.request(identity_seed="hold")
        with mock.patch.dict(
            os.environ, {**self.environment, "FAKE_HOLD_EXIT": "3"}, clear=False
        ):
            with self.assertRaisesRegex(worker_control.ControlError, "held or human-owned"):
                worker_control.reconcile_one(
                    held,
                    repository=self.repository,
                    workspace=self.workspace,
                    tasks=self.tasks,
                    launcher=self.launcher,
                    lifecycle_root=self.lifecycle_root,
                    lead_role="team-lead",
                    preset="full-stack",
                    integrator_role="integrator",
                )
        self.assertEqual([], self.launcher_records())

    def test_duplicate_completed_request_is_idempotent(self):
        request = self.request(identity_seed="idempotent")
        content = worker_control.canonical(request) + b"\n"
        self.write_pending(request)
        with mock.patch.dict(os.environ, self.environment, clear=False):
            self.assertEqual(0, worker_control.reconcile_command(self.reconcile_args()))
        self.assertEqual(1, len(self.launcher_records()))

        # Model a producer retry or broker redelivery after the first result was
        # durably archived. The control identity must make the side effect once-only.
        pending = self.workspace / "control-outbox" / "pending" / f"{request['id']}.json"
        pending.write_bytes(content)
        pending.chmod(0o600)
        with mock.patch.dict(os.environ, self.environment, clear=False):
            self.assertEqual(0, worker_control.reconcile_command(self.reconcile_args()))
        self.assertEqual(1, len(self.launcher_records()))
        done = self.workspace / "control-outbox" / "done" / f"{request['id']}.json"
        self.assertEqual("completed", json.loads(done.read_text())["result"])

    def test_generic_role_control_refuses_integrator(self):
        request = self.request(
            action="retire-role",
            target_role="integrator",
            identity_seed="integrator",
        )
        with self.assertRaisesRegex(worker_control.ControlError, "cannot target the integrator"):
            self.reconcile_one(request)
        self.assertEqual([], self.launcher_records())

        lead = self.request(
            action="retire-role",
            target_role="team-lead",
            identity_seed="retire-lead",
        )
        with self.assertRaisesRegex(worker_control.ControlError, "configured Team Lead"):
            self.reconcile_one(lead)
        self.assertEqual([], self.launcher_records())

    def test_role_control_uses_feature_generation_grant_and_lead_restart_only(self):
        retired = self.request(
            action="retire-role",
            target_role="senior-qa-engineer",
            identity_seed="retire-qa",
        )
        self.reconcile_one(retired)
        restarted = self.request(
            action="restart-role",
            target_role="team-lead",
            identity_seed="restart-lead",
        )
        self.reconcile_one(restarted)

        self.assertEqual(
            [
                [
                    "retire-role",
                    self.team,
                    self.feature,
                    "senior-qa-engineer",
                    retired["observedLifecycleCreatedAt"],
                    retired["id"],
                ],
                [
                    "restart-role",
                    self.team,
                    self.feature,
                    "team-lead",
                    restarted["observedLifecycleCreatedAt"],
                    restarted["id"],
                    "full-stack",
                ],
            ],
            [record["argv"] for record in self.launcher_records()],
        )
        grants = self.grant_records()
        self.assertEqual(2, len(grants))
        self.assertIn("retire-role", grants[0])
        self.assertIn("senior-qa-engineer", grants[0])
        self.assertIn("restart-role", grants[1])
        self.assertIn("team-lead", grants[1])

    def test_task_revision_execution_and_claim_digests_are_exact_cas(self):
        revision = self.request(action="nudge-task", identity_seed="revision-cas")
        changed_tasks = json.loads(json.dumps(self.tasks))
        changed_tasks["tasks"][0]["revision"] = "task-r2"
        with self.assertRaisesRegex(worker_control.ControlError, "observedTaskRevision is stale"):
            self.reconcile_one(revision, changed_tasks)

        execution = self.request(action="nudge-task", identity_seed="execution-cas")
        execution_bytes = self.execution_path.read_bytes()
        self.execution_path.write_bytes(execution_bytes + b"\n")
        with self.assertRaisesRegex(worker_control.ControlError, "observedExecutionSha256 is stale"):
            self.reconcile_one(execution)
        self.execution_path.write_bytes(execution_bytes)

        claim = self.request(action="nudge-task", identity_seed="claim-cas")
        claim_bytes = self.claim_path.read_bytes()
        self.claim_path.write_bytes(claim_bytes + b"\n")
        with self.assertRaisesRegex(worker_control.ControlError, "observedClaimSha256 is stale"):
            self.reconcile_one(claim)
        self.claim_path.write_bytes(claim_bytes)
        self.assertEqual([], self.launcher_records())

    def test_restart_requires_protected_completed_nudge_and_grace(self):
        absent_id = "control-" + hashlib.sha256(b"absent-nudge").hexdigest()[:32]
        absent = self.request(
            identity_seed="restart-without-nudge", prior_nudge_id=absent_id
        )
        with self.assertRaisesRegex(worker_control.ControlError, "completed nudge projection"):
            self.reconcile_one(absent)

        fresh_nudge = self.request(action="nudge-task", identity_seed="fresh-nudge")
        self.complete_nudge(fresh_nudge, age_seconds=0)
        early = self.request(
            identity_seed="restart-too-early", prior_nudge_id=fresh_nudge["id"]
        )
        with self.assertRaisesRegex(worker_control.ControlDeferred, "nudge grace"):
            self.reconcile_one(early, now=self.clock)
        self.assertEqual([], self.launcher_records())
        self.assertEqual([], self.grant_records())

        self.tasks["tasks"][0]["revision"] = "task-r2"
        stale_nudge = self.request(
            identity_seed="restart-after-revision-change",
            prior_nudge_id=self.default_nudge_id,
        )
        with self.assertRaisesRegex(
            worker_control.ControlError, "completed nudge does not bind"
        ):
            self.reconcile_one(stale_nudge)

    def test_request_retries_verify_pending_signature_and_ignore_done_squat(self):
        args, environment = self.request_command_context()
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            worker_control.time, "time", return_value=self.clock
        ), mock.patch("sys.stdout"):
            self.assertEqual(0, worker_control.request_command(args))

        pending = self.workspace / "control-outbox" / "pending"
        entries = list(pending.glob("control-*.json"))
        self.assertEqual(1, len(entries))
        target = entries[0]
        valid = json.loads(target.read_text(encoding="utf-8"))

        # A valid duplicate is idempotent, but a forged pending copy is rejected.
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            worker_control.time, "time", return_value=self.clock + 1
        ), mock.patch("sys.stdout"):
            self.assertEqual(0, worker_control.request_command(args))
        valid["producerCapability"]["signature"] = "hmac-sha256:" + "0" * 64
        target.write_text(json.dumps(valid), encoding="utf-8")
        with mock.patch.dict(os.environ, environment, clear=False), self.assertRaisesRegex(
            worker_control.ControlError, "capability rejected"
        ):
            worker_control.request_command(args)

        # An agent-writable done/failed projection cannot reserve the deterministic ID.
        target.unlink()
        done = self.workspace / "control-outbox" / "done" / target.name
        done.write_text("{}\n", encoding="utf-8")
        done.chmod(0o600)
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            worker_control.time, "time", return_value=self.clock + 2
        ), mock.patch("sys.stdout"):
            self.assertEqual(0, worker_control.request_command(args))
        self.assertTrue(target.is_file())

    def test_malformed_pending_entries_are_isolated_without_blocking_valid_control(self):
        valid = self.request(action="nudge-task", identity_seed="valid-batch-nudge")
        pending = self.workspace / "control-outbox" / "pending"
        pending.mkdir(parents=True, exist_ok=True)
        self.write_pending(valid)
        (pending / "junk.txt").write_text("unexpected\n", encoding="utf-8")
        malformed = pending / ("control-" + "a" * 32 + ".json")
        malformed.write_text("{not-json\n", encoding="utf-8")
        malformed.chmod(0o600)

        with mock.patch.dict(os.environ, self.environment, clear=False), mock.patch.object(
            worker_control.time, "time", return_value=self.clock + 121
        ), mock.patch("sys.stdout") as stdout:
            self.assertEqual(0, worker_control.reconcile_command(self.reconcile_args()))
        output = "".join(call.args[0] for call in stdout.write.call_args_list)
        summary = json.loads(output.strip().splitlines()[-1])
        self.assertEqual(
            {"deferred": 0, "processed": 1, "rejected": 2, "retained": False},
            summary,
        )
        self.assertTrue(
            (self.workspace / "control-outbox" / "done" / f"{valid['id']}.json").is_file()
        )
        self.assertEqual([], list(pending.iterdir()))
        rejected = list((self.workspace / "control-outbox" / "failed").glob("rejected-*.entry"))
        self.assertEqual(2, len(rejected))

    def test_reconcile_pass_has_strict_request_count_limit(self):
        pending = self.workspace / "control-outbox" / "pending"
        pending.mkdir(parents=True, exist_ok=True)
        for index in range(5):
            path = pending / f"control-{index:032x}.json"
            path.write_text("{malformed\n", encoding="utf-8")
            path.chmod(0o600)

        with mock.patch.object(
            worker_control, "MAX_CONTROL_REQUESTS_PER_PASS", 2
        ), mock.patch.dict(os.environ, self.environment, clear=False), mock.patch(
            "sys.stdout"
        ) as stdout:
            self.assertEqual(0, worker_control.reconcile_command(self.reconcile_args()))
        output = "".join(call.args[0] for call in stdout.write.call_args_list)
        summary = json.loads(output.strip().splitlines()[-1])
        self.assertEqual(2, summary["rejected"])
        self.assertTrue(summary["retained"])
        self.assertEqual(3, len(list(pending.iterdir())))

    def test_reconcile_pass_has_strict_aggregate_request_byte_limit(self):
        pending = self.workspace / "control-outbox" / "pending"
        pending.mkdir(parents=True, exist_ok=True)
        for index in range(2):
            path = pending / f"control-{index:032x}.json"
            path.write_bytes(b"{" + b" " * 39_999)
            path.chmod(0o600)

        with mock.patch.object(
            worker_control, "MAX_CONTROL_REQUEST_BYTES_PER_PASS", 70_000
        ), mock.patch.dict(os.environ, self.environment, clear=False), mock.patch(
            "sys.stdout"
        ) as stdout:
            self.assertEqual(0, worker_control.reconcile_command(self.reconcile_args()))
        output = "".join(call.args[0] for call in stdout.write.call_args_list)
        summary = json.loads(output.strip().splitlines()[-1])
        self.assertEqual(1, summary["rejected"])
        self.assertTrue(summary["retained"])
        self.assertEqual(1, len(list(pending.iterdir())))

    def test_bounded_protected_result_retention_never_replays_consumed_id(self):
        directory, key = worker_control.result_authority(
            self.lifecycle_root, self.repository
        )
        target = self.request(action="nudge-task", identity_seed="retained-target")
        with mock.patch.object(worker_control, "FULL_RESULT_RETENTION", 2):
            worker_control.store_protected_result(
                directory, key, target, "completed", "first result"
            )
            target_path = worker_control.protected_result_path(directory, target["id"])
            os.utime(target_path, ns=(1, 1))
            for index in range(3):
                request = self.request(
                    action="nudge-task", identity_seed=f"retention-{index}"
                )
                worker_control.store_protected_result(
                    directory, key, request, "completed", f"result {index}"
                )

            self.assertLessEqual(len(list(directory.glob("control-*.json"))), 2)
            self.assertFalse(target_path.exists())
            archived = worker_control.load_protected_result(target_path, key, target)
            self.assertIsNotNone(archived)
            self.assertEqual("failed", archived["result"])
            collided = dict(target)
            collided["reasonCode"] = "hung-tool"
            self.assertIsNotNone(
                worker_control.load_protected_result(target_path, key, collided)
            )

            self.write_pending(target)
            mailbox = self.workspace / "mailbox" / "backend"
            before = list(mailbox.iterdir()) if mailbox.exists() else []
            with mock.patch.dict(
                os.environ, self.environment, clear=False
            ), mock.patch("sys.stdout"):
                self.assertEqual(
                    0, worker_control.reconcile_command(self.reconcile_args())
                )
            after = list(mailbox.iterdir()) if mailbox.exists() else []
            self.assertEqual(before, after)
            failed = (
                self.workspace
                / "control-outbox"
                / "failed"
                / f"{target['id']}.json"
            )
            self.assertTrue(failed.is_file())


if __name__ == "__main__":
    unittest.main()
