#!/usr/bin/env python3
"""Immutable native gate completion; no guest verdict can assert its own pass."""
from __future__ import annotations
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "bin"), str(ROOT / "src")]
from startup_factory_cli.config_values import parse_config_bytes
from startup_factory_cli.execution_backend import LaunchScope
from startup_factory_cli.sandbox_registry import SandboxRegistry
from sandbox_acceptance import project_id, task_key
import sandbox_completion as completion

SPEC = importlib.util.spec_from_file_location("sf_completion_guard", ROOT / "bin/sandbox-execution-guard.py")
guard = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(guard)
DIGEST = "sha256:" + "a" * 64
CAP = "cap-" + "b" * 32
JOB = "job-" + "c" * 32


class GateCompletionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-completion-", dir=os.environ.get("SF_REGISTRY_TEST_ROOT"))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.root.chmod(0o700)
        self.repo = self.root / "repo"; self.repo.mkdir(mode=0o700)
        self.workspaces = self.repo / ".teamwork"; self.workspaces.mkdir(mode=0o700)
        self.workspace = self.workspaces / "team-one"; self.workspace.mkdir(mode=0o700)
        self.registry_root = self.root / "registry"; self.registry_root.mkdir(mode=0o700)
        self.registry = SandboxRegistry(self.registry_root, "sf-completion")
        self.addCleanup(self.registry.close)
        self.scope = LaunchScope(project_id(self.repo), "team-one", "FEATURE-1", "principal-architect", "TASK-1", 2)
        with self.registry.locked() as tx:
            self.epoch = tx.takeover()
            row = tx.reserve(self.scope.as_dict(), epoch=self.epoch)
            row = tx.bind(row["name"], row["generation"], self.epoch,
                sandbox_id="02418900-048d-44e9-86dc-9e036e546554", created_at="2026-11-17T10:08:29+01:00")
            row = tx.transition(row["name"], row["generation"], self.epoch, state="ready")
        self.row = row
        self.binding = {"schemaVersion": 1, "backend": "docker-sandboxes", "namespace": "sf-completion",
            **{key: row[key] for key in ("name", "sandboxId", "createdAt", "generation", "epoch")},
            "profileDigest": DIGEST, "policyDigest": DIGEST, "image": "registry.example.com/agent@" + DIGEST,
            "inputDigest": DIGEST, "baseCommit": "1" * 40, "state": "ready",
            "acceptedCommit": None, "acceptedTree": None, "acceptedExportDigest": None}
        self.review = {"requestDigest": "sha256:" + "d" * 64, "head": "1" * 40,
            "package": "sha256:" + "e" * 64, "base": "2" * 40, "reviewGates": ["security"]}
        self.allowed = True
        self.store = completion.GateCompletionStore(self.registry, authorize=lambda: self.allowed,
            deployment_digest=DIGEST, profile_basis_digest=DIGEST)
        self.profile = SimpleNamespace(namespace="sf-completion", digest=DIGEST,
            policy_digest=DIGEST, image=self.binding["image"])
        self.deployment = SimpleNamespace(profile_path="/fixture/profile.json", receipt_path="/fixture/receipt.json",
            registry_root=str(self.registry_root), digest=DIGEST,
            projects=({"projectId": self.scope.project_id, "repository": str(self.repo), "workspaceRoot": str(self.workspaces)},))

    def bind(self, **kwargs):
        return self.store.bind(capability_id=CAP, job_id=JOB, request_digest=DIGEST,
            scope=self.scope, binding=self.binding, review_binding=self.review, **kwargs)

    def remove(self):
        with self.registry.locked() as tx:
            args = self.row["name"], self.row["generation"], self.epoch
            tx.fence(*args)
            observation = {"sandboxId": self.row["sandboxId"], "createdAt": self.row["createdAt"], "state": "absent"}
            for state in ("stopping", "stopped", "removing", "removed"):
                tx.transition(*args, state=state, **({"observation": observation} if state in {"stopped", "removed"} else {}))

    def finish(self, *, success=True, verified=True, **kwargs):
        return self.store.finish(CAP, JOB, DIGEST, success=success,
            readonly_verified=verified, evidence_digest=DIGEST, **kwargs)

    def entry(self):
        bodies = self.workspace / "outbox/bodies"; bodies.mkdir(parents=True, mode=0o700)
        identifier = "8" * 32
        body = ("[architecture-approval]\nFiles: none\nApproved fixture\n"
            "Review-Request-SHA256: " + self.review["requestDigest"] + "\nTask-Branch-Head: " + self.review["head"] +
            "\nReview-Package-SHA256: " + self.review["package"] + "\n").encode()
        path = bodies / (identifier + ".md"); path.write_bytes(body); path.chmod(0o600)
        return {"id": identifier, "team": self.scope.team, "featureId": self.scope.feature_id,
            "taskId": self.scope.task_id, "attempt": self.scope.attempt, "actor": self.scope.role,
            "marker": "architecture-approval", "bodyPath": str(path),
            "producerCapability": {"id": CAP, "bodySha256": completion._digest(body)}}

    def verify(self, entry, **kwargs):
        with mock.patch.object(completion, "load_deployment", return_value=self.deployment), \
             mock.patch.object(completion, "load_profile", return_value=self.profile), \
             mock.patch.object(completion, "profile_basis_digest", return_value=DIGEST), \
             mock.patch.object(completion, "verify_deployment_enrollment"):
            return completion.verify_gate_completion(Path("/fixture/deployment.json"), self.repo,
                self.workspace, self.scope.team, self.scope.feature_id, self.scope.task_id, entry, **kwargs)

    def test_admitted_approval_waits_until_same_readonly_generation_and_cleanup_complete(self):
        entry = self.entry()
        with self.assertRaises(completion.CompletionPending): self.verify(entry)
        self.bind()
        with self.assertRaises(completion.CompletionPending): self.verify(entry)
        with self.assertRaises(completion.CompletionError): self.finish()
        self.remove()
        with self.assertRaises(completion.CompletionError): self.finish(verified=False)
        self.finish()
        receipt = self.verify(entry)
        self.assertEqual(receipt["completion"]["status"], "succeeded")
        self.assertEqual(receipt["binding"]["reviewBinding"], self.review)
        self.assertEqual(self.finish(), receipt["completion"])
        for path in (self.registry_root / "gate-completions").iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)

    def test_failed_readonly_or_cleanup_job_rejects_instead_of_pending_or_later_success(self):
        entry = self.entry(); self.bind()
        self.allowed = False
        self.finish(success=False, verified=False)
        with self.assertRaises(completion.CompletionError): self.verify(entry)
        self.remove(); self.allowed = True
        with self.assertRaises(completion.CompletionError): self.finish()

    def test_capability_task_role_attempt_body_and_request_swaps_cannot_reuse_completion(self):
        entry = self.entry(); self.bind(); self.remove(); self.finish()
        for changes in ({"actor": "backend"}, {"attempt": 1}, {"taskId": "TASK-2"},
                        {"producerCapability": {"id": "cap-" + "f" * 32, "bodySha256": entry["producerCapability"]["bodySha256"]}},
                        {"bodyPath": str(self.root / "unrelated-host-file")}):
            with self.subTest(changes=changes), self.assertRaises(completion.CompletionError):
                self.verify({**entry, **changes})
        body = Path(entry["bodyPath"]); body.write_text(body.read_text().replace(self.review["requestDigest"], "sha256:" + "f" * 64))
        entry["producerCapability"]["bodySha256"] = completion._digest(body.read_bytes())
        with self.assertRaises(completion.CompletionError): self.verify(entry)
        with self.assertRaises(completion.CompletionError):
            self.store.finish(CAP, "job-" + "f" * 32, DIGEST, success=False, readonly_verified=False, evidence_digest=DIGEST)

    def test_stable_anchors_allow_receipt_renewal_but_refuse_deployment_or_profile_change(self):
        entry = self.entry(); self.bind(); self.remove(); self.finish()
        self.profile.digest = "sha256:" + "9" * 64
        self.assertEqual(self.verify(entry)["binding"]["sandbox"]["profileDigest"], DIGEST)
        changed = completion.GateCompletionStore(self.registry, deployment_digest="sha256:" + "8" * 64, profile_basis_digest=DIGEST)
        with self.assertRaises(completion.CompletionError): changed.verify(CAP)
        changed = completion.GateCompletionStore(self.registry, deployment_digest=DIGEST, profile_basis_digest="sha256:" + "8" * 64)
        with self.assertRaises(completion.CompletionError): changed.verify(CAP)

    def test_supplied_transaction_preserves_registry_then_task_lock_and_scope(self):
        with self.registry.locked() as tx:
            self.bind(transaction=tx)
        self.remove()
        with self.registry.locked() as tx:
            self.finish(transaction=tx)
        self.assertEqual(self.store.verify(CAP)["completion"]["status"], "succeeded")
        self.binding["generation"] = "gen-" + "f" * 32
        with self.assertRaises(completion.CompletionError): self.bind()

    def test_revocation_before_bound_publication_never_creates_positive_completion(self):
        calls = iter((True, False))
        self.store.authorize = lambda: next(calls)
        with self.assertRaises(completion.CompletionError): self.bind()
        with self.assertRaises(completion.CompletionPending): self.store.verify(CAP)

    def test_unsafe_receipt_file_and_quota_cannot_create_or_enable_completion(self):
        with mock.patch.object(completion, "MAX_FILES", 0), self.assertRaises(completion.CompletionError):
            self.bind()
        self.bind(); self.remove(); self.finish()
        path = self.registry_root / "gate-completions" / (CAP + ".completed.json")
        path.chmod(0o644)
        with self.assertRaises(completion.CompletionError): self.store.verify(CAP)
        path.chmod(0o600); raw = path.read_bytes(); path.unlink(); path.symlink_to(self.root / "other")
        with self.assertRaises(completion.CompletionError): self.store.verify(CAP)

    def test_broker_guard_defers_running_verdict_rejects_failure_and_keeps_design_markers_available(self):
        entry = self.entry(); path = self.workspace / "entry.json"
        path.write_text(json.dumps(entry)); path.chmod(0o600)
        args = ["--repo", str(self.repo), "--workspace", str(self.workspace), "--team", self.scope.team,
            "--feature", self.scope.feature_id, "--publication-entry", str(path)]
        config = parse_config_bytes(b'AGENT_EXECUTION_BACKEND=docker-sandboxes\nAGENT_SANDBOX_ENFORCED=true\nAGENT_SANDBOX_DEPLOYMENT=/fixture/deployment.json\n')
        with mock.patch.object(guard, "read_config_file", return_value=config), \
             mock.patch.object(guard, "verify_gate_completion", side_effect=completion.CompletionPending()):
            self.assertEqual(guard.main(args), 75)
        with mock.patch.object(guard, "read_config_file", return_value=config), \
             mock.patch.object(guard, "verify_gate_completion", side_effect=completion.CompletionError()):
            self.assertEqual(guard.main(args), 1)
        entry["marker"] = "design-approved"
        body = Path(entry["bodyPath"])
        body.write_text("[design-approved]\nFiles: none\nApproved fixture design\n")
        entry["producerCapability"]["bodySha256"] = completion._digest(body.read_bytes())
        path.write_text(json.dumps(entry))
        with mock.patch.object(guard, "read_config_file", return_value=config), \
             mock.patch.object(guard, "verify_gate_completion", side_effect=lambda *_args, **kwargs: self.verify(entry, **kwargs)):
            self.assertEqual(guard.main(args), 75)
            self.store.bind(capability_id=CAP, job_id=JOB, request_digest=DIGEST,
                scope=self.scope, binding=self.binding, review_binding=None)
            self.remove(); self.finish()
            self.assertEqual(guard.main(args), 0, "a completed design gate must not need an implementation record")
        entry["marker"] = "review-findings"; path.write_text(json.dumps(entry))
        with mock.patch.object(guard, "verify_gate_completion") as receipt:
            self.assertEqual(guard.main(args), 0)
            receipt.assert_not_called()

    def test_broker_guard_accepts_completed_current_attempt_and_rejects_same_head_later_attempt(self):
        entry = self.entry(); self.bind(); self.remove(); self.finish()
        path = self.workspace / "entry.json"; path.write_text(json.dumps(entry)); path.chmod(0o600)
        executions = self.workspace / "executions"; executions.mkdir(mode=0o700)
        record_path = executions / (task_key(self.scope.task_id) + ".json")
        record = {"attempt": self.scope.attempt, "sandbox": {"acceptedCommit": self.review["head"]}}
        record_path.write_text(json.dumps(record)); record_path.chmod(0o600)
        args = ["--repo", str(self.repo), "--workspace", str(self.workspace), "--team", self.scope.team,
            "--feature", self.scope.feature_id, "--publication-entry", str(path)]
        config = parse_config_bytes(b'AGENT_EXECUTION_BACKEND=docker-sandboxes\nAGENT_SANDBOX_ENFORCED=true\nAGENT_SANDBOX_DEPLOYMENT=/fixture/deployment.json\n')
        with mock.patch.object(guard, "read_config_file", return_value=config), \
             mock.patch.object(guard, "verify_gate_completion", side_effect=lambda *_args, **kwargs: self.verify(entry, **kwargs)), \
             mock.patch.object(guard, "verify_configured_execution"):
            self.assertEqual(guard.main(args), 0)
            record["attempt"] += 1; record_path.write_text(json.dumps(record))
            self.assertEqual(guard.main(args), 1)


if __name__ == "__main__": unittest.main()
