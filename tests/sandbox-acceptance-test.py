#!/usr/bin/env python3
"""Protected source-import receipts cannot be supplied by execution projections."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "bin"), str(ROOT / "src")]
from startup_factory_cli.execution_backend import LaunchScope, DockerProfile, parse_profile
from startup_factory_cli.sandbox_registry import SandboxRegistry
from startup_factory_cli.sandbox_enrollment import profile_basis_digest
import sandbox_acceptance as acceptance
from execution_descriptor import ExecutionDescriptorError

DIGEST = "sha256:" + "a" * 64


class SandboxAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("SF_REGISTRY_TEST_ROOT"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.registry_root = self.root / "registry"; self.registry_root.mkdir(mode=0o700)
        self.registry = SandboxRegistry(self.registry_root, "sf-test")
        self.addCleanup(self.registry.close)
        self.scope = LaunchScope(DIGEST, "team-one", "FEATURE-1", "backend", "TASK-1", 1)
        with self.registry.locked() as transaction:
            epoch = transaction.takeover()
            row = transaction.reserve(self.scope.as_dict(), epoch=epoch)
            row = transaction.bind(row["name"], row["generation"], epoch,
                sandbox_id="02418900-048d-44e9-86dc-9e036e546554", created_at="2026-11-17T10:08:29+01:00")
            for state in ("ready", "running", "collecting", "work-complete"):
                row = transaction.transition(row["name"], row["generation"], epoch, state=state)
        self.row = row
        self.binding = {"schemaVersion": 1, "backend": "docker-sandboxes", "namespace": "sf-test",
            **{key: row[key] for key in ("name", "sandboxId", "createdAt", "generation", "epoch")},
            "profileDigest": DIGEST, "policyDigest": DIGEST,
            "image": "registry.example.com/factory/agent@" + DIGEST,
            "inputDigest": DIGEST, "baseCommit": "1" * 40, "state": "accepted",
            "acceptedCommit": "2" * 40, "acceptedTree": "3" * 40, "acceptedExportDigest": DIGEST}
        self.promotion = {"schemaVersion": 1, "kind": "sandbox-promotion", "exportId": "export-one",
            "assignmentDigest": DIGEST, "manifestDigest": DIGEST, "baseCommit": "1" * 40,
            "tree": "3" * 40, "commit": "2" * 40,
            "targetRef": "refs/heads/agent-task/team-one/" + acceptance.task_key("TASK-1"),
            "previousHead": "1" * 40}
        self.store = acceptance.AcceptanceStore(self.registry, authorize=lambda: True)

    def record(self, store=None):
        return (store or self.store).record(self.scope, self.binding, self.promotion, evidence_digest=DIGEST)

    def test_valid_import_is_private_immutable_and_bound_to_protected_generation(self):
        value = self.record()
        self.assertEqual(self.store.verify(self.scope, self.binding), value)
        path = self.registry_root / "acceptances" / (self.binding["generation"] + ".json")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual((path.parent.stat().st_mode & 0o777), 0o700)
        self.assertEqual(self.record(), value)
        changed = dict(self.promotion, commit="4" * 40)
        binding = dict(self.binding, acceptedCommit="4" * 40)
        with self.assertRaises(acceptance.AcceptanceError):
            self.store.record(self.scope, binding, changed, evidence_digest=DIGEST)

    def test_task_projection_cannot_replace_absent_protected_receipt(self):
        with self.assertRaises(acceptance.AcceptanceError):
            self.store.verify(self.scope, self.binding)
        self.assertFalse((self.registry_root / "acceptances").exists())

    def test_ref_commit_tree_manifest_scope_and_generation_swaps_are_rejected(self):
        self.record()
        for field, changed in (("generation", "gen-" + "9" * 32), ("acceptedCommit", "4" * 40),
                               ("acceptedTree", "5" * 40), ("acceptedExportDigest", "sha256:" + "b" * 64),
                               ("namespace", "sf-other"),
                               ("inputDigest", "sha256:" + "c" * 64), ("epoch", self.binding["epoch"] + 1)):
            binding = dict(self.binding); binding[field] = changed
            with self.subTest(field=field), self.assertRaises(acceptance.AcceptanceError):
                self.store.verify(self.scope, binding)
        other_scope = LaunchScope(DIGEST, "team-one", "FEATURE-1", "backend", "TASK-2", 1)
        with self.assertRaises(acceptance.AcceptanceError):
            self.store.verify(other_scope, self.binding)
        for field, changed in (("targetRef", "refs/heads/main"), ("previousHead", "4" * 40)):
            bad = dict(self.promotion); bad[field] = changed
            with self.subTest(field=field), self.assertRaises(acceptance.AcceptanceError):
                self.store.record(self.scope, self.binding, bad, evidence_digest=DIGEST)

    def test_revoked_or_missing_current_authorizer_cannot_publish_a_receipt(self):
        for authorize in (None, lambda: False, lambda: 1):
            store = acceptance.AcceptanceStore(self.registry, authorize=authorize)
            with self.subTest(authorize=authorize), self.assertRaises(acceptance.AcceptanceError):
                self.record(store)
        self.assertFalse((self.registry_root / "acceptances").exists())

    def test_authority_change_during_staging_does_not_publish_receipt(self):
        calls = iter((True, False))
        store = acceptance.AcceptanceStore(self.registry, authorize=lambda: next(calls))
        with self.assertRaises(acceptance.AcceptanceError):
            self.record(store)
        directory = self.registry_root / "acceptances"
        self.assertEqual([path.name for path in directory.iterdir()], ["." + self.binding["generation"] + ".json.pending"])
        self.assertEqual(self.record(), self.store.verify(self.scope, self.binding))

    def test_fence_and_unsafe_file_kinds_refuse_receipt_use(self):
        self.record()
        path = self.registry_root / "acceptances" / (self.binding["generation"] + ".json")
        raw = path.read_bytes()
        path.unlink(); path.symlink_to(self.root / "missing")
        with self.assertRaises(acceptance.AcceptanceError):
            self.store.verify(self.scope, self.binding)
        path.unlink(); path.write_bytes(raw); path.chmod(0o644)
        with self.assertRaises(acceptance.AcceptanceError):
            self.store.verify(self.scope, self.binding)
        path.chmod(0o600)
        with self.registry.locked() as transaction:
            transaction.fence(self.row["name"], self.row["generation"], self.row["epoch"])
        with self.assertRaises(acceptance.AcceptanceError):
            self.store.verify(self.scope, self.binding)

    def test_permanent_receipt_quota_does_not_remove_history(self):
        with mock.patch.object(acceptance, "MAX_RECEIPTS", 0), self.assertRaises(acceptance.AcceptanceError):
            self.record()
        self.assertEqual(list((self.registry_root / "acceptances").iterdir()), [])

    def test_held_transaction_preserves_lock_order_and_rejects_foreign_registry(self):
        with self.registry.locked() as tx:
            value = self.store.record(self.scope, self.binding, self.promotion, evidence_digest=DIGEST, transaction=tx)
            self.assertEqual(self.store.verify(self.scope, self.binding, transaction=tx), value)
        with self.assertRaises(acceptance.AcceptanceError):
            self.store.record(self.scope, self.binding, self.promotion, evidence_digest=DIGEST, transaction=object())

    def test_renewal_requires_protected_stable_anchors_and_keeps_original_provenance(self):
        deployment = SimpleNamespace(digest="sha256:" + "b" * 64)
        original = parse_profile((ROOT / "config/sandbox.config.example.json").read_bytes())
        profile = DockerProfile.from_dict({**original.as_dict(), "namespace": "sf-test"})
        self.binding["profileDigest"] = profile.digest
        self.binding.update(policyDigest=profile.policy_digest, image=profile.image, namespace=profile.namespace)
        store = acceptance.AcceptanceStore(self.registry, authorize=lambda: True,
            deployment_digest=deployment.digest, profile_basis_digest=profile_basis_digest(profile))
        receipt = self.record(store)
        self.assertEqual(receipt["sandbox"]["profileDigest"], profile.digest)
        data = profile.as_dict(); data["qualificationDigest"] = "sha256:" + "c" * 64
        renewed = DockerProfile.from_dict(data)
        acceptance.verify_profile_provenance(receipt, deployment, renewed)
        for changed in (dict(receipt, deploymentDigest=DIGEST), dict(receipt, profileBasisDigest=DIGEST)):
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.verify_profile_provenance(changed, deployment, renewed)
        legacy = {key: value for key, value in receipt.items() if key not in {"deploymentDigest", "profileBasisDigest"}}
        legacy["schemaVersion"] = 1
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.verify_profile_provenance(legacy, deployment, renewed)

    def config(self, backend="docker-sandboxes", enforced="true"):
        root = self.root / "runtime"; (root / "config").mkdir(parents=True, exist_ok=True)
        (root / "config/team.config.md").write_text(
            f"AGENT_EXECUTION_BACKEND={backend}\nAGENT_SANDBOX_ENFORCED={enforced}\n"
            "AGENT_SANDBOX_DEPLOYMENT=/opt/factory/deployment.json\n")
        return root

    def projection(self):
        return {"schemaVersion": 2, "sandbox": copy.deepcopy(self.binding),
                "claimLineage": {}, "lineageDigest": DIGEST, "role": "backend", "attempt": 1}

    def test_configured_backend_never_downgrades_a_docker_execution_to_native(self):
        record = self.projection(); root = self.config("protected-runner")
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.verify_configured_execution(record, self.root, self.root, "team-one", "FEATURE-1", "TASK-1", root)
        self.assertIsNone(acceptance.verify_configured_execution({"schemaVersion": 1}, self.root,
            self.root, "team-one", "FEATURE-1", "TASK-1", root))
        root = self.config()
        with self.assertRaises(acceptance.ImportPending):
            acceptance.verify_configured_execution({"schemaVersion": 1}, self.root, self.root,
                "team-one", "FEATURE-1", "TASK-1", root, allow_pending=True)

    def test_review_publication_defers_until_import_then_uses_the_protected_verifier(self):
        root = self.config(); record = self.projection()
        record["sandbox"].update(state="running", acceptedCommit=None, acceptedTree=None, acceptedExportDigest=None)
        with mock.patch.object(acceptance, "verify_execution_acceptance") as verifier:
            with self.assertRaises(acceptance.ImportPending):
                acceptance.verify_configured_execution(record, self.root, self.root, "team-one", "FEATURE-1", "TASK-1", root, allow_pending=True)
            verifier.assert_not_called()
            record = self.projection(); verifier.return_value = {"kind": "verified"}
            self.assertEqual(acceptance.verify_configured_execution(record, self.root, self.root,
                "team-one", "FEATURE-1", "TASK-1", root), {"kind": "verified"})
            self.assertEqual(verifier.call_args.args[0], Path("/opt/factory/deployment.json"))
        root = self.config(enforced="false")
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.verify_configured_execution(self.projection(), self.root, self.root,
                "team-one", "FEATURE-1", "TASK-1", root)


if __name__ == "__main__":
    unittest.main()
