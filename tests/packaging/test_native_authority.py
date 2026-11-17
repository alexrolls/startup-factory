"""Normal/uncertain authority model checks; no live qualification is issued."""
from __future__ import annotations
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/packaging")]
from startup_factory_cli import native_authority as authority
from startup_factory_cli.execution_backend import canonical_digest
from startup_factory_cli.docker_backend import OperationPermit
from startup_factory_cli.sandbox_controller import GenerationHandle
from test_docker_backend import profile


class NativeAuthorityTest(unittest.TestCase):
    def setUp(self):
        self.profile = profile()
        self.owner = object.__new__(authority.NativeRuntimeAuthority)
        self.owner.profile = self.profile
        self.owner._pid = os.getpid()
        self.owner.deployment = SimpleNamespace(digest="sha256:" + "c" * 64)
        self.owner.enrollment = SimpleNamespace(registry_id="reg-" + "d" * 32)
        self.owner.custody = SimpleNamespace(pool_blocked=False, diagnostics=lambda: {"activeClients": 0},
            journal=SimpleNamespace(records=lambda: ()), cancel_generation=mock.Mock())
        self.owner._backend = SimpleNamespace()
        self.owner._reconciliation = None
        self.owner._verify = mock.Mock()  # explicit qualified-host model, never a receipt/file
        self.owner._inventory = mock.Mock(return_value=[])
        self.record = {"name": "sf-" + "1" * 32, "generation": "gen-" + "2" * 32,
                       "epoch": 1, "state": "removed", "sandboxId": None, "createdAt": None}

    def test_constructor_cannot_accept_unvalidated_guest_data(self):
        with self.assertRaises(authority.NativeAuthorityError):
            authority.NativeRuntimeAuthority({}, {}, {}, {})

    def test_clean_start_requires_empty_inventory_and_acknowledged_history(self):
        proof = self.owner.reconcile(self.profile, self.owner.enrollment.registry_id, 1, ())
        self.owner._verify.assert_called_once_with(self.profile)
        self.owner._inventory.assert_called_once()
        self.assertTrue(proof.late_commands_quiescent)
        self.assertEqual(proof.absent_names, ())

    def test_removed_tombstones_remain_bound_and_unfinished_records_deny(self):
        proof = self.owner.reconcile(self.profile, self.owner.enrollment.registry_id, 1, (self.record,))
        self.assertEqual(proof.absent_names, (self.record["name"],))
        for state in ("fenced", "cleanup-pending", "allocated", "running"):
            with self.subTest(state=state), self.assertRaises(authority.NativeAuthorityError):
                self.owner.reconcile(self.profile, self.owner.enrollment.registry_id, 1, ({**self.record, "state": state},))

    def test_uncertain_history_or_nonempty_namespace_never_creates_barrier(self):
        self.owner.custody.pool_blocked = True
        with self.assertRaises(authority.NativeAuthorityError):
            self.owner.reconcile(self.profile, self.owner.enrollment.registry_id, 1, ())
        self.owner._inventory.assert_not_called()
        self.owner.custody.pool_blocked = False
        self.owner._inventory.return_value = [{"name": self.record["name"]}]
        with self.assertRaises(authority.NativeAuthorityError):
            self.owner.reconcile(self.profile, self.owner.enrollment.registry_id, 1, ())

    def test_cancellation_observation_cannot_become_cleanup_proof(self):
        self.owner.custody.pool_blocked = True
        self.owner.quiesce(self.profile, self.record)
        self.owner.custody.cancel_generation.assert_called_once_with(self.record["name"], self.record["generation"], 1)
        with self.assertRaises(authority.NativeAuthorityError):
            self.owner.confirm_absence(self.profile, self.record, None)
        self.owner._inventory.assert_not_called()

    def test_cleanup_requires_current_qualification_and_exact_positive_absence(self):
        self.owner._verify.side_effect = authority.NativeAuthorityError("evidence expired")
        with self.assertRaises(authority.NativeAuthorityError):
            self.owner.confirm_absence(self.profile, self.record, None)
        self.owner._verify.side_effect = None
        self.owner._inventory.return_value = [{"name": self.record["name"], "id": "x"}]
        with self.assertRaises(authority.NativeAuthorityError):
            self.owner.confirm_absence(self.profile, self.record, None)
        self.owner._inventory.return_value = []
        proof = self.owner.confirm_absence(self.profile, self.record, None)
        self.assertTrue(proof.name_and_id_absent)
        self.assertTrue(proof.storage_cleanup_verified)

    def test_policy_activation_permit_authorizes_only_fixed_policy_suboperations(self):
        handle = GenerationHandle(self.record["name"], self.record["generation"], 1)
        digest = "sha256:" + "a" * 64
        permit = OperationPermit(digest, handle.name, handle.generation, 1, digest)
        self.owner._operation = threading.local()
        self.owner._operation.binding = (digest, handle, False, "policy-activate")
        self.owner.watchdog = SimpleNamespace(operation_live=mock.Mock(return_value=True))
        intent = SimpleNamespace(name=handle.name, generation=handle.generation, epoch=1, operation="policy-allow")
        for operation in ("inspect", "policy-inspect", "policy-allow", "policy-remove-lock"):
            intent.operation = operation
            self.assertTrue(self.owner.authorize_native(self.profile, permit, intent))
        for operation in ("open-session", "credential-set", "destroy"):
            intent.operation = operation
            self.assertFalse(self.owner.authorize_native(self.profile, permit, intent))
        intent.operation = "policy-remove-lock"
        self.owner.watchdog.operation_live.return_value = False
        self.assertFalse(self.owner.authorize_native(self.profile, permit, intent))

    def test_each_native_release_requires_matching_operation_and_live_watchdog(self):
        handle = GenerationHandle(self.record["name"], self.record["generation"], 1)
        digest = "sha256:" + "a" * 64
        permit = OperationPermit(digest, handle.name, handle.generation, 1, digest)
        intent = SimpleNamespace(name=handle.name, generation=handle.generation, epoch=1, operation="open-session")
        self.owner._operation = threading.local()
        self.owner.watchdog = SimpleNamespace(operation_live=mock.Mock(return_value=True))
        self.owner._operation.binding = (digest, handle, False, "open-session")
        self.assertTrue(self.owner.authorize_native(self.profile, permit, intent))
        self.owner.watchdog.operation_live.return_value = False
        self.assertFalse(self.owner.authorize_native(self.profile, permit, intent))
        self.owner._operation.binding = (digest, handle, True, "stop")
        self.assertFalse(self.owner.authorize_native(self.profile, permit, intent))
        intent.operation = "stop"
        self.assertTrue(self.owner.authorize_native(self.profile, permit, intent))


if __name__ == "__main__":
    unittest.main()
