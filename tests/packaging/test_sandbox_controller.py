"""Pure lifecycle fixtures; run only in the assigned isolated test runner.

All runtime, root-enrollment, native journal, provisioner, and watchdog objects
are explicit fakes. No Docker invocation, target code, network, or real account
configuration is used. These fakes do not qualify the missing production parts.
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from startup_factory_cli import sandbox_controller as controller  # noqa: E402
from startup_factory_cli.execution_backend import (  # noqa: E402
    ArtifactReference, BackendIdentity, BackendObservation, DockerProfile,
    GuestCommand, LaunchScope, LaunchSpec,
)
from startup_factory_cli.sandbox_enrollment import EnrollmentReceipt, profile_basis_digest  # noqa: E402
from startup_factory_cli.sandbox_qualification import REQUIRED_CHECK_IDS  # noqa: E402
from startup_factory_cli.sandbox_registry import SandboxRegistry  # noqa: E402
from startup_factory_cli.sandbox_network_policy import ModelNetworkPolicy  # noqa: E402


DIGEST = "sha256:" + "1" * 64
CREATED = "2026-11-17T12:00:00Z"


def network_policy():
    return ModelNetworkPolicy.from_dict({"schemaVersion": 1, "namespace": "sf-fixture", "preset": "deny-all",
        "provider": "openai", "rules": [{"host": "api.openai.com:443", "method": "POST", "path": "/v1/responses"}]})


def profile() -> DockerProfile:
    return DockerProfile.from_dict({"schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1,
        "controllerUid": 501, "sbxPath": "/opt/startup-factory/sbx", "sbxSha256": "2" * 64,
        "namespace": "sf-fixture", "image": "registry.example.com/factory/agent@sha256:" + "3" * 64,
        "guestWorkdir": "/workspace/project", "limits": {"cpus": 2, "memoryMiB": 4096,
        "rootDiskMiB": 16384, "dockerDiskMiB": 16384, "wallSeconds": 1800, "maxOutputBytes": 1048576},
        "policyDigest": network_policy().digest, "qualificationDigest": "sha256:" + "5" * 64})


class FakeAuthorities:
    def __init__(self, fixture):
        self.fixture = fixture
        self.valid = True
        self.reconcile_good = True
        self.late_commands_quiescent = True
        self.clean = True
        self.provision_good = True
        self.lease_good = True
        self.wrong_lease_generation = False
        self.disarm_good = True
        self.fence_good = True
        self.live_leases = 0

    def validate_backend(self, backend, profile):
        return self.valid

    def reconcile(self, profile, registry_id, epoch, records):
        self.fixture.events.append("reconcile")
        self.fixture.assertTrue(all(record["state"] == "fenced" for record in records))
        return controller.ReconciliationProof(
            request_digest=controller.reconciliation_request_digest(profile, registry_id, epoch, records),
            evidence_digest=DIGEST, absent_names=tuple(record["name"] for record in records),
            native_clients_reaped=self.reconcile_good, late_commands_quiescent=self.late_commands_quiescent,
            namespace_exclusive=True, storage_cleanup_verified=self.clean)

    @contextlib.contextmanager
    def lease(self, profile, request, record, epoch):
        self.fixture.events.append("lease:" + request.operation)
        self.live_leases += 1
        try:
            binding = dict(record)
            if self.wrong_lease_generation:
                binding["generation"] = "gen-" + "0" * 32
            yield controller.NativeOperationLease(controller.native_lease_request_digest(request, binding, epoch), DIGEST, self.lease_good, True)
        finally:
            self.live_leases -= 1

    def provision(self, profile, backend, handle, identity, scope, manifest):
        self.fixture.events.append("provision")
        self.fixture.assertEqual(self.fixture.state(handle)["state"], "allocated")
        request = controller.provisioning_request_digest(profile, handle, identity, scope, manifest)
        return controller.AuthorityProof(request if self.provision_good else "sha256:" + "0" * 64, DIGEST)

    def arm(self, profile, handle, deadline):
        self.fixture.events.append("arm")
        self.fixture.assertIsNone(self.fixture.state(handle)["sandboxId"])
        self.fixture.assertGreater(deadline, int(time.time()))
        return controller.AuthorityProof(controller.watchdog_request_digest(profile, handle, deadline), DIGEST)

    def bind(self, handle, identity):
        self.fixture.events.append("bind-watchdog")
        return True

    def fence(self, handle):
        self.fixture.events.append("fence-watchdog")
        self.fixture.assertIn(self.fixture.state(handle)["state"], {"fenced", "cleanup-pending", "removed"})
        return self.fence_good

    def quiesce(self, profile, record):
        self.fixture.events.append("quiesce")
        return controller.AuthorityProof(controller.quiescence_request_digest(profile, record), DIGEST)

    def confirm_absence(self, profile, record, removal):
        self.fixture.events.append("confirm-absence")
        return controller.CleanupProof(request_digest=controller.cleanup_request_digest(profile, record, removal),
            evidence_digest=DIGEST, native_clients_reaped=True,
            late_commands_quiescent=self.late_commands_quiescent,
            storage_cleanup_verified=self.clean, name_and_id_absent=True)

    def disarm(self, handle, proof):
        self.fixture.events.append("disarm")
        self.fixture.assertIn(self.fixture.state(handle)["state"], {"fenced", "removing"})
        return self.disarm_good


class FakeSession:
    def __init__(self, lease):
        self.lease = lease

    def close(self):
        if self.lease is not None:
            self.lease.__exit__(None, None, None)
            self.lease = None


class FakeBackend:
    def __init__(self, fixture, authority):
        self.fixture = fixture
        self.native_client_reconciler = authority
        self.create_fails = False
        self.stop_wrong = False
        self.request_pid = os.getpid()
        self.sessions = []

    def request(self, operation, identity=None, spec=None, command=None):
        return controller.OperationRequest(operation=operation, profile_digest=self.fixture.profile.digest,
            namespace=self.fixture.profile.namespace, controller_pid=self.request_pid,
            identity=identity, launch_spec=spec, guest_command=command)

    def create(self, spec):
        self.fixture.events.append("create")
        with self.fixture.owner.operation_permit(self.fixture.profile, self.request("create", spec=spec)) as permit:
            self.fixture.assertIn("arm", self.fixture.events)
            self.fixture.assertEqual(self.fixture.state_name(permit.reserved_name)["state"], "allocated")
            if self.create_fails:
                raise OSError("fixture native client response lost")
            return BackendIdentity(permit.reserved_name, str(uuid.uuid4()), CREATED)

    def open_session(self, identity, command, *, operation="open-session", max_input_bytes=None, max_output_bytes=None):
        self.fixture.events.append(operation)
        lease = self.fixture.owner.operation_permit(self.fixture.profile, self.request(operation, identity, command=command))
        lease.__enter__()
        result = FakeSession(lease)
        self.sessions.append(result)
        self.fixture.addCleanup(result.close)
        return result

    def configure_network(self, identity, policy):
        self.fixture.events.append("policy-activate")
        with self.fixture.owner.operation_permit(self.fixture.profile, self.request("policy-activate", identity)):
            self.fixture.assertEqual(policy.digest, self.fixture.profile.policy_digest)
            return ArtifactReference(DIGEST)

    def stop(self, identity):
        self.fixture.events.append("stop")
        with self.fixture.owner.operation_permit(self.fixture.profile, self.request("stop", identity)):
            self.fixture.assertEqual(self.fixture.state_name(identity.name)["state"], "stopping")
            for session in self.sessions:
                session.close()
            return BackendObservation(identity, "running" if self.stop_wrong else "stopped")

    def destroy(self, identity):
        self.fixture.events.append("destroy")
        with self.fixture.owner.operation_permit(self.fixture.profile, self.request("destroy", identity)):
            self.fixture.assertEqual(self.fixture.state_name(identity.name)["state"], "removing")
            return ArtifactReference(DIGEST)


class SandboxControllerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-controller-", dir=os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd()))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.registry_path = self.root / "registry"
        self.registry_path.mkdir(mode=0o700)
        self.registry = SandboxRegistry(self.registry_path, "sf-fixture")
        self.addCleanup(self.registry.close)
        with self.registry.locked() as transaction:
            registry_id = transaction.registry_id
        self.profile = profile()
        info = self.registry_path.stat()
        self.receipt = EnrollmentReceipt(profile_basis_digest(self.profile), 501, "sf-fixture", str(self.registry_path), info.st_dev, info.st_ino, registry_id, int(time.time()) - 100, int(time.time()) + 3600, tuple((name, DIGEST) for name in sorted(REQUIRED_CHECK_IDS)))
        self.events = []
        self.authority = FakeAuthorities(self)
        self.backend = FakeBackend(self, self.authority)
        self.allowed = True
        self.policy = lambda action, profile, scope: self.allowed
        self.profile_patch = mock.patch.object(controller, "load_profile", return_value=self.profile)
        self.receipt_patch = mock.patch.object(controller, "load_enrollment", return_value=self.receipt)
        self.load_profile = self.profile_patch.start()
        self.load_receipt = self.receipt_patch.start()
        self.addCleanup(self.profile_patch.stop)
        self.addCleanup(self.receipt_patch.stop)
        self.owner = self.make_controller()
        self.scope = LaunchScope(DIGEST, "team-one", "FEATURE-1", "developer", "TASK-1", 1)
        self.spec = LaunchSpec(self.scope, self.profile.digest, GuestCommand(("/usr/bin/python3", "/opt/bridge.py")))

    def make_controller(self):
        return controller.SandboxController(Path("/opt/profile"), Path("/opt/receipt"), self.registry, self.backend, policy=self.policy, reconciler=self.authority, provisioner=self.authority, watchdog=self.authority)

    def state_name(self, name):
        # Reading fixture JSON avoids recursively acquiring the production lock
        # from fake callbacks invoked while the controller already owns it.
        import json
        return json.loads((self.registry_path / "registry.json").read_bytes())["records"][name]

    def state(self, handle):
        return self.state_name(handle.name)

    def ready(self):
        self.owner.start()
        handle = self.owner.allocate(self.spec)
        self.owner.configure_network(handle, network_policy())
        self.owner.provision(handle, ArtifactReference(DIGEST))
        return handle

    def test_reserve_watchdog_create_provision_activate_are_distinct(self):
        handle = self.ready()
        self.assertEqual(self.state(handle)["state"], "ready")
        self.assertLess(self.events.index("arm"), self.events.index("create"))
        self.assertLess(self.events.index("create"), self.events.index("provision"))
        with self.assertRaises(controller.ControllerError):
            self.owner.open_session(handle)
        self.owner.activate(handle)
        session = self.owner.open_session(handle)
        self.assertEqual(self.authority.live_leases, 1)
        contender = SandboxRegistry(self.registry_path, "sf-fixture")
        self.addCleanup(contender.close)
        with contender.locked() as transaction:
            self.assertEqual(transaction.epoch, handle.epoch)
        session.close()
        self.assertEqual(self.authority.live_leases, 0)
        self.owner.begin_collection(handle)
        with self.assertRaisesRegex(controller.ControllerError, "not integrated"):
            self.owner.collect_output(handle, ArtifactReference(DIGEST))

    def test_fence_precedes_native_stop_and_removal_requires_storage_absence(self):
        handle = self.ready()
        self.owner.activate(handle)
        self.owner.open_session(handle)
        self.allowed = False
        self.load_receipt.side_effect = ValueError("expired fixture receipt")
        proof = self.owner.cancel(handle)
        self.assertTrue(proof.storage_cleanup_verified)
        self.assertEqual(self.state(handle)["state"], "removed")
        self.assertLess(self.events.index("fence-watchdog"), self.events.index("quiesce"))
        self.assertLess(self.events.index("quiesce"), self.events.index("stop"))
        self.assertLess(self.events.index("stop"), self.events.index("destroy"))
        self.assertLess(self.events.index("confirm-absence"), self.events.index("disarm"))

    def test_ungated_backend_missing_authority_and_offline_receipt_cannot_start(self):
        del self.backend.native_client_reconciler
        with self.assertRaises(controller.ControllerError):
            self.owner.start()
        self.assertNotIn("reconcile", self.events)
        with self.assertRaises(controller.ControllerError):
            controller.SandboxController(Path("/opt/p"), Path("/opt/r"), self.registry, self.backend, policy=self.policy, reconciler=None, provisioner=self.authority, watchdog=self.authority)

    def test_missing_enrollment_does_not_initialize_an_empty_registry(self):
        empty_path = self.root / "not-enrolled"
        empty_path.mkdir(mode=0o700)
        empty = SandboxRegistry(empty_path, "sf-fixture")
        self.addCleanup(empty.close)
        owner = controller.SandboxController(Path("/opt/p"), Path("/opt/r"), empty, self.backend, policy=self.policy, reconciler=self.authority, provisioner=self.authority, watchdog=self.authority)
        self.load_receipt.side_effect = ValueError("missing root receipt")
        with self.assertRaises(controller.ControllerError):
            owner.start()
        self.assertEqual(list(empty_path.iterdir()), [])
        self.assertNotIn("reconcile", self.events)

    def test_failed_or_uncertain_create_is_permanent_and_unbound_cleanup_is_external(self):
        self.owner.start()
        self.backend.create_fails = True
        with self.assertRaises(controller.ControllerError):
            self.owner.allocate(self.spec)
        with self.registry.locked() as transaction:
            record = transaction.records()[0]
        self.assertEqual(record["state"], "cleanup-pending")
        self.assertIsNone(record["sandboxId"])
        handle = controller.GenerationHandle(record["name"], record["generation"], record["epoch"])
        with self.assertRaises(controller.ControllerError):
            self.owner.allocate(self.spec)
        self.owner.cancel(handle)
        self.assertEqual(self.state(handle)["state"], "removed")
        self.assertNotIn("stop", self.events)
        self.assertNotIn("destroy", self.events)

    def test_provision_policy_lease_and_cleanup_mismatch_remain_fenced(self):
        self.owner.start()
        handle = self.owner.allocate(self.spec)
        self.owner.configure_network(handle, network_policy())
        self.authority.provision_good = False
        with self.assertRaises(controller.ControllerError):
            self.owner.provision(handle, ArtifactReference(DIGEST))
        self.assertEqual(self.state(handle)["state"], "cleanup-pending")
        self.authority.clean = False
        with self.assertRaises(controller.ControllerError):
            self.owner.cancel(handle)
        self.assertEqual(self.state(handle)["state"], "cleanup-pending")

    def test_takeover_fences_and_removes_previous_work_without_resuming(self):
        handle = self.ready()
        replacement = self.make_controller()
        self.owner = replacement
        epoch = replacement.start()
        self.assertGreater(epoch, handle.epoch)
        self.assertEqual(self.state(handle)["state"], "removed")
        with self.assertRaises(controller.ControllerError):
            replacement.activate(handle)

    def test_external_or_changed_operation_cannot_obtain_permit(self):
        handle = self.ready()
        request = self.backend.request("create", spec=self.spec)
        with self.assertRaises(controller.ControllerError):
            with self.owner.operation_permit(self.profile, request):
                pass
        self.owner.activate(handle)
        self.authority.lease_good = False
        with self.assertRaises(controller.ControllerError):
            self.owner.open_session(handle)
        self.assertEqual(self.state(handle)["state"], "cleanup-pending")

    def test_current_policy_and_profile_change_fence_before_activation(self):
        handle = self.ready()
        self.load_profile.return_value = dataclasses.replace(self.profile, policy_digest="sha256:" + "7" * 64)
        with self.assertRaises(controller.ControllerError):
            self.owner.activate(handle)
        self.assertEqual(self.state(handle)["state"], "cleanup-pending")

    def test_runtime_request_is_bound_to_exact_current_controller_pid(self):
        handle = self.ready()
        self.owner.activate(handle)
        self.backend.request_pid = os.getpid() + 1
        with self.assertRaises(controller.ControllerError):
            self.owner.open_session(handle)
        self.assertEqual(self.state(handle)["state"], "cleanup-pending")

    def test_denied_current_policy_fences_ready_generation(self):
        handle = self.ready()
        self.allowed = False
        with self.assertRaises(controller.ControllerError):
            self.owner.activate(handle)
        self.assertEqual(self.state(handle)["state"], "cleanup-pending")
        self.assertIn("fence-watchdog", self.events)

    def test_stop_must_confirm_exact_stopped_state_before_destroy(self):
        handle = self.ready()
        self.backend.stop_wrong = True
        with self.assertRaises(controller.ControllerError):
            self.owner.cancel(handle)
        self.assertEqual(self.state(handle)["state"], "cleanup-pending")
        self.assertNotIn("destroy", self.events)

    def test_startup_failure_after_takeover_keeps_previous_record_fenced(self):
        handle = self.ready()
        self.authority.reconcile_good = False
        replacement = self.make_controller()
        with self.assertRaises(controller.ControllerError):
            replacement.start()
        self.assertEqual(self.state(handle)["state"], "fenced")

    def test_reaped_native_clients_do_not_prove_late_daemon_commands_quiescent(self):
        self.authority.late_commands_quiescent = False
        with self.assertRaises(controller.ControllerError):
            self.owner.start()
        self.assertNotIn("create", self.events)

    def test_native_provision_and_collect_streams_do_not_hold_registry_lock(self):
        self.owner.start()
        handle = self.owner.allocate(self.spec)
        self.owner.configure_network(handle, network_policy())
        command = GuestCommand(("/usr/bin/python3", "-I", "-B", "/opt/approved-provision.py"))
        native = self.owner.open_provision_session(handle, command)
        with self.registry.locked() as transaction:
            self.assertEqual(transaction.records()[0]["state"], "allocated")
        native.close()
        manifest = ArtifactReference(DIGEST)
        identity = self.owner._identity(self.state(handle))
        proof = controller.AuthorityProof(controller.provisioning_request_digest(self.profile, handle, identity, self.scope, manifest), DIGEST)
        self.owner.complete_provision(handle, manifest, proof)
        self.owner.activate(handle)
        self.owner.begin_collection(handle)
        native = self.owner.open_collection_session(handle, command)
        with self.registry.locked() as transaction:
            self.assertEqual(transaction.records()[0]["state"], "collecting")
        native.close()
        self.assertIn("provision", self.events)
        self.assertIn("collect", self.events)

    def test_model_credentials_get_identity_only_permits_and_expired_cleanup(self):
        self.owner.start()
        handle = self.owner.allocate(self.spec)
        self.owner.configure_network(handle, network_policy())
        lease = object()
        calls = []
        class Broker:
            def install(inner, profile, bound, identity, scope, *, lease, permit):
                self.assertEqual(permit.reserved_name, handle.name)
                self.assertEqual(permit.generation, handle.generation)
                self.assertEqual(bound, handle)
                self.assertEqual(scope, self.scope)
                calls.append("installed")
            def remove(inner, profile, bound, identity, prepared, *, permit):
                self.assertIs(prepared, lease)
                self.assertEqual(permit.reserved_name, handle.name)
                calls.append("removed")
        broker = Broker()
        self.owner.install_credentials(handle, broker, lease)
        self.allowed = False
        self.load_receipt.side_effect = ValueError("fixture enrollment expired")
        self.owner.remove_credentials(handle, broker, lease)
        self.assertEqual(calls, ["installed", "removed"])

    def test_network_activation_is_required_before_any_source_or_model_scope(self):
        self.owner.start()
        handle = self.owner.allocate(self.spec)
        command = GuestCommand(("/usr/bin/true",))
        broker = mock.Mock()
        for action in (lambda: self.owner.open_provision_session(handle, command),
                       lambda: self.owner.provision(handle, ArtifactReference(DIGEST)),
                       lambda: self.owner.install_credentials(handle, broker, object())):
            with self.assertRaisesRegex(controller.ControllerError, "network activation"):
                action()
        self.assertNotIn("provision", self.events)
        broker.install.assert_not_called()
        receipt = self.owner.configure_network(handle, network_policy())
        self.assertIsInstance(receipt, ArtifactReference)
        self.owner.open_provision_session(handle, command).close()
        self.assertLess(self.events.index("policy-activate"), self.events.index("provision"))

    def test_policy_for_another_profile_cannot_unlock_provisioning(self):
        self.owner.start()
        handle = self.owner.allocate(self.spec)
        changed = ModelNetworkPolicy.from_dict({**network_policy().as_dict(), "namespace": "sf-other"})
        with self.assertRaises(controller.ControllerError):
            self.owner.configure_network(handle, changed)
        with self.assertRaises(controller.ControllerError):
            self.owner.open_provision_session(handle, GuestCommand(("/usr/bin/true",)))
        self.assertNotIn("policy-activate", self.events)

    def test_native_lease_from_other_generation_cannot_authorize_create(self):
        self.owner.start()
        self.authority.wrong_lease_generation = True
        with self.assertRaises(controller.ControllerError):
            self.owner.allocate(self.spec)
        with self.registry.locked() as transaction:
            self.assertEqual(transaction.records()[0]["state"], "cleanup-pending")

    def test_failed_watchdog_disarm_remains_visible_to_restart_reconciliation(self):
        handle = self.ready()
        self.authority.disarm_good = False
        with self.assertRaises(controller.ControllerError):
            self.owner.cancel(handle)
        self.assertEqual(self.state(handle)["state"], "cleanup-pending")
        replacement = self.make_controller()
        self.owner = replacement
        replacement.start()
        self.assertEqual(self.state(handle)["state"], "removed")

    def test_failed_independent_fencing_is_reported_as_unconfirmed(self):
        handle = self.ready()
        self.allowed = False
        self.authority.fence_good = False
        with self.assertRaisesRegex(controller.ControllerError, "revocation is unconfirmed"):
            self.owner.activate(handle)
        self.assertEqual(self.state(handle)["state"], "cleanup-pending")


if __name__ == "__main__":
    unittest.main()
