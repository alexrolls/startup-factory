"""Model broker fixtures; no real keys, Docker API, network or root file writes."""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import sys
import tempfile
import threading
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))
from test_sandbox_deployment import deployment_data, profile_data, DIGEST  # noqa: E402
from startup_factory_cli.execution_backend import BackendIdentity, DockerProfile, LaunchScope, canonical_digest  # noqa: E402
from startup_factory_cli.sandbox_controller import GenerationHandle  # noqa: E402
from startup_factory_cli.sandbox_deployment import Deployment, canonical_bytes, DeploymentError  # noqa: E402
from startup_factory_cli import model_credentials as credentials  # noqa: E402


class FixedManager:
    def __init__(self):
        self.calls = []; self.fail = False; self.buffers = []

    def run_credential(self, profile, permit, *, operation, service, secret=None):
        self.calls.append({"profile": profile.digest, "permit": permit, "operation": operation, "service": service,
            "input": bytes(secret) if secret is not None else None})
        if secret is not None:
            self.buffers.append(secret)
        if self.fail:
            raise RuntimeError("fixed native failure")
        return canonical_digest({"operation": operation, "provider": service, "name": "fixed"})


class ModelCredentialTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-model-credential-", dir=os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd()))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.root.chmod(0o700)
        self.profile = DockerProfile.from_dict(profile_data(os.geteuid()))
        value = deployment_data(self.profile, str(self.root))
        value["modelCredentials"] = {"providers": {"openai": {"sourceFile": str(self.root / "protected/openai.key")}}, "roles": {"developer": "openai"}}
        self.deployment = Deployment(self.root / "deployment.json", canonical_bytes(value))
        selected = Path(self.deployment.credential_root); selected.mkdir(parents=True, mode=0o700)
        selected.parent.chmod(0o700); selected.parent.parent.chmod(0o700)
        self.manager = FixedManager()
        self.broker = credentials.ScopedModelCredentials(self.deployment, self.manager)
        self.addCleanup(self.broker.close)
        self.handle = GenerationHandle("sf-" + "1" * 32, "gen-" + "2" * 32, 1)
        self.identity = BackendIdentity(self.handle.name, "11111111-2222-3333-4444-555555555555", "2026-11-17T00:00:00Z")
        self.scope = LaunchScope(DIGEST, "fixture", "feature", "developer", "task", 1)
        self.permit = object()
        patch = mock.patch.object(credentials, "load_deployment", return_value=self.deployment)
        patch.start(); self.addCleanup(patch.stop)
        self.dummy = b"dummy-only-not-a-real-model-key\n"

    def install(self, lease):
        with mock.patch.object(credentials, "_source", side_effect=lambda *_args: bytearray(self.dummy)):
            return self.broker.install(self.profile, self.handle, self.identity, self.scope, lease=lease, permit=self.permit)

    def test_prepare_precedes_any_source_or_native_effect_and_retains_exact_scope(self):
        with mock.patch.object(credentials, "_source", side_effect=AssertionError("secret read before durable intent")):
            lease = self.broker.prepare(self.profile, self.handle, self.identity, self.scope)
        self.assertEqual(self.manager.calls, [])
        self.assertEqual(self.broker.records()[0]["state"], "prepared")
        self.assertEqual(lease.scope_digest, canonical_digest(self.scope.as_dict()))
        self.assertEqual(self.broker.prepare(self.profile, self.handle, self.identity, self.scope), lease)
        with self.assertRaises(credentials.ModelCredentialError):
            self.broker.prepare(self.profile, self.handle, self.identity, dataclasses.replace(self.scope, task_id="other"))

    def test_install_and_remove_are_scoped_stable_and_never_journal_secret_or_input_hash(self):
        lease = self.broker.prepare(self.profile, self.handle, self.identity, self.scope)
        receipt = self.install(lease)
        self.assertEqual(self.manager.calls[0]["operation"], "credential-set")
        self.assertEqual(self.manager.calls[0]["service"], "openai")
        self.assertEqual(self.manager.calls[0]["input"], self.dummy)
        self.assertEqual(bytes(self.manager.buffers[0]), b"\0" * len(self.dummy))
        # Exact acknowledged retry does not re-read a rotated source or set again.
        with mock.patch.object(credentials, "_source", side_effect=AssertionError("duplicate secret read")):
            self.assertEqual(self.broker.install(self.profile, self.handle, self.identity, self.scope, lease=lease, permit=self.permit), receipt)
        removed = self.broker.remove(self.profile, self.handle, self.identity, lease, permit=self.permit)
        self.assertEqual(self.broker.remove(self.profile, self.handle, self.identity, lease, permit=self.permit), removed)
        self.assertEqual([call["operation"] for call in self.manager.calls], ["credential-set", "credential-remove"])
        ledger = (Path(self.deployment.credential_root) / credentials.STATE_FILE).read_bytes()
        self.assertNotIn(self.dummy.strip(), ledger)
        self.assertNotIn(hashlib.sha256(self.dummy).hexdigest().encode(), ledger)
        self.assertNotIn(b"sourceFile", ledger)
        self.assertEqual(self.broker.records()[0]["state"], "removed")
        self.broker.assert_ready()

    def test_missing_model_mapping_denies_real_agent_but_explicit_validation_uses_no_key(self):
        scope = dataclasses.replace(self.scope, role="validator")
        with self.assertRaises(credentials.ModelCredentialError):
            self.broker.prepare(self.profile, self.handle, self.identity, scope)
        lease = self.broker.prepare(self.profile, self.handle, self.identity, scope, require_model=False)
        with mock.patch.object(credentials, "_source", side_effect=AssertionError("validation read a key")):
            self.broker.install(self.profile, self.handle, self.identity, scope, lease=lease, permit=self.permit)
            self.broker.remove(self.profile, self.handle, self.identity, lease, permit=self.permit)
        self.assertEqual(self.manager.calls, [])

    def test_partial_native_install_keeps_cleanup_intent_and_blocks_dispatch(self):
        lease = self.broker.prepare(self.profile, self.handle, self.identity, self.scope)
        self.manager.fail = True
        with self.assertRaises(RuntimeError):
            self.install(lease)
        self.assertEqual(self.broker.records()[0]["state"], "install-uncertain")
        with self.assertRaises(credentials.ModelCredentialError):
            self.broker.assert_ready()
        self.manager.fail = False
        self.broker.remove(self.profile, self.handle, self.identity, lease, permit=self.permit)
        self.broker.assert_ready()

    def test_cleanup_still_runs_after_post_set_journal_failure_without_reading_source(self):
        lease = self.broker.prepare(self.profile, self.handle, self.identity, self.scope)
        save = self.broker._save
        def fail_installed(transaction, state):
            if any(record["state"] == "installed" for record in state["leases"].values()):
                self.broker._poisoned = True
                raise OSError("fixed metadata interruption")
            return save(transaction, state)
        with mock.patch.object(self.broker, "_save", side_effect=fail_installed):
            with self.assertRaises(credentials.ModelCredentialError):
                self.install(lease)
        with mock.patch.object(credentials, "_source", side_effect=AssertionError("cleanup reads a model key")):
            with self.assertRaises(credentials.ModelCredentialError):
                self.broker.remove(self.profile, self.handle, self.identity, lease, permit=self.permit)
        self.assertEqual(self.manager.calls[-1]["operation"], "credential-remove")

    def test_reopen_keeps_unresolved_intent_and_cannot_reset_missing_history(self):
        lease = self.broker.prepare(self.profile, self.handle, self.identity, self.scope)
        reopened = credentials.ScopedModelCredentials(self.deployment, self.manager)
        self.addCleanup(reopened.close)
        with self.assertRaises(credentials.ModelCredentialError):
            reopened.assert_ready()
        # Current trusted cleanup can re-epoch a fenced generation, never change ID.
        handle = dataclasses.replace(self.handle, epoch=2)
        reopened.remove(self.profile, handle, self.identity, lease, permit=self.permit)
        reopened.assert_ready()
        (Path(self.deployment.credential_root) / credentials.STATE_FILE).unlink()
        with self.assertRaises(credentials.ModelCredentialError):
            credentials.ScopedModelCredentials(self.deployment, self.manager)

    def test_wrong_generation_identity_scope_or_retired_install_is_denied(self):
        lease = self.broker.prepare(self.profile, self.handle, self.identity, self.scope)
        for handle, identity, scope in ((dataclasses.replace(self.handle, epoch=2), self.identity, self.scope),
                (self.handle, dataclasses.replace(self.identity, sandbox_id="22222222-2222-3333-4444-555555555555"), self.scope),
                (self.handle, self.identity, dataclasses.replace(self.scope, task_id="other"))):
            with self.assertRaises(credentials.ModelCredentialError):
                self.broker.install(self.profile, handle, identity, scope, lease=lease, permit=self.permit)
        self.broker.remove(self.profile, self.handle, self.identity, lease, permit=self.permit)
        with self.assertRaises(credentials.ModelCredentialError):
            self.install(lease)
        self.assertFalse(any(call["operation"] == "credential-set" for call in self.manager.calls))

    def test_model_allowlist_never_accepts_github_registry_tracker_or_commands(self):
        for service in ("github", "registry", "linear", "anthropic"):
            value = self.deployment.as_dict(); value["modelCredentials"]["providers"] = {service: {"sourceFile": "/Library/private/model.key"}}
            value["modelCredentials"]["roles"] = {"developer": service}
            with self.assertRaises(DeploymentError):
                Deployment(self.deployment.source_path, canonical_bytes(value))
        value = self.deployment.as_dict(); value["modelCredentials"]["providers"]["openai"]["command"] = "gh auth token"
        with self.assertRaises(DeploymentError):
            Deployment(self.deployment.source_path, canonical_bytes(value))

    def test_source_refuses_controller_owned_credential_locations(self):
        # Real root-owned source success requires privileged installation; this
        # fixture verifies that controller-owned data can never become a source.
        selected = self.root / "not-root.key"; selected.write_bytes(self.dummy); selected.chmod(0o640)
        with self.assertRaises(credentials.ModelCredentialError):
            credentials._source(selected, self.deployment)
        selected.unlink(); selected.symlink_to(self.root / "outside")
        with self.assertRaises((credentials.ModelCredentialError, OSError)):
            credentials._source(selected, self.deployment)

    def test_source_content_bounds_and_links_use_real_dirfd_io_with_only_root_metadata_mocked(self):
        selected = self.root / "fixture.key"; selected.write_bytes(self.dummy); selected.chmod(0o640)
        # Ownership/access are the explicit privileged test seam; all no-follow
        # opens, link counts, byte limits and read stability below are real.
        actual = os
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        def root_metadata(info):
            return SimpleNamespace(**{key: 0 if key == "st_uid" else getattr(info, key) for key in fields})
        operations = SimpleNamespace(**vars(actual))
        operations.fstat = lambda descriptor: root_metadata(actual.fstat(descriptor))
        operations.stat = lambda *args, **kwargs: root_metadata(actual.stat(*args, **kwargs))
        operations.access = lambda *_args, **_kwargs: False
        with mock.patch.object(credentials, "os", operations):
            raw = credentials._source(selected, self.deployment)
            self.assertEqual(raw, self.dummy)
            for body in (b"", b"two\nlines\n", b"token\0value", b"x" * credentials.MAX_SECRET_BYTES):
                selected.write_bytes(body)
                with self.assertRaises(credentials.ModelCredentialError):
                    credentials._source(selected, self.deployment)
            selected.write_bytes(self.dummy)
            selected.chmod(0o644)
            with self.assertRaises(credentials.ModelCredentialError):
                credentials._source(selected, self.deployment)
            selected.chmod(0o640)
            hard = self.root / "hard.key"; actual.link(selected, hard)
            with self.assertRaises(credentials.ModelCredentialError):
                credentials._source(selected, self.deployment)
            hard.unlink(); selected.unlink(); selected.symlink_to(self.root / "outside")
            with self.assertRaises(OSError):
                credentials._source(selected, self.deployment)

    def test_interrupted_pending_ledger_refuses_reopen(self):
        pending = Path(self.deployment.credential_root) / credentials.PENDING_FILE
        pending.write_bytes(b"incomplete"); pending.chmod(0o600)
        with self.assertRaises(credentials.ModelCredentialError):
            credentials.ScopedModelCredentials(self.deployment, self.manager)


if __name__ == "__main__":
    unittest.main()
