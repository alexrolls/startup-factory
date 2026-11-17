"""Enrollment fixtures; execute only in the assigned isolated test runner."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from startup_factory_cli import sandbox_enrollment as enrollment  # noqa: E402
from startup_factory_cli.execution_backend import DockerProfile  # noqa: E402
from startup_factory_cli.sandbox_qualification import REQUIRED_CHECK_IDS  # noqa: E402
from startup_factory_cli.sandbox_registry import SandboxRegistry  # noqa: E402


NOW = 1800000000


def profile_data() -> dict:
    return {"schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1,
            "controllerUid": 501, "sbxPath": "/opt/startup-factory/sbx", "sbxSha256": "2" * 64,
            "namespace": "sf-fixture", "image": "registry.example.com/factory/agent@sha256:" + "3" * 64,
            "guestWorkdir": "/workspace/project", "limits": {"cpus": 2, "memoryMiB": 4096,
            "rootDiskMiB": 16384, "dockerDiskMiB": 16384, "wallSeconds": 1800, "maxOutputBytes": 1048576},
            "policyDigest": "sha256:" + "4" * 64, "qualificationDigest": "sha256:" + "0" * 64}


class SandboxEnrollmentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-enrollment-", dir=os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd()))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.path = self.root / "registry"
        self.path.mkdir(mode=0o700)
        self.registry = SandboxRegistry(self.path, "sf-fixture")
        self.addCleanup(self.registry.close)
        with self.registry.locked() as transaction:
            registry_id = transaction.registry_id
        info = self.path.stat()
        self.profile = DockerProfile.from_dict(profile_data())
        self.data = {
            "schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1,
            "profileBasisDigest": enrollment.profile_basis_digest(self.profile),
            "controllerUid": 501, "namespace": "sf-fixture", "dedicatedAccount": True,
            "exclusiveNamespace": True, "registry": {"root": str(self.path), "device": info.st_dev,
            "inode": info.st_ino, "registryId": registry_id}, "issuedAt": NOW - 100,
            "expiresAt": NOW + 100, "checks": {name: {"passed": True, "evidenceDigest": "sha256:" + "6" * 64} for name in REQUIRED_CHECK_IDS},
        }
        self.raw = json.dumps(self.data, separators=(",", ":")).encode()
        self.profile = dataclasses.replace(self.profile, qualification_digest="sha256:" + hashlib.sha256(self.raw).hexdigest())
        self.reader = mock.patch.object(enrollment, "_read_protected", return_value=(self.raw, hashlib.sha256(self.raw).hexdigest()))
        self.reader_mock = self.reader.start()
        self.addCleanup(self.reader.stop)
        # Keep the real registry's account/dirfd checks intact. Only enrollment's
        # current UID is a fixture; production uses the actual os module.
        patch = mock.patch.object(enrollment, "os", SimpleNamespace(geteuid=lambda: 501, fstat=os.fstat, stat=os.stat))
        patch.start()
        self.addCleanup(patch.stop)

    def load(self, **kwargs):
        return enrollment.load_enrollment(self.profile, Path("/opt/startup-factory/enrollment.json"), self.registry, now=NOW, **kwargs)

    def altered(self, mutate) -> None:
        data = copy.deepcopy(self.data)
        mutate(data)
        self.raw = json.dumps(data).encode()
        self.profile = dataclasses.replace(self.profile, qualification_digest="sha256:" + hashlib.sha256(self.raw).hexdigest())
        self.reader_mock.return_value = self.raw, hashlib.sha256(self.raw).hexdigest()

    def test_receipt_bytes_and_profile_basis_bind_without_digest_cycle(self) -> None:
        receipt = self.load()
        self.assertEqual(receipt.as_dict(), self.data)
        self.assertEqual(enrollment.profile_basis_digest(self.profile), self.data["profileBasisDigest"])
        changed_receipt = dataclasses.replace(self.profile, qualification_digest="sha256:" + "7" * 64)
        self.assertEqual(enrollment.profile_basis_digest(changed_receipt), enrollment.profile_basis_digest(self.profile))
        changed_policy = dataclasses.replace(self.profile, policy_digest="sha256:" + "7" * 64)
        self.assertNotEqual(enrollment.profile_basis_digest(changed_policy), enrollment.profile_basis_digest(self.profile))
        with self.registry.locked() as transaction:
            self.assertEqual(self.load(transaction=transaction), receipt)

    def test_all_mandatory_gates_and_closed_fields_are_required(self) -> None:
        for name in REQUIRED_CHECK_IDS:
            data = copy.deepcopy(self.data)
            del data["checks"][name]
            with self.subTest(name=name), self.assertRaises(enrollment.EnrollmentError):
                enrollment.EnrollmentReceipt.from_dict(data)
            data = copy.deepcopy(self.data)
            data["checks"][name]["passed"] = False
            with self.assertRaises(enrollment.EnrollmentError):
                enrollment.EnrollmentReceipt.from_dict(data)
        invalid = [
            {**self.data, "enabled": True}, {**self.data, "controllerUid": 0},
            {**self.data, "controllerUid": True}, {**self.data, "namespace": "sf-qualification"},
            {**self.data, "dedicatedAccount": False}, {**self.data, "exclusiveNamespace": 1},
            {**self.data, "expiresAt": self.data["issuedAt"]},
            {**self.data, "checks": {**self.data["checks"], "extra": {"passed": True, "evidenceDigest": "sha256:" + "6" * 64}}},
        ]
        for value in invalid:
            with self.subTest(value=str(value)[:80]), self.assertRaises(enrollment.EnrollmentError):
                enrollment.EnrollmentReceipt.from_dict(value)

    def test_duplicate_deep_nonfinite_and_nonunicode_json_are_rejected(self) -> None:
        for raw in (self.raw[:-1] + b',"schemaVersion":1}', b'{"schemaVersion":NaN}', b"[" * 30 + b"0" + b"]" * 30, b"\xff", b"{}"):
            with self.subTest(raw=raw[:40]), self.assertRaises(enrollment.EnrollmentError):
                enrollment.parse_receipt(raw)

    def test_expiry_issue_time_and_raw_digest_are_checked(self) -> None:
        for now in (NOW - 101, NOW + 100):
            with self.subTest(now=now), self.assertRaises(enrollment.EnrollmentError):
                enrollment.load_enrollment(self.profile, Path("/opt/receipt"), self.registry, now=now)
        self.reader_mock.return_value = self.raw + b" ", hashlib.sha256(self.raw + b" ").hexdigest()
        with self.assertRaises(enrollment.EnrollmentError):
            self.load()

    def test_profile_uid_namespace_root_inode_and_registry_id_are_pinned(self) -> None:
        changes = [
            lambda value: value.update(profileBasisDigest="sha256:" + "8" * 64),
            lambda value: value.update(controllerUid=502),
            lambda value: value.update(namespace="sf-other"),
            lambda value: value["registry"].update(root=str(self.root / "other")),
            lambda value: value["registry"].update(inode=self.path.stat().st_ino + 1),
            lambda value: value["registry"].update(registryId="reg-" + "0" * 32),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.altered(change)
                with self.assertRaises(enrollment.EnrollmentError):
                    self.load()

    def test_root_reader_failure_and_missing_registry_marker_do_not_initialize(self) -> None:
        self.reader_mock.side_effect = enrollment.BackendContractError("unsafe root ownership")
        with self.assertRaises(enrollment.EnrollmentError):
            self.load()
        self.reader_mock.side_effect = None
        (self.path / "registry.identity").unlink()
        state = (self.path / "registry.json").read_bytes()
        with self.assertRaises(enrollment.EnrollmentError):
            self.load()
        self.assertFalse((self.path / "registry.identity").exists())
        self.assertEqual((self.path / "registry.json").read_bytes(), state)


if __name__ == "__main__":
    unittest.main()
