#!/usr/bin/env python3
"""Version migration and sandbox-generation binding through real consumers."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "bin"), str(ROOT / "src")]
import execution_descriptor as descriptor


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runtime = load("descriptor_runtime_state", ROOT / "bin/runtime-state.py")
planner = load("descriptor_dispatch_plan", ROOT / "bin/dispatch-plan.py")
DIGEST = "sha256:" + "a" * 64


def binding():
    return {
        "schemaVersion": 1, "backend": "docker-sandboxes", "namespace": "sf-test",
        "name": "sf-" + "1" * 32, "sandboxId": "02418900-048d-44e9-86dc-9e036e546554",
        "createdAt": "2026-11-17T10:08:29+01:00", "generation": "gen-" + "2" * 32,
        "epoch": 1, "profileDigest": DIGEST, "policyDigest": DIGEST,
        "image": "registry.example.com/factory/agent@" + DIGEST,
        "inputDigest": DIGEST, "baseCommit": "3" * 40, "state": "ready",
        "acceptedCommit": None, "acceptedTree": None, "acceptedExportDigest": None,
    }


class ExecutionDescriptorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / "team-one"
        self.team = "team-one"; self.feature = "FEATURE-1"; self.task = "TASK-1"
        self.key = planner.task_key(self.task)

    def record(self):
        value = {"schemaVersion": 2, "sandbox": binding(),
                 "claimLineage": {"schemaVersion": 1}, "lineageDigest": DIGEST,
                 "modelProfile": "standard", "updatedAt": "2026-11-17T10:08:29Z"}
        value.update(descriptor.expected_execution_identity(value,
            workspace=self.workspace, team=self.team, feature=self.feature,
            task=self.task, key=self.key, role="backend", attempt=1))
        return value

    def test_legacy_version_remains_legacy_and_no_sandbox_downgrade_is_allowed(self):
        self.assertEqual(descriptor.execution_version({"schemaVersion": 1}), 1)
        self.assertEqual(descriptor.execution_extensions({"schemaVersion": 1}), frozenset())
        for version in (True, False, 0, 3, "2", None):
            with self.subTest(version=version), self.assertRaises(descriptor.ExecutionDescriptorError):
                descriptor.execution_version({"schemaVersion": version})
        for value in (None, binding(), {}):
            with self.subTest(value=value), self.assertRaises(descriptor.ExecutionDescriptorError):
                descriptor.execution_version({"schemaVersion": 1, "sandbox": value})

    def test_v2_is_closed_and_requires_immutable_lineage(self):
        value = self.record()
        self.assertEqual(descriptor.execution_version(value), 2)
        for field in ("sandbox", "claimLineage", "lineageDigest"):
            malformed = copy.deepcopy(value); del malformed[field]
            with self.subTest(field=field), self.assertRaises(descriptor.ExecutionDescriptorError):
                descriptor.execution_version(malformed)
        for field in descriptor.SANDBOX_FIELDS:
            malformed = binding(); del malformed[field]
            with self.subTest(field=field), self.assertRaises(descriptor.ExecutionDescriptorError):
                descriptor.validate_sandbox_binding(malformed)
        for field in ("hostPath", "credential", "command", "qualified"):
            malformed = binding(); malformed[field] = "untrusted"
            with self.subTest(field=field), self.assertRaises(descriptor.ExecutionDescriptorError):
                descriptor.validate_sandbox_binding(malformed)

    def test_locator_generation_object_and_profile_bindings_fail_closed(self):
        for field, invalid in (
            ("namespace", "sf-qualification"), ("namespace", "default"),
            ("name", "reusable-name"), ("generation", "gen-../other"),
            ("epoch", True), ("epoch", 0), ("sandboxId", "not-a-uuid"),
            ("createdAt", "2026-11-17"), ("inputDigest", "a" * 64),
            ("policyDigest", "sha256:bad"), ("image", "agent:latest"),
            ("baseCommit", "../HEAD"), ("state", "approved-by-guest"),
        ):
            value = binding(); value[field] = invalid
            with self.subTest(field=field, value=invalid), self.assertRaises(descriptor.ExecutionDescriptorError):
                descriptor.validate_sandbox_binding(value)

    def test_acceptance_is_all_or_nothing_and_never_inferred_from_guest_exit(self):
        record = self.record()
        with self.assertRaises(descriptor.ExecutionDescriptorError):
            descriptor.require_accepted_sandbox(record)
        record["sandbox"]["acceptedCommit"] = "4" * 40
        with self.assertRaises(descriptor.ExecutionDescriptorError):
            descriptor.execution_version(record)
        record["sandbox"].update(acceptedTree="5" * 40, acceptedExportDigest=DIGEST)
        with self.assertRaises(descriptor.ExecutionDescriptorError):
            descriptor.execution_version(record)
        record["sandbox"]["state"] = "accepted"
        self.assertEqual(descriptor.require_accepted_sandbox(record)["acceptedCommit"], "4" * 40)
        record["sandbox"]["state"] = "fenced"
        with self.assertRaises(descriptor.ExecutionDescriptorError):
            descriptor.require_accepted_sandbox(record)

    def test_shared_identity_binds_the_sandbox_without_mutating_input(self):
        record = self.record()
        expected = descriptor.expected_execution_identity(record, workspace=self.workspace,
            team=self.team, feature=self.feature, task=self.task, key=self.key)
        before = hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).digest()
        record["sandbox"]["generation"] = "gen-" + "9" * 32
        self.assertEqual(expected["sandbox"]["generation"], "gen-" + "2" * 32)
        changed = descriptor.expected_execution_identity(record, workspace=self.workspace,
            team=self.team, feature=self.feature, task=self.task, key=self.key)
        self.assertNotEqual(before, hashlib.sha256(json.dumps(changed, sort_keys=True).encode()).digest())

    def test_runtime_and_dispatch_accept_same_v2_and_reject_malformed_generations(self):
        record = self.record()
        self.assertEqual(runtime.validate_execution(record, workspace=self.workspace,
            team=self.team, feature=self.feature, task=self.task, key=self.key,
            role="backend"), (1, True))
        directory = self.workspace / "executions"; directory.mkdir(parents=True)
        path = directory / (self.key + ".json"); path.write_text(json.dumps(record))
        import os
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.assertEqual(planner.execution_identity(fd, self.workspace, self.team,
            self.feature, self.task), ("backend", 1))
        record["schemaVersion"] = 1; path.write_text(json.dumps(record))
        with self.assertRaises(SystemExit):
            runtime.validate_execution(record, workspace=self.workspace, team=self.team,
                feature=self.feature, task=self.task, key=self.key, role="backend")
        with self.assertRaises(RuntimeError):
            planner.execution_identity(fd, self.workspace, self.team, self.feature, self.task)


if __name__ == "__main__":
    unittest.main()
