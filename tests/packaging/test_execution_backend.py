from __future__ import annotations

import contextlib
import copy
import dataclasses
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import execution_backend as backend  # noqa: E402


DIGEST = "sha256:" + "1" * 64
IDENTITY = {"name": "sf-task-one", "sandboxId": "d9f44bce-019d-43c3-b8c2-dcf7ac05258b",
            "createdAt": "2026-11-16T23:52:57+01:00"}
SCOPE = {"projectId": DIGEST, "team": "feature-one", "featureId": "FEATURE-1",
         "role": "backend", "taskId": "TASK-1", "attempt": 1}


def profile_data() -> dict:
    return {"schemaVersion": 1, "backend": "docker-sandboxes", "protocolVersion": 1,
            "controllerUid": 501, "sbxPath": "/opt/startup-factory/sbx", "sbxSha256": "2" * 64,
            "namespace": "sf-test", "image": "registry.example.com/factory/agent@sha256:" + "3" * 64,
            "guestWorkdir": "/workspace/project",
            "limits": {"cpus": 2, "memoryMiB": 4096, "rootDiskMiB": 16384,
                       "dockerDiskMiB": 16384, "wallSeconds": 1800, "maxOutputBytes": 1048576},
            "policyDigest": "sha256:" + "4" * 64, "qualificationDigest": "sha256:" + "5" * 64}


class BackendDataContractTest(unittest.TestCase):
    def test_valid_profile_round_trip_has_bindings_but_no_authorization_flags(self) -> None:
        data = profile_data()
        profile = backend.parse_profile(json.dumps(data).encode())
        self.assertEqual(profile.as_dict(), data)
        self.assertEqual(profile.digest, backend.canonical_digest(data))
        for name in ("ready", "qualified", "enrolled", "autonomous_ready", "enabled"):
            self.assertFalse(hasattr(profile, name))
        exported = profile.as_dict()
        exported["limits"]["cpus"] = 9
        self.assertEqual(profile.limits.cpus, 2)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            profile.namespace = "sf-mutated"

    def test_example_is_syntactically_valid_without_asserting_enrollment(self) -> None:
        profile = backend.parse_profile((ROOT / "config/sandbox.config.example.json").read_bytes())
        self.assertEqual(profile.qualification_digest, "sha256:" + "0" * 64)
        self.assertEqual(profile.sbx_sha256, "0" * 64)
        self.assertFalse(hasattr(profile, "qualified"))

    def test_schema_and_python_contract_have_the_same_closed_fields_and_limits(self) -> None:
        schema = json.loads((ROOT / "config/sandbox.schema.json").read_bytes())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), backend.PROFILE_FIELDS)
        self.assertEqual(set(schema["properties"]), backend.PROFILE_FIELDS)
        limits = schema["properties"]["limits"]
        self.assertFalse(limits["additionalProperties"])
        self.assertEqual(set(limits["required"]), set(backend.LIMIT_BOUNDS))
        for name, (minimum, maximum) in backend.LIMIT_BOUNDS.items():
            self.assertEqual(limits["properties"][name]["minimum"], minimum)
            self.assertEqual(limits["properties"][name]["maximum"], maximum)
        path_pattern = re.compile(schema["properties"]["sbxPath"]["pattern"])
        self.assertIsNotNone(path_pattern.fullmatch(profile_data()["sbxPath"]))
        for path in ("/.", "/..", "/a/../sbx", "/a//sbx", "/a\\sbx", "/a\nsbx"):
            self.assertIsNone(path_pattern.fullmatch(path))
        image_pattern = re.compile(schema["properties"]["image"]["pattern"])
        self.assertIsNotNone(image_pattern.fullmatch(profile_data()["image"]))
        self.assertIsNone(image_pattern.fullmatch("localhost/image@" + DIGEST))

    def test_unknown_secret_environment_endpoint_or_enablement_fields_are_rejected(self) -> None:
        for key, value in (
            ("env", {"GH_TOKEN": "dummy"}), ("credentials", "dummy"),
            ("apiKey", "dummy"), ("dockerHost", "unix:///run/docker.sock"),
            ("endpoint", "https://example.com"), ("argv", ["/bin/sh"]),
            ("enabled", True), ("qualified", True), ("autonomousReady", True),
        ):
            data = profile_data()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(backend.BackendContractError):
                backend.DockerProfile.from_dict(data)

    def test_missing_fields_and_unknown_versions_are_rejected(self) -> None:
        for field in backend.PROFILE_FIELDS:
            data = profile_data()
            del data[field]
            with self.subTest(field=field), self.assertRaises(backend.BackendContractError):
                backend.DockerProfile.from_dict(data)
        for field, value in (("schemaVersion", 2), ("schemaVersion", True),
                             ("protocolVersion", 2), ("backend", "native")):
            data = profile_data()
            data[field] = value
            with self.subTest(field=field), self.assertRaises(backend.BackendContractError):
                backend.DockerProfile.from_dict(data)

    def test_namespace_is_dedicated_bounded_and_not_operator_qualification_namespace(self) -> None:
        for namespace in ("default", "personal", "sf-qualification", "sf-", "sf-a/other",
                          "sf-" + "a" * 18, "sf-evil;command", "sf-UPPER"):
            data = profile_data()
            data["namespace"] = namespace
            with self.subTest(namespace=namespace), self.assertRaises(backend.BackendContractError):
                backend.DockerProfile.from_dict(data)

    def test_runtime_and_guest_paths_require_normalized_absolute_values(self) -> None:
        for path in ("sbx", "~/bin/sbx", "https://example.com/sbx", "unix:///run/sbx",
                     "/opt/../bin/sbx", "/opt/./sbx", "/opt//sbx", "//server/sbx",
                     "/opt/sbx/", "/opt/sbx\n", "/opt\\sbx"):
            data = profile_data()
            data["sbxPath"] = path
            with self.subTest(path=path), self.assertRaises(backend.BackendContractError):
                backend.DockerProfile.from_dict(data)
        data = profile_data()
        data["guestWorkdir"] = "/Users/operator/project"
        with self.assertRaises(backend.BackendContractError):
            backend.DockerProfile.from_dict(data)

    def test_image_is_explicit_canonical_and_digest_pinned(self) -> None:
        for image in (
            "python:latest", "python@" + DIGEST, "registry.example.com/factory/agent:latest",
            "registry.example.com/factory/agent:tag@" + DIGEST,
            "https://registry.example.com/factory/agent@" + DIGEST,
            "operator:password@registry.example.com/image@" + DIGEST,
            "registry.example.com/image@sha256:" + "A" * 64,
            "registry.example.com/image@sha256:123", "127.0.0.1/image@" + DIGEST,
            "localhost/image@" + DIGEST, "registry.example.com:65536/image@" + DIGEST,
            "registry.-bad.example/image@" + DIGEST, "registry.example.com/a/../image@" + DIGEST,
        ):
            data = profile_data()
            data["image"] = image
            with self.subTest(image=image), self.assertRaises(backend.BackendContractError):
                backend.DockerProfile.from_dict(data)

    def test_every_limit_rejects_booleans_nonfinite_negative_and_oversized_values(self) -> None:
        for name, (minimum, maximum) in backend.LIMIT_BOUNDS.items():
            for value in (True, False, float("nan"), float("inf"), -1, minimum - 1, maximum + 1, "2", 2.0):
                data = profile_data()
                data["limits"][name] = value
                with self.subTest(name=name, value=value), self.assertRaises(backend.BackendContractError):
                    backend.DockerProfile.from_dict(data)
        data = profile_data()
        data["limits"]["extra"] = 1
        with self.assertRaises(backend.BackendContractError):
            backend.DockerProfile.from_dict(data)

    def test_controller_and_digest_types_fail_closed(self) -> None:
        for key, values in {
            "controllerUid": (0, -1, True, "501"),
            "sbxSha256": ("sha256:" + "1" * 64, "A" * 64, ""),
            "policyDigest": ("0" * 64, "sha256:" + "A" * 64),
            "qualificationDigest": ("yes", None, True),
        }.items():
            for value in values:
                data = profile_data()
                data[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(backend.BackendContractError):
                    backend.DockerProfile.from_dict(data)

    def test_strict_json_rejects_duplicates_nonfinite_invalid_encoding_and_depth(self) -> None:
        valid = json.dumps(profile_data()).encode()
        for raw in (
            valid[:-1] + b',"namespace":"sf-duplicate"}', b"NaN", b"Infinity",
            b'{"a":1e999}', b"\xff", b"{} trailing", b"[]", b"null",
            b'{"a":' + b"[" * 9 + b"0" + b"]" * 9 + b"}",
            b'{"a":"\\ud800"}', b"x" * (backend.MAX_PROFILE_BYTES + 1), b"",
        ):
            with self.subTest(raw=raw[:40]), self.assertRaises(backend.BackendContractError):
                backend.parse_profile(raw)

    def test_digest_binds_all_mutable_fields_and_is_order_independent(self) -> None:
        initial = profile_data()
        expected = backend.DockerProfile.from_dict(initial).digest
        reversed_data = dict(reversed(list(initial.items())))
        self.assertEqual(backend.DockerProfile.from_dict(reversed_data).digest, expected)
        for key, value in (
            ("controllerUid", 502), ("sbxPath", "/opt/factory/other-sbx"),
            ("sbxSha256", "6" * 64), ("namespace", "sf-other"),
            ("image", "registry.example.com/factory/other@sha256:" + "7" * 64),
            ("policyDigest", "sha256:" + "8" * 64),
            ("qualificationDigest", "sha256:" + "9" * 64),
        ):
            changed = copy.deepcopy(initial)
            changed[key] = value
            with self.subTest(key=key):
                self.assertNotEqual(backend.DockerProfile.from_dict(changed).digest, expected)
        for name in backend.LIMIT_BOUNDS:
            changed = copy.deepcopy(initial)
            changed["limits"][name] += 1
            with self.subTest(limit=name):
                self.assertNotEqual(backend.DockerProfile.from_dict(changed).digest, expected)

    def test_identity_and_scope_are_closed_and_preserve_exact_generations(self) -> None:
        identity = backend.BackendIdentity.from_dict(IDENTITY)
        self.assertEqual(identity.as_dict(), IDENTITY)
        precise = dict(IDENTITY, createdAt="2026-11-16T23:52:57.123456789+01:00")
        self.assertEqual(backend.BackendIdentity.from_dict(precise).created_at, precise["createdAt"])
        scope = backend.LaunchScope.from_dict(SCOPE)
        self.assertEqual(scope.as_dict(), SCOPE)
        for field, value in (("sandboxId", IDENTITY["sandboxId"].upper()), ("createdAt", "2026-11-16"),
                             ("createdAt", "2026-02-30T00:00:00Z"), ("createdAt", "2026-11-16T00:00:00+00:99"),
                             ("name", "--all"), ("extra", True)):
            data = dict(IDENTITY)
            data[field] = value
            with self.subTest(field=field), self.assertRaises(backend.BackendContractError):
                backend.BackendIdentity.from_dict(data)
        for fields in ({"projectId": "repo"}, {"attempt": True}, {"taskId": "-"},
                       {"attempt": 0}, {"team": ".."}, {"role": "--all"}, {"extra": True}):
            data = dict(SCOPE)
            data.update(fields)
            with self.subTest(fields=fields), self.assertRaises(backend.BackendContractError):
                backend.LaunchScope.from_dict(data)
        gate = dict(SCOPE, taskId="-", attempt=0)
        self.assertEqual(backend.LaunchScope.from_dict(gate).attempt, 0)

    def test_guest_commands_are_literal_bounded_data_without_host_execution(self) -> None:
        command = backend.GuestCommand(("/usr/bin/python3", "-c", "literal ; $(data)"))
        self.assertEqual(backend.GuestCommand.from_dict(command.as_dict()), command)
        for argv in (["/bin/true"], (), ("python3",), ("/bin/../true",), ("/bin/true", "bad\narg"),
                     tuple(["/bin/true"] + ["x"] * 128)):
            with self.subTest(argv=argv), self.assertRaises(backend.BackendContractError):
                backend.GuestCommand(argv)
        with self.assertRaises(backend.BackendContractError):
            backend.GuestCommand.from_dict({"argv": ["/bin/true"], "env": {}})
        spec = backend.LaunchSpec(backend.LaunchScope.from_dict(SCOPE), DIGEST, command)
        self.assertEqual(spec.command.argv, command.argv)
        self.assertEqual(backend.ArtifactReference(DIGEST).digest, DIGEST)
        self.assertFalse(hasattr(backend.BackendProbe(1, ("observation only",)), "ready"))
        for state in ("unknown", [], True):
            with self.subTest(state=state), self.assertRaises(backend.BackendContractError):
                backend.BackendObservation(backend.BackendIdentity.from_dict(IDENTITY), state)


class ProtectedProfileLoadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sf-profile-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.runtime = self.root / "sbx"
        self.runtime.write_bytes(b"pinned binary fixture, never execute\n")
        self.runtime.chmod(0o755)
        self.path = self.root / "profile.json"
        self.data = profile_data()
        self.data["sbxPath"] = str(self.runtime)
        self.data["sbxSha256"] = hashlib.sha256(self.runtime.read_bytes()).hexdigest()
        self.write_profile()

    def write_profile(self) -> None:
        self.path.write_text(json.dumps(self.data), encoding="utf-8")
        self.path.chmod(0o644)

    @contextlib.contextmanager
    def trusted_controller(self, *, mutate_stat=None, writable=None):
        """Simulate protected ownership/ACLs only inside scoped unit fixtures."""
        real_fstat, real_stat = os.fstat, os.stat

        def view(original):
            names = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size",
                     "st_mtime_ns", "st_ctime_ns", "st_nlink")
            result = SimpleNamespace(**{name: getattr(original, name) for name in names})
            result.st_uid = 0
            result.st_mode &= ~0o022
            if mutate_stat is not None:
                mutate_stat(result)
            return result

        def access(path, mode, **_kwargs):
            if mode == os.X_OK:
                return True
            return bool(writable is not None and Path(path) == writable)

        with (
            mock.patch.object(backend.os, "geteuid", return_value=501),
            mock.patch.object(backend.os, "fstat", side_effect=lambda fd: view(real_fstat(fd))),
            mock.patch.object(backend.os, "stat", side_effect=lambda *args, **kw: view(real_stat(*args, **kw))),
            mock.patch.object(backend.os, "access", side_effect=access),
            mock.patch("subprocess.Popen", side_effect=AssertionError("runtime execution")),
            mock.patch("subprocess.run", side_effect=AssertionError("runtime execution")),
        ):
            yield

    def test_protected_profile_and_pinned_runtime_load_without_execution_or_environment_changes(self) -> None:
        before = (self.path.read_bytes(), self.runtime.read_bytes(), dict(os.environ))
        with self.trusted_controller():
            loaded = backend.load_profile(self.path, expected_uid=501)
        self.assertEqual(loaded.as_dict(), self.data)
        self.assertEqual((self.path.read_bytes(), self.runtime.read_bytes(), dict(os.environ)), before)

    def test_root_controller_and_mismatched_expected_uid_are_rejected_before_reads(self) -> None:
        with mock.patch.object(backend, "_read_protected") as reader:
            for actual, expected in ((0, 0), (0, 501), (501, 502), (501, True)):
                with self.subTest(actual=actual, expected=expected):
                    with mock.patch.object(backend.os, "geteuid", return_value=actual):
                        with self.assertRaises(backend.BackendContractError):
                            backend.load_profile(self.path, expected_uid=expected)
            reader.assert_not_called()

    def test_profile_controller_uid_must_match_actual_nonroot_controller(self) -> None:
        self.data["controllerUid"] = 502
        self.write_profile()
        with self.trusted_controller(), self.assertRaises(backend.BackendContractError):
            backend.load_profile(self.path, expected_uid=501)

    def test_operator_owned_profile_runtime_or_ancestor_is_rejected(self) -> None:
        for target in (self.path, self.runtime, self.root):
            target_identity = (target.stat().st_dev, target.stat().st_ino)

            def untrusted(info):
                if (info.st_dev, info.st_ino) == target_identity:
                    info.st_uid = 501

            with self.subTest(target=target), self.trusted_controller(mutate_stat=untrusted):
                with self.assertRaises(backend.BackendContractError):
                    backend.load_profile(self.path, expected_uid=501)

    def test_group_writable_or_acl_writable_profile_runtime_and_ancestors_are_rejected(self) -> None:
        for target in (self.path, self.runtime, self.root):
            target_identity = (target.stat().st_dev, target.stat().st_ino)

            def group_writable(info):
                if (info.st_dev, info.st_ino) == target_identity:
                    info.st_mode |= 0o020

            with self.subTest(target=target, kind="mode"), self.trusted_controller(mutate_stat=group_writable):
                with self.assertRaises(backend.BackendContractError):
                    backend.load_profile(self.path, expected_uid=501)
            with self.subTest(target=target, kind="acl"), self.trusted_controller(writable=target):
                with self.assertRaises(backend.BackendContractError):
                    backend.load_profile(self.path, expected_uid=501)

    def test_setuid_and_setgid_protected_files_are_rejected_even_when_digest_matches(self) -> None:
        for target in (self.path, self.runtime):
            selected = (target.stat().st_dev, target.stat().st_ino)
            for bit in (stat.S_ISUID, stat.S_ISGID):
                def identity_changing(info):
                    if (info.st_dev, info.st_ino) == selected:
                        info.st_mode |= bit
                with self.subTest(target=target, bit=bit), self.trusted_controller(mutate_stat=identity_changing):
                    with self.assertRaises(backend.BackendContractError):
                        backend.load_profile(self.path, expected_uid=501)

    def test_symlink_leaf_or_ancestor_and_hardlinked_profile_are_rejected(self) -> None:
        alias = self.root / "alias"
        alias.symlink_to(self.path)
        directory_alias = self.root / "directory-alias"
        directory_alias.symlink_to(self.root, target_is_directory=True)
        for path in (alias, directory_alias / self.path.name):
            with self.subTest(path=path), self.trusted_controller():
                with self.assertRaises(backend.BackendContractError):
                    backend.load_profile(path, expected_uid=501)
        hardlink = self.root / "hardlink.json"
        os.link(self.path, hardlink)
        with self.trusted_controller(), self.assertRaises(backend.BackendContractError):
            backend.load_profile(self.path, expected_uid=501)

    def test_runtime_hash_symlink_and_executable_permission_are_checked(self) -> None:
        self.runtime.write_bytes(b"changed binary")
        with self.trusted_controller(), self.assertRaises(backend.BackendContractError):
            backend.load_profile(self.path, expected_uid=501)
        self.data["sbxSha256"] = hashlib.sha256(self.runtime.read_bytes()).hexdigest()
        self.write_profile()
        self.runtime.chmod(0o644)
        with self.trusted_controller(), self.assertRaises(backend.BackendContractError):
            backend.load_profile(self.path, expected_uid=501)
        self.runtime.chmod(0o755)
        alias = self.root / "binary-alias"
        alias.symlink_to(self.runtime)
        self.data["sbxPath"] = str(alias)
        self.write_profile()
        with self.trusted_controller(), self.assertRaises(backend.BackendContractError):
            backend.load_profile(self.path, expected_uid=501)

    def test_file_mutation_during_read_is_rejected(self) -> None:
        original_read = os.read
        original_fstat = os.fstat
        profile_inode = self.path.stat().st_ino
        changed = [False]

        def mutate(descriptor, count):
            result = original_read(descriptor, count)
            if result and not changed[0] and original_fstat(descriptor).st_ino == profile_inode:
                changed[0] = True
                with self.path.open("ab") as output:
                    output.write(b" ")
            return result

        with self.trusted_controller(), mock.patch.object(backend.os, "read", side_effect=mutate):
            with self.assertRaisesRegex(backend.BackendContractError, "changed"):
                backend.load_profile(self.path, expected_uid=501)
        self.assertTrue(changed[0])

    def test_missing_secure_filesystem_primitive_fails_closed(self) -> None:
        with self.trusted_controller(), mock.patch.object(backend, "_OPEN_SUPPORTS_DIR_FD", False):
            with self.assertRaises(backend.BackendContractError):
                backend.load_profile(self.path, expected_uid=501)

    def test_protected_runtime_hash_streams_without_retaining_large_native_binary(self) -> None:
        size = 8 * 1024 * 1024
        with self.runtime.open("wb") as output:
            output.truncate(size)
        expected = hashlib.sha256()
        for _ in range(size // 65536):
            expected.update(b"\0" * 65536)
        original_read = os.read
        read_sizes = []

        def observe(descriptor, count):
            read_sizes.append(count)
            return original_read(descriptor, count)

        tracemalloc.start()
        try:
            with self.trusted_controller(), mock.patch.object(backend.os, "read", side_effect=observe):
                content, digest = backend._read_protected(
                    self.runtime, maximum=backend.MAX_RUNTIME_BYTES, capture=False, executable=True
                )
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertIsNone(content)
        self.assertEqual(digest, expected.hexdigest())
        self.assertLessEqual(max(read_sizes), 65536)
        self.assertLess(peak, 2 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
