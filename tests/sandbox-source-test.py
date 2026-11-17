#!/usr/bin/env python3
"""Finite source transfer tests; execute only in the disposable test runner."""
from __future__ import annotations

import copy
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
sys.path.insert(0, str(ROOT / "src"))
import sandbox_source as source  # noqa: E402
from startup_factory_cli.secret_safety import contains_secret_like  # noqa: E402


def fixture(names=None):
    names = names or {"README.md": ("100644", b"fixture\n"), "run.sh": ("100755", b"#!/bin/sh\nexit 0\n"), "data.bin": ("100644", b"\0\xff\x01")}
    objects = {}
    entries = []
    for name, (mode, body) in names.items():
        oid = source.object_id("blob", body)
        objects[("blob", oid)] = body
        entries.append((name.encode(), mode, oid))
    tree = b"".join(mode.encode() + b" " + name + b"\0" + bytes.fromhex(oid) for name, mode, oid in sorted(entries))
    tree_oid = source.object_id("tree", tree)
    objects[("tree", tree_oid)] = tree
    commit = ("tree " + tree_oid + "\nparent " + "a" * 40 + "\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nfinite source fixture\n").encode()
    base = source.object_id("commit", commit)
    objects[("commit", base)] = commit
    return base, tree_oid, objects


class SandboxSourceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-source-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.base, self.tree, self.objects = fixture()

    def package(self, *, objects=None, base=None, scanner=lambda _text: False):
        objects = self.objects if objects is None else objects
        return source.build_source_package(base or self.base, lambda kind, oid: objects[(kind, oid)], contains_secret=scanner)

    def test_finite_package_contains_only_reachable_objects_and_binary_regular_files(self):
        visited = []
        def read(kind, oid):
            visited.append((kind, oid))
            return self.objects[(kind, oid)]
        raw = source.build_source_package(self.base, read, contains_secret=lambda _text: False)
        base, tree, accepted, files = source.parse_source_package(raw)
        self.assertEqual((base, tree), (self.base, self.tree))
        self.assertEqual(len(accepted), 5)
        self.assertEqual(files["data.bin"][2], b"\0\xff\x01")
        self.assertNotIn(("commit", "a" * 40), visited)
        self.assertNotIn(str(self.root).encode(), raw)

    def test_guest_clone_preserves_exact_commit_tree_and_has_no_remote_or_host_git_state(self):
        destination = self.root / "project"
        receipt = source.initialize_guest(self.package(), destination)
        self.assertEqual(receipt["baseCommit"], self.base)
        self.assertEqual(receipt["tree"], self.tree)
        self.assertEqual((destination / "data.bin").read_bytes(), b"\0\xff\x01")
        env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        def git(*args):
            return subprocess.check_output(["/usr/bin/git", "-C", str(destination), *args], env=env, timeout=5).decode().strip()
        self.assertEqual(git("rev-parse", "HEAD"), self.base)
        self.assertEqual(git("rev-parse", "HEAD^{tree}"), self.tree)
        self.assertEqual(git("status", "--porcelain"), "")
        self.assertEqual(git("remote"), "")
        self.assertEqual(git("rev-list", "--count", "HEAD"), "1")
        self.assertFalse((destination / ".git/objects/info/alternates").exists())
        self.assertFalse((destination / ".git/hooks").exists())
        self.assertEqual((destination / ".git/shallow").read_text(), self.base + "\n")

    def test_existing_workspace_or_symlink_is_never_reused_or_cleaned(self):
        destination = self.root / "project"
        destination.mkdir()
        marker = destination / "preserve"
        marker.write_text("existing work")
        with self.assertRaises(FileExistsError):
            source.initialize_guest(self.package(), destination)
        self.assertEqual(marker.read_text(), "existing work")
        link = self.root / "link"
        link.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            source.initialize_guest(self.package(), link)

    def test_duplicate_missing_extra_and_corrupt_objects_are_rejected(self):
        original = json.loads(self.package())
        variants = []
        duplicate = copy.deepcopy(original)
        duplicate["objects"].append(copy.deepcopy(duplicate["objects"][0]))
        variants.append(duplicate)
        missing = copy.deepcopy(original)
        missing["objects"].pop()
        variants.append(missing)
        extra = copy.deepcopy(original)
        extra["objects"].append({"kind": "blob", "oid": source.object_id("blob", b"extra"), "bodyHex": b"extra".hex()})
        variants.append(extra)
        corrupt = copy.deepcopy(original)
        corrupt["objects"][0]["bodyHex"] += "00"
        variants.append(corrupt)
        wrong_tree = copy.deepcopy(original)
        wrong_tree["tree"] = "a" * 40
        variants.append(wrong_tree)
        for item in variants:
            with self.subTest(item=str(item)[:60]), self.assertRaises(source.SourceError):
                source.parse_source_package(json.dumps(item).encode())

    def test_closed_schema_duplicate_keys_and_nonfinite_values_fail(self):
        for raw in (b'{"schemaVersion":1,"schemaVersion":1}', b'{"schemaVersion":NaN}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(source.SourceError):
                source.parse_source_package(raw)
        package = json.loads(self.package())
        package["hostPath"] = "/dummy/forbidden"
        with self.assertRaises(source.SourceError):
            source.parse_source_package(json.dumps(package).encode())

    def test_unsafe_case_colliding_control_and_noncanonical_paths_fail(self):
        for names in ({".git": ("100644", b"x")}, {"../outside": ("100644", b"x")},
                      {"A": ("100644", b"x"), "a": ("100644", b"x")},
                      {".teamwork": ("100644", b"x")}, {"trailing.": ("100644", b"x")},
                      {"e\u0301": ("100644", b"x")}, {"bad\\path": ("100644", b"x")},
                      {".ｇｉｔ": ("100644", b"x")}, {".gi\u200ct": ("100644", b"x")},
                      {"A": ("100644", b"x"), "Ａ": ("100644", b"x")}):
            base, _tree, objects = fixture(names)
            with self.subTest(names=names), self.assertRaises(source.SourceError):
                self.package(objects=objects, base=base)

    def test_symlinks_and_submodules_are_explicitly_unsupported_for_source(self):
        for mode in ("120000", "160000"):
            base, _tree, objects = fixture({"link": (mode, b"target")})
            with self.subTest(mode=mode), self.assertRaises(source.SourceError):
                self.package(objects=objects, base=base)

    def test_lfs_pointers_fail_without_implicit_hydration_or_silent_omission(self):
        base, _tree, objects = fixture({"large.bin": ("100644", b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 1000000\n")})
        with self.assertRaisesRegex(source.SourceError, "LFS"):
            self.package(objects=objects, base=base)

    def test_source_scanner_is_required_and_positive_does_not_silently_redact(self):
        with self.assertRaises(source.SourceError):
            self.package(scanner=None)
        with self.assertRaises(source.SourceError):
            self.package(scanner=lambda _text: True)
        with self.assertRaises(source.SourceError):
            self.package(scanner=lambda _text: None)
        self.assertEqual(self.objects[("blob", source.object_id("blob", b"fixture\n"))], b"fixture\n")

    def test_bom_unicode_configuration_uses_decoded_secret_scanning(self):
        dummy = "key=" + "AKIA" + "A" * 16 + "\n"
        for encoding in ("utf-16", "utf-32", "utf-8"):
            base, _tree, objects = fixture({"config.txt": ("100644", dummy.encode(encoding))})
            with self.subTest(encoding=encoding), self.assertRaisesRegex(source.SourceError, "secret scanner"):
                self.package(base=base, objects=objects, scanner=contains_secret_like)

    def test_file_count_expanded_bytes_and_individual_object_limits_are_enforced(self):
        with mock.patch.object(source, "MAX_FILES", 2), self.assertRaises(source.SourceError):
            self.package()
        with mock.patch.object(source, "MAX_SOURCE_BYTES", 4), self.assertRaises(source.SourceError):
            self.package()
        with mock.patch.object(source, "MAX_FILE_BYTES", 2), self.assertRaises(source.SourceError):
            self.package()

    def test_shared_tree_dag_has_a_separate_expansion_and_path_byte_budget(self):
        objects = {}
        empty = b""
        child = source.object_id("tree", empty)
        objects[("tree", child)] = empty
        for _ in range(6):
            raw = b"".join(b"40000 " + str(index).encode() + b"\0" + bytes.fromhex(child) for index in range(8))
            child = source.object_id("tree", raw)
            objects[("tree", child)] = raw
        commit = ("tree " + child + "\nauthor F <f@example.invalid> 1 +0000\ncommitter F <f@example.invalid> 1 +0000\n\nfixture\n").encode()
        base = source.object_id("commit", commit)
        objects[("commit", base)] = commit
        self.assertLess(len(objects), 10)
        for limits in ({"MAX_ENTRIES": 20}, {"MAX_DIRECTORIES": 20}, {"MAX_PATH_BYTES": 20}):
            with self.subTest(limits=limits), mock.patch.multiple(source, **limits), self.assertRaisesRegex(source.SourceError, "path budget"):
                self.package(base=base, objects=objects)

    def test_real_host_source_guest_workspace_and_authorized_artifact_promotion(self):
        from host_git import HostGit
        from sandbox_artifacts import ArtifactError, ArtifactStore
        repository = self.root / "canonical"
        repository.mkdir(mode=0o700)
        environment = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        def git(path, *args):
            return subprocess.check_output(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(path), *args],
                stderr=subprocess.PIPE, env=environment, timeout=5).decode().strip()
        git(repository, "init", "-q")
        git(repository, "config", "user.name", "Fixture")
        git(repository, "config", "user.email", "fixture@example.invalid")
        (repository / "README.md").write_bytes(b"approved base\n")
        git(repository, "add", "README.md")
        git(repository, "commit", "-q", "-m", "base")
        base = git(repository, "rev-parse", "HEAD")
        assigned_ref = "refs/heads/agent-task/team/task"
        git(repository, "update-ref", assigned_ref, base)
        boundary = HostGit(repository)
        package = source.build_source_package(base, boundary.read_object, contains_secret=contains_secret_like)
        guest = self.root / "private-guest"
        source.initialize_guest(package, guest)
        content = b"accepted guest change\n"
        (guest / "README.md").write_bytes(content)
        # The guest may choose any claim; the host independently reconstructs
        # the full tree. Use guest Git as an independent test oracle here.
        git(guest, "add", "README.md")
        tree = git(guest, "write-tree")
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        manifest = {"schemaVersion": 1, "id": "a" * 32, "baseCommit": base, "resultingTree": tree,
                    "changes": [{"operation": "replace", "path": "README.md", "mode": "100644", "size": len(content), "sha256": digest}]}
        quarantine = self.root / "quarantine"
        quarantine.mkdir(mode=0o700)
        active = False
        with ArtifactStore(boundary, quarantine, assignment_digest="sha256:" + "b" * 64,
                target_ref=assigned_ref, expected_base=base,
                authorize=lambda *_arguments: active, authority_lock=contextlib.nullcontext) as store:
            collected = store.collect(manifest, {digest: content})
            self.assertEqual(collected["tree"], tree)
            with self.assertRaises(ArtifactError):
                store.promote(manifest["id"])
            self.assertEqual(boundary.read_ref(assigned_ref), base)
            active = True
            promoted = store.promote(manifest["id"])
            self.assertEqual(boundary.read_ref(assigned_ref), promoted["commit"])
            self.assertEqual(boundary.commit_tree(promoted["commit"]), tree)
            accepted_blob = boundary.entries(promoted["commit"])["README.md"][1]
            self.assertEqual(boundary.read_blob(accepted_blob), content)
        self.assertEqual(git(repository, "rev-parse", "HEAD"), base)
        self.assertEqual((repository / "README.md").read_bytes(), b"approved base\n")


if __name__ == "__main__":
    unittest.main()
