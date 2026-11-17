#!/usr/bin/env python3
"""Raw Git/quarantine fixtures; run only inside the assigned isolated runner.

All repositories, hooks and source programs are synthetic fixtures. No fixture
or repository command is executed on the developer host. The guest initializer
test runs inside this same disposable container, never as a host provisioner.
"""

from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from host_git import HostGit, HostGitError, RefConflict, object_id  # noqa: E402
import sandbox_artifacts as artifacts  # noqa: E402
from sandbox_source import build_source_package, initialize_guest  # noqa: E402


ASSIGNMENT = "sha256:" + "7" * 64
TARGET = "refs/heads/codex/artifact-fixture"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ.get("SF_ARTIFACT_TEST_ROOT", os.environ.get("SF_REGISTRY_TEST_ROOT", os.getcwd())))
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-artifact-test-", dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name)
        self.repo = self.scratch / "repo"
        self.repo.mkdir(mode=0o700)
        self.quarantine = self.scratch / "quarantine"
        self.quarantine.mkdir(mode=0o700)
        self.environment = {
            "PATH": "/usr/bin:/bin", "HOME": str(self.scratch), "TMPDIR": str(self.scratch),
            "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@invalid",
            "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
        }
        self.fixture_git("init", "-q", "-b", "main")
        (self.repo / "hello.txt").write_bytes(b"hello\n")
        (self.repo / "dir").mkdir()
        (self.repo / "dir/keep.bin").write_bytes(b"\0keep\xff")
        self.fixture_git("add", "--", "hello.txt", "dir/keep.bin")
        self.fixture_git("commit", "-q", "--no-gpg-sign", "-m", "trusted fixture")
        self.base = self.fixture_git("rev-parse", "HEAD").strip().decode()
        self.fixture_git("update-ref", TARGET, self.base)
        self.git = HostGit(self.repo)
        self.lock_active = False
        self.allowed = True
        self.authorizations = 0

    def fixture_git(self, *arguments, content=None):
        result = subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), *arguments], input=content,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            env=self.environment, cwd=self.scratch, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    @contextmanager
    def authority_lock(self):
        self.assertFalse(self.lock_active)
        self.lock_active = True
        try:
            yield
        finally:
            self.lock_active = False

    def authorize(self, assignment, receipt):
        self.assertTrue(self.lock_active, "authorization must occur under the external task lock")
        self.assertEqual(assignment["targetRef"], TARGET)
        self.assertEqual(assignment["baseCommit"], self.base)
        self.assertEqual(receipt["assignmentDigest"], ASSIGNMENT)
        self.authorizations += 1
        return self.allowed

    def store(self, *, authorized=True, **kwargs):
        result = artifacts.ArtifactStore(
            self.git, self.quarantine, assignment_digest=ASSIGNMENT, target_ref=TARGET,
            expected_base=self.base, authorize=self.authorize if authorized else None,
            authority_lock=self.authority_lock if authorized else None, **kwargs,
        )
        self.addCleanup(result.close)
        return result

    def manifest(self, *, identifier="a" * 32, content=b"changed\0\xff\n", changes=None, claimed_tree=None):
        if changes is None:
            changes = [{"operation": "replace", "path": "hello.txt", "mode": "100644", "size": len(content), "sha256": digest(content)}]
        blobs = {digest(content): content} if any(change.get("sha256") == digest(content) for change in changes) else {}
        if claimed_tree is None:
            entries = self.git.entries(self.base)
            for change in changes:
                if change["operation"] == "delete":
                    entries.pop(change["path"], None)
                else:
                    entries[change["path"]] = (change["mode"], object_id("blob", blobs[change["sha256"]]))
            claimed_tree = artifacts.tree_objects(entries)[0]
        return {"schemaVersion": 1, "id": identifier, "baseCommit": self.base, "resultingTree": claimed_tree, "changes": changes}, blobs

    def test_full_tree_matches_git_and_collect_has_no_ref_or_object_writes(self):
        entries = self.git.entries(self.base)
        tree, _objects = artifacts.tree_objects(entries)
        self.assertEqual(tree, self.git.commit_tree(self.base))
        store = self.store(authorized=False)
        manifest, blobs = self.manifest()
        with mock.patch.object(self.git, "write_object", side_effect=AssertionError("canonical write")):
            receipt = store.collect(manifest, blobs)
        self.assertEqual(receipt["kind"], "sandbox-quarantine")
        self.assertEqual(self.git.read_ref(TARGET), self.base)
        with self.assertRaises(artifacts.ArtifactError):
            store.promote(manifest["id"])
        self.assertEqual(self.git.read_ref(TARGET), self.base)

    def test_authorized_promotion_is_raw_exact_and_leaves_worktree_untouched(self):
        store = self.store()
        manifest, blobs = self.manifest()
        quarantine = store.collect(manifest, blobs)
        receipt = store.promote(manifest["id"])
        self.assertEqual(receipt["kind"], "sandbox-promotion")
        self.assertEqual(receipt["commit"], quarantine["commit"])
        self.assertEqual(self.git.read_ref(TARGET), receipt["commit"])
        self.assertEqual(self.git.commit_tree(receipt["commit"]), manifest["resultingTree"])
        self.assertEqual((self.repo / "hello.txt").read_bytes(), b"hello\n")
        self.assertEqual(self.fixture_git("rev-parse", "refs/heads/main").strip().decode(), self.base)
        self.assertEqual(self.git.entries(receipt["commit"])["dir/keep.bin"], self.git.entries(self.base)["dir/keep.bin"])
        self.assertEqual(self.authorizations, 2)
        self.allowed = False
        with mock.patch.object(self.git, "compare_and_swap", side_effect=AssertionError("duplicate CAS")):
            self.assertEqual(store.promote(manifest["id"]), receipt)

    def test_revoke_after_collection_and_before_cas_denies_new_effect(self):
        store = self.store()
        manifest, blobs = self.manifest()
        store.collect(manifest, blobs)
        self.allowed = False
        with self.assertRaises(artifacts.ArtifactError):
            store.promote(manifest["id"])
        self.assertEqual(self.git.read_ref(TARGET), self.base)
        self.allowed = True
        original = self.git.write_object

        def revoke(kind, raw):
            result = original(kind, raw)
            if kind == "commit":
                self.allowed = False
            return result

        with mock.patch.object(self.git, "write_object", side_effect=revoke):
            with self.assertRaises(artifacts.ArtifactError):
                store.promote(manifest["id"])
        self.assertEqual(self.git.read_ref(TARGET), self.base)

    def test_after_cas_before_receipt_crash_recovers_exact_effect_after_fence(self):
        store = self.store()
        manifest, blobs = self.manifest()
        candidate = store.collect(manifest, blobs)["commit"]
        save = store._save

        def crash_after_cas(state):
            if any(record["state"] == "promoted" for record in state["exports"].values()):
                raise OSError("fixture crash after ref effect")
            return save(state)

        with mock.patch.object(store, "_save", side_effect=crash_after_cas):
            with self.assertRaises((OSError, artifacts.ArtifactError)):
                store.promote(manifest["id"])
        self.assertEqual(self.git.read_ref(TARGET), candidate)
        reopened = self.store()
        self.allowed = False
        with mock.patch.object(self.git, "compare_and_swap", side_effect=AssertionError("recovered CAS")):
            receipt = reopened.promote(manifest["id"])
        self.assertEqual(receipt["commit"], candidate)

    def test_recovery_never_restores_a_different_projection_head(self):
        store = self.store()
        manifest, blobs = self.manifest()
        store.collect(manifest, blobs)
        with mock.patch.object(self.git, "compare_and_swap", side_effect=RefConflict("fixture before CAS")):
            with self.assertRaises(HostGitError):
                store.promote(manifest["id"])
        tree = self.git.commit_tree(self.base)
        other_raw = f"tree {tree}\nparent {self.base}\nauthor Fixture <fixture@invalid> 0 +0000\ncommitter Fixture <fixture@invalid> 0 +0000\n\nunrelated\n".encode()
        other = self.git.write_object("commit", other_raw)
        self.fixture_git("update-ref", TARGET, other, self.base)
        reopened = self.store()
        with mock.patch.object(self.git, "compare_and_swap", side_effect=AssertionError("stale CAS")):
            with self.assertRaises(artifacts.ArtifactError):
                reopened.promote(manifest["id"])
        self.assertEqual(self.git.read_ref(TARGET), other)

    def test_changed_export_id_payload_or_claimed_tree_is_denied(self):
        store = self.store()
        manifest, blobs = self.manifest()
        receipt = store.collect(manifest, blobs)
        self.assertEqual(store.collect(manifest, blobs), receipt)
        changed, other_blobs = self.manifest(content=b"different")
        with self.assertRaises(artifacts.ArtifactError):
            store.collect(changed, other_blobs)
        with self.assertRaises(artifacts.ArtifactError):
            store.collect({**manifest, "id": "b" * 32, "resultingTree": "0" * 40}, blobs)
        with self.assertRaises(artifacts.ArtifactError):
            store.collect(manifest, {digest(next(iter(blobs.values()))): b"tampered"})

    def test_manifest_paths_modes_collisions_and_strict_schema_are_denied(self):
        store = self.store()
        manifest, blobs = self.manifest()
        for path in ("/etc/passwd", "../outside", "dir/../outside", ".git/config", ".GIT/config", ".teamwork/state", ".sf-control/session", ".startup-factory-control/state", "dir\\file", "dir//file", "dir/cafe\u0301.txt", "dir/hidden\u200dname"):
            value = copy.deepcopy(manifest)
            value["changes"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(artifacts.ArtifactError):
                store.collect(value, blobs)
        for mode in ("120000", "160000", "040000", "100664"):
            value = copy.deepcopy(manifest)
            value["changes"][0]["mode"] = mode
            with self.subTest(mode=mode), self.assertRaises(artifacts.ArtifactError):
                store.collect(value, blobs)
        for operation in ([], {}, None, True):
            value = copy.deepcopy(manifest)
            value["changes"][0]["operation"] = operation
            with self.subTest(operation=operation), self.assertRaises(artifacts.ArtifactError):
                store.collect(value, blobs)
        for path in ("DIR/new.txt", "dir"):
            value = copy.deepcopy(manifest)
            value["changes"][0].update(operation="add", path=path)
            with self.subTest(path=path), self.assertRaises(artifacts.ArtifactError):
                store.collect(value, blobs)
        for raw in (b'{"schemaVersion":1,"schemaVersion":1}', b'{"schemaVersion":NaN}', b"[" * 20 + b"0" + b"]" * 20):
            with self.assertRaises(artifacts.ArtifactError):
                store.collect(raw, {})

    def test_binary_add_delete_executable_mode_and_existing_symlink_preservation(self):
        (self.repo / "link").symlink_to("/outside-guest-source")
        self.fixture_git("add", "--", "link")
        self.fixture_git("commit", "-q", "--no-gpg-sign", "-m", "trusted link fixture")
        self.base = self.fixture_git("rev-parse", "HEAD").strip().decode()
        self.fixture_git("update-ref", TARGET, self.base)
        content = b"\x00\xffbinary"
        changes = [
            {"operation": "delete", "path": "hello.txt"},
            {"operation": "add", "path": "bin/tool", "mode": "100755", "size": len(content), "sha256": digest(content)},
        ]
        manifest, blobs = self.manifest(changes=changes, content=content)
        store = self.store()
        store.collect(manifest, blobs)
        receipt = store.promote(manifest["id"])
        entries = self.git.entries(receipt["commit"])
        self.assertNotIn("hello.txt", entries)
        self.assertEqual(entries["bin/tool"][0], "100755")
        self.assertEqual(self.git.read_blob(entries["bin/tool"][1]), content)
        self.assertEqual(entries["link"], self.git.entries(self.base)["link"])
        deletion, _ = self.manifest(identifier="b" * 32, changes=[{"operation": "delete", "path": "link"}], claimed_tree=self.git.commit_tree(self.base))
        with self.assertRaises(artifacts.ArtifactError):
            store.collect(deletion, {})

    def test_hooks_filters_merge_drivers_and_replacement_refs_do_not_execute(self):
        sentinel = self.scratch / "must-not-execute"
        command = "/bin/sh -c " + shlex.quote("printf unsafe > " + shlex.quote(str(sentinel)))
        hook = self.repo / ".git/hooks/reference-transaction"
        hook.write_text("#!/bin/sh\nprintf unsafe > " + shlex.quote(str(sentinel)) + "\n")
        hook.chmod(0o700)
        self.fixture_git("config", "filter.poison.clean", command)
        self.fixture_git("config", "filter.poison.smudge", command)
        self.fixture_git("config", "merge.poison.driver", command)
        (self.repo / ".gitattributes").write_text("*.txt filter=poison merge=poison\n")
        original_commit = self.git.read_commit(self.base)
        tree = self.git.commit_tree(self.base)
        other = self.git.write_object("commit", f"tree {tree}\nauthor Fixture <fixture@invalid> 0 +0000\ncommitter Fixture <fixture@invalid> 0 +0000\n\nreplacement\n".encode())
        # Set the replacement through the fixed fixture command with hooks off.
        self.fixture_git("-c", "core.hooksPath=/dev/null", "replace", self.base, other)
        self.assertEqual(self.git.read_commit(self.base), original_commit)
        manifest, blobs = self.manifest()
        store = self.store()
        store.collect(manifest, blobs)
        store.promote(manifest["id"])
        self.assertFalse(sentinel.exists())

    def test_promisor_config_includes_and_alternates_fail_before_git_runs(self):
        config = self.repo / ".git/config"
        initial = config.read_bytes()
        for extra in (b'\n[remote "origin"]\n promisor = true\n', b'\n[include]\n path = /outside/config\n'):
            config.write_bytes(initial + extra)
            with mock.patch("host_git.subprocess.Popen", side_effect=AssertionError("Git executed")):
                with self.assertRaises(HostGitError):
                    HostGit(self.repo)
        config.write_bytes(initial)
        alternate = self.repo / ".git/objects/info/alternates"
        alternate.symlink_to(self.scratch / "outside")
        with mock.patch("host_git.subprocess.Popen", side_effect=AssertionError("Git executed")):
            with self.assertRaises(HostGitError):
                HostGit(self.repo)

    def test_quarantine_symlinks_and_hardlinks_cannot_promote(self):
        store = self.store()
        manifest, blobs = self.manifest()
        store.collect(manifest, blobs)
        key = hashlib.sha256(manifest["id"].encode()).hexdigest()
        digest_value, content = next(iter(blobs.items()))
        blob = store.directory.path / key / digest_value[7:]
        sentinel = self.scratch / "outside-private-body"
        sentinel.write_bytes(content)
        sentinel.chmod(0o600)
        blob.unlink()
        blob.symlink_to(sentinel)
        with self.assertRaises((artifacts.ArtifactError, HostGitError, OSError)):
            store.promote(manifest["id"])
        blob.unlink()
        os.link(sentinel, blob)
        store = self.store()
        with self.assertRaises((artifacts.ArtifactError, HostGitError)):
            store.promote(manifest["id"])
        self.assertEqual(self.git.read_ref(TARGET), self.base)

    def test_permanent_staging_quota_counts_interrupted_exports_and_allows_retry(self):
        limits = artifacts.ArtifactLimits(max_exports=1)
        store = self.store(limits=limits)
        manifest, blobs = self.manifest()
        original = artifacts._Directory.write

        def fail_blob(directory, name, raw, **kwargs):
            if len(name) == 64 and name.isalnum():
                raise OSError("fixture incomplete content staging")
            return original(directory, name, raw, **kwargs)

        with mock.patch.object(artifacts._Directory, "write", autospec=True, side_effect=fail_blob):
            with self.assertRaises(artifacts.ArtifactError):
                store.collect(manifest, blobs)
        reopened = self.store(limits=limits)
        with self.assertRaises(artifacts.ArtifactError):
            reopened.collect({**manifest, "id": "b" * 32}, blobs)
        self.assertEqual(reopened.collect(manifest, blobs)["exportId"], manifest["id"])

    def test_input_mapping_and_assignment_are_snapshots(self):
        store = self.store()
        changed = store.assignment
        changed["targetRef"] = "refs/heads/other"
        self.assertEqual(store.assignment["targetRef"], TARGET)
        manifest, blobs = self.manifest()
        original = store._candidate

        def replace_caller_mapping(value, snapshot, **kwargs):
            result = original(value, snapshot, **kwargs)
            blobs[next(iter(blobs))] = b"caller-replaced"
            return result

        with mock.patch.object(store, "_candidate", side_effect=replace_caller_mapping):
            receipt = store.collect(manifest, blobs)
        self.assertEqual(receipt["tree"], manifest["resultingTree"])
        self.assertEqual(store.promote(manifest["id"])["tree"], manifest["resultingTree"])

    def test_expected_projection_head_must_equal_the_approved_base(self):
        for expected_head in ("f" * 40, "", False, 0):
            with self.subTest(expected_head=expected_head), self.assertRaises((artifacts.ArtifactError, HostGitError)):
                self.store(expected_head=expected_head)

    def test_collection_expiry_after_base_read_creates_no_export_record(self):
        store = self.store()
        manifest, blobs = self.manifest()
        clock = mock.Mock()
        clock.monotonic.return_value = 0
        entries = self.git.entries

        def slow_base(identifier):
            result = entries(identifier)
            clock.monotonic.return_value = 31
            return result

        with mock.patch.object(artifacts, "time", clock), mock.patch.object(self.git, "entries", side_effect=slow_base):
            with self.assertRaisesRegex(artifacts.ArtifactError, "deadline"):
                store.collect(manifest, blobs)
        self.assertFalse((store.directory.path / "exports.json").exists())

    def test_waiting_for_authority_past_budget_never_attempts_new_ref_effect(self):
        store = self.store()
        manifest, blobs = self.manifest()
        store.collect(manifest, blobs)
        clock = mock.Mock()
        clock.monotonic.return_value = 0

        @contextmanager
        def delayed_authority_lock():
            with self.authority_lock():
                clock.monotonic.return_value = 31
                yield

        store.authority_lock = delayed_authority_lock
        with mock.patch.object(artifacts, "time", clock), mock.patch.object(self.git, "compare_and_swap", side_effect=AssertionError("late CAS")):
            with self.assertRaisesRegex(artifacts.ArtifactError, "deadline"):
                store.promote(manifest["id"])
        self.assertEqual(self.git.read_ref(TARGET), self.base)

    def test_native_git_output_deadline_and_descendant_pipe_cleanup_are_bounded(self):
        native_popen = subprocess.Popen
        scripts = (
            "import os; os.write(1, b'x' * 4096)",
            "import os; os.write(2, b'x' * 20000)",
            "import os, time; child = os.fork(); "
            "os._exit(0) if child else time.sleep(10)",
        )
        for script in scripts:
            launched = []

            def fixture_child(_command, **kwargs):
                child = native_popen([sys.executable, "-c", script], **kwargs)
                launched.append(child)
                return child

            self.git.timeout_seconds = 0.15
            with self.subTest(script=script), mock.patch("host_git.subprocess.Popen", side_effect=fixture_child):
                with self.assertRaises(HostGitError):
                    self.git._run(["cat-file", "-t", self.base], maximum=64)
            self.assertEqual(len(launched), 1)
            self.assertIsNotNone(launched[0].returncode, "owned leader must be reaped on failure")
            # The leader may have exited before its descendant stopped retaining
            # the pipes. The implementation must still kill the unreaped group.
            proc = Path("/proc")
            if proc.exists():
                survivors = []
                for _attempt in range(10):
                    survivors = []
                    for entry in proc.iterdir():
                        if not entry.name.isdigit():
                            continue
                        try:
                            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                        except (FileNotFoundError, ProcessLookupError, PermissionError):
                            continue
                        if int(fields[2]) == launched[0].pid and fields[0] != "Z":
                            survivors.append(entry.name)
                    if not survivors:
                        break
                    time.sleep(0.02)
                self.assertEqual(survivors, [], "native child group survived cleanup")

    def test_real_hostgit_source_package_and_guest_initializer_preserve_exact_base(self):
        package = build_source_package(self.base, self.git.read_object, contains_secret=lambda _text: False)
        guest = self.scratch / "guest-workspace"
        receipt = initialize_guest(package, guest)
        self.assertEqual(receipt["baseCommit"], self.base)
        self.assertEqual((guest / "hello.txt").read_bytes(), b"hello\n")
        self.assertEqual((guest / "dir/keep.bin").read_bytes(), b"\0keep\xff")
        self.assertEqual((guest / ".git/HEAD").read_text().strip(), self.base)
        self.assertEqual((guest / ".git/shallow").read_text().strip(), self.base)


if __name__ == "__main__":
    unittest.main()
