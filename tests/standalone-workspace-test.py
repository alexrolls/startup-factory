#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("standalone_workspace", ROOT / "bin/standalone_workspace.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(module)


class StandaloneWorkspaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "canonical"
        self.repo.mkdir()
        self.git(self.repo, "init", "-q", "-b", "main")
        self.git(self.repo, "config", "user.name", "Fixture")
        self.git(self.repo, "config", "user.email", "fixture@example.invalid")
        (self.repo / "base.txt").write_text("base\n")
        self.git(self.repo, "add", "base.txt")
        self.git(self.repo, "commit", "-qm", "base")
        self.git(self.repo, "branch", "feature-runtime")
        self.base = self.git(self.repo, "rev-parse", "feature-runtime")
        self.clone_root = self.root / "clones"
        self.branch = "agent-task/feature-runtime/task-key"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def git(where: Path, *args: str) -> str:
        return subprocess.check_output(["git", "-C", str(where), *args], text=True).strip()

    def create(self) -> Path:
        result = module.create_attempt(
            self.repo, self.clone_root, "feature-runtime", "backend", 1, "task-key",
            self.branch, "feature-runtime",
        )
        return Path(result["path"])

    def test_clone_has_independent_git_and_exact_quarantine_import(self) -> None:
        clone = self.create()
        self.assertTrue((clone / ".git").is_dir())
        self.assertFalse((clone / ".git/commondir").exists())
        (clone / "change.txt").write_text("change\n")
        self.git(clone, "add", "change.txt")
        self.git(clone, "commit", "-qm", "task checkpoint")
        bundle = self.root / "broker" / "task.bundle"
        imported = module.quarantine_import(
            self.repo, clone, self.branch, self.base, "feature-runtime", "task-key", 1, bundle
        )
        self.assertEqual(self.git(self.repo, "rev-parse", imported["quarantineRef"]), imported["headCommit"])
        self.assertEqual(self.git(self.repo, "rev-parse", imported["quarantineRef"] + "^{tree}"), imported["tree"])
        self.assertRegex(imported["bundleSha256"], r"^sha256:[0-9a-f]{64}$")

    def test_fresh_disposable_clone_can_import_only_the_exact_quarantine_head(self) -> None:
        producer = self.create()
        (producer / "change.txt").write_text("exact imported validation input\n")
        self.git(producer, "add", "change.txt")
        self.git(producer, "commit", "-qm", "task checkpoint")
        imported = module.quarantine_import(
            self.repo,
            producer,
            self.branch,
            self.base,
            "feature-runtime",
            "task-key",
            1,
            self.root / "broker" / "task.bundle",
        )
        validator = module.create_attempt(
            self.repo,
            self.clone_root,
            "feature-runtime",
            "integration-validator",
            1,
            "task-key-validation",
            "startup-factory-validation/exact-head",
            imported["headCommit"],
        )
        validation_clone = Path(validator["path"])
        self.assertEqual(validator["headCommit"], imported["headCommit"])
        self.assertEqual(validator["tree"], imported["tree"])
        self.assertEqual(
            self.git(validation_clone, "for-each-ref", "--format=%(refname)"),
            "refs/heads/startup-factory-validation/exact-head",
        )
        self.assertFalse((validation_clone / ".git/commondir").exists())

    def test_create_cli_rejects_an_extra_unbound_clone_root_argument(self) -> None:
        result = subprocess.run(
            [
                "python3",
                str(ROOT / "bin/standalone_workspace.py"),
                "create",
                "--repo",
                str(self.repo),
                "--root",
                str(self.clone_root),
                str(self.clone_root),
                "--team",
                "feature-runtime",
                "--role",
                "integration-validator",
                "--attempt",
                "1",
                "--task-key",
                "task-key-validation",
                "--branch",
                "startup-factory-validation/exact-head",
                "--base-ref",
                self.base,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments", result.stderr)
        self.assertFalse(self.clone_root.exists())

    def test_team_dot_segments_and_unsafe_existing_team_directory_are_rejected(self) -> None:
        for team in (".", ".."):
            with self.subTest(team=team), self.assertRaisesRegex(module.WorkspaceError, "unsafe team"):
                module.attempt_path(self.clone_root, team, "backend", 1, "task-key")

        self.clone_root.mkdir(mode=0o700)
        team_root = self.clone_root / "feature-runtime"
        team_root.mkdir(mode=0o755)
        with self.assertRaisesRegex(module.WorkspaceError, "caller-owned mode 0700"):
            self.create()
        self.assertEqual(list(team_root.iterdir()), [])

    def test_dirty_extra_refs_and_unsafe_git_config_fail_closed(self) -> None:
        clone = self.create()
        (clone / "dirty").write_text("dirty\n")
        with self.assertRaisesRegex(module.WorkspaceError, "dirty"):
            module.validate_attempt(clone, self.branch, self.base)
        (clone / "dirty").unlink()
        self.git(clone, "branch", "extra")
        with self.assertRaisesRegex(module.WorkspaceError, "unexpected refs"):
            module.validate_attempt(clone, self.branch, self.base)
        self.git(clone, "branch", "-D", "extra")
        self.git(clone, "config", "filter.hostile.clean", "/bin/false")
        with self.assertRaisesRegex(module.WorkspaceError, "unsafe Git config"):
            module.validate_attempt(clone, self.branch, self.base)

    def test_alternates_and_linked_git_metadata_are_rejected(self) -> None:
        clone = self.create()
        alternates = clone / ".git/objects/info/alternates"
        alternates.write_text(str(self.repo / ".git/objects") + "\n")
        with self.assertRaisesRegex(module.WorkspaceError, "indirection"):
            module.validate_attempt(clone, self.branch, self.base)

    def test_recursive_git_symlinks_hardlinks_and_promisor_state_are_rejected(self) -> None:
        cases = ("objects", "refs", "config")
        for relative in cases:
            with self.subTest(relative=relative):
                clone = self.create()
                target = clone / ".git" / relative
                saved = clone / ".git" / (relative.replace("/", "-") + ".saved")
                target.rename(saved)
                target.symlink_to(saved, target_is_directory=saved.is_dir())
                with self.assertRaisesRegex(module.WorkspaceError, "symlink"):
                    module.validate_attempt(clone, self.branch, self.base)
                target.unlink()
                saved.rename(target)

        clone = self.create()
        source = clone / ".git/HEAD"
        alias = clone / ".git/HEAD.hardlink"
        os.link(source, alias)
        with self.assertRaisesRegex(module.WorkspaceError, "hard-linked"):
            module.validate_attempt(clone, self.branch, self.base)
        alias.unlink()

        promisor = clone / ".git/objects/pack/hostile.promisor"
        promisor.write_text("partial clone\n")
        with self.assertRaisesRegex(module.WorkspaceError, "indirection"):
            module.validate_attempt(clone, self.branch, self.base)

    def test_head_outside_bound_base_is_rejected(self) -> None:
        clone = self.create()
        self.git(clone, "checkout", "--orphan", "replacement")
        self.git(clone, "rm", "-qf", "base.txt")
        (clone / "unrelated.txt").write_text("unrelated\n")
        self.git(clone, "add", "unrelated.txt")
        self.git(clone, "commit", "-qm", "unrelated root")
        self.git(clone, "branch", "-M", self.branch)
        with self.assertRaisesRegex(module.WorkspaceError, "not a descendant"):
            module.validate_attempt(clone, self.branch, self.base)

    def test_retire_refuses_symlink_alias_and_preserves_clone(self) -> None:
        clone = self.create()
        alias = self.root / "clone-alias"
        alias.symlink_to(clone, target_is_directory=True)
        with self.assertRaisesRegex(module.WorkspaceError, "path is unsafe"):
            module.retire_attempt(self.repo, self.clone_root, alias, self.branch)
        self.assertTrue(clone.is_dir())

    def test_bounded_inputs_are_staged_read_only_without_dirtying_clone(self) -> None:
        clone = self.create()
        source = self.root / "task-packet.md"
        source.write_text("bounded task packet\n")
        result = module.stage_input(clone, self.branch, self.base, source, "task-packet.md")
        staged = Path(result["inputPath"])
        self.assertEqual(staged.read_text(), "bounded task packet\n")
        self.assertEqual(staged.stat().st_mode & 0o777, 0o400)
        self.assertEqual(self.git(clone, "status", "--porcelain=v1", "-uall"), "")
        source.write_text("changed after issue\n")
        with self.assertRaisesRegex(module.WorkspaceError, "destination changed"):
            module.stage_input(clone, self.branch, self.base, source, "task-packet.md")

        symlink = self.root / "packet-link.md"
        symlink.symlink_to(source)
        with self.assertRaisesRegex(module.WorkspaceError, "source is unsafe"):
            module.stage_input(clone, self.branch, self.base, symlink, "link.md")


if __name__ == "__main__":
    unittest.main()
