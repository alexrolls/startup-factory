#!/usr/bin/env python3
"""Regression coverage for detached, non-reused review worktrees."""

import concurrent.futures
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review_worktree", ROOT / "bin/review-worktree.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReviewWorktreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.test")
        (self.repo / ".gitignore").write_text(".teamwork/\n.env\n", encoding="utf-8")
        (self.repo / "code.txt").write_text("original\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "initial")
        self.commit = self.git("rev-parse", "HEAD")
        self.workspace = self.repo / ".teamwork" / "batch"

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args], stderr=subprocess.DEVNULL, text=True,
        ).strip()

    def create(self, role="reviewer", commit=None):
        return module.create(str(self.repo), str(self.workspace), role, "task-1", commit or self.commit)

    def test_pinned_clean_detached_tree_does_not_copy_local_secrets_or_edits(self):
        (self.repo / ".env").write_text("TEST_KEY=local-only\n", encoding="utf-8")
        (self.repo / "code.txt").write_text("uncommitted edit\n", encoding="utf-8")
        result = self.create()
        tree = Path(result["worktree"])
        self.assertEqual((tree / "code.txt").read_text(), "original\n")
        self.assertFalse((tree / ".env").exists())
        self.assertEqual(module.git(tree, "rev-parse", "HEAD"), self.commit)
        self.assertEqual(module.git(tree, "branch", "--show-current"), "")
        self.assertEqual((self.repo / "code.txt").read_text(), "uncommitted edit\n")

    def test_parallel_and_replacement_reviews_never_share_or_reset_a_slot(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: self.create(), range(3)))
        slots = [Path(result["worktree"]) for result in results]
        self.assertEqual(len(set(slots)), 3)
        (slots[0] / "code.txt").write_text("review in flight\n")
        successor = Path(self.create()["worktree"])
        self.assertNotIn(successor, slots)
        self.assertEqual((slots[0] / "code.txt").read_text(), "review in flight\n")

    def test_branch_movement_does_not_change_pinned_head(self):
        (self.repo / "code.txt").write_text("later commit\n")
        self.git("commit", "-qam", "later")
        tree = Path(self.create()["worktree"])
        self.assertEqual(module.git(tree, "rev-parse", "HEAD"), self.commit)
        self.assertEqual((tree / "code.txt").read_text(), "original\n")

    def test_rejects_unsafe_paths_identifiers_and_non_commit_objects(self):
        for role in ("../reviewer", "-reviewer", "reviewer/other"):
            with self.subTest(role=role), self.assertRaises(ValueError):
                self.create(role=role)
        for commit in ("HEAD", "-bad", "f" * 40, self.git("rev-parse", "HEAD:code.txt")):
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                self.create(commit=commit)
        with self.assertRaises(SystemExit):
            module.create(str(self.repo), str(self.repo.parent / "outside"), "reviewer", "task-1", self.commit)
        self.workspace.mkdir(parents=True)
        outside = self.repo.parent / "outside"
        outside.mkdir()
        (self.workspace / "worktrees").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(SystemExit):
            self.create()
        self.assertEqual(list(outside.iterdir()), [])

    def test_checkout_does_not_run_repository_hooks(self):
        hook = self.repo / ".git/hooks/post-checkout"
        canary = self.repo.parent / "hook-ran"
        hook.write_text(f"#!/bin/sh\ntouch '{canary}'\n", encoding="utf-8")
        hook.chmod(0o700)
        self.create()
        self.assertFalse(canary.exists())

    def test_directory_replacement_during_checkout_cannot_report_success(self):
        original_git = module.git
        outside = self.repo.parent / "outside"
        outside.mkdir()

        def replace_parent(repo, *args):
            if args[:2] == ("worktree", "add"):
                parent = self.workspace / "worktrees/reviews"
                parent.rename(parent.with_name("reserved-reviews"))
                parent.symlink_to(outside, target_is_directory=True)
            return original_git(repo, *args)

        with patch.object(module, "git", side_effect=replace_parent):
            with self.assertRaises((ValueError, SystemExit)):
                self.create()
        # Failed allocation must never follow the replacement path to clean up.
        self.assertTrue(any((self.workspace / "worktrees/reserved-reviews").iterdir()))

    def test_directory_replaced_by_regular_directory_is_also_detected(self):
        original_git = module.git

        def replace_parent(repo, *args):
            result = original_git(repo, *args)
            if args[:2] == ("worktree", "add"):
                parent = self.workspace / "worktrees/reviews"
                parent.rename(parent.with_name("reserved-reviews"))
                parent.mkdir()
                (parent / Path(args[3]).name).mkdir()
            return result

        with patch.object(module, "git", side_effect=replace_parent):
            with self.assertRaisesRegex(ValueError, "identity changed"):
                self.create()


if __name__ == "__main__":
    unittest.main()
