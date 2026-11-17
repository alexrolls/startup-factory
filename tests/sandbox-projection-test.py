#!/usr/bin/env python3
"""Real raw-object task projection, with adversarial checkout inputs."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
from host_git import HostGit, HostGitError
from sandbox_acceptance import task_key
from sandbox_projection import materialize


class ProjectionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("SF_REGISTRY_TEST_ROOT"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.repo = self.root / "repo"; self.repo.mkdir(mode=0o700)
        self.env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture"); self.git("config", "user.email", "f@example.invalid")
        (self.repo / "old").mkdir(); (self.repo / "old/file").write_bytes(b"base\n")
        (self.repo / "replace").write_bytes(b"file to directory\n")
        self.git("add", "."); self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.key = task_key("T-1"); self.ref = "refs/heads/agent-task/team/" + self.key
        self.workspace = self.repo / ".teamwork/team"
        self.wt = self.workspace / "worktrees" / ("backend#1-" + self.key)
        self.wt.parent.mkdir(mode=0o700, parents=True)
        self.git("worktree", "add", "-qb", self.ref[len("refs/heads/"):], str(self.wt), self.base)
        (self.repo / "old/file").unlink(); (self.repo / "old").rmdir()
        (self.repo / "replace").unlink(); (self.repo / "replace").mkdir()
        (self.repo / "replace/child").write_bytes(b"accepted\x00\xff")
        (self.repo / "new.sh").write_bytes(b"#!/bin/sh\nexit 0\n"); (self.repo / "new.sh").chmod(0o755)
        self.git("add", "old", "replace", "new.sh"); self.git("commit", "-qm", "candidate")
        self.accepted = self.git("rev-parse", "HEAD")
        self.git("update-ref", self.ref, self.accepted, self.base)
        self.host = HostGit(self.repo)

    def git(self, *args, path=None):
        return subprocess.check_output(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(path or self.repo), *args], env=self.env, stderr=subprocess.PIPE, timeout=5).decode().strip()

    def project(self):
        materialize(self.host, workspace=self.workspace, team="team", task="T-1", role="backend", attempt=1,
            base_commit=self.base, accepted_commit=self.accepted, staging=self.root / "stage")

    def test_raw_projection_updates_index_and_is_idempotent(self):
        self.project(); self.project()
        self.assertFalse((self.wt / "old").exists())
        self.assertEqual((self.wt / "replace/child").read_bytes(), b"accepted\x00\xff")
        self.assertTrue((self.wt / "new.sh").stat().st_mode & 0o111)
        self.assertEqual(self.git("status", "--porcelain", path=self.wt), "")

    def test_human_edit_untracked_and_links_are_preserved_and_refused(self):
        path = self.wt / "old/file"
        path.write_bytes(b"human work\n")
        with self.assertRaises(HostGitError): self.project()
        self.assertEqual(path.read_bytes(), b"human work\n")
        path.write_bytes(b"base\n")
        extra = self.wt / "extra"; extra.symlink_to(self.root)
        with self.assertRaises(HostGitError): self.project()
        extra.unlink(); extra.write_bytes(b"untracked")
        with self.assertRaises(HostGitError): self.project()

    def test_configured_filters_are_rejected_before_any_materialization(self):
        self.git("config", "filter.evil.smudge", "touch " + str(self.root / "executed"))
        with self.assertRaisesRegex(HostGitError, "filters"): self.project()
        self.assertFalse((self.root / "executed").exists())
        self.assertEqual((self.wt / "old/file").read_bytes(), b"base\n")

    def test_wrong_linked_worktree_and_ref_never_get_adopted(self):
        (self.wt / ".git").write_text("gitdir: /tmp/other\n")
        with self.assertRaises(HostGitError): self.project()
        self.assertEqual((self.wt / "old/file").read_bytes(), b"base\n")


if __name__ == "__main__": unittest.main()
