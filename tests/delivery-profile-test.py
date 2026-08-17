#!/usr/bin/env python3
"""Offline fail-closed tests for diagnostic delivery profile assessment."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from delivery_profile import (  # noqa: E402
    DeliveryProfileError,
    assess_diff,
    assess_task,
    is_ordinary_documentation_path,
)
from task_metadata import parse_task_metadata  # noqa: E402


class GitFixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.run("init", "-q")
        self.run("config", "user.name", "Test User")
        self.run("config", "user.email", "test@example.invalid")
        self.run("config", "core.filemode", "true")
        self.write("README.md", "baseline\n")
        self.commit("baseline")

    def close(self):
        self.temporary.cleanup()

    def run(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.stdout.strip()

    def write(self, relative: str, content: str | bytes):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.run("add", "-A")
        self.run("commit", "-q", "-m", message)
        return self.run("rev-parse", "HEAD")

    @property
    def head(self) -> str:
        return self.run("rev-parse", "HEAD")


def task(description: str = "", title: str = "Update docs") -> dict:
    return {"title": title, "description": description}


class TaskAssessmentTests(unittest.TestCase):
    def test_only_allowlisted_ordinary_documentation_paths(self):
        for path in (
            "README.md",
            "LICENSE",
            "docs/guide.md",
            "documentation/setup.rst",
        ):
            self.assertTrue(is_ordinary_documentation_path(path), path)
        for path in (
            "src/README.md",
            "tests/README.md",
            "config/README.md",
            "roles/qa.md",
            "docs/AGENTS.md",
            "docs/superpowers/plan.md",
            "docs/settings.json",
            "docs/component.mdx",
            "../README.md",
            "/README.md",
            "docs\\guide.md",
            "docs//guide.md",
        ):
            self.assertFalse(is_ordinary_documentation_path(path), path)

    def test_task_micro_requires_bounded_declared_docs(self):
        result = assess_task(task("files: docs/guide.md\ndelivery-profile: auto"))
        self.assertEqual("micro", result["effectiveProfile"])
        self.assertTrue(result["diagnosticOnly"])
        self.assertEqual(["bounded-ordinary-documentation"], result["reasons"])

    def test_task_ambiguity_and_control_paths_fail_closed(self):
        cases = (
            task(""),
            task("delivery-profile: micro"),
            task("files: src/widget.py\ndelivery-profile: micro"),
            task("files: docs/AGENTS.md"),
            task("files: docs/a.md, docs/b.md, docs/c.md, docs/d.md"),
            task("files: docs/a.md, docs/a.md"),
            task("files: docs/a.md\nresources: database"),
            task("files: docs/auth.md", title="Document authentication"),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate):
                self.assertEqual("standard", assess_task(candidate)["effectiveProfile"])

    def test_standard_request_can_only_increase_rigor(self):
        result = assess_task(task("files: README.md\ndelivery-profile: standard"))
        self.assertEqual("standard", result["effectiveProfile"])
        self.assertIn("standard-requested", result["reasons"])

    def test_metadata_rejects_unknown_delivery_profile(self):
        with self.assertRaisesRegex(ValueError, "delivery-profile"):
            parse_task_metadata("delivery-profile: turbo")
        with self.assertRaisesRegex(ValueError, "more than once"):
            parse_task_metadata("delivery-profile: standard\ndelivery-profile: micro")


class DiffAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.git = GitFixture()

    def tearDown(self):
        self.git.close()

    def assess(self, base: str, description: str = "delivery-profile: auto") -> dict:
        return assess_diff(self.git.root, base, self.git.head, task(description))

    def test_small_documentation_diff_is_micro_and_deterministic(self):
        base = self.git.head
        self.git.write("docs/guide.md", "one\ntwo\n")
        self.git.commit("docs")
        expected = self.assess(base, "files: docs/guide.md\ndelivery-profile: micro")
        actual = self.assess(base, "files: docs/guide.md\ndelivery-profile: micro")
        self.assertEqual(expected, actual)
        self.assertEqual("micro", actual["effectiveProfile"])
        self.assertEqual(2, actual["changedLines"])
        self.assertEqual(["docs/guide.md"], actual["files"])
        self.assertEqual(["bounded-ordinary-documentation-diff"], actual["reasons"])

    def test_standard_request_and_declared_scope_mismatch_fail_closed(self):
        base = self.git.head
        self.git.write("docs/guide.md", "guide\n")
        self.git.commit("docs")
        standard = self.assess(base, "files: docs/guide.md\ndelivery-profile: standard")
        mismatch = self.assess(base, "files: docs/other.md\ndelivery-profile: micro")
        self.assertEqual("standard", standard["effectiveProfile"])
        self.assertEqual("standard", mismatch["effectiveProfile"])
        self.assertIn("declared-files-mismatch", mismatch["reasons"])

    def test_code_binary_and_large_changes_fail_closed(self):
        cases = (
            ("src/widget.py", b"print('x')\n", "non-ordinary-documentation-path"),
            ("docs/blob.md", b"text\x00binary", "binary-content"),
            (
                "docs/large.md",
                ("line\n" * 201).encode(),
                "too-many-changed-lines",
            ),
        )
        for relative, content, reason in cases:
            with self.subTest(relative=relative):
                fixture = GitFixture()
                try:
                    base = fixture.head
                    fixture.write(relative, content)
                    fixture.commit("change")
                    result = assess_diff(
                        fixture.root,
                        base,
                        fixture.head,
                        task("delivery-profile: micro"),
                    )
                    self.assertEqual("standard", result["effectiveProfile"])
                    self.assertTrue(any(item.startswith(reason) for item in result["reasons"]))
                finally:
                    fixture.close()

    def test_actual_path_and_patch_content_raise_the_risk_floor(self):
        cases = (
            ("docs/schema.md", b"ordinary words\n", "strong-risk-diff-path"),
            (
                "docs/guide.md",
                b"Document the authentication flow.\n",
                "strong-risk-diff-content",
            ),
            ("docs/component.mdx", b"# Heading\n", "non-ordinary-documentation-path"),
        )
        for relative, content, reason in cases:
            with self.subTest(relative=relative):
                fixture = GitFixture()
                try:
                    base = fixture.head
                    fixture.write(relative, content)
                    fixture.commit("docs")
                    result = assess_diff(
                        fixture.root,
                        base,
                        fixture.head,
                        task("delivery-profile: micro", "Ordinary documentation"),
                    )
                    self.assertEqual("standard", result["effectiveProfile"])
                    self.assertIn(reason, result["reasons"])
                finally:
                    fixture.close()

    def test_oversized_and_non_utf8_patches_fail_closed(self):
        cases = (
            (b"x" * 600_000, "unreadable-or-oversized-patch"),
            (b"invalid: \xff\n", "unreadable-or-oversized-patch"),
        )
        for content, reason in cases:
            with self.subTest(reason=reason, size=len(content)):
                fixture = GitFixture()
                try:
                    base = fixture.head
                    fixture.write("docs/guide.md", content)
                    fixture.commit("docs")
                    result = assess_diff(
                        fixture.root,
                        base,
                        fixture.head,
                        task("delivery-profile: micro", "Ordinary documentation"),
                    )
                    self.assertEqual("standard", result["effectiveProfile"])
                    self.assertIn(reason, result["reasons"])
                finally:
                    fixture.close()

    def test_delete_rename_symlink_and_mode_change_fail_closed(self):
        fixtures: list[tuple[GitFixture, str]] = []
        try:
            deletion = GitFixture()
            deletion.write("docs/old.md", "old\n")
            deletion.commit("seed doc")
            base = deletion.head
            (deletion.root / "docs/old.md").unlink()
            deletion.commit("delete")
            fixtures.append((deletion, base))

            rename = GitFixture()
            rename.write("docs/old.md", "same contents\n")
            rename.commit("seed doc")
            base = rename.head
            (rename.root / "docs/old.md").rename(rename.root / "docs/new.md")
            rename.commit("rename")
            fixtures.append((rename, base))

            symlink = GitFixture()
            base = symlink.head
            (symlink.root / "docs").mkdir()
            os.symlink("../README.md", symlink.root / "docs/link.md")
            symlink.commit("symlink")
            fixtures.append((symlink, base))

            mode = GitFixture()
            mode.write("docs/guide.md", "guide\n")
            mode.commit("seed doc")
            base = mode.head
            os.chmod(mode.root / "docs/guide.md", 0o755)
            mode.commit("mode")
            fixtures.append((mode, base))

            for fixture, base in fixtures:
                with self.subTest(root=fixture.root):
                    result = assess_diff(
                        fixture.root,
                        base,
                        fixture.head,
                        task("delivery-profile: micro"),
                    )
                    self.assertEqual("standard", result["effectiveProfile"])
        finally:
            for fixture, _ in fixtures:
                fixture.close()

    def test_empty_diff_and_strong_risk_language_fail_closed(self):
        empty = assess_diff(
            self.git.root,
            self.git.head,
            self.git.head,
            task("delivery-profile: micro"),
        )
        self.assertEqual("standard", empty["effectiveProfile"])
        self.assertIn("empty-diff", empty["reasons"])
        base = self.git.head
        self.git.write("docs/auth.md", "authentication\n")
        self.git.commit("auth docs")
        risky = assess_diff(
            self.git.root,
            base,
            self.git.head,
            task("files: docs/auth.md\ndelivery-profile: micro", "Authentication docs"),
        )
        self.assertEqual("standard", risky["effectiveProfile"])
        self.assertIn("strong-risk-language", risky["reasons"])

    def test_requires_exact_repository_root_and_valid_commits(self):
        (self.git.root / "docs").mkdir()
        with self.assertRaisesRegex(DeliveryProfileError, "top level"):
            assess_diff(
                self.git.root / "docs",
                self.git.head,
                self.git.head,
                task(),
            )
        with self.assertRaisesRegex(DeliveryProfileError, "git command failed"):
            assess_diff(self.git.root, "missing-revision", self.git.head, task())


if __name__ == "__main__":
    unittest.main(verbosity=2)
