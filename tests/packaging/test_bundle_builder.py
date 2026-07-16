#!/usr/bin/env python3
"""Focused tests for the deterministic Git-object bundle builder."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILDER_PATH = ROOT / "packaging" / "build_bundle.py"
MODULE_SPEC = importlib.util.spec_from_file_location("startup_factory_bundle_builder", BUILDER_PATH)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError(f"cannot load {BUILDER_PATH}")
builder = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = builder
MODULE_SPEC.loader.exec_module(builder)


PRESERVED_CONFIGS = [
    "config/project-management.config.md",
    "config/planning.config.md",
    "config/team.config.md",
    "config/statuses.config.json",
    "config/automation.config.json",
    "config/deployment.config.json",
    "config/guardrails.config.json",
]
INCLUDED_ROOTS = [
    "adapters",
    "bin",
    "config",
    "extensions",
    "reference",
    "roles",
    "teams",
    "tests",
]


class BundleBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temp = Path(self.temporary_directory.name)

    def git(self, repo: Path, *arguments: str) -> str:
        process = subprocess.run(
            ["git", "-C", os.fspath(repo), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        if process.returncode:
            self.fail(
                f"git {' '.join(arguments)} failed ({process.returncode}): {process.stderr}"
            )
        return process.stdout.strip()

    def write(self, repo: Path, relative: str, data: str, mode: int = 0o644) -> None:
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(data, encoding="utf-8")
        destination.chmod(mode)

    def commit_all(self, repo: Path, message: str) -> str:
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-q", "-m", message)
        return self.git(repo, "rev-parse", "HEAD")

    def make_repo(self, name: str) -> tuple[Path, str]:
        repo = self.temp / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.name", "Bundle Test")
        self.git(repo, "config", "user.email", "bundle-test@example.invalid")

        self.write(repo, "LICENSE", "MIT fixture\n")
        self.write(repo, "README.md", "# Fixture\n")
        self.write(repo, "SKILL.md", "---\nname: startup-factory\n---\n")
        self.write(repo, "adapters/_TEMPLATE.md", "adapter fixture\n")
        self.write(repo, "bin/tool.sh", "#!/bin/sh\necho committed\n", 0o755)
        for relative in PRESERVED_CONFIGS:
            self.write(repo, relative, f"fixture:{relative}\n")
        self.write(repo, "extensions/tracker-backends/README.md", "extension fixture\n")
        self.write(repo, "reference/automation.md", "reference fixture\n")
        self.write(repo, "roles/team-lead.md", "role fixture\n")
        self.write(repo, "teams/_PLAYBOOK.md", "team fixture\n")
        self.write(repo, "tests/run-all.sh", "#!/bin/sh\nexit 0\n", 0o755)
        self.write(
            repo,
            "tests/packaging/release-only-test.py",
            "raise RuntimeError('must not ship in the operational bundle')\n",
        )

        required_paths = [
            *(f"{root}/" for root in INCLUDED_ROOTS),
            "LICENSE",
            "README.md",
            "SKILL.md",
            "adapters/_TEMPLATE.md",
            "bin/tool.sh",
            *PRESERVED_CONFIGS,
            "extensions/tracker-backends/README.md",
            "reference/automation.md",
            "roles/team-lead.md",
            "teams/_PLAYBOOK.md",
            "tests/run-all.sh",
        ]
        spec = {
            "schemaVersion": 1,
            "sourceRepository": "https://example.invalid/startup-factory",
            "include": {
                "files": ["LICENSE", "README.md", "SKILL.md"],
                "roots": INCLUDED_ROOTS,
                "excludeRoots": ["tests/packaging"],
            },
            "requiredPaths": required_paths,
            "preservationPolicy": {
                "version": 1,
                "preservedConfigFiles": PRESERVED_CONFIGS,
                "extensionRoots": ["adapters", "extensions", "teams"],
            },
        }
        self.write(
            repo,
            "packaging/bundle-spec.json",
            json.dumps(spec, indent=2, sort_keys=True) + "\n",
        )
        return repo, self.commit_all(repo, "fixture")

    def build(self, repo: Path, commit: str, output: Path):
        return builder.build_bundle(
            repo=repo,
            commit=commit,
            version="1.2.3-test.1",
            output=output,
        )

    def manifest(self, archive: Path) -> dict:
        with tarfile.open(archive, "r:gz") as bundle:
            member = bundle.getmember("startup-factory/.startup-factory-bundle.json")
            extracted = bundle.extractfile(member)
            self.assertIsNotNone(extracted)
            return json.loads(extracted.read())

    def test_reproducible_archive_manifest_and_sidecar(self) -> None:
        repo, commit = self.make_repo("reproducible")
        first = self.temp / "first" / "startup-factory-1.2.3.tar.gz"
        second = self.temp / "second" / "startup-factory-1.2.3.tar.gz"

        first_result = self.build(repo, commit, first)
        second_result = self.build(repo, commit, second)

        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_result.sidecar.read_bytes(), second_result.sidecar.read_bytes())
        self.assertEqual(first.read_bytes()[4:8], b"\0\0\0\0")
        archive_digest = hashlib.sha256(first.read_bytes()).hexdigest()
        self.assertEqual(first_result.sha256, archive_digest)
        self.assertEqual(
            first_result.sidecar.read_text(encoding="ascii"),
            f"{archive_digest}  {first.name}\n",
        )

        with tarfile.open(first, "r:gz") as archive:
            members = archive.getmembers()
            self.assertTrue(members)
            self.assertEqual(
                members[0].name,
                "startup-factory/.startup-factory-bundle.json",
            )
            self.assertTrue(all(member.name.startswith("startup-factory/") for member in members))
            self.assertTrue(all(member.isfile() for member in members))
            for member in members:
                self.assertEqual(member.mtime, 0)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertEqual(member.uname, "")
                self.assertEqual(member.gname, "")

            executable = archive.getmember("startup-factory/bin/tool.sh")
            self.assertEqual(executable.mode, 0o755)
            readme = archive.extractfile("startup-factory/README.md")
            self.assertIsNotNone(readme)
            self.assertEqual(readme.read(), b"# Fixture\n")

        manifest = self.manifest(first)
        self.assertEqual(
            set(manifest),
            {
                "schemaVersion",
                "name",
                "version",
                "sourceRepository",
                "sourceCommit",
                "preservationPolicy",
                "requiredPaths",
                "files",
            },
        )
        self.assertEqual(manifest["schemaVersion"], 1)
        self.assertEqual(manifest["name"], "startup-factory")
        self.assertEqual(manifest["version"], "1.2.3-test.1")
        self.assertEqual(manifest["sourceCommit"], commit)
        self.assertEqual(
            manifest["sourceRepository"], "https://example.invalid/startup-factory"
        )
        self.assertEqual(
            manifest["preservationPolicy"]["preservedConfigFiles"],
            PRESERVED_CONFIGS,
        )
        self.assertEqual(
            manifest["preservationPolicy"]["extensionRoots"],
            ["adapters", "extensions", "teams"],
        )
        self.assertIn("tests/", manifest["requiredPaths"])
        rows = manifest["files"]
        self.assertEqual([row["path"] for row in rows], sorted(row["path"] for row in rows))
        self.assertNotIn(".startup-factory-bundle.json", {row["path"] for row in rows})
        executable_row = next(row for row in rows if row["path"] == "bin/tool.sh")
        self.assertEqual(executable_row["mode"], "0755")
        self.assertEqual(executable_row["size"], len(b"#!/bin/sh\necho committed\n"))
        self.assertEqual(
            executable_row["sha256"],
            hashlib.sha256(b"#!/bin/sh\necho committed\n").hexdigest(),
        )

    def test_dirty_worktree_and_dirty_spec_are_excluded(self) -> None:
        repo, commit = self.make_repo("dirty")
        self.write(repo, "bin/tool.sh", "dirty worktree bytes\n", 0o600)
        self.write(repo, "bin/untracked.py", "raise RuntimeError('not committed')\n")
        self.write(repo, "packaging/bundle-spec.json", "not valid JSON\n")

        output = self.temp / "dirty-output" / "bundle.tar.gz"
        self.build(repo, commit, output)

        with tarfile.open(output, "r:gz") as archive:
            committed = archive.extractfile("startup-factory/bin/tool.sh")
            self.assertIsNotNone(committed)
            self.assertEqual(committed.read(), b"#!/bin/sh\necho committed\n")
            self.assertEqual(archive.getmember("startup-factory/bin/tool.sh").mode, 0o755)
            self.assertNotIn("startup-factory/bin/untracked.py", archive.getnames())
            self.assertNotIn(
                "startup-factory/tests/packaging/release-only-test.py",
                archive.getnames(),
            )
        self.assertEqual(self.manifest(output)["sourceCommit"], commit)

    def test_rejects_symlinks_submodules_and_newline_paths(self) -> None:
        repo, _ = self.make_repo("symlink")
        (repo / "bin" / "linked-tool").symlink_to("tool.sh")
        symlink_commit = self.commit_all(repo, "add symlink")
        with self.assertRaisesRegex(builder.BundleError, "symlink"):
            self.build(repo, symlink_commit, self.temp / "symlink.tar.gz")

        repo, head = self.make_repo("submodule")
        self.git(
            repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{head},extensions/vendor",
        )
        self.git(repo, "commit", "-q", "-m", "add gitlink")
        submodule_commit = self.git(repo, "rev-parse", "HEAD")
        with self.assertRaisesRegex(builder.BundleError, "submodule"):
            self.build(repo, submodule_commit, self.temp / "submodule.tar.gz")

        repo, _ = self.make_repo("newline")
        self.write(repo, "bin/bad\nname.py", "unsafe\n")
        newline_commit = self.commit_all(repo, "add newline path")
        with self.assertRaisesRegex(builder.BundleError, "newline"):
            self.build(repo, newline_commit, self.temp / "newline.tar.gz")


if __name__ == "__main__":
    unittest.main()
