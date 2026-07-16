from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from startup_factory_cli import cli, installer  # noqa: E402


CONFIG_PATHS = (
    "config/project-management.config.md",
    "config/planning.config.md",
    "config/team.config.md",
    "config/statuses.config.json",
    "config/automation.config.json",
    "config/deployment.config.json",
    "config/guardrails.config.json",
)


def base_payload(version: str = "1") -> dict[str, tuple[bytes, int]]:
    payload: dict[str, tuple[bytes, int]] = {
        "SKILL.md": (b"---\nname: startup-factory\ndescription: fixture\n---\n", 0o644),
        "README.md": (f"fixture-{version}\n".encode(), 0o644),
        "bin/update-installed-skill.sh": (b"#!/bin/sh\nexit 0\n", 0o755),
        "bin/runtime.sh": (f"#!/bin/sh\necho runtime-{version}\n".encode(), 0o755),
        "adapters/_TEMPLATE.md": (b"adapter-template\n", 0o644),
        "adapters/Retired.md": (b"retired-v1\n", 0o644),
        "extensions/tracker-backends/README.md": (b"backend-contract\n", 0o644),
        "reference/automation.md": (b"automation-reference\n", 0o644),
        "roles/team-lead.md": (b"team-lead\n", 0o644),
        "teams/_PLAYBOOK.md": (b"playbook\n", 0o644),
        "tests/run-all.sh": (b"#!/bin/sh\necho ALL TESTS PASS\n", 0o755),
    }
    for path in CONFIG_PATHS:
        payload[path] = (f"default-{version}:{path}\n".encode(), 0o644)
    return payload


def write_bundle(
    path: Path,
    *,
    version: str = "1.0.0",
    payload: dict[str, tuple[bytes, int]] | None = None,
    bad_digest: str | None = None,
    unexpected: str | None = None,
    unsafe: str | None = None,
    symlink: str | None = None,
    duplicate: str | None = None,
    manifest_mode: int = 0o644,
) -> Path:
    payload = dict(payload or base_payload(version.split(".")[0]))
    records = []
    for relative in sorted(payload):
        content, mode = payload[relative]
        digest = hashlib.sha256(content).hexdigest()
        if relative == bad_digest:
            digest = "0" * 64
        records.append(
            {
                "path": relative,
                "size": len(content),
                "mode": f"0{mode:o}",
                "sha256": digest,
            }
        )
    manifest = {
        "schemaVersion": 1,
        "name": "startup-factory",
        "version": version,
        "sourceRepository": "alexrolls/startup-factory",
        "sourceCommit": ("1" if version.startswith("1") else "2") * 40,
        "preservationPolicy": {
            "version": 1,
            "preservedConfigFiles": list(CONFIG_PATHS),
            "extensionRoots": ["adapters", "extensions", "teams"],
        },
        "requiredPaths": [
            "SKILL.md",
            "bin/update-installed-skill.sh",
            "adapters/",
            "config/",
            "extensions/",
            "reference/",
            "roles/",
            "teams/",
            "tests/",
        ],
        "files": records,
    }
    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        manifest_info = tarfile.TarInfo("startup-factory/.startup-factory-bundle.json")
        manifest_info.size = len(manifest_bytes)
        manifest_info.mode = manifest_mode
        manifest_info.mtime = 0
        archive.addfile(manifest_info, io.BytesIO(manifest_bytes))
        for relative in sorted(payload):
            content, mode = payload[relative]
            info = tarfile.TarInfo(f"startup-factory/{relative}")
            info.size = len(content)
            info.mode = mode
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
            if duplicate == relative:
                archive.addfile(info, io.BytesIO(content))
        if unexpected:
            content = b"unexpected\n"
            info = tarfile.TarInfo(f"startup-factory/{unexpected}")
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
        if unsafe:
            content = b"unsafe\n"
            info = tarfile.TarInfo(unsafe)
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
        if symlink:
            info = tarfile.TarInfo(f"startup-factory/{symlink}")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../outside"
            info.mode = 0o777
            archive.addfile(info)
    return path


def run_cli(*arguments: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = cli.main(list(arguments))
    return result, stdout.getvalue(), stderr.getvalue()


class CliInstallerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.bundle_v1 = write_bundle(self.root / "v1.tar.gz")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def install(self, *, agent: str = "codex", bundle: Path | None = None) -> Path:
        selected = bundle or self.bundle_v1
        code, output, error = run_cli(
            "install",
            "--agent",
            agent,
            "--project",
            str(self.project),
            "--bundle",
            str(selected),
            "--json",
        )
        self.assertEqual((code, error), (0, ""), output + error)
        relative = ".claude/skills/startup-factory" if agent.startswith("claude") else ".agents/skills/startup-factory"
        return self.project / relative

    def update(self, target: Path, bundle: Path, *extra: str) -> tuple[int, str, str]:
        return run_cli(
            "update",
            "--install-dir",
            str(target),
            "--project",
            str(self.project),
            "--bundle",
            str(bundle),
            "--json",
            *extra,
        )

    def test_install_verify_and_agent_mappings(self) -> None:
        target = self.install(agent="claude-code")
        self.assertTrue((target / "SKILL.md").is_file())
        self.assertEqual(stat.S_IMODE((target / "bin/runtime.sh").stat().st_mode), 0o755)
        provenance = json.loads((target / ".startup-factory-install.json").read_text())
        self.assertEqual(provenance["version"], "1.0.0")
        self.assertRegex(provenance["archiveSha256"], r"^[0-9a-f]{64}$")
        owned = set((target / ".startup-factory-owned-files").read_text().splitlines())
        self.assertIn("config/automation.config.json", owned)
        self.assertIn("config/planning.config.md", owned)

        (target / "config/automation.config.json").write_text("project-owned\n")
        code, output, error = run_cli(
            "verify",
            "--agent",
            "claude",
            "--project",
            str(self.project),
            "--json",
        )
        self.assertEqual((code, error), (0, ""), output + error)
        verified = json.loads(output)
        self.assertEqual(verified["action"], "verify")
        self.assertIn("config/automation.config.json", verified["preservedConfigs"])
        self.assertIn("config/planning.config.md", verified["preservedConfigs"])

        (target / "bin/runtime.sh").write_text("tampered\n")
        code, _, error = run_cli(
            "verify", "--install-dir", str(target), "--project", str(self.project), "--json"
        )
        self.assertEqual(code, 1)
        self.assertIn("digest mismatch", error)

    def test_update_preserves_config_and_custom_extensions(self) -> None:
        target = self.install()
        for relative in CONFIG_PATHS:
            (target / relative).write_text(f"project:{relative}\n")
        custom_files = {
            "adapters/Acme.md": ("custom-adapter\n", 0o644),
            "extensions/tracker-backends/Acme.py": ("#!/usr/bin/env python3\n", 0o755),
            "teams/acme.md": ("custom-team\n", 0o644),
            "teams/roles/acme-specialist.md": ("custom-role\n", 0o644),
        }
        for relative, (content, mode) in custom_files.items():
            path = target / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(mode)
        (target / "outside-custom.txt").write_text("delete-me\n")

        payload_v2 = base_payload("2")
        del payload_v2["adapters/Retired.md"]
        payload_v2["adapters/BuiltIn.md"] = (b"built-in-v2\n", 0o644)
        bundle_v2 = write_bundle(self.root / "v2.tar.gz", version="2.0.0", payload=payload_v2)
        code, output, error = self.update(target, bundle_v2)
        self.assertEqual((code, error), (0, ""), output + error)
        self.assertIn("runtime-2", (target / "bin/runtime.sh").read_text())
        self.assertFalse((target / "adapters/Retired.md").exists())
        self.assertFalse((target / "outside-custom.txt").exists())
        for relative in CONFIG_PATHS:
            self.assertEqual((target / relative).read_text(), f"project:{relative}\n")
        for relative, (content, mode) in custom_files.items():
            path = target / relative
            self.assertEqual(path.read_text(), content)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)

        code, output, error = self.update(target, bundle_v2, "--overwrite-config")
        self.assertEqual((code, error), (0, ""), output + error)
        for relative in CONFIG_PATHS:
            self.assertEqual((target / relative).read_bytes(), payload_v2[relative][0])
        self.assertTrue((target / "extensions/tracker-backends/Acme.py").is_file())

    def test_new_upstream_custom_collision_fails_before_mutation(self) -> None:
        target = self.install()
        custom = target / "adapters/Future.md"
        custom.write_text("project-future\n")
        before_runtime = (target / "bin/runtime.sh").read_bytes()
        payload_v2 = base_payload("2")
        payload_v2["adapters/Future.md"] = (b"upstream-future\n", 0o644)
        bundle_v2 = write_bundle(self.root / "collision.tar.gz", version="2.0.0", payload=payload_v2)
        code, _, error = self.update(target, bundle_v2)
        self.assertEqual(code, 1)
        self.assertIn("collides with project-owned path", error)
        self.assertEqual(custom.read_text(), "project-future\n")
        self.assertEqual((target / "bin/runtime.sh").read_bytes(), before_runtime)

    def test_fresh_dry_run_writes_nothing(self) -> None:
        target = self.project / ".agents/skills/startup-factory"
        code, output, error = run_cli(
            "install",
            "--project",
            str(self.project),
            "--bundle",
            str(self.bundle_v1),
            "--dry-run",
            "--json",
        )
        self.assertEqual((code, error), (0, ""), output + error)
        self.assertFalse(target.exists())
        self.assertFalse((self.project / ".agents").exists())
        self.assertTrue(json.loads(output)["dryRun"])

    def test_destination_safety_refuses_root_home_git_symlink_and_unrelated(self) -> None:
        cases: list[tuple[str, Path]] = [("root", Path("/")), ("home", Path.home())]
        git_root = self.root / "git-root"
        (git_root / ".git").mkdir(parents=True)
        cases.append(("git", git_root))
        real = self.root / "real"
        real.mkdir()
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)
        cases.append(("symlink", link))
        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        (unrelated / "sentinel").write_text("keep\n")
        cases.append(("unrelated", unrelated))

        for label, target in cases:
            with self.subTest(label=label):
                code, _, error = run_cli(
                    "install",
                    "--project",
                    str(self.project),
                    "--install-dir",
                    str(target),
                    "--bundle",
                    str(self.bundle_v1),
                    "--dry-run",
                    "--json",
                )
                self.assertEqual(code, 1)
                self.assertTrue(error)
        self.assertEqual((unrelated / "sentinel").read_text(), "keep\n")

    def test_project_scoped_targets_cannot_follow_symlink_ancestors_or_escape(self) -> None:
        for marker, agent in ((".agents", "codex"), (".claude", "claude")):
            with self.subTest(marker=marker):
                project = self.root / f"project-{marker[1:]}"
                outside = self.root / f"outside-{marker[1:]}"
                project.mkdir()
                outside.mkdir()
                (project / marker).symlink_to(outside, target_is_directory=True)
                code, _, error = run_cli(
                    "install",
                    "--agent",
                    agent,
                    "--project",
                    str(project),
                    "--bundle",
                    str(self.bundle_v1),
                    "--json",
                )
                self.assertEqual(code, 1)
                self.assertIn("symlink component", error)
                self.assertEqual(list(outside.iterdir()), [])

        relative_project = self.root / "relative-project"
        relative_outside = self.root / "relative-outside"
        relative_project.mkdir()
        relative_outside.mkdir()
        (relative_project / "linked").symlink_to(relative_outside, target_is_directory=True)
        code, _, error = run_cli(
            "install",
            "--project",
            str(relative_project),
            "--install-dir",
            "linked/startup-factory",
            "--bundle",
            str(self.bundle_v1),
            "--json",
        )
        self.assertEqual(code, 1)
        self.assertIn("symlink component", error)
        self.assertEqual(list(relative_outside.iterdir()), [])

        escaped = self.root / "escaped"
        code, _, error = run_cli(
            "install",
            "--project",
            str(relative_project),
            "--install-dir",
            "../escaped/startup-factory",
            "--bundle",
            str(self.bundle_v1),
            "--json",
        )
        self.assertEqual(code, 1)
        self.assertIn("remain inside --project", error)
        self.assertFalse(escaped.exists())

        external_target = self.root / "protected-external" / "startup-factory"
        code, output, error = run_cli(
            "install",
            "--project",
            str(relative_project),
            "--install-dir",
            str(external_target),
            "--bundle",
            str(self.bundle_v1),
            "--json",
        )
        self.assertEqual((code, error), (0, ""), output + error)
        self.assertTrue((external_target / "SKILL.md").is_file())

    def test_installer_lock_rejects_symlinks_and_hardlinks_without_clobbering(self) -> None:
        target = self.project / ".agents/skills/startup-factory"
        target.parent.mkdir(parents=True)
        lock = target.parent / ".startup-factory.startup-factory.lock"

        for link_type in ("symlink", "hardlink"):
            with self.subTest(link_type=link_type):
                sentinel = self.root / f"{link_type}-sentinel"
                sentinel.write_text(f"keep-{link_type}\n")
                if link_type == "symlink":
                    lock.symlink_to(sentinel)
                else:
                    os.link(sentinel, lock)

                code, _, error = run_cli(
                    "install",
                    "--project",
                    str(self.project),
                    "--bundle",
                    str(self.bundle_v1),
                    "--json",
                )

                self.assertEqual(code, 1)
                self.assertIn("installer lock", error)
                self.assertEqual(sentinel.read_text(), f"keep-{link_type}\n")
                self.assertTrue(os.path.lexists(lock))
                if link_type == "symlink":
                    self.assertTrue(lock.is_symlink())
                else:
                    self.assertTrue(lock.samefile(sentinel))
                self.assertFalse(target.exists())
                lock.unlink()

    def test_archive_validation_rejects_tampering_and_unsafe_members(self) -> None:
        malformed = {
            "digest": write_bundle(self.root / "bad-digest.tar.gz", bad_digest="README.md"),
            "unexpected": write_bundle(
                self.root / "unexpected.tar.gz", unexpected="surprise.txt"
            ),
            "unsafe": write_bundle(
                self.root / "unsafe.tar.gz", unsafe="startup-factory/../escape"
            ),
            "symlink": write_bundle(self.root / "symlink.tar.gz", symlink="linked"),
            "duplicate": write_bundle(
                self.root / "duplicate.tar.gz", duplicate="README.md"
            ),
            "manifest-mode": write_bundle(
                self.root / "manifest-mode.tar.gz", manifest_mode=0o600
            ),
        }
        for label, archive in malformed.items():
            with self.subTest(label=label):
                with self.assertRaises(installer.InstallerError):
                    installer.validate_bundle(archive)

        with self.assertRaisesRegex(installer.InstallerError, "trusted sidecar"):
            installer.validate_bundle(self.bundle_v1, expected_sha256="0" * 64)

    def test_failed_swap_rolls_back_original_installation(self) -> None:
        target = self.install()
        payload_v2 = base_payload("2")
        bundle_v2_path = write_bundle(
            self.root / "rollback.tar.gz", version="2.0.0", payload=payload_v2
        )
        bundle_v2 = installer.validate_bundle(bundle_v2_path)
        before = (target / "bin/runtime.sh").read_bytes()
        real_replace = os.replace
        calls = 0

        def fail_second_replace(source: os.PathLike[str], destination: os.PathLike[str]) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected swap failure")
            real_replace(source, destination)

        with mock.patch.object(installer.os, "replace", side_effect=fail_second_replace):
            with self.assertRaisesRegex(installer.InstallerError, "transaction failed"):
                installer.install_or_update(
                    bundle_v2,
                    target,
                    command="update",
                    overwrite_config=False,
                    dry_run=False,
                )
        self.assertEqual((target / "bin/runtime.sh").read_bytes(), before)
        self.assertFalse(any(target.parent.glob(".startup-factory.backup.*")))

    def test_preserved_symlinks_and_nonregular_extensions_fail_preflight(self) -> None:
        target = self.install()
        payload_v2 = base_payload("2")
        bundle_v2 = write_bundle(
            self.root / "nonregular-v2.tar.gz", version="2.0.0", payload=payload_v2
        )
        before = (target / "bin/runtime.sh").read_bytes()
        outside = self.root / "outside-config"
        outside.write_text("outside\n")
        config = target / CONFIG_PATHS[0]
        config.unlink()
        config.symlink_to(outside)
        code, _, error = self.update(target, bundle_v2)
        self.assertEqual(code, 1)
        self.assertIn("preserved config is not a regular file", error)
        self.assertEqual((target / "bin/runtime.sh").read_bytes(), before)

        config.unlink()
        config.write_text("project-config\n")
        extension_link = target / "adapters/Linked.md"
        extension_link.symlink_to(outside)
        code, _, error = self.update(target, bundle_v2)
        self.assertEqual(code, 1)
        self.assertIn("project extension is not a regular file", error)
        self.assertEqual((target / "bin/runtime.sh").read_bytes(), before)

        extension_link.unlink()
        if hasattr(os, "mkfifo"):
            fifo = target / "extensions/tracker-backends/events.fifo"
            os.mkfifo(fifo)
            code, _, error = self.update(target, bundle_v2)
            self.assertEqual(code, 1)
            self.assertIn("project extension is not a regular file", error)
            self.assertEqual((target / "bin/runtime.sh").read_bytes(), before)

    def test_explicit_bundle_sidecar_is_enforced_when_present(self) -> None:
        sidecar = Path(str(self.bundle_v1) + ".sha256")
        sidecar.write_text(f"{'0' * 64}  {self.bundle_v1.name}\n", encoding="ascii")
        code, _, error = run_cli(
            "install",
            "--project",
            str(self.project),
            "--bundle",
            str(self.bundle_v1),
            "--json",
        )
        self.assertEqual(code, 1)
        self.assertIn("trusted sidecar", error)
        self.assertFalse((self.project / ".agents").exists())

        digest = hashlib.sha256(self.bundle_v1.read_bytes()).hexdigest()
        sidecar.write_text(f"{digest}  {self.bundle_v1.name}\n", encoding="ascii")
        code, output, error = run_cli(
            "install",
            "--project",
            str(self.project),
            "--bundle",
            str(self.bundle_v1),
            "--json",
        )
        self.assertEqual((code, error), (0, ""), output + error)

    def test_tilde_bundle_path_also_enforces_its_sidecar(self) -> None:
        fake_home = self.root / "home"
        fake_home.mkdir()
        bundle = fake_home / "bundle.tar.gz"
        self.bundle_v1.replace(bundle)
        sidecar = Path(str(bundle) + ".sha256")
        sidecar.write_text(f"{'0' * 64}  {bundle.name}\n", encoding="ascii")
        with mock.patch.dict(os.environ, {"HOME": str(fake_home)}):
            code, _, error = run_cli(
                "install",
                "--project",
                str(self.project),
                "--bundle",
                "~/bundle.tar.gz",
                "--json",
            )
        self.assertEqual(code, 1)
        self.assertIn("trusted sidecar", error)

    def test_version_command_is_machine_readable(self) -> None:
        code, output, error = run_cli("version", "--json")
        self.assertEqual((code, error), (0, ""))
        self.assertIn("version", json.loads(output))


if __name__ == "__main__":
    unittest.main()
