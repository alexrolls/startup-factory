#!/usr/bin/env python3
"""Distribution metadata and embedded-bundle identity tests."""

from __future__ import annotations

import email.parser
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - metadata tests run on 3.11+
    tomllib = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
PROJECT_MANAGEMENT_CONFIG = ROOT / "config" / "project-management.config.md"
TEAM_CONFIG = ROOT / "config" / "team.config.md"
README = ROOT / "README.md"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
PACKAGE_CI_WORKFLOW = ROOT / ".github" / "workflows" / "package-ci.yml"
RESOURCE_ARCHIVE = "startup_factory_cli/resources/startup-factory.tar.gz"
RESOURCE_CHECKSUM = f"{RESOURCE_ARCHIVE}.sha256"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def checksum_digest(payload: bytes) -> str:
    text = payload.decode("ascii").strip()
    match = re.fullmatch(r"([0-9a-f]{64})\s+[* ]?[^\s]+", text)
    if match is None:
        raise AssertionError("embedded checksum is not in sha256sum format")
    return match.group(1)


def canonicalize_sdist(path: Path, *, source_date_epoch: int) -> None:
    """Normalize an sdist's tar and gzip metadata without changing file bytes."""
    if source_date_epoch < 0:
        raise ValueError("source_date_epoch must be non-negative")
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    seen: set[str] = set()
    roots: set[str] = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                raise ValueError(f"unsafe sdist member path: {member.name}")
            if member.name in seen:
                raise ValueError(f"duplicate sdist member path: {member.name}")
            seen.add(member.name)
            roots.add(pure.parts[0])
            if member.isdir():
                payload = None
            elif member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"cannot read sdist member: {member.name}")
                payload = stream.read()
                if len(payload) != member.size:
                    raise ValueError(f"sdist member size mismatch: {member.name}")
            else:
                raise ValueError(f"sdist member is not a regular file or directory: {member.name}")
            entries.append((member, payload))
    if len(roots) != 1:
        raise ValueError("sdist must contain exactly one top-level directory")

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as raw:
            temporary = Path(raw.name)
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw,
                mtime=0,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.USTAR_FORMAT,
                ) as canonical:
                    for original, payload in sorted(entries, key=lambda item: item[0].name):
                        member = tarfile.TarInfo(original.name)
                        member.type = tarfile.DIRTYPE if payload is None else tarfile.REGTYPE
                        member.mode = original.mode & 0o777
                        member.uid = 0
                        member.gid = 0
                        member.uname = ""
                        member.gname = ""
                        member.mtime = source_date_epoch
                        member.size = 0 if payload is None else len(payload)
                        canonical.addfile(member, None if payload is None else io.BytesIO(payload))
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class ProjectMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if tomllib is None:
            raise unittest.SkipTest("tomllib requires Python 3.11+")
        with PYPROJECT.open("rb") as stream:
            cls.config = tomllib.load(stream)

    def test_build_backend_is_setuptools(self) -> None:
        build_system = self.config["build-system"]
        self.assertEqual(build_system["build-backend"], "setuptools.build_meta")
        self.assertEqual(build_system["requires"], ["setuptools==83.0.0"])

    def test_codex_command_templates_use_automatic_review(self) -> None:
        team_config = TEAM_CONFIG.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        codex_commands = [
            line
            for line in team_config.splitlines()
            if line.startswith(
                (
                    "SCEPTICAL_ARCHITECT_CMD=",
                    "SENIOR_SECURITY_ENGINEER_CMD=",
                    "BACKEND_CMD=",
                    "FRONTEND_CMD=",
                )
            )
            and "codex exec" in line
        ]

        self.assertEqual(len(codex_commands), 4)
        self.assertTrue(
            all("--approve-for-me" in command for command in codex_commands)
        )
        self.assertNotIn("--full-auto", team_config)
        self.assertIn("codex exec --approve-for-me", readme)
        self.assertNotIn("codex exec --full-auto", readme)

    def test_public_package_metadata(self) -> None:
        project = self.config["project"]
        self.assertEqual(project["name"], "startup-factory")
        self.assertEqual(project["version"], "0.1.15")
        self.assertEqual(project["requires-python"], ">=3.10")
        self.assertEqual(project["license"], "MIT")
        self.assertEqual(project["license-files"], ["LICENSE"])

    def test_runtime_is_dependency_free(self) -> None:
        self.assertEqual(self.config["project"]["dependencies"], [])

    def test_console_entry_point(self) -> None:
        self.assertEqual(
            self.config["project"]["scripts"]["startup-factory"],
            "startup_factory_cli.cli:main",
        )
        self.assertEqual(
            self.config["project"]["scripts"]["startup-factory-beads-controller"],
            "startup_factory_cli.beads_boundary_controller:main",
        )

    def test_src_layout_and_generated_resources(self) -> None:
        setuptools = self.config["tool"]["setuptools"]
        self.assertEqual(setuptools["package-dir"], {"": "src"})
        self.assertFalse(setuptools["include-package-data"])
        self.assertEqual(setuptools["packages"]["find"]["where"], ["src"])
        self.assertEqual(
            setuptools["package-data"]["startup_factory_cli"],
            ["resources/*.tar.gz", "resources/*.sha256"],
        )


class BundledDefaultsTests(unittest.TestCase):
    def test_team_mode_is_enabled_by_default(self) -> None:
        config = PROJECT_MANAGEMENT_CONFIG.read_text(encoding="utf-8")
        self.assertRegex(config, r"(?m)^TEAM_MODE=true(?:\s|$)")
        self.assertNotRegex(config, r"(?m)^TEAM_MODE=false(?:\s|$)")

    def test_protected_beads_runtime_module_and_fixture_are_shipped(self) -> None:
        module = ROOT / "src" / "startup_factory_cli" / "beads_protected_runtime.py"
        controller = ROOT / "src" / "startup_factory_cli" / "beads_boundary_controller.py"
        native_boundary = ROOT / "src" / "startup_factory_cli" / "beads_native_boundary_v27.py"
        fixture = ROOT / "tests" / "fixtures" / "beads-protected-runtime-v1.json"
        config_example = ROOT / "runtime" / "beads-boundary-controller-v1.example.json"
        native_manifest = ROOT / "runtime" / "beads-native-boundary-v27.example.json"
        service_example = ROOT / "runtime" / "startup-factory-beads-controller.service.example"
        tmpfiles_example = ROOT / "runtime" / "startup-factory-beads-controller.tmpfiles.example"
        linux_probe = ROOT / "tests" / "beads-boundary-controller-linux-opt-in.py"
        native_linux_probe = ROOT / "tests" / "beads-native-boundary-linux-opt-in.py"
        native_assets = (
            ROOT / "runtime" / "beads-v27" / "startup-factory-beads-launcher-v27.c",
            ROOT / "runtime" / "beads-v27" / "startup-factory-beads-supervisor-v27.c",
            ROOT / "runtime" / "beads-v27" / "startup-factory-v27-crypto.h",
            ROOT / "runtime" / "beads-v27" / "build.sh",
            ROOT / "runtime" / "beads-v27" / "generate-native-manifest-v27.py",
            ROOT / "runtime" / "beads-v27" / "Containerfile",
            ROOT / "runtime" / "beads-v27" / "startup_factory_beads_v27.te",
            ROOT / "runtime" / "beads-v27" / "startup_factory_beads_v27.fc",
        )
        spec = (ROOT / "packaging" / "bundle-spec.json").read_text(encoding="utf-8")
        self.assertTrue(module.is_file())
        self.assertTrue(controller.is_file())
        self.assertTrue(native_boundary.is_file())
        self.assertTrue(fixture.is_file())
        self.assertTrue(config_example.is_file())
        self.assertTrue(native_manifest.is_file())
        controller_config = json.loads(config_example.read_bytes())
        self.assertIs(controller_config["beadsEnabled"], False)
        self.assertEqual(
            "sha256:" + hashlib.sha256(native_manifest.read_bytes()).hexdigest(),
            controller_config["nativeBoundaryManifestSha256"],
        )
        self.assertEqual(
            "/usr/local/lib/python3.13/site-packages/startup_factory_cli/beads_boundary_controller.py",
            controller_config["modulePath"],
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(controller.read_bytes()).hexdigest(),
            controller_config["moduleSha256"],
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(native_boundary.read_bytes()).hexdigest(),
            controller_config["nativeModuleSha256"],
        )
        self.assertEqual(
            "/usr/local/lib/python3.13/site-packages/startup_factory_cli/beads_native_boundary_v27.py",
            controller_config["nativeModulePath"],
        )
        self.assertEqual(
            "startup_factory_cli.beads_boundary_controller:main",
            tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["scripts"][
                "startup-factory-beads-controller"
            ],
        )
        self.assertTrue(service_example.is_file())
        self.assertTrue(tmpfiles_example.is_file())
        self.assertFalse(
            (ROOT / "runtime" / "startup-factory-beads-controller.socket.example").exists()
        )
        self.assertTrue(linux_probe.is_file())
        self.assertTrue(native_linux_probe.is_file())
        self.assertTrue(all(path.is_file() for path in native_assets))
        self.assertIn('"tests/beads-protected-runtime-test.py"', spec)
        self.assertIn('"tests/beads-protected-runtime-hostile-test.py"', spec)
        self.assertIn('"tests/beads-boundary-controller-test.py"', spec)
        self.assertIn('"tests/beads-native-boundary-v27-test.py"', spec)
        self.assertIn('"tests/support/beads_protected_runtime_harness.py"', spec)
        self.assertIn('"tests/fixtures/beads-protected-runtime-v1.json"', spec)
        self.assertIn('"runtime/beads-boundary-controller-v1.example.json"', spec)
        self.assertIn('"runtime/beads-native-boundary-v27.example.json"', spec)
        for path in native_assets:
            self.assertIn(
                f'"{path.relative_to(ROOT).as_posix()}"', spec
            )
        self.assertIn('"runtime/startup-factory-beads-controller.service.example"', spec)
        self.assertIn('"runtime/startup-factory-beads-controller.tmpfiles.example"', spec)
        self.assertNotIn('"runtime/startup-factory-beads-controller.socket.example"', spec)
        self.assertIn('"tests/beads-boundary-controller-linux-opt-in.py"', spec)
        self.assertIn('"tests/beads-native-boundary-linux-opt-in.py"', spec)
        for name in (
            "beads-v1.1.2-issue-envelope.json",
            "beads-v1.1.2-labels-envelope.json",
            "beads-v1.1.2-comments-envelope.json",
            "beads-v1.1.2-down-dependencies-envelope.json",
            "beads-v1.1.2-wire-provenance.json",
        ):
            self.assertIn(f'"tests/fixtures/{name}"', spec)


class ReleaseWorkflowTests(unittest.TestCase):
    def test_pull_requests_must_use_an_unreleased_version(self) -> None:
        workflow = PACKAGE_CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Require an unreleased version before merge", workflow)
        self.assertIn("if: github.event_name == 'pull_request'", workflow)
        self.assertIn("project.version must increase before merge", workflow)
        self.assertIn('refs/tags/v$VERSION^{commit}', workflow)

    def test_release_runs_for_merged_main_commits(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("    branches:\n      - main", workflow)
        self.assertNotIn("    tags:\n", workflow)
        self.assertIn('test "$GITHUB_REF" = "refs/heads/main"', workflow)
        self.assertIn('test "$commit" = "$GITHUB_SHA"', workflow)
        self.assertIn("bump project.version", workflow)
        self.assertIn("  group: release-main", workflow)

    def test_github_release_tag_comes_from_the_package_version(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "          RELEASE_TAG: v${{ needs.build.outputs.version }}",
            workflow,
        )
        self.assertNotIn("$GITHUB_REF_NAME", workflow)

    def test_runtime_suite_uses_a_private_temporary_directory(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('runtime_tmp="$RUNNER_TEMP/startup-factory-runtime"', workflow)
        self.assertIn('install -d -m 700 "$runtime_tmp"', workflow)
        self.assertIn(
            'PATH="/usr/bin:/bin" TMPDIR="$runtime_tmp" /bin/bash tests/run-all.sh',
            workflow,
        )
        self.assertNotIn("        run: bash tests/run-all.sh", workflow)

    def test_github_release_commands_have_explicit_repository_context(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("          GH_REPO: ${{ github.repository }}", workflow)

    def test_public_uvx_install_is_verified_before_github_release(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  verify-uvx:\n", workflow)
        self.assertIn("    name: Verify the public uvx installation", workflow)
        self.assertIn(
            "        uses: astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d # v10.0.1",
            workflow,
        )
        self.assertIn('uvx --refresh "startup-factory@$VERSION" version --json', workflow)
        self.assertIn('uvx --refresh "startup-factory@latest" version --json', workflow)
        github_release = workflow.split("  github-release:\n", 1)[1]
        self.assertIn("      - verify-uvx", github_release.split("    runs-on:", 1)[0])

    def test_draft_release_target_is_verified_before_the_tag_exists(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        publish = workflow.split(
            "      - name: Reconcile a draft release, verify bytes, then publish",
            1,
        )[1]
        edit_index = publish.index(
            '          gh release edit "$RELEASE_TAG" --draft=false'
        )
        before_publish = publish[:edit_index]
        after_publish = publish[edit_index:]

        self.assertIn("          verify_release_target() {", before_publish)
        self.assertIn("                --json targetCommitish", before_publish)
        self.assertEqual(before_publish.count("          verify_release_target\n"), 2)
        self.assertNotIn('test "$(resolve_tag_commit)"', before_publish)
        self.assertIn('test "$(resolve_tag_commit)"', after_publish)


class SdistCanonicalizationTests(unittest.TestCase):
    def _write_sdist(self, path: Path, *, mtime: int, uid: int) -> None:
        with tarfile.open(path, "w:gz") as archive:
            directory = tarfile.TarInfo("startup_factory-0.1.1")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.mtime = mtime
            directory.uid = uid
            archive.addfile(directory)
            payload = b"metadata fixture\n"
            member = tarfile.TarInfo("startup_factory-0.1.1/PKG-INFO")
            member.mode = 0o644
            member.mtime = mtime
            member.uid = uid
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))

    def test_canonicalization_removes_container_metadata_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.tar.gz"
            second = Path(directory) / "second.tar.gz"
            self._write_sdist(first, mtime=10, uid=501)
            self._write_sdist(second, mtime=20, uid=1001)
            canonicalize_sdist(first, source_date_epoch=123456789)
            canonicalize_sdist(second, source_date_epoch=123456789)
            self.assertEqual(first.read_bytes(), second.read_bytes())


class BuiltDistributionIdentityTests(unittest.TestCase):
    """Enabled by release CI after the canonical archive and dists exist."""

    @classmethod
    def setUpClass(cls) -> None:
        dist_value = os.environ.get("STARTUP_FACTORY_DIST_DIR")
        bundle_value = os.environ.get("STARTUP_FACTORY_BUNDLE")
        if not dist_value or not bundle_value:
            raise unittest.SkipTest("built-distribution paths were not provided")

        cls.dist_dir = Path(dist_value).resolve()
        cls.bundle = Path(bundle_value).resolve()
        cls.bundle_bytes = cls.bundle.read_bytes()
        wheels = sorted(cls.dist_dir.glob("*.whl"))
        sdists = sorted(cls.dist_dir.glob("*.tar.gz"))
        if len(wheels) != 1 or len(sdists) != 1:
            raise AssertionError(
                f"expected one wheel and one sdist, found {len(wheels)} and {len(sdists)}"
            )
        cls.wheel = wheels[0]
        cls.sdist = sdists[0]

    def test_wheel_metadata_and_entry_point(self) -> None:
        with zipfile.ZipFile(self.wheel) as archive:
            metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            entry_names = [
                name for name in archive.namelist() if name.endswith(".dist-info/entry_points.txt")
            ]
            license_names = [
                name for name in archive.namelist() if name.endswith(".dist-info/licenses/LICENSE")
            ]
            self.assertEqual(len(metadata_names), 1)
            self.assertEqual(len(entry_names), 1)
            self.assertEqual(len(license_names), 1)
            metadata = email.parser.Parser().parsestr(
                archive.read(metadata_names[0]).decode("utf-8")
            )
            entry_points = archive.read(entry_names[0]).decode("utf-8")
            license_bytes = archive.read(license_names[0])

        self.assertEqual(metadata["Name"], "startup-factory")
        self.assertEqual(metadata["Version"], "0.1.15")
        self.assertEqual(metadata["Requires-Python"], ">=3.10")
        self.assertEqual(metadata["License-Expression"], "MIT")
        self.assertEqual(metadata.get_all("License-File", []), ["LICENSE"])
        self.assertEqual(metadata.get_all("Requires-Dist", []), [])
        self.assertIn("startup-factory = startup_factory_cli.cli:main", entry_points)
        self.assertIn(
            "startup-factory-beads-controller = startup_factory_cli.beads_boundary_controller:main",
            entry_points,
        )
        self.assertEqual(license_bytes, (ROOT / "LICENSE").read_bytes())

    def test_wheel_embeds_the_exact_canonical_bundle(self) -> None:
        with zipfile.ZipFile(self.wheel) as archive:
            names = archive.namelist()
            self.assertEqual(names.count(RESOURCE_ARCHIVE), 1)
            self.assertEqual(names.count(RESOURCE_CHECKSUM), 1)
            embedded = archive.read(RESOURCE_ARCHIVE)
            checksum = archive.read(RESOURCE_CHECKSUM)

        self.assertEqual(embedded, self.bundle_bytes)
        self.assertEqual(checksum_digest(checksum), sha256_bytes(embedded))

    def test_sdist_embeds_the_exact_canonical_bundle(self) -> None:
        archive_suffix = f"/{RESOURCE_ARCHIVE}"
        checksum_suffix = f"/{RESOURCE_CHECKSUM}"
        with tarfile.open(self.sdist, "r:gz") as archive:
            archive_members = [member for member in archive.getmembers() if member.name.endswith(archive_suffix)]
            checksum_members = [
                member for member in archive.getmembers() if member.name.endswith(checksum_suffix)
            ]
            self.assertEqual(len(archive_members), 1)
            self.assertEqual(len(checksum_members), 1)
            embedded_file = archive.extractfile(archive_members[0])
            checksum_file = archive.extractfile(checksum_members[0])
            self.assertIsNotNone(embedded_file)
            self.assertIsNotNone(checksum_file)
            embedded = embedded_file.read()  # type: ignore[union-attr]
            checksum = checksum_file.read()  # type: ignore[union-attr]
            license_members = [
                member for member in archive.getmembers() if member.name.endswith("/LICENSE")
            ]
            self.assertEqual(len(license_members), 1)
            license_file = archive.extractfile(license_members[0])
            self.assertIsNotNone(license_file)
            license_bytes = license_file.read()  # type: ignore[union-attr]

        self.assertEqual(embedded, self.bundle_bytes)
        self.assertEqual(checksum_digest(checksum), sha256_bytes(embedded))
        self.assertEqual(license_bytes, (ROOT / "LICENSE").read_bytes())


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--canonicalize-sdist":
        if len(sys.argv) != 4:
            raise SystemExit(
                "usage: test_packaging_metadata.py --canonicalize-sdist PATH SOURCE_DATE_EPOCH"
            )
        canonicalize_sdist(Path(sys.argv[2]), source_date_epoch=int(sys.argv[3]))
    else:
        unittest.main()
