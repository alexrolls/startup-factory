#!/usr/bin/env python3
"""Distribution metadata and embedded-bundle identity tests."""

from __future__ import annotations

import email.parser
import gzip
import hashlib
import io
import os
import re
import shlex
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
DEPLOYMENT_REFERENCE = ROOT / "reference" / "deployment.md"
AUTOMATION_REFERENCE = ROOT / "reference" / "automation.md"
PM_PRODUCTION_ENV_EXAMPLE = ROOT / "config" / "pm-agent.production.env.example"
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
        self.assertEqual(project["version"], "0.2.0")
        self.assertEqual(project["requires-python"], ">=3.10")
        self.assertEqual(project["license"], "MIT")
        self.assertEqual(project["license-files"], ["LICENSE"])
        self.assertIn("Development Status :: 4 - Beta", project["classifiers"])
        self.assertNotIn("Development Status :: 3 - Alpha", project["classifiers"])

    def test_runtime_is_dependency_free(self) -> None:
        self.assertEqual(self.config["project"]["dependencies"], [])

    def test_console_entry_point(self) -> None:
        self.assertEqual(
            self.config["project"]["scripts"]["startup-factory"],
            "startup_factory_cli.cli:main",
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
    def test_role_command_defaults_keep_complete_quoted_prompt_templates(self) -> None:
        config = TEAM_CONFIG.read_text(encoding="utf-8")
        command_keys = (
            "TEAM_LEAD_CMD",
            "PRINCIPAL_ARCHITECT_CMD",
            "SCEPTICAL_ARCHITECT_CMD",
            "SENIOR_SECURITY_ENGINEER_CMD",
            "INTEGRATOR_CMD",
            "BACKEND_CMD",
            "FRONTEND_CMD",
            "REVIEWER_CMD",
            "TEAM_DEFAULT_CMD",
        )
        values = {}
        for line in config.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if key in command_keys:
                    values[key] = value

        self.assertEqual(set(values), set(command_keys))
        for key, value in values.items():
            self.assertTrue(value.startswith('"') and value.endswith('"'), key)
            self.assertIn("{prompt_file}", value, key)
            self.assertIn(r'\"', value, key)
            # The parsed value must be the command string an operator wrote:
            # outer quotes removed, documented escapes folded, so the interior
            # quotes still group the prompt at execution time.
            parsed = value[1:-1].replace(r'\"', '"').replace('\\\\', '\\')
            self.assertIn('"$(cat \'{prompt_file}\')"', parsed, key)
            self.assertEqual(shlex.split(parsed).count("$(cat '{prompt_file}')"), 1, key)

        self.assertIn("Configuration parsing is inert", config)
        self.assertIn("launch-team.sh config-value <KEY>", config)

    def test_agent_sandbox_home_is_absent_by_default(self) -> None:
        config = TEAM_CONFIG.read_text(encoding="utf-8")
        self.assertRegex(config, r"(?m)^AGENT_SANDBOX_HOME=null(?:\s+#.*)?$")

    def test_team_mode_is_enabled_by_default(self) -> None:
        config = PROJECT_MANAGEMENT_CONFIG.read_text(encoding="utf-8")
        self.assertRegex(config, r"(?m)^TEAM_MODE=true(?:\s|$)")
        self.assertNotRegex(config, r"(?m)^TEAM_MODE=false(?:\s|$)")

    def test_preserved_lifecycle_authority_migration_is_explicit(self) -> None:
        env_example = PM_PRODUCTION_ENV_EXAMPLE.read_text(encoding="utf-8")
        deployment = DEPLOYMENT_REFERENCE.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")

        self.assertIn(
            "may only repeat the exact canonical BROKER_LIFECYCLE_ROOT",
            env_example,
        )
        self.assertIn("Required 0.1.x lifecycle-authority migration", deployment)
        self.assertIn("BROKER_LIFECYCLE_ROOT=null", deployment)
        self.assertRegex(
            deployment, r"The\s+environment value cannot create or override"
        )
        self.assertIn("0.1.x upgrade action", readme)
        self.assertIn(
            "STARTUP_FACTORY_LIFECYCLE_STATE_ROOT` may only repeat", readme
        )

    def test_automation_uses_the_root_protected_runner_contract(self) -> None:
        automation = AUTOMATION_REFERENCE.read_text(encoding="utf-8")

        self.assertRegex(
            automation, r"outside\s+both the repository and installed runtime"
        )
        self.assertRegex(
            automation, r"complete\s+ancestor chain must be real, root-owned"
        )
        self.assertIn("not writable by the executor", automation)
        self.assertIn(
            "operator-owned mode-0700 wrapper is deliberately refused", automation
        )
        self.assertIn("revalidates that boundary immediately before every", automation)
        self.assertNotIn("owned by the executor or root", automation)

    def test_readme_does_not_claim_unmeasured_onboarding_latency(self) -> None:
        readme = README.read_text(encoding="utf-8").casefold()

        self.assertNotIn("two-minute", readme)
        self.assertNotIn("two minutes", readme)
        self.assertIn("quick start (local markdown, no tracker account)", readme)


class ReleaseWorkflowTests(unittest.TestCase):
    def test_full_validation_jobs_have_sufficient_timeout_budget(self) -> None:
        def job_timeout(workflow: str, job: str) -> int:
            prefix, marker, tail = workflow.partition(f"  {job}:\n")
            self.assertTrue(marker, f"missing {job!r} job")
            header, steps_marker, _steps = tail.partition("    steps:\n")
            self.assertTrue(steps_marker, f"missing steps for {job!r} job")
            matches = re.findall(
                r"(?m)^    timeout-minutes: ([1-9][0-9]*)$", header
            )
            self.assertEqual(len(matches), 1, f"expected one timeout for {job!r}")
            return int(matches[0])

        package_timeout = job_timeout(
            PACKAGE_CI_WORKFLOW.read_text(encoding="utf-8"), "package"
        )
        release_timeout = job_timeout(
            RELEASE_WORKFLOW.read_text(encoding="utf-8"), "build"
        )

        self.assertGreaterEqual(package_timeout, 60)
        self.assertGreaterEqual(release_timeout, 60)
        self.assertGreaterEqual(release_timeout, package_timeout)

    def test_pull_requests_must_use_an_unreleased_version(self) -> None:
        workflow = PACKAGE_CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Require an unreleased version before merge", workflow)
        self.assertIn("if: github.event_name == 'pull_request'", workflow)
        self.assertIn("project.version must increase before merge", workflow)
        self.assertIn('refs/tags/v$VERSION^{commit}', workflow)

    def test_pull_requests_prove_source_compatibility_on_python_310(self) -> None:
        workflow = PACKAGE_CI_WORKFLOW.read_text(encoding="utf-8")
        minimum = workflow.split("  minimum-python:\n", 1)[1].split(
            "\n  package:\n", 1
        )[0]
        self.assertIn("if: github.event_name == 'pull_request'", minimum)
        self.assertIn('python-version: "3.10"', minimum)
        self.assertIn("sys.version_info[:2] == (3, 10)", minimum)
        self.assertIn("python -m startup_factory_cli version --json", minimum)
        self.assertIn(
            'python -m unittest discover -s tests/packaging -p "test_*.py" -v',
            minimum,
        )

    def test_release_is_manual_protected_and_exact_evidence_gated(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertIn("      release_commit:\n", workflow)
        self.assertIn("      evidence_commit:\n", workflow)
        self.assertNotIn("  push:\n", workflow)
        self.assertNotIn("    tags:\n", workflow)
        self.assertIn("  authorize:\n", workflow)
        authorize = workflow.split("  authorize:\n", 1)[1].split("\n  build:\n", 1)[0]
        self.assertIn("      name: release", authorize)
        self.assertIn("          ref: main", authorize)
        self.assertIn("          ref: release-evidence", authorize)
        self.assertIn(
            'test "$(git -C candidate rev-parse origin/main)" = "$RELEASE_COMMIT"',
            authorize,
        )
        self.assertIn('test "$GITHUB_REF" = "refs/heads/main"', authorize)
        self.assertIn('test "$RELEASE_COMMIT" = "$GITHUB_SHA"', authorize)
        self.assertIn(
            'test "$(git -C release-evidence rev-parse HEAD)" = "$EVIDENCE_COMMIT"',
            authorize,
        )
        self.assertIn(
            'git -C release-evidence show-ref --verify --quiet', authorize
        )
        self.assertIn(
            'rev-parse origin/release-evidence)', authorize
        )
        self.assertIn("Extract only bounded regular secret-free evidence blobs", authorize)
        self.assertIn("candidate/packaging/extract_release_evidence.py", authorize)
        self.assertIn("--source release-evidence", authorize)
        self.assertIn('--commit "$EVIDENCE_COMMIT"', authorize)
        self.assertIn("--target candidate", authorize)
        self.assertIn("python3 bin/beta-readiness.py", authorize)
        self.assertIn("releaseSetSha256", authorize)
        self.assertIn("candidateVersion", authorize)
        self.assertIn("release_set_sha256=$release_set_sha256", authorize)
        self.assertIn("version=$candidate_version", authorize)
        build_header = workflow.split("  build:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertIn("    needs: authorize", build_header)
        self.assertIn(
            "          ref: ${{ needs.authorize.outputs.source_commit }}", workflow
        )
        self.assertIn("bump project.version", workflow)
        self.assertIn("  group: release-main", workflow)

        binding = workflow.index(
            "      - name: Bind rebuilt artifact names and bytes to approved evidence"
        )
        first_upload = workflow.index("      - name: Upload Python distributions")
        self.assertLess(binding, first_upload)
        bind_step = workflow[binding:first_upload]
        self.assertIn(
            "EXPECTED_RELEASE_SET_SHA256: ${{ needs.authorize.outputs.release_set_sha256 }}",
            bind_step,
        )
        self.assertIn("packaging/verify_release_artifacts.py", bind_step)
        self.assertIn("--distributions dist", bind_step)
        self.assertIn("--release-assets release-assets", bind_step)

        publish = workflow.split("  publish:\n", 1)[1].split("\n  verify-uvx:\n", 1)[0]
        self.assertIn("      - authorize", publish)
        self.assertIn("      name: pypi", publish)
        self.assertIn("Check out the current main tip after publication approval", publish)
        self.assertIn("Check out the current protected evidence tip", publish)
        self.assertIn("Reconfirm both authorized protected tips after approval", publish)
        self.assertIn("Freshly extract the exact bounded evidence set", publish)
        self.assertIn("Revalidate freshness and exact release identity after approval", publish)
        self.assertIn('"candidateCommit": expected_commit', publish)
        self.assertIn('"candidateVersion": expected_version', publish)
        self.assertIn('"releaseSetSha256": expected_release_set', publish)
        self.assertIn("Download the complete attested release set", publish)
        self.assertIn("Rebind downloaded names and bytes to approved evidence", publish)
        self.assertIn("candidate/packaging/verify_release_artifacts.py", publish)
        self.assertIn("Refuse a last-moment protected-tip change", publish)
        self.assertIn("git/ref/heads/main", publish)
        self.assertIn("git/ref/heads/release-evidence", publish)
        self.assertEqual(workflow.count("extract_release_evidence.py"), 2)
        self.assertEqual(workflow.count("verify_release_artifacts.py"), 2)
        last_tip = publish.index("Refuse a last-moment protected-tip change")
        pypi = publish.index("pypa/gh-action-pypi-publish")
        self.assertLess(last_tip, pypi)

    def test_python_310_smoke_exercises_installed_integration_pack(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        smoke = workflow.split("  smoke:\n", 1)[1].split("\n  publish:\n", 1)[0]
        self.assertIn('python-version: "3.10"', smoke)
        for operation in ("list", "validate", "preview", "apply", "doctor"):
            self.assertRegex(smoke, rf"startup-factory integration-pack {operation}\b")
        self.assertNotIn("bin/integration_pack.py", smoke)
        self.assertIn('report["configured"]["status"] == "configured"', smoke)
        self.assertIn('report["proved"]["status"] == "unknown"', smoke)

    def test_github_release_tag_comes_from_the_package_version(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "          RELEASE_TAG: v${{ needs.build.outputs.version }}",
            workflow,
        )
        self.assertNotIn("$GITHUB_REF_NAME", workflow)

    def test_runtime_suites_use_a_protected_pinned_python_in_a_private_tmpdir(self) -> None:
        for path in (PACKAGE_CI_WORKFLOW, RELEASE_WORKFLOW):
            with self.subTest(workflow=path.name):
                workflow = path.read_text(encoding="utf-8")
                self.assertIn(
                    'runtime_tmp="$RUNNER_TEMP/startup-factory-runtime"', workflow
                )
                self.assertIn('install -d -m 700 "$runtime_tmp"', workflow)
                self.assertIn('python-version: "3.14"', workflow)
                self.assertIn(
                    'build_env="$(mktemp -d "$RUNNER_TEMP/startup-factory-build.XXXXXX")"',
                    workflow,
                )
                self.assertIn(
                    '"$protected_python" -I -B -m venv --copies "$build_env"',
                    workflow,
                )
                self.assertIn('build_python="$build_env/bin/python"', workflow)
                self.assertIn(
                    '"$build_python" -I -B -m pip install --disable-pip-version-check',
                    workflow,
                )
                self.assertIn(
                    '"$build_python" -I -B -m build --no-isolation', workflow
                )
                self.assertIn('setup_prefix="$(python -I -S -E -s', workflow)
                self.assertIn(
                    'test "$RUNNER_TOOL_CACHE" = "/opt/hostedtoolcache"', workflow
                )
                self.assertIn(
                    '"$RUNNER_TOOL_CACHE"/Python/3.14.*/x64', workflow
                )
                self.assertIn(
                    'sudo chown root:root /opt "$RUNNER_TOOL_CACHE" "$python_root" '
                    '"$version_root"',
                    workflow,
                )
                self.assertIn(
                    'sudo chmod go-w /opt "$RUNNER_TOOL_CACHE" "$python_root" '
                    '"$version_root"',
                    workflow,
                )
                self.assertIn('sudo chown -R root:root "$setup_prefix"', workflow)
                self.assertIn('sudo chmod -R go-w "$setup_prefix"', workflow)
                self.assertIn("sys.version_info[:2] == (3, 14)", workflow)
                self.assertIn('assert info.st_uid == 0', workflow)
                self.assertIn('assert not stat.S_IMODE(info.st_mode) & 0o022', workflow)
                self.assertIn('path.resolve(strict=True).is_relative_to(root)', workflow)
                self.assertIn('maps = Path("/proc/self/maps")', workflow)
                self.assertIn('path.name.startswith("libpython3.14")', workflow)
                self.assertLess(
                    workflow.index('sudo chown -R root:root "$setup_prefix"'),
                    workflow.index('"$build_python" -I -B -m pip install'),
                )
                self.assertLess(
                    workflow.index('TMPDIR="$runtime_tmp" /bin/bash tests/run-all.sh'),
                    workflow.index('build_env="$(mktemp -d'),
                )
                self.assertLess(
                    workflow.index('Prepare two clean package source trees'),
                    workflow.index('build_env="$(mktemp -d'),
                )
                self.assertIn(
                    'PATH="$setup_prefix/bin:/usr/bin:/bin" \\\n'
                    '            TMPDIR="$runtime_tmp" /bin/bash tests/run-all.sh',
                    workflow,
                )
                self.assertNotIn('protected_python_root=', workflow)
                self.assertNotIn('sudo cp -a "$setup_prefix/."', workflow)
                self.assertNotIn('BUILD_PYTHON=', workflow)
                self.assertNotIn('setup_python="$(command -v python3)"', workflow)
                self.assertNotIn('PATH="$setup_python_dir:/usr/bin:/bin"', workflow)
                self.assertNotIn("/usr/bin/python3 -c", workflow)
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

    def test_uvx_version_check_is_part_of_the_retry_condition(self) -> None:
        # A freshly published version is not immediately visible to the index
        # `@latest` resolves against, so the first attempts legitimately report
        # the previous version. The check must therefore be part of the `if`
        # condition: inside the body, `set -e` aborts the step on the first
        # stale answer and the retry budget never applies to the propagation lag
        # it exists for — which skips github-release and half-publishes a release.
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        step = workflow.split("      - name: Resolve the published release through uvx", 1)[1]
        step = step.split("\n  github-release:", 1)[0]
        loop = step.split("for attempt in", 1)[1]
        # The condition ends at a `then` on its own line. Requiring the split to
        # actually find one matters: without it, a body-style `; then` leaves the
        # whole loop as the "condition" and every assertion below passes
        # vacuously — which is exactly the shape this test exists to reject.
        head, sep, _tail = loop.partition("\n            then\n")
        self.assertTrue(sep, "the uvx retry condition must end at a standalone `then`")
        self.assertIn('uvx --refresh "startup-factory@$VERSION"', head)
        self.assertIn('uvx --refresh "startup-factory@latest"', head)
        self.assertIn('python - "$VERSION" "$exact_output" "$latest_output"', head)
        # The retry must still exist, and the step must still fail closed.
        self.assertIn("$(seq 1 18)", step)
        self.assertIn("sleep 10", step)
        self.assertIn("exit 1", step)

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
        self.assertEqual(metadata["Version"], "0.2.0")
        self.assertEqual(metadata["Requires-Python"], ">=3.10")
        self.assertEqual(metadata["License-Expression"], "MIT")
        self.assertEqual(metadata.get_all("License-File", []), ["LICENSE"])
        self.assertEqual(metadata.get_all("Requires-Dist", []), [])
        self.assertIn("startup-factory = startup_factory_cli.cli:main", entry_points)
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
