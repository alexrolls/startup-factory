#!/usr/bin/env python3
"""Offline tests for authoritative, monotonic delivery-profile decisions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

import delivery_profile  # noqa: E402
from delivery_profile import (  # noqa: E402
    DeliveryProfileError,
    _git,
    _resolve_git_executable,
    assess_diff,
    assess_review_diff,
    assess_task,
    build_review_package,
    canonical_merge_tree,
    create_review_package,
    is_control_plane_path,
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


COMPOUND_SECURITY_PATHS = (
    "src/oauth2client.py",
    "src/jwtvalidator.py",
    "src/rbacengine.py",
    "src/credentialstore.py",
    "src/csrffilter.py",
    "src/api_keys.py",
    "src/private_keys.py",
    "src/tokenstore.py",
    "src/passwordreset.py",
    "src/passwordmanager.py",
    "src/passwordless.py",
    "src/apikey.py",
    "src/apikeys.py",
    "src/apikeymanager.py",
    "src/apikeyvalidator.py",
    "src/apikeycontroller.py",
    "src/privatekey.py",
    "src/privatekeys.py",
    "src/privatekeymanager.py",
    "src/privatekeyhandler.py",
    "src/publickeyvalidator.py",
    "src/signingkeymanager.py",
    "src/signingkeyrepository.py",
    "src/encryptionkeymanager.py",
    "src/accesscontrol.py",
    "src/accesscontroller.py",
    "src/permissioncheck.py",
    "src/permissionservice.py",
    "src/permissionvalidator.py",
    "src/secretstore.py",
    "src/secretmanager.py",
    "src/sessionstore.py",
    "src/cookiehandler.py",
    "src/identityprovider.py",
    "src/signatureverifier.py",
    "src/encryptionservice.py",
    "src/encryptionmanager.py",
    "src/certvalidator.py",
    "src/authcontroller.py",
    "src/oauthserver.py",
    "src/permissions.py",
    "src/authenticator.py",
    "src/authorizer.py",
    "src/passwordhash.py",
    "src/tokenissuer.py",
    "src/admincontroller.py",
    "src/administratorservice.py",
    "src/aclvalidator.py",
    "src/cryptomanager.py",
    "src/entitlementengine.py",
    "src/keyringmanager.py",
    "src/keystoreprovider.py",
    "src/loginhandler.py",
    "src/logouthandler.py",
    "src/mfaprovider.py",
    "src/ssoprovider.py",
    "src/signingservice.py",
    "src/decryptionservice.py",
    "src/hmacverifier.py",
    "src/iampolicy.py",
    "src/migrationmanager.py",
    "src/schemavalidator.py",
    "src/userauthservice.py",
    "src/accountsessionstore.py",
    "src/customerpasswordreset.py",
    "src/mycredentialstore.py",
    "src/internalapikeyvalidator.py",
    "src/memberidentityprovider.py",
    "src/tenantpermissioncheck.py",
    "src/oauthclientv2.py",
    "src/userauthservicev12.py",
    "src/customeridentityproviderv3.py",
    "src/paymenttokenvalidator.py",
    "src/serviceauthmiddleware.py",
    "src/orgsecretstore.py",
    "src/webhooksignatureverifier.py",
    "src/adminauthservice.py",
    "src/paymentsessionstore.py",
    "src/platformcredentialmanager.py",
    "src/checkoutapikeyvalidator.py",
    "src/billingoauthclient.py",
    "src/webcookiehandler.py",
    "src/securitytokenvalidator.py",
    "src/platformsecretsmanager.py",
    "src/orgcredentialsstore.py",
    "src/orgpermissionsvalidator.py",
    "src/apitokensissuer.py",
    "src/websignaturesverifier.py",
    "src/vaultpasswordsmanager.py",
    "src/directoryidentitiesprovider.py",
    "src/browsercookieshandler.py",
    "src/orgsecrets.py",
    "src/platformcredentials.py",
    "src/apitokens.py",
    "src/websignatures.py",
    "src/vaultpasswords.py",
    "src/directoryidentities.py",
    "src/browsercookies.py",
    "src/tenantpermissions.py",
    "src/accesstokens.py",
    "src/refreshTokens.py",
    "src/tenantauthtokens.py",
    "src/platformsessiontokens.py",
)

CONFUSABLE_ORDINARY_PATHS = (
    "src/oauth2clientele.py",
    "src/jwttable.py",
    "src/rbacengineer.py",
    "src/credentialstory.py",
    "src/csrffiltering.py",
    "src/keyboard_keys.py",
    "src/tokenizer.py",
    "src/apikeyboard.py",
    "src/apikeycontrollerial.py",
    "src/privatekeyboard.py",
    "src/signingkeynote.py",
    "src/permissionslip.py",
    "src/secretary.py",
    "src/sessioncard.py",
    "src/cookiecutter.py",
    "src/identitymatrix.py",
    "src/signaturestyle.py",
    "src/encryptionist.py",
    "src/certifiable.py",
    "src/authorship.py",
    "src/oauthology.py",
    "src/keyboard.py",
    "src/turnkey.py",
    "src/accesscolor.py",
    "src/administrivia.py",
    "src/keyringtone.py",
    "src/keystory.py",
    "src/loginfo.py",
    "src/association.py",
    "src/tokens.py",
    "src/access.py",
    "src/userauthorship.py",
    "src/accountsessioncard.py",
    "src/customerpasswordlessons.py",
    "src/mycredentialstory.py",
    "src/internalapikeyboard.py",
    "src/memberidentitymatrix.py",
    "src/tenantpermissionslip.py",
    "src/oauthclientelev2.py",
    "src/oauthclientvnext.py",
    "src/userauthserviceversion2.py",
    "src/designingservice.py",
    "src/assigningservice.py",
    "src/possessionmanager.py",
    "src/concertservice.py",
    "src/emigrationmanager.py",
    "src/authorshipservice.py",
    "src/oauthclientele.py",
    "src/secretaryservice.py",
    "src/credentialstorymanager.py",
    "src/tokenizervalidator.py",
    "src/signaturestyleverifier.py",
    "src/platformsecretarymanager.py",
    "src/orgcredentialstorymanager.py",
    "src/orgpermissionslipvalidator.py",
    "src/apitokenshipissuer.py",
    "src/websignaturestyleverifier.py",
    "src/vaultpasswordstorymanager.py",
    "src/directoryidentitymatrixprovider.py",
    "src/browsercookiecutterhandler.py",
    "src/designTokens.py",
    "src/design tokens.py",
    "src/design_tokens.py",
    "src/designtokens.py",
    "src/producttokens.py",
    "src/platformsecretary.py",
    "src/orgcredentialstory.py",
    "src/orgcredentialsstory.py",
    "src/orgpermissionslip.py",
    "src/apitokenship.py",
    "src/websignaturestyle.py",
    "src/websignatureseries.py",
    "src/vaultpasswordstory.py",
    "src/directoryidentitymatrix.py",
    "src/browsercookiecutter.py",
    "src/platformsessions.py",
    "src/platformsigning.py",
    "src/platformcerts.py",
    "src/platformmigrations.py",
    "src/platformschemas.py",
)


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

    def test_control_plane_paths_are_identified_separately_from_product_code(self):
        for path in ("bin/dispatch.sh", "config/team.config.md", ".github/workflows/ci.yml"):
            self.assertTrue(is_control_plane_path(path), path)
        for path in ("src/widget.py", "tests/test_widget.py", "docs/guide.md"):
            self.assertFalse(is_control_plane_path(path), path)

    def test_common_security_dependency_and_deployment_surfaces_are_high_risk(self):
        security_paths = (
            ".gitattributes",
            ".gitmodules",
            ".pre-commit-config.yaml",
            "src/admin_guard.py",
            "src/entitlement_check.py",
            "src/encryption.py",
            "src/decrypt.py",
            "src/hmac.py",
            "src/signing.py",
            "src/signature.py",
            "src/login.py",
            "src/session/store.py",
            "src/session.py",
            "src/csrf_guard.py",
            "config/.env.production",
            ".envrc",
            "certs/server.pem",
            "src/db_schema.py",
            "src/migrations/001_create_table.py",
            "services/access-control/policy.go",
            "src/rbacPolicy.ts",
            "src/csrfProtection.ts",
            "src/passwordHash.ts",
            "src/refreshToken.ts",
            "src/privateKey.ts",
        )
        dependency_paths = (
            "pyproject.toml",
            "uv.lock",
            "environment.yml",
            "environment.yaml",
            "conda-lock.yml",
            "conda-lock.yaml",
            "requirements-dev.txt",
            "web/package-lock.json",
            "service/Cargo.toml",
            "ios/Package.swift",
            "requirements/prod.txt",
            ".mvn/wrapper/maven-wrapper.properties",
        )
        deployment_paths = (
            "k8s/app.yaml",
            "ci/pipeline.yml",
            "charts/api/values.yaml",
            "main.tf",
            "infra/network.tf.json",
            "Dockerfile.production",
            "docker-compose.yml",
            "Procfile",
            "app.yaml",
            "tools/release.py",
            "alembic/versions/abc_add_role.py",
            "db/migrate/20260919_add_role.sql",
        )
        for path in (
            security_paths
            + COMPOUND_SECURITY_PATHS
            + dependency_paths
            + deployment_paths
        ):
            with self.subTest(path=path):
                result = assess_task(task(f"files: {path}", "Bounded change"))
                self.assertTrue(is_control_plane_path(path))
                self.assertEqual("high-risk", result["effectiveProfile"])
                self.assertEqual(
                    ["qa", "security"],
                    result["authority"]["profileForcedReviewGates"],
                )

    def test_similar_ordinary_names_do_not_trigger_high_risk_path_rules(self):
        cases = (
            ("src/author.py", "standard"),
            ("src/chart_renderer.py", "standard"),
            ("src/terraforming_game.py", "standard"),
            ("src/schematic_view.py", "standard"),
            ("src/emigration_report.py", "standard"),
            ("docs/package-design.md", "micro"),
            ("src/releaseDate.ts", "standard"),
            ("src/useTheme.ts", "standard"),
            ("src/workshopSessionCard.ts", "standard"),
            ("src/publishAuthorProfile.ts", "standard"),
        ) + tuple((path, "standard") for path in CONFUSABLE_ORDINARY_PATHS)
        for path, expected in cases:
            with self.subTest(path=path):
                self.assertFalse(is_control_plane_path(path))
                result = assess_task(
                    task(f"files: {path}", "Ordinary product change")
                )
                self.assertEqual(expected, result["effectiveProfile"])
                self.assertEqual(
                    [], result["authority"]["profileForcedReviewGates"]
                )

    def test_benign_product_language_does_not_force_security_gates(self):
        cases = (
            ("Add React hook for theme state", "src/useTheme.ts"),
            ("Update design tokens for dark mode", "src/theme.ts"),
            ("Display the release date", "src/version_banner.ts"),
            ("Add a delete button confirmation", "src/button.ts"),
            ("Render two workshop sessions", "src/schedule.ts"),
            ("Update business policy copy", "src/copy.ts"),
            ("Render the author card", "src/author.py"),
            ("Display authority attribution", "src/byline.py"),
        )
        for title, path in cases:
            with self.subTest(title=title):
                result = assess_task(task(f"files: {path}", title))
                self.assertEqual("standard", result["effectiveProfile"])
                self.assertNotIn("strong-risk-language", result["reasons"])

    def test_sensitive_language_is_high_risk_even_when_the_path_is_generic(self):
        for title in (
            "Fix CSRF validation",
            "Rotate login sessions",
            "Change RBAC enforcement",
            "Rotate refreshToken credentials",
            "Update dependency graph",
            "Run database migration",
            "Deploy to production",
            "Release v2.0",
            "Publish package to PyPI",
            "Update Terraform networking",
            "Verify webhook signature",
            "Prevent SQL injection",
            "Change administrator privileges",
            "Update entitlement enforcement",
            "Deploy an AWS serverless function",
            "Authenticate signed requests",
            "Replace the request authenticator",
            "Authorize tenant access",
            "Authorise administrator access",
            "Install a request authorizer",
            "Reject unauthenticated requests",
            "Handle unauthorized users",
            "List authorized authors",
        ):
            with self.subTest(title=title):
                result = assess_task(task("files: src/handler.py", title))
                self.assertEqual("high-risk", result["effectiveProfile"])
                self.assertIn("strong-risk-language", result["reasons"])

    def test_task_micro_requires_bounded_declared_docs(self):
        result = assess_task(task("files: docs/guide.md\ndelivery-profile: auto"))
        self.assertEqual("micro", result["effectiveProfile"])
        self.assertEqual("micro", result["inferredProfile"])
        self.assertTrue(result["authoritative"])
        self.assertFalse(result["diagnosticOnly"])
        self.assertEqual(["bounded-ordinary-documentation"], result["reasons"])
        self.assertEqual("fast", result["deliveryPolicy"]["modelProfileFloor"])
        self.assertEqual(
            {"modelProfileFloor", "implementationConcurrency"},
            set(result["deliveryPolicy"]),
        )

    def test_sensitive_scope_and_control_paths_are_high_risk(self):
        cases = (
            task("files: docs/AGENTS.md"),
            task("files: docs/a.md, docs/a.md"),
            task("files: docs/auth.md", title="Document authentication"),
            task("files: config/team.config.md", title="Update defaults"),
            task("files: src/tool.py\nwork-kind: operations", title="Run maintenance"),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate):
                result = assess_task(candidate)
                self.assertEqual("high-risk", result["effectiveProfile"])
                self.assertEqual(["qa", "security"], result["authority"]["profileForcedReviewGates"])

    def test_absent_scope_is_high_risk(self):
        for candidate in (task(""), task("delivery-profile: micro")):
            with self.subTest(candidate=candidate):
                result = assess_task(candidate)
                self.assertEqual("high-risk", result["effectiveProfile"])
                self.assertEqual("high-risk", result["inferredProfile"])
                self.assertIn("files-not-declared", result["reasons"])
                self.assertEqual("strong", result["deliveryPolicy"]["modelProfileFloor"])
                self.assertEqual(
                    "exclusive", result["deliveryPolicy"]["implementationConcurrency"]
                )
                self.assertEqual(
                    ["qa", "security"],
                    result["authority"]["profileForcedReviewGates"],
                )
                if result["requestedProfile"] == "micro":
                    self.assertIn(
                        "micro-request-cannot-lower-high-risk", result["reasons"]
                    )

    def test_declared_ordinary_code_and_broader_docs_are_standard(self):
        cases = (
            task("files: src/widget.py\ndelivery-profile: micro"),
            task("files: docs/a.md, docs/b.md, docs/c.md, docs/d.md"),
            task("files: docs/a.md\nresources: shared-index"),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate):
                result = assess_task(candidate)
                self.assertEqual("standard", result["effectiveProfile"])
                if result["requestedProfile"] == "micro":
                    self.assertIn(
                        "micro-request-cannot-lower-standard", result["reasons"]
                    )

    def test_standard_request_can_only_increase_rigor(self):
        result = assess_task(task("files: README.md\ndelivery-profile: standard"))
        self.assertEqual("standard", result["effectiveProfile"])
        self.assertIn("standard-requested", result["reasons"])

    def test_requests_are_monotonic_and_high_risk_is_explicit(self):
        elevated = assess_task(task("files: README.md\ndelivery-profile: high-risk"))
        refused = assess_task(
            task("files: src/auth.py\ndelivery-profile: micro", "Authentication change")
        )
        self.assertEqual("high-risk", elevated["effectiveProfile"])
        self.assertEqual("micro", refused["requestedProfile"])
        self.assertEqual("high-risk", refused["inferredProfile"])
        self.assertEqual("high-risk", refused["effectiveProfile"])
        self.assertIn("micro-request-cannot-lower-high-risk", refused["reasons"])

    def test_authority_invariants_never_vary_by_profile(self):
        decisions = (
            assess_task(task("files: README.md")),
            assess_task(task("files: src/widget.py")),
            assess_task(task("files: src/auth.py", "Authentication change")),
        )
        for decision in decisions:
            authority = decision["authority"]
            self.assertEqual(
                ["team-lead", "principal-architect", "sceptical-architect"],
                authority["coreReviewRoles"],
            )
            self.assertEqual(3, authority["distinctCoreReviewDecisionsRequired"])
            self.assertTrue(authority["exactPackageEvidenceRequired"])
            self.assertTrue(authority["independentValidationRequired"])
            self.assertTrue(authority["integratorAuthorityRequired"])
            self.assertTrue(authority["immutableDenyRulesEnforced"])
            self.assertFalse(authority["profileMayReduceCoreReviewModel"])
            self.assertEqual("credential-separated-external", authority["releaseAuthority"])
            self.assertEqual("credential-separated-external", authority["productionAuthority"])

    def test_metadata_rejects_unknown_delivery_profile(self):
        with self.assertRaisesRegex(ValueError, "delivery-profile"):
            parse_task_metadata("delivery-profile: turbo")
        with self.assertRaisesRegex(ValueError, "more than once"):
            parse_task_metadata("delivery-profile: standard\ndelivery-profile: micro")
        self.assertEqual(
            "high-risk",
            assess_task(task("delivery-profile: turbo"))["effectiveProfile"],
        )
        self.assertEqual(
            "high-risk",
            assess_task(
                task("delivery-profile: standard\ndelivery-profile: micro")
            )["effectiveProfile"],
        )
        self.assertEqual(
            "high-risk",
            assess_task(task("files: README.md"), metadata=[])["effectiveProfile"],
        )
        self.assertEqual(
            "high-risk",
            assess_task(
                task("files: src/auth.py\nfiles: docs/guide.md", "Conflicting scope")
            )["effectiveProfile"],
        )

    def test_metadata_rejects_unknown_model_profile_and_empty_declarations(self):
        for value in ("model-profile: strongg", "model-profile:", "delivery-profile:", "review-gates:"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_task_metadata(value)
                self.assertEqual(
                    "high-risk", assess_task(task(value))["effectiveProfile"]
                )
        parsed = parse_task_metadata(
            "This prose contains model-profile: but is not a metadata declaration.\n"
            "files: README.md"
        )
        self.assertIsNone(parsed["modelProfile"])


class GitExecutionSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fake_git = self.root / "git"
        self.fake_git.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, subprocess, sys, time\n"
            "mode = sys.argv[-1]\n"
            "if mode == 'flood':\n"
            "    while True:\n"
            "        os.write(1, b'x' * 65536)\n"
            "elif mode == 'hang':\n"
            "    time.sleep(30)\n"
            "elif mode == 'hang-child':\n"
            "    code = ('import pathlib,sys,time; time.sleep(0.6); '"
            "            'pathlib.Path(sys.argv[1]).write_text(\\\"survived\\\")')\n"
            "    child = subprocess.Popen([sys.executable, '-c', code, sys.argv[-2]])\n"
            "    pathlib.Path(sys.argv[-3]).write_text(str(child.pid))\n"
            "    time.sleep(30)\n"
            "elif mode == 'stdin':\n"
            "    os.write(1, sys.stdin.buffer.read())\n"
            "elif mode == 'environment':\n"
            "    names = ('PATH', 'HOME', 'GIT_DIR', 'GIT_WORK_TREE', "
            "'GIT_OBJECT_DIRECTORY', "
            "'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG_COUNT', "
            "'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_ASKPASS', "
            "'SSH_ASKPASS', 'GIT_SSH_COMMAND', 'GIT_ALLOW_PROTOCOL', "
            "'GIT_PROTOCOL_FROM_USER', 'GIT_NO_LAZY_FETCH', "
            "'GIT_NO_REPLACE_OBJECTS')\n"
            "    payload = {name: os.environ.get(name) for name in names}\n"
            "    payload['ARGV'] = sys.argv\n"
            "    print(json.dumps(payload))\n"
            "else:\n"
            "    print('trusted-absolute-git')\n",
            encoding="utf-8",
        )
        self.fake_git.chmod(0o755)
        self.git_patcher = mock.patch.object(
            delivery_profile, "GIT_EXECUTABLE", str(self.fake_git.resolve())
        )
        self.git_patcher.start()
        self.environment = {
            "PATH": str(self.root) + os.pathsep + os.environ.get("PATH", ""),
        }

    def tearDown(self):
        self.git_patcher.stop()
        self.temporary.cleanup()

    def test_git_capture_enforces_output_cap_while_process_is_running(self):
        with mock.patch.dict(os.environ, self.environment):
            started = time.monotonic()
            with self.assertRaisesRegex(DeliveryProfileError, "output exceeds"):
                _git(
                    self.root,
                    "flood",
                    max_output_bytes=1024,
                    timeout_seconds=2,
                )
        self.assertLess(time.monotonic() - started, 2)

    def test_git_capture_enforces_deadline(self):
        with mock.patch.dict(os.environ, self.environment):
            started = time.monotonic()
            with self.assertRaisesRegex(DeliveryProfileError, "timed out"):
                _git(self.root, "hang", timeout_seconds=0.05)
        self.assertLess(time.monotonic() - started, 2)

    def test_git_deadline_terminates_the_child_process_group(self):
        pid_file = self.root / "child.pid"
        survivor_file = self.root / "child-survived"
        with self.assertRaisesRegex(DeliveryProfileError, "timed out"):
            _git(
                self.root,
                str(pid_file),
                str(survivor_file),
                "hang-child",
                timeout_seconds=0.2,
            )
        self.assertRegex(pid_file.read_text(), r"^[0-9]+$")
        time.sleep(0.8)
        self.assertFalse(
            survivor_file.exists(), "timed-out Git left its child process running"
        )

    def test_git_capture_streams_bounded_standard_input(self):
        body = b"Review-Package-SHA256: sha256:" + b"a" * 64 + b"\n"
        self.assertEqual(body, _git(self.root, "stdin", input_bytes=body))

    def test_git_capture_uses_a_controlled_environment(self):
        hostile = {
            **self.environment,
            "HOME": "/attacker/home",
            "GIT_DIR": "/attacker/repository",
            "GIT_WORK_TREE": "/attacker/worktree",
            "GIT_OBJECT_DIRECTORY": "/attacker/objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/attacker/alternates",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare",
            "GIT_CONFIG_VALUE_0": "true",
            "GIT_ASKPASS": "/attacker/askpass",
            "SSH_ASKPASS": "/attacker/ssh-askpass",
            "GIT_SSH_COMMAND": "/attacker/ssh",
            "GIT_ALLOW_PROTOCOL": "https:ssh",
            "GIT_PROTOCOL_FROM_USER": "1",
            "GIT_NO_LAZY_FETCH": "0",
            "GIT_NO_REPLACE_OBJECTS": "0",
        }
        with mock.patch.dict(os.environ, hostile):
            child = json.loads(_git(self.root, "environment"))
        for name in (
            "PATH",
            "HOME",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_SSH_COMMAND",
        ):
            self.assertIsNone(child[name], name)
        self.assertEqual("", child["GIT_ALLOW_PROTOCOL"])
        self.assertEqual("0", child["GIT_PROTOCOL_FROM_USER"])
        self.assertEqual("1", child["GIT_NO_LAZY_FETCH"])
        self.assertEqual("1", child["GIT_NO_REPLACE_OBJECTS"])
        self.assertIn("protocol.allow=never", child["ARGV"])
        self.assertIn("credential.helper=", child["ARGV"])
        self.assertIn("core.attributesFile=/dev/null", child["ARGV"])
        self.assertIn("diff.ignoreSubmodules=none", child["ARGV"])
        self.assertIn("diff.interHunkContext=0", child["ARGV"])

    def test_git_resolution_ignores_the_inherited_path(self):
        with mock.patch.dict(os.environ, self.environment):
            resolved = Path(_resolve_git_executable())
        self.assertTrue(resolved.is_absolute())
        self.assertNotEqual(self.fake_git.resolve(), resolved)
        self.assertTrue(resolved.is_file())

    def test_git_capture_executes_the_resolved_absolute_binary(self):
        with mock.patch.dict(os.environ, self.environment):
            self.assertEqual(b"trusted-absolute-git\n", _git(self.root, "default"))


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
        self.assertEqual("high-risk", mismatch["effectiveProfile"])
        self.assertIn("declared-files-mismatch", mismatch["reasons"])

    def test_code_is_standard_while_binary_is_high_risk_and_large_docs_are_standard(self):
        cases = (
            ("src/widget.py", b"print('x')\n", "non-ordinary-documentation-path", "standard"),
            ("docs/blob.md", b"text\x00binary", "binary-content", "high-risk"),
            (
                "docs/large.md",
                ("line\n" * 201).encode(),
                "too-many-changed-lines",
                "standard",
            ),
        )
        for relative, content, reason, expected_profile in cases:
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
                        task(f"files: {relative}\ndelivery-profile: micro"),
                    )
                    self.assertEqual(expected_profile, result["effectiveProfile"])
                    self.assertTrue(any(item.startswith(reason) for item in result["reasons"]))
                finally:
                    fixture.close()

    def test_actual_path_and_patch_content_raise_the_risk_floor(self):
        cases = (
            ("docs/schema.md", b"ordinary words\n", "strong-risk-diff-path", "high-risk"),
            (
                "docs/guide.md",
                b"Document the authentication flow.\n",
                "strong-risk-diff-content",
                "high-risk",
            ),
            (
                "docs/component.mdx",
                b"# Heading\n",
                "non-ordinary-documentation-path",
                "standard",
            ),
        )
        for relative, content, reason, expected_profile in cases:
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
                        task(
                            f"files: {relative}\ndelivery-profile: micro",
                            "Ordinary documentation",
                        ),
                    )
                    self.assertEqual(expected_profile, result["effectiveProfile"])
                    self.assertIn(reason, result["reasons"])
                finally:
                    fixture.close()

    def test_authentication_verbs_in_an_ordinary_path_force_security_review(self):
        snippets = (
            "def authenticate(request):\n    return request.identity is not None\n",
            "request_authorizer = middleware\n",
            "allow_unauthenticated_requests = False\n",
            "message = 'unauthorized user'\n",
        )
        for snippet in snippets:
            with self.subTest(snippet=snippet):
                fixture = GitFixture()
                try:
                    base = fixture.head
                    fixture.write("src/middleware.py", snippet)
                    fixture.commit("change request identity handling")
                    result = assess_diff(
                        fixture.root,
                        base,
                        fixture.head,
                        task(
                            "files: src/middleware.py\ndelivery-profile: standard",
                            "Validate requests",
                        ),
                    )
                    self.assertEqual("high-risk", result["effectiveProfile"])
                    self.assertIn("strong-risk-diff-content", result["reasons"])
                    self.assertEqual(
                        ["qa", "security"],
                        result["authority"]["profileForcedReviewGates"],
                    )
                finally:
                    fixture.close()

    def test_undeclared_exact_documentation_diff_remains_high_risk(self):
        base = self.git.head
        self.git.write("docs/guide.md", "guide\n")
        self.git.commit("docs")
        result = self.assess(base, "delivery-profile: micro")
        self.assertEqual("high-risk", result["inferredProfile"])
        self.assertEqual("high-risk", result["effectiveProfile"])
        self.assertIn("files-not-declared", result["reasons"])
        self.assertIn("micro-request-cannot-lower-high-risk", result["reasons"])
        self.assertEqual(
            ["qa", "security"], result["authority"]["profileForcedReviewGates"]
        )

    def test_exact_diff_detects_security_dependency_and_deployment_surfaces(self):
        cases = (
            (".gitattributes", "*.generated -diff\n"),
            (".gitmodules", "[submodule \"vendor\"]\n\tpath = vendor\n\turl = https://example.invalid/vendor.git\n"),
            (".pre-commit-config.yaml", "repos: []\n"),
            ("src/login.py", "LOGIN_TTL = 300\n"),
            ("src/session/store.py", "DEFAULT_TTL = 300\n"),
            ("src/db_schema.py", "VERSION = 2\n"),
            (".envrc", "export APP_MODE=dev\n"),
            ("server.key", "test fixture key\n"),
            ("pyproject.toml", '[project]\nname = "demo"\n'),
            ("requirements-dev.txt", "pytest==1.0\n"),
            ("ios/Package.swift", "// package definition\n"),
            ("k8s/app.yaml", "replicas: 2\n"),
            ("ci/pipeline.yml", "steps: []\n"),
            ("charts/api/values.yaml", "replicas: 2\n"),
            ("main.tf", 'resource "cloud_vpc" "main" {}\n'),
            ("Dockerfile.production", "FROM scratch\n"),
            ("src/rbacPolicy.ts", "export const rbacPolicy = loadPolicy();\n"),
            ("src/csrfProtection.ts", "export const csrfProtection = enabled;\n"),
            ("src/passwordHash.ts", "export const passwordHash = secretKey;\n"),
            ("requirements/prod.txt", "safe-lib==1.0\n"),
            ("db/migrate/20260919_add_role.sql", "ALTER TABLE accounts ADD owner_role TEXT;\n"),
            ("alembic/versions/abc_add_role.py", "op.add_column('accounts', column)\n"),
            ("Procfile", "web: python app.py\n"),
            ("app.yaml", "runtime: python312\n"),
            ("tools/release.py", "print('release')\n"),
            ("src/admin_guard.py", "allowed = user.is_admin\n"),
            ("src/entitlement_check.py", "allowed = user.entitlement\n"),
            ("src/webhook.py", "verify_webhook_signature(payload)\n"),
            ("src/encryption.py", "def encrypt(value): return value\n"),
            ("src/decrypt.py", "def decrypt(value): return value\n"),
            ("src/hmac.py", "def hmac_digest(value): return value\n"),
            ("src/signing.py", "def sign(value): return value\n"),
            ("template.yaml", "Type: AWS::Serverless::Function\n"),
        )
        for relative, content in cases:
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
                        task(
                            f"files: {relative}\ndelivery-profile: micro",
                            "Bounded change",
                        ),
                    )
                    self.assertEqual("high-risk", result["effectiveProfile"])
                    self.assertTrue(
                        any(
                            reason.startswith("control-plane-path:")
                            or reason == "strong-risk-diff-content"
                            for reason in result["reasons"]
                        )
                    )
                finally:
                    fixture.close()

    def test_conda_manifests_force_high_risk_for_version_only_exact_diffs(self):
        cases = {
            "environment.yml": ("python=3.13", "python=3.14"),
            "environment.yaml": ("python=3.13", "python=3.14"),
            "conda-lock.yml": ("version: 1", "version: 2"),
            "conda-lock.yaml": ("version: 1", "version: 2"),
        }
        for relative, (before, after) in cases.items():
            with self.subTest(relative=relative):
                fixture = GitFixture()
                try:
                    fixture.write(relative, before + "\n")
                    fixture.commit("seed Conda manifest")
                    base = fixture.head
                    fixture.write(relative, after + "\n")
                    fixture.commit("update version only")
                    result = assess_diff(
                        fixture.root,
                        base,
                        fixture.head,
                        task(
                            f"files: {relative}\ndelivery-profile: micro",
                            "Bounded version bump",
                        ),
                    )
                    self.assertEqual("high-risk", result["inferredProfile"])
                    self.assertEqual("high-risk", result["effectiveProfile"])
                    self.assertIn(
                        f"control-plane-path:{relative}", result["reasons"]
                    )
                    self.assertEqual(
                        ["qa", "security"],
                        result["authority"]["profileForcedReviewGates"],
                    )
                finally:
                    fixture.close()

    def test_exact_diff_detects_compound_and_plural_security_filenames(self):
        for relative in COMPOUND_SECURITY_PATHS:
            with self.subTest(relative=relative):
                fixture = GitFixture()
                try:
                    base = fixture.head
                    fixture.write(relative, "value = 1\n")
                    fixture.commit("bounded product change")
                    result = assess_diff(
                        fixture.root,
                        base,
                        fixture.head,
                        task(
                            f"files: {relative}\ndelivery-profile: micro",
                            "Bounded product change",
                        ),
                    )
                    self.assertEqual("high-risk", result["effectiveProfile"])
                    self.assertIn(
                        f"control-plane-path:{relative}", result["reasons"]
                    )
                    self.assertEqual(
                        ["qa", "security"],
                        result["authority"]["profileForcedReviewGates"],
                    )
                finally:
                    fixture.close()

    def test_exact_diff_keeps_similar_ordinary_product_paths_standard(self):
        cases = (
            ("src/author.py", "name = 'writer'\n"),
            ("src/chart_renderer.py", "kind = 'bar'\n"),
            ("src/terraforming_game.py", "score = 1\n"),
            ("src/schematic_view.py", "kind = 'view'\n"),
            ("src/emigration_report.py", "count = 1\n"),
        ) + tuple((path, "value = 1\n") for path in CONFUSABLE_ORDINARY_PATHS)
        for relative, content in cases:
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
                        task(f"files: {relative}", "Ordinary product change"),
                    )
                    self.assertEqual("standard", result["effectiveProfile"])
                    self.assertEqual(
                        [], result["authority"]["profileForcedReviewGates"]
                    )
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
                    self.assertEqual("high-risk", result["effectiveProfile"])
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
                    self.assertEqual("high-risk", result["effectiveProfile"])
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
        self.assertEqual("high-risk", empty["effectiveProfile"])
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
        self.assertEqual("high-risk", risky["effectiveProfile"])
        self.assertIn("strong-risk-language", risky["reasons"])

    def test_explicit_high_risk_can_raise_an_exact_micro_diff(self):
        base = self.git.head
        self.git.write("docs/guide.md", "guide\n")
        self.git.commit("docs")
        result = self.assess(
            base,
            "files: docs/guide.md\ndelivery-profile: high-risk",
        )
        self.assertEqual("micro", result["inferredProfile"])
        self.assertEqual("high-risk", result["effectiveProfile"])
        self.assertEqual("strong", result["deliveryPolicy"]["modelProfileFloor"])
        self.assertEqual(["qa", "security"], result["authority"]["profileForcedReviewGates"])

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

    def test_review_ambiguity_returns_high_risk_instead_of_skipping_gates(self):
        result = assess_review_diff(
            self.git.root / "missing",
            "not-a-commit",
            None,
            task("delivery-profile: micro"),
        )
        self.assertEqual("high-risk", result["effectiveProfile"])
        self.assertEqual("unreadable-exact-diff", result["reasons"][0])
        self.assertEqual(
            ["qa", "security"], result["authority"]["profileForcedReviewGates"]
        )

    def test_replace_refs_cannot_change_the_classified_exact_diff(self):
        base = self.git.head
        self.git.write("docs/guide.md", "ordinary guide\n")
        documented_head = self.git.commit("docs")
        self.git.run("checkout", "-q", "-b", "replacement", base)
        self.git.write("src/auth.py", "authentication_enabled = True\n")
        replacement = self.git.commit("replacement")
        self.git.run("replace", documented_head, replacement)

        result = assess_diff(
            self.git.root,
            base,
            documented_head,
            task("files: docs/guide.md", "Ordinary documentation"),
        )
        self.assertEqual("micro", result["effectiveProfile"])
        self.assertEqual(["docs/guide.md"], result["files"])
        package, package_base, package_head = build_review_package(
            self.git.root, "TASK-REPLACE", base, documented_head
        )
        self.assertEqual(base, package_base)
        self.assertEqual(documented_head, package_head)
        self.assertIn(b"docs/guide.md", package)
        self.assertIn(b"+ordinary guide", package)
        self.assertNotIn(b"src/auth.py", package)
        statistics = package.split(b"## Files changed\n", 1)[1].split(
            b"\n## Diff\n", 1
        )[0]
        self.assertIn(b"docs/guide.md", statistics)

    def test_review_package_ignores_hostile_diff_helpers_attributes_and_path(self):
        self.git.write(".gitattributes", "*.txt diff=hostile\n*.blob -diff\n")
        self.git.write("src/value.txt", "old value\n")
        self.git.write("src/configured.data", "old configured value\n")
        self.git.write("assets/value.blob", b"old\x00value\n")
        self.git.commit("seed hostile diff surfaces")
        base = self.git.head
        self.git.write("src/value.txt", "new value\n")
        self.git.write("src/configured.data", "new configured value\n")
        self.git.write("assets/value.blob", b"new\x00value\n")
        head = self.git.commit("change both surfaces")

        expected, _, _ = build_review_package(
            self.git.root, "TASK-HOSTILE-DIFF", base, head
        )
        hostile_dir = self.git.root / "hostile-bin"
        hostile_dir.mkdir()
        marker = self.git.root / "helper-ran"
        helper = hostile_dir / "omit-diff"
        helper.write_text(
            "#!/bin/sh\n"
            f"printf invoked > '{marker}'\n"
            "printf 'OMITTED BY HOSTILE HELPER\\n'\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)
        attributes = hostile_dir / "attributes"
        attributes.write_text("*.data -diff\n", encoding="utf-8")
        fake_git = hostile_dir / "git"
        fake_git.write_text(
            "#!/bin/sh\n"
            f"printf invoked > '{marker}'\n"
            "exit 99\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        for name, value in (
            ("diff.external", str(helper)),
            ("diff.hostile.command", str(helper)),
            ("diff.hostile.textconv", str(helper)),
            ("core.attributesFile", str(attributes)),
            ("diff.ignoreSubmodules", "all"),
            ("diff.interHunkContext", "99"),
            ("diff.noprefix", "true"),
            ("diff.srcPrefix", "attacker-old/"),
            ("diff.dstPrefix", "attacker-new/"),
            ("diff.orderFile", str(self.git.root / "missing-order-file")),
            ("diff.statWidth", "9999"),
            ("core.abbrev", "4"),
            ("log.showSignature", "true"),
        ):
            self.git.run("config", name, value)
        with mock.patch.dict(os.environ, {"PATH": str(hostile_dir)}):
            actual, package_base, package_head = build_review_package(
                self.git.root, "TASK-HOSTILE-DIFF", base, head
            )

        self.assertEqual(base, package_base)
        self.assertEqual(head, package_head)
        self.assertEqual(expected, actual)
        self.assertFalse(marker.exists(), "hostile Git/diff helper was executed")
        self.assertIn(b"diff --git a/src/value.txt b/src/value.txt", actual)
        self.assertIn(b"-old value", actual)
        self.assertIn(b"+new value", actual)
        self.assertIn(b"diff --git a/src/configured.data b/src/configured.data", actual)
        self.assertIn(b"-old configured value", actual)
        self.assertIn(b"+new configured value", actual)
        self.assertIn(b"diff --git a/assets/value.blob b/assets/value.blob", actual)
        self.assertIn(b"GIT binary patch", actual)
        self.assertNotIn(b"OMITTED BY HOSTILE HELPER", actual)

    def test_forced_text_attribute_cannot_hide_or_embed_a_binary_blob(self):
        self.git.write(".gitattributes", "*.blob diff\n")
        self.git.commit("seed forced text attributes")
        base = self.git.head
        self.git.write("assets/value.blob", b"abc\0def\n")
        head = self.git.commit("add NUL-bearing blob")

        decision = assess_diff(
            self.git.root,
            base,
            head,
            task("files: assets/value.blob", "Add value blob"),
        )
        self.assertEqual("high-risk", decision["effectiveProfile"])
        self.assertIn("binary-content", decision["reasons"])
        with self.assertRaisesRegex(DeliveryProfileError, "raw NUL"):
            build_review_package(self.git.root, "TASK-BINARY", base, head)

    def test_create_review_package_runs_end_to_end_on_a_clean_branch(self):
        base = self.git.head
        self.git.write("docs/guide.md", "governed guide\n")
        head = self.git.commit("guide")
        branch = self.git.run("branch", "--show-current")
        output = self.git.root / ".review-output"
        destination = create_review_package(
            self.git.root,
            self.git.root,
            base,
            branch,
            "TASK-PACKAGE",
            output,
        )
        self.assertTrue(destination.is_file())
        self.assertIn(head.encode("ascii"), destination.read_bytes())
        self.assertTrue(destination.with_suffix(".bindings.json").exists())

    def test_canonical_merge_tree_is_a_disjoint_reviewed_overlay(self):
        review_base = self.git.head
        main_branch = self.git.run("branch", "--show-current")
        self.git.run("switch", "-q", "-c", "task-change")
        self.git.write("task.txt", "reviewed\n")
        task_head = self.git.commit("task")
        self.git.run("switch", "-q", main_branch)
        self.git.write("concurrent.txt", "base change\n")
        integration_base = self.git.commit("concurrent")

        tree, base, head, observed_review_base = canonical_merge_tree(
            self.git.root, integration_base, task_head, review_base
        )
        self.assertEqual((integration_base, task_head, review_base), (base, head, observed_review_base))
        self.assertEqual(
            "reviewed",
            self.git.run("show", f"{tree}:task.txt"),
        )
        self.assertEqual(
            "base change",
            self.git.run("show", f"{tree}:concurrent.txt"),
        )

    def test_canonical_merge_tree_rejects_overlap_and_ignores_custom_driver(self):
        self.git.write(".gitattributes", "*.txt merge=hostile\n")
        self.git.write("shared.txt", "base\n")
        review_base = self.git.commit("seed")
        main_branch = self.git.run("branch", "--show-current")
        self.git.run("switch", "-q", "-c", "task-change")
        self.git.write("task.txt", "task\n")
        task_head = self.git.commit("task")
        self.git.run("switch", "-q", main_branch)
        self.git.write("concurrent.txt", "main\n")
        integration_base = self.git.commit("main")
        marker = self.git.root / "merge-driver-ran"
        self.git.run(
            "config",
            "merge.hostile.driver",
            f"touch '{marker}'; cp %A %A",
        )
        tree, _, _, _ = canonical_merge_tree(
            self.git.root, integration_base, task_head, review_base
        )
        self.assertFalse(marker.exists())
        self.assertEqual("task", self.git.run("show", f"{tree}:task.txt"))

        self.git.run("switch", "-q", "task-change")
        self.git.write("shared.txt", "task overlap\n")
        overlapping_head = self.git.commit("task overlap")
        self.git.run("switch", "-q", main_branch)
        self.git.write("shared.txt", "main overlap\n")
        overlapping_base = self.git.commit("main overlap")
        with self.assertRaisesRegex(DeliveryProfileError, "overlaps reviewed paths"):
            canonical_merge_tree(
                self.git.root, overlapping_base, overlapping_head, review_base
            )
        self.assertFalse(marker.exists())

    def test_hostile_git_environment_cannot_redirect_the_assessed_repository(self):
        base = self.git.head
        self.git.write("docs/guide.md", "ordinary guide\n")
        head = self.git.commit("docs")
        hostile = {
            "GIT_DIR": "/definitely/not/the/repository",
            "GIT_WORK_TREE": "/definitely/not/the/worktree",
            "GIT_OBJECT_DIRECTORY": "/definitely/not/the/objects",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare",
            "GIT_CONFIG_VALUE_0": "true",
        }
        with mock.patch.dict(os.environ, hostile):
            result = assess_diff(
                self.git.root,
                base,
                head,
                task("files: docs/guide.md", "Ordinary documentation"),
            )
        self.assertEqual("micro", result["effectiveProfile"])
        self.assertEqual(["docs/guide.md"], result["files"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
