#!/usr/bin/env python3
"""Focused recovery and trust-boundary tests for the production executor."""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bin"))
SPEC = importlib.util.spec_from_file_location(
    "startup_factory_release_feature", ROOT / "bin" / "release-feature.py"
)
assert SPEC and SPEC.loader
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


class ReleaseLifecycleTest(unittest.TestCase):
    @staticmethod
    def valid_ci_proof(commit: str = "a" * 40) -> dict:
        completed = datetime.now(timezone.utc)
        return {
            "schemaVersion": 1,
            "green": True,
            "commit": commit,
            "provider": "fixture-ci",
            "pipelineId": "fixture-pipeline-12345678",
            "requiredChecks": ["build", "test", "security"],
            "successfulChecks": ["build", "test", "security"],
            "failedChecks": [],
            "pendingChecks": [],
            "skippedChecks": [],
            "completedAt": completed.isoformat(timespec="seconds"),
            "expiresAt": (completed + timedelta(minutes=10)).isoformat(
                timespec="seconds"
            ),
        }

    @staticmethod
    def valid_verification_proof() -> dict:
        return {
            "schemaVersion": 1,
            "healthy": True,
            "releaseId": "release-fixture-12345678",
            "artifactDigest": "sha256:" + "a" * 64,
            "probes": [
                {
                    "id": "acceptance.public-entry",
                    "acceptanceCriterion": "AC-1",
                    "entryPath": "public service endpoint",
                    "preconditions": ["authenticated session"],
                    "passed": True,
                    "negativeControl": False,
                    "evidenceDigest": "sha256:" + "b" * 64,
                },
                {
                    "id": "acceptance.denied-path",
                    "acceptanceCriterion": "AC-2",
                    "entryPath": "public service endpoint",
                    "preconditions": [],
                    "passed": True,
                    "negativeControl": True,
                    "evidenceDigest": "sha256:" + "c" * 64,
                },
            ],
        }

    def test_verification_requires_exact_behavioral_probe_coverage(self) -> None:
        config = {
            "verification": {
                "requiredProbeIds": [
                    "acceptance.public-entry",
                    "acceptance.denied-path",
                ],
                "requireNegativeProbe": True,
            }
        }
        proof = self.valid_verification_proof()
        release.validate_verification_attestation(
            proof,
            release_id="release-fixture-12345678",
            artifact_digest="sha256:" + "a" * 64,
            config=config,
        )
        with self.assertRaisesRegex(release.ReleaseError, "cover exactly"):
            release.validate_verification_attestation(
                {**proof, "probes": proof["probes"][:1]},
                release_id="release-fixture-12345678",
                artifact_digest="sha256:" + "a" * 64,
                config=config,
            )
        with self.assertRaisesRegex(release.ReleaseError, "negative/failure-path"):
            release.validate_verification_attestation(
                {
                    **proof,
                    "probes": [
                        {**item, "negativeControl": False}
                        for item in proof["probes"]
                    ],
                },
                release_id="release-fixture-12345678",
                artifact_digest="sha256:" + "a" * 64,
                config=config,
            )

    def test_verification_rejects_helper_only_or_unbound_evidence(self) -> None:
        config = {
            "verification": {
                "requiredProbeIds": [
                    "acceptance.public-entry",
                    "acceptance.denied-path",
                ],
                "requireNegativeProbe": True,
            }
        }
        proof = self.valid_verification_proof()
        invalid = {
            **proof,
            "probes": [
                {**proof["probes"][0], "entryPath": ""},
                proof["probes"][1],
            ],
        }
        with self.assertRaisesRegex(release.ReleaseError, "entryPath"):
            release.validate_verification_attestation(
                invalid,
                release_id="release-fixture-12345678",
                artifact_digest="sha256:" + "a" * 64,
                config=config,
            )
        with self.assertRaisesRegex(release.ReleaseError, "deployed artifact"):
            release.validate_verification_attestation(
                proof,
                release_id="release-fixture-12345678",
                artifact_digest="sha256:" + "d" * 64,
                config=config,
            )

    def test_ci_proof_requires_exact_commit_and_closed_schema(self) -> None:
        proof = self.valid_ci_proof()
        proof["pipelineId"] = "1"
        release.validate_ci_proof(
            proof,
            commit="a" * 40,
            config={"ciAttestationTtlSeconds": 900},
            require_fresh=True,
        )
        with self.assertRaisesRegex(release.ReleaseError, "exact release commit"):
            release.validate_ci_proof(
                proof,
                commit="b" * 40,
                config={"ciAttestationTtlSeconds": 900},
                require_fresh=True,
            )
        with self.assertRaisesRegex(release.ReleaseError, "bounded provider identity"):
            release.validate_ci_proof(
                {**proof, "provider": " fixture-ci "},
                commit="a" * 40,
                config={"ciAttestationTtlSeconds": 900},
                require_fresh=True,
            )
        with self.assertRaisesRegex(release.ReleaseError, "exact closed proof schema"):
            release.validate_ci_proof(
                {**proof, "untrustedOverride": True},
                commit="a" * 40,
                config={"ciAttestationTtlSeconds": 900},
                require_fresh=True,
            )

    def test_ci_proof_blocks_every_non_green_check_state(self) -> None:
        proof = self.valid_ci_proof()
        non_green = (
            {**proof, "green": False},
            {**proof, "successfulChecks": ["build", "test"]},
            {**proof, "failedChecks": ["security"]},
            {**proof, "pendingChecks": ["security"]},
            {**proof, "skippedChecks": ["security"]},
        )
        for candidate in non_green:
            with self.subTest(candidate=candidate):
                with self.assertRaises(release.AwaitingCi):
                    release.validate_ci_proof(
                        candidate,
                        commit="a" * 40,
                        config={"ciAttestationTtlSeconds": 900},
                        require_fresh=True,
                    )

    def test_expired_green_ci_proof_cannot_authorize_apply(self) -> None:
        completed = datetime.now(timezone.utc) - timedelta(minutes=20)
        proof = {
            **self.valid_ci_proof(),
            "completedAt": completed.isoformat(timespec="seconds"),
            "expiresAt": (completed + timedelta(minutes=10)).isoformat(
                timespec="seconds"
            ),
        }
        with self.assertRaises(release.AwaitingCi):
            release.validate_ci_proof(
                proof,
                commit="a" * 40,
                config={"ciAttestationTtlSeconds": 900},
                require_fresh=True,
            )
        release.validate_ci_proof(
            proof,
            commit="a" * 40,
            config={"ciAttestationTtlSeconds": 900},
            require_fresh=False,
        )

    def test_preapply_sibling_is_superseded_but_postapply_sibling_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            releases = Path(raw)
            old = releases / "old"
            old.mkdir()
            release.atomic_json(old / "transaction.json", {
                "phase": "awaiting-product-approval",
                "commit": "a" * 40,
            })

            release.check_sibling_transactions(releases, "new", "b" * 40)
            superseded = json.loads((old / "transaction.json").read_text())
            self.assertEqual(superseded["phase"], "superseded")
            self.assertEqual(superseded["supersededByReleaseId"], "new")
            self.assertEqual(superseded["supersededByCommit"], "b" * 40)

            applying = releases / "applying"
            applying.mkdir()
            release.atomic_json(applying / "transaction.json", {
                "phase": "applying",
                "commit": "c" * 40,
                "productAcceptanceConsumedAt": "2026-01-01T00:00:00+00:00",
            })
            with self.assertRaisesRegex(release.ReleaseError, "active deployment transaction"):
                release.check_sibling_transactions(releases, "new", "b" * 40)

    def test_expired_attestation_is_fresh_preapply_but_historical_postapply(self) -> None:
        issued = datetime.now(timezone.utc) - timedelta(minutes=20)
        proof = {
            "schemaVersion": 1,
            "trusted": True,
            "featureIdDigest": release.text_digest("feature-1"),
            "team": "factory-one",
            "commit": "a" * 40,
            "sourceArchiveDigest": "sha256:" + "d" * 64,
            "integrationEvidenceDigest": "sha256:" + "b" * 64,
            "productAcceptanceDigest": "sha256:" + "c" * 64,
            "roleIsolation": True,
            "approvalAuthenticity": True,
            "planningIsolation": True,
            "isolationProvider": "test-isolator",
            "planningIsolationProvider": "test-planning-sandbox",
            "attestationId": "attestation-test-0001",
            "issuedAt": issued.isoformat(timespec="seconds"),
            "expiresAt": (issued + timedelta(minutes=10)).isoformat(timespec="seconds"),
        }
        arguments = {
            "feature_id": "feature-1",
            "team": "factory-one",
            "commit": "a" * 40,
            "source_archive_digest": "sha256:" + "d" * 64,
            "integration_evidence_digest": "sha256:" + "b" * 64,
            "product_acceptance_digest": "sha256:" + "c" * 64,
            "config": {
                "deliveryAttestationTtlSeconds": 900,
                "planningIsolation": {"provider": "test-planning-sandbox"},
            },
        }
        with self.assertRaises(release.AwaitingAuthorization):
            release.validate_delivery_attestation(proof, **arguments, require_fresh=True)
        release.validate_delivery_attestation(proof, **arguments, require_fresh=False)

    def test_approval_is_rechecked_for_expiry_before_apply(self) -> None:
        created = datetime.now(timezone.utc) - timedelta(minutes=20)
        expires = created + timedelta(minutes=10)
        manifest = {
            "nonce": "n" * 64,
            "createdAt": created.isoformat(timespec="seconds"),
            "expiresAt": expires.isoformat(timespec="seconds"),
        }
        proof = {
            "schemaVersion": 1,
            "approved": True,
            "manifestDigest": release.canonical_digest(manifest),
            "nonce": manifest["nonce"],
            "approver": {"id": "release-manager@example.test"},
            "approvalId": "approval-expired-0001",
            "approvedAt": manifest["createdAt"],
            "expiresAt": manifest["expiresAt"],
        }
        with self.assertRaises(release.AwaitingAuthorization):
            release.validate_approval_proof(proof, manifest, require_fresh=True)
        release.validate_approval_proof(proof, manifest, require_fresh=False)

    def test_expiry_check_runs_after_delay_at_process_spawn_boundary(self) -> None:
        created = datetime.now(timezone.utc) - timedelta(seconds=1)
        expires = datetime.now(timezone.utc) + timedelta(milliseconds=150)
        manifest = {
            "nonce": "n" * 64,
            "createdAt": created.isoformat(),
            "expiresAt": expires.isoformat(),
        }
        proof = {
            "schemaVersion": 1,
            "approved": True,
            "manifestDigest": release.canonical_digest(manifest),
            "nonce": manifest["nonce"],
            "approver": {"id": "release-manager@example.test"},
            "approvalId": "approval-boundary-0001",
            "approvedAt": manifest["createdAt"],
            "expiresAt": manifest["expiresAt"],
        }
        with tempfile.TemporaryDirectory() as raw:
            sentinel = Path(raw) / "apply-started"

            def delayed_boundary_check() -> None:
                time.sleep(0.3)
                release.validate_approval_proof(
                    proof,
                    manifest,
                    require_fresh=True,
                )

            with self.assertRaises(release.AwaitingAuthorization):
                release.run_process_group(
                    ["/bin/sh", "-c", f"printf started > {sentinel}"],
                    cwd=Path(raw),
                    env={"PATH": "/usr/bin:/bin"},
                    timeout=2,
                    before_spawn=delayed_boundary_check,
                )
            self.assertFalse(sentinel.exists())

    def test_timed_out_hook_terminates_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            sentinel = root / "late-production-write"
            hook = root / "hook.sh"
            hook.write_text(
                "#!/bin/sh\n"
                f"(sleep 0.5; printf unsafe > '{sentinel}') &\n"
                "sleep 30\n"
            )
            hook.chmod(0o700)
            with self.assertRaises(release.ProcessDeadline):
                release.run_process_group(
                    [str(hook)],
                    cwd=root,
                    env={"PATH": "/usr/bin:/bin"},
                    timeout=0.1,
                )
            time.sleep(0.7)
            self.assertFalse(sentinel.exists())

    def test_outer_termination_reaps_term_resistant_provider_hook(self) -> None:
        """A stale-worker SIGTERM must not strand a privileged hook session."""
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            hook_pid = root / "hook.pid"
            hook = root / "hook.sh"
            hook.write_text(
                "#!/bin/sh\n"
                "trap '' TERM INT\n"
                f"printf '%s\\n' \"$$\" > '{hook_pid}'\n"
                "while :; do sleep 30; done\n"
            )
            hook.chmod(0o700)
            driver = root / "driver.py"
            driver.write_text(
                "import importlib.util, pathlib, sys\n"
                f"path=pathlib.Path({str(ROOT / 'bin' / 'release-feature.py')!r})\n"
                "sys.path.insert(0,str(path.parent))\n"
                "spec=importlib.util.spec_from_file_location('release_signal_test',path)\n"
                "module=importlib.util.module_from_spec(spec); "
                "sys.modules[spec.name]=module; spec.loader.exec_module(module)\n"
                "module.install_release_signal_handlers()\n"
                "try:\n"
                f" module.run_process_group([{str(hook)!r}],cwd=pathlib.Path({str(root)!r}),"
                "env={'PATH':'/usr/bin:/bin'},timeout=30)\n"
                "except module.ReleaseInterrupted:\n"
                " raise SystemExit(143)\n"
            )
            executor = subprocess.Popen(
                [sys.executable, str(driver)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not hook_pid.exists() and time.monotonic() < deadline:
                    if executor.poll() is not None:
                        break
                    time.sleep(0.02)
                if not hook_pid.exists():
                    stdout, stderr = executor.communicate(timeout=1)
                    self.fail(
                        "provider hook did not start: "
                        f"exit={executor.returncode} stdout={stdout!r} stderr={stderr!r}"
                    )
                provider_pid = int(hook_pid.read_text().strip())
                os.killpg(executor.pid, signal.SIGTERM)
                executor.wait(timeout=8)
                self.assertEqual(executor.returncode, 143)
                with self.assertRaises(ProcessLookupError):
                    os.kill(provider_pid, 0)
            finally:
                if executor.poll() is None:
                    os.killpg(executor.pid, signal.SIGKILL)
                    executor.wait(timeout=2)
                if executor.stdout is not None:
                    executor.stdout.close()
                if executor.stderr is not None:
                    executor.stderr.close()

    def test_security_json_rejects_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            release.strict_json('{"secretValueAccess":true,"secretValueAccess":false}')

    def test_attestation_refresh_invalidates_every_derived_authorization(self) -> None:
        transaction = {
            "phase": "planned",
            "productAcceptanceDigest": "sha256:" + "a" * 64,
            "productAcceptanceState": "approved",
            "artifactDigest": "sha256:" + "b" * 64,
            "planDigest": "sha256:" + "c" * 64,
            "manifestDigest": "sha256:" + "d" * 64,
            "deliveryAttestationDigest": "sha256:" + "e" * 64,
            "approvalProofDigest": "sha256:" + "f" * 64,
        }
        release.reset_preapply_transaction_for_attestation(transaction)
        self.assertEqual(transaction["phase"], "new")
        self.assertEqual(transaction["productAcceptanceState"], "approved")
        self.assertIn("productAcceptanceDigest", transaction)
        for key in (
            "artifactDigest", "planDigest", "manifestDigest",
            "deliveryAttestationDigest", "approvalProofDigest",
        ):
            self.assertNotIn(key, transaction)

    def test_git_inspection_environment_has_no_scheduler_credentials(self) -> None:
        os.environ["LINEAR_API_KEY"] = "must-not-cross"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "must-not-cross"
        os.environ["HOME"] = "/tmp/untrusted-home"
        child = release.unprivileged_git_environment()
        self.assertNotIn("LINEAR_API_KEY", child)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", child)
        self.assertNotIn("HOME", child)
        argv = release.git_argv("status")
        self.assertIn("core.hooksPath=/dev/null", argv)
        self.assertIn("core.fsmonitor=false", argv)

    def test_repository_git_directory_identity_is_bound_and_rechecked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repository = Path(raw) / "repo"
            repository.mkdir()
            subprocess.run(["/usr/bin/git", "init", "-q", "-b", "feature"], cwd=repository, check=True)
            old = (
                release.ACTIVE_TRUSTED_PATH,
                release.TRUSTED_GIT,
                release.BOUND_GIT_DIR,
                release.BOUND_WORK_TREE,
                release.BOUND_GIT_COMMON_DIR,
                release.BOUND_GIT_DIR_ID,
                release.BOUND_GIT_COMMON_DIR_ID,
            )
            try:
                release.configure_trusted_tools(
                    {"trustedPath": "/usr/bin", "planningEnvironmentAllowlist": ["PATH"]},
                    repository,
                )
                args = SimpleNamespace(
                    expected_git_dir=None,
                    expected_git_dir_id=None,
                    expected_git_common_dir=None,
                    expected_git_common_dir_id=None,
                )
                release.bind_repository_identity(args, repository.resolve())
                git_dir = repository / ".git"
                git_dir.rename(repository / ".git.original")
                git_dir.mkdir()
                with self.assertRaisesRegex(release.ReleaseError, "identity changed"):
                    release.revalidate_bound_repository_identity(repository.resolve())
            finally:
                (
                    release.ACTIVE_TRUSTED_PATH,
                    release.TRUSTED_GIT,
                    release.BOUND_GIT_DIR,
                    release.BOUND_WORK_TREE,
                    release.BOUND_GIT_COMMON_DIR,
                    release.BOUND_GIT_DIR_ID,
                    release.BOUND_GIT_COMMON_DIR_ID,
                ) = old
    def test_hook_placeholders_are_exact_and_snake_case_only(self) -> None:
        self.assertEqual(
            release.render_hook(["/protected/hook", "{artifact_digest}"], {"artifact_digest": "sha256:x"}, "apply"),
            ["/protected/hook", "sha256:x"],
        )
        with self.assertRaisesRegex(release.ReleaseError, "unknown placeholder"):
            release.render_hook(["/protected/hook", "{artifactDigest}"], {"artifact_digest": "sha256:x"}, "apply")
        with self.assertRaisesRegex(release.ReleaseError, "malformed placeholder"):
            release.render_hook(["/protected/hook", "{{artifact_digest}"], {"artifact_digest": "sha256:x"}, "apply")

    def test_protected_policy_runs_in_process_without_ambient_child(self) -> None:
        old_root, old_cache = release.TRUSTED_SKILL_DIR, release.PROTECTED_POLICY_CACHE
        release.TRUSTED_SKILL_DIR = ROOT
        release.PROTECTED_POLICY_CACHE = None
        try:
            with mock.patch.object(
                release.subprocess, "run", side_effect=AssertionError("policy spawned a child")
            ):
                release.policy_command(
                    "deploy.plan", "production", ["/protected/plan-hook"],
                    authorization_digest=None,
                )
        finally:
            release.TRUSTED_SKILL_DIR = old_root
            release.PROTECTED_POLICY_CACHE = old_cache

    def test_hook_snapshot_cannot_hide_destructive_source_argv_from_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            values = {
                "source_dir": str(root),
                "source_archive": str(root / "source.tar"),
            }
            config = {
                "environment": "production",
                "hooks": {"apply": ["/bin/rm", "-rf", "/tmp/target"]},
                "timeoutsSeconds": {"apply": 1},
            }
            completed = subprocess.CompletedProcess(
                ["/protected/trusted-hooks/apply", "-rf", "/tmp/target"], 0, "", ""
            )
            with (
                mock.patch.object(
                    release,
                    "validate_hook_executable",
                    return_value=("sha256:" + "a" * 64, Path("/protected/trusted-hooks/apply")),
                ),
                mock.patch.object(release, "policy_command") as policy,
                mock.patch.object(release, "run_process_group", return_value=completed),
            ):
                release.run_hook(
                    "apply",
                    "deploy.apply",
                    config,
                    values,
                    repository=root,
                    env={"PATH": "/usr/bin:/bin"},
                    secrets=[],
                    logs=root / "logs",
                )
            policy.assert_called_once_with(
                "deploy.apply",
                "production",
                ["/bin/rm", "-rf", "/tmp/target"],
                authorization_digest=None,
            )

    def test_hook_bytes_are_captured_before_the_source_path_can_change(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repository = root / "repo"
            repository.mkdir()
            hook = root / "release-apply"
            original = b"#!/bin/sh\nexit 0\n"
            hook.write_bytes(original)
            hook.chmod(0o500)
            digest = "sha256:" + __import__("hashlib").sha256(original).hexdigest()
            old_root = release.PROTECTED_HOOK_ROOT
            release.PROTECTED_HOOK_ROOT = root / "protected" / "trusted-hooks"
            try:
                observed, snapshot = release.validate_hook_executable(
                    "apply",
                    [str(hook), "--release", "fixture"],
                    {"trustedHookDigests": {"apply": digest}},
                    repository,
                    root / "source",
                    root / "source.tar",
                )
                self.assertEqual(observed, digest)
                hook.chmod(0o700)
                hook.write_bytes(b"#!/bin/sh\nprintf tampered\n")
                self.assertEqual(snapshot.read_bytes(), original)
            finally:
                release.PROTECTED_HOOK_ROOT = old_root

    def test_privileged_environment_rejects_loader_controls_and_fixes_path(self) -> None:
        with self.assertRaisesRegex(release.ReleaseError, "loader/control"):
            release.read_environment(
                {"planningEnvironmentAllowlist": ["PATH", "PYTHONPATH"]},
                "planningEnvironmentAllowlist",
            )
        with self.assertRaisesRegex(release.ReleaseError, "loader/control"):
            release.read_environment(
                {"planningEnvironmentAllowlist": ["PYTHONPLATLIBDIR"]},
                "planningEnvironmentAllowlist",
            )
        for unsafe_credential in ("PATH", "PYTHONUSERBASE", "PYTHONBREAKPOINT"):
            with self.assertRaisesRegex(release.ReleaseError, "loader/control"):
                release.read_credentials(
                    {
                        "trustedPath": "/usr/bin",
                        "environmentAllowlist": [],
                        "credentialEnvironmentAllowlist": [unsafe_credential],
                    },
                    ROOT,
                )
        original_path = os.environ.get("PATH")
        os.environ["PATH"] = "/tmp/agent-controlled"
        try:
            child = release.read_environment(
                {
                    "trustedPath": "/usr/bin",
                    "planningEnvironmentAllowlist": ["PATH"],
                },
                "planningEnvironmentAllowlist",
            )
        finally:
            if original_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original_path
        self.assertEqual(child["PATH"], "/usr/bin")

        portable = release.read_environment(
            {
                "trustedPath": "/usr/bin:/bin",
                "planningEnvironmentAllowlist": ["PATH"],
            },
            "planningEnvironmentAllowlist",
            ROOT,
        )
        expected = []
        for raw_path in ("/usr/bin", "/bin"):
            resolved = str(Path(raw_path).resolve())
            if resolved not in expected:
                expected.append(resolved)
        self.assertEqual(portable["PATH"], ":".join(expected))

        with tempfile.TemporaryDirectory() as raw:
            writable = Path(raw).resolve() / "bin"
            writable.mkdir(mode=0o777)
            writable.chmod(0o777)
            with self.assertRaisesRegex(release.ReleaseError, "group/world writable"):
                release.read_environment(
                    {
                        "trustedPath": str(writable),
                        "planningEnvironmentAllowlist": ["PATH"],
                    },
                    "planningEnvironmentAllowlist",
                    Path(raw) / "repository",
                )

        old_path, old_git = release.ACTIVE_TRUSTED_PATH, release.TRUSTED_GIT
        try:
            release.configure_trusted_tools(
                {
                    "trustedPath": "/usr/bin",
                    "planningEnvironmentAllowlist": ["PATH"],
                },
                ROOT,
            )
            self.assertTrue(Path(release.git_argv("status")[0]).is_absolute())
        finally:
            release.ACTIVE_TRUSTED_PATH, release.TRUSTED_GIT = old_path, old_git

    def test_target_lease_survives_failure_and_only_safe_terminal_releases_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            owner = root / "features" / "group-one" / "releases" / "release-one" / "transaction.json"
            owner.parent.mkdir(parents=True)
            active = root / "targets" / ("a" * 64) / "active.json"
            active.parent.mkdir(parents=True)
            target = {"id": "prod"}
            release.atomic_json(owner, {
                "releaseId": "release-one",
                "featureId": "feature-one",
                "phase": "applying",
            })
            arguments = {
                "active_file": active,
                "state_root": root,
                "transaction_file": owner,
                "release_id": "release-one",
                "feature_id": "feature-one",
                "environment": "production",
                "target": target,
                "lease_key": "a" * 64,
            }
            release.claim_target_lease(**arguments)
            self.assertTrue(active.exists())
            transaction = json.loads(owner.read_text())
            transaction["phase"] = "failed"
            release.atomic_json(owner, transaction)
            contender = root / "features" / "group-two" / "releases" / "release-two" / "transaction.json"
            contender.parent.mkdir(parents=True)
            release.atomic_json(contender, {
                "releaseId": "release-two",
                "featureId": "feature-two",
                "phase": "planned",
            })
            with self.assertRaisesRegex(release.ReleaseError, "failed release"):
                release.claim_target_lease(
                    active,
                    state_root=root,
                    transaction_file=contender,
                    release_id="release-two",
                    feature_id="feature-two",
                    environment="production",
                    target=target,
                    lease_key="a" * 64,
                )
            transaction["phase"] = "rolled-back"
            release.atomic_json(owner, transaction)
            release.claim_target_lease(
                active,
                state_root=root,
                transaction_file=contender,
                release_id="release-two",
                feature_id="feature-two",
                environment="production",
                target=target,
                lease_key="a" * 64,
            )
            self.assertEqual(json.loads(active.read_text())["releaseId"], "release-two")
            self.assertTrue(release.release_target_lease(active, "release-two", require_owner=True))
            self.assertFalse(active.exists())

    def test_rolling_back_recovery_never_replays_apply(self) -> None:
        previous = "sha256:" + "b" * 64
        transaction = {"phase": "rolling-back", "previousArtifactDigest": previous}
        outcome = release.reconcile_rolling_back(
            transaction,
            {"state": "applied", "artifactDigest": previous},
        )
        self.assertEqual(outcome, "rolled-back")
        self.assertEqual(transaction["phase"], "rolled-back")

        uncertain = {"phase": "rolling-back", "previousArtifactDigest": previous}
        outcome = release.reconcile_rolling_back(
            uncertain,
            {"state": "applied", "artifactDigest": "sha256:" + "a" * 64},
        )
        self.assertEqual(outcome, "failed")
        self.assertIn("explicit operator recovery", uncertain["failure"])

    def test_release_source_excludes_untracked_files_and_rejects_unsafe_tar(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repository = root / "repo"
            repository.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.test"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repository, check=True)
            (repository / "committed.txt").write_text("committed\n")
            subprocess.run(["git", "add", "committed.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "initial"], cwd=repository, check=True)
            (repository / "untracked.txt").write_text("untracked\n")
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
            release_dir = root / "release"
            release_dir.mkdir()
            config = {
                "gitLfsPolicy": "reject-pointers",
                "maxSourceArchiveBytes": 1024 * 1024,
                "maxSourceBytes": 1024 * 1024,
                "maxSourceFiles": 100,
            }
            archive, digest = release.create_source_archive(repository, commit, release_dir, config)
            source = release.materialize_source_archive(archive, digest, commit, release_dir, config)
            self.assertEqual((source / "committed.txt").read_text(), "committed\n")
            self.assertFalse((source / "untracked.txt").exists())
            for path in sorted(source.rglob("*"), key=lambda item: len(item.parts), reverse=True):
                path.chmod(0o700 if path.is_dir() else 0o600)
            source.chmod(0o700)

            unsafe_dir = root / "unsafe"
            unsafe_dir.mkdir()
            unsafe_tar = unsafe_dir / "source.tar"
            with tarfile.open(unsafe_tar, "w") as handle:
                member = tarfile.TarInfo("../escape")
                member.size = 0
                handle.addfile(member)
            unsafe_digest = release.file_digest(unsafe_tar)
            with self.assertRaisesRegex(release.ReleaseError, "unsafe member path"):
                release.materialize_source_archive(
                    unsafe_tar, unsafe_digest, commit, unsafe_dir, config
                )

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "platform has no O_NOFOLLOW")
    def test_atomic_writer_replaces_final_symlink_and_rejects_symlink_parent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            outside = root / "outside.json"
            outside.write_text("sentinel")
            target = root / "target.json"
            target.symlink_to(outside)
            release.atomic_json(target, {"safe": True})
            self.assertEqual(outside.read_text(), "sentinel")
            self.assertEqual(json.loads(target.read_text()), {"safe": True})

            real = root / "real"
            real.mkdir()
            linked_parent = root / "linked"
            linked_parent.symlink_to(real, target_is_directory=True)
            with self.assertRaises(release.ReleaseError):
                release.atomic_json(linked_parent / "request.json", {"unsafe": True})
            self.assertFalse((real / "request.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
