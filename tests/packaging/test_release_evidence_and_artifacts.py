#!/usr/bin/env python3
"""Focused tests for protected evidence extraction and release-set verification."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _synthetic_provider_value(*parts: str) -> str:
    """Build scanner fixtures at runtime without embedding provider tokens in Git."""

    return "".join(parts)


def _load(name: str, relative: str):
    specification = importlib.util.spec_from_file_location(name, ROOT / relative)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {relative}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


extractor = _load("release_evidence_extractor", "packaging/extract_release_evidence.py")
verifier = _load("release_artifact_verifier", "packaging/verify_release_artifacts.py")


class ReleaseEvidenceExtractorTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = self.root / "evidence"
        self.repository.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Evidence Test")
        self.git("config", "user.email", "evidence@example.invalid")

    def git(self, *arguments: str) -> str:
        process = subprocess.run(
            ["git", "-C", os.fspath(self.repository), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if process.returncode:
            self.fail(f"git {' '.join(arguments)} failed: {process.stderr}")
        return process.stdout.strip()

    def write(self, relative: str, payload: bytes) -> None:
        target = self.repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)

    def commit(self, *, artifact_path: str = ".startup-factory/beta-evidence/check.json") -> tuple[str, bytes, bytes]:
        artifact = b'{"artifact":"bounded"}\n'
        artifact_digest = hashlib.sha256(artifact).hexdigest()
        envelope = (
            json.dumps(
                {
                    "schemaVersion": 1,
                    "candidateCommit": "a" * 40,
                    "generatedAt": "2026-09-20T12:00:00Z",
                    "criteria": [
                        {
                            "id": "full-validation",
                            "status": "pass",
                            "observedAt": "2026-09-20T11:59:00Z",
                            "evidencePath": artifact_path,
                            "evidenceSha256": artifact_digest,
                            "detail": "fixture",
                        }
                    ],
                },
                sort_keys=True,
            )
            + "\n"
        ).encode()
        self.write(extractor.ENVELOPE, envelope)
        self.write(artifact_path, artifact)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "evidence")
        return self.git("rev-parse", "HEAD"), envelope, artifact

    def test_extracts_only_the_exact_regular_referenced_set(self) -> None:
        commit, envelope, artifact = self.commit()
        target = self.root / "candidate"
        target.mkdir()
        result = extractor.extract_evidence(self.repository, commit, target)
        self.assertEqual(result["commit"], commit)
        self.assertEqual(
            (target / extractor.ENVELOPE).read_bytes(), envelope
        )
        artifact_path = target / ".startup-factory/beta-evidence/check.json"
        self.assertEqual(artifact_path.read_bytes(), artifact)
        self.assertEqual(artifact_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(result["files"]), 2)

    def test_unexpected_tree_entry_and_reference_mismatch_fail_closed(self) -> None:
        commit, _, _ = self.commit()
        self.write("README.md", b"not evidence\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "unexpected")
        unexpected = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(extractor.EvidenceExtractionError, "unexpected path"):
            extractor.extract_evidence(self.repository, unexpected, self.root / "missing")

        target = self.root / "candidate"
        target.mkdir()
        self.git("reset", "--hard", commit)
        (self.repository / ".startup-factory/beta-evidence/check.json").unlink()
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "missing referenced artifact")
        mismatch = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(
            extractor.EvidenceExtractionError,
            "exactly match envelope pass references",
        ):
            extractor.extract_evidence(self.repository, mismatch, target)

    def test_duplicate_json_symlink_and_existing_destination_are_rejected(self) -> None:
        commit, envelope, _ = self.commit()
        envelope_path = self.repository / extractor.ENVELOPE
        envelope_path.write_bytes(envelope.replace(b'"schemaVersion": 1', b'"schemaVersion": 1, "schemaVersion": 1'))
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "duplicate key")
        duplicate = self.git("rev-parse", "HEAD")
        target = self.root / "candidate-duplicate"
        target.mkdir()
        with self.assertRaisesRegex(extractor.EvidenceExtractionError, "duplicate JSON key"):
            extractor.extract_evidence(self.repository, duplicate, target)

        self.git("reset", "--hard", commit)
        artifact = self.repository / ".startup-factory/beta-evidence/check.json"
        artifact.unlink()
        artifact.symlink_to("outside")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "symlink")
        symlink_commit = self.git("rev-parse", "HEAD")
        symlink_target = self.root / "candidate-symlink"
        symlink_target.mkdir()
        with self.assertRaisesRegex(extractor.EvidenceExtractionError, "regular mode 100644"):
            extractor.extract_evidence(self.repository, symlink_commit, symlink_target)

        collision_target = self.root / "candidate-collision"
        (collision_target / ".startup-factory").mkdir(parents=True)
        (collision_target / ".startup-factory/beta-readiness-evidence.json").write_text(
            "do not replace\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(extractor.EvidenceExtractionError, "already exists"):
            extractor.extract_evidence(self.repository, commit, collision_target)
        self.assertEqual(
            (collision_target / ".startup-factory/beta-readiness-evidence.json").read_text(),
            "do not replace\n",
        )

    def test_duplicate_secret_key_and_secret_like_path_never_reach_logs(self) -> None:
        _, envelope, _ = self.commit()
        token = _synthetic_provider_value(
            "gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"
        )
        envelope_path = self.repository / extractor.ENVELOPE
        injected = envelope.replace(
            b'"schemaVersion": 1',
            ('"%s": 1, "%s": 2, "schemaVersion": 1' % (token, token)).encode(),
        )
        envelope_path.write_bytes(injected)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "duplicate secret key")
        duplicate = self.git("rev-parse", "HEAD")
        target = self.root / "candidate-duplicate-secret"
        target.mkdir()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            return_code = extractor.main(
                [
                    "--source",
                    os.fspath(self.repository),
                    "--commit",
                    duplicate,
                    "--target",
                    os.fspath(target),
                ]
            )
        self.assertEqual(2, return_code)
        self.assertIn("duplicate JSON key", stderr.getvalue())
        self.assertNotIn(token, stderr.getvalue())

        secret_path = f".startup-factory/beta-evidence/{token}.json"
        self.git("reset", "--hard", "HEAD~1")
        commit, _, _ = self.commit(artifact_path=secret_path)
        secret_target = self.root / "candidate-secret-path"
        secret_target.mkdir()
        with self.assertRaises(extractor.EvidenceExtractionError) as raised:
            extractor.extract_evidence(self.repository, commit, secret_target)
        self.assertIn("secret-like path", str(raised.exception))
        self.assertNotIn(token, str(raised.exception))

    def test_oversize_blob_and_non_exact_commit_are_rejected(self) -> None:
        commit, _, _ = self.commit()
        artifact = self.repository / ".startup-factory/beta-evidence/check.json"
        artifact.write_bytes(b"x" * (extractor.MAX_ARTIFACT_BYTES + 1))
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "oversize artifact")
        oversize = self.git("rev-parse", "HEAD")
        target = self.root / "candidate-oversize"
        target.mkdir()
        with self.assertRaisesRegex(extractor.EvidenceExtractionError, "exceeds"):
            extractor.extract_evidence(self.repository, oversize, target)
        self.assertFalse((target / ".startup-factory").exists())

        with self.assertRaisesRegex(extractor.EvidenceExtractionError, "full lowercase"):
            extractor.extract_evidence(self.repository, commit[:12], target)


class ReleaseArtifactVerifierTest(unittest.TestCase):
    VERSION = "0.2.0"

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.distributions = self.root / "dist"
        self.assets = self.root / "release-assets"
        self.distributions.mkdir()
        self.assets.mkdir()
        self.names = {
            "bundle": f"startup-factory-{self.VERSION}.tar.gz",
            "wheel": f"startup_factory-{self.VERSION}-py3-none-any.whl",
            "sdist": f"startup_factory-{self.VERSION}.tar.gz",
        }
        self.payloads = {
            "bundle": b"bundle bytes",
            "wheel": b"wheel bytes",
            "sdist": b"sdist bytes",
        }
        for kind in ("wheel", "sdist"):
            (self.distributions / self.names[kind]).write_bytes(self.payloads[kind])
            (self.assets / self.names[kind]).write_bytes(self.payloads[kind])
        (self.assets / self.names["bundle"]).write_bytes(self.payloads["bundle"])
        bundle_digest = hashlib.sha256(self.payloads["bundle"]).hexdigest()
        (self.assets / f"{self.names['bundle']}.sha256").write_text(
            f"{bundle_digest}  {self.names['bundle']}\n", encoding="ascii"
        )
        artifacts = [
            {
                "kind": kind,
                "name": self.names[kind],
                "sha256": hashlib.sha256(self.payloads[kind]).hexdigest(),
            }
            for kind in ("bundle", "wheel", "sdist")
        ]
        self.digest = hashlib.sha256(
            json.dumps(
                {"schemaVersion": 1, "artifacts": artifacts},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()

    def verify(self):
        return verifier.verify_release_artifacts(
            version=self.VERSION,
            expected_digest=self.digest,
            distributions=self.distributions,
            release_assets=self.assets,
        )

    def test_exact_release_set_sidecar_and_distribution_copies_pass(self) -> None:
        result = self.verify()
        self.assertEqual(result["sha256"], self.digest)
        self.assertEqual(
            [artifact["kind"] for artifact in result["artifacts"]],
            ["bundle", "wheel", "sdist"],
        )

    def test_inventory_copy_sidecar_and_digest_mismatches_fail_closed(self) -> None:
        (self.assets / "unexpected.txt").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(verifier.ReleaseArtifactError, "wrong exact inventory"):
            self.verify()
        (self.assets / "unexpected.txt").unlink()

        wheel = self.assets / self.names["wheel"]
        wheel.write_bytes(b"different wheel")
        with self.assertRaisesRegex(verifier.ReleaseArtifactError, "wheel does not match"):
            self.verify()
        wheel.write_bytes(self.payloads["wheel"])

        sidecar = self.assets / f"{self.names['bundle']}.sha256"
        sidecar.write_text("0" * 64 + "  wrong.tar.gz\n", encoding="ascii")
        with self.assertRaisesRegex(verifier.ReleaseArtifactError, "checksum sidecar"):
            self.verify()

        bundle_digest = hashlib.sha256(self.payloads["bundle"]).hexdigest()
        sidecar.write_text(
            f"{bundle_digest}  {self.names['bundle']}\n", encoding="ascii"
        )
        with self.assertRaisesRegex(verifier.ReleaseArtifactError, "does not match approved"):
            verifier.verify_release_artifacts(
                version=self.VERSION,
                expected_digest="0" * 64,
                distributions=self.distributions,
                release_assets=self.assets,
            )


if __name__ == "__main__":
    unittest.main()
