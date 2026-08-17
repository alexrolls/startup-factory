#!/usr/bin/env python3
"""Offline adversarial tests for the untrusted evidence provider boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from evidence_provider import (  # noqa: E402
    REQUIRED_REDACTIONS,
    EvidenceValidationError,
    validate_and_index,
    validate_manifest,
)


def png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff"))
        + chunk(b"IEND", b"")
    )


class EvidenceFixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.manifest_path = self.root / "manifest.json"
        self.expected_path = self.root / "expected.json"
        content = png()
        (self.artifacts / "journey.png").write_bytes(content)
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        self.manifest = {
            "schemaVersion": 1,
            "provider": {
                "id": "startup-factory.playwright",
                "version": "0.1.0",
                "executableSha256": "sha256:" + "a" * 64,
            },
            "subject": {"taskId": "TASK-1", "attempt": 1, "commit": "b" * 40},
            "capability": "browser-qa",
            "invocation": {
                "sanitizedArgv": [
                    "--journey",
                    "<journey-json>",
                    "--manifest",
                    "<manifest-json>",
                    "--artifacts",
                    "<artifact-directory>",
                    "--project-root",
                    "<project-root>",
                ],
                "environmentNames": ["LANG", "LC_ALL", "TZ"],
                "startedAt": "2026-08-17T10:00:00Z",
                "finishedAt": "2026-08-17T10:00:02Z",
            },
            "target": {
                "origin": "https://example.test",
                "allowedOrigins": ["https://api.example.test", "https://example.test"],
            },
            "status": "passed",
            "assertions": [
                {
                    "id": "checkout@desktop",
                    "acceptanceCriterion": "AC-1 checkout completes",
                    "entryPath": "/checkout",
                    "status": "passed",
                    "behavioral": {
                        "status": "passed",
                        "checks": [{"id": "confirmation", "type": "visible", "status": "passed"}],
                    },
                    "precondition": {
                        "status": "passed",
                        "checks": [{"id": "invalid-card", "type": "rejected", "status": "passed"}],
                    },
                    "consoleErrors": [],
                    "failedRequests": [],
                    "accessibilityViolations": [],
                    "artifactIds": ["checkout.desktop.behavioral"],
                }
            ],
            "artifacts": [
                {
                    "id": "checkout.desktop.behavioral",
                    "assertionId": "checkout@desktop",
                    "kind": "screenshot",
                    "viewport": "desktop",
                    "phase": "behavioral",
                    "path": "journey.png",
                    "mimeType": "image/png",
                    "sizeBytes": len(content),
                    "sha256": digest,
                }
            ],
            "redactions": copy.deepcopy(REQUIRED_REDACTIONS),
        }
        self.write()

    @property
    def expected(self):
        return {
            key: copy.deepcopy(self.manifest[key])
            for key in ("provider", "subject", "capability", "target")
        }

    def write(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.expected_path.write_text(json.dumps(self.expected), encoding="utf-8")

    def validate(self):
        self.write()
        return validate_and_index(self.manifest_path, self.artifacts, self.expected)

    def close(self):
        self.temporary.cleanup()


class EvidenceProviderTests(unittest.TestCase):
    def setUp(self):
        self.fixture = EvidenceFixture()

    def tearDown(self):
        self.fixture.close()

    def test_valid_manifest_is_indexed_but_never_authoritative(self):
        result = self.fixture.validate()
        self.assertTrue(result["manifestValid"])
        self.assertTrue(result["untrusted"])
        self.assertFalse(result["authoritative"])
        self.assertEqual(["checkout@desktop"], list(result["assertionIndex"]))
        self.assertEqual(["checkout.desktop.behavioral"], list(result["artifactIndex"]))
        for field in ("manifestSha256", "artifactSetSha256", "indexSha256"):
            self.assertRegex(result[field], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(result, self.fixture.validate())

    def test_index_digests_bind_manifest_bytes_and_artifact_set(self):
        first = self.fixture.validate()
        self.fixture.manifest_path.write_text(
            json.dumps(self.fixture.manifest, indent=2) + "\n", encoding="utf-8"
        )
        second = validate_and_index(
            self.fixture.manifest_path, self.fixture.artifacts, self.fixture.expected
        )
        self.assertNotEqual(first["manifestSha256"], second["manifestSha256"])
        self.assertEqual(first["artifactSetSha256"], second["artifactSetSha256"])
        self.assertNotEqual(first["indexSha256"], second["indexSha256"])

    def test_duplicate_and_extra_keys_are_rejected_at_every_depth(self):
        raw = self.fixture.manifest_path.read_text(encoding="utf-8")
        self.fixture.manifest_path.write_text(
            raw.replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1', 1),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(EvidenceValidationError, "duplicate JSON key"):
            validate_manifest(self.fixture.manifest_path, self.fixture.artifacts, self.fixture.expected)
        self.fixture.manifest["assertions"][0]["viewport"] = "desktop"
        with self.assertRaisesRegex(EvidenceValidationError, "extra viewport"):
            self.fixture.validate()
        self.fixture = self._replace_fixture()
        assertion = self.fixture.manifest["assertions"][0]
        assertion["negativeControl"] = assertion.pop("precondition")
        with self.assertRaisesRegex(EvidenceValidationError, "negativeControl|precondition"):
            self.fixture.validate()

    def test_expected_binding_is_mandatory_and_exact(self):
        for key in ("provider", "subject", "capability", "target"):
            with self.subTest(key=key):
                expected = self.fixture.expected
                if isinstance(expected[key], dict):
                    expected[key] = {**expected[key], next(iter(expected[key])): "wrong"}
                else:
                    expected[key] = "wrong"
                with self.assertRaisesRegex(EvidenceValidationError, "expected binding"):
                    validate_manifest(self.fixture.manifest_path, self.fixture.artifacts, expected)

    def test_screenshot_only_or_errorful_success_is_rejected(self):
        self.fixture.manifest["assertions"][0]["behavioral"]["checks"] = []
        with self.assertRaisesRegex(EvidenceValidationError, "executable checks"):
            self.fixture.validate()
        self.fixture = self._replace_fixture()
        self.fixture.manifest["assertions"][0]["consoleErrors"] = [
            {
                "phase": "behavioral",
                "type": "error",
                "messageSha256": "sha256:" + "c" * 64,
                "urlPath": "/checkout",
            }
        ]
        with self.assertRaisesRegex(EvidenceValidationError, "browser errors"):
            self.fixture.validate()

    def test_sanitized_argv_is_an_exact_secret_free_sequence(self):
        allowed_suffixes = (
            ["--allow-private-origins"],
            ["--allow-public-origins"],
            ["--allow-private-origins", "--allow-public-origins"],
        )
        base = list(self.fixture.manifest["invocation"]["sanitizedArgv"])
        for suffix in allowed_suffixes:
            with self.subTest(suffix=suffix):
                self.fixture = self._replace_fixture()
                self.fixture.manifest["invocation"]["sanitizedArgv"] = base + suffix
                self.fixture.validate()
        hostile = (
            [*base, "--token=secret"],
            [*base, "--allow-public-origins", "--allow-private-origins"],
            [*base, "--allow-public-origins", "--allow-public-origins"],
            ["--journey", "/private/path", *base[2:]],
        )
        for argv in hostile:
            with self.subTest(argv=argv):
                self.fixture = self._replace_fixture()
                self.fixture.manifest["invocation"]["sanitizedArgv"] = argv
                with self.assertRaisesRegex(EvidenceValidationError, "placeholder sequence"):
                    self.fixture.validate()
    def _replace_fixture(self):
        self.fixture.close()
        return EvidenceFixture()

    def test_ids_and_cross_references_are_strict(self):
        self.fixture.manifest["assertions"][0]["artifactIds"] = ["missing"]
        with self.assertRaisesRegex(EvidenceValidationError, "unknown artifact"):
            self.fixture.validate()
        self.fixture = self._replace_fixture()
        duplicate = copy.deepcopy(self.fixture.manifest["assertions"][0])
        self.fixture.manifest["assertions"].append(duplicate)
        with self.assertRaisesRegex(EvidenceValidationError, "duplicate IDs"):
            self.fixture.validate()

    def test_artifact_hash_size_media_and_path_are_verified(self):
        mutations = ("hash", "size", "media", "path")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.fixture = self._replace_fixture()
                artifact = self.fixture.manifest["artifacts"][0]
                if mutation == "hash":
                    artifact["sha256"] = "sha256:" + "d" * 64
                    pattern = "hash does not match"
                elif mutation == "size":
                    artifact["sizeBytes"] += 1
                    pattern = "size does not match"
                elif mutation == "media":
                    content = b"not actually png"
                    (self.fixture.artifacts / "journey.png").write_bytes(content)
                    artifact["sizeBytes"] = len(content)
                    artifact["sha256"] = "sha256:" + hashlib.sha256(content).hexdigest()
                    pattern = "not PNG media"
                else:
                    artifact["path"] = "../journey.png"
                    pattern = "safe basename"
                with self.assertRaisesRegex(EvidenceValidationError, pattern):
                    self.fixture.validate()

    def test_symlink_artifacts_and_roots_are_rejected(self):
        outside = self.fixture.root / "outside.png"
        outside.write_bytes(png())
        (self.fixture.artifacts / "journey.png").unlink()
        os.symlink(outside, self.fixture.artifacts / "journey.png")
        with self.assertRaises(EvidenceValidationError):
            self.fixture.validate()
        self.fixture = self._replace_fixture()
        linked_root = self.fixture.root / "linked-artifacts"
        os.symlink(self.fixture.artifacts, linked_root)
        with self.assertRaisesRegex(EvidenceValidationError, "artifact root"):
            validate_manifest(self.fixture.manifest_path, linked_root, self.fixture.expected)

    def test_hardlinked_manifests_and_artifacts_are_rejected(self):
        os.link(
            self.fixture.artifacts / "journey.png",
            self.fixture.artifacts / "hardlink.png",
        )
        with self.assertRaisesRegex(EvidenceValidationError, "hard-linked"):
            self.fixture.validate()
        self.fixture = self._replace_fixture()
        os.link(self.fixture.manifest_path, self.fixture.root / "manifest-copy.json")
        with self.assertRaisesRegex(EvidenceValidationError, "hard-linked"):
            validate_manifest(
                self.fixture.manifest_path, self.fixture.artifacts, self.fixture.expected
            )

    def test_status_origin_path_invocation_and_redaction_semantics(self):
        mutations = (
            ("status", lambda m: m.update(status="failed"), "failed without"),
            ("origin", lambda m: m["target"].update(origin="https://Example.test"), "canonical"),
            ("path", lambda m: m["assertions"][0].update(entryPath="/checkout?secret=x"), "origin-free"),
            (
                "time",
                lambda m: m["invocation"].update(finishedAt="2026-08-17T09:59:59Z"),
                "precedes",
            ),
            ("redaction", lambda m: m["redactions"].pop(), "required protections"),
        )
        for name, mutate, pattern in mutations:
            with self.subTest(name=name):
                self.fixture = self._replace_fixture()
                mutate(self.fixture.manifest)
                with self.assertRaisesRegex(EvidenceValidationError, pattern):
                    self.fixture.validate()

    def test_cli_validate_uses_duplicate_free_expected_binding(self):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "bin" / "evidence_provider.py"),
                "validate",
                "--manifest",
                str(self.fixture.manifest_path),
                "--artifact-root",
                str(self.fixture.artifacts),
                "--expected-binding",
                str(self.fixture.expected_path),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["manifestValid"])
        self.assertFalse(payload["authoritative"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
