#!/usr/bin/env python3
"""Offline tests for deployment-bound live-probe transcript evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from live_probe_evidence import (  # noqa: E402
    MAX_ARTIFACT_BYTES,
    MAX_MANIFEST_BYTES,
    REQUIRED_REDACTIONS,
    EvidenceValidationError,
    validate_and_index,
)


class Fixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.manifest_path = self.root / "manifest.json"
        self.expected_path = self.root / "expected.json"
        self.expected = {
            "provider": {
                "id": "startup-factory.live-probe", "version": "0.1.0",
                "procedureSha256": "sha256:" + "a" * 64,
            },
            "subject": {"taskId": "TASK-1", "attempt": 1, "commit": "b" * 40},
            "capability": "live-probe",
            "target": {"origin": "https://preview.example.test", "deploymentId": "preview-42"},
            "requiredProbes": [{
                "id": "search.de-DE.empty", "acceptanceCriterionId": "AC-1",
                "entryPath": "/search", "locale": "de-DE", "variantId": "empty-state",
                "preconditionCheckIds": ["empty-catalog"],
                "behavioralCheckIds": ["empty-response"],
            }],
        }
        self.manifest = {
            key: copy.deepcopy(self.expected[key])
            for key in ("provider", "subject", "capability", "target")
        } | {
            "schemaVersion": 1,
            "collection": {
                "method": "operator", "engine": None,
                "startedAt": "2026-10-25T10:00:00Z", "finishedAt": "2026-10-25T10:00:10Z",
            },
            "status": "passed",
            "probes": [{
                key: copy.deepcopy(value)
                for key, value in self.expected["requiredProbes"][0].items()
                if not key.endswith("CheckIds")
            } | {
                "startedAt": "2026-10-25T10:00:01Z", "finishedAt": "2026-10-25T10:00:09Z",
                "status": "passed",
                "precondition": {
                    "status": "passed",
                    "checks": [{"id": "empty-catalog", "status": "passed",
                                "observedAt": "2026-10-25T10:00:02Z", "artifactId": "baseline"}],
                },
                "behavioral": {
                    "status": "passed",
                    "checks": [{"id": "empty-response", "status": "passed",
                                "observedAt": "2026-10-25T10:00:05Z", "artifactId": "response"}],
                },
            }],
            "artifacts": [],
            "redactions": copy.deepcopy(REQUIRED_REDACTIONS),
        }
        for identifier, phase, content in (
            ("baseline", "precondition", b"Catalog state: zero items. Personal values: [MASKED].\n"),
            ("response", "behavioral", b"Entry path /search: the empty response is displayed in de-DE.\n"),
        ):
            filename = identifier + ".txt"
            (self.artifacts / filename).write_bytes(content)
            self.manifest["artifacts"].append({
                "id": identifier, "probeId": "search.de-DE.empty", "phase": phase,
                "kind": "transcript", "path": filename, "mimeType": "text/plain",
                "sizeBytes": len(content), "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
            })
        self.write()

    def write(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.expected_path.write_text(json.dumps(self.expected), encoding="utf-8")

    def validate(self):
        self.write()
        return validate_and_index(self.manifest_path, self.artifacts, self.expected)

    def cli(self):
        return subprocess.run(
            [sys.executable, str(ROOT / "bin" / "live_probe_evidence.py"), "validate",
             "--manifest", str(self.manifest_path), "--artifact-root", str(self.artifacts),
             "--expected-binding", str(self.expected_path)],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def close(self):
        self.temporary.cleanup()


class LiveProbeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def tearDown(self):
        self.fixture.close()

    def reset(self):
        self.fixture.close()
        self.fixture = Fixture()

    def test_index_binds_evidence_expectations_and_never_grants_authority(self):
        result = self.fixture.validate()
        self.assertTrue(result["manifestValid"])
        self.assertTrue(result["untrusted"])
        self.assertFalse(result["authoritative"])
        self.assertEqual(["search.de-DE.empty"], list(result["probeIndex"]))
        self.assertEqual(["baseline", "response"], list(result["artifactIndex"]))
        self.assertEqual(result, self.fixture.validate())
        for key in ("manifestSha256", "expectedBindingSha256", "artifactSetSha256", "indexSha256"):
            self.assertRegex(result[key], r"^sha256:[0-9a-f]{64}$")
        self.fixture.manifest_path.write_text(json.dumps(self.fixture.manifest, indent=2))
        reformatted = validate_and_index(self.fixture.manifest_path, self.fixture.artifacts, self.fixture.expected)
        self.assertNotEqual(result["manifestSha256"], reformatted["manifestSha256"])
        self.assertNotEqual(result["indexSha256"], reformatted["indexSha256"])
        self.assertEqual(result["artifactSetSha256"], reformatted["artifactSetSha256"])

    def test_stale_commit_deployment_origin_and_procedure_are_rejected(self):
        for field, key, stale in (
            ("subject", "commit", "c" * 40), ("subject", "attempt", 2),
            ("target", "deploymentId", "old-preview"),
            ("target", "origin", "https://other.example.test"),
            ("provider", "procedureSha256", "sha256:" + "d" * 64),
        ):
            with self.subTest(field=field, key=key):
                self.reset()
                self.fixture.manifest[field][key] = stale
                with self.assertRaisesRegex(EvidenceValidationError, "expected binding"):
                    self.fixture.validate()

    def test_expected_binding_controls_probe_acceptance_variant_locale_and_entry_path(self):
        for key, value in (
            ("id", "different-probe"), ("acceptanceCriterionId", "AC-other"),
            ("entryPath", "/internal-debug"), ("locale", "en-US"), ("variantId", "other-variant"),
        ):
            with self.subTest(key=key):
                self.reset()
                self.fixture.manifest["probes"][0][key] = value
                with self.assertRaisesRegex(EvidenceValidationError, "expected binding"):
                    self.fixture.validate()
        self.reset()
        self.fixture.expected["requiredProbes"].append({
            **copy.deepcopy(self.fixture.expected["requiredProbes"][0]), "id": "required-second-probe",
        })
        with self.assertRaisesRegex(EvidenceValidationError, "probe IDs.*expected binding"):
            self.fixture.validate()

    def test_required_check_coverage_cannot_be_selected_by_evidence(self):
        for mutate in (
            lambda probe: probe["behavioral"].update(checks=[]),
            lambda probe: probe["behavioral"]["checks"][0].update(id="easy-check"),
            lambda probe: probe["precondition"].update(checks=[]),
        ):
            self.reset()
            mutate(self.fixture.manifest["probes"][0])
            with self.assertRaisesRegex(EvidenceValidationError, "check IDs.*expected binding"):
                self.fixture.validate()

    def test_failure_is_valid_diagnostic_evidence_but_cannot_aggregate_to_passed(self):
        probe = self.fixture.manifest["probes"][0]
        probe["behavioral"]["checks"][0]["status"] = "failed"
        with self.assertRaisesRegex(EvidenceValidationError, "status aggregate"):
            self.fixture.validate()
        probe["behavioral"]["status"] = "failed"
        probe["status"] = "failed"
        self.fixture.manifest["status"] = "failed"
        result = self.fixture.validate()
        self.assertEqual("failed", result["status"])
        self.assertFalse(result["authoritative"])

    def test_errors_are_explicit_and_aggregate_above_failed(self):
        probe = self.fixture.manifest["probes"][0]
        probe["precondition"]["checks"][0]["status"] = "failed"
        probe["precondition"]["status"] = "failed"
        probe["behavioral"]["checks"][0].update(status="error", artifactId=None)
        probe["behavioral"]["status"] = "error"
        probe["status"] = "error"
        self.fixture.manifest["status"] = "error"
        self.fixture.manifest["artifacts"].pop()
        self.assertEqual("error", self.fixture.validate()["status"])
        self.fixture.manifest["status"] = "failed"
        with self.assertRaisesRegex(EvidenceValidationError, "status aggregate"):
            self.fixture.validate()

    def test_behavior_requires_successful_preconditions_and_bound_transcripts(self):
        probe = self.fixture.manifest["probes"][0]
        probe["precondition"]["status"] = "failed"
        probe["precondition"]["checks"][0]["status"] = "failed"
        with self.assertRaisesRegex(EvidenceValidationError, "checked preconditions"):
            self.fixture.validate()
        self.reset()
        self.fixture.manifest["probes"][0]["behavioral"]["checks"][0]["artifactId"] = None
        with self.assertRaisesRegex(EvidenceValidationError, "requires a transcript"):
            self.fixture.validate()

    def test_statuses_must_be_known_and_consistent_at_every_level(self):
        for path in ("top", "probe", "group", "check"):
            with self.subTest(path=path):
                self.reset()
                probe = self.fixture.manifest["probes"][0]
                target = {
                    "top": self.fixture.manifest, "probe": probe,
                    "group": probe["behavioral"], "check": probe["behavioral"]["checks"][0],
                }[path]
                for status in ("success", True, {}, "error"):
                    target["status"] = status
                    if path == "check" and status == "error":
                        pattern = "status aggregate"
                    else:
                        pattern = "unsupported value|status aggregate"
                    with self.assertRaisesRegex(EvidenceValidationError, pattern):
                        self.fixture.validate()

    def test_duplicate_ids_and_unknown_fields_are_rejected(self):
        for field in ("probes", "artifacts"):
            self.reset()
            self.fixture.manifest[field].append(copy.deepcopy(self.fixture.manifest[field][0]))
            with self.assertRaisesRegex(EvidenceValidationError, "duplicate IDs"):
                self.fixture.validate()
        self.reset()
        self.fixture.manifest["probes"][0]["behavioral"]["checks"].append(
            copy.deepcopy(self.fixture.manifest["probes"][0]["behavioral"]["checks"][0])
        )
        with self.assertRaisesRegex(EvidenceValidationError, "duplicate check IDs"):
            self.fixture.validate()
        self.reset()
        self.fixture.manifest["collection"]["token"] = "not-allowed"
        with self.assertRaisesRegex(EvidenceValidationError, "invalid fields"):
            self.fixture.validate()

    def test_json_duplicate_keys_fail_in_manifest_and_expected_binding(self):
        for path in (self.fixture.manifest_path, self.fixture.expected_path):
            with self.subTest(path=path.name):
                self.fixture.write()
                raw = path.read_text()
                path.write_text(raw.replace('"attempt": 1', '"attempt": 1, "attempt": 1', 1))
                completed = self.fixture.cli()
                self.assertEqual(2, completed.returncode)
                self.assertIn("duplicate JSON key", completed.stderr)
                self.assertEqual("", completed.stdout)

    def test_expected_contract_is_itself_strict(self):
        for mutate in (
            lambda e: e.update(extra=True),
            lambda e: e.update(requiredProbes=[]),
            lambda e: e["requiredProbes"][0].update(behavioralCheckIds=[]),
            lambda e: e["requiredProbes"][0].update(behavioralCheckIds=["z", "a"]),
            lambda e: e["requiredProbes"].append(copy.deepcopy(e["requiredProbes"][0])),
        ):
            self.reset()
            mutate(self.fixture.expected)
            with self.assertRaises(EvidenceValidationError):
                self.fixture.validate()

    def test_manifest_types_cannot_exploit_binding_equality(self):
        self.fixture.manifest["subject"]["attempt"] = True
        with self.assertRaisesRegex(EvidenceValidationError, "integer in range"):
            self.fixture.validate()

    def test_task_ids_support_markdown_tracker_paths_without_controls(self):
        for task_id in ("feat/search.md#1", "feat/search experience.md#12"):
            self.fixture.expected["subject"]["taskId"] = task_id
            self.fixture.manifest["subject"]["taskId"] = task_id
            self.assertEqual(task_id, self.fixture.validate()["subject"]["taskId"])
        for task_id in ("bad\nidentifier", "x" * 257, ""):
            self.fixture.expected["subject"]["taskId"] = task_id
            self.fixture.manifest["subject"]["taskId"] = task_id
            with self.assertRaises(EvidenceValidationError):
                self.fixture.validate()

    def test_timestamps_are_real_ordered_and_contained(self):
        for mutate in (
            lambda m: m["collection"].update(finishedAt="2026-10-25T09:00:00Z"),
            lambda m: m["probes"][0].update(startedAt="2026-10-24T10:00:00Z"),
            lambda m: m["probes"][0]["behavioral"]["checks"][0].update(observedAt="2026-10-25T10:01:00Z"),
            lambda m: m["probes"][0]["precondition"]["checks"][0].update(observedAt="2026-10-25T10:00:06Z"),
            lambda m: m["collection"].update(startedAt="2026-02-30T10:00:00Z"),
        ):
            self.reset()
            mutate(self.fixture.manifest)
            with self.assertRaises(EvidenceValidationError):
                self.fixture.validate()

    def test_engine_metadata_is_optional_and_has_only_nonsecret_identifier_fields(self):
        self.fixture.manifest["collection"]["engine"] = {"id": "example-engine", "version": "1.2.3", "modelId": "example-model"}
        self.fixture.validate()
        self.fixture.manifest["collection"]["engine"]["apiKey"] = "forbidden"
        with self.assertRaisesRegex(EvidenceValidationError, "invalid fields"):
            self.fixture.validate()
        self.fixture.manifest["collection"]["engine"] = {"id": "engine", "version": "1.0", "modelId": "model?token=value"}
        with self.assertRaisesRegex(EvidenceValidationError, "safe identifier"):
            self.fixture.validate()

    def test_hash_size_path_and_artifact_type_are_verified(self):
        for field, value, pattern in (
            ("sha256", "sha256:" + "d" * 64, "hash does not match"),
            ("sizeBytes", 1, "size does not match"),
            ("sizeBytes", MAX_ARTIFACT_BYTES + 1, "integer in range"),
            ("path", "../baseline.txt", "safe .txt basename"),
            ("path", "/baseline.txt", "safe .txt basename"),
            ("path", "baseline\\other.txt", "safe .txt basename"),
            ("mimeType", "text/html", "plain-text transcript"),
            ("kind", "command", "plain-text transcript"),
        ):
            with self.subTest(field=field, value=value):
                self.reset()
                self.fixture.manifest["artifacts"][0][field] = value
                with self.assertRaisesRegex(EvidenceValidationError, pattern):
                    self.fixture.validate()

    def test_transcripts_are_bounded_utf8_without_terminal_or_direction_controls(self):
        for content in (b"\xff", b"\x1b[31mtext\n", "text\u202esecret".encode(), b"\n \n", b"x" * (MAX_ARTIFACT_BYTES + 1)):
            self.reset()
            (self.fixture.artifacts / "baseline.txt").write_bytes(content)
            artifact = self.fixture.manifest["artifacts"][0]
            artifact["sizeBytes"] = min(len(content), MAX_ARTIFACT_BYTES)
            artifact["sha256"] = "sha256:" + hashlib.sha256(content).hexdigest()
            with self.assertRaises(EvidenceValidationError):
                self.fixture.validate()

    def test_artifacts_cannot_be_rebound_or_left_unreferenced(self):
        for mutate in (
            lambda m: m["artifacts"][1].update(phase="precondition"),
            lambda m: m["artifacts"][1].update(path="baseline.txt"),
            lambda m: m["probes"][0]["behavioral"]["checks"][0].update(artifactId="missing"),
        ):
            self.reset()
            mutate(self.fixture.manifest)
            with self.assertRaises(EvidenceValidationError):
                self.fixture.validate()
        self.reset()
        probe = self.fixture.manifest["probes"][0]
        probe["behavioral"]["checks"][0].update(status="error", artifactId=None)
        probe["behavioral"]["status"] = probe["status"] = self.fixture.manifest["status"] = "error"
        with self.assertRaisesRegex(EvidenceValidationError, "unreferenced"):
            self.fixture.validate()

    def test_symlink_root_manifest_binding_and_artifacts_are_rejected(self):
        for target in ("root", "manifest", "binding", "artifact"):
            with self.subTest(target=target):
                self.reset()
                path = {
                    "root": self.fixture.artifacts, "manifest": self.fixture.manifest_path,
                    "binding": self.fixture.expected_path, "artifact": self.fixture.artifacts / "baseline.txt",
                }[target]
                moved = path.with_name(path.name + ".real")
                path.rename(moved)
                os.symlink(moved, path)
                completed = self.fixture.cli()
                self.assertEqual(2, completed.returncode, completed.stdout)

    def test_hardlinks_and_oversized_manifests_are_rejected(self):
        for target in (self.fixture.manifest_path, self.fixture.artifacts / "baseline.txt"):
            os.link(target, target.with_name(target.name + ".copy"))
            completed = self.fixture.cli()
            self.assertEqual(2, completed.returncode)
            self.assertIn("hard-linked", completed.stderr)
            target.with_name(target.name + ".copy").unlink()
        self.fixture.manifest_path.write_bytes(b" " * (MAX_MANIFEST_BYTES + 1))
        completed = self.fixture.cli()
        self.assertEqual(2, completed.returncode)
        self.assertIn("size cap", completed.stderr)

    def test_count_caps_and_excessively_nested_json_fail_closed(self):
        for field, maximum in (("probes", 100), ("artifacts", 200)):
            self.reset()
            self.fixture.manifest[field] = [self.fixture.manifest[field][0]] * (maximum + 1)
            with self.assertRaisesRegex(EvidenceValidationError, "item cap"):
                self.fixture.validate()
        self.reset()
        group = self.fixture.manifest["probes"][0]["behavioral"]
        group["checks"] = [group["checks"][0]] * 51
        with self.assertRaisesRegex(EvidenceValidationError, "item cap"):
            self.fixture.validate()
        self.fixture.manifest_path.write_text("[" * 2_000 + "]" * 2_000)
        completed = self.fixture.cli()
        self.assertEqual(2, completed.returncode)
        self.assertIn("nesting cap", completed.stderr)

    def test_total_transcript_bytes_are_capped_across_valid_artifacts(self):
        prototype_required = copy.deepcopy(self.fixture.expected["requiredProbes"][0])
        prototype_probe = copy.deepcopy(self.fixture.manifest["probes"][0])
        prototype_artifact = copy.deepcopy(self.fixture.manifest["artifacts"][0])
        content = b"Sanitized observation.\n" * 11_000
        self.assertLess(len(content), MAX_ARTIFACT_BYTES)
        self.fixture.expected["requiredProbes"] = []
        self.fixture.manifest["probes"] = []
        self.fixture.manifest["artifacts"] = []
        for number in range(9):
            probe_id = "probe-%d" % number
            self.fixture.expected["requiredProbes"].append({**prototype_required, "id": probe_id})
            probe = copy.deepcopy(prototype_probe)
            probe["id"] = probe_id
            for phase in ("precondition", "behavioral"):
                artifact_id = probe_id + "." + phase
                probe[phase]["checks"][0]["artifactId"] = artifact_id
                filename = artifact_id + ".txt"
                (self.fixture.artifacts / filename).write_bytes(content)
                self.fixture.manifest["artifacts"].append({
                    **prototype_artifact, "id": artifact_id, "probeId": probe_id,
                    "phase": phase, "path": filename, "sizeBytes": len(content),
                    "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
                })
            self.fixture.manifest["probes"].append(probe)
        with self.assertRaisesRegex(EvidenceValidationError, "total size cap"):
            self.fixture.validate()

    def test_redaction_declarations_are_exact_and_cli_success_remains_untrusted(self):
        completed = self.fixture.cli()
        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(1, result["probeCount"])
        self.assertFalse(result["authoritative"])
        self.fixture.manifest["redactions"].pop()
        with self.assertRaisesRegex(EvidenceValidationError, "required protections"):
            self.fixture.validate()


if __name__ == "__main__":
    unittest.main(verbosity=2)
