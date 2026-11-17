#!/usr/bin/env python3
"""Host admission fixtures; run only in the assigned isolated test runner.

These tests exercise the existing broker's real signing/admission/revocation
functions against dummy state. Only Git path discovery is replaced; no Git,
tracker, network, Docker runtime, credentials, or subprocess is used.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
import outbox_capability as capability  # noqa: E402
from sandbox_ingest import (  # noqa: E402
    ArtifactAdmission,
    BoundContext,
    IngestError,
    MAX_BODY_BYTES,
    parse_request,
    recover_exact_admission,
)


class SandboxIngestTest(unittest.TestCase):
    def setUp(self) -> None:
        # AF_UNIX locators must stay short independently of the checkout and
        # TMPDIR lengths. HOME is a protected account directory; the fixture
        # itself remains owner-only and production path checks stay enabled.
        self.temporary = tempfile.TemporaryDirectory(prefix="sf-ingest-",
            dir=os.environ.get("SF_REGISTRY_TEST_ROOT", str(Path.home())))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.repo = self.root / "r"
        self.repo.mkdir(mode=0o700)
        self.common = self.repo / ".git"
        self.common.mkdir(mode=0o700)
        self.workspace = self.repo / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.protected = self.root / "journal"
        self.repo_patch = mock.patch.object(capability, "_repo", return_value=self.repo)
        self.common_patch = mock.patch.object(capability, "git_common_dir", return_value=self.common)
        self.repo_patch.start()
        self.common_patch.start()
        self.addCleanup(self.repo_patch.stop)
        self.addCleanup(self.common_patch.stop)
        self.capability = capability.mint(
            str(self.repo), str(self.workspace), "team-one", "FEATURE-1",
            "developer", "task", "TASK-1", 1, "task:TASK-1",
        )
        leaf = hashlib.sha256((str(self.repo) + "\0" + self.capability["id"]).encode()).hexdigest()[:32]
        self.context = BoundContext(
            repository=self.repo, workspace=self.workspace, team="team-one",
            feature="FEATURE-1", role="developer", task="TASK-1", attempt=1,
            generation="generation-1", transport=str(self.root / "p" / leaf),
        )
        self.active = True
        self.calls: list[dict] = []

    def request(self, *, identifier: str = "a" * 32, body: bytes = b"[task-complete]\nfixture body\n", marker: str = "task-complete", target: str | None = None) -> dict:
        return {"schemaVersion": 1, "id": identifier, "operation": "artifact.submit", "marker": marker, "bodyHex": body.hex(), "targetStatus": target}

    def authorize(self, context: BoundContext, request: dict) -> bool:
        return self.active and context == self.context and request["marker"] == "task-complete" and request["targetStatus"] is None

    def signer(self, transport: str, entry: dict, body: bytes) -> dict:
        self.assertEqual(transport, self.context.transport)
        records = list(self.protected.glob("*/*.json"))
        matches = [json.loads(path.read_text()) for path in records if json.loads(path.read_text())["entry"]["id"] == entry["id"]]
        self.assertEqual(len(matches), 1, "stable journal must precede signing")
        stored = matches[0]
        self.assertEqual(stored["state"], "prepared")
        self.assertIsNone(stored["producerCapability"])
        self.assertEqual(stored["entry"], entry)
        self.calls.append(dict(entry))
        return capability.sign_active_entry(str(self.repo), str(self.workspace), self.capability["id"], entry, body)

    def admission(self, **arguments) -> ArtifactAdmission:
        result = ArtifactAdmission(self.context, self.protected, authorize=self.authorize, signer=self.signer, **arguments)
        self.addCleanup(result.close)
        return result

    def journal(self) -> tuple[Path, dict]:
        paths = list(self.protected.glob("*/*.json"))
        self.assertEqual(len(paths), 1)
        return paths[0], json.loads(paths[0].read_text())

    def revoke(self) -> None:
        self.active = False
        capability.revoke_exact(str(self.repo), str(self.workspace), self.capability["id"])

    def test_request_uses_only_host_bound_identity_and_standard_outbox_envelope(self) -> None:
        ingest = self.admission()
        receipt = ingest.submit(json.dumps(self.request()).encode())
        self.assertEqual(set(receipt), {"schemaVersion", "id", "operation", "entryId", "status"})
        self.assertEqual(receipt["status"], "admitted")
        path = self.workspace / "outbox/pending" / (receipt["entryId"] + ".json")
        package = json.loads(path.read_text())
        self.assertEqual(set(package), capability.OUTBOX_PRODUCER_FIELDS | {"producerCapability"})
        self.assertEqual(package["actor"], self.context.role)
        self.assertEqual(package["taskId"], self.context.task)
        self.assertEqual(package["attempt"], self.context.attempt)
        self.assertEqual(package["bodyPath"], str(self.workspace / "outbox/bodies" / (receipt["entryId"] + ".md")))
        body = Path(package["bodyPath"]).read_bytes()
        verified = capability.verify_entry(str(self.repo), str(self.workspace), package, "sha256:" + hashlib.sha256(body).hexdigest())
        self.assertEqual(verified["role"], "developer")
        self.assertFalse(verified["admissionRecovery"])
        self.assertNotIn(self.capability["secret"], json.dumps(receipt))
        self.assertNotIn(str(self.root), json.dumps(receipt))
        for name in ("outbox", "outbox/pending", "outbox/bodies"):
            self.assertEqual((self.workspace / name).stat().st_mode & 0o777, 0o700)

    def test_duplicate_returns_same_receipt_without_signing_or_requeueing(self) -> None:
        ingest = self.admission()
        first = ingest.submit(self.request())
        self.revoke()
        # Model a broker that already consumed the canonical producer entry.
        pending = self.workspace / "outbox/pending" / (first["entryId"] + ".json")
        pending.unlink()
        second = ingest.submit(self.request())
        self.assertEqual(first, second)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(pending.exists(), "queued retries must not recreate consumed packages")

    def test_reused_request_id_with_changed_payload_is_denied(self) -> None:
        ingest = self.admission()
        ingest.submit(self.request())
        with self.assertRaisesRegex(IngestError, "^artifact admission denied$"):
            ingest.submit(self.request(body=b"[task-complete]\nchanged\n"))
        self.assertEqual(len(self.calls), 1)

    def test_lost_signer_response_recovers_exact_admission_after_revocation(self) -> None:
        def response_lost(transport: str, entry: dict, body: bytes) -> dict:
            self.signer(transport, entry, body)
            raise ConnectionError("test-only lost native supervisor response")

        ingest = ArtifactAdmission(self.context, self.protected, authorize=self.authorize, signer=response_lost)
        self.addCleanup(ingest.close)
        with self.assertRaises(IngestError):
            ingest.submit(self.request())
        _, before = self.journal()
        self.assertEqual(before["state"], "prepared")
        identifier = before["entry"]["id"]
        self.assertEqual(list((self.workspace / "outbox/pending").iterdir()), [])
        self.revoke()
        receipt = ingest.submit(self.request())
        self.assertEqual(receipt["entryId"], identifier)
        self.assertEqual(len(self.calls), 1, "recovery must never create another signature")
        pending = json.loads((self.workspace / "outbox/pending" / (identifier + ".json")).read_text())
        verification = capability.verify_entry(str(self.repo), str(self.workspace), pending, "sha256:" + hashlib.sha256(bytes.fromhex(self.request()["bodyHex"])).hexdigest())
        self.assertTrue(verification["admissionRecovery"])
        self.assertEqual(len(list(capability.admission_directory(self.repo).iterdir())), 1)

    def test_unadmitted_prepared_request_cannot_sign_after_revocation(self) -> None:
        def unavailable(_transport: str, _entry: dict, _body: bytes) -> dict:
            raise ConnectionError("not admitted")

        ingest = ArtifactAdmission(self.context, self.protected, authorize=self.authorize, signer=unavailable)
        self.addCleanup(ingest.close)
        with self.assertRaises(IngestError):
            ingest.submit(self.request())
        self.revoke()
        with self.assertRaises(IngestError):
            ingest.submit(self.request())
        self.assertEqual(self.calls, [])
        self.assertEqual(self.journal()[1]["state"], "prepared")

    def test_signed_journal_survives_queue_failure_and_revocation(self) -> None:
        ingest = self.admission()
        with mock.patch.object(ingest.pending, "ensure", side_effect=OSError("fixture full queue")):
            with self.assertRaises(IngestError):
                ingest.submit(self.request())
        _, before = self.journal()
        self.assertEqual(before["state"], "signed")
        self.revoke()
        receipt = ingest.submit(self.request())
        self.assertEqual(receipt["entryId"], before["entry"]["id"])
        self.assertEqual(self.journal()[1]["state"], "queued")
        self.assertEqual(len(self.calls), 1)

    def test_partial_queue_write_is_not_published_and_retry_keeps_identity(self) -> None:
        ingest = self.admission()
        original = ingest.pending._exclusive
        def interrupted_write(name: str, content: bytes) -> None:
            original(name, content[:10])
            raise OSError("fixture interrupted disk write")
        with mock.patch.object(ingest.pending, "_exclusive", side_effect=interrupted_write):
            with self.assertRaises(IngestError):
                ingest.submit(self.request())
        _, record = self.journal()
        identifier = record["entry"]["id"]
        self.assertEqual(list((self.workspace / "outbox/pending").iterdir()), [])
        self.revoke()
        receipt = ingest.submit(self.request())
        self.assertEqual(receipt["entryId"], identifier)
        package = json.loads((self.workspace / "outbox/pending" / (identifier + ".json")).read_text())
        self.assertEqual(package["id"], identifier)
        self.assertEqual(len(self.calls), 1)

    def test_fresh_unauthorized_or_wrong_marker_request_creates_no_journal(self) -> None:
        ingest = self.admission()
        self.active = False
        with self.assertRaises(IngestError):
            ingest.submit(self.request())
        self.active = True
        with self.assertRaises(IngestError):
            ingest.submit(self.request(marker="review-approved", body=b"[review-approved]\nno"))
        self.assertEqual(list(self.protected.glob("*/*.json")), [])
        self.assertEqual(self.calls, [])

    def test_host_authorizer_exception_and_mutation_cannot_leak_or_change_request(self) -> None:
        ingest = self.admission()
        def failing(_context: BoundContext, _request: dict) -> bool:
            raise Exception("PRIVATE fixture token and host path")
        ingest.authorize = failing
        with self.assertRaisesRegex(IngestError, "^artifact admission denied$"):
            ingest.submit(self.request())
        def modifying(_context: BoundContext, request: dict) -> bool:
            request["marker"] = "worker-control"
            request["bodyHex"] = b"[worker-control]".hex()
            return True
        ingest.authorize = modifying
        receipt = ingest.submit(self.request())
        package = json.loads((self.workspace / "outbox/pending" / (receipt["entryId"] + ".json")).read_text())
        self.assertEqual(package["marker"], "task-complete")

    def test_concurrent_identical_requests_share_one_signing_and_receipt(self) -> None:
        ingest = self.admission()
        other = self.admission()
        barrier = threading.Barrier(2)
        def submit(admission: ArtifactAdmission) -> dict:
            barrier.wait(timeout=2)
            return admission.submit(self.request())
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(submit, item) for item in (ingest, other)]
            results = [future.result(timeout=5) for future in futures]
        self.assertEqual(results[0], results[1])
        self.assertEqual(len(self.calls), 1)

    def test_durable_request_quota_survives_reconnect_and_allows_exact_retry(self) -> None:
        ingest = self.admission(max_requests=1)
        first = ingest.submit(self.request())
        ingest.close()
        reopened = self.admission(max_requests=1)
        with self.assertRaises(IngestError):
            reopened.submit(self.request(identifier="b" * 32))
        self.revoke()
        self.assertEqual(reopened.submit(self.request()), first)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(list(self.protected.glob("*/*.lock"))), 1)
        self.assertEqual(len(list(self.protected.glob("*/*.json"))), 1)

    def test_durable_aggregate_body_quota_counts_prepared_records(self) -> None:
        body = bytes.fromhex(self.request()["bodyHex"])
        def unavailable(_transport: str, _entry: dict, _body: bytes) -> dict:
            raise ConnectionError("fixture supervisor unavailable")
        ingest = ArtifactAdmission(self.context, self.protected, authorize=self.authorize, signer=unavailable, max_requests=2, max_total_body_bytes=len(body) + 1)
        self.addCleanup(ingest.close)
        with self.assertRaises(IngestError):
            ingest.submit(self.request())
        with self.assertRaises(IngestError):
            ingest.submit(self.request(identifier="b" * 32))
        self.assertEqual(len(list(self.protected.glob("*/*.json"))), 1)
        self.assertEqual(self.journal()[1]["state"], "prepared")

    def test_quota_policy_cannot_be_broadened_on_reopen(self) -> None:
        ingest = self.admission(max_requests=1)
        ingest.submit(self.request())
        reopened = self.admission(max_requests=2)
        with self.assertRaises(IngestError):
            reopened.submit(self.request(identifier="b" * 32))
        self.assertEqual(len(self.calls), 1)

    def test_interrupted_body_temporary_is_removed_before_exact_recovery(self) -> None:
        ingest = self.admission()
        with mock.patch.object(ingest.pending, "ensure", side_effect=OSError("pause after signed journal")):
            with self.assertRaises(IngestError):
                ingest.submit(self.request())
        _, record = self.journal()
        identifier = record["entry"]["id"]
        leftover = self.workspace / "outbox/pending" / ("." + identifier + ".json." + "1" * 32)
        leftover.write_bytes(b"partial")
        leftover.chmod(0o600)
        self.revoke()
        self.assertEqual(ingest.submit(self.request())["entryId"], identifier)
        self.assertFalse(leftover.exists())

    def test_exact_prepared_retry_reconciles_interrupted_journal_temporary(self) -> None:
        def unavailable(_transport: str, _entry: dict, _body: bytes) -> dict:
            raise ConnectionError("fixture supervisor unavailable")
        ingest = ArtifactAdmission(self.context, self.protected, authorize=self.authorize, signer=unavailable, max_requests=1)
        self.addCleanup(ingest.close)
        with self.assertRaises(IngestError):
            ingest.submit(self.request())
        path, record = self.journal()
        self.assertEqual(record["state"], "prepared")
        leftover = path.parent / ("." + path.name + "." + "1" * 32)
        leftover.write_bytes(b"partial journal")
        leftover.chmod(0o600)
        ingest.signer = self.signer
        receipt = ingest.submit(self.request())
        self.assertEqual(receipt["entryId"], record["entry"]["id"])
        self.assertFalse(leftover.exists())
        self.assertEqual(len(list(path.parent.glob("*.json"))), 1)
        self.assertEqual(len(self.calls), 1)

    def test_closed_schema_and_strict_json_reject_guest_authority(self) -> None:
        ingest = self.admission()
        invalid = [
            {**self.request(), "bodyPath": "/outside"},
            {**self.request(), "actor": "integrator"},
            {**self.request(), "producerCapability": {}},
            {**self.request(), "generation": "other"},
            {**self.request(), "schemaVersion": True},
            {**self.request(), "id": "../../outside"},
            {**self.request(), "operation": "control.propose"},
            {**self.request(), "bodyHex": "FF"},
            {**self.request(), "bodyHex": "aa bb"},
            {**self.request(), "bodyHex": "f"},
            {**self.request(), "bodyHex": b"[task-complete]\x00".hex()},
            {**self.request(), "bodyHex": b"[task-complete]\xff".hex()},
            {**self.request(), "bodyHex": b"[other]".hex()},
            {**self.request(), "targetStatus": "bad\nstatus"},
        ]
        raw = json.dumps(self.request()).encode()
        invalid.extend([raw[:-1] + b',"id":"' + b"b" * 32 + b'"}', b"[" * 100 + b"0" + b"]" * 100, b"\xff", b"{}", b'{"schemaVersion":NaN}'])
        for item in invalid:
            with self.subTest(item=str(item)[:100]):
                with self.assertRaisesRegex(IngestError, "^artifact admission denied$"):
                    ingest.submit(item)
        self.assertEqual(self.calls, [])

    def test_exact_maximum_body_and_uuid_request_id_are_accepted(self) -> None:
        prefix = b"[task-complete]\n"
        body = prefix + b"x" * (MAX_BODY_BYTES - len(prefix))
        valid = self.request(identifier="f7983a14-1ad3-44da-9d38-d54375256ba2", body=body)
        parsed, decoded = parse_request(json.dumps(valid).encode())
        self.assertEqual(parsed, valid)
        self.assertEqual(decoded, body)
        with self.assertRaises(IngestError):
            parse_request(self.request(body=body + b"x"))

    def test_changed_journal_identity_is_rejected(self) -> None:
        ingest = self.admission()
        ingest.submit(self.request())
        path, record = self.journal()
        record["entry"]["taskId"] = "OTHER-TASK"
        path.write_text(json.dumps(record))
        with self.assertRaises(IngestError):
            ingest.submit(self.request())
        self.assertEqual(len(self.calls), 1)

    def test_recovery_rejects_other_transport_and_changed_package(self) -> None:
        ingest = self.admission()
        ingest.submit(self.request())
        _, record = self.journal()
        body = bytes.fromhex(self.request()["bodyHex"])
        other = dataclasses.replace(self.context, transport=str(self.root / "p" / ("0" * 32)))
        with self.assertRaises(IngestError):
            recover_exact_admission(other, record["entry"], body)
        with self.assertRaises(IngestError):
            recover_exact_admission(self.context, {**record["entry"], "targetStatus": "Done"}, body)

    def test_protected_root_and_outbox_symlinks_and_permissions_are_rejected(self) -> None:
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        self.protected.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(IngestError):
            self.admission()
        self.protected.unlink()
        self.protected.mkdir(mode=0o755)
        self.protected.chmod(0o755)
        with self.assertRaises(IngestError):
            self.admission()
        self.protected.chmod(0o700)
        (self.workspace / "outbox").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(IngestError):
            self.admission()
        self.assertEqual(list(outside.iterdir()), [])

    def test_body_hardlink_and_pending_symlink_are_not_followed_or_overwritten(self) -> None:
        ingest = self.admission()
        with mock.patch.object(ingest.pending, "ensure", side_effect=OSError("pause after signed journal")):
            with self.assertRaises(IngestError):
                ingest.submit(self.request())
        _, record = self.journal()
        body = Path(record["entry"]["bodyPath"])
        outside = self.root / "outside-body"
        os.link(body, outside)
        with self.assertRaises(IngestError):
            ingest.submit(self.request())
        outside.unlink()
        pending = self.workspace / "outbox/pending" / (record["entry"]["id"] + ".json")
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"untouched")
        pending.symlink_to(sentinel)
        with self.assertRaises(IngestError):
            ingest.submit(self.request())
        self.assertEqual(sentinel.read_bytes(), b"untouched")
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
