#!/usr/bin/env python3
"""Unit tests for protected broker publication receipts."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

import broker_evidence  # noqa: E402
import outbox_capability  # noqa: E402


TEAM = "factory-one"
FEATURE = "FEATURE-1"
TASK = "TASK-1"


class BrokerEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(self.repository)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.workspace = self.repository / ".teamwork" / TEAM
        self.bodies = self.workspace / "outbox" / "bodies"
        self.pending = self.workspace / "outbox" / "pending"
        self.bodies.mkdir(parents=True)
        self.pending.mkdir(parents=True)
        self.deliveries = outbox_capability.delivery_directory(
            self.repository, self.workspace, TEAM, FEATURE
        )
        self.authority = self.root / "authority"
        self.authority.mkdir(mode=0o700)
        self.key = os.urandom(32)
        key_path = self.authority / "record-auth.key"
        key_path.write_bytes(self.key)
        key_path.chmod(0o600)
        self.environment = mock.patch.dict(
            os.environ,
            {"STARTUP_FACTORY_LIFECYCLE_STATE_ROOT": str(self.authority)},
            clear=False,
        )
        self.environment.start()
        self.counter = 0

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def make_entry(
        self,
        marker: str,
        *,
        kind: str | None = None,
        role: str | None = None,
        target_status: object = "default",
        binding: dict | None = None,
        expired: bool = False,
        final_body: bytes | None = None,
    ) -> tuple[Path, dict, str]:
        self.counter += 1
        delivery = "delivery-%032x" % self.counter
        request = marker == "review-request"
        kind = kind or ("task" if request else "gate")
        role = role or ("backend" if request else "principal-architect")
        target = ("Review" if request else None) if target_status == "default" else target_status
        capability_task = TASK if kind == "task" else "-"
        capability_attempt = 1 if kind == "task" else 0
        if expired:
            with mock.patch.object(outbox_capability.time, "time", return_value=1):
                capability = outbox_capability.mint(
                    str(self.repository),
                    str(self.workspace),
                    TEAM,
                    FEATURE,
                    role,
                    kind,
                    capability_task,
                    capability_attempt,
                    "%s-instance" % role,
                    60,
                )
        else:
            capability = outbox_capability.mint(
                str(self.repository),
                str(self.workspace),
                TEAM,
                FEATURE,
                role,
                kind,
                capability_task,
                capability_attempt,
                "%s-instance" % role,
            )
        producer_body = ("[%s]\nproducer-authored body\n" % marker).encode()
        identifier = "entry-%032x" % self.counter
        producer_body_path = self.bodies / (identifier + ".md")
        producer_body_path.write_bytes(producer_body)
        entry = {
            "schemaVersion": 1,
            "id": identifier,
            "team": TEAM,
            "featureId": FEATURE,
            "taskId": TASK,
            "attempt": 1,
            "actor": role,
            "marker": marker,
            "bodyPath": str(producer_body_path),
            "targetStatus": target,
            "phase": "pending",
            "createdAt": "2026-09-19T10:00:00+00:00",
        }
        entry["producerCapability"] = outbox_capability.sign_entry(
            entry,
            producer_body,
            capability["id"],
            capability["secret"],
            capability["instance"],
            capability["expiresAt"],
        )
        source_entry = self.pending / (identifier + ".json")
        source_entry_raw = broker_evidence.canonical(entry) + b"\n"
        source_entry.write_bytes(source_entry_raw)
        source = self.deliveries / (delivery + ".source.md")
        source.write_bytes(producer_body)
        source.chmod(0o400)
        publish = self.deliveries / (delivery + ".publish.md")
        if final_body is None:
            final_body = ("[%s]\nbroker-bound body\n" % marker).encode()
        publish.write_bytes(final_body)
        publish.chmod(0o400)
        if binding is None:
            if request:
                binding = {
                    "kind": marker,
                    "base": "1" * 40,
                    "head": "2" * 40,
                    "package": "sha256:" + "3" * 64,
                }
            else:
                binding = {"kind": marker}
        entry.update(
            {
                "brokerSchemaVersion": 1,
                "deliveryId": delivery,
                "brokerAssignedAt": "2026-09-19T10:00:01+00:00",
                "sourceEntryPath": str(source_entry),
                "sourceEntrySha256": broker_evidence.sha256(source_entry_raw),
                "stagedBodyPath": str(source),
                "stagedBodySha256": broker_evidence.sha256(producer_body),
                "publishBodyPath": str(publish),
                "publishBodySha256": broker_evidence.sha256(final_body),
                "reviewBinding": binding,
                "brokerPhase": "published",
            }
        )
        entry_path = self.deliveries / (identifier + ".entry.json")
        entry_path.write_bytes(broker_evidence.canonical(entry) + b"\n")
        entry_path.chmod(0o600)
        tracker_body = final_body.decode().rstrip("\n") + "\n\ndelivery-id: " + delivery
        return entry_path, entry, tracker_body

    def receipt_file(self, payload: dict) -> Path:
        directory = self.authority / "broker-publications"
        return broker_evidence.receipt_path(directory, payload)

    def verify(self, entry: dict, tracker_body: str) -> dict:
        return broker_evidence.verify_review_publication(
            self.repository,
            self.workspace,
            team=TEAM,
            feature=FEATURE,
            task=TASK,
            marker=entry["marker"],
            delivery=entry["deliveryId"],
            target_status=entry["targetStatus"],
            tracker_body=tracker_body,
        )

    def test_review_request_receipt_binds_exact_capability_and_tracker_body(self) -> None:
        entry_path, entry, tracker_body = self.make_entry("review-request")

        envelope = broker_evidence.record(self.repository, self.workspace, entry_path)
        verified = self.verify(entry, tracker_body)

        payload = envelope["payload"]
        self.assertEqual(payload["schemaVersion"], 2)
        self.assertEqual(payload["receiptKind"], "review-publication")
        self.assertEqual(payload["executionKind"], "task")
        self.assertEqual(payload["producerRole"], "backend")
        self.assertEqual(payload["capabilityId"], entry["producerCapability"]["id"])
        self.assertEqual(
            payload["producerCapabilitySha256"],
            broker_evidence.sha256(
                broker_evidence.canonical(entry["producerCapability"])
            ),
        )
        self.assertEqual(
            payload["trackerBodySha256"],
            broker_evidence.sha256(tracker_body.encode()),
        )
        self.assertEqual(verified["reviewBinding"], entry["reviewBinding"])
        self.assertRegex(verified["receiptSha256"], r"^sha256:[0-9a-f]{64}$")

    def test_delivery_uses_immutable_producer_phase_and_protected_broker_phase(self) -> None:
        entry_path, entry, _tracker_body = self.make_entry("review-request")

        self.assertEqual(entry["phase"], "pending")
        self.assertEqual(entry["brokerPhase"], "published")
        self.assertEqual(entry_path.parent.resolve(), self.deliveries.resolve())
        self.assertNotEqual(entry_path.parent.resolve(), self.workspace.resolve())

        for field, value, message in (
            ("phase", "published", "schema"),
            ("brokerPhase", "pending", "completed publication"),
        ):
            tampered = dict(entry)
            tampered[field] = value
            entry_path.write_bytes(broker_evidence.canonical(tampered) + b"\n")
            with self.subTest(field=field), self.assertRaisesRegex(
                broker_evidence.EvidenceError, message
            ):
                broker_evidence.record(self.repository, self.workspace, entry_path)

    def test_gate_approval_receipt_is_idempotent_and_survives_expiry(self) -> None:
        entry_path, entry, tracker_body = self.make_entry(
            "architecture-approval", expired=True
        )

        first = broker_evidence.record(self.repository, self.workspace, entry_path)
        second = broker_evidence.record(self.repository, self.workspace, entry_path)

        self.assertEqual(first, second)
        self.assertEqual(first["payload"]["executionKind"], "gate")
        self.assertEqual(self.verify(entry, tracker_body)["producerRole"], "principal-architect")

    def test_review_publication_requires_protected_authority(self) -> None:
        review_path, _entry, _body = self.make_entry("review-request")
        ordinary_path, _ordinary, _ordinary_body = self.make_entry("progress")
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                broker_evidence.EvidenceError, "protected lifecycle authority"
            ):
                broker_evidence.record(self.repository, self.workspace, review_path)
            self.assertEqual(
                broker_evidence.record(self.repository, self.workspace, ordinary_path),
                {"protected": False},
            )

    def test_request_and_approval_require_the_right_capability_kind(self) -> None:
        request, _entry, _body = self.make_entry("review-request", kind="gate")
        approval, _entry, _body = self.make_entry(
            "architecture-approval", kind="task"
        )
        with self.assertRaisesRegex(broker_evidence.EvidenceError, "task producer"):
            broker_evidence.record(self.repository, self.workspace, request)
        with self.assertRaisesRegex(broker_evidence.EvidenceError, "gate producer"):
            broker_evidence.record(self.repository, self.workspace, approval)

    def test_malformed_binding_and_embedded_delivery_trailer_fail_closed(self) -> None:
        malformed, _entry, _body = self.make_entry(
            "review-request", binding={"kind": "review-request"}
        )
        trailer, _entry, _body = self.make_entry(
            "architecture-approval",
            final_body=b"[architecture-approval]\ndelivery-id: forged\n",
        )
        with self.assertRaisesRegex(broker_evidence.EvidenceError, "binding"):
            broker_evidence.record(self.repository, self.workspace, malformed)
        with self.assertRaisesRegex(broker_evidence.EvidenceError, "delivery trailer"):
            broker_evidence.record(self.repository, self.workspace, trailer)

    def test_tracker_body_target_and_scope_mismatches_fail_closed(self) -> None:
        entry_path, entry, tracker_body = self.make_entry("review-request")
        broker_evidence.record(self.repository, self.workspace, entry_path)
        cases = (
            {"tracker_body": tracker_body + "\ntampered"},
            {"target_status": "Active"},
            {"team": "another-team"},
        )
        for changes in cases:
            arguments = {
                "team": TEAM,
                "feature": FEATURE,
                "task": TASK,
                "marker": entry["marker"],
                "delivery": entry["deliveryId"],
                "target_status": entry["targetStatus"],
                "tracker_body": tracker_body,
                **changes,
            }
            with self.subTest(changes=changes), self.assertRaises(
                broker_evidence.EvidenceError
            ):
                broker_evidence.verify_review_publication(
                    self.repository, self.workspace, **arguments
                )

    def test_tampered_hmac_and_validly_signed_extra_payload_field_fail_closed(self) -> None:
        entry_path, entry, tracker_body = self.make_entry("review-request")
        envelope = broker_evidence.record(self.repository, self.workspace, entry_path)
        receipt = self.receipt_file(envelope["payload"])
        tampered = json.loads(receipt.read_text())
        tampered["payload"]["producerRole"] = "attacker"
        receipt.write_bytes(broker_evidence.canonical(tampered) + b"\n")
        with self.assertRaisesRegex(broker_evidence.EvidenceError, "authentication"):
            self.verify(entry, tracker_body)

        tampered["payload"]["unexpected"] = True
        unsigned = {"payload": tampered["payload"]}
        tampered["auth"] = "hmac-sha256:" + hmac.new(
            self.key,
            broker_evidence.canonical(unsigned),
            hashlib.sha256,
        ).hexdigest()
        receipt.write_bytes(broker_evidence.canonical(tampered) + b"\n")
        with self.assertRaisesRegex(broker_evidence.EvidenceError, "payload schema"):
            self.verify(entry, tracker_body)

    def test_schema_one_hold_receipt_remains_compatible(self) -> None:
        entry_path, entry, _tracker_body = self.make_entry("resume-review")

        envelope = broker_evidence.record(self.repository, self.workspace, entry_path)

        self.assertEqual(envelope["payload"]["schemaVersion"], 1)
        self.assertNotIn("receiptKind", envelope["payload"])
        self.assertTrue(
            broker_evidence.verify_delivery(
                self.repository,
                self.workspace,
                team=TEAM,
                feature=FEATURE,
                task=TASK,
                marker="resume-review",
                delivery=entry["deliveryId"],
                target_status=None,
                final_body_digest=entry["publishBodySha256"],
            )
        )


if __name__ == "__main__":
    unittest.main()
