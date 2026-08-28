#!/usr/bin/env python3
"""Cross-task and descriptor-custody tests for the V27 read-back stage plan."""

from __future__ import annotations

import hashlib
import hmac
import json
import dataclasses
import multiprocessing
import os
import signal
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from bin import beads_contract as contract
from startup_factory_cli import beads_native_boundary_v27 as boundary
from startup_factory_cli import beads_boundary_controller as controller


FIXTURE = ROOT / "tests/fixtures/prepared-beads-store-payload-v1.golden.json"
PAYLOAD_DOMAIN = b"startup-factory/prepared-beads-store-payload/v1\0"


def raw_sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def domain_sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(PAYLOAD_DOMAIN + value).hexdigest()


def stat_value(path: Path) -> dict[str, object]:
    observed = os.lstat(path)
    return {
        "device": observed.st_dev,
        "inode": observed.st_ino,
        "uid": observed.st_uid,
        "mode": f"{stat.S_IMODE(observed.st_mode):04o}",
        "linkCount": observed.st_nlink,
        "size": observed.st_size,
    }


class NativeStagePlanV27Test(unittest.TestCase):
    NATIVE_ARTIFACT_DOMAIN = (
        b"startup-factory/beads/v27/native-creator-artifact/v1\0"
    )
    NATIVE_ARTIFACT_SPECS = (
        (".native-creator-atomic-capture.v1", "NativePostReturnAtomicCaptureV1"),
        (".native-creator-join-result.v2", "CreatorJoinResultV2"),
        (".native-creator-post-return.v2", "CreatorPostReturnObservationV2"),
        (".native-creator-lifetime.v4", "CreatorThreadLifetimeReceiptV4"),
        (".native-allocation-gate-release.v1", "NativeAllocationGateReleaseReceiptV1"),
    )

    @staticmethod
    def linux_setgid_observation(root: Path):
        """Model the root-provisioned Linux setgid bit on Darwin only."""

        real_lstat = os.lstat

        def observe(path, *args, **kwargs):
            result = real_lstat(path, *args, **kwargs)
            if Path(path) == root and sys.platform == "darwin":
                fields = list(result)
                fields[0] = (result.st_mode & ~0o7777) | 0o2710
                return os.stat_result(fields)
            return result

        return mock.patch.object(boundary.os, "lstat", side_effect=observe)

    @staticmethod
    def retirement_receipt(placement_mask: int = 63) -> dict[str, object]:
        descendants = 6 if placement_mask == 63 else 0
        return {
            "schemaVersion": 27,
            "visibleDescendants": descendants,
            "placementMask": placement_mask,
            "controllerTrackedPlacementMask": placement_mask,
            "initControllers": [],
            "preRemovalCgroupStat": {
                "nr_descendants": descendants,
                "nr_dying_descendants": 0,
            },
            "terminalCgroupStat": {
                "nr_descendants": 0,
                "nr_dying_descendants": 0,
            },
        }

    @staticmethod
    def emit_success_native_events(stage_plan) -> None:
        handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
        if not callable(handler):
            raise AssertionError("native event handler is absent")
        for sequence, event in enumerate(boundary._SUCCESS_NATIVE_EVENTS_V27, 1):
            before = boundary._reference_native_event_observation_v27(
                event, "before"
            )
            before_evidence = boundary._native_event_evidence_v27(
                stage_plan_sha256=stage_plan["stagePlanSha256"],
                sequence=(sequence * 2) - 1,
                event=event,
                phase="before",
                observation=before,
            )
            handler(event, "before", before_evidence, before)
            after = boundary._reference_native_event_observation_v27(
                event, "after"
            )
            after_evidence = boundary._native_event_evidence_v27(
                stage_plan_sha256=stage_plan["stagePlanSha256"],
                sequence=sequence * 2,
                event=event,
                phase="after",
                observation=after,
            )
            handler(event, "after", after_evidence, after)

    @classmethod
    def successful_native_result(cls, stage_plan, *, stdout: bytes) -> dict:
        cls.emit_success_native_events(stage_plan)
        result = {
            "exitCode": 0,
            "placementMask": 63,
            "stdout": stdout,
            "stderr": b"",
            "lifecycle": list(boundary._EFFECT_LIFECYCLE),
            "resultKind": "success",
            "resultPredecessorKind": "creator-lifetime-closed-positive",
            "failureEvidenceSha256": None,
        }
        handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
        observation = boundary._decode_native_stage_result_v27(
            result, require_discriminants=True
        )
        handler.authorize_result_offer(observation)
        handler.receipt_result_handoff(observation)
        handler.terminalize_result_handoff(cls.retirement_receipt())
        return result

    @staticmethod
    def reader_outputs() -> list[bytes]:
        names = (
            "beads-v1.1.2-issue-envelope.json",
            "beads-v1.1.2-labels-envelope.json",
            "beads-v1.1.2-comments-envelope.json",
            "beads-v1.1.2-down-dependencies-envelope.json",
        )
        return [(ROOT / "tests/fixtures" / name).read_bytes() for name in names]

    def golden(self) -> tuple[bytes, contract.PreparedBeadsStoreExpectedBindingsV1]:
        value = json.loads(FIXTURE.read_bytes())["create"]
        canonical = value["canonicalUtf8"].encode("utf-8")
        return canonical, contract.PreparedBeadsStoreExpectedBindingsV1(
            **value["expectedBindings"]
        )

    def prepare_arena(
        self, manifest, stage_plan, key: bytes, runtime_root: Path
    ) -> Path:
        with mock.patch.object(
            boundary, "try_operation_lock_v27", return_value=("acquired", 0)
        ):
            prepared = boundary.prepare_native_stage_result_arena_v27(
                manifest, stage_plan, key, runtime_root=runtime_root
            )
        envelope = controller._controller_result_arena_envelope_v27(
            prepared,
            stage_plan,
            key,
            b"controller-only-test-key-material-32",
        )
        boundary.persist_controller_result_arena_v27(
            manifest, stage_plan, envelope, runtime_root=runtime_root
        )
        result_path = boundary._native_stage_result_path_v27(
            stage_plan, runtime_root=runtime_root
        )
        payload_name = (
            f"payload-{stage_plan['operationId']}-s{stage_plan['stageLocation']}-"
            f"{stage_plan['stagePlanSha256'].removeprefix('sha256:')[:16]}"
        )
        arena_sha = boundary.sha256(boundary.canonical_bytes(envelope))
        payload_identity = {
            "device": 17,
            "gid": os.getegid(),
            "inode": 19,
            "mode": "2710",
            "uid": os.geteuid(),
        }
        removal_plan = [
            {
                "parent": "payload",
                "name": f"lifecycle-{ordinal}",
                "identity": {
                    "device": 17,
                    "gid": os.getegid(),
                    "inode": 100 + ordinal,
                    "mode": "0770",
                    "nlink": 2,
                    "uid": os.geteuid(),
                },
            }
            for ordinal in range(6)
        ]
        intent_body = {
            "schemaVersion": 27,
            "payloadIdentity": payload_identity,
            "placementMask": 63,
            "visibleDescendants": 6,
            "initControllers": [],
            "preRemovalCgroupStat": {
                "nr_descendants": 6,
                "nr_dying_descendants": 0,
            },
            "removalPlan": removal_plan,
        }
        controller_key = b"controller-only-test-key-material-32"
        intent = controller._controller_retirement_envelope_v27(
            kind="intent",
            plan=stage_plan,
            payload_name=payload_name,
            payload_identity=payload_identity,
            arena_record_sha256=arena_sha,
            predecessor_artifact_sha256=None,
            body=intent_body,
            controller_key=controller_key,
        )
        receipt = controller._controller_retirement_envelope_v27(
            kind="receipt",
            plan=stage_plan,
            payload_name=payload_name,
            payload_identity=payload_identity,
            arena_record_sha256=arena_sha,
            predecessor_artifact_sha256=boundary.sha256(
                boundary.canonical_bytes(intent)
            ),
            body={
                "schemaVersion": 27,
                "visibleDescendants": 6,
                "placementMask": 63,
                "controllerTrackedPlacementMask": 63,
                "initControllers": [],
                "preRemovalCgroupStat": {
                    "nr_descendants": 6,
                    "nr_dying_descendants": 0,
                },
                "terminalCgroupStat": {
                    "nr_descendants": 0,
                    "nr_dying_descendants": 0,
                },
            },
            controller_key=controller_key,
        )
        for filename, value in (
            ("controller-retirement.intent.json", intent),
            ("controller-retirement.json", receipt),
        ):
            target = result_path / filename
            target.write_bytes(boundary.canonical_bytes(value))
            target.chmod(0o600)
        return result_path

    def native_creator_artifact_chain(
        self, stage_plan: dict, key: bytes, *,
        return_sentinel: str = "creator-positive-sentinel",
        common_overrides: dict[str, object] | None = None,
        lifetime_before: dict[str, object] | None = None,
        lifetime_after: dict[str, object] | None = None,
    ) -> list[tuple[str, bytes]]:
        digest = lambda label: boundary.sha256(label.encode("ascii"))
        common = {
            "capturePreparationRecordSha256": digest(
                "capture-preparation-record"
            ),
            "capturePreparationSha256": digest("capture-preparation"),
            "creationNonceSha256": digest("creation-nonce"),
            "creatorHandleConsumed": True,
            "creatorReturnCurrentRecordSha256": digest(
                "creator-return-current"
            ),
            "joinOwnerTokenSha256": digest("join-owner"),
            "operationId": stage_plan["operationId"],
            "requestKeyId": stage_plan["requestKeyId"],
            "returnAuthorizationRecordSha256": digest(
                "return-authorization"
            ),
            "returnSentinel": return_sentinel,
            "slotGeneration": 1,
            "stageLocation": stage_plan["stageLocation"],
            "stagePlanSha256": stage_plan["stagePlanSha256"],
            "taskSetSha256": digest("task-set"),
        }
        if common_overrides:
            common.update(common_overrides)
        payloads = (
            {
                "allocationGateHeld": True,
                "bootIdSha256": digest("boot"),
                "captureMonotonicNs": 12,
                "capturePreparationSha256": common[
                    "capturePreparationSha256"
                ],
                "capturePrepareMonotonicNs": 11,
                "captureWritersSha256": digest("writers"),
                "creatorStartTicks": "101",
                "creatorTaskBytesSha256": digest("task-bytes"),
                "creatorTid": 4243,
                "fd11GetfdErrno": 9,
                "fd7GetfdErrno": 9,
                "joinOwnerTokenSha256": common["joinOwnerTokenSha256"],
                "pthreadJoinRc": 0,
                "resultFdIdentitySha256": digest("result-fd"),
                "returnSentinel": common["returnSentinel"],
                "slotGeneration": 1,
                "taskSetSha256": common["taskSetSha256"],
            },
            {
                "atomicCaptureSha256": None,
                "creatorHandleConsumed": True,
                "joinOwnerTokenSha256": common["joinOwnerTokenSha256"],
                "pthreadJoinCount": 1,
                "pthreadJoinRc": 0,
                "returnSentinel": common["returnSentinel"],
                "slotGeneration": 1,
            },
            {
                "atomicCaptureSha256": None,
                "capturePreparationSha256": common[
                    "capturePreparationSha256"
                ],
                "creatorHandleConsumed": True,
                "joinResultSha256": None,
                "taskSetSha256": common["taskSetSha256"],
            },
            {
                "allocationGateHeld": True,
                "atomicCaptureSha256": None,
                "creatorHandleConsumed": True,
                "creatorTaskAbsent": True,
                "joinResultSha256": None,
                "postReturnObservationSha256": None,
                "proofFd11Closed": True,
                "proofFd7Closed": True,
                "pthreadJoinRc": 0,
                "returnSentinel": common["returnSentinel"],
            },
            {
                "allocationGateHeld": False,
                "allocationGateReleaseCount": 1,
                "lifetimeSha256": None,
                "releaseMonotonicNs": 13,
            },
        )
        if lifetime_before is not None:
            before = lifetime_before
            after = lifetime_after
            assert after is not None
            payloads[0].update(
                {
                    "allocationGateHeld": before["allocationGateHeld"],
                    "bootIdSha256": before["bootIdSha256"],
                    "captureMonotonicNs": before["captureMonotonicNs"],
                    "capturePreparationSha256": before[
                        "capturePreparationSha256"
                    ],
                    "capturePrepareMonotonicNs": before[
                        "capturePrepareMonotonicNs"
                    ],
                    "captureWritersSha256": before["captureWritersSha256"],
                    "creatorStartTicks": before["creatorStartTicks"],
                    "creatorTaskBytesSha256": before[
                        "creatorTaskBytesSha256"
                    ],
                    "creatorTid": before["creatorTid"],
                    "fd11GetfdErrno": before["fd11GetfdErrno"],
                    "fd7GetfdErrno": before["fd7GetfdErrno"],
                    "joinOwnerTokenSha256": before[
                        "joinOwnerTokenSha256"
                    ],
                    "pthreadJoinRc": before["pthreadJoinRc"],
                    "resultFdIdentitySha256": before[
                        "resultFdIdentitySha256"
                    ],
                    "returnSentinel": before["returnSentinel"],
                    "slotGeneration": before["slotGeneration"],
                    "taskSetSha256": before["taskSetSha256"],
                }
            )
            payloads[1].update(
                {
                    "creatorHandleConsumed": before[
                        "creatorHandleConsumed"
                    ],
                    "joinOwnerTokenSha256": before[
                        "joinOwnerTokenSha256"
                    ],
                    "pthreadJoinCount": before["pthreadJoinCount"],
                    "pthreadJoinRc": before["pthreadJoinRc"],
                    "returnSentinel": before["returnSentinel"],
                    "slotGeneration": before["slotGeneration"],
                }
            )
            payloads[2].update(
                {
                    "capturePreparationSha256": before[
                        "capturePreparationSha256"
                    ],
                    "creatorHandleConsumed": before[
                        "creatorHandleConsumed"
                    ],
                    "taskSetSha256": before["taskSetSha256"],
                }
            )
            payloads[3].update(
                {
                    "allocationGateHeld": before["allocationGateHeld"],
                    "creatorHandleConsumed": before[
                        "creatorHandleConsumed"
                    ],
                    "creatorTaskAbsent": before["creatorTaskAbsent"],
                    "proofFd11Closed": before["proofFd11Closed"],
                    "proofFd7Closed": before["proofFd7Closed"],
                    "pthreadJoinRc": before["pthreadJoinRc"],
                    "returnSentinel": before["returnSentinel"],
                }
            )
            payloads[4].update(
                {
                    "allocationGateHeld": after["allocationGateHeld"],
                    "allocationGateReleaseCount": after[
                        "allocationGateReleaseCount"
                    ],
                    "releaseMonotonicNs": after[
                        "allocationGateReleaseMonotonicNs"
                    ],
                }
            )
        predecessors = (
            (
                "NativePostReturnCapturePreparationV1",
                str(common["capturePreparationRecordSha256"]),
            ),
            ("NativePostReturnAtomicCaptureV1", None),
            ("CreatorJoinResultV2", None),
            ("CreatorPostReturnObservationV2", None),
            ("CreatorThreadLifetimeReceiptV4", None),
        )
        result: list[tuple[str, bytes]] = []
        previous_digest: str | None = None
        for sequence, ((name, kind), payload, predecessor) in enumerate(
            zip(self.NATIVE_ARTIFACT_SPECS, payloads, predecessors, strict=True)
        ):
            predecessor_kind, fixed_predecessor = predecessor
            predecessor_sha = fixed_predecessor or previous_digest
            assert predecessor_sha is not None
            if sequence == 1:
                payload["atomicCaptureSha256"] = previous_digest
            elif sequence == 2:
                payload["atomicCaptureSha256"] = boundary.sha256(result[0][1])
                payload["joinResultSha256"] = previous_digest
            elif sequence == 3:
                payload["atomicCaptureSha256"] = boundary.sha256(result[0][1])
                payload["joinResultSha256"] = boundary.sha256(result[1][1])
                payload["postReturnObservationSha256"] = previous_digest
            elif sequence == 4:
                payload["lifetimeSha256"] = previous_digest
            artifact = {
                "artifactKind": kind,
                "capturePreparationRecordSha256": common[
                    "capturePreparationRecordSha256"
                ],
                "capturePreparationSha256": common[
                    "capturePreparationSha256"
                ],
                "creationNonceSha256": common["creationNonceSha256"],
                "creatorHandleConsumed": common["creatorHandleConsumed"],
                "creatorReturnCurrentRecordSha256": common[
                    "creatorReturnCurrentRecordSha256"
                ],
                "joinOwnerTokenSha256": common["joinOwnerTokenSha256"],
                "operationId": common["operationId"],
                "payload": payload,
                "predecessorKind": predecessor_kind,
                "predecessorSha256": predecessor_sha,
                "requestKeyId": common["requestKeyId"],
                "returnAuthorizationRecordSha256": common[
                    "returnAuthorizationRecordSha256"
                ],
                "returnSentinel": common["returnSentinel"],
                "schemaVersion": 27,
                "sequence": sequence,
                "slotGeneration": common["slotGeneration"],
                "stageLocation": common["stageLocation"],
                "stagePlanSha256": common["stagePlanSha256"],
                "taskSetSha256": common["taskSetSha256"],
            }
            artifact_raw = boundary.canonical_bytes(artifact)
            envelope = boundary.canonical_bytes(
                {
                    "artifact": artifact,
                    "artifactHmac": "hmac-sha256:" + hmac.new(
                        key,
                        self.NATIVE_ARTIFACT_DOMAIN + artifact_raw,
                        hashlib.sha256,
                    ).hexdigest(),
                }
            ) + b"\n"
            result.append((name, envelope))
            previous_digest = boundary.sha256(envelope)
        return result

    def mutate_native_creator_artifact_chain(
        self, chain: list[tuple[str, bytes]], key: bytes, *,
        sequence: int, field: str, replacement: object,
    ) -> list[tuple[str, bytes]]:
        decoded = [
            json.loads(raw)
            for _filename, raw in chain
        ]
        decoded[sequence]["artifact"]["payload"][field] = replacement
        result: list[tuple[str, bytes]] = []
        digests: list[str] = []
        for ordinal, ((filename, _raw), envelope) in enumerate(
            zip(chain, decoded, strict=True)
        ):
            artifact = envelope["artifact"]
            if ordinal > 0:
                artifact["predecessorSha256"] = digests[-1]
            if ordinal == 1:
                if not (sequence == ordinal and field == "atomicCaptureSha256"):
                    artifact["payload"]["atomicCaptureSha256"] = digests[0]
            elif ordinal == 2:
                if not (sequence == ordinal and field == "atomicCaptureSha256"):
                    artifact["payload"]["atomicCaptureSha256"] = digests[0]
                if not (sequence == ordinal and field == "joinResultSha256"):
                    artifact["payload"]["joinResultSha256"] = digests[1]
            elif ordinal == 3:
                if not (sequence == ordinal and field == "atomicCaptureSha256"):
                    artifact["payload"]["atomicCaptureSha256"] = digests[0]
                if not (sequence == ordinal and field == "joinResultSha256"):
                    artifact["payload"]["joinResultSha256"] = digests[1]
                if not (
                    sequence == ordinal
                    and field == "postReturnObservationSha256"
                ):
                    artifact["payload"]["postReturnObservationSha256"] = (
                        digests[2]
                    )
            elif ordinal == 4:
                if not (sequence == ordinal and field == "lifetimeSha256"):
                    artifact["payload"]["lifetimeSha256"] = digests[3]
            artifact_raw = boundary.canonical_bytes(artifact)
            envelope["artifactHmac"] = "hmac-sha256:" + hmac.new(
                key,
                self.NATIVE_ARTIFACT_DOMAIN + artifact_raw,
                hashlib.sha256,
            ).hexdigest()
            encoded = boundary.canonical_bytes(envelope) + b"\n"
            result.append((filename, encoded))
            digests.append(boundary.sha256(encoded))
        return result

    def test_cross_task_candidate_is_recomputed_not_raw_hashed(self) -> None:
        canonical, expected = self.golden()
        verified = boundary.verify_protected_read_back_candidate_v27(
            canonical,
            protected_raw_sha256=raw_sha(canonical),
            protected_expected_bindings=expected,
        )
        self.assertEqual(expected.payload_sha256, domain_sha(canonical))
        self.assertEqual(
            "sha256:fe7dd91760b115a3c0b6dda7c191de272808606468fa9d38056456efa60847b8",
            verified.candidate_plan_sha256,
        )
        self.assertNotEqual(
            verified.candidate_plan_sha256,
            raw_sha(boundary.canonical_bytes(dict(verified.candidate))),
        )

        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_protected_read_back_candidate_v27(
                canonical,
                protected_raw_sha256=domain_sha(canonical),
                protected_expected_bindings=expected,
            )

    def test_prepared_expected_binding_is_separate_and_carries_payload_digest(self) -> None:
        canonical, expected = self.golden()
        evidence = dataclasses.asdict(expected)
        restored = controller._prepared_expected_bindings_v27(evidence)
        self.assertEqual(expected, restored)
        self.assertEqual(domain_sha(canonical), restored.payload_sha256)

        candidate = json.loads(canonical)
        candidate["projectRootLocatorSha256"] = "sha256:" + "f" * 64
        # Changing candidate bytes cannot change the protected expected object.
        self.assertEqual(expected, controller._prepared_expected_bindings_v27(evidence))
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_protected_read_back_candidate_v27(
                boundary.canonical_bytes(candidate),
                protected_raw_sha256=raw_sha(boundary.canonical_bytes(candidate)),
                protected_expected_bindings=restored,
            )

        forged = dict(evidence)
        forged["payload_sha256"] = raw_sha(canonical)
        forged_expected = controller._prepared_expected_bindings_v27(forged)
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_protected_read_back_candidate_v27(
                canonical,
                protected_raw_sha256=raw_sha(canonical),
                protected_expected_bindings=forged_expected,
            )

    def test_four_distinct_reader_schemas_join_one_authoritative_projection(self) -> None:
        reads = self.reader_outputs()
        self.assertEqual(4, len(set(reads)))
        decoded = boundary.decode_beads_read_back_outputs_v27(
            reads, target_id="task-1"
        )
        self.assertEqual(
            {
                "id": "task-1",
                "revision": "2026-08-24T16:35:03Z",
                "status": "in_progress",
            },
            decoded["projection"],
        )
        self.assertEqual(
            [
                "01a034a0-1f41-755a-9ae2-478eef0b97fb",
                "01a034a0-21f6-707d-b978-aeec8d45324d",
            ],
            decoded["commentIds"],
        )
        self.assertEqual(
            [{"dependencyType": "blocks", "id": "task-0"}],
            decoded["dependencies"],
        )

    def test_reader_decoder_rejects_cross_ordinal_and_join_substitution(self) -> None:
        reads = self.reader_outputs()
        hostile: list[list[bytes]] = []
        wrong_shape = list(reads)
        wrong_shape[1] = reads[0]
        hostile.append(wrong_shape)
        wrong_labels = list(reads)
        wrong_labels[1] = boundary.canonical_bytes(
            {"data": ["automation"], "schema_version": 1}
        ) + b"\n"
        hostile.append(wrong_labels)
        wrong_comment = list(reads)
        comment_value = json.loads(wrong_comment[2])
        comment_value["data"][0]["issue_id"] = "task-2"
        wrong_comment[2] = boundary.canonical_bytes(comment_value) + b"\n"
        hostile.append(wrong_comment)
        wrong_dependency_count = list(reads)
        wrong_dependency_count[3] = boundary.canonical_bytes(
            {"data": [], "schema_version": 1}
        ) + b"\n"
        hostile.append(wrong_dependency_count)
        for candidate in hostile:
            with self.subTest(candidate=[raw[:40] for raw in candidate]):
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary.decode_beads_read_back_outputs_v27(
                        candidate, target_id="task-1"
                    )

        for field in ("no_history", "pinned"):
            candidate = list(reads)
            value = json.loads(candidate[0])
            value["data"][0][field] = True
            candidate[0] = boundary.canonical_bytes(value) + b"\n"
            with self.subTest(unsupported_true=field):
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error, "supported regular domain"
                ):
                    boundary.decode_beads_read_back_outputs_v27(
                        candidate, target_id="task-1"
                    )

    def test_reader_issue_v112_validates_every_field_type_and_nullability(self) -> None:
        reads = self.reader_outputs()
        nullable = (
            "estimated_minutes", "started_at", "closed_at", "due_at",
            "defer_until", "external_ref", "compacted_at",
            "compacted_at_commit",
        )
        for field in nullable:
            candidate = list(reads)
            value = json.loads(candidate[0])
            value["data"][0][field] = None
            candidate[0] = boundary.canonical_bytes(value) + b"\n"
            with self.subTest(nullable=field):
                boundary.decode_beads_read_back_outputs_v27(
                    candidate, target_id="task-1"
                )

        invalid_types = {
            **{
                field: 7 for field in (
                    "description", "design", "acceptance_criteria", "notes",
                    "spec_id", "status", "issue_type", "assignee", "owner",
                    "created_by", "close_reason", "closed_by_session",
                    "source_system", "sender", "wisp_type", "await_type",
                    "await_id", "source_formula", "source_location", "mol_type",
                    "work_type", "event_kind", "actor", "target", "payload",
                )
            },
            "estimated_minutes": "1",
            "started_at": 1,
            "closed_at": 1,
            "due_at": 1,
            "defer_until": 1,
            "external_ref": 1,
            "compaction_level": False,
            "compacted_at": 1,
            "compacted_at_commit": 1,
            "original_size": False,
            "labels": {},
            "dependencies": {},
            "comments": {},
            "ephemeral": 0,
            "no_history": 0,
            "pinned": 0,
            "is_template": 0,
            "bonded_from": {},
            "timeout": False,
            "waiters": {},
        }
        for field, invalid in invalid_types.items():
            candidate = list(reads)
            value = json.loads(candidate[0])
            value["data"][0][field] = invalid
            candidate[0] = boundary.canonical_bytes(value) + b"\n"
            with self.subTest(field=field, invalid=invalid):
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary.decode_beads_read_back_outputs_v27(
                        candidate, target_id="task-1"
                    )

    def test_official_go_envelopes_have_exact_framing_not_canonical_presentation(self) -> None:
        reads = self.reader_outputs()
        self.assertTrue(all(raw.startswith(b"{\n  \"data\"") for raw in reads))
        decoded = boundary.decode_beads_read_back_outputs_v27(
            reads, target_id="task-1"
        )
        self.assertEqual("2026-08-24T16:35:03Z", decoded["projection"]["revision"])

        provenance = json.loads(
            (ROOT / "tests/fixtures/beads-v1.1.2-wire-provenance.json").read_bytes()
        )
        self.assertEqual("v1.1.2", provenance["releaseTag"])
        self.assertEqual(
            "20e493e569c922d1253bdeff068c5e56c94957fb",
            provenance["sourceCommit"],
        )
        for path, raw in zip(
            (
                "beads-v1.1.2-issue-envelope.json",
                "beads-v1.1.2-labels-envelope.json",
                "beads-v1.1.2-comments-envelope.json",
                "beads-v1.1.2-down-dependencies-envelope.json",
            ),
            reads,
        ):
            self.assertEqual(len(raw), provenance["fixtures"][path]["bytes"])
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                provenance["fixtures"][path]["sha256"],
            )

        issue = reads[0]
        body = issue[:-1]
        hostile = (
            b"\xef\xbb\xbf" + issue,
            body,
            body + b" \n",
            body + b"\n{}\n",
            issue.replace(b'"schema_version": 1', b'"schema_version": 1,\n  "schema_version": 1'),
            b"{\xff}\n",
        )
        for raw in hostile:
            with self.subTest(raw=raw[:48]):
                candidate = list(reads)
                candidate[0] = raw
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary.decode_beads_read_back_outputs_v27(
                        candidate, target_id="task-1"
                    )

    def test_rfc3339nano_calendar_roundtrip_and_signed_int64_are_exact(self) -> None:
        for value in (
            "0000-02-29T00:00:00Z",
            "2000-02-29T23:59:59.123456789-07:45",
            "2026-08-24T09:30:00.1+02:30",
        ):
            with self.subTest(valid=value):
                self.assertEqual(value, boundary._timestamp_v112(value, "timestamp"))
        for value in (
            "2026-02-29T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T23:60:00Z",
            "2024-01-01T23:59:60Z",
            "2024-01-01T00:00:00.100Z",
            "2024-01-01T00:00:00+00:00",
            "2024-01-01T00:00:00-00:00",
            "2024-01-01T00:00:00+24:00",
            "2024-01-01T00:00:00+02:60",
        ):
            with self.subTest(invalid=value):
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary._timestamp_v112(value, "timestamp")

        reads = self.reader_outputs()
        for field, accepted in (
            ("estimated_minutes", (1 << 63) - 1),
            ("compaction_level", -(1 << 63)),
            ("original_size", (1 << 63) - 1),
        ):
            value = json.loads(reads[0])
            value["data"][0][field] = accepted
            candidate = list(reads)
            candidate[0] = json.dumps(value, indent=2).encode() + b"\n"
            boundary.decode_beads_read_back_outputs_v27(
                candidate, target_id="task-1"
            )
            for rejected in (-(1 << 63) - 1, 1 << 63):
                value["data"][0][field] = rejected
                candidate[0] = json.dumps(value, indent=2).encode() + b"\n"
                with self.subTest(field=field, rejected=rejected):
                    with self.assertRaisesRegex(
                        boundary.NativeBoundaryV27Error, "signed int64"
                    ):
                        boundary.decode_beads_read_back_outputs_v27(
                            candidate, target_id="task-1"
                        )

        for field in ("dependency_count", "dependent_count", "comment_count"):
            value = json.loads(reads[0])
            value["data"][0][field] = 1 << 63
            candidate = list(reads)
            candidate[0] = json.dumps(value, indent=2).encode() + b"\n"
            with self.subTest(count=field), self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "signed int64"
            ):
                boundary.decode_beads_read_back_outputs_v27(
                    candidate, target_id="task-1"
                )
        for rejected in (-(1 << 63) - 1, 1 << 63):
            value = json.loads(reads[0])
            value["data"][0]["timeout"] = rejected
            candidate = list(reads)
            candidate[0] = json.dumps(value, indent=2).encode() + b"\n"
            with self.subTest(timeout=rejected), self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "signed int64"
            ):
                boundary.decode_beads_read_back_outputs_v27(
                    candidate, target_id="task-1"
                )

    def test_effect_environment_forces_official_bd_envelopes(self) -> None:
        manifest, plan = self.ordinary_plan()
        self.assertEqual("1", plan["environment"]["BD_JSON_ENVELOPE"])
        stage = next(
            row for row in boundary.literal_stage_schedule_v27("ordinary")
            if row.stage_key == "reader-0-payload-terminal"
        )
        derived = boundary.derive_native_stage_action_plan_v27(
            manifest, plan, stage
        )
        self.assertEqual("1", derived["environment"]["BD_JSON_ENVELOPE"])

    def test_request_key_is_rederived_from_launch_generation_and_epochs(self) -> None:
        manifest = boundary.parse_native_boundary_manifest_v27(
            json.loads((ROOT / "runtime/beads-native-boundary-v27.example.json").read_text())
        )
        plan = boundary.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="1" * 64,
            operation_class="ordinary",
            argv=["/usr/local/bin/bd", "update", "task-1", "--json"],
            repository_path="/tmp/repository",
            launch_core_sha256="sha256:" + "2" * 64,
            operator_generation=7,
            config_epoch=11,
            key_epoch=13,
        )
        stage = next(
            item for item in boundary.literal_stage_schedule_v27("ordinary")
            if item.stage_kind == "payload-terminal"
        )
        retained = bytes(range(32))
        first = boundary._derive_native_request_key_v27(retained, plan, stage)
        self.assertEqual(32, len(first))
        changed = dict(plan)
        changed["keyEpoch"] = 14
        changed["planSha256"] = boundary._effect_plan_digest(changed)
        self.assertNotEqual(
            first,
            boundary._derive_native_request_key_v27(retained, changed, stage),
        )
        stage_plan = boundary.derive_native_stage_action_plan_v27(
            manifest, plan, stage
        )
        assert stage_plan is not None
        stage_plan = {
            **stage_plan,
            "requestKeyId": boundary.sha256(first),
            "stagePlanSha256": None,
        }
        stage_plan["stagePlanSha256"] = boundary._native_stage_plan_digest_v27(
            stage_plan
        )
        boundary.validate_native_stage_action_plan_v27(stage_plan, manifest)

    def test_fd10_result_recovery_authenticates_request_key_id_and_hmac(self) -> None:
        key = bytes(range(32))
        key_id = boundary.sha256(key)
        result = {
            "exitCode": 0,
            "placementMask": 63,
            "lifecycle": list(boundary._EFFECT_LIFECYCLE),
            "stderrBase64": "",
            "stdoutBase64": "e30=",
            "resultKind": "success",
            "resultPredecessorKind": "creator-lifetime-closed-positive",
            "failureEvidenceSha256": None,
        }
        result_raw = boundary.canonical_bytes(result)
        result_hmac = "hmac-sha256:" + hmac.new(
            key,
            b"startup-factory/beads/v27/result\0" + result_raw,
            hashlib.sha256,
        ).hexdigest()
        envelope = boundary.canonical_bytes(
            {
                "requestKeyId": key_id,
                "result": result,
                "resultHmac": result_hmac,
            }
        ) + b"\n"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            root.chmod(0o700)
            (root / "result.json").write_bytes(envelope)
            (root / "result.json").chmod(0o600)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(
                    (envelope, result_raw),
                    boundary._reopen_authenticated_fd10_result_v27(
                        descriptor, key, key_id
                    ),
                )
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary._reopen_authenticated_fd10_result_v27(
                        descriptor, b"x" * 32, boundary.sha256(b"x" * 32)
                    )
            finally:
                os.close(descriptor)

        manifest, effect_plan = self.ordinary_plan()
        stage = next(
            row for row in boundary.literal_stage_schedule_v27("ordinary")
            if row.stage_kind == "payload-terminal"
        )
        stage_plan = boundary.derive_native_stage_action_plan_v27(
            manifest, effect_plan, stage
        )
        assert stage_plan is not None
        stage_plan = {
            **stage_plan,
            "requestKeyId": key_id,
            "stagePlanSha256": None,
        }
        stage_plan["stagePlanSha256"] = boundary._native_stage_plan_digest_v27(
            stage_plan
        )
        with tempfile.TemporaryDirectory() as name:
            runtime_root = Path(name).resolve()
            runtime_root.chmod(0o700)
            result_path = self.prepare_arena(
                manifest, stage_plan, key, runtime_root
            )
            for filename, artifact in self.native_creator_artifact_chain(
                stage_plan, key
            ):
                (result_path / filename).write_bytes(artifact)
                (result_path / filename).chmod(0o600)
            (result_path / "result.json").write_bytes(envelope)
            (result_path / "result.json").chmod(0o600)
            with mock.patch.object(
                boundary, "try_operation_lock_v27", return_value=("acquired", 0)
            ):
                recovered = boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )
            self.assertEqual(63, recovered["placementMask"])
            self.assertEqual(b"{}", recovered["stdout"])
            self.assertEqual(
                {"arena", "intent", "receipt"},
                set(recovered["_controllerRetirementChain"]),
            )
            (result_path / "unexpected").write_bytes(b"")
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "unexpected state"
            ):
                with mock.patch.object(
                    boundary, "try_operation_lock_v27", return_value=("acquired", 0)
                ):
                    boundary.recover_durable_native_stage_result_v27(
                        manifest, stage_plan, key, runtime_root=runtime_root
                    )

    def test_fd10_native_creator_artifacts_are_authenticated_and_ordered(self) -> None:
        key = bytes(range(32))
        manifest, effect_plan = self.ordinary_plan()
        stage = next(
            row for row in boundary.literal_stage_schedule_v27("ordinary")
            if row.stage_kind == "payload-terminal"
        )
        stage_plan = boundary.derive_native_stage_action_plan_v27(
            manifest, effect_plan, stage
        )
        assert stage_plan is not None
        stage_plan = {
            **stage_plan,
            "requestKeyId": boundary.sha256(key),
            "stagePlanSha256": None,
        }
        stage_plan["stagePlanSha256"] = boundary._native_stage_plan_digest_v27(
            stage_plan
        )
        result = {
            "exitCode": 0,
            "placementMask": 63,
            "lifecycle": list(boundary._EFFECT_LIFECYCLE),
            "stderrBase64": "",
            "stdoutBase64": "e30=",
            "resultKind": "success",
            "resultPredecessorKind": "creator-lifetime-closed-positive",
            "failureEvidenceSha256": None,
        }
        result_raw = boundary.canonical_bytes(result)
        result_envelope = boundary.canonical_bytes(
            {
                "requestKeyId": stage_plan["requestKeyId"],
                "result": result,
                "resultHmac": "hmac-sha256:" + hmac.new(
                    key,
                    b"startup-factory/beads/v27/result\0" + result_raw,
                    hashlib.sha256,
                ).hexdigest(),
            }
        ) + b"\n"
        chain = self.native_creator_artifact_chain(stage_plan, key)

        with tempfile.TemporaryDirectory() as name:
            runtime_root = Path(name).resolve()
            runtime_root.chmod(0o700)
            result_path = self.prepare_arena(
                manifest, stage_plan, key, runtime_root
            )
            for filename, raw in chain:
                (result_path / filename).write_bytes(raw)
                (result_path / filename).chmod(0o600)
            (result_path / "result.json").write_bytes(result_envelope)
            (result_path / "result.json").chmod(0o600)
            with mock.patch.object(
                boundary, "try_operation_lock_v27", return_value=("acquired", 0)
            ):
                recovered = boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )
            self.assertEqual("success", recovered["resultKind"])

        revoke = {
            **result,
            "exitCode": 75,
            "placementMask": 0,
            "resultKind": "revoke-verified-no-effect",
            "resultPredecessorKind": (
                "creator-lifetime-closed-revoke-verified-no-effect"
            ),
            "failureEvidenceSha256": boundary.sha256(b"revoke"),
        }
        revoke_raw = boundary.canonical_bytes(revoke)
        revoke_envelope = boundary.canonical_bytes(
            {
                "requestKeyId": stage_plan["requestKeyId"],
                "result": revoke,
                "resultHmac": "hmac-sha256:" + hmac.new(
                    key,
                    b"startup-factory/beads/v27/result\0" + revoke_raw,
                    hashlib.sha256,
                ).hexdigest(),
            }
        ) + b"\n"
        revoke_chain = self.native_creator_artifact_chain(
            stage_plan, key, return_sentinel="creator-abort-sentinel"
        )
        with tempfile.TemporaryDirectory() as name:
            runtime_root = Path(name).resolve()
            runtime_root.chmod(0o700)
            result_path = self.prepare_arena(
                manifest, stage_plan, key, runtime_root
            )
            for filename, raw in revoke_chain:
                (result_path / filename).write_bytes(raw)
                (result_path / filename).chmod(0o600)
            (result_path / "result.json").write_bytes(revoke_envelope)
            (result_path / "result.json").chmod(0o600)
            with mock.patch.object(
                boundary, "try_operation_lock_v27", return_value=("acquired", 0)
            ):
                recovered = boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )
            self.assertEqual(
                "revoke-verified-no-effect", recovered["resultKind"]
            )

        # Every writer is reserved before return.  Before-write, short-write,
        # and full-write/before-fsync prefixes may only become the existing
        # no-replay loss; a complete chain without result.json covers the
        # final artifact fsync and gate-receipt/result-install boundary.
        crash_prefixes = []
        for cutoff in range(len(chain)):
            crash_prefixes.extend(
                (cutoff, state)
                for state in ("empty", "partial", "missing-lf", "full")
            )
        for cutoff, state in crash_prefixes:
            with self.subTest(cutoff=cutoff, state=state), tempfile.TemporaryDirectory() as name:
                runtime_root = Path(name).resolve()
                runtime_root.chmod(0o700)
                result_path = self.prepare_arena(
                    manifest, stage_plan, key, runtime_root
                )
                for index, (filename, raw) in enumerate(chain):
                    persisted = raw if index < cutoff else b""
                    if index == cutoff:
                        persisted = {
                            "empty": b"",
                            "partial": raw[:17],
                            "missing-lf": raw[:-1],
                            "full": raw,
                        }[state]
                    (result_path / filename).write_bytes(persisted)
                    (result_path / filename).chmod(0o600)
                with mock.patch.object(
                    boundary, "try_operation_lock_v27",
                    return_value=("acquired", 0),
                ):
                    recovered = boundary.recover_durable_native_stage_result_v27(
                        manifest, stage_plan, key, runtime_root=runtime_root
                    )
                self.assertEqual(
                    "dead-holder-without-terminal",
                    recovered["nativeSupervisorLoss"]["reason"],
                )

        for reservation_count in range(1, len(chain)):
            with self.subTest(
                reservation_prefix=reservation_count
            ), tempfile.TemporaryDirectory() as name:
                runtime_root = Path(name).resolve()
                runtime_root.chmod(0o700)
                result_path = self.prepare_arena(
                    manifest, stage_plan, key, runtime_root
                )
                for filename, _raw in chain[:reservation_count]:
                    (result_path / filename).write_bytes(b"")
                    (result_path / filename).chmod(0o600)
                with mock.patch.object(
                    boundary, "try_operation_lock_v27",
                    return_value=("acquired", 0),
                ):
                    recovered = boundary.recover_durable_native_stage_result_v27(
                        manifest, stage_plan, key, runtime_root=runtime_root
                    )
                self.assertEqual(
                    "dead-holder-without-terminal",
                    recovered["nativeSupervisorLoss"]["reason"],
                )

        for hostile_name, hostile_bytes in (
            (chain[0][0], b'{"artifact":!'),
            (chain[0][0], chain[0][1].replace(b'"artifact":', b'"artifact"!', 1)),
            (".native-creator-unknown.v1", b"substitution"),
        ):
            with self.subTest(hostile_prefix=hostile_name), \
                 tempfile.TemporaryDirectory() as name:
                runtime_root = Path(name).resolve()
                runtime_root.chmod(0o700)
                result_path = self.prepare_arena(
                    manifest, stage_plan, key, runtime_root
                )
                for filename, _raw in chain:
                    (result_path / filename).write_bytes(b"")
                    (result_path / filename).chmod(0o600)
                (result_path / hostile_name).write_bytes(hostile_bytes)
                (result_path / hostile_name).chmod(0o600)
                with self.assertRaises(boundary.NativeBoundaryV27Error), \
                     mock.patch.object(
                         boundary, "try_operation_lock_v27",
                         return_value=("acquired", 0),
                     ):
                    boundary.recover_durable_native_stage_result_v27(
                        manifest, stage_plan, key, runtime_root=runtime_root
                    )

        # A fully authenticated creator chain still cannot swap the terminal
        # branch: positive is success-only and abort is revoke-only.
        with tempfile.TemporaryDirectory() as name:
            runtime_root = Path(name).resolve()
            runtime_root.chmod(0o700)
            result_path = self.prepare_arena(
                manifest, stage_plan, key, runtime_root
            )
            for filename, raw in revoke_chain:
                (result_path / filename).write_bytes(raw)
                (result_path / filename).chmod(0o600)
            (result_path / "result.json").write_bytes(result_envelope)
            (result_path / "result.json").chmod(0o600)
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "return sentinel differ"
            ), mock.patch.object(
                boundary, "try_operation_lock_v27",
                return_value=("acquired", 0),
            ):
                boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )

        hostile = (
            "missing", "swapped", "wrong-mode", "wrong-owner",
            "hardlink", "symlink", "reordered",
        )
        for case in hostile:
            with self.subTest(hostile=case), tempfile.TemporaryDirectory() as name:
                runtime_root = Path(name).resolve()
                runtime_root.chmod(0o700)
                result_path = self.prepare_arena(
                    manifest, stage_plan, key, runtime_root
                )
                values = dict(chain)
                if case == "missing":
                    values.pop(chain[2][0])
                elif case == "swapped":
                    values[chain[0][0]], values[chain[1][0]] = (
                        values[chain[1][0]], values[chain[0][0]]
                    )
                elif case == "reordered":
                    decoded = json.loads(values[chain[2][0]])
                    decoded["artifact"]["predecessorSha256"] = boundary.sha256(
                        b"wrong-predecessor"
                    )
                    artifact_raw = boundary.canonical_bytes(decoded["artifact"])
                    decoded["artifactHmac"] = "hmac-sha256:" + hmac.new(
                        key,
                        self.NATIVE_ARTIFACT_DOMAIN + artifact_raw,
                        hashlib.sha256,
                    ).hexdigest()
                    values[chain[2][0]] = boundary.canonical_bytes(decoded) + b"\n"
                for filename, raw in values.items():
                    (result_path / filename).write_bytes(raw)
                    (result_path / filename).chmod(0o600)
                if case == "wrong-mode":
                    (result_path / chain[0][0]).chmod(0o644)
                elif case == "hardlink":
                    (result_path / chain[1][0]).unlink()
                    os.link(result_path / chain[0][0], result_path / chain[1][0])
                elif case == "symlink":
                    (result_path / chain[0][0]).unlink()
                    os.symlink("arena.json", result_path / chain[0][0])
                (result_path / "result.json").write_bytes(result_envelope)
                (result_path / "result.json").chmod(0o600)
                real_fstat = os.fstat
                wrong_inode = os.lstat(result_path / chain[0][0]).st_ino

                def hostile_fstat(descriptor: int):
                    observed = real_fstat(descriptor)
                    if case != "wrong-owner" or observed.st_ino != wrong_inode:
                        return observed
                    return os.stat_result((
                        observed.st_mode, observed.st_ino, observed.st_dev,
                        observed.st_nlink, observed.st_uid + 1, observed.st_gid,
                        observed.st_size, observed.st_atime, observed.st_mtime,
                        observed.st_ctime,
                    ))

                with self.assertRaises(boundary.NativeBoundaryV27Error), \
                     mock.patch.object(
                         boundary, "try_operation_lock_v27",
                         return_value=("acquired", 0),
                     ), mock.patch.object(boundary.os, "fstat", hostile_fstat):
                    boundary.recover_durable_native_stage_result_v27(
                        manifest, stage_plan, key, runtime_root=runtime_root
                    )

    def test_result_arena_prepare_ack_is_durable_before_payload_cgroup(self) -> None:
        manifest, effect_plan = self.ordinary_plan()
        stage = next(
            row for row in boundary.literal_stage_schedule_v27("ordinary")
            if row.stage_kind == "payload-terminal"
        )
        key = b"p" * 32
        stage_plan = boundary.derive_native_stage_action_plan_v27(
            manifest, effect_plan, stage
        )
        assert stage_plan is not None
        stage_plan = {
            **stage_plan,
            "requestKeyId": boundary.sha256(key),
            "stagePlanSha256": None,
        }
        stage_plan["stagePlanSha256"] = boundary._native_stage_plan_digest_v27(
            stage_plan
        )
        phases = (
            "result-arena:directory-created",
            "result-arena:parent-fsynced",
            "result-arena:operation-lock-created",
            "result-arena:operation-lock-fsynced",
            "result-arena:directory-fsynced",
        )
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                runtime_root = Path(name).resolve()
                runtime_root.chmod(0o700)

                def crash(observed: str) -> None:
                    if observed == phase:
                        raise SystemExit(observed)

                with self.assertRaises(SystemExit), mock.patch.object(
                    boundary, "try_operation_lock_v27", return_value=("acquired", 0)
                ):
                    boundary.prepare_native_stage_result_arena_v27(
                        manifest,
                        stage_plan,
                        key,
                        runtime_root=runtime_root,
                        phase_hook=crash,
                    )
                with mock.patch.object(
                    boundary, "try_operation_lock_v27", return_value=("acquired", 0)
                ):
                    prepared = boundary.prepare_native_stage_result_arena_v27(
                        manifest, stage_plan, key, runtime_root=runtime_root
                    )
                controller_key = b"controller-only-arena-key-material-32"
                envelope = controller._controller_result_arena_envelope_v27(
                    prepared, stage_plan, key, controller_key
                )
                arena_sha = boundary.persist_controller_result_arena_v27(
                    manifest,
                    stage_plan,
                    envelope,
                    runtime_root=runtime_root,
                )
                self.assertEqual(
                    boundary.sha256(boundary.canonical_bytes(envelope)), arena_sha
                )
                result_path = boundary._native_stage_result_path_v27(
                    stage_plan, runtime_root=runtime_root
                )
                self.assertTrue((result_path / "operation.lock").is_file())
                self.assertEqual(
                    boundary.canonical_bytes(envelope),
                    (result_path / "arena.json").read_bytes(),
                )

    def test_native_creator_artifacts_join_controller_signed_roots(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        manifest, plan = self.ordinary_plan()
        local = self.stage_executor([])
        verified_bindings: list[dict[str, object]] = []

        def executor(stage_manifest, effect_plan, stage):
            if stage.location != 5:
                return local(stage_manifest, effect_plan, stage)
            handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
            self.assertTrue(callable(handler))
            stage_plan = boundary.derive_native_stage_action_plan_v27(
                stage_manifest, effect_plan, stage
            )
            assert stage_plan is not None
            handler.bind_native_stage_authority_v27(stage_plan)
            observations: dict[tuple[str, str], dict[str, object]] = {}
            roots = None
            common = None
            creator_chain = None
            prepared_lifetime_after = None
            for event in boundary._SUCCESS_NATIVE_EVENTS_V27:
                for phase in ("before", "after"):
                    observation = (
                        dict(prepared_lifetime_after)
                        if event == "creator-lifetime-closed"
                        and phase == "after"
                        and prepared_lifetime_after is not None
                        else dict(
                            boundary._reference_native_event_observation_v27(
                                event, phase
                            )
                        )
                    )
                    if event in {
                        "creator-creation-consumed",
                        "native-creator-created",
                    }:
                        observation["creatorPlanSha256"] = stage_plan[
                            "stagePlanSha256"
                        ]
                    if event == "creator-lifetime-closed" and phase == "before":
                        self.assertIsNotNone(roots)
                        assert roots is not None
                        common = {
                            **roots,
                            "capturePreparationSha256": observations[
                                ("creator-return-ready", "before")
                            ]["capturePreparationSha256"],
                            "creationNonceSha256": observations[
                                ("creator-creation-consumed", "before")
                            ]["creationNonceSha256"],
                            "creatorHandleConsumed": True,
                            "joinOwnerTokenSha256": observations[
                                ("creator-return-ready", "before")
                            ]["joinOwnerTokenSha256"],
                            "operationId": stage_plan["operationId"],
                            "requestKeyId": stage_plan["requestKeyId"],
                            "returnSentinel": "creator-positive-sentinel",
                            "slotGeneration": 1,
                            "stageLocation": stage_plan["stageLocation"],
                            "stagePlanSha256": stage_plan[
                                "stagePlanSha256"
                            ],
                            "taskSetSha256": observation["taskSetSha256"],
                        }
                        prepared_lifetime_after = dict(
                            boundary._reference_native_event_observation_v27(
                                event, "after"
                            )
                        )
                        creator_chain = self.native_creator_artifact_chain(
                            stage_plan, key, common_overrides=common,
                            lifetime_before=observation,
                            lifetime_after=prepared_lifetime_after,
                        )
                        artifact_digests = [
                            boundary.sha256(raw)
                            for _filename, raw in creator_chain
                        ]
                        for target in (observation, prepared_lifetime_after):
                            target.update(
                                {
                                    "atomicCaptureSha256": artifact_digests[0],
                                    "joinResultSha256": artifact_digests[1],
                                    "postReturnObservationSha256": (
                                        artifact_digests[2]
                                    ),
                                    "lifetimeRecordSha256": artifact_digests[3],
                                }
                            )
                        prepared_lifetime_after[
                            "allocationGateReleaseReceiptSha256"
                        ] = artifact_digests[4]
                    observations[(event, phase)] = observation
                    sequence = len(observations)
                    handler(
                        event,
                        phase,
                        boundary._native_event_evidence_v27(
                            stage_plan_sha256=stage_plan["stagePlanSha256"],
                            sequence=sequence,
                            event=event,
                            phase=phase,
                            observation=observation,
                        ),
                        observation,
                    )
                    if event == "creator-return-ready" and phase == "before":
                        roots = handler.creator_capture_binding_v27()
            self.assertIsNotNone(roots)
            assert roots is not None
            self.assertIsNotNone(common)
            self.assertIsNotNone(creator_chain)
            assert common is not None
            assert creator_chain is not None

            def reopen(overrides=None, chain_override=None):
                chain = (
                    chain_override or creator_chain
                    if not overrides
                    else self.native_creator_artifact_chain(
                        stage_plan, key,
                        common_overrides={**common, **overrides},
                        lifetime_before=observations[
                            ("creator-lifetime-closed", "before")
                        ],
                        lifetime_after=observations[
                            ("creator-lifetime-closed", "after")
                        ],
                    )
                )
                with tempfile.TemporaryDirectory() as artifact_name:
                    artifact_root = Path(artifact_name)
                    for filename, raw in chain:
                        (artifact_root / filename).write_bytes(raw)
                        (artifact_root / filename).chmod(0o600)
                    descriptor = os.open(
                        artifact_root, os.O_RDONLY | os.O_DIRECTORY
                    )
                    try:
                        return boundary._reopen_native_creator_artifacts_v27(
                            descriptor,
                            key,
                            stage_plan,
                            {filename for filename, _raw in chain},
                            return_binding=True,
                        )["binding"]
                    finally:
                        os.close(descriptor)

            reopened = reopen()
            handler.verify_creator_artifact_binding_v27(reopened, "success")
            verified_bindings.append(reopened)
            self.assertEqual(5, len(reopened["artifactDigests"]))
            self.assertEqual(
                {
                    "creatorTidPresent": True,
                    "creatorTid": observations[
                        ("creator-lifetime-closed", "before")
                    ]["creatorTid"],
                    "creatorStartTicksPresent": True,
                    "creatorStartTicks": observations[
                        ("creator-lifetime-closed", "before")
                    ]["creatorStartTicks"],
                },
                reopened["creatorIdentity"],
            )
            self.assertEqual(
                {
                    "atomicCapture", "joinResult", "postReturnObservation",
                    "lifetime", "gateReleaseReceipt",
                },
                {
                    field
                    for field in reopened
                    if field in {
                        "atomicCapture", "joinResult",
                        "postReturnObservation", "lifetime",
                        "gateReleaseReceipt",
                    }
                },
            )
            common_mutations = {
                "capturePreparationRecordSha256": raw_sha(b"foreign-capture-root"),
                "returnAuthorizationRecordSha256": raw_sha(b"foreign-auth-root"),
                "creatorReturnCurrentRecordSha256": raw_sha(b"foreign-current"),
                "capturePreparationSha256": raw_sha(b"foreign-capture-prep"),
                "creationNonceSha256": raw_sha(b"foreign-creation-nonce"),
                "joinOwnerTokenSha256": raw_sha(b"foreign-join-owner"),
                "taskSetSha256": raw_sha(b"foreign-task-set"),
                "creatorHandleConsumed": False,
                "operationId": "f" * 64,
                "requestKeyId": raw_sha(b"foreign-request-key"),
                "returnSentinel": "creator-abort-sentinel",
                "slotGeneration": 2,
                "stageLocation": int(stage_plan["stageLocation"]) + 1,
                "stagePlanSha256": raw_sha(b"foreign-stage-plan"),
            }
            self.assertEqual(14, len(common_mutations))
            for field, replacement in common_mutations.items():
                with self.subTest(controller_root_mutation=field), \
                     self.assertRaises(boundary.NativeBoundaryV27Error):
                    handler.verify_creator_artifact_binding_v27(
                        reopen({field: replacement}),
                        "success",
                    )

            def alternate(value):
                if type(value) is bool:
                    return not value
                if type(value) is int:
                    return value + 1
                if isinstance(value, str):
                    if value.startswith("sha256:"):
                        return raw_sha(("mutated-" + value).encode())
                    if value == "creator-positive-sentinel":
                        return "creator-abort-sentinel"
                    if value.isdigit():
                        return str(int(value) + 1)
                    return value + "-changed"
                self.fail(f"no hostile replacement for {value!r}")

            hostile_leaf_count = 0
            for sequence, (_filename, raw) in enumerate(creator_chain):
                payload = json.loads(raw)["artifact"]["payload"]
                for field, value in payload.items():
                    hostile_leaf_count += 1
                    with self.subTest(
                        artifact_sequence=sequence, security_leaf=field
                    ):
                        mutated_chain = self.mutate_native_creator_artifact_chain(
                            creator_chain, key, sequence=sequence,
                            field=field, replacement=alternate(value),
                        )
                        try:
                            mutated = reopen(chain_override=mutated_chain)
                        except boundary.NativeBoundaryV27Error:
                            continue
                        self.assertNotEqual(
                            boundary.sha256(boundary.canonical_bytes(reopened)),
                            boundary.sha256(boundary.canonical_bytes(mutated)),
                        )
                        with self.assertRaises(boundary.NativeBoundaryV27Error):
                            handler.verify_creator_artifact_binding_v27(
                                mutated, "success"
                            )
            self.assertEqual(43, hostile_leaf_count)

            result = {
                "exitCode": 0,
                "placementMask": 63,
                "stdout": b"{}",
                "stderr": b"",
                "lifecycle": list(boundary._EFFECT_LIFECYCLE),
                "resultKind": "success",
                "resultPredecessorKind": (
                    "creator-lifetime-closed-positive"
                ),
                "failureEvidenceSha256": None,
            }
            decoded = boundary._decode_native_stage_result_v27(
                result, require_discriminants=True
            )
            handler.authorize_result_offer(decoded)
            handler.receipt_result_handoff(decoded)
            handler.terminalize_result_handoff(self.retirement_receipt())
            return {
                "evidenceSha256": stage_plan["stagePlanSha256"],
                "observation": decoded,
                "terminalObservation": None,
                "resultKind": "success",
                "resultPredecessorKind": (
                    "creator-lifetime-closed-positive"
                ),
                "failureEvidenceSha256": None,
            }

        with tempfile.TemporaryDirectory() as name:
            boundary.execute_literal_stage_schedule_v27(
                Path(name),
                key,
                manifest,
                plan,
                action_executor=executor,
                end_location=5,
                require_native_events=True,
            )
        self.assertEqual(1, len(verified_bindings))

    def test_fd10_fixed_temps_promote_only_authenticated_full_terminal(self) -> None:
        key = bytes(range(32))
        manifest, effect_plan = self.ordinary_plan()
        stage = next(
            row for row in boundary.literal_stage_schedule_v27("ordinary")
            if row.stage_kind == "payload-terminal"
        )
        stage_plan = boundary.derive_native_stage_action_plan_v27(
            manifest, effect_plan, stage
        )
        assert stage_plan is not None
        stage_plan = {
            **stage_plan,
            "requestKeyId": boundary.sha256(key),
            "stagePlanSha256": None,
        }
        stage_plan["stagePlanSha256"] = boundary._native_stage_plan_digest_v27(
            stage_plan
        )
        result = {
            "exitCode": 0,
            "placementMask": 63,
            "lifecycle": list(boundary._EFFECT_LIFECYCLE),
            "stderrBase64": "",
            "stdoutBase64": "e30=",
            "resultKind": "success",
            "resultPredecessorKind": "creator-lifetime-closed-positive",
            "failureEvidenceSha256": None,
        }
        result_raw = boundary.canonical_bytes(result)
        envelope = boundary.canonical_bytes(
            {
                "requestKeyId": boundary.sha256(key),
                "result": result,
                "resultHmac": "hmac-sha256:" + hmac.new(
                    key,
                    b"startup-factory/beads/v27/result\0" + result_raw,
                    hashlib.sha256,
                ).hexdigest(),
            }
        ) + b"\n"
        with tempfile.TemporaryDirectory() as name:
            runtime_root = Path(name).resolve()
            runtime_root.chmod(0o700)
            result_path = self.prepare_arena(
                manifest, stage_plan, key, runtime_root
            )
            for filename, artifact in self.native_creator_artifact_chain(
                stage_plan, key
            ):
                (result_path / filename).write_bytes(artifact)
                (result_path / filename).chmod(0o600)
            (result_path / ".result.json.tmp").write_bytes(envelope)
            (result_path / ".result.json.tmp").chmod(0o600)
            lock_seen = False
            real_listdir = os.listdir

            def acquired(_descriptor: int) -> tuple[str, int]:
                nonlocal lock_seen
                lock_seen = True
                return "acquired", 0

            def listed(path) -> list[str]:
                self.assertTrue(lock_seen)
                return real_listdir(path)

            with mock.patch.object(
                boundary, "try_operation_lock_v27", side_effect=acquired
            ), mock.patch.object(boundary.os, "listdir", side_effect=listed):
                recovered = boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )
            self.assertEqual(63, recovered["placementMask"])
            self.assertEqual(
                {"arena", "intent", "receipt"},
                set(recovered["_controllerRetirementChain"]),
            )
            self.assertTrue((result_path / "result.json").is_file())
            self.assertFalse((result_path / ".result.json.tmp").exists())

            (result_path / "result.json").unlink()
            partial = envelope[: len(envelope) // 2]
            (result_path / ".result.json.tmp").write_bytes(partial)
            (result_path / ".result.json.tmp").chmod(0o600)
            with mock.patch.object(
                boundary, "try_operation_lock_v27", return_value=("acquired", 0)
            ):
                loss = boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )
            self.assertEqual(
                "dead-holder-without-terminal",
                loss["nativeSupervisorLoss"]["reason"],
            )
            self.assertEqual(
                partial, (result_path / ".result.json.tmp").read_bytes()
            )
            (result_path / ".result.json.tmp").unlink()
            for filename, _artifact in self.native_creator_artifact_chain(
                stage_plan, key
            ):
                (result_path / filename).unlink()
            lock = (result_path / "operation.lock").stat()
            disposition = {
                "disposition": "controller-lost-payload-drained",
                "operationId": stage_plan["operationId"],
                "operationLock": {
                    "device": lock.st_dev,
                    "gid": lock.st_gid,
                    "inode": lock.st_ino,
                    "mode": "0600",
                    "nlink": 1,
                    "uid": lock.st_uid,
                },
                "requestKeyId": boundary.sha256(key),
                "schemaVersion": 27,
                "stageLocation": stage_plan["stageLocation"],
                "stagePlanSha256": stage_plan["stagePlanSha256"],
            }
            disposition_raw = boundary.canonical_bytes(disposition)
            disposition_envelope = boundary.canonical_bytes(
                {
                    "disposition": disposition,
                    "dispositionHmac": "hmac-sha256:" + hmac.new(
                        key,
                        b"startup-factory/beads/v27/disposition\0"
                        + disposition_raw,
                        hashlib.sha256,
                    ).hexdigest(),
                }
            ) + b"\n"
            (result_path / ".disposition.json.tmp").write_bytes(
                disposition_envelope
            )
            (result_path / ".disposition.json.tmp").chmod(0o600)
            with mock.patch.object(
                boundary, "try_operation_lock_v27", return_value=("acquired", 0)
            ):
                loss = boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )
            self.assertEqual(
                "authenticated-controller-loss",
                loss["nativeSupervisorLoss"]["reason"],
            )
            self.assertTrue((result_path / "disposition.json").is_file())
            self.assertFalse((result_path / ".disposition.json.tmp").exists())

            (result_path / "disposition.json").unlink()
            (result_path / "result.json").write_bytes(envelope)
            (result_path / "result.json").chmod(0o600)
            (result_path / ".result.json.tmp").write_bytes(envelope)
            (result_path / ".result.json.tmp").chmod(0o600)
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "conflicts"
            ), mock.patch.object(
                boundary, "try_operation_lock_v27", return_value=("acquired", 0)
            ):
                boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )
            self.assertTrue((result_path / "result.json").is_file())
            self.assertTrue((result_path / ".result.json.tmp").is_file())

    def test_fd10_terminal_xor_authenticates_disposition_or_dead_holder_loss(self) -> None:
        key = bytes(range(32))
        key_id = boundary.sha256(key)
        manifest, effect_plan = self.ordinary_plan()
        stage = next(
            row for row in boundary.literal_stage_schedule_v27("ordinary")
            if row.stage_kind == "payload-terminal"
        )
        stage_plan = boundary.derive_native_stage_action_plan_v27(
            manifest, effect_plan, stage
        )
        assert stage_plan is not None
        stage_plan = {
            **stage_plan,
            "requestKeyId": key_id,
            "stagePlanSha256": None,
        }
        stage_plan["stagePlanSha256"] = boundary._native_stage_plan_digest_v27(
            stage_plan
        )
        with tempfile.TemporaryDirectory() as name:
            runtime_root = Path(name).resolve()
            runtime_root.chmod(0o700)
            result_path = self.prepare_arena(
                manifest, stage_plan, key, runtime_root
            )
            lock_path = result_path / "operation.lock"
            lock = lock_path.stat()
            disposition = {
                "disposition": "controller-lost-payload-drained",
                "operationId": stage_plan["operationId"],
                "operationLock": {
                    "device": lock.st_dev,
                    "gid": lock.st_gid,
                    "inode": lock.st_ino,
                    "mode": "0600",
                    "nlink": 1,
                    "uid": lock.st_uid,
                },
                "requestKeyId": key_id,
                "schemaVersion": 27,
                "stageLocation": stage_plan["stageLocation"],
                "stagePlanSha256": stage_plan["stagePlanSha256"],
            }
            raw = boundary.canonical_bytes(disposition)
            envelope = boundary.canonical_bytes(
                {
                    "disposition": disposition,
                    "dispositionHmac": "hmac-sha256:" + hmac.new(
                        key,
                        b"startup-factory/beads/v27/disposition\0" + raw,
                        hashlib.sha256,
                    ).hexdigest(),
                }
            ) + b"\n"
            disposition_path = result_path / "disposition.json"
            disposition_path.write_bytes(envelope)
            disposition_path.chmod(0o600)
            with mock.patch.object(
                boundary, "try_operation_lock_v27", return_value=("acquired", 0)
            ):
                loss = boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )
            self.assertTrue(boundary._is_native_supervisor_loss_v27(loss))
            self.assertEqual(
                "authenticated-controller-loss",
                loss["nativeSupervisorLoss"]["reason"],
            )

            hostile_envelopes = (
                b'{"disposition":}\n',
                envelope.replace(b"hmac-sha256:", b"hmac-sha256:0", 1),
            )
            for hostile in hostile_envelopes:
                with self.subTest(hostile=hostile[:24]):
                    disposition_path.write_bytes(hostile)
                    with self.assertRaises(boundary.NativeBoundaryV27Error), mock.patch.object(
                        boundary, "try_operation_lock_v27", return_value=("acquired", 0)
                    ):
                        boundary.recover_durable_native_stage_result_v27(
                            manifest, stage_plan, key, runtime_root=runtime_root
                        )
            disposition_path.write_bytes(envelope)

            result = {
                "exitCode": 0,
                "placementMask": 63,
                "lifecycle": list(boundary._EFFECT_LIFECYCLE),
                "stderrBase64": "",
                "stdoutBase64": "e30=",
                "resultKind": "success",
                "resultPredecessorKind": "creator-lifetime-closed-positive",
                "failureEvidenceSha256": None,
            }
            result_raw = boundary.canonical_bytes(result)
            (result_path / "result.json").write_bytes(
                boundary.canonical_bytes(
                    {
                        "requestKeyId": key_id,
                        "result": result,
                        "resultHmac": "hmac-sha256:" + hmac.new(
                            key,
                            b"startup-factory/beads/v27/result\0" + result_raw,
                            hashlib.sha256,
                        ).hexdigest(),
                    }
                ) + b"\n"
            )
            (result_path / "result.json").chmod(0o600)
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "terminal XOR"
            ), mock.patch.object(
                boundary, "try_operation_lock_v27", return_value=("acquired", 0)
            ):
                boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )

            (result_path / "result.json").unlink()
            disposition_path.unlink()
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "lock is unavailable"
            ), mock.patch.object(
                boundary, "try_operation_lock_v27", return_value=("held", 4242)
            ):
                boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )
            with mock.patch.object(
                boundary, "try_operation_lock_v27", return_value=("acquired", 0)
            ):
                loss = boundary.recover_durable_native_stage_result_v27(
                    manifest, stage_plan, key, runtime_root=runtime_root
                )
            self.assertEqual(
                "dead-holder-without-terminal",
                loss["nativeSupervisorLoss"]["reason"],
            )

    def test_authenticated_fd10_loss_installs_one_quarantine_cas_without_replay(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            calls: list[tuple[int, str]] = []
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27(
                    "location-5-launch-consumed-current"
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        root,
                        key,
                        manifest,
                        plan,
                        action_executor=self.stage_executor(calls),
                    )
            recovered = boundary._native_supervisor_loss_v27(
                reason="authenticated-controller-loss",
                evidence_sha256=raw_sha(b"authenticated disposition"),
            )
            recovered["controllerRetirement"] = {
                "schemaVersion": 27,
                "visibleDescendants": 6,
                "placementMask": 63,
                "controllerTrackedPlacementMask": 63,
                "initControllers": [],
                "preRemovalCgroupStat": {
                    "nr_descendants": 6,
                    "nr_dying_descendants": 0,
                },
                "terminalCgroupStat": {
                    "nr_descendants": 0,
                    "nr_dying_descendants": 0,
                },
            }
            attempts = 0

            def recover_stage(_manifest, _plan, _stage):
                nonlocal attempts
                attempts += 1
                return recovered

            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "unresolved terminal"
            ):
                boundary.execute_literal_stage_schedule_v27(
                    root,
                    key,
                    manifest,
                    plan,
                    action_executor=self.stage_executor(calls),
                    action_recovery=recover_stage,
                )
            current = boundary.inspect_supervised_effect_v27(
                root, key, plan["operationId"]
            )
            self.assertEqual(
                "UnresolvedTerminalCurrentV3", current["kind"]
            )
            self.assertEqual(
                raw_sha(b"authenticated disposition"),
                current["payload"]["lossEvidenceSha256"],
            )
            history = root / "native-effects-v27" / plan["operationId"] / "history"
            count = len(tuple(history.glob("*.json")))
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "cannot replay"
            ):
                boundary.execute_literal_stage_schedule_v27(
                    root,
                    key,
                    manifest,
                    plan,
                    action_executor=self.stage_executor(calls),
                    action_recovery=recover_stage,
                )
            self.assertEqual(1, attempts)
            self.assertEqual(count, len(tuple(history.glob("*.json"))))

    def test_late_disable_after_signal_uses_authenticated_unresolved_crash_chain(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        retirement = {
            "schemaVersion": 27,
            "visibleDescendants": 6,
            "placementMask": 63,
            "controllerTrackedPlacementMask": 63,
            "initControllers": [],
            "preRemovalCgroupStat": {
                "nr_descendants": 6,
                "nr_dying_descendants": 0,
            },
            "terminalCgroupStat": {
                "nr_descendants": 0,
                "nr_dying_descendants": 0,
            },
        }
        recovered = boundary._native_supervisor_loss_v27(
            reason="authenticated-controller-loss",
            evidence_sha256=raw_sha(b"late-disable-disposition"),
        )
        recovered["controllerRetirement"] = retirement
        phases = (
            "location-5-authenticated-supervisor-loss-written",
            "location-5-unresolved-drain-pending",
            "location-5-unresolved-drain-proved",
        )
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                calls: list[tuple[int, str]] = []

                def cutoff_executor(_manifest, _plan, stage):
                    calls.append((stage.location, stage.stage_key))
                    value = self.stage_executor([])(_manifest, _plan, stage)
                    if stage.stage_kind != "payload-terminal":
                        return value
                    handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
                    self.assertTrue(callable(handler))
                    for sequence, event in enumerate(
                        boundary._SUCCESS_NATIVE_EVENTS_V27[:7], 1
                    ):
                        evidence = raw_sha(
                            f"late-disable:{sequence}:{event}".encode()
                        )
                        handler(
                            event, "before", evidence,
                            boundary._reference_native_event_observation_v27(
                                event, "before"
                            ),
                        )
                        handler(
                            event, "after", evidence,
                            boundary._reference_native_event_observation_v27(
                                event, "after"
                            ),
                        )
                    raise RuntimeError("controller disabled after release cutoff")

                with self.assertRaisesRegex(RuntimeError, "release cutoff"):
                    boundary.execute_literal_stage_schedule_v27(
                        root,
                        key,
                        manifest,
                        plan,
                        action_executor=cutoff_executor,
                        require_native_events=True,
                    )
                before = boundary.inspect_supervised_effect_v27(
                    root, key, plan["operationId"]
                )
                self.assertEqual("SignalAttemptConsumedCurrentV1", before["kind"])

                attempts = 0

                def recover_stage(_manifest, _plan, _stage):
                    nonlocal attempts
                    attempts += 1
                    return recovered

                with self.assertRaises(SystemExit), boundary.inject_native_effect_fault_v27(
                    phase
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        root,
                        key,
                        manifest,
                        plan,
                        action_executor=cutoff_executor,
                        action_recovery=recover_stage,
                        require_native_events=True,
                    )
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error, "unresolved terminal"
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        root,
                        key,
                        manifest,
                        plan,
                        action_executor=cutoff_executor,
                        action_recovery=recover_stage,
                        require_native_events=True,
                    )
                current = boundary.inspect_supervised_effect_v27(
                    root, key, plan["operationId"]
                )
                self.assertEqual("UnresolvedTerminalCurrentV3", current["kind"])
                self.assertEqual(63, current["payload"]["placementMask"])
                self.assertEqual(
                    raw_sha(boundary.canonical_bytes(retirement)),
                    current["payload"]["controllerRetirementSha256"],
                )
                history_root = (
                    root
                    / "native-effects-v27"
                    / plan["operationId"]
                    / "history"
                )
                unresolved = sorted(
                    (
                        json.loads(path.read_bytes())
                        for path in history_root.glob("*.json")
                        if json.loads(path.read_bytes())["kind"]
                        in {
                            "UnresolvedDrainPendingCurrentV1",
                            "UnresolvedDrainProvedCurrentV3",
                            "UnresolvedTerminalCurrentV3",
                        }
                    ),
                    key=lambda item: item["payload"]["generation"],
                )
                self.assertEqual(
                    [
                        "UnresolvedDrainPendingCurrentV1",
                        "UnresolvedDrainProvedCurrentV3",
                        "UnresolvedTerminalCurrentV3",
                    ],
                    [item["kind"] for item in unresolved],
                )
                for predecessor, successor in zip(unresolved, unresolved[1:]):
                    self.assertEqual(
                        predecessor["payload"]["generation"] + 1,
                        successor["payload"]["generation"],
                    )
                    self.assertEqual(
                        predecessor["recordSha256"],
                        successor["payload"]["predecessorRecordSha256"],
                    )
                    for field in (
                        "lossReason", "lossEvidenceSha256",
                        "lossEvidenceRecordSha256",
                        "controllerRetirementSha256", "placementMask",
                    ):
                        self.assertEqual(
                            predecessor["payload"][field],
                            successor["payload"][field],
                        )
                self.assertNotIn(
                    "SupervisorOuterLossQuarantinedCurrentV4",
                    {
                        json.loads(path.read_bytes())["kind"]
                        for path in (
                            root
                            / "native-effects-v27"
                            / plan["operationId"]
                            / "history"
                        ).glob("*.json")
                    },
                )
                self.assertEqual(2 if phase.endswith("written") else 1, attempts)
                self.assertEqual(1, sum(1 for location, _ in calls if location == 5))
                history_count = len(tuple(history_root.glob("*.json")))
                recovery_attempts = attempts
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error,
                    "non-public unresolved terminal",
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        root,
                        key,
                        manifest,
                        plan,
                        action_executor=cutoff_executor,
                        action_recovery=recover_stage,
                        require_native_events=True,
                    )
                self.assertEqual(history_count, len(tuple(history_root.glob("*.json"))))
                self.assertEqual(recovery_attempts, attempts)

    def test_literal_schedules_are_contiguous_and_action_specific(self) -> None:
        expected_tails = {
            "claim-cas": [
                "after-observation-a", "after-observation-b",
                "checkpoint-candidate-stored", "repository-current-cas",
                "public-result-stored", "combined-terminal-receipt-stored",
                "operation-done",
            ],
            "ordinary": [
                "after-observation-a", "after-observation-b",
                "checkpoint-candidate-stored", "repository-current-cas",
                "public-result-stored", "combined-terminal-receipt-stored",
                "operation-done",
            ],
            "receipt-comment": [
                "after-observation-a", "after-observation-b",
                "checkpoint-candidate-stored", "repository-current-cas",
                "claim-receipt-comment-stored", "public-result-stored",
                "combined-terminal-receipt-stored", "operation-done",
            ],
            "create-preparation": [
                "installation-intent-stored", "stage-identity-reopened",
                "host-install-transition", "installed-identity-observed",
                "host-cleanup-retired", "after-observation-a",
                "after-observation-b", "checkpoint-candidate-stored",
                "repository-current-cas", "preparation-receipt-stored",
                "preparation-done",
            ],
            "reattest-preparation": [
                "selector-store-reopened", "after-observation-a",
                "after-observation-b", "predecessor-checkpoint-reopened",
                "checkpoint-candidate-stored", "candidate-current-intent-stored",
                "repository-current-cas", "cas-receipt-stored",
                "activation-receipt-stored", "fresh-current-verified",
                "preparation-done",
            ],
        }
        for operation_class, done in boundary.DONE_LOCATIONS_V27.items():
            with self.subTest(operation_class=operation_class):
                schedule = boundary.literal_stage_schedule_v27(operation_class)
                self.assertEqual(done, len(schedule))
                self.assertEqual(list(range(1, done + 1)), [row.location for row in schedule])
                self.assertEqual(expected_tails[operation_class], [row.stage_kind for row in schedule[-len(expected_tails[operation_class]):]])
                self.assertEqual(len(schedule), len({row.stage_key for row in schedule}))
                self.assertTrue(all(row.action_kind != "synthetic" for row in schedule))

    def manifest(self):
        value = json.loads(
            (ROOT / "runtime/beads-native-boundary-v27.example.json").read_bytes()
        )
        return boundary.parse_native_boundary_manifest_v27(value)

    @staticmethod
    def stage_executor(calls: list[tuple[int, str]]):
        def execute(_manifest, _plan, stage):
            calls.append((stage.location, stage.stage_key))
            terminal = None
            if stage.stage_kind in {"operation-done", "preparation-done"}:
                if _plan["operationClass"] in {
                    "create-preparation", "reattest-preparation"
                }:
                    stages = (
                        [
                            "binary-proof-payload-terminal",
                            "initialize-payload-terminal",
                            "status-write-payload-terminal",
                            "status-read-payload-terminal",
                        ]
                        if _plan["operationClass"] == "create-preparation"
                        else ["status-read-payload-terminal"]
                    )
                    terminal = {
                        "schemaVersion": 27,
                        "profile": boundary.PROFILE,
                        "preparationState": "sequence-completed",
                        "operationClass": _plan["operationClass"],
                        "commandCount": len(stages),
                        "commandStages": stages,
                        "commandResultsSha256": [
                            raw_sha(stage_key.encode("utf-8"))
                            for stage_key in stages
                        ],
                        "observedByNativeSupervisor": True,
                    }
                else:
                    reads = NativeStagePlanV27Test.reader_outputs()
                    terminal = {
                        "nativeObservation": {
                            "exitCode": 0,
                            "stdoutSha256": raw_sha(b'{"id":"task-1"}\n'),
                            "stderrSha256": raw_sha(b""),
                            "readBackSha256": raw_sha(b"joined-read-back"),
                            "readBackProjection": {
                                "id": "task-1",
                                "revision": "2026-08-24T16:35:03Z",
                                "status": "in_progress",
                            },
                            "readBacksSha256": [raw_sha(item) for item in reads],
                            "physicalEqualityPasses": [True, True],
                            "repeatabilityPasses": [True] * 6,
                            "repeatabilityEvidenceSha256": raw_sha(
                                b"repeatability"
                            ),
                            "rollingJoinPasses": [True] * 5,
                            "rollingJoinEvidenceSha256": raw_sha(
                                b"rolling-joins"
                            ),
                            "crossWindowNoEffect": True,
                            "crossWindowNoEffectEvidenceSha256": raw_sha(
                                b"cross-window"
                            ),
                            "independentReadCount": 4,
                            "lifecycle": list(boundary._EFFECT_LIFECYCLE),
                            "observedByNativeSupervisor": True,
                        }
                    }
            return {
                "evidenceSha256": raw_sha(f"{stage.location}:{stage.stage_key}".encode()),
                "observation": {"stageKey": stage.stage_key},
                "terminalObservation": terminal,
            }
        return execute

    def ordinary_plan(
        self,
        repository_path: str = "/srv/startup-factory/repositories/repository-1",
    ):
        manifest = self.manifest()
        return manifest, boundary.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="a" * 64,
            operation_class="ordinary",
            argv=["/usr/local/bin/bd", "update", "task-1", "--status", "active", "--json"],
            repository_path=repository_path,
        )

    def claim_plan(
        self,
        repository_path: str = "/srv/startup-factory/repositories/repository-1",
    ):
        manifest = self.manifest()
        return manifest, boundary.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="e" * 64,
            operation_class="claim-cas",
            argv=["/usr/local/bin/bd", "update", "task-1", "--status", "active", "--json"],
            repository_path=repository_path,
        )

    def receipt_comment_plan(
        self,
        repository_path: str = "/srv/startup-factory/repositories/repository-1",
    ):
        manifest = self.manifest()
        return manifest, boundary.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="f" * 64,
            operation_class="receipt-comment",
            argv=["/usr/local/bin/bd", "comments", "add", "task-1", "receipt", "--json"],
            repository_path=repository_path,
        )

    def create_preparation_plan(
        self,
        repository_path: str = "/srv/startup-factory/preparation/sequence-1",
    ):
        manifest = self.manifest()
        commands = [
            ["/usr/local/bin/bd", "version", "--json"],
            ["/usr/local/bin/bd", "--db", "/workspace/db", "--json", "--sandbox", "init"],
            ["/usr/local/bin/bd", "--db", "/workspace/db", "--json", "--sandbox", "config", "set", "status.custom", "open"],
            ["/usr/local/bin/bd", "--db", "/workspace/db", "--json", "--sandbox", "config", "list"],
        ]
        return manifest, boundary.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="c" * 64,
            operation_class="create-preparation",
            argv=commands[0],
            repository_path=repository_path,
            preparation_commands=commands,
        )

    def reattest_preparation_plan(
        self,
        repository_path: str = "/srv/startup-factory/preparation/selector-1",
    ):
        manifest = self.manifest()
        command = [
            "/usr/local/bin/bd", "--db", "/workspace/db", "--json",
            "--sandbox", "config", "list",
        ]
        return manifest, boundary.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="d" * 64,
            operation_class="reattest-preparation",
            argv=command,
            repository_path=repository_path,
            preparation_commands=[command],
        )

    def test_named_engine_runs_each_action_once_and_writes_no_future_row(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        calls: list[tuple[int, str]] = []
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27("location-73-intent-current"):
                    boundary.execute_literal_stage_schedule_v27(
                        root, key, manifest, plan,
                        action_executor=self.stage_executor(calls),
                    )
            current = boundary.inspect_supervised_effect_v27(root, key, plan["operationId"])
            self.assertEqual((73, "intent-current"), (
                current["payload"]["location"], current["payload"]["state"]
            ))
            history = root / "native-effects-v27" / plan["operationId"] / "history"
            self.assertLessEqual(
                max(json.loads(path.read_bytes())["payload"]["location"] for path in history.glob("*.json")),
                73,
            )
            result = boundary.execute_literal_stage_schedule_v27(
                root, key, manifest, plan,
                action_executor=self.stage_executor(calls),
                action_recovery=self.stage_executor(calls),
            )
            self.assertEqual(0, result["exitCode"])
            self.assertEqual(
                list(range(1, 77)),
                [location for location, _stage in calls],
            )
            repeated = boundary.execute_literal_stage_schedule_v27(
                root, key, manifest, plan,
                action_executor=self.stage_executor(calls),
            )
            self.assertEqual(result, repeated)
            self.assertEqual(76, len(calls))

    def test_production_history_uses_exact_named_outer_currents_before_done(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        calls: list[tuple[int, str]] = []
        expected_success_lineage = {
            "SupervisorLaunchSlotReservedCurrentV1",
            "SupervisorLaunchSlotConsumedCurrentV1",
            "SupervisorRunningCurrentV1",
            "SupervisorRunAuthorizationConsumedCurrentV1",
            "SupervisorRunAcknowledgedCurrentV1",
            "NativeCreatorCreatedCurrentV1",
            "SignalAttemptConsumedCurrentV1",
            "ReleaseIssuedCurrentV1",
            "ReleaseKnownLiveCurrentV1",
            "ReleaseTerminalCurrentV1",
            "CreatorReturnReadyCurrentV2",
            "CreatorLifetimeClosedCurrentV5",
            "SupervisorResultEnvelopeStoredCurrentV4",
            "SupervisorResultHandoffAttemptConsumedCurrentV4",
            "SupervisorResultHandoffReceiptedCurrentV4",
            "SupervisorTerminalReceiptStoredCurrentV4",
            "SupervisorTerminalCurrentV3",
        }
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            result = boundary.execute_literal_stage_schedule_v27(
                root,
                key,
                manifest,
                plan,
                action_executor=self.stage_executor(calls),
            )
            operation = root / "native-effects-v27" / plan["operationId"]
            history = [
                json.loads(path.read_bytes())
                for path in (operation / "history").glob("*.json")
            ]
            kinds = {record["kind"] for record in history}
            self.assertTrue(expected_success_lineage <= kinds)
            stage_states = {
                record["payload"]["state"]
                for record in history
                if record["kind"] == "StageCurrentV3"
            }
            self.assertEqual(
                {
                    "bootstrap-terminal",
                    "ready",
                    "intent-current",
                    "release-consumed-current",
                    "completion",
                },
                stage_states,
            )
            current = boundary.inspect_supervised_effect_v27(
                root, key, plan["operationId"]
            )
        self.assertEqual("StageCurrentV3", current["kind"])
        self.assertEqual((76, "completion"), (
            current["payload"]["location"], current["payload"]["state"]
        ))
        self.assertEqual(0, result["exitCode"])
        self.assertEqual(76, len(calls))

    def test_exact_schedule_vocabulary_and_current_domains_are_closed(self) -> None:
        expected_tail_kinds = {
            "receipt-comment": "claim-receipt-comment-stored",
            "create-preparation": (
                "installation-intent-stored",
                "stage-identity-reopened",
                "host-install-transition",
                "installed-identity-observed",
                "host-cleanup-retired",
            ),
            "reattest-preparation": (
                "selector-store-reopened",
                "predecessor-checkpoint-reopened",
                "fresh-current-verified",
            ),
        }
        receipt = boundary.literal_stage_schedule_v27("receipt-comment")
        self.assertEqual(
            expected_tail_kinds["receipt-comment"], receipt[73].stage_kind
        )
        create_kinds = {
            row.stage_kind
            for row in boundary.literal_stage_schedule_v27("create-preparation")
        }
        reattest_kinds = {
            row.stage_kind
            for row in boundary.literal_stage_schedule_v27("reattest-preparation")
        }
        self.assertTrue(set(expected_tail_kinds["create-preparation"]) <= create_kinds)
        self.assertTrue(set(expected_tail_kinds["reattest-preparation"]) <= reattest_kinds)
        self.assertEqual(
            set(boundary.CURRENT_UNION_V27),
            set(boundary.CURRENT_UNION_V27) & set(boundary.HMAC_DOMAINS_V27),
        )

    def test_all_five_native_result_kinds_reach_terminal_xor_and_failures_quarantine(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        predecessor = {
            "success": "creator-lifetime-closed-positive",
            "precreate-failed": "supervisor-precreate-failed",
            "create-failed-no-thread": "supervisor-create-failed-no-thread",
            "controlled-abort-failed": "creator-abort-failure-lifetime",
            "revoke-verified-no-effect": (
                "creator-lifetime-closed-revoke-verified-no-effect"
            ),
        }
        for result_kind, predecessor_kind in predecessor.items():
            with self.subTest(result_kind=result_kind), tempfile.TemporaryDirectory() as name:
                calls: list[tuple[int, str]] = []

                def execute(_manifest, _plan, stage):
                    calls.append((stage.location, stage.stage_key))
                    value = self.stage_executor([])(_manifest, _plan, stage)
                    if stage.stage_kind != "payload-terminal":
                        return value
                    handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
                    self.assertTrue(callable(handler))
                    for sequence, (_kind, event) in enumerate(
                        boundary._NATIVE_EVENT_CHAINS_V27[result_kind], 1
                    ):
                        evidence = raw_sha(
                            f"{stage.stage_key}:{sequence}:{event}".encode()
                        )
                        handler(
                            event, "before", evidence,
                            boundary._reference_native_event_observation_v27(
                                event, "before"
                            ),
                        )
                        handler(
                            event, "after", evidence,
                            boundary._reference_native_event_observation_v27(
                                event, "after"
                            ),
                        )
                    result = {
                        **value,
                        "resultKind": result_kind,
                        "resultPredecessorKind": predecessor_kind,
                        "failureEvidenceSha256": (
                            None if result_kind == "success"
                            else raw_sha(result_kind.encode("ascii"))
                        ),
                    }
                    observation = result["observation"]
                    if result_kind != "success":
                        observation["placementMask"] = 0
                    handler.authorize_result_offer(
                        {
                            "nativeResultSha256": raw_sha(
                                boundary.canonical_bytes(observation)
                            ),
                            "resultKind": result_kind,
                            "resultPredecessorKind": predecessor_kind,
                            "failureEvidenceSha256": result[
                                "failureEvidenceSha256"
                            ],
                        }
                    )
                    handler.receipt_result_handoff(observation)
                    handler.terminalize_result_handoff(
                        self.retirement_receipt(
                            63 if result_kind == "success" else 0
                        )
                    )
                    return result

                if result_kind == "success":
                    boundary.execute_literal_stage_schedule_v27(
                        Path(name), key, manifest, plan,
                        action_executor=execute,
                        require_native_events=True,
                    )
                else:
                    with self.assertRaisesRegex(
                        boundary.NativeBoundaryV27Error, "quarantined"
                    ):
                        boundary.execute_literal_stage_schedule_v27(
                            Path(name), key, manifest, plan,
                            action_executor=execute,
                            require_native_events=True,
                        )
                operation = Path(name) / "native-effects-v27" / plan["operationId"]
                objects = [
                    json.loads(path.read_bytes())
                    for path in (operation / "objects").glob("*.json")
                ]
                envelopes = [
                    item for item in objects
                    if item["kind"] == "SupervisorResultEnvelopeV4"
                ]
                expected_terminals = 5 if result_kind == "success" else 1
                self.assertEqual(expected_terminals, len(envelopes))
                self.assertEqual(
                    {result_kind},
                    {item["payload"]["resultKind"] for item in envelopes},
                )
                if result_kind == "create-failed-no-thread":
                    precreate = [
                        item for item in objects
                        if item["kind"] == "NativeCreatorPreCreateFailureV2"
                    ]
                    self.assertEqual(1, len(precreate))
                    self.assertFalse(precreate[0]["payload"]["createCalled"])
                    self.assertFalse(precreate[0]["payload"]["slotAllocated"])
                terminals = [
                    json.loads(path.read_bytes())
                    for path in (operation / "history").glob("*.json")
                    if json.loads(path.read_bytes())["kind"]
                    == "SupervisorTerminalCurrentV3"
                ]
                done_currents = [
                    json.loads(path.read_bytes())
                    for path in (operation / "history").glob("*.json")
                    if json.loads(path.read_bytes())["kind"] == "StageCurrentV3"
                    and json.loads(path.read_bytes())["payload"].get("state")
                    == "completion"
                    and json.loads(path.read_bytes())["payload"].get("location")
                    == 76
                ]
                self.assertEqual(expected_terminals, len(terminals))
                self.assertEqual(
                    "result-handoff-terminal",
                    terminals[0]["payload"]["terminalBranch"],
                )
                current = boundary.inspect_supervised_effect_v27(
                    Path(name), key, plan["operationId"]
                )
                if result_kind != "success":
                    self.assertEqual([], done_currents)
                    self.assertEqual(
                        "SupervisorOuterLossQuarantinedCurrentV4", current["kind"]
                    )
                    self.assertLess(current["payload"]["location"], 76)
                else:
                    self.assertEqual(1, len(done_currents))

    def test_launch_pre_effect_never_created_uses_terminal_xor_and_repairs_only(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        evidence = raw_sha(b"popen returned no process")
        phases = (
            "location-5-launch-pre-effect-failed",
            "location-5-supervisor-terminal",
            "location-5-outer-loss-drain-pending",
            "location-5-outer-loss-quarantined-current",
        )
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                calls: list[int] = []

                def execute(_manifest, _plan, stage):
                    calls.append(stage.location)
                    if stage.stage_kind == "payload-terminal":
                        handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
                        proof = {
                            "proof": {
                                "operationId": _plan["operationId"],
                                "stageLocation": stage.location,
                                "stagePlanSha256": evidence,
                                "consumedCurrentRecordSha256": handler.current[
                                    "recordSha256"
                                ],
                                "controllerRetirement": {"placementMask": 0},
                            },
                            "controllerHmac": "hmac-sha256:" + ("a" * 64),
                        }
                        raise boundary._NativeLaunchPreEffectFailedV27(
                            evidence, proof=proof
                        )
                    return self.stage_executor([])(_manifest, _plan, stage)

                with self.assertRaises(SystemExit), boundary.inject_native_effect_fault_v27(phase):
                    boundary.execute_literal_stage_schedule_v27(
                        Path(name), key, manifest, plan,
                        action_executor=execute,
                        require_native_events=True,
                    )
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error,
                    "quarantined|cannot replay",
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        Path(name), key, manifest, plan,
                        action_executor=execute,
                        require_native_events=True,
                    )
                operation = Path(name) / "native-effects-v27" / plan["operationId"]
                history = [
                    json.loads(path.read_bytes())
                    for path in (operation / "history").glob("*.json")
                ]
                terminals = [
                    item for item in history
                    if item["kind"] == "SupervisorTerminalCurrentV3"
                ]
                self.assertEqual(1, len(terminals))
                self.assertEqual(
                    "launch-pre-effect-never-created",
                    terminals[0]["payload"]["terminalBranch"],
                )
                self.assertRegex(
                    terminals[0]["payload"]["launchPreEffectFailedSha256"],
                    r"\Asha256:[0-9a-f]{64}\Z",
                )
                self.assertIsNone(
                    terminals[0]["payload"]["resultEnvelopeRecordSha256"]
                )
                self.assertEqual(
                    1,
                    sum(
                        json.loads(path.read_bytes())["kind"]
                        == "SupervisorLaunchPreEffectProofV1"
                        for path in (operation / "objects").glob("*.json")
                    ),
                )
                objects = [
                    json.loads(path.read_bytes())
                    for path in (operation / "objects").glob("*.json")
                ]
                self.assertFalse(any(
                    item["kind"] == "SupervisorResultEnvelopeV4"
                    for item in objects
                ))
                self.assertEqual(1, calls.count(5))

    def test_recovered_pre_effect_proof_swapped_from_another_consumed_current_is_unresolved(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        retirement = {
            "schemaVersion": 27,
            "visibleDescendants": 0,
            "placementMask": 0,
            "controllerTrackedPlacementMask": 0,
            "initControllers": [],
            "preRemovalCgroupStat": {
                "nr_descendants": 0, "nr_dying_descendants": 0,
            },
            "terminalCgroupStat": {
                "nr_descendants": 0, "nr_dying_descendants": 0,
            },
        }
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with self.assertRaises(SystemExit), boundary.inject_native_effect_fault_v27(
                "location-5-launch-consumed-current"
            ):
                boundary.execute_literal_stage_schedule_v27(
                    root, key, manifest, plan,
                    action_executor=self.stage_executor([]),
                    require_native_events=True,
                )

            def recover(_manifest, stage_plan, stage):
                self.assertEqual(5, stage.location)
                proof = {
                    "proof": {
                        "operationId": stage_plan["operationId"],
                        "stageLocation": stage.location,
                        "stagePlanSha256": raw_sha(b"other-stage-plan"),
                        "consumedCurrentRecordSha256": raw_sha(
                            b"other-consumed-current"
                        ),
                        "controllerRetirement": retirement,
                    },
                    "controllerHmac": "hmac-sha256:" + "a" * 64,
                }
                raise boundary._NativeLaunchPreEffectFailedV27(
                    raw_sha(b"swapped-controller-proof"), proof=proof
                )

            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "closed as unresolved"
            ):
                boundary.execute_literal_stage_schedule_v27(
                    root, key, manifest, plan,
                    action_executor=lambda *_args: self.fail(
                        "a consumed launch must never execute again"
                    ),
                    action_recovery=recover,
                    require_native_events=True,
                )
            current = boundary.inspect_supervised_effect_v27(
                root, key, plan["operationId"]
            )
            self.assertEqual("UnresolvedTerminalCurrentV3", current["kind"])
            self.assertEqual(
                "unresolved-terminal", current["payload"]["state"]
            )

    def test_local_rows_never_fabricate_native_outer_lifecycle(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        with tempfile.TemporaryDirectory() as name:
            boundary.execute_literal_stage_schedule_v27(
                Path(name),
                key,
                manifest,
                plan,
                action_executor=self.stage_executor([]),
            )
            operation = Path(name) / "native-effects-v27" / plan["operationId"]
            history = [
                json.loads(path.read_bytes())
                for path in (operation / "history").glob("*.json")
            ]
            outer_locations = {
                item["payload"]["location"]
                for item in history
                if item["kind"] != "StageCurrentV3"
            }
            self.assertEqual({5, 19, 33, 47, 61}, outer_locations)
            envelopes = [
                json.loads(path.read_bytes())
                for path in (operation / "objects").glob("*.json")
                if json.loads(path.read_bytes())["kind"]
                == "SupervisorResultEnvelopeV4"
            ]
            self.assertEqual(
                {5, 19, 33, 47, 61},
                {item["payload"]["location"] for item in envelopes},
            )

    def test_native_outer_currents_are_causal_event_gates_not_posthoc_labels(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        expected_events = (
            "supervisor-running",
            "run-authorization-consumed",
            "run-acknowledged",
            "creator-creation-consumed",
            "native-creator-created",
            "release-consumed-current",
            "signal-attempt-consumed",
            "release-issued",
            "release-known-live",
            "release-terminal",
            "creator-return-ready",
            "creator-lifetime-closed",
        )

        def runner(_manifest, stage_plan):
            handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
            self.assertTrue(callable(handler))
            first_event = expected_events[0]
            first_after = boundary._reference_native_event_observation_v27(
                first_event, "after"
            )
            with self.assertRaises(boundary.NativeBoundaryV27Error):
                handler(
                    first_event, "after",
                    boundary._native_event_evidence_v27(
                        stage_plan_sha256=stage_plan["stagePlanSha256"],
                        sequence=1, event=first_event, phase="after",
                        observation=first_after,
                    ),
                    first_after,
                )
            for sequence, (expected_kind, event) in enumerate(
                boundary._SUCCESS_NATIVE_EVENT_CHAIN_V27, 1
            ):
                before = boundary._reference_native_event_observation_v27(
                    event, "before"
                )
                after = boundary._reference_native_event_observation_v27(
                    event, "after"
                )
                before_evidence = boundary._native_event_evidence_v27(
                    stage_plan_sha256=stage_plan["stagePlanSha256"],
                    sequence=(sequence * 2) - 1, event=event,
                    phase="before", observation=before,
                )
                after_evidence = boundary._native_event_evidence_v27(
                    stage_plan_sha256=stage_plan["stagePlanSha256"],
                    sequence=sequence * 2, event=event,
                    phase="after", observation=after,
                )
                predecessor_kind = handler.current["kind"]
                authorization = handler(
                    event, "before", before_evidence, before,
                )
                self.assertRegex(authorization, r"\Asha256:[0-9a-f]{64}\Z")
                self.assertEqual(
                    expected_kind
                    if event in boundary._NATIVE_PRE_ACTION_CURRENT_EVENTS_V27
                    else predecessor_kind,
                    handler.current["kind"],
                    "before-action currents precede the call while outcome "
                    "currents cannot precede their result",
                )
                if event in boundary._NATIVE_PRE_ACTION_CURRENT_EVENTS_V27:
                    self.assertEqual(
                        (
                            event, "before-action", before_evidence,
                            raw_sha(boundary.canonical_bytes(before)), None,
                        ),
                        (
                            handler.current["payload"]["nativeEvent"],
                            handler.current["payload"]["nativeEventTiming"],
                            handler.current["payload"][
                                "nativeEventBeforeEvidenceSha256"
                            ],
                            handler.current["payload"][
                                "nativeEventBeforeObservationSha256"
                            ],
                            handler.current["payload"][
                                "nativeEventAfterEvidenceSha256"
                            ],
                        ),
                    )
                next_event = expected_events[min(sequence, len(expected_events) - 1)]
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    handler(
                        next_event, "before", before_evidence,
                        boundary._reference_native_event_observation_v27(
                            next_event, "before"
                        ),
                    )
                if event == "creator-creation-consumed":
                    with self.assertRaisesRegex(
                        boundary.NativeBoundaryV27Error,
                        "creation intent changed",
                    ):
                        handler(
                            event, "after", after_evidence,
                            {
                                **after,
                                "creationNonceSha256": raw_sha(
                                    b"substituted-creation-nonce"
                                ),
                            },
                        )
                if event == "native-creator-created":
                    with self.assertRaisesRegex(
                        boundary.NativeBoundaryV27Error,
                        "creation receipt changed",
                    ):
                        handler(
                            event, "after", after_evidence,
                            {
                                **after,
                                "joinOwnerTokenSha256": raw_sha(
                                    b"foreign-join-owner-token"
                                ),
                            },
                        )
                if event == "creator-return-ready":
                    with self.assertRaisesRegex(
                        boundary.NativeBoundaryV27Error,
                        "creatorTid changed",
                    ):
                        handler(
                            event, "after", after_evidence,
                            {**after, "creatorTid": after["creatorTid"] + 1},
                        )
                receipt = handler(
                    event, "after", after_evidence, after,
                )
                self.assertRegex(receipt, r"\Asha256:[0-9a-f]{64}\Z")
                self.assertEqual(expected_kind, handler.current["kind"])
                if event not in boundary._NATIVE_PRE_ACTION_CURRENT_EVENTS_V27:
                    self.assertEqual(
                        (
                            event, "after-outcome", before_evidence,
                            after_evidence,
                            raw_sha(boundary.canonical_bytes(after)),
                        ),
                        (
                            handler.current["payload"]["nativeEvent"],
                            handler.current["payload"]["nativeEventTiming"],
                            handler.current["payload"][
                                "nativeEventBeforeEvidenceSha256"
                            ],
                            handler.current["payload"][
                                "nativeEventAfterEvidenceSha256"
                            ],
                            handler.current["payload"][
                                "nativeEventAfterObservationSha256"
                            ],
                        ),
                    )
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    handler(event, "after", after_evidence, after)
            stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
            if stage_plan["stageKey"].startswith("reader-"):
                stdout = reads[int(stage_plan["stageKey"].split("-")[1])]
            result = {
                "exitCode": 0,
                "placementMask": 63,
                "stdout": stdout,
                "stderr": b"",
                "lifecycle": list(boundary._EFFECT_LIFECYCLE),
                "resultKind": "success",
                "resultPredecessorKind": "creator-lifetime-closed-positive",
                "failureEvidenceSha256": None,
            }
            observation = boundary._decode_native_stage_result_v27(
                result, require_discriminants=True
            )
            handler.authorize_result_offer(observation)
            handler.receipt_result_handoff(observation)
            handler.terminalize_result_handoff(self.retirement_receipt())
            return result

        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            repository = root / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            manifest, plan = self.ordinary_plan(str(repository))
            result = boundary.execute_supervised_effect_v27(
                root, key, manifest, plan, runner=runner
            )
            objects = [
                json.loads(path.read_bytes())
                for path in (
                    root / "native-effects-v27" / plan["operationId"] / "objects"
                ).glob("*.json")
            ]
        self.assertEqual(0, result["exitCode"])
        receipts = [
            item for item in objects if item["kind"] == "NativeOuterEventReceiptV1"
        ]
        self.assertEqual(5 * len(expected_events), len(receipts))
        self.assertEqual(
            set(expected_events),
            {item["payload"]["event"] for item in receipts},
        )
        exact_creator_kinds = {
            "NativeCreatorCreationIntentV1",
            "NativeCreatorCreationReceiptV1",
            "NativeCreatorJoinOwnershipReceiptV1",
            "CreatorReturnAuthorizationV2",
            "NativePostReturnCapturePreparationV1",
            "CreatorReturnDepartureIntentV1",
            "CreatorJoinAttemptV2",
            "NativePostReturnAtomicCaptureV1",
            "CreatorJoinResultV2",
            "CreatorPostReturnObservationV2",
            "NativeAllocationGateReleaseReceiptV1",
            "CreatorThreadLifetimeReceiptV4",
        }
        self.assertTrue(exact_creator_kinds.issubset({item["kind"] for item in objects}))
        creation_receipt = next(
            item for item in objects
            if item["kind"] == "NativeCreatorCreationReceiptV1"
            and item["payload"]["location"] == 5
        )
        ownership_receipt = next(
            item
            for item in objects
            if item["kind"] == "NativeCreatorJoinOwnershipReceiptV1"
            and item["payload"]["location"] == 5
        )
        self.assertEqual(
            (
                creation_receipt["payload"]["slotGeneration"],
                ownership_receipt["payload"]["transferCount"],
                ownership_receipt["payload"]["joinHandleDisposition"],
            ),
            (1, 0, "opaque-same-live-retained"),
        )
        creation_intent = next(
            item for item in objects
            if item["kind"] == "NativeCreatorCreationIntentV1"
            and item["payload"]["location"] == 5
        )
        self.assertEqual(
            creation_intent["recordSha256"],
            creation_receipt["payload"]["intentRecordSha256"],
        )
        departure = next(
            item for item in objects
            if item["kind"] == "CreatorReturnDepartureIntentV1"
            and item["payload"]["location"] == 5
        )
        join_attempt = next(
            item for item in objects if item["kind"] == "CreatorJoinAttemptV2"
            and item["payload"]["location"] == 5
        )
        capture = next(
            item for item in objects
            if item["kind"] == "NativePostReturnAtomicCaptureV1"
            and item["payload"]["location"] == 5
        )
        join_result = next(
            item for item in objects if item["kind"] == "CreatorJoinResultV2"
            and item["payload"]["location"] == 5
        )
        post_return = next(
            item for item in objects
            if item["kind"] == "CreatorPostReturnObservationV2"
            and item["payload"]["location"] == 5
        )
        lifetime = next(
            item for item in objects
            if item["kind"] == "CreatorThreadLifetimeReceiptV4"
            and item["payload"]["location"] == 5
        )
        gate_release = next(
            item for item in objects
            if item["kind"] == "NativeAllocationGateReleaseReceiptV1"
            and item["payload"]["location"] == 5
        )
        self.assertEqual(
            departure["recordSha256"],
            join_attempt["payload"]["predecessorExactRecordSha256"],
        )
        self.assertEqual(
            capture["recordSha256"],
            join_result["payload"]["predecessorExactRecordSha256"],
        )
        self.assertEqual(
            join_result["recordSha256"],
            post_return["payload"]["predecessorExactRecordSha256"],
        )
        self.assertEqual(
            post_return["recordSha256"],
            lifetime["payload"]["predecessorExactRecordSha256"],
        )
        self.assertEqual(
            lifetime["recordSha256"],
            gate_release["payload"]["predecessorExactRecordSha256"],
        )
        self.assertTrue(lifetime["payload"]["allocationGateHeld"])
        self.assertFalse(gate_release["payload"]["allocationGateHeld"])

    def test_native_event_faults_preserve_before_action_and_after_outcome_truth(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        cases = (
            (
                "run-authorization-consumed", "authorized",
                "SupervisorRunAuthorizationConsumedCurrentV1", 0, 0,
            ),
            (
                "run-authorization-consumed", "receipted",
                "SupervisorRunAuthorizationConsumedCurrentV1", 1, 1,
            ),
            (
                "native-creator-created", "authorized",
                "NativeCreatorCreationConsumedCurrentV1", 1, 0,
            ),
            (
                "native-creator-created", "receipted",
                "NativeCreatorCreatedCurrentV1", 1, 1,
            ),
        )
        for event, boundary_phase, expected_kind, expected_calls, expected_receipts in cases:
            with self.subTest(
                event=event, boundary_phase=boundary_phase
            ), tempfile.TemporaryDirectory() as name:
                manifest, plan = self.ordinary_plan()
                calls: list[str] = []

                def runner(_manifest, effect_plan):
                    handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
                    self.assertTrue(callable(handler))
                    payload_stage = next(
                        row
                        for row in boundary.literal_stage_schedule_v27(
                            effect_plan["operationClass"]
                        )
                        if row.location == 5
                    )
                    stage_plan = boundary.derive_native_stage_action_plan_v27(
                        _manifest, effect_plan, payload_stage
                    )
                    self.assertIsNotNone(stage_plan)
                    assert stage_plan is not None
                    stage_plan = {
                        **stage_plan,
                        "stagePlanSha256": None,
                    }
                    stage_plan["stagePlanSha256"] = (
                        boundary._native_stage_plan_digest_v27(stage_plan)
                    )
                    sequence = 0

                    def send(item: str, phase: str):
                        nonlocal sequence
                        sequence += 1
                        observation = (
                            boundary._reference_native_event_observation_v27(
                                item, phase
                            )
                        )
                        return handler(
                            item, phase,
                            boundary._native_event_evidence_v27(
                                stage_plan_sha256=stage_plan[
                                    "stagePlanSha256"
                                ],
                                sequence=sequence, event=item, phase=phase,
                                observation=observation,
                            ),
                            observation,
                        )

                    send("supervisor-running", "before")
                    send("supervisor-running", "after")
                    if event == "run-authorization-consumed":
                        send(event, "before")
                        calls.append("release-send")
                        send(event, "after")
                    else:
                        send("run-authorization-consumed", "before")
                        send("run-authorization-consumed", "after")
                        send("run-acknowledged", "before")
                        send("run-acknowledged", "after")
                        send("creator-creation-consumed", "before")
                        calls.append("pthread-create")
                        send("creator-creation-consumed", "after")
                        send(event, "before")
                        send(event, "after")
                    self.fail("the injected event boundary did not fire")

                fault = (
                    f"location-5-native-event-{event}-{boundary_phase}"
                )
                with self.assertRaises(SystemExit), boundary.inject_native_effect_fault_v27(
                    fault
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        Path(name), key, manifest, plan,
                        action_executor=lambda manifest_value, plan_value, stage: (
                            runner(manifest_value, plan_value)
                            if stage.location == 5
                            else self.stage_executor([])(
                                manifest_value, plan_value, stage
                            )
                        ),
                        require_native_events=True,
                    )
                current = boundary.inspect_supervised_effect_v27(
                    Path(name), key, plan["operationId"]
                )
                self.assertEqual(expected_kind, current["kind"])
                self.assertEqual(expected_calls, len(calls))
                operation = (
                    Path(name) / "native-effects-v27" / plan["operationId"]
                )
                event_receipts = [
                    json.loads(path.read_bytes())
                    for path in (operation / "objects").glob("*.json")
                    if json.loads(path.read_bytes())["kind"]
                    == "NativeOuterEventReceiptV1"
                    and json.loads(path.read_bytes())["payload"]["event"]
                    == event
                ]
                self.assertEqual(expected_receipts, len(event_receipts))
                intents = [
                    json.loads(path.read_bytes())
                    for path in (operation / "objects").glob("*.json")
                    if json.loads(path.read_bytes())["kind"]
                    == "NativeOuterEventIntentV1"
                    and json.loads(path.read_bytes())["payload"]["event"]
                    == event
                ]
                self.assertEqual(1, len(intents))
                self.assertEqual(
                    "before-action"
                    if event in boundary._NATIVE_PRE_ACTION_CURRENT_EVENTS_V27
                    else "after-outcome",
                    intents[0]["payload"]["currentTiming"],
                )

    def test_creator_abi_crash_lattice_never_preclaims_create_or_join(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        cases = (
            (
                "creator-creation-consumed", "authorized",
                "NativeCreatorCreationConsumedCurrentV1", 0,
                {"NativeCreatorCreationIntentV1"},
            ),
            (
                "creator-creation-consumed", "receipted",
                "NativeCreatorCreationConsumedCurrentV1", 0,
                {"NativeCreatorCreationIntentV1"},
            ),
            (
                "native-creator-created", "authorized",
                "NativeCreatorCreationConsumedCurrentV1", 1,
                {"NativeCreatorCreationIntentV1"},
            ),
            (
                "native-creator-created", "receipted",
                "NativeCreatorCreatedCurrentV1", 1,
                {
                    "NativeCreatorCreationIntentV1",
                    "NativeCreatorCreationReceiptV1",
                    "NativeCreatorJoinOwnershipReceiptV1",
                },
            ),
            (
                "creator-return-ready", "authorized",
                "CreatorReturnReadyCurrentV2", 1,
                {
                    "NativeCreatorCreationReceiptV1",
                    "CreatorReturnAuthorizationV2",
                    "NativePostReturnCapturePreparationV1",
                    "CreatorReturnDepartureIntentV1",
                    "CreatorJoinAttemptV2",
                },
            ),
            (
                "creator-return-ready", "receipted",
                "CreatorReturnReadyCurrentV2", 1,
                {
                    "CreatorReturnAuthorizationV2",
                    "NativePostReturnCapturePreparationV1",
                    "CreatorReturnDepartureIntentV1",
                    "CreatorJoinAttemptV2",
                },
            ),
            (
                "creator-lifetime-closed", "authorized",
                "CreatorReturnReadyCurrentV2", 2,
                {
                    "CreatorJoinAttemptV2", "NativePostReturnAtomicCaptureV1",
                    "CreatorJoinResultV2", "CreatorPostReturnObservationV2",
                    "CreatorThreadLifetimeReceiptV4",
                },
            ),
            (
                "creator-lifetime-closed", "receipted",
                "CreatorLifetimeClosedCurrentV5", 2,
                {
                    "NativePostReturnAtomicCaptureV1", "CreatorJoinResultV2",
                    "CreatorPostReturnObservationV2",
                    "NativeAllocationGateReleaseReceiptV1",
                    "CreatorThreadLifetimeReceiptV4",
                },
            ),
        )
        for event, fault_boundary, expected_kind, expected_calls, required in cases:
            with self.subTest(
                event=event, fault_boundary=fault_boundary
            ), tempfile.TemporaryDirectory() as name:
                manifest, plan = self.ordinary_plan()
                calls: list[str] = []

                def runner(_manifest, effect_plan):
                    handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
                    self.assertTrue(callable(handler))
                    payload_stage = next(
                        row
                        for row in boundary.literal_stage_schedule_v27(
                            effect_plan["operationClass"]
                        )
                        if row.location == 5
                    )
                    stage_plan = boundary.derive_native_stage_action_plan_v27(
                        _manifest, effect_plan, payload_stage
                    )
                    self.assertIsNotNone(stage_plan)
                    assert stage_plan is not None
                    sequence = 0

                    def send(item: str, phase: str) -> None:
                        nonlocal sequence
                        sequence += 1
                        observation = boundary._reference_native_event_observation_v27(
                            item, phase
                        )
                        handler(
                            item, phase,
                            boundary._native_event_evidence_v27(
                                stage_plan_sha256=stage_plan["stagePlanSha256"],
                                sequence=sequence, event=item, phase=phase,
                                observation=observation,
                            ),
                            observation,
                        )

                    for _kind, item in boundary._SUCCESS_NATIVE_EVENT_CHAIN_V27:
                        if item == "native-creator-created":
                            calls.append("pthread-create")
                        send(item, "before")
                        send(item, "after")
                        if item == "creator-return-ready":
                            calls.append("pthread-join")
                    self.fail("the creator ABI fault boundary did not fire")

                fault = f"location-5-native-event-{event}-{fault_boundary}"
                with self.assertRaises(SystemExit), boundary.inject_native_effect_fault_v27(
                    fault
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        Path(name), key, manifest, plan,
                        action_executor=lambda manifest_value, plan_value, stage: (
                            runner(manifest_value, plan_value)
                            if stage.location == 5
                            else self.stage_executor([])(
                                manifest_value, plan_value, stage
                            )
                        ),
                        require_native_events=True,
                    )
                current = boundary.inspect_supervised_effect_v27(
                    Path(name), key, plan["operationId"]
                )
                self.assertEqual(expected_kind, current["kind"])
                self.assertEqual(expected_calls, len(calls))
                operation = Path(name) / "native-effects-v27" / plan["operationId"]
                kinds = {
                    json.loads(path.read_bytes())["kind"]
                    for path in (operation / "objects").glob("*.json")
                }
                self.assertTrue(required.issubset(kinds))
                if event == "native-creator-created" and fault_boundary == "authorized":
                    self.assertNotIn("NativeCreatorCreationReceiptV1", kinds)
                if event == "creator-return-ready" and fault_boundary == "authorized":
                    self.assertIn("CreatorReturnDepartureIntentV1", kinds)
                    self.assertIn("CreatorJoinAttemptV2", kinds)
                if event == "creator-lifetime-closed" and fault_boundary == "authorized":
                    self.assertIn("NativePostReturnAtomicCaptureV1", kinds)
                    self.assertIn("CreatorThreadLifetimeReceiptV4", kinds)
                    self.assertNotIn("NativeAllocationGateReleaseReceiptV1", kinds)

    def test_controlled_abort_crash_lattice_never_replays_wake_or_join(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        cases = (
            (
                "abort-wake-consumed", "authorized",
                "CreatorAbortWakeConsumedCurrentV1", 0, 0,
                {"CreatorAbortWakeDecisionV1", "CreatorAbortWakeAttemptV1"},
                {"CreatorAbortWakeReturnV1", "CreatorAbortWakeReceiptV1"},
            ),
            (
                "abort-wake-consumed", "receipted",
                "CreatorAbortWakeConsumedCurrentV1", 1, 0,
                {
                    "CreatorAbortWakeDecisionV1", "CreatorAbortWakeAttemptV1",
                    "CreatorAbortWakeReturnV1", "CreatorAbortWakeReceiptV1",
                },
                set(),
            ),
            (
                "abort-join-consumed", "authorized",
                "CreatorAbortJoinConsumedCurrentV1", 1, 0,
                {"CreatorAbortJoinAttemptV1"},
                {"CreatorAbortJoinReturnV1", "CreatorAbortJoinReceiptV1"},
            ),
            (
                "abort-join-consumed", "receipted",
                "CreatorAbortJoinConsumedCurrentV1", 1, 1,
                {
                    "CreatorAbortJoinAttemptV1", "CreatorAbortJoinReturnV1",
                    "CreatorAbortJoinReceiptV1",
                },
                set(),
            ),
            (
                "abort-failure-lifetime", "authorized",
                "CreatorAbortJoinConsumedCurrentV1", 1, 1,
                {"CreatorAbortJoinReceiptV1"},
                set(),
            ),
            (
                "abort-failure-lifetime", "receipted",
                "CreatorAbortFailureLifetimeCurrentV1", 1, 1,
                {"CreatorAbortJoinReceiptV1"},
                set(),
            ),
        )
        for (
            event, fault_boundary, expected_kind, expected_wakes,
            expected_joins, required, forbidden,
        ) in cases:
            with self.subTest(
                event=event, fault_boundary=fault_boundary
            ), tempfile.TemporaryDirectory() as name:
                manifest, plan = self.ordinary_plan()
                wake_calls: list[str] = []
                join_calls: list[str] = []

                def runner(_manifest, effect_plan):
                    handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
                    self.assertTrue(callable(handler))
                    payload_stage = next(
                        row
                        for row in boundary.literal_stage_schedule_v27(
                            effect_plan["operationClass"]
                        )
                        if row.location == 5
                    )
                    stage_plan = boundary.derive_native_stage_action_plan_v27(
                        _manifest, effect_plan, payload_stage
                    )
                    self.assertIsNotNone(stage_plan)
                    assert stage_plan is not None
                    sequence = 0

                    def send(item: str, phase: str) -> None:
                        nonlocal sequence
                        sequence += 1
                        observation = boundary._reference_native_event_observation_v27(
                            item, phase
                        )
                        handler(
                            item, phase,
                            boundary._native_event_evidence_v27(
                                stage_plan_sha256=stage_plan["stagePlanSha256"],
                                sequence=sequence, event=item, phase=phase,
                                observation=observation,
                            ),
                            observation,
                        )

                    for _kind, item in boundary._NATIVE_EVENT_CHAINS_V27[
                        "controlled-abort-failed"
                    ]:
                        send(item, "before")
                        if item == "abort-wake-consumed":
                            wake_calls.append("abort-store-and-wake")
                        if item == "abort-join-consumed":
                            join_calls.append("pthread-join")
                        send(item, "after")
                    self.fail("the controlled-abort fault boundary did not fire")

                fault = f"location-5-native-event-{event}-{fault_boundary}"
                with self.assertRaises(SystemExit), boundary.inject_native_effect_fault_v27(
                    fault
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        Path(name), key, manifest, plan,
                        action_executor=lambda manifest_value, plan_value, stage: (
                            runner(manifest_value, plan_value)
                            if stage.location == 5
                            else self.stage_executor([])(
                                manifest_value, plan_value, stage
                            )
                        ),
                        require_native_events=True,
                    )
                current = boundary.inspect_supervised_effect_v27(
                    Path(name), key, plan["operationId"]
                )
                self.assertEqual(expected_kind, current["kind"])
                self.assertEqual(expected_wakes, len(wake_calls))
                self.assertEqual(expected_joins, len(join_calls))
                operation = Path(name) / "native-effects-v27" / plan["operationId"]
                kinds = {
                    json.loads(path.read_bytes())["kind"]
                    for path in (operation / "objects").glob("*.json")
                }
                self.assertTrue(required.issubset(kinds))
                self.assertTrue(forbidden.isdisjoint(kinds))

    def test_credentialed_result_handoff_crash_prefixes_repair_without_relaunch(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        phases = (
            "location-5-result-handoff-recovery-receipt-bytes-written",
            "location-5-result-handoff-recovery-receipt-file-fsynced",
            "location-5-result-handoff-receipted-history-bytes-written",
            "location-5-result-handoff-receipted-current-cas-directory-fsynced",
            "location-5-terminal-recovery-receipt-bytes-written",
            "location-5-terminal-recovery-receipt-directory-fsynced",
            "location-5-terminal-receipt-stored-history-file-fsynced",
            "location-5-terminal-receipt-stored-current-cas-replaced",
            "location-5-supervisor-terminal-history-directory-fsynced",
            "location-5-supervisor-terminal-current-cas-directory-fsynced",
        )

        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                root = Path(name).resolve()
                repository = root / "repository"
                beads = repository / ".beads"
                beads.mkdir(parents=True)
                (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
                manifest, plan = self.ordinary_plan(str(repository))

                class Runner:
                    def __init__(runner_self) -> None:
                        runner_self.location_five_launches = 0
                        runner_self.location_five_recoveries = 0

                    def result(runner_self, stage_plan, *, recovered: bool):
                        stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                        if stage_plan["stageKey"].startswith("reader-"):
                            stdout = reads[int(stage_plan["stageKey"].split("-")[1])]
                        value = {
                            "exitCode": 0,
                            "placementMask": 63,
                            "stdout": stdout,
                            "stderr": b"",
                            "lifecycle": list(boundary._EFFECT_LIFECYCLE),
                            "resultKind": "success",
                            "resultPredecessorKind": "creator-lifetime-closed-positive",
                            "failureEvidenceSha256": None,
                        }
                        if recovered:
                            value["controllerRetirement"] = self.retirement_receipt()
                        return value

                    def __call__(runner_self, _manifest, stage_plan):
                        if stage_plan["stageLocation"] == 5:
                            runner_self.location_five_launches += 1
                        self.emit_success_native_events(stage_plan)
                        result = runner_self.result(stage_plan, recovered=False)
                        handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
                        observation = boundary._decode_native_stage_result_v27(
                            result, require_discriminants=True
                        )
                        handler.authorize_result_offer(observation)
                        if stage_plan["stageLocation"] == 5:
                            # Model process death after the native supervisor
                            # received its ACK and made FD10 durable, but before
                            # the credentialed full-result packet arrived.
                            raise SystemExit("after-native-result-offer-ack")
                        handler.receipt_result_handoff(observation)
                        handler.terminalize_result_handoff(
                            self.retirement_receipt()
                        )
                        return result

                    def recover(runner_self, _manifest, stage_plan):
                        if stage_plan["stageLocation"] == 5:
                            runner_self.location_five_recoveries += 1
                        return runner_self.result(stage_plan, recovered=True)

                runner = Runner()
                with self.assertRaises(SystemExit):
                    boundary.execute_supervised_effect_v27(
                        root, key, manifest, plan, runner=runner
                    )
                with self.assertRaises(SystemExit):
                    with boundary.inject_native_effect_fault_v27(phase):
                        boundary.execute_supervised_effect_v27(
                            root, key, manifest, plan, runner=runner
                        )
                result = boundary.execute_supervised_effect_v27(
                    root, key, manifest, plan, runner=runner
                )
                self.assertEqual(0, result["exitCode"])
                self.assertEqual(1, runner.location_five_launches)
                self.assertGreaterEqual(runner.location_five_recoveries, 2)
                current = boundary.inspect_supervised_effect_v27(
                    root, key, plan["operationId"]
                )
                self.assertEqual("completion", current["payload"]["state"])

    def test_pre_ack_result_offer_crashes_close_as_unresolved_without_public_result(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        phases = (
            "location-5-result-envelope-directory-fsynced",
            "location-5-result-handoff-authorization-directory-fsynced",
            "location-5-result-envelope-stored-current-cas-directory-fsynced",
            "location-5-result-handoff-consumed-current-cas-directory-fsynced",
        )
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                root = Path(name).resolve()
                repository = root / "repository"
                beads = repository / ".beads"
                beads.mkdir(parents=True)
                (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
                manifest, plan = self.ordinary_plan(str(repository))

                class Runner:
                    launches = 0

                    def __call__(runner_self, _manifest, stage_plan):
                        runner_self.launches += 1
                        self.emit_success_native_events(stage_plan)
                        result = {
                            "exitCode": 0,
                            "placementMask": 63,
                            "stdout": b"effect-completed-before-handoff",
                            "stderr": b"",
                            "lifecycle": list(boundary._EFFECT_LIFECYCLE),
                            "resultKind": "success",
                            "resultPredecessorKind": "creator-lifetime-closed-positive",
                            "failureEvidenceSha256": None,
                        }
                        handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
                        handler.authorize_result_offer(
                            boundary._decode_native_stage_result_v27(
                                result, require_discriminants=True
                            )
                        )
                        raise AssertionError("fault must stop before ACK")

                    def recover(runner_self, _manifest, stage_plan):
                        loss = boundary._native_supervisor_loss_v27(
                            reason="dead-holder-without-terminal",
                            evidence_sha256=raw_sha(
                                str(stage_plan["stagePlanSha256"]).encode()
                            ),
                        )
                        loss["controllerRetirement"] = self.retirement_receipt()
                        return loss

                runner = Runner()
                with self.assertRaises(SystemExit):
                    with boundary.inject_native_effect_fault_v27(phase):
                        boundary.execute_supervised_effect_v27(
                            root, key, manifest, plan, runner=runner
                        )
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error,
                    "authenticated unresolved terminal",
                ):
                    boundary.execute_supervised_effect_v27(
                        root, key, manifest, plan, runner=runner
                    )
                current = boundary.inspect_supervised_effect_v27(
                    root, key, plan["operationId"]
                )
                self.assertEqual("UnresolvedTerminalCurrentV3", current["kind"])
                self.assertEqual(1, runner.launches)
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error,
                    "non-public unresolved terminal",
                ):
                    boundary.execute_supervised_effect_v27(
                        root, key, manifest, plan, runner=runner
                    )
                self.assertEqual(1, runner.launches)

    def test_every_admitted_nonpublic_current_has_an_explicit_no_replay_closure(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        intermediate_paths = {
            "TakeoverKillAttemptConsumedCurrentV1": (
                ("TakeoverKillAttemptConsumedCurrentV1", "takeover-kill-attempt-consumed"),
            ),
            "NormalMissPendingCurrentV4": (
                ("NormalMissPendingCurrentV4", "normal-miss-pending"),
            ),
            "BootChangedUnresolvedCurrentV2": (
                ("BootChangedUnresolvedCurrentV2", "boot-changed-unresolved"),
            ),
            "LateCutoffContinuationCurrentV2": (
                ("NormalMissPendingCurrentV4", "normal-miss-pending"),
                ("LateCutoffContinuationCurrentV2", "late-cutoff-continuation"),
            ),
            "LateNormalPendingRawCurrentV1": (
                ("NormalMissPendingCurrentV4", "normal-miss-pending"),
                ("LateCutoffContinuationCurrentV2", "late-cutoff-continuation"),
                ("LateNormalPendingRawCurrentV1", "late-normal-pending-raw"),
            ),
        }
        terminal_paths = {
            "NormalMissResolvedCurrentV4": (
                ("NormalMissPendingCurrentV4", "normal-miss-pending"),
                ("NormalMissResolvedCurrentV4", "normal-miss-resolved"),
            ),
            "LateCutoffUnresolvedCurrentV3": (
                ("NormalMissPendingCurrentV4", "normal-miss-pending"),
                ("LateCutoffContinuationCurrentV2", "late-cutoff-continuation"),
                ("LateNormalPendingRawCurrentV1", "late-normal-pending-raw"),
                ("LateCutoffUnresolvedCurrentV3", "late-cutoff-unresolved"),
            ),
            "CreatorReturnPermanentlyQuarantinedCurrentV2": (
                ("CreatorReturnReadyCurrentV2", "creator-return-ready"),
                (
                    "CreatorReturnPermanentlyQuarantinedCurrentV2",
                    "creator-return-permanently-quarantined",
                ),
            ),
        }

        for expected_kind, path in {**intermediate_paths, **terminal_paths}.items():
            with self.subTest(kind=expected_kind), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                with self.assertRaises(SystemExit):
                    with boundary.inject_native_effect_fault_v27(
                        "location-5-launch-consumed-current"
                    ):
                        boundary.execute_literal_stage_schedule_v27(
                            root,
                            key,
                            manifest,
                            plan,
                            action_executor=self.stage_executor([]),
                            require_native_events=True,
                        )
                operation, history, objects = boundary._effect_state_paths(
                    root, plan["operationId"]
                )
                current_path = operation / "current.json"
                current = boundary._read_effect_record(current_path, key)
                consumed = current["recordSha256"]
                stage = boundary.literal_stage_schedule_v27("ordinary")[4]
                for kind, state in path:
                    current = boundary._install_effect_current_kind_v27(
                        current_path,
                        history,
                        key,
                        kind,
                        boundary._outer_current_payload_v27(
                            plan,
                            stage,
                            state=state,
                            predecessor=current,
                            consumed_record_sha256=consumed,
                            result=None,
                            result_kind=None,
                            failure_evidence_sha256=None,
                        ),
                        expected=current,
                    )
                launches: list[int] = []
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error,
                    "exact non-public|exact final non-public",
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        root,
                        key,
                        manifest,
                        plan,
                        action_executor=lambda *_args: launches.append(1),
                        action_recovery=lambda *_args: None,
                        require_native_events=True,
                    )
                self.assertEqual([], launches)
                observed = boundary._read_effect_record(current_path, key)
                if expected_kind in intermediate_paths:
                    self.assertEqual(
                        "SupervisorOuterLossQuarantinedCurrentV4",
                        observed["kind"],
                    )
                    closures = [
                        boundary._read_effect_record(item, key)
                        for item in objects.glob("*.json")
                    ]
                    self.assertEqual(
                        1,
                        sum(
                            item["kind"] == "AdmittedOuterRecoveryClosureV1"
                            for item in closures
                        ),
                    )
                else:
                    self.assertEqual(expected_kind, observed["kind"])

    def test_admitted_nonpublic_closure_crash_prefixes_are_idempotent(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        phases = (
            "location-5-takeover-kill-consumed-no-replay-bytes-written",
            "location-5-takeover-kill-consumed-no-replay-file-fsynced",
            "location-5-takeover-kill-consumed-no-replay-directory-fsynced",
            "location-5-outer-loss-quarantined-current-history-file-fsynced",
            "location-5-outer-loss-quarantined-current-current-cas-replaced",
            "location-5-outer-loss-quarantined-current-current-cas-directory-fsynced",
        )
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                with self.assertRaises(SystemExit):
                    with boundary.inject_native_effect_fault_v27(
                        "location-5-launch-consumed-current"
                    ):
                        boundary.execute_literal_stage_schedule_v27(
                            root, key, manifest, plan,
                            action_executor=self.stage_executor([]),
                            require_native_events=True,
                        )
                operation, history, _objects = boundary._effect_state_paths(
                    root, plan["operationId"]
                )
                current_path = operation / "current.json"
                current = boundary._read_effect_record(current_path, key)
                stage = boundary.literal_stage_schedule_v27("ordinary")[4]
                current = boundary._install_effect_current_kind_v27(
                    current_path,
                    history,
                    key,
                    "TakeoverKillAttemptConsumedCurrentV1",
                    boundary._outer_current_payload_v27(
                        plan,
                        stage,
                        state="takeover-kill-attempt-consumed",
                        predecessor=current,
                        consumed_record_sha256=current["recordSha256"],
                        result=None,
                        result_kind=None,
                        failure_evidence_sha256=None,
                    ),
                    expected=current,
                )
                launches: list[int] = []
                with self.assertRaises(SystemExit):
                    with boundary.inject_native_effect_fault_v27(phase):
                        boundary.execute_literal_stage_schedule_v27(
                            root, key, manifest, plan,
                            action_executor=lambda *_args: launches.append(1),
                            action_recovery=lambda *_args: None,
                            require_native_events=True,
                        )
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error, "non-public|quarantined"
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        root, key, manifest, plan,
                        action_executor=lambda *_args: launches.append(1),
                        action_recovery=lambda *_args: None,
                        require_native_events=True,
                    )
                self.assertEqual([], launches)
                observed = boundary._read_effect_record(current_path, key)
                self.assertEqual(
                    "SupervisorOuterLossQuarantinedCurrentV4", observed["kind"]
                )

    def test_consumed_without_result_quarantines_but_durable_result_repairs(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            calls: list[tuple[int, str]] = []
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27("location-5-launch-consumed-current"):
                    boundary.execute_literal_stage_schedule_v27(
                        root, key, manifest, plan,
                        action_executor=self.stage_executor(calls),
                    )
            self.assertNotIn(5, [location for location, _stage in calls])
            with self.assertRaisesRegex(boundary.NativeBoundaryV27Error, "quarantined"):
                boundary.execute_literal_stage_schedule_v27(
                    root, key, manifest, plan,
                    action_executor=self.stage_executor(calls),
                )
            current = boundary.inspect_supervised_effect_v27(root, key, plan["operationId"])
            self.assertEqual("SupervisorOuterLossQuarantinedCurrentV4", current["kind"])

        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            calls = []
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27("location-73-result-object-written"):
                    boundary.execute_literal_stage_schedule_v27(
                        root, key, manifest, plan,
                        action_executor=self.stage_executor(calls),
                    )
            self.assertEqual(1, [location for location, _stage in calls].count(73))
            result = boundary.execute_literal_stage_schedule_v27(
                root, key, manifest, plan,
                action_executor=self.stage_executor(calls),
            )
            self.assertEqual(0, result["exitCode"])
            self.assertEqual(1, [location for location, _stage in calls].count(73))

    def test_incomplete_tail_never_synthesizes_a_missing_future_stage(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            calls: list[tuple[int, str]] = []
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27(
                    "location-72-completion-current-installed"
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        root,
                        key,
                        manifest,
                        plan,
                        action_executor=self.stage_executor(calls),
                    )
            current = boundary.inspect_supervised_effect_v27(
                root, key, plan["operationId"]
            )
            self.assertEqual((72, "completion"), (
                current["payload"]["location"], current["payload"]["state"]
            ))
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "without synthesis"
            ):
                boundary.execute_literal_stage_schedule_v27(
                    root,
                    key,
                    manifest,
                    plan,
                    action_executor=self.stage_executor(calls),
                )
            current = boundary.inspect_supervised_effect_v27(
                root, key, plan["operationId"]
            )
            self.assertEqual("SupervisorOuterLossQuarantinedCurrentV4", current["kind"])
            history = root / "native-effects-v27" / plan["operationId"] / "history"
            self.assertFalse(any(
                json.loads(path.read_bytes())["payload"].get("location") == 73
                for path in history.glob("*.json")
            ))

        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            calls = []
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27(
                    "location-5-launch-consumed-current"
                ):
                    boundary.execute_literal_stage_schedule_v27(
                        root, key, manifest, plan,
                        action_executor=self.stage_executor(calls),
                    )
            recovered_locations: list[int] = []

            def recover_stage(_manifest, _plan, stage):
                recovered_locations.append(stage.location)
                return self.stage_executor([])(_manifest, _plan, stage)

            result = boundary.execute_literal_stage_schedule_v27(
                root, key, manifest, plan,
                action_executor=self.stage_executor(calls),
                action_recovery=recover_stage,
            )
            self.assertEqual(0, result["exitCode"])
            self.assertEqual([5], recovered_locations)
            self.assertNotIn(5, [location for location, _stage in calls])
            result = boundary.execute_literal_stage_schedule_v27(
                root, key, manifest, plan,
                action_executor=self.stage_executor(calls),
            )
            self.assertEqual(0, result["exitCode"])
            self.assertEqual(1, [location for location, _stage in calls].count(73))

    def test_write_fsync_cas_and_receipt_prefixes_repair_without_replay(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        repair_phases = (
            "location-5-result-object-bytes-written",
            "location-5-result-object-file-fsynced",
            "location-5-result-object-directory-fsynced",
            "location-5-receipt-object-bytes-written",
            "location-5-receipt-object-file-fsynced",
            "location-5-receipt-object-directory-fsynced",
            "location-5-completion-history-bytes-written",
            "location-5-completion-history-file-fsynced",
            "location-5-completion-current-temporary-bytes-written",
            "location-5-completion-current-temporary-file-fsynced",
            "location-5-completion-current-cas-replaced",
            "location-5-completion-current-cas-directory-fsynced",
        )
        for phase in repair_phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                calls: list[tuple[int, str]] = []
                with self.assertRaises(SystemExit):
                    with boundary.inject_native_effect_fault_v27(phase):
                        boundary.execute_literal_stage_schedule_v27(
                            Path(name), key, manifest, plan,
                            action_executor=self.stage_executor(calls),
                        )
                result = boundary.execute_literal_stage_schedule_v27(
                    Path(name), key, manifest, plan,
                    action_executor=self.stage_executor(calls),
                )
                self.assertEqual(0, result["exitCode"])
                self.assertEqual(
                    1,
                    [location for location, _stage in calls].count(5),
                    phase,
                )

        for phase, expected_calls in (
            (
                "location-5-launch-slot-consumed-current-temporary-file-fsynced",
                1,
            ),
            ("location-5-launch-slot-consumed-current-cas-replaced", 0),
        ):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                calls = []
                with self.assertRaises(SystemExit):
                    with boundary.inject_native_effect_fault_v27(phase):
                        boundary.execute_literal_stage_schedule_v27(
                            Path(name), key, manifest, plan,
                            action_executor=self.stage_executor(calls),
                        )
                if expected_calls:
                    result = boundary.execute_literal_stage_schedule_v27(
                        Path(name), key, manifest, plan,
                        action_executor=self.stage_executor(calls),
                    )
                    self.assertEqual(0, result["exitCode"])
                else:
                    with self.assertRaisesRegex(
                        boundary.NativeBoundaryV27Error, "quarantined"
                    ):
                        boundary.execute_literal_stage_schedule_v27(
                            Path(name), key, manifest, plan,
                            action_executor=self.stage_executor(calls),
                        )
                self.assertEqual(expected_calls, len([
                    location for location, _stage in calls if location == 5
                ]))

    def test_named_result_handoff_prefixes_repair_without_action_replay(self) -> None:
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        phases = (
            "location-5-result-envelope-bytes-written",
            "location-5-result-envelope-file-fsynced",
            "location-5-result-envelope-directory-fsynced",
            "location-5-result-envelope-written",
            "location-5-result-envelope-stored-history-bytes-written",
            "location-5-result-envelope-stored-current-cas-replaced",
            "location-5-result-handoff-consumed-history-file-fsynced",
            "location-5-result-handoff-consumed-current-cas-directory-fsynced",
            "location-5-result-handoff-receipted-history-bytes-written",
            "location-5-terminal-receipt-stored-current-cas-replaced",
            "location-5-supervisor-terminal-current-cas-directory-fsynced",
        )
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                calls: list[tuple[int, str]] = []
                with self.assertRaises(SystemExit):
                    with boundary.inject_native_effect_fault_v27(phase):
                        boundary.execute_literal_stage_schedule_v27(
                            Path(name),
                            key,
                            manifest,
                            plan,
                            action_executor=self.stage_executor(calls),
                        )
                result = boundary.execute_literal_stage_schedule_v27(
                    Path(name),
                    key,
                    manifest,
                    plan,
                    action_executor=self.stage_executor(calls),
                )
                self.assertEqual(0, result["exitCode"])
                self.assertEqual(
                    1,
                    [location for location, _stage in calls].count(5),
                    phase,
                )

    def test_real_sigkill_at_every_intent_location_repairs_exact_suffix(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("real SIGKILL matrix requires fork")
        manifest, plan = self.ordinary_plan()
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        context = multiprocessing.get_context("fork")

        for location in range(1, 77):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as name:
                root = Path(name).resolve()

                def die_at_intent() -> None:
                    with boundary.inject_native_effect_sigkill_v27(
                        f"location-{location}-intent-current"
                    ):
                        boundary.execute_literal_stage_schedule_v27(
                            root,
                            key,
                            manifest,
                            plan,
                            action_executor=self.stage_executor([]),
                        )

                process = context.Process(target=die_at_intent)
                process.start()
                process.join(20)
                self.assertFalse(process.is_alive(), location)
                self.assertEqual(-signal.SIGKILL, process.exitcode, location)
                current = boundary.inspect_supervised_effect_v27(
                    root, key, plan["operationId"]
                )
                self.assertEqual(
                    (location, "intent-current"),
                    (current["payload"]["location"], current["payload"]["state"]),
                )
                result = boundary.execute_literal_stage_schedule_v27(
                    root,
                    key,
                    manifest,
                    plan,
                    action_executor=self.stage_executor([]),
                    action_recovery=self.stage_executor([]),
                )
                self.assertEqual(0, result["exitCode"])

    def test_production_entry_uses_literal_engine_not_aggregate_runner(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        calls: list[tuple[int, str]] = []
        reads = self.reader_outputs()

        def runner(_manifest, stage_plan):
            self.assertEqual(
                {
                    "schemaVersion", "profile", "operationId", "operationClass",
                    "effectPlanSha256", "stageLocation", "stageKey", "stageKind",
                    "actionKind", "repositoryPath", "repositoryCustody", "argv", "imageReference",
                    "imageDigest", "networkMode", "pullPolicy", "environment",
                    "requestKeyId", "stagePlanSha256",
                },
                set(stage_plan),
            )
            calls.append((stage_plan["stageLocation"], stage_plan["stageKey"]))
            stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
            if stage_plan["stageKey"].startswith("reader-"):
                stdout = reads[int(stage_plan["stageKey"].split("-")[1])]
            return self.successful_native_result(stage_plan, stdout=stdout)

        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            repository = root / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            manifest, plan = self.ordinary_plan(str(repository))
            result = boundary.execute_supervised_effect_v27(root, key, manifest, plan, runner=runner)
            current = boundary.inspect_supervised_effect_v27(
                root, key, plan["operationId"]
            )
        self.assertEqual("StageCurrentV3", current["kind"])
        self.assertEqual((76, "completion"), (
            current["payload"]["location"], current["payload"]["state"]
        ))
        self.assertEqual(
            [
                (5, "effect-payload-terminal"),
                (19, "reader-0-payload-terminal"),
                (33, "reader-1-payload-terminal"),
                (47, "reader-2-payload-terminal"),
                (61, "reader-3-payload-terminal"),
            ],
            calls,
        )
        self.assertEqual(4, result["independentReadCount"])
        self.assertEqual([True, True], result["physicalEqualityPasses"])
        self.assertEqual([True] * 6, result["repeatabilityPasses"])
        self.assertEqual([True] * 5, result["rollingJoinPasses"])
        self.assertTrue(result["crossWindowNoEffect"])

    def _custody_runner(
        self,
        *,
        root: Path,
        key: bytes,
        probe_factory=None,
    ):
        owner = self
        reads = self.reader_outputs()

        class CustodyRunner:
            def __init__(self):
                self.receipts = {}
                self.observed = []

            def repository_custody_profile_v27(self, _plan):
                return {
                    "rootPath": str(root),
                    "controllerUid": os.geteuid(),
                    "workerGid": os.getegid(),
                    "workerSessionNonce": "a" * 64,
                }

            def __call__(self, _manifest, stage_plan):
                custody = boundary.validate_repository_custody_binding_v27(
                    stage_plan["repositoryCustody"],
                    repository_path=stage_plan["repositoryPath"],
                )
                readonly = stage_plan["stageKey"].startswith("reader-")
                self.observed.append(
                    (
                        stage_plan["stageKey"],
                        stat.S_IMODE(os.lstat(stage_plan["repositoryPath"]).st_mode),
                        custody["accessMode"],
                    )
                )
                expected_dir = 0o550 if readonly else 0o770
                expected_file = 0o440 if readonly else 0o660
                for item in custody["manifest"]["entries"]:
                    owner.assertEqual(
                        f"{expected_dir:04o}" if item["kind"] == "directory"
                        else f"{expected_file:04o}",
                        item["mode"],
                    )
                if not readonly:
                    (
                        Path(stage_plan["repositoryPath"])
                        / ".beads" / "issues.jsonl"
                    ).write_bytes(b'{"id":"task-1","status":"active"}\n')
                    stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                else:
                    ordinal = int(stage_plan["stageKey"].split("-")[1])
                    stdout = reads[ordinal]
                request_key = boundary._NATIVE_REQUEST_KEY_V27.get()
                owner.assertIsNotNone(request_key)
                post = boundary._repository_custody_manifest_v27(
                    Path(stage_plan["repositoryPath"]),
                    controller_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    directory_mode=expected_dir,
                    file_mode=expected_file,
                )
                factory = probe_factory or (
                    lambda plan, request_key, post: (
                        controller._worker_repository_release_probe_v27(
                            plan,
                            request_key,
                            worker_session_nonce="a" * 64,
                            probe_nonce="b" * 64,
                            post_manifest=post,
                            descriptor_names=lambda: [],
                            mountinfo_reader=lambda: (
                                b"1 0 0:1 / / rw - tmpfs tmpfs rw\n"
                            ),
                        )
                    )
                )
                self.receipts[stage_plan["stagePlanSha256"]] = factory(
                    stage_plan, request_key, post
                )
                return owner.successful_native_result(
                    stage_plan, stdout=stdout
                )

            def repository_custody_release_receipt_v27(self, stage_plan):
                return self.receipts.pop(stage_plan["stagePlanSha256"])

        return CustodyRunner()

    def test_group_handoff_is_hmac_named_bounded_and_revoked(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        with tempfile.TemporaryDirectory() as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            handoff = top / "handoff"
            handoff.mkdir()
            handoff.chmod(0o710 if sys.platform == "darwin" else 0o2710)
            manifest, plan = self.ordinary_plan(str(repository))
            runner = self._custody_runner(root=handoff, key=key)
            with self.linux_setgid_observation(handoff):
                result = boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner
                )
            leaves = tuple(handoff.iterdir())
            self.assertEqual(5, len(leaves))
            self.assertTrue(all(
                item.name.startswith("v27-")
                and len(item.name) == 68
                and stat.S_IMODE(os.lstat(item).st_mode) == 0o700
                for item in leaves
            ))
            for leaf in leaves:
                for current, directories, files in os.walk(leaf):
                    self.assertEqual(0o700, stat.S_IMODE(os.lstat(current).st_mode))
                    for child in directories:
                        self.assertEqual(
                            0o700,
                            stat.S_IMODE(os.lstat(Path(current) / child).st_mode),
                        )
                    for child in files:
                        self.assertEqual(
                            0o600,
                            stat.S_IMODE(os.lstat(Path(current) / child).st_mode),
                        )
            self.assertEqual(
                [(0o770, "read-write")] + [(0o550, "read-only")] * 4,
                [(mode, access) for _stage, mode, access in runner.observed],
            )
            self.assertEqual(4, result["independentReadCount"])

    def test_group_handoff_denies_second_writable_and_guessed_leaf(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        for guessed_mode in (0o700, 0o770):
            with self.subTest(mode=oct(guessed_mode)), tempfile.TemporaryDirectory() as name:
                top = Path(name).resolve()
                state = top / "state"
                state.mkdir(mode=0o700)
                repository = top / "repository"
                beads = repository / ".beads"
                beads.mkdir(parents=True)
                (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
                handoff = top / "handoff"
                handoff.mkdir()
                handoff.chmod(0o710 if sys.platform == "darwin" else 0o2710)
                guessed = handoff / ("v27-" + ("f" * 64))
                guessed.mkdir(mode=guessed_mode)
                guessed.chmod(guessed_mode)
                manifest, plan = self.ordinary_plan(str(repository))
                runner = self._custody_runner(root=handoff, key=key)
                with self.linux_setgid_observation(handoff), self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error,
                    "guessed or missing leaf|already has an accessible",
                ):
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner,
                        start_location=1, end_location=5,
                    )

    def test_group_handoff_denies_second_readable_leaf(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        with tempfile.TemporaryDirectory() as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            handoff = top / "handoff"
            handoff.mkdir()
            handoff.chmod(0o710 if sys.platform == "darwin" else 0o2710)
            manifest, plan = self.ordinary_plan(str(repository))
            runner = self._custody_runner(root=handoff, key=key)
            with self.linux_setgid_observation(handoff):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=1, end_location=4,
                )
            custody = (
                state / "native-effects-v27" / plan["operationId"] / "custody"
            )
            stage = boundary._read_effect_record(
                custody / "repository-stage.json",
                key,
                expected_kind="ControllerRepositoryStageV1",
            )
            readable = handoff / stage["payload"]["repositoryCustodyBinding"][
                "snapshotLeaves"
            ][0]
            readable.chmod(0o550)
            with self.linux_setgid_observation(handoff), self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "still granted|already has an accessible custody leaf",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=5, end_location=5,
                )

    def test_release_probe_detects_retained_fd_and_mount_alias(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        retained: list[int] = []

        def hostile_probe(stage_plan, request_key, post):
            descriptor = os.open(
                stage_plan["repositoryPath"],
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            retained.append(descriptor)
            escaped = stage_plan["repositoryPath"].replace(" ", "\\040")
            return controller._worker_repository_release_probe_v27(
                stage_plan,
                request_key,
                worker_session_nonce="a" * 64,
                probe_nonce="c" * 64,
                post_manifest=post,
                descriptor_names=lambda: [str(descriptor)],
                descriptor_target=lambda _descriptor: "/retained-custody-fd",
                mountinfo_reader=lambda: (
                    f"2 1 0:2 {escaped} /mnt rw - none none rw\n".encode()
                ),
            )

        try:
            with tempfile.TemporaryDirectory(prefix="handoff root ") as name:
                top = Path(name).resolve()
                state = top / "state"
                state.mkdir(mode=0o700)
                repository = top / "repository"
                beads = repository / ".beads"
                beads.mkdir(parents=True)
                (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
                handoff = top / "handoff"
                handoff.mkdir()
                handoff.chmod(0o710 if sys.platform == "darwin" else 0o2710)
                manifest, plan = self.ordinary_plan(str(repository))
                runner = self._custody_runner(
                    root=handoff, key=key, probe_factory=hostile_probe
                )
                with self.linux_setgid_observation(handoff), self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error,
                    "release evidence changed",
                ):
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner,
                        start_location=1, end_location=5,
                    )
                self.assertEqual(
                    1,
                    sum(
                        stat.S_IMODE(os.lstat(item).st_mode) == 0o770
                        for item in handoff.iterdir()
                    ),
                )
        finally:
            for descriptor in retained:
                os.close(descriptor)

    def test_release_probe_closes_each_fd_nonce_and_mode_escape(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        with tempfile.TemporaryDirectory(prefix="custody probe ") as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            handoff = top / "handoff"
            handoff.mkdir()
            handoff.chmod(0o710 if sys.platform == "darwin" else 0o2710)
            manifest, plan = self.ordinary_plan(str(repository))
            operation, _history, objects = boundary._effect_state_paths(
                state, plan["operationId"]
            )
            profile = {
                "rootPath": str(handoff),
                "controllerUid": os.geteuid(),
                "workerGid": os.getegid(),
                "workerSessionNonce": "a" * 64,
            }
            with self.linux_setgid_observation(handoff):
                stage_record, effect, _snapshots, _retained, _custody = (
                    boundary._ensure_controller_repository_stage_v27(
                        operation, objects, key, plan, profile=profile
                    )
                )
                stage = boundary.literal_stage_schedule_v27("ordinary")[4]
                binding = boundary._grant_repository_custody_v27(
                    path=effect, stage_record=stage_record, stage=stage
                )
                self.assertIsNotNone(binding)
                stage_plan = boundary.derive_native_stage_action_plan_v27(
                    manifest, plan, stage
                )
                assert stage_plan is not None and binding is not None
                request_key = boundary._derive_native_request_key_v27(
                    key, plan, stage
                )
                stage_plan.update(
                    {
                        "repositoryPath": str(effect),
                        "repositoryCustody": binding,
                        "requestKeyId": boundary.sha256(request_key),
                        "stagePlanSha256": None,
                    }
                )
                stage_plan["stagePlanSha256"] = (
                    boundary._native_stage_plan_digest_v27(stage_plan)
                )
                post = boundary._repository_custody_manifest_v27(
                    effect,
                    controller_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    directory_mode=0o770,
                    file_mode=0o660,
                )
                mountinfo = b"1 0 0:1 / / rw - tmpfs tmpfs rw\n"
                consumed: set[str] = set()
                clean = controller._worker_repository_release_probe_v27(
                    stage_plan,
                    request_key,
                    worker_session_nonce="a" * 64,
                    probe_nonce="1" * 64,
                    post_manifest=post,
                    consumed_nonces=consumed,
                    descriptor_names=lambda: [],
                    mountinfo_reader=lambda: mountinfo,
                )
                self.assertEqual(([], []), (
                    clean["descriptorMatches"], clean["mountMatches"]
                ))
                with self.assertRaisesRegex(
                    controller.ControllerProtocolError, "replayed"
                ):
                    controller._worker_repository_release_probe_v27(
                        stage_plan,
                        request_key,
                        worker_session_nonce="a" * 64,
                        probe_nonce="1" * 64,
                        post_manifest=post,
                        consumed_nonces=consumed,
                        descriptor_names=lambda: [],
                        mountinfo_reader=lambda: mountinfo,
                    )
                directory_fd = os.open(effect, os.O_RDONLY)
                file_fd = os.open(effect / ".beads/issues.jsonl", os.O_RDONLY)
                try:
                    for descriptor, relative in (
                        (directory_fd, "pre:."),
                        (file_fd, "pre:.beads/issues.jsonl"),
                    ):
                        receipt = controller._worker_repository_release_probe_v27(
                            stage_plan,
                            request_key,
                            worker_session_nonce="a" * 64,
                            probe_nonce=("2" if descriptor == directory_fd else "3") * 64,
                            post_manifest=post,
                            descriptor_names=lambda descriptor=descriptor: [str(descriptor)],
                            descriptor_target=lambda _descriptor: "/retained-custody-fd",
                            mountinfo_reader=lambda: mountinfo,
                        )
                        self.assertIn(
                            relative,
                            receipt["descriptorMatches"][0]["relativePaths"],
                        )
                finally:
                    os.close(file_fd)
                    os.close(directory_fd)
                forged = dict(clean)
                forged["probeNonce"] = "9" * 64
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error, "release evidence changed"
                ):
                    boundary._revoke_repository_custody_v27(
                        binding, forged, request_key
                    )
                target = effect / ".beads/issues.jsonl"
                target.chmod(0o666)
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error,
                    "identity or mode changed",
                ):
                    boundary._revoke_repository_custody_v27(
                        binding, clean, request_key
                    )
                target.chmod(0o660)
                renamed = effect.with_name(effect.name + "-substituted")
                effect.rename(renamed)
                with self.assertRaises(FileNotFoundError):
                    boundary._revoke_repository_custody_v27(
                        binding, clean, request_key
                    )

    def test_granted_leaf_restart_requires_fresh_probe_then_revokes(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"

        class CrashRunner:
            def __init__(self, root):
                self.root = root

            def repository_custody_profile_v27(self, _plan):
                return {
                    "rootPath": str(self.root),
                    "controllerUid": os.geteuid(),
                    "workerGid": os.getegid(),
                    "workerSessionNonce": "a" * 64,
                }

            def __call__(self, _manifest, _stage_plan):
                raise RuntimeError("simulated controller death after grant")

            def repository_custody_release_receipt_v27(self, _stage_plan):
                raise RuntimeError("old worker unavailable")

        with tempfile.TemporaryDirectory() as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            handoff = top / "handoff"
            handoff.mkdir()
            handoff.chmod(0o710 if sys.platform == "darwin" else 0o2710)
            manifest, plan = self.ordinary_plan(str(repository))
            runner = CrashRunner(handoff)
            with self.linux_setgid_observation(handoff), self.assertRaisesRegex(
                RuntimeError, "old worker unavailable"
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=1, end_location=5,
                )
            granted = [
                item for item in handoff.iterdir()
                if stat.S_IMODE(os.lstat(item).st_mode) == 0o770
            ]
            self.assertEqual(1, len(granted))
            probes: list[tuple[str, str]] = []

            def fresh_probe(stage_plan, request_key):
                post = boundary._repository_custody_manifest_v27(
                    Path(stage_plan["repositoryPath"]),
                    controller_uid=os.geteuid(),
                    worker_gid=os.getegid(),
                    directory_mode=0o770,
                    file_mode=0o660,
                )
                probes.append(
                    (
                        stage_plan["repositoryCustody"]["workerSessionNonce"],
                        "d" * 64,
                    )
                )
                return controller._worker_repository_release_probe_v27(
                    stage_plan,
                    request_key,
                    worker_session_nonce="d" * 64,
                    probe_nonce="e" * 64,
                    post_manifest=post,
                    descriptor_names=lambda: [],
                    mountinfo_reader=lambda: (
                        b"1 0 0:1 / / rw - tmpfs tmpfs rw\n"
                    ),
                )

            profile = {
                "rootPath": str(handoff),
                "controllerUid": os.geteuid(),
                "workerGid": os.getegid(),
                "workerSessionNonce": "d" * 64,
            }
            with self.linux_setgid_observation(handoff):
                recovered = boundary.recover_repository_custody_v27(
                    state,
                    key,
                    manifest,
                    profile,
                    release_probe=fresh_probe,
                )
                retried = boundary.recover_repository_custody_v27(
                    state,
                    key,
                    manifest,
                    profile,
                    release_probe=lambda _plan, _key: self.fail(
                        "a private already-receipted leaf must not be reprobed"
                    ),
                )
            self.assertEqual(
                {
                    "admittedLeaves": 5,
                    "normalizedPartialGrants": 0,
                    "recoveredGrants": 1,
                },
                recovered,
            )
            self.assertEqual(
                {
                    "admittedLeaves": 5,
                    "normalizedPartialGrants": 0,
                    "recoveredGrants": 0,
                },
                retried,
            )
            self.assertEqual([("a" * 64, "d" * 64)], probes)
            self.assertTrue(all(
                stat.S_IMODE(os.lstat(item).st_mode) == 0o700
                for item in handoff.iterdir()
            ))

    def test_real_sigkill_custody_grant_probe_revoke_release_prefixes(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("real custody SIGKILL matrix requires fork")
        phases = (
            "repository-access-5-intent-temporary-bytes-written",
            "repository-access-5-intent-temporary-file-fsynced",
            "repository-access-5-intent-installed",
            "repository-access-5-intent-install-directory-fsynced",
            "repository-access-5-intent-temporary-unlinked",
            "repository-access-5-intent-directory-fsynced",
            "repository-access-5-intent-durable",
            "repository-access-5-grant-mode-0",
            "repository-access-5-grant-mode-1",
            "repository-access-5-grant-mode-2",
            "repository-access-5-grant-verified",
            "repository-access-5-before-release-probe",
            "repository-access-5-release-probed",
            "repository-access-5-post-manifest-temporary-bytes-written",
            "repository-access-5-post-manifest-temporary-file-fsynced",
            "repository-access-5-post-manifest-installed",
            "repository-access-5-post-manifest-install-directory-fsynced",
            "repository-access-5-post-manifest-temporary-unlinked",
            "repository-access-5-post-manifest-directory-fsynced",
            "repository-access-5-revoke-mode-0",
            "repository-access-5-revoke-mode-1",
            "repository-access-5-revoke-mode-2",
            "repository-access-5-revoke-verified",
            "repository-access-5-release-temporary-bytes-written",
            "repository-access-5-release-temporary-file-fsynced",
            "repository-access-5-release-installed",
            "repository-access-5-release-install-directory-fsynced",
            "repository-access-5-release-temporary-unlinked",
            "repository-access-5-release-directory-fsynced",
        )
        context = multiprocessing.get_context("fork")
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                top = Path(name).resolve()
                state = top / "state"
                state.mkdir(mode=0o700)
                repository = top / "repository"
                beads = repository / ".beads"
                beads.mkdir(parents=True)
                (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
                handoff = top / "handoff"
                handoff.mkdir()
                handoff.chmod(0o710 if sys.platform == "darwin" else 0o2710)
                manifest, plan = self.ordinary_plan(str(repository))

                def die_at_prefix():
                    runner = self._custody_runner(root=handoff, key=key)
                    with self.linux_setgid_observation(handoff):
                        with boundary.inject_native_effect_sigkill_v27(phase):
                            boundary.execute_supervised_effect_v27(
                                state, key, manifest, plan, runner=runner,
                                start_location=1, end_location=5,
                            )

                process = context.Process(target=die_at_prefix)
                process.start()
                process.join(10)
                self.assertFalse(process.is_alive(), phase)
                self.assertEqual(-signal.SIGKILL, process.exitcode, phase)
                probes: list[str] = []

                def recover_probe(stage_plan, request_key):
                    path = Path(stage_plan["repositoryPath"])
                    custody = stage_plan["repositoryCustody"]
                    post = boundary._repository_custody_manifest_v27(
                        path,
                        controller_uid=os.geteuid(),
                        worker_gid=os.getegid(),
                        directory_mode=(
                            0o550 if custody["accessMode"] == "read-only" else 0o770
                        ),
                        file_mode=(
                            0o440 if custody["accessMode"] == "read-only" else 0o660
                        ),
                    )
                    probes.append(stage_plan["stagePlanSha256"])
                    return controller._worker_repository_release_probe_v27(
                        stage_plan,
                        request_key,
                        worker_session_nonce="d" * 64,
                        probe_nonce=(f"{len(probes):064x}"),
                        post_manifest=post,
                        descriptor_names=lambda: [],
                        mountinfo_reader=lambda: (
                            b"1 0 0:1 / / rw - tmpfs tmpfs rw\n"
                        ),
                    )

                with self.linux_setgid_observation(handoff):
                    boundary.recover_repository_custody_v27(
                        state,
                        key,
                        manifest,
                        {
                            "rootPath": str(handoff),
                            "controllerUid": os.geteuid(),
                            "workerGid": os.getegid(),
                            "workerSessionNonce": "d" * 64,
                        },
                        release_probe=recover_probe,
                    )
                self.assertTrue(all(
                    stat.S_IMODE(os.lstat(item).st_mode) == 0o700
                    for item in handoff.iterdir()
                ), phase)
                for leaf in handoff.iterdir():
                    for current, _directories, files in os.walk(leaf):
                        self.assertEqual(
                            0,
                            stat.S_IMODE(os.lstat(current).st_mode) & 0o077,
                            phase,
                        )
                        for filename in files:
                            self.assertEqual(
                                0,
                                stat.S_IMODE(
                                    os.lstat(Path(current) / filename).st_mode
                                ) & 0o077,
                                phase,
                            )

    def test_real_sigkill_stage_and_four_snapshot_materialization_prefixes(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("real materialization SIGKILL matrix requires fork")
        atomic_suffixes = (
            "temporary-bytes-written", "temporary-file-fsynced", "installed",
            "install-directory-fsynced", "temporary-unlinked",
            "directory-fsynced",
        )
        copy_suffixes = (
            "root-created",
            "entry-0-file-created", "entry-0-bytes-written",
            "entry-0-file-fsynced", "entry-0-parent-fsynced",
            "entry-1-directory-created",
            "entry-2-file-created", "entry-2-bytes-written",
            "entry-2-file-fsynced", "entry-2-parent-fsynced",
            "directory-0-fsynced", "directory-1-fsynced",
            "source-revalidated",
        )
        cases: list[tuple[str, int, int]] = []
        cases.extend(
            (
                f"controller-repository-stage-materialization-intent-{suffix}",
                1,
                0,
            )
            for suffix in atomic_suffixes
        )
        cases.extend(
            (f"controller-repository-stage-copy-{suffix}", 1, 0)
            for suffix in copy_suffixes
        )
        cases.extend(
            (f"controller-repository-stage-{suffix}", 1, 0)
            for suffix in atomic_suffixes
        )
        for ordinal in range(4):
            location = 14 + ordinal * 14
            prefix = f"controller-reader-{ordinal}-snapshot"
            cases.extend(
                (f"{prefix}-materialization-intent-{suffix}", location, ordinal + 1)
                for suffix in atomic_suffixes
            )
            cases.extend(
                (f"{prefix}-copy-{suffix}", location, ordinal + 1)
                for suffix in copy_suffixes
            )
            cases.extend(
                (f"{prefix}-{suffix}", location, ordinal + 1)
                for suffix in atomic_suffixes
            )

        context = multiprocessing.get_context("fork")
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        for phase, end_location, expected_calls in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                top = Path(name).resolve()
                state = top / "state"
                state.mkdir(mode=0o700)
                repository = top / "repository"
                beads = repository / ".beads"
                (beads / "noms").mkdir(parents=True)
                (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
                (beads / "noms/manifest").write_bytes(b"manifest-v1\n")
                counter = top / "payload-calls"
                manifest, plan = self.ordinary_plan(str(repository))

                def runner(_manifest, stage_plan):
                    descriptor = os.open(
                        counter,
                        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                        0o600,
                    )
                    try:
                        os.write(descriptor, b"1\n")
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    stage_key = stage_plan["stageKey"]
                    stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                    if stage_key.startswith("reader-"):
                        stdout = reads[int(stage_key.split("-")[1])]
                    return self.successful_native_result(stage_plan, stdout=stdout)

                def prepare_and_run_target() -> None:
                    if end_location == 1:
                        boundary.execute_supervised_effect_v27(
                            state, key, manifest, plan, runner=runner,
                            start_location=1, end_location=1,
                        )
                        return
                    target_ordinal = (end_location - 14) // 14
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner,
                        start_location=1, end_location=13,
                    )
                    for prior_ordinal in range(target_ordinal):
                        boundary.execute_supervised_effect_v27(
                            state, key, manifest, plan, runner=runner,
                            start_location=14 + prior_ordinal * 14,
                            end_location=27 + prior_ordinal * 14,
                        )
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner,
                        start_location=end_location,
                        end_location=end_location,
                    )

                def die_at_prefix():
                    with boundary.inject_native_effect_sigkill_v27(phase):
                        prepare_and_run_target()

                process = context.Process(target=die_at_prefix)
                process.start()
                process.join(15)
                self.assertFalse(process.is_alive(), phase)
                self.assertEqual(-signal.SIGKILL, process.exitcode, phase)
                before = (
                    counter.read_text().count("1\n") if counter.exists() else 0
                )
                self.assertEqual(expected_calls, before, phase)
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=end_location, end_location=end_location,
                )
                after = (
                    counter.read_text().count("1\n") if counter.exists() else 0
                )
                self.assertEqual(expected_calls, after, phase)

                operation = state / "native-effects-v27" / plan["operationId"]
                custody = operation / "custody"
                stage = boundary._read_effect_record(
                    custody / "repository-stage.json",
                    key,
                    expected_kind="ControllerRepositoryStageV1",
                )
                self.assertRegex(stage["recordSha256"], r"\Asha256:[0-9a-f]{64}\Z")
                if end_location > 1:
                    ordinal = (end_location - 14) // 14
                    snapshot = boundary._read_effect_record(
                        custody / f"reader-{ordinal}-snapshot.json",
                        key,
                        expected_kind="ControllerReadSnapshotV1",
                    )
                    self.assertEqual(ordinal, snapshot["payload"]["ordinal"])

    def test_materialization_intent_rejects_source_or_destination_substitution(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        with tempfile.TemporaryDirectory() as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            issues = beads / "issues.jsonl"
            issues.write_bytes(b'{"id":"task-1"}\n')
            manifest, plan = self.ordinary_plan(str(repository))
            with self.assertRaises(SystemExit), boundary.inject_native_effect_fault_v27(
                "controller-repository-stage-copy-entry-0-file-created"
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=lambda *_args: self.fail()
                )
            replacement = beads / "issues.next"
            replacement.write_bytes(issues.read_bytes())
            os.replace(replacement, issues)
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "final bytes conflict",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=lambda *_args: self.fail()
                )

        with tempfile.TemporaryDirectory() as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            manifest, plan = self.ordinary_plan(str(repository))
            with self.assertRaises(SystemExit), boundary.inject_native_effect_fault_v27(
                "controller-repository-stage-copy-entry-0-file-created"
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=lambda *_args: self.fail()
                )
            operation = state / "native-effects-v27" / plan["operationId"]
            staged = operation / "custody/effect/.beads"
            external = top / "external"
            external.mkdir()
            (staged / "issues.jsonl").unlink()
            staged.rmdir()
            staged.symlink_to(external, target_is_directory=True)
            with self.assertRaises(boundary.NativeBoundaryV27Error):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=lambda *_args: self.fail()
                )
            self.assertEqual([], list(external.iterdir()))

        with tempfile.TemporaryDirectory() as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            manifest, plan = self.ordinary_plan(str(repository))
            with self.assertRaises(SystemExit), boundary.inject_native_effect_fault_v27(
                "controller-repository-stage-materialization-intent-directory-fsynced"
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=lambda *_args: self.fail()
                )
            original = top / "repository-original"
            repository.rename(original)
            repository.symlink_to(original, target_is_directory=True)
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "cannot pin repository ancestry",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=lambda *_args: self.fail()
                )

    def test_real_sigkill_publication_and_public_receipt_suffixes(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("real publication SIGKILL matrix requires fork")
        atomic_suffixes = (
            "temporary-bytes-written", "temporary-file-fsynced", "installed",
            "install-directory-fsynced", "temporary-unlinked",
            "directory-fsynced",
        )
        immutable_suffixes = (
            "bytes-written", "file-fsynced", "directory-fsynced",
        )
        completion_suffixes = (
            "history-bytes-written", "history-file-fsynced",
            "history-directory-fsynced", "current-temporary-bytes-written",
            "current-temporary-file-fsynced", "current-cas-replaced",
            "current-cas-directory-fsynced",
        )

        def engine_phases(location: int) -> list[str]:
            phases = [
                *(f"location-{location}-result-object-{suffix}" for suffix in immutable_suffixes),
                f"location-{location}-result-object-written",
                *(f"location-{location}-receipt-object-{suffix}" for suffix in immutable_suffixes),
                f"location-{location}-receipt-object-written",
                *(f"location-{location}-completion-{suffix}" for suffix in completion_suffixes),
                f"location-{location}-completion-current-installed",
            ]
            return list(phases)

        cases: list[tuple[str, int]] = [
            *(
                (f"repository-publication-candidate-{suffix}", 72)
                for suffix in atomic_suffixes
            ),
            *((phase, 72) for phase in engine_phases(72)),
            ("repository-publication-candidate-copy-root-created", 73),
            ("repository-publication-candidate-copy-entry-0-file-created", 73),
            ("repository-publication-candidate-copy-entry-0-bytes-written", 73),
            ("repository-publication-candidate-copy-entry-0-file-fsynced", 73),
            ("repository-publication-candidate-copy-entry-0-parent-fsynced", 73),
            ("repository-publication-candidate-copy-directory-0-fsynced", 73),
            ("repository-publication-candidate-copy-source-revalidated", 73),
            *(
                (f"repository-publication-materialization-{suffix}", 73)
                for suffix in atomic_suffixes
            ),
            ("repository-publication-previous-installed", 73),
            ("repository-publication-candidate-installed", 73),
            *(
                (f"repository-publication-receipt-{suffix}", 73)
                for suffix in atomic_suffixes
            ),
            *((phase, 73) for phase in engine_phases(73)),
            *((phase, 74) for phase in engine_phases(74)),
            *((phase, 75) for phase in engine_phases(75)),
        ]
        context = multiprocessing.get_context("fork")
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        for phase, target_location in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                top = Path(name).resolve()
                state = top / "state"
                state.mkdir(mode=0o700)
                repository = top / "repository"
                beads = repository / ".beads"
                beads.mkdir(parents=True)
                issues = beads / "issues.jsonl"
                issues.write_bytes(b'{"id":"task-1","status":"open"}\n')
                counter = top / "payload-calls"
                manifest, plan = self.ordinary_plan(str(repository))

                def runner(_manifest, stage_plan):
                    descriptor = os.open(
                        counter,
                        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                        0o600,
                    )
                    try:
                        os.write(descriptor, b"1\n")
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    stage_key = stage_plan["stageKey"]
                    stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                    if stage_key == "effect-payload-terminal":
                        (
                            Path(stage_plan["repositoryPath"])
                            / ".beads/issues.jsonl"
                        ).write_bytes(
                            b'{"id":"task-1","status":"active"}\n'
                        )
                    elif stage_key.startswith("reader-"):
                        stdout = reads[int(stage_key.split("-")[1])]
                    return self.successful_native_result(stage_plan, stdout=stdout)

                def execute_row(location: int) -> None:
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner,
                        start_location=location, end_location=location,
                    )

                # Reach the exact tail predecessor with one payload per
                # authorized segment; no incomplete segment spans two native
                # commands.
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=1, end_location=13,
                )
                for ordinal in range(4):
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner,
                        start_location=14 + ordinal * 14,
                        end_location=27 + ordinal * 14,
                    )
                execute_row(70)
                execute_row(71)
                for prior in range(72, target_location):
                    execute_row(prior)
                self.assertEqual(5, counter.read_text().count("1\n"), phase)

                def die_at_prefix():
                    with boundary.inject_native_effect_sigkill_v27(phase):
                        execute_row(target_location)

                process = context.Process(target=die_at_prefix)
                process.start()
                process.join(15)
                self.assertFalse(process.is_alive(), phase)
                self.assertEqual(-signal.SIGKILL, process.exitcode, phase)
                execute_row(target_location)
                self.assertEqual(5, counter.read_text().count("1\n"), phase)
                current = boundary.inspect_supervised_effect_v27(
                    state, key, plan["operationId"]
                )
                self.assertEqual(
                    (target_location, "completion"),
                    (current["payload"]["location"], current["payload"]["state"]),
                    phase,
                )
                if target_location >= 73:
                    self.assertEqual(
                        b'{"id":"task-1","status":"active"}\n',
                        issues.read_bytes(),
                        phase,
                    )
                    custody = (
                        state / "native-effects-v27" / plan["operationId"]
                        / "custody"
                    )
                    boundary._read_effect_record(
                        custody / "publication-receipt.json",
                        key,
                        expected_kind="RepositoryPublicationReceiptV1",
                    )

    def test_real_sigkill_combined_receipt_comment_and_done_suffixes(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("real terminal-receipt SIGKILL matrix requires fork")
        immutable_suffixes = (
            "bytes-written", "file-fsynced", "directory-fsynced",
        )
        completion_suffixes = (
            "history-bytes-written", "history-file-fsynced",
            "history-directory-fsynced", "current-temporary-bytes-written",
            "current-temporary-file-fsynced", "current-cas-replaced",
            "current-cas-directory-fsynced",
        )

        def engine_phases(location: int) -> list[str]:
            return [
                *(f"location-{location}-result-object-{suffix}" for suffix in immutable_suffixes),
                f"location-{location}-result-object-written",
                *(f"location-{location}-receipt-object-{suffix}" for suffix in immutable_suffixes),
                f"location-{location}-receipt-object-written",
                *(f"location-{location}-completion-{suffix}" for suffix in completion_suffixes),
                f"location-{location}-completion-current-installed",
            ]

        targets = {
            "ordinary": (75, 76),
            "claim-cas": (75, 76),
            "receipt-comment": (74, 75, 76, 77),
        }
        context = multiprocessing.get_context("fork")
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        for operation_class, locations in targets.items():
            for target_location in locations:
                for phase in engine_phases(target_location):
                    with self.subTest(
                        operation_class=operation_class,
                        location=target_location,
                        phase=phase,
                    ), tempfile.TemporaryDirectory() as name:
                        top = Path(name).resolve()
                        state = top / "state"
                        state.mkdir(mode=0o700)
                        repository = top / "repository"
                        beads = repository / ".beads"
                        beads.mkdir(parents=True)
                        issues = beads / "issues.jsonl"
                        issues.write_bytes(b'{"id":"task-1","status":"open"}\n')
                        counter = top / "payload-calls"
                        if operation_class == "ordinary":
                            manifest, plan = self.ordinary_plan(str(repository))
                        elif operation_class == "claim-cas":
                            manifest, plan = self.claim_plan(str(repository))
                        else:
                            manifest, plan = self.receipt_comment_plan(str(repository))

                        def runner(_manifest, stage_plan):
                            descriptor = os.open(
                                counter,
                                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                                0o600,
                            )
                            try:
                                os.write(descriptor, b"1\n")
                                os.fsync(descriptor)
                            finally:
                                os.close(descriptor)
                            stage_key = stage_plan["stageKey"]
                            stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                            if stage_key == "effect-payload-terminal":
                                (
                                    Path(stage_plan["repositoryPath"])
                                    / ".beads/issues.jsonl"
                                ).write_bytes(
                                    b'{"id":"task-1","status":"active"}\n'
                                )
                            elif stage_key.startswith("reader-"):
                                stdout = reads[int(stage_key.split("-")[1])]
                            return self.successful_native_result(
                                stage_plan, stdout=stdout
                            )

                        def execute_row(location: int):
                            return boundary.execute_supervised_effect_v27(
                                state, key, manifest, plan, runner=runner,
                                start_location=location, end_location=location,
                            )

                        boundary.execute_supervised_effect_v27(
                            state, key, manifest, plan, runner=runner,
                            start_location=1, end_location=13,
                        )
                        for ordinal in range(4):
                            boundary.execute_supervised_effect_v27(
                                state, key, manifest, plan, runner=runner,
                                start_location=14 + ordinal * 14,
                                end_location=27 + ordinal * 14,
                            )
                        for prior in range(70, target_location):
                            execute_row(prior)
                        self.assertEqual(
                            5, counter.read_text().count("1\n"), phase
                        )

                        def die_at_prefix():
                            with boundary.inject_native_effect_sigkill_v27(phase):
                                execute_row(target_location)

                        process = context.Process(target=die_at_prefix)
                        process.start()
                        process.join(15)
                        self.assertFalse(process.is_alive(), phase)
                        self.assertEqual(-signal.SIGKILL, process.exitcode, phase)
                        recovered = execute_row(target_location)
                        self.assertEqual(
                            5, counter.read_text().count("1\n"), phase
                        )
                        self.assertEqual(
                            b'{"id":"task-1","status":"active"}\n',
                            issues.read_bytes(),
                            phase,
                        )
                        current = boundary.inspect_supervised_effect_v27(
                            state, key, plan["operationId"]
                        )
                        self.assertEqual(
                            (target_location, "completion"),
                            (
                                current["payload"]["location"],
                                current["payload"]["state"],
                            ),
                            phase,
                        )
                        history = (
                            state / "native-effects-v27"
                            / plan["operationId"] / "history"
                        )
                        self.assertLessEqual(
                            max(
                                json.loads(path.read_bytes())["payload"]["location"]
                                for path in history.glob("*.json")
                            ),
                            target_location,
                            phase,
                        )
                        expected_stage = boundary.literal_stage_schedule_v27(
                            operation_class
                        )[target_location - 1]
                        objects = (
                            state / "native-effects-v27"
                            / plan["operationId"] / "objects"
                        )
                        results = [
                            json.loads(path.read_bytes())
                            for path in objects.glob("*.json")
                            if json.loads(path.read_bytes()).get("kind")
                            == "StageActionResultV1"
                            and json.loads(path.read_bytes()).get("payload", {}).get(
                                "location"
                            ) == target_location
                        ]
                        self.assertEqual(1, len(results), phase)
                        self.assertEqual(
                            expected_stage.stage_key,
                            results[0]["payload"]["stageKey"],
                            phase,
                        )
                        if target_location == len(
                            boundary.literal_stage_schedule_v27(operation_class)
                        ):
                            self.assertEqual(4, recovered["independentReadCount"])

    def test_publication_requires_all_snapshot_and_physical_join_evidence(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        with tempfile.TemporaryDirectory() as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            manifest, plan = self.ordinary_plan(str(repository))

            def runner(_manifest, stage_plan):
                stage_key = stage_plan["stageKey"]
                stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                if stage_key.startswith("reader-"):
                    stdout = reads[int(stage_key.split("-")[1])]
                return self.successful_native_result(stage_plan, stdout=stdout)

            boundary.execute_supervised_effect_v27(
                state, key, manifest, plan, runner=runner,
                start_location=1, end_location=13,
            )
            for ordinal in range(4):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=14 + ordinal * 14,
                    end_location=27 + ordinal * 14,
                )
            for location in (70, 71):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=location, end_location=location,
                )
            operation = state / "native-effects-v27" / plan["operationId"]
            missing = operation / "custody/reader-3-snapshot.json"
            missing.unlink()
            with self.assertRaises(boundary.NativeBoundaryV27Error):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=72, end_location=72,
                )
            self.assertFalse(
                (operation / "custody/publication-candidate.json").exists()
            )

    def test_publication_rejects_old_candidate_ambiguity_and_cleanup_before_install(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        with tempfile.TemporaryDirectory() as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            manifest, plan = self.ordinary_plan(str(repository))

            def runner(_manifest, stage_plan):
                stage_key = stage_plan["stageKey"]
                stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                if stage_key.startswith("reader-"):
                    stdout = reads[int(stage_key.split("-")[1])]
                return self.successful_native_result(stage_plan, stdout=stdout)

            boundary.execute_supervised_effect_v27(
                state, key, manifest, plan, runner=runner,
                start_location=1, end_location=13,
            )
            for ordinal in range(4):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=14 + ordinal * 14,
                    end_location=27 + ordinal * 14,
                )
            for location in (70, 71, 72):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=location, end_location=location,
                )
            operation = state / "native-effects-v27" / plan["operationId"]
            custody = operation / "custody"
            stage_record = boundary._read_effect_record(
                custody / "repository-stage.json",
                key,
                expected_kind="ControllerRepositoryStageV1",
            )
            candidate = boundary._read_effect_record(
                custody / "publication-candidate.json",
                key,
                expected_kind="RepositoryPublicationCandidateV1",
            )
            previous = repository / candidate["payload"]["previousLeaf"]
            boundary.materialize_controller_owned_beads_tree_v27(
                repository / ".beads",
                previous,
                source_requires_private_modes=False,
                destination_parent_requires_private_modes=False,
            )
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "rollback tree was substituted|did not reach",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=73, end_location=73,
                )
            self.assertFalse((custody / "publication-receipt.json").exists())
            with self.assertRaises(boundary.NativeBoundaryV27Error):
                boundary._retire_controller_previous_tree_v27(
                    custody=custody,
                    retained=operation / "custody/retained",
                    key=key,
                    plan=plan,
                    stage_record=stage_record,
                )

    def test_publication_rejects_same_byte_installed_inode_replacement(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        with tempfile.TemporaryDirectory() as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            issues = beads / "issues.jsonl"
            issues.write_bytes(b'{"id":"task-1","status":"open"}\n')
            manifest, plan = self.ordinary_plan(str(repository))

            def runner(_manifest, stage_plan):
                stage_key = stage_plan["stageKey"]
                stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                if stage_key == "effect-payload-terminal":
                    (
                        Path(stage_plan["repositoryPath"])
                        / ".beads/issues.jsonl"
                    ).write_bytes(
                        b'{"id":"task-1","status":"active"}\n'
                    )
                elif stage_key.startswith("reader-"):
                    stdout = reads[int(stage_key.split("-")[1])]
                return self.successful_native_result(stage_plan, stdout=stdout)

            boundary.execute_supervised_effect_v27(
                state, key, manifest, plan, runner=runner,
                start_location=1, end_location=13,
            )
            for ordinal in range(4):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=14 + ordinal * 14,
                    end_location=27 + ordinal * 14,
                )
            for location in (70, 71, 72):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=location, end_location=location,
                )
            with self.assertRaises(SystemExit), boundary.inject_native_effect_fault_v27(
                "repository-publication-candidate-installed"
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=73, end_location=73,
                )

            replacement = repository / ".same-byte-replacement"
            boundary.materialize_controller_owned_beads_tree_v27(
                repository / ".beads",
                replacement,
                source_requires_private_modes=True,
                destination_parent_requires_private_modes=False,
            )
            os.rename(repository / ".beads", repository / ".installed-original")
            os.rename(replacement, repository / ".beads")
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "publication materialization was substituted",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=73, end_location=73,
                )
            operation = state / "native-effects-v27" / plan["operationId"]
            self.assertFalse(
                (operation / "custody/publication-receipt.json").exists()
            )

    def test_publication_rejects_repository_root_replacement_with_same_beads_inode(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        with tempfile.TemporaryDirectory() as name:
            top = Path(name).resolve()
            state = top / "state"
            state.mkdir(mode=0o700)
            repository = top / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(
                b'{"id":"task-1","status":"open"}\n'
            )
            manifest, plan = self.ordinary_plan(str(repository))

            def runner(_manifest, stage_plan):
                stage_key = stage_plan["stageKey"]
                stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                if stage_key == "effect-payload-terminal":
                    (
                        Path(stage_plan["repositoryPath"])
                        / ".beads/issues.jsonl"
                    ).write_bytes(
                        b'{"id":"task-1","status":"active"}\n'
                    )
                elif stage_key.startswith("reader-"):
                    stdout = reads[int(stage_key.split("-")[1])]
                return self.successful_native_result(stage_plan, stdout=stdout)

            boundary.execute_supervised_effect_v27(
                state, key, manifest, plan, runner=runner,
                start_location=1, end_location=13,
            )
            for ordinal in range(4):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=14 + ordinal * 14,
                    end_location=27 + ordinal * 14,
                )
            for location in (70, 71, 72):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=location, end_location=location,
                )

            original_repository = top / "repository-original"
            repository.rename(original_repository)
            repository.mkdir()
            os.rename(
                original_repository / ".beads", repository / ".beads"
            )
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "producer repository path identity changed",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=73, end_location=73,
                )
            operation = state / "native-effects-v27" / plan["operationId"]
            self.assertFalse(
                (operation / "custody/publication-receipt.json").exists()
            )

    def test_real_sigkill_create_install_observe_cleanup_rows_53_to_57(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("real create-tail SIGKILL matrix requires fork")
        atomic_suffixes = (
            "temporary-bytes-written", "temporary-file-fsynced", "installed",
            "install-directory-fsynced", "temporary-unlinked",
            "directory-fsynced",
        )
        immutable_suffixes = (
            "bytes-written", "file-fsynced", "directory-fsynced",
        )
        completion_suffixes = (
            "history-bytes-written", "history-file-fsynced",
            "history-directory-fsynced", "current-temporary-bytes-written",
            "current-temporary-file-fsynced", "current-cas-replaced",
            "current-cas-directory-fsynced",
        )

        def engine_phases(location: int) -> list[str]:
            return [
                *(f"location-{location}-result-object-{suffix}" for suffix in immutable_suffixes),
                f"location-{location}-result-object-written",
                *(f"location-{location}-receipt-object-{suffix}" for suffix in immutable_suffixes),
                f"location-{location}-receipt-object-written",
                *(f"location-{location}-completion-{suffix}" for suffix in completion_suffixes),
                f"location-{location}-completion-current-installed",
            ]

        cases: list[tuple[str, int]] = [
            *(
                (f"repository-publication-candidate-{suffix}", 53)
                for suffix in atomic_suffixes
            ),
            *((phase, 53) for phase in engine_phases(53)),
            *((phase, 54) for phase in engine_phases(54)),
            ("repository-publication-candidate-copy-root-created", 55),
            ("repository-publication-candidate-copy-entry-0-file-created", 55),
            ("repository-publication-candidate-copy-entry-0-bytes-written", 55),
            ("repository-publication-candidate-copy-entry-0-file-fsynced", 55),
            ("repository-publication-candidate-copy-entry-0-parent-fsynced", 55),
            ("repository-publication-candidate-copy-directory-0-fsynced", 55),
            ("repository-publication-candidate-copy-source-revalidated", 55),
            *(
                (f"repository-publication-materialization-{suffix}", 55)
                for suffix in atomic_suffixes
            ),
            ("repository-publication-previous-installed", 55),
            ("repository-publication-candidate-installed", 55),
            *(
                (f"repository-publication-receipt-{suffix}", 55)
                for suffix in atomic_suffixes
            ),
            *((phase, 55) for phase in engine_phases(55)),
            *((phase, 56) for phase in engine_phases(56)),
            ("controller-cleanup-previous-retired", 57),
            *(
                (f"controller-cleanup-retirement-{suffix}", 57)
                for suffix in atomic_suffixes
            ),
            *((phase, 57) for phase in engine_phases(57)),
        ]
        context = multiprocessing.get_context("fork")
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        for phase, target_location in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                top = Path(name).resolve()
                state = top / "state"
                state.mkdir(mode=0o700)
                repository = top / "preparation"
                beads = repository / ".beads"
                beads.mkdir(parents=True, mode=0o700)
                beads.chmod(0o700)
                metadata = beads / "metadata.json"
                metadata.write_bytes(b'{"state":"before"}\n')
                metadata.chmod(0o600)
                counter = top / "payload-calls"
                manifest, plan = self.create_preparation_plan(str(repository))

                def runner(_manifest, stage_plan):
                    descriptor = os.open(
                        counter,
                        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                        0o600,
                    )
                    try:
                        os.write(descriptor, b"1\n")
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    if stage_plan["stageKey"] == "status-read-payload-terminal":
                        (
                            Path(stage_plan["repositoryPath"])
                            / ".beads/metadata.json"
                        ).write_bytes(b'{"state":"installed"}\n')
                    return self.successful_native_result(
                        stage_plan,
                        stdout=b'{"data":{},"schema_version":1}\n',
                    )

                def execute_row(location: int) -> None:
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner,
                        start_location=location, end_location=location,
                    )

                for ordinal in range(4):
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner,
                        start_location=ordinal * 13 + 1,
                        end_location=(ordinal + 1) * 13,
                    )
                for prior in range(53, target_location):
                    execute_row(prior)
                self.assertEqual(4, counter.read_text().count("1\n"), phase)

                def die_at_prefix():
                    with boundary.inject_native_effect_sigkill_v27(phase):
                        execute_row(target_location)

                process = context.Process(target=die_at_prefix)
                process.start()
                process.join(15)
                self.assertFalse(process.is_alive(), phase)
                self.assertEqual(-signal.SIGKILL, process.exitcode, phase)
                execute_row(target_location)
                self.assertEqual(4, counter.read_text().count("1\n"), phase)
                current = boundary.inspect_supervised_effect_v27(
                    state, key, plan["operationId"]
                )
                self.assertEqual(
                    (target_location, "completion"),
                    (current["payload"]["location"], current["payload"]["state"]),
                    phase,
                )
                self.assertEqual(
                    (
                        b'{"state":"installed"}\n'
                        if target_location >= 55
                        else b'{"state":"before"}\n'
                    ),
                    metadata.read_bytes(),
                    phase,
                )
                previous = tuple(
                    repository.glob(".startup-factory-beads-previous-*")
                )
                if target_location == 55 or target_location == 56:
                    self.assertEqual(1, len(previous), phase)
                elif target_location >= 57:
                    self.assertEqual((), previous, phase)
                    retained = (
                        state / "native-effects-v27" / plan["operationId"]
                        / "custody/retained"
                    )
                    self.assertEqual(1, len(tuple(retained.glob("previous-*"))), phase)

    def test_real_sigkill_reattest_checkpoint_and_activation_rows_17_to_22(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("real reattest-tail SIGKILL matrix requires fork")
        atomic_suffixes = (
            "temporary-bytes-written", "temporary-file-fsynced", "installed",
            "install-directory-fsynced", "temporary-unlinked",
            "directory-fsynced",
        )
        immutable_suffixes = (
            "bytes-written", "file-fsynced", "directory-fsynced",
        )
        completion_suffixes = (
            "history-bytes-written", "history-file-fsynced",
            "history-directory-fsynced", "current-temporary-bytes-written",
            "current-temporary-file-fsynced", "current-cas-replaced",
            "current-cas-directory-fsynced",
        )

        def engine_phases(location: int) -> list[str]:
            return [
                *(f"location-{location}-result-object-{suffix}" for suffix in immutable_suffixes),
                f"location-{location}-result-object-written",
                *(f"location-{location}-receipt-object-{suffix}" for suffix in immutable_suffixes),
                f"location-{location}-receipt-object-written",
                *(f"location-{location}-completion-{suffix}" for suffix in completion_suffixes),
                f"location-{location}-completion-current-installed",
            ]

        cases: list[tuple[str, int]] = [
            *((phase, 17) for phase in engine_phases(17)),
            *(
                (f"repository-publication-candidate-{suffix}", 18)
                for suffix in atomic_suffixes
            ),
            *((phase, 18) for phase in engine_phases(18)),
            *((phase, 19) for phase in engine_phases(19)),
            *((phase, 20) for phase in engine_phases(20)),
            *((phase, 21) for phase in engine_phases(21)),
            *((phase, 22) for phase in engine_phases(22)),
        ]
        context = multiprocessing.get_context("fork")
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        for phase, target_location in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                top = Path(name).resolve()
                state = top / "state"
                state.mkdir(mode=0o700)
                repository = top / "installed-selector"
                beads = repository / ".beads"
                beads.mkdir(parents=True, mode=0o700)
                beads.chmod(0o700)
                metadata = beads / "metadata.json"
                original = b'{"state":"installed"}\n'
                metadata.write_bytes(original)
                metadata.chmod(0o600)
                counter = top / "payload-calls"
                manifest, plan = self.reattest_preparation_plan(str(repository))

                def runner(_manifest, stage_plan):
                    descriptor = os.open(
                        counter,
                        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                        0o600,
                    )
                    try:
                        os.write(descriptor, b"1\n")
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    return self.successful_native_result(
                        stage_plan,
                        stdout=b'{"data":{},"schema_version":1}\n',
                    )

                def execute_row(location: int) -> None:
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner,
                        start_location=location, end_location=location,
                    )

                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=1, end_location=13,
                )
                for prior in range(14, target_location):
                    execute_row(prior)
                self.assertEqual(1, counter.read_text().count("1\n"), phase)

                def die_at_prefix():
                    with boundary.inject_native_effect_sigkill_v27(phase):
                        execute_row(target_location)

                process = context.Process(target=die_at_prefix)
                process.start()
                process.join(15)
                self.assertFalse(process.is_alive(), phase)
                self.assertEqual(-signal.SIGKILL, process.exitcode, phase)
                execute_row(target_location)
                self.assertEqual(1, counter.read_text().count("1\n"), phase)
                self.assertEqual(original, metadata.read_bytes(), phase)
                self.assertEqual(
                    (), tuple(repository.glob(".startup-factory-beads-previous-*")),
                    phase,
                )
                current = boundary.inspect_supervised_effect_v27(
                    state, key, plan["operationId"]
                )
                self.assertEqual(
                    (target_location, "completion"),
                    (current["payload"]["location"], current["payload"]["state"]),
                    phase,
                )
                history = (
                    state / "native-effects-v27" / plan["operationId"] / "history"
                )
                self.assertLessEqual(
                    max(
                        json.loads(path.read_bytes())["payload"]["location"]
                        for path in history.glob("*.json")
                    ),
                    target_location,
                    phase,
                )

    def test_controller_stage_and_four_snapshots_never_expose_producer_path(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        native_paths: dict[str, Path] = {}

        def runner(_manifest, stage_plan):
            stage_key = stage_plan["stageKey"]
            repository_path = Path(stage_plan["repositoryPath"])
            native_paths[stage_key] = repository_path
            self.assertNotEqual(producer, repository_path)
            self.assertTrue(repository_path.is_dir())
            self.assertTrue((repository_path / ".beads").is_dir())
            if stage_key == "effect-payload-terminal":
                (repository_path / ".beads/issues.jsonl").write_bytes(
                    b'{"id":"task-1","status":"active"}\n'
                )
                stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
            else:
                ordinal = int(stage_key.split("-")[1])
                stdout = reads[ordinal]
            return self.successful_native_result(stage_plan, stdout=stdout)

        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            state = root / "state"
            state.mkdir(mode=0o700)
            producer = root / "repository"
            beads = producer / ".beads"
            beads.mkdir(parents=True, mode=0o700)
            beads.chmod(0o700)
            issues = beads / "issues.jsonl"
            issues.write_bytes(b'{"id":"task-1","status":"open"}\n')
            issues.chmod(0o600)
            manifest, plan = self.ordinary_plan(str(producer))
            result = boundary.execute_supervised_effect_v27(
                state, key, manifest, plan, runner=runner
            )
            self.assertEqual(
                b'{"id":"task-1","status":"active"}\n', issues.read_bytes()
            )
            effect_path = native_paths["effect-payload-terminal"]
            reader_paths = [
                native_paths[f"reader-{ordinal}-payload-terminal"]
                for ordinal in range(4)
            ]
            self.assertEqual(4, len(set(reader_paths)))
            self.assertNotIn(effect_path, reader_paths)
            self.assertTrue(
                all(path.is_relative_to(state) for path in [effect_path, *reader_paths])
            )
            objects = [
                json.loads(path.read_bytes())
                for path in (
                    state / "native-effects-v27" / plan["operationId"] / "objects"
                ).glob("*.json")
            ]
            snapshots = [
                item["payload"]["observation"]["controllerSnapshot"]
                for item in objects
                if item["kind"] == "StageActionResultV1"
                and item["payload"]["stageKind"] == "snapshot"
            ]
            snapshots.sort(key=lambda item: item["ordinal"])
            self.assertEqual([0, 1, 2, 3], [item["ordinal"] for item in snapshots])
            self.assertEqual(4, len({item["snapshotIdentitySha256"] for item in snapshots}))
            self.assertTrue(result["crossWindowNoEffect"])

    def test_repository_publication_refuses_producer_change_and_preserves_stage(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        changed = False
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            state = root / "state"
            state.mkdir(mode=0o700)
            producer = root / "repository"
            beads = producer / ".beads"
            beads.mkdir(parents=True, mode=0o700)
            beads.chmod(0o700)
            issues = beads / "issues.jsonl"
            original = b'{"id":"task-1","status":"open"}\n'
            issues.write_bytes(original)
            issues.chmod(0o600)
            manifest, plan = self.ordinary_plan(str(producer))

            def runner(_manifest, stage_plan):
                nonlocal changed
                stage_key = stage_plan["stageKey"]
                if stage_key == "effect-payload-terminal":
                    (Path(stage_plan["repositoryPath"]) / ".beads/issues.jsonl").write_bytes(
                        b'{"id":"task-1","status":"active"}\n'
                    )
                    stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                else:
                    stdout = reads[int(stage_key.split("-")[1])]
                    if stage_key == "reader-3-payload-terminal" and not changed:
                        issues.write_bytes(original + b'{"producer":"changed"}\n')
                        changed = True
                return self.successful_native_result(stage_plan, stdout=stdout)

            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "repository prestate changed before publication",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner
                )
            self.assertEqual(original + b'{"producer":"changed"}\n', issues.read_bytes())
            current = boundary.inspect_supervised_effect_v27(
                state, key, plan["operationId"]
            )
            self.assertEqual((73, "intent-current"), (
                current["payload"]["location"], current["payload"]["state"]
            ))
            stage = (
                state / "native-effects-v27" / plan["operationId"]
                / "custody" / "effect"
            )
            self.assertEqual(
                b'{"id":"task-1","status":"active"}\n',
                (stage / ".beads/issues.jsonl").read_bytes(),
            )

    def test_create_install_and_cleanup_run_only_at_literal_tail_rows(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        calls: list[tuple[int, Path]] = []
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            state = root / "state"
            state.mkdir(mode=0o700)
            producer = root / "preparation"
            beads = producer / ".beads"
            beads.mkdir(parents=True, mode=0o700)
            beads.chmod(0o700)
            metadata = beads / "metadata.json"
            metadata.write_bytes(b'{"state":"before"}\n')
            metadata.chmod(0o600)
            manifest, plan = self.create_preparation_plan(str(producer))

            def runner(_manifest, stage_plan):
                stage_path = Path(stage_plan["repositoryPath"])
                calls.append((stage_plan["stageLocation"], stage_path))
                if stage_plan["stageKey"] == "status-read-payload-terminal":
                    (stage_path / ".beads/metadata.json").write_bytes(
                        b'{"state":"installed"}\n'
                    )
                return self.successful_native_result(
                    stage_plan, stdout=b'{"data":{},"schema_version":1}\n'
                )

            for ordinal in range(4):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner,
                    start_location=(ordinal * 13) + 1,
                    end_location=(ordinal + 1) * 13,
                )
            self.assertEqual(b'{"state":"before"}\n', metadata.read_bytes())
            boundary.execute_supervised_effect_v27(
                state, key, manifest, plan, runner=runner,
                start_location=53, end_location=54,
            )
            self.assertEqual(b'{"state":"before"}\n', metadata.read_bytes())
            boundary.execute_supervised_effect_v27(
                state, key, manifest, plan, runner=runner,
                start_location=55, end_location=55,
            )
            self.assertEqual(b'{"state":"installed"}\n', metadata.read_bytes())
            retained_before_cleanup = tuple(producer.glob(".startup-factory-beads-previous-*"))
            self.assertEqual(1, len(retained_before_cleanup))
            boundary.execute_supervised_effect_v27(
                state, key, manifest, plan, runner=runner,
                start_location=56, end_location=57,
            )
            self.assertEqual((), tuple(producer.glob(".startup-factory-beads-previous-*")))
            retired = (
                state / "native-effects-v27" / plan["operationId"]
                / "custody" / "retained"
            )
            self.assertEqual(1, len(tuple(retired.glob("previous-*"))))
            self.assertEqual(
                [5, 18, 31, 44], [location for location, _path in calls]
            )

    def test_reader_window_store_mutation_fails_before_terminal_publication(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            state = root / "state"
            state.mkdir(mode=0o700)
            repository = root / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            issues = beads / "issues.jsonl"
            issues.write_bytes(b'{"id":"task-1"}\n')
            manifest, plan = self.ordinary_plan(str(repository))
            mutated = False

            def runner(_manifest, stage_plan):
                nonlocal mutated
                stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                stage_key = stage_plan["stageKey"]
                if stage_key.startswith("reader-"):
                    ordinal = int(stage_key.split("-")[1])
                    stdout = reads[ordinal]
                    if ordinal == 1 and not mutated:
                        # A read container that can mutate the staged store is a
                        # containment failure even if its own JSON is valid.
                        (
                            Path(stage_plan["repositoryPath"])
                            / ".beads" / "issues.jsonl"
                        ).write_bytes(
                            b'{"id":"task-1"}\n{"hostile":"reader-write"}\n'
                        )
                        mutated = True
                return self.successful_native_result(stage_plan, stdout=stdout)

            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "controller snapshot was substituted",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner
                )
            current = boundary.inspect_supervised_effect_v27(
                state, key, plan["operationId"]
            )
            self.assertEqual((35, "intent-current"), (
                current["payload"]["location"], current["payload"]["state"]
            ))
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "controller snapshot was substituted",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner
                )
            retained = boundary.inspect_supervised_effect_v27(
                state, key, plan["operationId"]
            )
            self.assertEqual(
                "StageCurrentV3",
                retained["kind"],
            )
            self.assertNotEqual(
                    "completion", retained["payload"]["state"]
            )

    def test_mutate_then_restore_fails_at_first_rolling_window(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        reads = self.reader_outputs()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            state = root / "state"
            state.mkdir(mode=0o700)
            repository = root / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            issues = beads / "issues.jsonl"
            original = b'{"id":"task-1"}\n'
            issues.write_bytes(original)
            manifest, plan = self.ordinary_plan(str(repository))
            mutated = False
            mutated_path: Path | None = None

            def runner(_manifest, stage_plan):
                nonlocal mutated, mutated_path
                stdout = b'{"data":{"id":"task-1"},"schema_version":1}\n'
                stage_key = stage_plan["stageKey"]
                if stage_key.startswith("reader-"):
                    ordinal = int(stage_key.split("-")[1])
                    stdout = reads[ordinal]
                    if ordinal == 0 and not mutated:
                        mutated_path = (
                            Path(stage_plan["repositoryPath"])
                            / ".beads" / "issues.jsonl"
                        )
                        mutated_path.write_bytes(
                            original + b'{"hostile":"temporary"}\n'
                        )
                        mutated = True
                return self.successful_native_result(stage_plan, stdout=stdout)

            capture = boundary._capture_physical_store_scan_v27

            def capture_then_restore(repository_path, *, capture_ordinal):
                observed = capture(
                    repository_path, capture_ordinal=capture_ordinal
                )
                if (
                    capture_ordinal == "b"
                    and mutated_path is not None
                    and b"temporary" in mutated_path.read_bytes()
                ):
                    mutated_path.write_bytes(original)
                return observed

            with mock.patch.object(
                boundary,
                "_capture_physical_store_scan_v27",
                side_effect=capture_then_restore,
            ), self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "controller snapshot was substituted",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner
                )
            self.assertEqual(original, issues.read_bytes())
            current = boundary.inspect_supervised_effect_v27(
                state, key, plan["operationId"]
            )
            self.assertEqual((21, "intent-current"), (
                current["payload"]["location"], current["payload"]["state"]
            ))
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error,
                "controller snapshot was substituted",
            ):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner
                )

    def test_physical_scan_binds_identity_and_only_normalizes_noms_manifest(self) -> None:
        def scan(repository: Path) -> dict:
            return boundary._capture_physical_store_scan_v27(
                str(repository), capture_ordinal="a"
            )["physicalStoreScan"]

        with tempfile.TemporaryDirectory() as name:
            repository = Path(name).resolve() / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            issue = beads / "issues.jsonl"
            issue.write_bytes(b'{"id":"task-1"}\n')
            before = scan(repository)
            self.assertEqual(
                boundary.sha256(
                    boundary.canonical_bytes(before["repositoryAncestry"])
                ),
                before["repositoryAncestrySha256"],
            )
            self.assertEqual({"entries"}, set(before["rawProjection"]))
            self.assertEqual({"entries"}, set(before["normalizedProjection"]))
            replacement = beads / "replacement"
            replacement.write_bytes(issue.read_bytes())
            replacement.chmod(issue.stat().st_mode & 0o777)
            replacement.replace(issue)
            after = scan(repository)
            self.assertNotEqual(
                before["rawProjectionSha256"], after["rawProjectionSha256"]
            )
            self.assertNotEqual(
                before["normalizedProjectionSha256"],
                after["normalizedProjectionSha256"],
            )

        with tempfile.TemporaryDirectory() as name:
            repository = Path(name).resolve() / "repository"
            nested = repository / ".beads" / "state"
            nested.mkdir(parents=True)
            (nested / "value").write_bytes(b"same\n")
            before = scan(repository)
            old = repository / "state-old"
            nested.rename(old)
            nested.mkdir()
            (nested / "value").write_bytes(b"same\n")
            after = scan(repository)
            self.assertNotEqual(
                before["normalizedProjectionSha256"],
                after["normalizedProjectionSha256"],
            )

        with tempfile.TemporaryDirectory() as name:
            repository = Path(name).resolve() / "repository"
            beads = repository / ".beads"
            beads.mkdir(parents=True)
            (beads / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')
            before = scan(repository)
            (beads / "sibling-store").write_bytes(b"hostile\n")
            after = scan(repository)
            self.assertNotEqual(before["entryCount"], after["entryCount"])
            self.assertNotEqual(
                before["normalizedProjectionSha256"],
                after["normalizedProjectionSha256"],
            )

        with tempfile.TemporaryDirectory() as name:
            repository = Path(name).resolve() / "repository"
            manifest = (
                repository
                / ".beads/embeddeddolt/startup_factory/.dolt/noms/manifest"
            )
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(b"manifest-before\n")
            before = scan(repository)
            replacement = manifest.with_name("manifest-new")
            replacement.write_bytes(b"manifest-before\n")
            replacement.chmod(manifest.stat().st_mode & 0o777)
            replacement.replace(manifest)
            after = scan(repository)
            self.assertNotEqual(
                before["rawProjectionSha256"], after["rawProjectionSha256"]
            )
            self.assertEqual(
                before["normalizedProjectionSha256"],
                after["normalizedProjectionSha256"],
            )
            self.assertEqual(
                [
                    ".beads/embeddeddolt/startup_factory/.dolt/noms/manifest"
                ],
                before["normalizedTransitionPaths"],
            )
            self.assertEqual(
                before["normalizedTransitionPaths"],
                after["normalizedTransitionPaths"],
            )
            changed = manifest.with_name("manifest-changed")
            changed.write_bytes(b"manifest-after-with-new-size\n")
            changed.chmod(manifest.stat().st_mode & 0o777)
            changed.replace(manifest)
            changed_scan = scan(repository)
            self.assertNotEqual(
                after["normalizedProjectionSha256"],
                changed_scan["normalizedProjectionSha256"],
            )

    def test_preparation_commands_resume_one_exact_sequence_current(self) -> None:
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        calls: list[tuple[int, str]] = []

        def runner(_manifest, stage_plan):
            calls.append((stage_plan["stageLocation"], stage_plan["stageKey"]))
            return self.successful_native_result(
                stage_plan, stdout=b'{"data":{},"schema_version":1}\n'
            )

        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            preparation = root / "preparation"
            beads = preparation / ".beads"
            beads.mkdir(parents=True)
            (beads / "metadata.json").write_bytes(b"{}\n")
            manifest, plan = self.create_preparation_plan(str(preparation))
            for ordinal in range(4):
                result = boundary.execute_supervised_effect_v27(
                    root,
                    key,
                    manifest,
                    plan,
                    runner=runner,
                    start_location=ordinal * 13 + 1,
                    end_location=ordinal * 13 + 13,
                )
                self.assertEqual(
                    (ordinal * 13 + 1, ordinal * 13 + 13),
                    (result["stageStart"], result["stageEnd"]),
                )
                current = boundary.inspect_supervised_effect_v27(
                    root, key, plan["operationId"]
                )
                self.assertEqual(ordinal * 13 + 13, current["payload"]["location"])
            terminal = boundary.execute_supervised_effect_v27(
                root,
                key,
                manifest,
                plan,
                runner=runner,
                start_location=53,
                end_location=63,
            )
            self.assertEqual("sequence-completed", terminal["preparationState"])
            self.assertEqual(4, terminal["commandCount"])
            current = boundary.inspect_supervised_effect_v27(
                root, key, plan["operationId"]
            )
            self.assertEqual((63, "completion"), (
                current["payload"]["location"], current["payload"]["state"]
            ))
            with self.assertRaisesRegex(boundary.NativeBoundaryV27Error, "passed|outside|predecessor"):
                boundary.execute_supervised_effect_v27(
                    root,
                    key,
                    manifest,
                    plan,
                    runner=runner,
                    start_location=14,
                    end_location=26,
                )
        self.assertEqual(
            [
                (5, "binary-proof-payload-terminal"),
                (18, "initialize-payload-terminal"),
                (31, "status-write-payload-terminal"),
                (44, "status-read-payload-terminal"),
            ],
            calls,
        )

    def _prepared_payload(self, temporary: Path) -> tuple[bytes, object, Path, Path]:
        binary = temporary / "bd"
        binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        binary.chmod(0o500)
        beads = temporary / ".beads"
        embedded = beads / "embeddeddolt"
        database = embedded / "startup_factory"
        dolt = database / ".dolt"
        dolt.mkdir(parents=True)
        for directory in (beads, embedded, database, dolt):
            directory.chmod(0o700)
        immutable: list[dict[str, object]] = []
        for ordinal, name in enumerate((".local_version", "metadata.json"), 1):
            path = beads / name
            path.write_bytes(b"1.1.2" if ordinal == 1 else b"{}")
            path.chmod(0o600)
            immutable.append(
                {
                    "path": name,
                    "size": path.stat().st_size,
                    "sha256": raw_sha(path.read_bytes()),
                    "stat": stat_value(path),
                }
            )
        inputs = contract.PreparedBeadsStorePayloadInputsV1(
            preparation_mode="create",
            repository_locator_sha256=raw_sha(b"repository"),
            project_root_locator_sha256=raw_sha(b"project"),
            beads_root_locator_sha256=raw_sha(b"beads"),
            beads_root_stat=stat_value(beads),
            embedded_data_root_stat=stat_value(embedded),
            database_name="startup_factory",
            database_root_stat=stat_value(database),
            database_dolt_root_stat=stat_value(dolt),
            executable={
                "pathLocatorSha256": raw_sha(b"binary-path"),
                "sha256": raw_sha(binary.read_bytes()),
                "device": binary.stat().st_dev,
                "inode": binary.stat().st_ino,
                "uid": binary.stat().st_uid,
                "mode": "0500",
                "linkCount": binary.stat().st_nlink,
                "size": binary.stat().st_size,
                "mtimeNs": binary.stat().st_mtime_ns,
                "version": "1.1.2",
                "sourceCommit": "20e493e569c922d1253bdeff068c5e56c94957fb",
            },
            immutable_files=immutable,
            metadata={
                "database": "dolt",
                "backend": "dolt",
                "doltMode": "embedded",
                "doltDatabase": "startup_factory",
                "projectId": "fixture-project",
                "sha256": raw_sha(b"metadata"),
            },
            status_profile_payload_sha256=raw_sha(b"status-payload"),
            status_profile_static_bindings_sha256=raw_sha(b"status-static"),
            status_profile_derivation_policy_sha256=raw_sha(b"status-policy"),
            status_profile_dynamic_bindings_sha256=raw_sha(b"status-dynamic"),
            status_profile_expected_bindings_sha256=raw_sha(b"status-expected"),
            derivation_journal_head_sha256=raw_sha(b"journal"),
            runtime_api_manifest_sha256=raw_sha(b"runtime-api"),
            release_manifest_sha256=raw_sha(b"release"),
            generic_status_config_sha256=raw_sha(b"statuses"),
            pre_store_observation_sha256=raw_sha(b"pre"),
            post_store_observation_sha256=raw_sha(b"post"),
            store_state_sha256=raw_sha(b"state"),
            config_envelope_canonical_sha256=raw_sha(b"config"),
            cleanup_observation_sha256=raw_sha(b"cleanup"),
            preparation_plan_sha256=raw_sha(b"preparation-plan"),
            authority_epoch="0123456789abcdef0123456789abcdef",
            predecessor_prepared_store_payload_sha256=None,
        )
        canonical = contract.build_prepared_beads_store_payload_v1(inputs)
        payload = json.loads(canonical)
        expected = contract.PreparedBeadsStoreExpectedBindingsV1(
            preparation_mode=payload["preparationMode"],
            repository_locator_sha256=payload["repositoryLocatorSha256"],
            project_root_locator_sha256=payload["projectRootLocatorSha256"],
            beads_root_locator_sha256=payload["beadsRootLocatorSha256"],
            database_name=payload["databaseName"],
            metadata_sha256=payload["metadata"]["sha256"],
            status_profile_payload_sha256=payload["statusProfilePayloadSha256"],
            status_profile_static_bindings_sha256=payload["statusProfileStaticBindingsSha256"],
            status_profile_derivation_policy_sha256=payload["statusProfileDerivationPolicySha256"],
            status_profile_dynamic_bindings_sha256=payload["statusProfileDynamicBindingsSha256"],
            status_profile_expected_bindings_sha256=payload["statusProfileExpectedBindingsSha256"],
            derivation_journal_head_sha256=payload["derivationJournalHeadSha256"],
            runtime_api_manifest_sha256=payload["runtimeApiManifestSha256"],
            release_manifest_sha256=payload["releaseManifestSha256"],
            generic_status_config_sha256=payload["genericStatusConfigSha256"],
            pre_store_observation_sha256=payload["preStoreObservationSha256"],
            post_store_observation_sha256=payload["postStoreObservationSha256"],
            store_state_sha256=payload["storeStateSha256"],
            config_envelope_canonical_sha256=payload["configEnvelopeCanonicalSha256"],
            cleanup_observation_sha256=payload["cleanupObservationSha256"],
            preparation_plan_sha256=payload["preparationPlanSha256"],
            authority_epoch=payload["authorityEpoch"],
            predecessor_prepared_store_payload_sha256=payload["predecessorPreparedStorePayloadSha256"],
            read_back_plan_candidate_sha256=payload["readBackPlanCandidateSha256"],
            payload_sha256=domain_sha(canonical),
        )
        return canonical, expected, binary, database

    def test_descriptor_pinned_substitution_is_exact_and_no_alias(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            temporary = Path(name)
            canonical, expected, binary, database = self._prepared_payload(temporary)
            target = temporary / "last-touched"
            target.write_bytes(b"task-1\n")
            target.chmod(0o600)
            binary_fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
            database_fd = os.open(database, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            target_fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                verified = boundary.verify_protected_read_back_candidate_v27(
                    canonical,
                    protected_raw_sha256=raw_sha(canonical),
                    protected_expected_bindings=expected,
                )
                plan = boundary.derive_descriptor_pinned_read_back_plan_v27(
                    verified,
                    binary_fd=binary_fd,
                    database_fd=database_fd,
                    target_id_fd=target_fd,
                )
            finally:
                os.close(binary_fd)
                os.close(database_fd)
                os.close(target_fd)
            self.assertEqual([0, 1, 2, 3], [item["ordinal"] for item in plan.steps])
            self.assertEqual(4, len({item["stagePlanSha256"] for item in plan.steps}))
            for item in plan.steps:
                self.assertEqual("/usr/local/bin/bd", item["argv"][0])
                self.assertIn("/run/startup-factory/store/embeddeddolt/startup_factory", item["argv"])
                self.assertIn("task-1", item["argv"])
                self.assertFalse({"$B", "$E", "$ID"} & set(item["argv"]))

            binary.chmod(0o700)
            binary.write_bytes(b"tampered")
            binary.chmod(0o500)
            binary_fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
            database_fd = os.open(database, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            target_fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary.derive_descriptor_pinned_read_back_plan_v27(
                        verified,
                        binary_fd=binary_fd,
                        database_fd=database_fd,
                        target_id_fd=target_fd,
                    )
            finally:
                os.close(binary_fd)
                os.close(database_fd)
                os.close(target_fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
