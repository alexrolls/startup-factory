#!/usr/bin/env python3
"""Offline contract tests for the internal protected Beads V27 boundary."""

from __future__ import annotations

import importlib
import hashlib
import hmac
import json
import os
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

boundary = importlib.import_module("startup_factory_cli.beads_native_boundary_v27")
controller = importlib.import_module("startup_factory_cli.beads_boundary_controller")
runtime = importlib.import_module("startup_factory_cli.beads_protected_runtime")


def digest(label: str) -> str:
    return "sha256:" + __import__("hashlib").sha256(label.encode()).hexdigest()


def raw_sha(value: bytes) -> str:
    return "sha256:" + __import__("hashlib").sha256(value).hexdigest()


def reader_outputs_v27() -> list[bytes]:
    issue = {
        "comment_count": 2,
        "created_at": "2026-08-24T08:00:00Z",
        "dependency_count": 1,
        "dependent_count": 0,
        "id": "task-1",
        "labels": ["automation", "team-preset:deep-backend"],
        "priority": 2,
        "status": "in_progress",
        "title": "Protected task",
        "updated_at": "2026-08-24T09:30:00Z",
    }
    dependency = {
        "created_at": "2026-08-23T08:00:00Z",
        "dependency_type": "blocks",
        "id": "task-0",
        "priority": 1,
        "status": "closed",
        "title": "Required predecessor",
        "updated_at": "2026-08-24T07:00:00Z",
    }
    values = (
        [issue],
        ["automation", "team-preset:deep-backend"],
        [
            {
                "author": "startup-factory",
                "created_at": "2026-08-24T09:00:00Z",
                "id": "comment-1",
                "issue_id": "task-1",
                "text": "claim receipt",
            },
            {
                "author": "reviewer",
                "created_at": "2026-08-24T09:10:00Z",
                "id": "comment-2",
                "issue_id": "task-1",
                "text": "reviewed",
            },
        ],
        [dependency],
    )
    return [
        boundary.canonical_bytes({"data": value, "schema_version": 1}) + b"\n"
        for value in values
    ]


def stage_stdout_v27(plan: dict) -> bytes:
    stage_key = str(plan.get("stageKey", ""))
    if stage_key.startswith("reader-"):
        ordinal = int(stage_key.split("-", 2)[1])
        return reader_outputs_v27()[ordinal]
    return b'{"data":{"id":"task-1"},"schema_version":1}\n'


def retirement_receipt_v27() -> dict[str, object]:
    return {
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


def successful_native_result_v27(stage_plan: dict, *, stdout: bytes) -> dict:
    """Drive the production causal protocol and return its exact success shape."""
    handler = boundary._NATIVE_OUTER_EVENT_HANDLER_V27.get()
    if not callable(handler):
        raise AssertionError("native event handler is absent")
    for sequence, event in enumerate(boundary._SUCCESS_NATIVE_EVENTS_V27, 1):
        before = boundary._reference_native_event_observation_v27(event, "before")
        after = boundary._reference_native_event_observation_v27(event, "after")
        handler(event, "before", raw_sha(
            f"{stage_plan['stagePlanSha256']}:{sequence}:{event}:before".encode()
        ), before)
        handler(event, "after", raw_sha(
            f"{stage_plan['stagePlanSha256']}:{sequence}:{event}:after".encode()
        ), after)
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
    handler.terminalize_result_handoff(retirement_receipt_v27())
    return result


def initialize_test_store_v27(repository: Path) -> None:
    store = repository / ".beads"
    store.mkdir(parents=True)
    (store / "issues.jsonl").write_bytes(b'{"id":"task-1"}\n')


class NativeBoundaryV27Test(unittest.TestCase):
    def test_popen_exec_failures_are_unresolved_after_child_side_channel(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            nonexec = root / "nonexec-launcher"
            nonexec.write_bytes(b"not executable\n")
            nonexec.chmod(0o600)
            for executable, expected_errno in (
                (root / "missing-launcher", __import__("errno").ENOENT),
                (nonexec, __import__("errno").EACCES),
            ):
                with self.subTest(executable=executable):
                    read_fd, write_fd = os.pipe()
                    try:
                        def child_side_channel() -> None:
                            os.write(write_fd, b"child-ran\n")

                        with self.assertRaises(
                            boundary._NativeLaunchUnresolvedV27
                        ) as raised:
                            boundary._run_bounded_process_v27(
                                [str(executable)],
                                timeout=1,
                                pass_fds=(write_fd,),
                                preexec_fn=child_side_channel,
                                executable=str(executable),
                            )
                        os.close(write_fd)
                        write_fd = -1
                        self.assertEqual(b"child-ran\n", os.read(read_fd, 32))
                        loss = raised.exception.recovered[
                            "nativeSupervisorLoss"
                        ]
                        self.assertEqual(
                            "dead-holder-without-terminal", loss["reason"]
                        )
                        self.assertRegex(
                            loss["evidenceSha256"], r"\Asha256:[0-9a-f]{64}\Z"
                        )
                    except boundary._NativeLaunchUnresolvedV27 as exc:
                        self.fail(
                            f"Popen errno {expected_errno} escaped the unresolved "
                            f"classification: {exc}"
                        )
                    finally:
                        os.close(read_fd)
                        if write_fd >= 0:
                            os.close(write_fd)

    def _run_failure_handshake(
        self,
        result_kind: str,
        predecessor_kind: str,
        *,
        revoke_at_release_before: bool = False,
        placement_mask: int = 0,
        expect_rejection: bool = False,
    ) -> list[bytes]:
        request_key = b"h" * 32
        stage_plan_sha256 = digest("handshake-stage-plan")
        native_result_sha256 = digest("handshake-" + result_kind)
        failure_evidence_sha256 = digest("failure-" + result_kind)
        process_pid = 4242
        packets = [b"SETUPREADY\n"]
        if revoke_at_release_before:
            event_observation = (
                boundary._reference_native_event_observation_v27(
                    "release-consumed-current", "before"
                )
            )
            event_body = {
                "schemaVersion": 27,
                "stagePlanSha256": stage_plan_sha256,
                "sequence": 7,
                "event": "release-consumed-current",
                "phase": "before",
                "eventObservation": event_observation,
                "eventEvidenceSha256": boundary._native_event_evidence_v27(
                    stage_plan_sha256=stage_plan_sha256,
                    sequence=7,
                    event="release-consumed-current",
                    phase="before",
                    observation=event_observation,
                ),
            }
            event_hmac = boundary._native_event_hmac_v27(
                request_key, event_body
            ).removeprefix("hmac-sha256:")
            packets.append(
                (
                    "EVENT 7 before release-consumed-current "
                    f"{boundary.canonical_bytes(event_observation).hex()} "
                    f"{event_body['eventEvidenceSha256'].removeprefix('sha256:')} "
                    f"{event_hmac}\n"
                ).encode("ascii")
            )
        offer = {
            "schemaVersion": 27,
            "protocol": "startup-factory/beads-native-worker/v27",
            "status": "result-offer",
            "stagePlanSha256": stage_plan_sha256,
            "nativeResultSha256": native_result_sha256,
            "resultKind": result_kind,
            "resultPredecessorKind": predecessor_kind,
            "failureEvidenceSha256": failure_evidence_sha256,
            "placementMask": placement_mask,
        }
        offer_hmac = hmac.new(
            request_key,
            boundary._NATIVE_RESULT_OFFER_DOMAIN_V27
            + boundary.canonical_bytes(offer),
            hashlib.sha256,
        ).hexdigest()
        packets.extend(
            [
                (
                    "RESULT-OFFER "
                    f"{native_result_sha256.removeprefix('sha256:')} "
                    f"{result_kind} {predecessor_kind} "
                    f"{failure_evidence_sha256.removeprefix('sha256:')} "
                    f"{placement_mask} "
                    f"{offer_hmac}\n"
                ).encode("ascii"),
                b"CONTROL-DONE 0\n",
            ]
        )

        class Process:
            pid = process_pid

            @staticmethod
            def poll():
                return None

        class Channel:
            def __init__(self) -> None:
                self.sent: list[bytes] = []

            def settimeout(self, _value) -> None:
                return None

            def setsockopt(self, *_values) -> None:
                return None

            def sendmsg(self, values, _rights) -> int:
                value = bytes(values[0])
                self.sent.append(value)
                return len(value)

            def sendall(self, value: bytes) -> None:
                self.sent.append(bytes(value))

            def send(self, value: bytes) -> int:
                self.sent.append(bytes(value))
                return len(value)

            def recvmsg(self, _size, _ancillary_size):
                value = packets.pop(0)
                credentials = struct.pack(
                    "3i", process_pid, os.geteuid(), os.getegid()
                )
                return (
                    value,
                    [(boundary.socket.SOL_SOCKET, 0x7F01, credentials)],
                    0,
                    None,
                )

        channel = Channel()

        def event_mediator(value: dict) -> dict:
            revoke = revoke_at_release_before and (
                value["event"], value["phase"]
            ) == ("release-consumed-current", "before")
            response = {
                "schemaVersion": 27,
                "stagePlanSha256": stage_plan_sha256,
                "sequence": value["sequence"],
                "event": value["event"],
                "phase": value["phase"],
                "authorityRecordSha256": digest(
                    f"authority-{value['sequence']}"
                ),
                "controlAction": "revoke" if revoke else "continue",
                "controlAuthorityRecordSha256": (
                    digest("release-revoke-authority") if revoke else None
                ),
            }
            response["ackHmac"] = boundary._native_event_ack_hmac_v27(
                request_key,
                dict(response),
            )
            return response

        def result_offer_mediator(value: dict) -> dict:
            self.assertEqual(offer, value)
            response = {
                "schemaVersion": 27,
                "protocol": "startup-factory/beads-native-worker/v27",
                "action": "ACK-RESULT-OFFER",
                "stagePlanSha256": stage_plan_sha256,
                "nativeResultSha256": native_result_sha256,
                "authorizationRecordSha256": digest(
                    "result-offer-authorization"
                ),
            }
            response["ackHmac"] = "hmac-sha256:" + hmac.new(
                request_key,
                boundary._NATIVE_RESULT_OFFER_ACK_DOMAIN_V27
                + boundary.canonical_bytes(response),
                hashlib.sha256,
            ).hexdigest()
            return response

        with mock.patch.object(
            boundary.socket, "SO_PASSCRED", 0x7F00, create=True
        ), mock.patch.object(
            boundary.socket, "SCM_CREDENTIALS", 0x7F01, create=True
        ):
            invoke = lambda: boundary._credentialed_supervisor_handshake_v27(
                channel,
                Process(),
                (3, 4),
                lambda _value: {},
                event_mediator,
                result_offer_mediator,
                stage_plan_sha256,
                request_key,
            )
            if expect_rejection:
                with self.assertRaisesRegex(
                    boundary.NativeBoundaryV27Error,
                    "result offer placement mask changed",
                ):
                    invoke()
            else:
                self.assertEqual(0, invoke())
                self.assertFalse(packets)
        return channel.sent

    def test_failure_result_kinds_complete_zero_mask_handshake_without_restart(
        self,
    ) -> None:
        predecessors = {
            "precreate-failed": "supervisor-precreate-failed",
            "create-failed-no-thread": "supervisor-create-failed-no-thread",
            "controlled-abort-failed": "creator-abort-failure-lifetime",
            "revoke-verified-no-effect": (
                "creator-lifetime-closed-revoke-verified-no-effect"
            ),
        }
        for result_kind, predecessor in predecessors.items():
            with self.subTest(result_kind=result_kind):
                sent = self._run_failure_handshake(result_kind, predecessor)
                self.assertEqual(b"RELEASE\n", sent[0])
                self.assertTrue(
                    any(value.startswith(b"RESULT-OFFER-ACK ") for value in sent)
                )

    def test_release_before_cutoff_accepts_exact_authenticated_revoke_ack(
        self,
    ) -> None:
        sent = self._run_failure_handshake(
            "revoke-verified-no-effect",
            "creator-lifetime-closed-revoke-verified-no-effect",
            revoke_at_release_before=True,
        )
        self.assertTrue(
            any(
                value.startswith(
                    b"EVENT-ACK 7 before release-consumed-current "
                )
                and b" revoke " in value
                for value in sent
            )
        )

    def test_nonzero_failure_mask_is_rejected_at_result_offer_before_ack(
        self,
    ) -> None:
        sent = self._run_failure_handshake(
            "precreate-failed",
            "supervisor-precreate-failed",
            placement_mask=1,
            expect_rejection=True,
        )
        self.assertFalse(
            any(value.startswith(b"RESULT-OFFER-ACK ") for value in sent)
        )

    def test_zero_placement_mask_requires_exact_authenticated_failure_kind(self) -> None:
        predecessors = {
            "precreate-failed": "supervisor-precreate-failed",
            "create-failed-no-thread": "supervisor-create-failed-no-thread",
            "controlled-abort-failed": "creator-abort-failure-lifetime",
            "revoke-verified-no-effect": (
                "creator-lifetime-closed-revoke-verified-no-effect"
            ),
        }
        for result_kind, predecessor in predecessors.items():
            with self.subTest(result_kind=result_kind):
                value = {
                    "exitCode": 125,
                    "placementMask": 0,
                    "stdout": b"",
                    "stderr": b"",
                    "lifecycle": list(boundary._EFFECT_LIFECYCLE),
                    "resultKind": result_kind,
                    "resultPredecessorKind": predecessor,
                    "failureEvidenceSha256": digest(result_kind),
                }
                self.assertEqual(
                    0,
                    boundary._decode_native_stage_result_v27(
                        value, require_discriminants=True
                    )["placementMask"],
                )
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary._decode_native_stage_result_v27(
                        {**value, "resultPredecessorKind": "wrong"},
                        require_discriminants=True,
                    )
                for forbidden_mask in sorted(
                    boundary._LIFECYCLE_RECOVERY_MASKS_V27 - {0}
                ):
                    with self.subTest(
                        result_kind=result_kind,
                        forbidden_mask=forbidden_mask,
                    ), self.assertRaises(boundary.NativeBoundaryV27Error):
                        boundary._decode_native_stage_result_v27(
                            {**value, "placementMask": forbidden_mask},
                            require_discriminants=True,
                        )
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary._decode_native_stage_result_v27(
                        {
                            "exitCode": 0,
                            "placementMask": 0,
                            "stdout": b"",
                            "stderr": b"",
                            "lifecycle": list(boundary._EFFECT_LIFECYCLE),
                            "resultKind": "success",
                            "resultPredecessorKind": (
                                "creator-lifetime-closed-positive"
                            ),
                            "failureEvidenceSha256": None,
                        },
                        require_discriminants=True,
                    )

    def test_native_event_observations_reject_semantically_false_action_evidence(self) -> None:
        invalid: tuple[tuple[str, str, dict[str, object]], ...] = (
            ("supervisor-running", "before", {"supervisorPid": 1}),
            ("supervisor-running", "after", {"pidfdTerminal": True}),
            ("supervisor-running", "after", {"fd11IdentityRevalidated": False}),
            ("supervisor-running", "after", {"controlPeek": "readable"}),
            ("run-authorization-consumed", "before", {"releaseSendCount": 1}),
            ("run-authorization-consumed", "before", {"cgroupDescriptorCount": 3}),
            ("run-authorization-consumed", "before", {"sendmsgReturn": 8}),
            ("run-authorization-consumed", "after", {"sendmsgReturn": 7}),
            ("run-acknowledged", "before", {"ackSendCount": 1}),
            ("run-acknowledged", "before", {"sendReturn": 4}),
            ("run-acknowledged", "after", {"pidfdTerminal": True}),
            ("run-acknowledged", "after", {"fd11IdentityRevalidated": False}),
            ("run-acknowledged", "after", {"controlPeek": "eof"}),
            ("supervisor-precreate-failed", "after", {
                "mutexInitRc": 0, "conditionInitRc": 0,
            }),
            ("supervisor-precreate-failed", "after", {"partialCleanupRc": 1}),
            ("supervisor-precreate-failed", "after", {"fd7CloseRc": 1}),
            ("supervisor-precreate-failed", "after", {"fd11CloseRc": 1}),
            ("supervisor-precreate-failed", "after", {"proofFdsClosed": False}),
            ("supervisor-create-failed-no-thread", "after", {"pthreadCreateRc": 0}),
            ("supervisor-create-failed-no-thread", "after", {"creatorHandleCaptured": True}),
            ("supervisor-create-failed-no-thread", "after", {"fd7CloseRc": 1}),
            ("supervisor-create-failed-no-thread", "after", {"fd11CloseRc": 1}),
            ("supervisor-create-failed-no-thread", "after", {"proofFdsClosed": False}),
            ("supervisor-create-failed-no-thread", "after", {"pidfdPreCloseTerminal": True}),
            ("supervisor-create-failed-no-thread", "after", {"fd11PreCloseIdentityRevalidated": False}),
            ("native-creator-created", "after", {"pthreadCreateRc": 1}),
            ("native-creator-created", "after", {"creatorHandleCaptured": False}),
            ("native-creator-created", "after", {"creatorHandshakeComplete": False}),
            ("native-creator-created", "after", {"joinOwnerTokenRetained": False}),
            ("native-creator-created", "after", {"fd7CloseRc": 1}),
            ("native-creator-created", "after", {"fd11CloseRc": 1}),
            ("native-creator-created", "after", {"proofFdsClosed": False}),
            ("native-creator-created", "after", {"pidfdPreCloseTerminal": True}),
            ("native-creator-created", "after", {"fd11PreCloseIdentityRevalidated": False}),
            ("creator-status-uncertain", "after", {"pthreadCreateRc": 1}),
            ("creator-status-uncertain", "after", {"creatorHandleCaptured": False}),
            ("creator-status-uncertain", "after", {"readinessObserved": False}),
            ("abort-wake-consumed", "before", {"abortStoreCount": 1}),
            ("abort-wake-consumed", "after", {"futexWakeCount": 0}),
            ("abort-wake-completed", "after", {"abortStoreReturn": 1}),
            ("abort-wake-completed", "after", {"futexWakeReturn": 2}),
            ("abort-wake-completed", "after", {"conditionBroadcastRc": 1}),
            ("abort-join-consumed", "before", {"pthreadJoinCount": 1}),
            ("abort-join-consumed", "after", {"pthreadJoinCount": 0}),
            ("abort-failure-lifetime", "after", {"pthreadJoinRc": 1}),
            ("abort-failure-lifetime", "after", {"returnSentinel": "wrong"}),
            ("abort-failure-lifetime", "after", {"creatorTaskAbsent": False}),
            ("release-consumed-current", "before", {"releaseStoreCount": 1}),
            ("release-consumed-current", "after", {"futexWakeCount": 1}),
            ("signal-attempt-consumed", "before", {"releaseStoreReturn": 0}),
            ("signal-attempt-consumed", "after", {"releaseStoreReturn": 1}),
            ("signal-attempt-consumed", "after", {"futexWakeReturn": 2}),
            ("signal-attempt-consumed", "after", {"conditionBroadcastRc": 1}),
            ("release-issued", "after", {"releaseAuthorized": False}),
            ("release-issued", "after", {"releaseStoreReturn": 1}),
            ("release-issued", "after", {"futexWakeReturn": 2}),
            ("release-known-live", "after", {"releaseKnownLive": False}),
            ("release-known-live", "after", {"creatorTaskObserved": False}),
            ("release-known-live", "after", {"secondAckBarrierHeld": False}),
            ("release-terminal", "before", {"pthreadJoinRc": 0}),
            ("release-terminal", "after", {"pthreadJoinRc": 1}),
            ("release-terminal", "after", {"returnSentinel": "wrong"}),
            ("release-terminal", "after", {"creatorReturnWaiting": False}),
            ("release-terminal", "after", {"creatorTaskObserved": False}),
            ("release-terminal", "after", {"terminalObservationPhase": "wrong"}),
            ("creator-return-ready", "after", {"pthreadJoinCount": 1}),
            ("creator-return-ready", "after", {"pthreadJoinRc": 0}),
            ("creator-return-ready", "after", {"returnSentinel": "wrong"}),
            ("creator-return-ready", "after", {"creatorHandleConsumed": True}),
            ("creator-return-ready", "after", {"creatorTaskAbsent": False}),
            ("creator-return-ready", "after", {"atomicCaptureSha256": digest("future")}),
            ("creator-return-ready", "after", {"postReturnObservationSha256": digest("future")}),
            ("creator-return-ready", "after", {"departureIntentSha256": None}),
            ("creator-return-ready", "after", {"joinAttemptNonceSha256": None}),
            ("creator-lifetime-closed", "after", {"creatorTaskAbsent": False}),
            ("creator-lifetime-closed", "after", {"proofFd7Closed": False}),
            ("creator-lifetime-closed", "after", {"proofFd11Closed": False}),
            ("creator-lifetime-closed", "after", {"payloadDrained": False}),
            ("creator-lifetime-closed", "after", {"creatorHandleConsumed": False}),
            ("creator-lifetime-closed", "after", {"closureFlagsSha256": None}),
            ("revoke-decision", "before", {"revokeAuthorized": False}),
            ("revoke-decision", "after", {"releaseNotIssued": False}),
            ("revoke-issued", "before", {"abortStoreReturn": 0}),
            ("revoke-issued", "after", {"abortStoreReturn": 1}),
            ("revoke-issued", "after", {"futexWakeReturn": 2}),
            ("revoke-issued", "after", {"conditionBroadcastRc": 1}),
            ("revoke-terminal", "before", {"abortAuthorized": False}),
            ("revoke-terminal", "after", {"creatorTaskObserved": False}),
            ("revoke-terminal", "after", {"creatorHandleConsumed": True}),
        )
        for event, phase, mutation in invalid:
            value = boundary._reference_native_event_observation_v27(event, phase)
            value.update(mutation)
            with self.subTest(event=event, phase=phase, mutation=mutation), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary._validate_native_event_observation_v27(event, phase, value)

        for event in (
            "run-authorization-consumed", "run-acknowledged",
            "abort-wake-consumed", "abort-join-consumed",
            "signal-attempt-consumed", "release-terminal",
            "revoke-issued",
        ):
            before = boundary._reference_native_event_observation_v27(event, "before")
            after = boundary._reference_native_event_observation_v27(event, "after")
            with self.subTest(event=event, wrong_phase="before-as-after"), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary._validate_native_event_observation_v27(event, "after", before)
            with self.subTest(event=event, wrong_phase="after-as-before"), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary._validate_native_event_observation_v27(event, "before", after)

        plan = digest("closed-observation-plan")
        first = boundary._reference_native_event_observation_v27(
            "run-acknowledged", "before"
        )
        second = boundary._reference_native_event_observation_v27(
            "run-acknowledged", "after"
        )
        first_evidence = boundary._native_event_evidence_v27(
            stage_plan_sha256=plan, sequence=1,
            event="run-acknowledged", phase="before", observation=first,
        )
        self.assertNotEqual(digest(plan), first_evidence)
        self.assertNotEqual(
            first_evidence,
            boundary._native_event_evidence_v27(
                stage_plan_sha256=plan, sequence=2,
                event="run-acknowledged", phase="after", observation=second,
            ),
        )

    def test_creator_abi_uses_exact_joinable_identity_and_post_return_contract(self) -> None:
        source = (
            ROOT / "runtime/beads-v27/startup-factory-beads-supervisor-v27.c"
        ).read_text()
        for required in (
            "pthread_attr_setdetachstate",
            "PTHREAD_CREATE_JOINABLE",
            "pthread_attr_setguardsize",
            "pthread_attr_setstacksize",
            "pthread_attr_getdetachstate",
            "pthread_setcancelstate",
            "PTHREAD_CANCEL_DISABLE",
            "pthread_sigmask",
            "SYS_gettid",
            "creator_slot_generation",
            "join_owner_token_sha256",
            "creator_creation_nonce_sha256",
            "creator_return_authorized",
            "creator_return_waiting",
            "creator_handle_consumed",
            "native_allocation_gate",
            "prepare_post_return_capture",
            "capture_post_return_task_set",
            "SYS_getdents64",
            "sf_creator_thread_args_v1",
            "child_creation_nonce_sha256",
            "child_plan_digest",
            "child_supervisor_pid",
            "child_supervisor_start_ticks",
            "parent_identity_verified",
            "NativeCreatorPreCreateFailureV2",
            "pthread_attr_init_rc",
            "pthread_attr_getdetachstate_rc",
            "create_called",
            "slot_allocated",
        ):
            self.assertIn(required, source)
        for forbidden in (
            '\"creatorTaskPresent\":true',
            '\"pidfdTerminal\":true',
            '\"sPOTerminalSha256\"',
            "pthread_t creator=creator_slot",
        ):
            self.assertNotIn(forbidden, source)
        self.assertEqual(1, source.count("pthread_create("))
        self.assertEqual(3, source.count("pthread_join(creator_slot"))
        native_event_body = source[
            source.index("static int native_event("):
            source.index("static void print_runtime_probe")
        ]
        self.assertNotIn("malloc(", native_event_body)
        self.assertNotIn("calloc(", native_event_body)
        prepare = source.index("prepare_post_return_capture(", source.index("execute_plan"))
        departure = source.index(
            'native_event(&plan,"creator-return-ready","after"', prepare
        )
        join = source.index("pthread_join(creator_slot.pthread", departure)
        capture = source.index(
            "persist_post_return_artifacts_while_held_v27(", join
        )
        held_observation = source.index(
            'native_event(&plan,"creator-lifetime-closed","before"', capture
        )
        release_gate = source.index("release_post_return_capture();", capture)
        release_receipt = source.index(
            "persist_allocation_gate_release_receipt_v27", release_gate
        )
        observation = source.index(
            'native_event(&plan,"creator-lifetime-closed","after"',
            release_receipt,
        )
        self.assertLess(prepare, join)
        self.assertLess(prepare, departure)
        self.assertLess(departure, join)
        self.assertLess(join, capture)
        self.assertLess(capture, held_observation)
        self.assertLess(held_observation, release_gate)
        self.assertLess(release_gate, release_receipt)
        self.assertLess(release_gate, observation)

        # The creator must echo its sealed inputs and process identity from the
        # child handshake.  Filling these fields from globals in the parent is
        # not evidence of what the child observed.
        creator_start = source[
            source.index("static int sf_beads_creator_start_v1"):
            source.index("static int request_controller_placement")
        ]
        self.assertIn(
            "pthread_create(&slot->pthread,&attr,"
            "sf_beads_creator_thread_main_v1,&slot->thread_args)",
            creator_start,
        )
        self.assertIn(
            "started_out->child_supervisor_pid=sealed_plan->result->"
            "child_supervisor_pid",
            creator_start,
        )
        self.assertNotIn(
            "memcpy(started_out->handshake_nonce_sha256,"
            "creator_creation_nonce_sha256",
            creator_start,
        )
        self.assertNotIn(
            "memcpy(started_out->plan_digest,plan_commitment",
            creator_start,
        )

        creation = boundary._reference_native_event_observation_v27(
            "native-creator-created", "after"
        )
        self.assertGreater(creation["creatorTid"], 1)
        self.assertRegex(creation["creatorStartTicks"], r"\A[1-9][0-9]*\Z")
        self.assertEqual("joinable", creation["pthreadDetachState"])
        self.assertTrue(creation["creatorHandshakeComplete"])
        self.assertTrue(creation["joinOwnerTokenRetained"])
        for mutation in (
            {"slotGeneration": 0},
            {"creatorTid": 0},
            {"creatorStartTicks": "0"},
            {"pthreadDetachState": "detached"},
            {"creatorHandshakeComplete": False},
            {"joinOwnerTokenRetained": False},
            {"pthreadAttrDestroyRc": 1},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary._validate_native_event_observation_v27(
                    "native-creator-created", "after", {**creation, **mutation}
                )

    def test_creator_attr_create_union_is_closed_and_pre_call_failures_are_typed(self) -> None:
        source = (
            ROOT / "runtime/beads-v27/startup-factory-beads-supervisor-v27.c"
        ).read_text()
        for phase in (
            "attr-init", "attr-setdetach", "attr-getdetach",
            "attr-guard", "attr-stack", "pthread-create",
        ):
            self.assertIn(f'"{phase}"', source)
        self.assertIn("NativeCreatorPreCreateFailureV2", source)
        self.assertIn("STARTUP_FACTORY_V27_TEST_ATTR_FAILURE_PHASE", source)
        return_intent = source.index(
            'native_event(&plan,"creator-return-ready","before"')
        self.assertLess(
            return_intent,
            source.index("result.creator_return_authorized=1", return_intent),
        )

        failure = boundary._reference_native_event_observation_v27(
            "supervisor-create-failed-no-thread", "after"
        )
        self.assertFalse(failure["createCalled"])
        self.assertFalse(failure["slotAllocated"])
        self.assertEqual("attr-stack", failure["failurePhase"])
        self.assertEqual("joinable", failure["pthreadAttrDetachStateReadback"])
        for mutation in (
            {"createCalled": True},
            {"slotAllocated": True},
            {"pthreadAttrGetDetachStateRc": 1},
            {"pthreadAttrDetachStateReadback": "detached"},
            {"failurePhase": "unknown"},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary._validate_native_event_observation_v27(
                    "supervisor-create-failed-no-thread", "after",
                    {**failure, **mutation},
                )

    def test_creator_failure_validator_is_phase_discriminated_and_nullable(self) -> None:
        base = boundary._reference_native_event_observation_v27(
            "supervisor-create-failed-no-thread", "after"
        )
        no_thread_cases = {
            "attr-init": {
                "pthreadAttrInitRc": 22,
                "pthreadAttrSetDetachStateRc": None,
                "pthreadAttrGetDetachStateRc": None,
                "pthreadAttrDetachStateReadback": None,
                "pthreadAttrSetGuardSizeRc": None,
                "pthreadAttrSetStackSizeRc": None,
                "pthreadAttrDestroyRc": None,
            },
            "attr-setdetach": {
                "pthreadAttrInitRc": 0,
                "pthreadAttrSetDetachStateRc": 22,
                "pthreadAttrGetDetachStateRc": None,
                "pthreadAttrDetachStateReadback": None,
                "pthreadAttrSetGuardSizeRc": None,
                "pthreadAttrSetStackSizeRc": None,
                "pthreadAttrDestroyRc": 0,
            },
            "attr-getdetach": {
                "pthreadAttrInitRc": 0,
                "pthreadAttrSetDetachStateRc": 0,
                "pthreadAttrGetDetachStateRc": 22,
                "pthreadAttrDetachStateReadback": None,
                "pthreadAttrSetGuardSizeRc": None,
                "pthreadAttrSetStackSizeRc": None,
                "pthreadAttrDestroyRc": 0,
            },
            "attr-guard": {
                "pthreadAttrInitRc": 0,
                "pthreadAttrSetDetachStateRc": 0,
                "pthreadAttrGetDetachStateRc": 0,
                "pthreadAttrDetachStateReadback": "joinable",
                "pthreadAttrSetGuardSizeRc": 22,
                "pthreadAttrSetStackSizeRc": None,
                "pthreadAttrDestroyRc": 0,
            },
            "attr-stack": {},
            "pthread-create": {
                "pthreadAttrSetStackSizeRc": 0,
                "pthreadCreateRc": 11,
                "createCalled": True,
            },
        }
        for failure_phase, changes in no_thread_cases.items():
            with self.subTest(no_thread=failure_phase):
                value = {**base, "failurePhase": failure_phase, **changes}
                boundary._validate_native_event_observation_v27(
                    "supervisor-create-failed-no-thread", "after", value
                )

        uncertain = boundary._reference_native_event_observation_v27(
            "creator-status-uncertain", "after"
        )
        for status, changes in (
            (
                "attr-destroy",
                {
                    "failurePhase": "attr-destroy",
                    "pthreadAttrDestroyRc": 22,
                    "creatorHandshakeStatus": "valid",
                    "readinessObserved": True,
                },
            ),
            (
                "cancellation-disable-failed",
                {
                    "failurePhase": "creator-handshake",
                    "creatorCancelDisableRc": 22,
                    "creatorSignalMaskRc": None,
                    "creatorTid": None,
                    "creatorStartTicks": None,
                    "creationNonceSha256": None,
                    "creatorPlanSha256": None,
                    "parentIdentityVerified": None,
                    "supervisorPid": None,
                    "supervisorStartTicks": None,
                    "creatorHandshakeStatus": "cancellation-disable-failed",
                    "readinessObserved": False,
                    "pthreadAttrDestroyRc": 0,
                    "creatorCancelDisablePresent": True,
                    "creatorSignalMaskPresent": False,
                    "creatorTidPresent": False,
                    "creatorStartTicksPresent": False,
                    "supervisorPidPresent": False,
                    "supervisorStartTicksPresent": False,
                    "parentIdentityPresent": False,
                    "creationNoncePresent": False,
                    "creatorPlanPresent": False,
                },
            ),
            (
                "signal-mask-failed",
                {
                    "failurePhase": "creator-handshake",
                    "creatorCancelDisableRc": 0,
                    "creatorSignalMaskRc": 22,
                    "creatorTid": None,
                    "creatorStartTicks": None,
                    "creationNonceSha256": None,
                    "creatorPlanSha256": None,
                    "parentIdentityVerified": None,
                    "supervisorPid": None,
                    "supervisorStartTicks": None,
                    "creatorHandshakeStatus": "signal-mask-failed",
                    "readinessObserved": False,
                    "pthreadAttrDestroyRc": 0,
                    "creatorCancelDisablePresent": True,
                    "creatorSignalMaskPresent": True,
                    "creatorTidPresent": False,
                    "creatorStartTicksPresent": False,
                    "supervisorPidPresent": False,
                    "supervisorStartTicksPresent": False,
                    "parentIdentityPresent": False,
                    "creationNoncePresent": False,
                    "creatorPlanPresent": False,
                },
            ),
            (
                "parent-identity-mismatch",
                {
                    "failurePhase": "creator-handshake",
                    "creatorSignalMaskRc": 0,
                    "parentIdentityVerified": False,
                    "creatorHandshakeStatus": "parent-identity-mismatch",
                    "readinessObserved": False,
                    "pthreadAttrDestroyRc": 0,
                    "creationNonceSha256": None,
                    "creatorPlanSha256": None,
                    "creationNoncePresent": False,
                    "creatorPlanPresent": False,
                },
            ),
            (
                "creation-nonce-echo-failed",
                {
                    "failurePhase": "creator-handshake",
                    "creatorSignalMaskRc": 0,
                    "creatorHandshakeStatus": "creation-nonce-echo-failed",
                    "readinessObserved": False,
                    "pthreadAttrDestroyRc": 0,
                    "creatorPlanSha256": None,
                    "creatorPlanPresent": False,
                },
            ),
            (
                "plan-digest-echo-failed",
                {
                    "failurePhase": "creator-handshake",
                    "creatorSignalMaskRc": 0,
                    "creatorHandshakeStatus": "plan-digest-echo-failed",
                    "readinessObserved": False,
                    "pthreadAttrDestroyRc": 0,
                },
            ),
            (
                "handshake-timeout",
                {
                    "failurePhase": "creator-handshake-timeout",
                    "creatorHandshakePresent": False,
                    "creatorHandshakeStatus": "handshake-timeout",
                    "readinessObserved": False,
                    "pthreadAttrDestroyRc": 0,
                    "creatorCancelDisableRc": None,
                    "creatorSignalMaskRc": None,
                    "creatorTid": None,
                    "creatorStartTicks": None,
                    "creationNonceSha256": None,
                    "creatorPlanSha256": None,
                    "parentIdentityVerified": None,
                    "supervisorPid": None,
                    "supervisorStartTicks": None,
                    "handshakeFutexValue": None,
                    "handshakeFutexWakeReturn": None,
                    "handshakeFutexWaitReturn": -1,
                    "handshakeFutexWaitErrno": 110,
                    "creatorCancelDisablePresent": False,
                    "creatorSignalMaskPresent": False,
                    "creatorTidPresent": False,
                    "creatorStartTicksPresent": False,
                    "supervisorPidPresent": False,
                    "supervisorStartTicksPresent": False,
                    "parentIdentityPresent": False,
                    "creationNoncePresent": False,
                    "creatorPlanPresent": False,
                    "handshakeFutexPresent": False,
                },
            ),
        ):
            with self.subTest(uncertain=status):
                boundary._validate_native_event_observation_v27(
                    "creator-status-uncertain", "after",
                    {**uncertain, **changes},
                )

        lifetime = boundary._reference_native_event_observation_v27(
            "abort-failure-lifetime", "after"
        )
        boundary._validate_native_event_observation_v27(
            "abort-failure-lifetime", "after", lifetime
        )
        for status, tid_present, start_present in (
            ("cancellation-disable-failed", False, False),
            ("creator-tid-invalid", False, False),
            ("creator-start-unreadable", True, False),
            ("handshake-timeout", False, False),
        ):
            value = {
                **lifetime,
                "creatorHandshakeStatus": status,
                "failurePhase": (
                    "creator-handshake-timeout"
                    if status == "handshake-timeout"
                    else "creator-handshake"
                ),
                "creatorTidPresent": tid_present,
                "creatorStartTicksPresent": start_present,
                "creatorTid": lifetime["creatorTid"] if tid_present else None,
                "creatorStartTicks": (
                    lifetime["creatorStartTicks"] if start_present else None
                ),
                "creatorTaskAbsent": None,
            }
            with self.subTest(abort_status=status):
                boundary._validate_native_event_observation_v27(
                    "abort-failure-lifetime", "after", value
                )
                for mutation in (
                    {"creatorTaskAbsent": True},
                    {"creatorTaskAbsent": False},
                    {"creatorTidPresent": not tid_present},
                    {"creatorStartTicksPresent": not start_present},
                ):
                    with self.assertRaises(boundary.NativeBoundaryV27Error):
                        boundary._validate_native_event_observation_v27(
                            "abort-failure-lifetime", "after",
                            {**value, **mutation},
                        )

    def test_lifecycle_placement_masks_are_closed_for_success_and_early_failure(self) -> None:
        sequences = {
            (0,): 1,
            (0, 1): 3,
            (0, 1, 2): 7,
            (0, 1, 2, 3): 15,
            (0, 4): 17,
            (0, 1, 4): 19,
            (0, 1, 2, 4): 23,
            (0, 1, 2, 3, 4): 31,
            (0, 4, 5): 49,
            (0, 1, 4, 5): 51,
            (0, 1, 2, 4, 5): 55,
            (0, 1, 2, 3, 4, 5): 63,
        }
        for ordinals, expected_mask in sequences.items():
            with self.subTest(ordinals=ordinals):
                mask = 0
                for ordinal in ordinals:
                    self.assertTrue(
                        boundary._lifecycle_placement_transition_allowed_v27(
                            mask, ordinal
                        )
                    )
                    mask |= 1 << ordinal
                self.assertEqual(expected_mask, mask)
                self.assertIn(mask, boundary._LIFECYCLE_RECOVERY_MASKS_V27)
        self.assertEqual(
            frozenset({1, 3, 7, 15, 31, 49, 51, 55, 63}),
            boundary._LIFECYCLE_TERMINAL_MASKS_V27,
        )
        for mask, ordinal in ((0, 1), (1, 0), (1, 5), (3, 3), (31, 4), (63, 5)):
            with self.subTest(hostile=(mask, ordinal)):
                self.assertFalse(
                    boundary._lifecycle_placement_transition_allowed_v27(
                        mask, ordinal
                    )
                )

    def manifest(self) -> dict:
        return {
            "schemaVersion": 27,
            "profile": "startup-factory/beads-native-boundary/v27",
            "systemdVersion": "254",
            "podmanVersion": "5.4.1",
            "conmonVersion": "2.1.12",
            "ociRuntimeName": "crun",
            "ociRuntimeVersion": "crun version 1.14.4",
            "ociRuntimeVersionOutputSha256": raw_sha(
                b"crun version 1.14.4\ncommit: fixture\n"
            ),
            "ociRuntimeSelectionSource": "fixed-podman-create-argv",
            "selinuxMode": "enforcing",
            "launcherPath": "/usr/local/libexec/startup-factory-beads-launcher-v27",
            "launcherSourceSha256": digest("launcher-source"),
            "launcherSha256": digest("launcher"),
            "supervisorPath": "/usr/local/libexec/startup-factory-beads-supervisor-v27",
            "supervisorSourceSha256": digest("supervisor-source"),
            "supervisorSha256": digest("supervisor"),
            "podmanPath": "/usr/bin/podman",
            "podmanSha256": digest("podman"),
            "conmonPath": "/usr/bin/conmon",
            "conmonSha256": digest("conmon"),
            "ociRuntimePath": "/usr/bin/crun",
            "ociRuntimeSha256": digest("crun"),
            "selinuxPolicySha256": digest("policy"),
            "imageDigest": digest("beads-v27-image"),
            "imageReference": "localhost/startup-factory/beads-v27@"
            + digest("beads-v27-image"),
            "selinuxContexts": {
                "proc-current-preexec": self.context("system_u:system_r:beads_controller_t:s0", "none"),
                "proc-exec-preexec": self.context("", "empty"),
                "file-xattr-supervisor-exec": self.context(
                    "system_u:object_r:beads_supervisor_exec_t:s0\0", "one-trailing-nul"
                ),
                "proc-current-setupready": self.context(
                    "system_u:system_r:startup_factory_beads_controller_t:s0", "none"
                ),
            },
        }

    @staticmethod
    def context(text: str, terminator: str) -> dict:
        raw = text.encode()
        import base64
        import hashlib

        return {
            "rawBytesBase64": base64.b64encode(raw).decode("ascii"),
            "byteLength": len(raw),
            "terminatorKind": terminator,
            "rawBytesSha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        }

    def test_public_surface_remains_frozen_and_v27_is_internal(self) -> None:
        self.assertEqual(92, len(runtime._TYPE_NAMES))
        self.assertEqual(33, len(runtime._FUNCTION_EXPORTS))
        self.assertEqual(30, len(controller.ALLOWED_OPERATIONS))
        self.assertTrue(set(boundary.INTERNAL_SCHEMA_NAMES).isdisjoint(runtime._TYPE_NAMES))
        self.assertTrue(set(boundary.INTERNAL_SCHEMA_NAMES).isdisjoint(runtime.__all__))
        schema = json.loads(boundary.internal_schema_fixture_v27())
        self.assertEqual(27, schema["schemaVersion"])
        self.assertEqual(sorted(boundary.INTERNAL_SCHEMA_NAMES), schema["internalSchemas"])

    def test_exact_profile_and_full_raw_selinux_contexts(self) -> None:
        parsed = boundary.parse_native_boundary_manifest_v27(self.manifest())
        self.assertEqual("5.4.1", parsed.podman_version)
        self.assertEqual("crun", parsed.oci_runtime_name)
        for interface, expectation in parsed.selinux_contexts.items():
            boundary.verify_selinux_raw_context_v27(interface, expectation.raw_bytes, parsed)

        mutations = (
            ("podmanVersion", "5.4.2"),
            ("systemdVersion", "255"),
            ("conmonVersion", "2.1.13"),
            ("ociRuntimeName", "runc"),
            ("ociRuntimeSelectionSource", "containers.conf"),
            ("ociRuntimeVersion", "crun version 1.14.4 attacker"),
            ("selinuxMode", "permissive"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                candidate = {**self.manifest(), field: value}
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary.parse_native_boundary_manifest_v27(candidate)

        candidate = self.manifest()
        candidate["selinuxContexts"] = dict(candidate["selinuxContexts"])
        candidate["selinuxContexts"]["proc-current-preexec"] = self.context(
            "system_u:system_r:beads_controller_t:s0\0", "one-trailing-nul"
        )
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.parse_native_boundary_manifest_v27(candidate)

    def test_socket_fd_key_and_creator_custody_are_closed(self) -> None:
        plan = boundary.validate_launch_plan_v27(boundary.reference_launch_plan_v27())
        self.assertEqual((70, 71, 6), (plan.controller_source_fd, plan.child_source_fd, plan.child_socket_fd))
        self.assertEqual(tuple(range(14)), tuple(sorted(plan.fixed_fd_roles)))
        self.assertEqual("controller-pidfd", plan.fixed_fd_roles[7])
        self.assertEqual("launcher-tid-stat", plan.fixed_fd_roles[11])
        self.assertEqual("supervisor-executable", plan.fixed_fd_roles[13])

        for mutation in (
            {"childSocketFd": 7},
            {"controllerSourceFd": 71},
            {"parentClosesChildSourceBeforeRelease": False},
            {"childCloseRangeStartsAt": 15},
            {"retainedThroughCreate": [7]},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary.validate_launch_plan_v27(
                        {**boundary.reference_launch_plan_v27(), **mutation}
                    )

        key = b"k" * 32
        with tempfile.TemporaryFile() as handle:
            handle.write(key)
            handle.flush()
            handle.seek(0)
            before = handle.tell()
            boundary.verify_sealed_key_material_v27(
                handle.fileno(),
                expected_sha256=boundary.sha256(key),
                seals_verified=True,
            )
            self.assertEqual(before, handle.tell())
        with tempfile.TemporaryFile() as handle:
            handle.write(key + b"x")
            handle.flush()
            with self.assertRaises(boundary.NativeBoundaryV27Error):
                boundary.verify_sealed_key_material_v27(
                    handle.fileno(), expected_sha256=boundary.sha256(key), seals_verified=True
                )

    def test_result_terminal_and_round49_recovery_xors(self) -> None:
        success = boundary.validate_result_envelope_v4(
            {
                "resultKind": "success",
                "predecessorKind": "creator-lifetime-closed-positive",
                "failureEvidenceSha256": None,
            }
        )
        self.assertEqual("success", success["resultKind"])
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_result_envelope_v4(
                {
                    "resultKind": "success",
                    "predecessorKind": "revoke-verified-no-effect",
                    "failureEvidenceSha256": None,
                }
            )
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_result_envelope_v4(
                {
                    "resultKind": "unresolved",
                    "predecessorKind": "creator-lifetime-closed-positive",
                    "failureEvidenceSha256": None,
                }
            )

        terminal = boundary.validate_supervisor_terminal_current_v3(
            {
                "terminalBranch": "result-handoff-terminal",
                "resultEnvelopeSha256": digest("result"),
                "launchPreEffectFailedSha256": None,
            }
        )
        self.assertEqual("result-handoff-terminal", terminal["terminalBranch"])
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_supervisor_terminal_current_v3(
                {
                    "terminalBranch": "result-handoff-terminal",
                    "resultEnvelopeSha256": digest("result"),
                    "launchPreEffectFailedSha256": digest("impossible-second-branch"),
                }
            )

        base = boundary.reference_prior_recovery_attempt_result_v3(
            "acquired-holder-lost", "acquisition-receipt"
        )
        boundary.validate_prior_recovery_attempt_result_v3(base)
        self.assertEqual("not-reached", base["dispositionState"])
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_prior_recovery_attempt_result_v3(
                {**base, "dispositionState": "reached", "dispositionPair": boundary.digest_pair("d")}
            )

        disposed = boundary.reference_prior_recovery_attempt_result_v3(
            "acquired-holder-lost", "disposition-receipt"
        )
        boundary.validate_prior_recovery_attempt_result_v3(disposed)
        self.assertEqual("reached", disposed["dispositionState"])
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_prior_recovery_attempt_result_v3(
                {**disposed, "dispositionState": "not-reached", "dispositionPair": None}
            )

        for prefix in ("release-durable-close-unreceipted", "close-receipt"):
            for state in ("not-reached", "reached"):
                value = boundary.reference_prior_recovery_attempt_result_v3(
                    "acquired-holder-lost", prefix, disposition_state=state
                )
                boundary.validate_prior_recovery_attempt_result_v3(value)
                self.assertEqual(state == "reached", value["dispositionPair"] is not None)

    def test_operation_lock_and_platform_observation_are_exact(self) -> None:
        self.assertEqual(
            {
                "openFlags": ["O_RDWR", "O_CLOEXEC", "O_NOFOLLOW"],
                "lockCommand": "F_OFD_SETLK",
                "l_type": "F_WRLCK",
                "l_whence": "SEEK_SET",
                "l_start": 0,
                "l_len": 0,
                "l_pid": 0,
            },
            boundary.operation_lock_contract_v27(),
        )
        manifest = boundary.parse_native_boundary_manifest_v27(self.manifest())
        observation = {
            "platform": "linux",
            "systemdVersion": "254",
            "podmanVersion": "5.4.1",
            "podmanRootless": True,
            "conmonVersion": "2.1.12",
            "ociRuntimeName": "crun",
            "ociRuntimeVersion": "crun version 1.14.4",
            "ociRuntimeVersionOutputSha256": raw_sha(
                b"crun version 1.14.4\ncommit: fixture\n"
            ),
            "ociRuntimeSelectionSource": "fixed-podman-create-argv",
            "selinuxMode": "enforcing",
            "supervisorSha256": digest("supervisor"),
            "podmanSha256": digest("podman"),
            "conmonSha256": digest("conmon"),
            "ociRuntimeSha256": digest("crun"),
            "selinuxPolicySha256": digest("policy"),
            "podmanSocketMounted": False,
            "sudoAvailableToWorker": False,
            "agentRunsAsRoot": False,
        }
        boundary.validate_platform_observation_v27(observation, manifest)
        for field, bad in (
            ("podmanRootless", False),
            ("selinuxMode", "permissive"),
            ("podmanSocketMounted", True),
            ("sudoAvailableToWorker", True),
            ("agentRunsAsRoot", True),
        ):
            with self.subTest(field=field), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary.validate_platform_observation_v27(
                    {**observation, field: bad}, manifest
                )

    def test_internal_hmac_current_and_recovery_stage_contracts_are_closed(self) -> None:
        self.assertEqual(
            b"startup-factory/beads/prior-recovery-attempt-result/v3\0",
            boundary.HMAC_DOMAINS_V27["PriorRecoveryAttemptResultV3"],
        )
        self.assertEqual(43, len(boundary.CURRENT_UNION_V27))
        self.assertEqual(
            {
                "claim-cas": 76,
                "ordinary": 76,
                "receipt-comment": 77,
                "create-preparation": 63,
                "reattest-preparation": 24,
            },
            boundary.DONE_LOCATIONS_V27,
        )
        self.assertEqual(
            tuple(range(70, 76)), boundary.INCOMPLETE_TAILS_V27["claim-cas"]
        )
        evidence = boundary.reference_recovery_suffix_v27(
            "ordinary", 72, "object-before-current"
        )
        boundary.validate_recovery_suffix_v27(evidence)
        for mutation in (
            {"targetLocation": 69},
            {"targetLocation": 73},
            {"candidateCurrentPair": boundary.digest_pair("future")},
            {"receiptPair": boundary.digest_pair("fabricated")},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary.validate_recovery_suffix_v27({**evidence, **mutation})

        sequence = boundary.OneUseSequenceV27()
        self.assertEqual(1, sequence.consume("one-use-token-0001", "claim-cas", 0))
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            sequence.consume("one-use-token-0001", "claim-cas", 1)
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            sequence.consume("another-one-use-token", "claim-cas", 76)

    def test_seqpacket_creator_and_all_recovery_result_branches_fail_closed(self) -> None:
        packet = {
            "packetLength": 128,
            "msgTrunc": False,
            "msgCtrunc": False,
            "zeroLengthRecord": False,
            "credentialsCount": 1,
            "rightsCount": 0,
            "extraQueuedRecord": False,
            "peerEof": False,
        }
        boundary.validate_seqpacket_observation_v27(packet, expected_length=128)
        for field, value in (
            ("msgTrunc", True),
            ("credentialsCount", 2),
            ("rightsCount", 1),
            ("extraQueuedRecord", True),
            ("peerEof", True),
        ):
            with self.subTest(field=field), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary.validate_seqpacket_observation_v27(
                    {**packet, field: value}, expected_length=128
                )

        gate = boundary.reference_creator_gate_observation_v27()
        boundary.validate_creator_gate_observation_v27(gate)
        for field, value in (
            ("controllerPidfdReadable", True),
            ("launcherTidIdentityMatches", False),
            ("childSocketPeek", "eof"),
            ("pthreadCreateAdjacent", False),
            ("runAuthorizationUseCount", 2),
            ("podmanSocketMounted", True),
            ("agentRunsAsRoot", True),
        ):
            with self.subTest(field=field), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary.validate_creator_gate_observation_v27(
                    {**gate, field: value}
                )

        cases = (
            ("nonacquired-clean-closed", "nonacquired-closed-current"),
            ("acquired-clean-closed", "acquired-closed-before-disposition"),
            ("acquired-clean-closed", "acquired-closed-after-disposition"),
            ("lost-before-call-result", "intent-current-no-call-consume"),
            ("lost-before-call-result", "call-consumed-no-result"),
            ("lost-after-nonacquired-result", "nonacquired-result-close-unreceipted"),
            ("lost-after-nonacquired-result", "nonacquired-close-receipt"),
            (
                "lost-after-acquired-result-before-acquisition",
                "acquired-result-no-acquisition-receipt",
            ),
        )
        for kind, prefix in cases:
            with self.subTest(kind=kind, prefix=prefix):
                value = boundary.reference_prior_recovery_attempt_result_v3(
                    kind, prefix
                )
                boundary.validate_prior_recovery_attempt_result_v3(value)
                forbidden_field = (
                    "releasePair"
                    if kind == "nonacquired-clean-closed"
                    else "holderAbsencePair"
                    if kind == "acquired-clean-closed"
                    else "closedCurrentPair"
                )
                with self.assertRaises(boundary.NativeBoundaryV27Error):
                    boundary.validate_prior_recovery_attempt_result_v3(
                        {**value, forbidden_field: boundary.digest_pair("smuggled")}
                    )

    def test_native_supervisor_probe_binds_full_gate_and_fixed_local_commands(self) -> None:
        manifest = boundary.parse_native_boundary_manifest_v27(self.manifest())
        probe = boundary.reference_native_supervisor_probe_v27(manifest)
        boundary.validate_native_supervisor_probe_v27(probe, manifest)
        tampered = json.loads(json.dumps(probe))
        tampered["agentBoundary"]["task2CanMintAuthority"] = True
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.validate_native_supervisor_probe_v27(tampered, manifest)

        commands = []

        def runner(argv):
            commands.append(tuple(argv))
            if argv == ["/usr/bin/systemd", "--version"]:
                return b"systemd 254 (254.26-1)\n"
            if argv == [str(manifest.podman_path), "--version"]:
                return b"podman version 5.4.1\n"
            if argv == [str(manifest.podman_path), "info", "--format", "json"]:
                return boundary.canonical_bytes(
                    {
                        "host": {
                            "cgroupManager": "systemd",
                            "cgroupVersion": "v2",
                            "idMappings": {
                                "gidmap": [
                                    {"container_id": 0, "host_id": 81003, "size": 1}
                                ],
                                "uidmap": [
                                    {"container_id": 0, "host_id": 81003, "size": 1}
                                ],
                            },
                            "security": {"rootless": True},
                            "ociRuntime": {
                                "name": "crun",
                                "path": "/usr/bin/crun",
                                "version": "crun version 1.14.4\ncommit: fixture",
                            },
                        }
                    }
                ) + b"\n"
            if argv == [
                str(manifest.podman_path),
                "image",
                "inspect",
                "--format",
                "json",
                manifest.image_reference,
            ]:
                return boundary.canonical_bytes(
                    [
                        {
                            "Id": manifest.image_digest,
                            "RepoDigests": [manifest.image_reference],
                        }
                    ]
                ) + b"\n"
            if argv == [str(manifest.conmon_path), "--version"]:
                return b"conmon version 2.1.12\n"
            if argv == [str(manifest.oci_runtime_path), "--version"]:
                return b"crun version 1.14.4\ncommit: fixture\n"
            if argv == [str(manifest.supervisor_path), "--startup-factory-probe-v27"]:
                return boundary.canonical_bytes(probe) + b"\n"
            self.fail(f"unexpected argv: {argv!r}")

        observed = boundary.verify_local_platform_gate_v27(
            manifest,
            runner=runner,
            selinux_enforce_reader=lambda: b"1\n",
            selinux_policy_reader=lambda: b"policy",
            platform_name="linux",
        )
        self.assertEqual(probe, observed)
        self.assertEqual(
            [
                ("/usr/bin/systemd", "--version"),
                (str(manifest.podman_path), "--version"),
                (str(manifest.podman_path), "info", "--format", "json"),
                (
                    str(manifest.podman_path),
                    "image",
                    "inspect",
                    "--format",
                    "json",
                    manifest.image_reference,
                ),
                (str(manifest.conmon_path), "--version"),
                (str(manifest.oci_runtime_path), "--version"),
                (str(manifest.supervisor_path), "--startup-factory-probe-v27"),
            ],
            commands,
        )
        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_local_platform_gate_v27(
                manifest,
                runner=runner,
                selinux_enforce_reader=lambda: b"0\n",
                selinux_policy_reader=lambda: b"policy",
                platform_name="linux",
            )

        def hostile_systemd(argv):
            if argv == ["/usr/bin/systemd", "--version"]:
                return b"systemd 254 attacker-controlled-suffix\n"
            return runner(argv)

        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_local_platform_gate_v27(
                manifest,
                runner=hostile_systemd,
                selinux_enforce_reader=lambda: b"1\n",
                selinux_policy_reader=lambda: b"policy",
                platform_name="linux",
            )

        for hostile in (
            b'{"host":{"cgroupManager":"systemd","cgroupVersion":"v2","idMappings":{"gidmap":[],"uidmap":[]},"security":{"rootless":true}}}\n',
            b'{"host":{"cgroupManager":"systemd","cgroupVersion":"v2","idMappings":{"gidmap":[{"container_id":0,"host_id":81003,"size":1}],"uidmap":[{"container_id":0,"host_id":81003,"size":1}]},"security":{"rootless":true,"rootless":true}}}\n',
        ):
            with self.subTest(hostile_podman_info=hostile), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary.verify_local_platform_gate_v27(
                    manifest,
                    runner=lambda argv, hostile=hostile: (
                        hostile
                        if argv
                        == [str(manifest.podman_path), "info", "--format", "json"]
                        else runner(argv)
                    ),
                    selinux_enforce_reader=lambda: b"1\n",
                    selinux_policy_reader=lambda: b"policy",
                    platform_name="linux",
                )

        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_local_platform_gate_v27(
                manifest,
                runner=lambda argv: (
                    boundary.canonical_bytes(
                        [
                            {
                                "Id": manifest.image_digest,
                                "RepoDigests": [manifest.image_reference],
                            },
                            {
                                "Id": manifest.image_digest,
                                "RepoDigests": [manifest.image_reference],
                            },
                        ]
                    )
                    + b"\n"
                    if argv[:3]
                    == [str(manifest.podman_path), "image", "inspect"]
                    else runner(argv)
                ),
                selinux_enforce_reader=lambda: b"1\n",
                selinux_policy_reader=lambda: b"policy",
                platform_name="linux",
            )

        def hostile_conmon(argv):
            if argv == [str(manifest.conmon_path), "--version"]:
                return b"not-conmon 2.1.12-malicious\n"
            return runner(argv)

        with self.assertRaises(boundary.NativeBoundaryV27Error):
            boundary.verify_local_platform_gate_v27(
                manifest,
                runner=hostile_conmon,
                selinux_enforce_reader=lambda: b"1\n",
                selinux_policy_reader=lambda: b"policy",
                platform_name="linux",
            )

        with self.assertRaisesRegex(
            boundary.NativeBoundaryV27Error,
            "loaded SELinux policy",
        ):
            boundary.verify_local_platform_gate_v27(
                manifest,
                runner=runner,
                selinux_enforce_reader=lambda: b"1\n",
                selinux_policy_reader=lambda: b"substituted-policy",
                platform_name="linux",
            )

        def hostile_runtime_version(argv):
            if argv == [str(manifest.oci_runtime_path), "--version"]:
                return b"crun version 1.14.4\ncommit: substituted\n"
            return runner(argv)

        with self.assertRaisesRegex(
            boundary.NativeBoundaryV27Error, "OCI runtime version"
        ):
            boundary.verify_local_platform_gate_v27(
                manifest,
                runner=hostile_runtime_version,
                selinux_enforce_reader=lambda: b"1\n",
                selinux_policy_reader=lambda: b"policy",
                platform_name="linux",
            )

        def hostile_podman_runtime(argv):
            if argv == [str(manifest.podman_path), "info", "--format", "json"]:
                value = json.loads(runner(argv))
                value["host"]["ociRuntime"]["path"] = "/usr/bin/runc"
                return boundary.canonical_bytes(value) + b"\n"
            return runner(argv)

        with self.assertRaisesRegex(
            boundary.NativeBoundaryV27Error,
            "rootless systemd cgroup-v2 execution",
        ):
            boundary.verify_local_platform_gate_v27(
                manifest,
                runner=hostile_podman_runtime,
                selinux_enforce_reader=lambda: b"1\n",
                selinux_policy_reader=lambda: b"policy",
                platform_name="linux",
            )

    def test_production_effect_is_durable_hmac_cas_and_never_replays_consumed_launch(self) -> None:
        manifest = boundary.parse_native_boundary_manifest_v27(self.manifest())
        plan = boundary.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="a" * 64,
            operation_class="ordinary",
            argv=["/usr/local/bin/bd", "update", "task-1", "--status", "active", "--json"],
            repository_path="/srv/startup-factory/repositories/repository-1",
        )
        calls = []

        class Runner:
            def __init__(self) -> None:
                self.durable_fd10: set[str] = set()

            def __call__(self, _manifest, observed_plan):
                calls.append(observed_plan)
                result = successful_native_result_v27(
                    observed_plan, stdout=stage_stdout_v27(observed_plan)
                )
                self.durable_fd10.add(observed_plan["stagePlanSha256"])
                return result

            def recover(self, _manifest, observed_plan):
                if observed_plan["stagePlanSha256"] not in self.durable_fd10:
                    return None
                return {
                    "exitCode": 0,
                    "placementMask": 63,
                    "stdout": stage_stdout_v27(observed_plan),
                    "stderr": b"",
                    "lifecycle": list(boundary._EFFECT_LIFECYCLE),
                    "resultKind": "success",
                    "resultPredecessorKind": "creator-lifetime-closed-positive",
                    "failureEvidenceSha256": None,
                    "controllerRetirement": retirement_receipt_v27(),
                }

        runner = Runner()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = root / "repository"
            state = root / "state"
            state.mkdir(mode=0o700)
            initialize_test_store_v27(repository)
            plan = boundary.reference_supervised_effect_plan_v27(
                manifest,
                operation_id="a" * 64,
                operation_class="ordinary",
                argv=["/usr/local/bin/bd", "update", "task-1", "--status", "active", "--json"],
                repository_path=str(repository),
            )
            result = boundary.execute_supervised_effect_v27(
                state,
                b"v27-test-stage-hmac-key-material-32-bytes",
                manifest,
                plan,
                runner=runner,
            )
            self.assertEqual(0, result["exitCode"])
            self.assertEqual(5, len(calls))
            current = boundary.inspect_supervised_effect_v27(
                state,
                b"v27-test-stage-hmac-key-material-32-bytes",
                plan["operationId"],
            )
            self.assertEqual(boundary.DONE_LOCATIONS_V27["ordinary"], current["payload"]["location"])
            self.assertEqual("completion", current["payload"]["state"])
            self.assertTrue(current["auth"].startswith("hmac-sha256:"))

            repeated = boundary.execute_supervised_effect_v27(
                state,
                b"v27-test-stage-hmac-key-material-32-bytes",
                manifest,
                plan,
                runner=runner,
            )
            self.assertEqual(result, repeated)
            self.assertEqual(5, len(calls), "a Done current must return without replay")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = root / "repository"
            state = root / "state"
            state.mkdir(mode=0o700)
            initialize_test_store_v27(repository)
            plan = boundary.reference_supervised_effect_plan_v27(
                manifest,
                operation_id="a" * 64,
                operation_class="ordinary",
                argv=["/usr/local/bin/bd", "update", "task-1", "--status", "active", "--json"],
                repository_path=str(repository),
            )
            def runner_without_fd10(_manifest, observed_plan):
                return runner(_manifest, observed_plan)

            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27(
                    "location-5-launch-consumed-current"
                ):
                    boundary.execute_supervised_effect_v27(
                        state,
                        b"v27-test-stage-hmac-key-material-32-bytes",
                        manifest,
                        plan,
                        runner=runner_without_fd10,
                    )
            with self.assertRaisesRegex(
                boundary.NativeBoundaryV27Error, "quarantined"
            ):
                boundary.execute_supervised_effect_v27(
                    state,
                    b"v27-test-stage-hmac-key-material-32-bytes",
                    manifest,
                    plan,
                    runner=runner_without_fd10,
                )
            self.assertEqual(5, len(calls), "a consumed launch is never replayed")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = root / "repository"
            state = root / "state"
            state.mkdir(mode=0o700)
            initialize_test_store_v27(repository)
            plan = boundary.reference_supervised_effect_plan_v27(
                manifest,
                operation_id="a" * 64,
                operation_class="ordinary",
                argv=["/usr/local/bin/bd", "update", "task-1", "--status", "active", "--json"],
                repository_path=str(repository),
            )
            before = len(calls)
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27(
                    "location-5-result-object-written"
                ):
                    boundary.execute_supervised_effect_v27(
                        state,
                        b"v27-test-stage-hmac-key-material-32-bytes",
                        manifest,
                        plan,
                        runner=runner,
                    )
            recovered = boundary.execute_supervised_effect_v27(
                state,
                b"v27-test-stage-hmac-key-material-32-bytes",
                manifest,
                plan,
                runner=runner,
            )
            self.assertEqual(0, recovered["exitCode"])
            self.assertEqual(
                before + 5,
                len(calls),
                "stored mutation result recovers once before four distinct reads",
            )

    def test_native_runner_uses_pinned_supervisor_and_closed_podman_lifecycle(self) -> None:
        manifest = boundary.parse_native_boundary_manifest_v27(self.manifest())
        effect_plan = boundary.reference_supervised_effect_plan_v27(
            manifest,
            operation_id="b" * 64,
            operation_class="ordinary",
            argv=["/usr/local/bin/bd", "update", "task-1", "--json"],
            repository_path="/srv/startup-factory/repositories/repository-2",
        )
        plan = boundary.derive_native_stage_action_plan_v27(
            manifest,
            effect_plan,
            boundary.literal_stage_schedule_v27("ordinary")[4],
        )
        self.assertIsNotNone(plan)
        captured = {}

        def process_runner(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return boundary.subprocess.CompletedProcess(
                argv,
                0,
                boundary.canonical_bytes(
                    {
                        "exitCode": 0,
                        "placementMask": 63,
                        "lifecycle": ["create", "init", "start-attach", "terminal", "cleanup", "rm"],
                        "stderrBase64": "",
                        "stdoutBase64": "e30K",
                        "resultKind": "success",
                        "resultPredecessorKind": "creator-lifetime-closed-positive",
                        "failureEvidenceSha256": None,
                    }
                )
                + b"\n",
                b"",
            )

        result = boundary.run_native_stage_action_v27(
            manifest, plan, process_runner=process_runner
        )
        self.assertEqual(0, result["exitCode"])
        self.assertEqual(
            [str(manifest.supervisor_path), "--startup-factory-execute-v27"],
            captured["argv"],
        )
        self.assertEqual(
            boundary._fixed_worker_environment_v27(),
            captured["kwargs"]["env"],
        )
        self.assertFalse(captured["kwargs"]["shell"])
        self.assertEqual("/", captured["kwargs"]["cwd"])

    def test_shipped_native_assets_bind_reproducible_closed_profile(self) -> None:
        source = (ROOT / "runtime/beads-v27/startup-factory-beads-supervisor-v27.c").read_text()
        launcher_source = (ROOT / "runtime/beads-v27/startup-factory-beads-launcher-v27.c").read_text()
        containerfile = (ROOT / "runtime/beads-v27/Containerfile").read_text()
        policy = (ROOT / "runtime/beads-v27/startup_factory_beads_v27.te").read_text()
        build = (ROOT / "runtime/beads-v27/build.sh").read_text()
        generator_path = ROOT / "runtime/beads-v27/generate-native-manifest-v27.py"
        generator_source = generator_path.read_text()
        file_contexts = (ROOT / "runtime/beads-v27/startup_factory_beads_v27.fc").read_text()
        service = (ROOT / "runtime/startup-factory-beads-controller.service.example").read_text()
        tmpfiles = (ROOT / "runtime/startup-factory-beads-controller.tmpfiles.example").read_text()
        protected_runtime_source = (ROOT / "src/startup_factory_cli/beads_protected_runtime.py").read_text()
        native_source = (ROOT / "src/startup_factory_cli/beads_native_boundary_v27.py").read_text()

        self.assertIn("--startup-factory-execute-v27", source)
        for stage in ("create", "init", "start", "wait", "cleanup", "rm"):
            self.assertIn(f'\"{stage}\"', source)
        self.assertIn("--pull", source)
        self.assertIn("never", source)
        self.assertIn("--network", source)
        self.assertIn("none", source)
        self.assertIn("--cgroups", source)
        self.assertIn("--runtime", source)
        self.assertIn("OCI_RUNTIME", source)
        self.assertIn("verify_selinux_transition", source)
        self.assertIn('open("/proc/self/exe", O_RDONLY | O_CLOEXEC)', source)
        self.assertIn("print_runtime_probe", source)
        self.assertIn("verify_preexec_selinux", launcher_source)
        self.assertIn("security.selinux", launcher_source)
        self.assertNotIn("security.selinux", source)
        self.assertIn("FROM scratch", containerfile)
        self.assertIn("beads_native_supervisor_t", policy)
        for edge in (
            "domtrans_pattern(startup_factory_beads_controller_t, startup_factory_beads_conmon_exec_t, startup_factory_beads_conmon_t)",
            "domtrans_pattern(startup_factory_beads_controller_t, startup_factory_beads_runtime_exec_t, startup_factory_beads_runtime_t)",
            "domtrans_pattern(startup_factory_beads_conmon_t, startup_factory_beads_runtime_exec_t, startup_factory_beads_runtime_t)",
        ):
            self.assertIn(edge, policy)
        for nnp_edge in (
            "allow startup_factory_beads_controller_t startup_factory_beads_conmon_t:process2 nnp_transition;",
            "allow startup_factory_beads_controller_t startup_factory_beads_runtime_t:process2 nnp_transition;",
            "allow startup_factory_beads_conmon_t startup_factory_beads_runtime_t:process2 nnp_transition;",
        ):
            self.assertIn(nnp_edge, policy)
        self.assertIn(
            "allow startup_factory_beads_runtime_t startup_factory_beads_payload_t:process transition;",
            policy,
        )
        self.assertIn("nnp_transition nosuid_transition", policy)
        self.assertIn(
            "allow startup_factory_beads_runtime_t self:process setexec;",
            policy,
        )
        self.assertNotRegex(
            policy,
            r"allow\s+startup_factory_beads_conmon_t\s+"
            r"startup_factory_beads_podman_exec_t:file",
        )
        self.assertIn("beads_runtime_result_t:file", policy)
        self.assertIn("lock open read write", policy)
        self.assertIn("beads_runtime_result_t:dir", policy)
        for domain in (
            "beads_controller_t",
            "startup_factory_beads_controller_t",
            "startup_factory_beads_runtime_t",
        ):
            self.assertIn(f"allow {domain} cgroup_t:filesystem getattr;", policy)
            self.assertRegex(
                policy,
                rf"allow {domain} cgroup_t:file \{{[^}}]*read[^}}]*write[^}}]*\}};",
            )
        self.assertRegex(
            policy,
            r"allow beads_controller_t cgroup_t:dir \{[^}]*create[^}]*write[^}]*\};",
        )
        native_cgroup = policy[
            policy.index("allow startup_factory_beads_controller_t cgroup_t:dir") :
            policy.index("allow startup_factory_beads_controller_t self:process")
        ]
        for required in ("add_name", "create", "remove_name", "rmdir", "write"):
            self.assertIn(required, native_cgroup.split("};", 1)[0])
        runtime_cgroup = policy[
            policy.index("allow startup_factory_beads_runtime_t cgroup_t:dir") :
            policy.index("allow startup_factory_beads_controller_t self:process")
        ]
        for required in ("add_name", "create", "remove_name", "rmdir", "write"):
            self.assertIn(required, runtime_cgroup.split("};", 1)[0])
        for forbidden_domain in (
            "startup_factory_beads_conmon_t",
            "startup_factory_beads_payload_t",
        ):
            self.assertNotRegex(policy, rf"allow {forbidden_domain} cgroup_t:")
        self.assertNotRegex(policy, r"cgroup_t:filesystem\s+mount")
        self.assertNotRegex(policy, r"cgroup_t:(?:dir|file)[^;]*relabel")
        self.assertIn("cgroup.kill", policy)
        self.assertIn("-Werror", build)
        self.assertIn("-pthread", build)
        self.assertIn('script_dir=$(CDPATH= cd -- "$(dirname -- "$0")"', build)
        self.assertIn('"$script_dir/startup-factory-beads-launcher-v27.c"', build)
        self.assertIn('"$script_dir/startup-factory-beads-supervisor-v27.c"', build)
        self.assertIn('"$script_dir/generate-native-manifest-v27.py"', build)
        self.assertIn("runtime self-digest slot", build)
        self.assertIn("launcherSourceSha256", generator_source)
        self.assertIn("launcherSha256", generator_source)
        self.assertIn("ociRuntimeSha256", generator_source)
        self.assertIn("os.replace", generator_source)
        self.assertIn("os.fsync(parent_fd)", generator_source)
        self.assertIn("Delegate=yes", service)
        self.assertIn("DelegateSubgroup=controller", service)
        self.assertIn("ProtectControlGroups=false", service)
        self.assertIn("KillMode=control-group", service)
        self.assertIn(
            "SELinuxContext=system_u:system_r:beads_controller_t:s0", service
        )
        self.assertNotIn("ExecStartPre=", service)
        self.assertNotIn("matchpathcon", service)
        self.assertNotIn("ExecStartPre=/usr/sbin/restorecon", service)
        self.assertNotRegex(
            service, r"(?m)^CapabilityBoundingSet=.*CAP_MAC_ADMIN"
        )
        self.assertIn(
            "d /run/user/993/startup-factory-beads-results 0700 "
            "startup-factory-beads-worker startup-factory-beads-worker -",
            tmpfiles,
        )
        self.assertIn(
            "Z /run/user/993/startup-factory-beads-results 0700",
            tmpfiles,
        )
        self.assertIn(
            "/run/user/993/startup-factory-beads-results(/.*)?",
            file_contexts,
        )
        self.assertNotIn("def _spawn_verified_executable_v1", protected_runtime_source)
        self.assertNotIn("subprocess.run(", protected_runtime_source)
        production_custody = native_source[
            native_source.index("def _production_supervisor_custody_v27") :
            native_source.index("def _encode_native_stage_plan_v27")
        ]
        close_finally = production_custody[production_custody.rindex("finally:") :]
        self.assertIn("worker_cgroup,", close_finally)
        self.assertIn("payload_events,", close_finally)
        self.assertIn("payload_kill,", close_finally)
        self.assertNotIn("payload_procs,", close_finally)
        self.assertIn("placement_mediator", production_custody)

    def test_native_manifest_generator_separates_source_and_binary_identities(self) -> None:
        generator_path = ROOT / "runtime/beads-v27/generate-native-manifest-v27.py"
        spec = importlib.util.spec_from_file_location("beads_manifest_generator_v27", generator_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        template = (ROOT / "runtime/beads-native-boundary-v27.example.json").read_bytes()
        launcher_source = b"launcher-source\n"
        supervisor_source = b"supervisor-source\n"
        launcher_binary = b"\x7fELFlauncher-binary"
        supervisor_binary = b"\x7fELFsupervisor-binary"
        oci_runtime_binary = b"\x7fELFcrun-binary"
        generated = module.build_manifest(
            template,
            launcher_source=launcher_source,
            launcher_binary=launcher_binary,
            supervisor_source=supervisor_source,
            supervisor_binary=supervisor_binary,
            oci_runtime_binary=oci_runtime_binary,
        )
        value = json.loads(generated)
        self.assertEqual(
            boundary.canonical_bytes(value) + b"\n", generated
        )
        self.assertEqual(raw_sha(launcher_source), value["launcherSourceSha256"])
        self.assertEqual(raw_sha(launcher_binary), value["launcherSha256"])
        self.assertEqual(raw_sha(supervisor_source), value["supervisorSourceSha256"])
        self.assertEqual(raw_sha(supervisor_binary), value["supervisorSha256"])
        self.assertEqual(raw_sha(oci_runtime_binary), value["ociRuntimeSha256"])
        self.assertNotEqual(value["launcherSourceSha256"], value["launcherSha256"])
        self.assertNotEqual(value["supervisorSourceSha256"], value["supervisorSha256"])

        example = json.loads(template)
        for field in (
            "launcherSourceSha256", "launcherSha256",
            "supervisorSourceSha256", "supervisorSha256",
            "ociRuntimeSha256",
        ):
            self.assertEqual("sha256:" + "0" * 64, example[field])

    def test_callable_effect_persists_every_literal_schedule_location(self) -> None:
        manifest = boundary.parse_native_boundary_manifest_v27(self.manifest())
        key = b"v27-test-stage-hmac-key-material-32-bytes"

        def runner(_manifest, observed_plan):
            return successful_native_result_v27(
                observed_plan, stdout=stage_stdout_v27(observed_plan)
            )

        for ordinal, (operation_class, done) in enumerate(
            boundary.DONE_LOCATIONS_V27.items(), 1
        ):
            with self.subTest(operation_class=operation_class), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                state = root / "state"
                repository = root / "repository"
                state.mkdir(mode=0o700)
                initialize_test_store_v27(repository)
                commands = [
                    ["/usr/local/bin/bd", "version", "--json"],
                    ["/usr/local/bin/bd", "--db", "/workspace/db", "--json", "--sandbox", "init"],
                    ["/usr/local/bin/bd", "--db", "/workspace/db", "--json", "--sandbox", "config", "set", "status.custom", "open"],
                    ["/usr/local/bin/bd", "--db", "/workspace/db", "--json", "--sandbox", "config", "list"],
                ]
                is_preparation = operation_class in {
                    "create-preparation", "reattest-preparation"
                }
                selected_commands = (
                    commands
                    if operation_class == "create-preparation"
                    else [commands[-1]]
                    if operation_class == "reattest-preparation"
                    else None
                )
                plan = boundary.reference_supervised_effect_plan_v27(
                    manifest,
                    operation_id=f"{ordinal:064x}",
                    operation_class=operation_class,
                    argv=(
                        selected_commands[0]
                        if is_preparation
                        else ["/usr/local/bin/bd", "update", "task-1", "--json"]
                    ),
                    repository_path=str(repository),
                    preparation_commands=selected_commands,
                )
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner
                )
                history = state / "native-effects-v27" / plan["operationId"] / "history"
                locations = {
                    json.loads(path.read_bytes())["payload"]["location"]
                    for path in history.glob("*.json")
                }
                self.assertEqual({0, *range(1, done + 1)}, locations)

    def test_intent_current_is_known_no_effect_repair_but_consumed_launch_quarantines(self) -> None:
        manifest = boundary.parse_native_boundary_manifest_v27(self.manifest())
        key = b"v27-test-stage-hmac-key-material-32-bytes"
        calls = []

        def runner(_manifest, observed):
            calls.append(observed["stagePlanSha256"])
            return successful_native_result_v27(
                observed, stdout=stage_stdout_v27(observed)
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = root / "state"
            repository = root / "repository"
            state.mkdir(mode=0o700)
            initialize_test_store_v27(repository)
            plan = boundary.reference_supervised_effect_plan_v27(
                manifest,
                operation_id="c" * 64,
                operation_class="ordinary",
                argv=["/usr/local/bin/bd", "update", "task-1", "--json"],
                repository_path=str(repository),
            )
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27(
                    "location-73-intent-current"
                ):
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner
                    )
            repaired = boundary.execute_supervised_effect_v27(
                state, key, manifest, plan, runner=runner
            )
            self.assertEqual(0, repaired["exitCode"])
            self.assertEqual(5, len(calls))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = root / "state"
            repository = root / "repository"
            state.mkdir(mode=0o700)
            initialize_test_store_v27(repository)
            plan = boundary.reference_supervised_effect_plan_v27(
                manifest,
                operation_id="d" * 64,
                operation_class="ordinary",
                argv=["/usr/local/bin/bd", "update", "task-1", "--json"],
                repository_path=str(repository),
            )
            with self.assertRaises(SystemExit):
                with boundary.inject_native_effect_fault_v27(
                    "location-5-launch-consumed-current"
                ):
                    boundary.execute_supervised_effect_v27(
                        state, key, manifest, plan, runner=runner
                    )
            with self.assertRaisesRegex(boundary.NativeBoundaryV27Error, "quarantined"):
                boundary.execute_supervised_effect_v27(
                    state, key, manifest, plan, runner=runner
                )
            current = boundary.inspect_supervised_effect_v27(
                state, key, plan["operationId"]
            )
            self.assertEqual("outer-loss-quarantined-current", current["payload"]["state"])
            self.assertEqual(5, len(calls), "a consumed launch is never replayed")

    def test_durable_writes_retry_eintr_and_short_writes_but_fail_closed_on_enospc(self) -> None:
        sink = bytearray()
        outcomes = [InterruptedError(), 2, 1]

        def partial_write(_descriptor, block):
            outcome = outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            sink.extend(bytes(block[:outcome]))
            return outcome

        boundary._write_all_v27(9, b"abc", writer=partial_write)
        self.assertEqual(b"abc", bytes(sink))
        with self.assertRaisesRegex(boundary.NativeBoundaryV27Error, "ENOSPC"):
            boundary._write_all_v27(
                9,
                b"x",
                writer=lambda _fd, _block: (_ for _ in ()).throw(
                    OSError(__import__("errno").ENOSPC, "full")
                ),
            )

    def test_delegated_cgroup_roles_resolve_one_supervisor_not_nested(self) -> None:
        self.assertEqual(
            Path("/sys/fs/cgroup/system.slice/example.service/supervisor"),
            boundary._delegated_supervisor_path_v27(
                "/system.slice/example.service/controller"
            ),
        )
        self.assertEqual(
            Path("/sys/fs/cgroup/system.slice/example.service/supervisor"),
            boundary._delegated_supervisor_path_v27(
                "/system.slice/example.service/supervisor"
            ),
        )
        for hostile in (
            "/system.slice/example.service",
            "/system.slice/example.service/supervisor/supervisor",
            "/system.slice/../escape/controller",
        ):
            with self.subTest(hostile=hostile), self.assertRaises(
                boundary.NativeBoundaryV27Error
            ):
                boundary._delegated_supervisor_path_v27(hostile)

    def test_native_assets_implement_the_runtime_abi_not_a_probe_shortcut(self) -> None:
        source = (ROOT / "runtime/beads-v27/startup-factory-beads-supervisor-v27.c").read_text()
        service = (ROOT / "runtime/startup-factory-beads-controller.service.example").read_text()
        fixture = (ROOT / "tests/beads-native-boundary-linux-opt-in.py").read_text()
        for required in (
            "SCM_CREDENTIALS",
            "SO_PASSCRED",
            "execveat",
            "pthread_create",
            "cgroup.kill",
            "RESULT_FD",
            "EVIDENCE_FD",
            "SUPERVISOR_EXEC_FD",
        ):
            self.assertIn(required, source)
        creator_start = source.index("static int sf_beads_creator_start_v1")
        final_liveness = source.index(
            "verify_controller_liveness(1);", creator_start
        )
        creator_call = source.index("pthread_create(&slot->pthread", final_liveness)
        proof_close = source.index(
            "close_creation_proof_fds(&started_out->pidfd_close_rc",
            creator_call,
        )
        self.assertLess(final_liveness, creator_call)
        self.assertLess(creator_call, proof_close)
        for exact_observation_field in (
            "fd7CloseRc",
            "fd11CloseRc",
            "fd11PreCloseIdentityRevalidated",
            "pidfdPreCloseTerminal",
            "proofFdsClosed",
        ):
            self.assertIn(exact_observation_field, source)
        self.assertNotIn('"readBackBase64":"%s"', source)
        self.assertIn("DelegateSubgroup=controller", service)
        self.assertNotIn("DelegateSubgroup=supervisor", service)
        for worker_path in (
            "/var/lib/startup-factory/beads-worker",
            "/run/user/",
            "/var/lib/startup-factory/beads-handoff",
        ):
            self.assertIn(worker_path, service)
        self.assertIn("systemctl", fixture)
        self.assertIn("startup_factory_cli.beads_protected_runtime", fixture)
        self.assertNotIn("os.chown(path, account.pw_uid", fixture)


if __name__ == "__main__":
    unittest.main(verbosity=2)
