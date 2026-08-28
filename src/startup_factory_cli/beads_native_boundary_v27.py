"""Internal V27 contracts for the protected Beads native boundary.

This module is deliberately not re-exported by ``startup_factory_cli`` or the
public protected-runtime module.  It validates the root-owned Linux execution
profile and the evidence shapes consumed by the controller.  It grants no
authority by itself: production authority still requires the live controller,
native supervisor, enforcing SELinux, systemd and rootless Podman gates.
"""

from __future__ import annotations

import base64
import array
import dataclasses
import errno
import fcntl
import hashlib
import hmac
import json
import os
import pwd
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Final


PROFILE: Final = "startup-factory/beads-native-boundary/v27"
SYSTEMD_VERSION: Final = "254"
PODMAN_VERSION: Final = "5.4.1"
CONMON_VERSION: Final = "2.1.12"
OCI_RUNTIME_NAME: Final = "crun"
OCI_RUNTIME_SELECTION_SOURCE: Final = "fixed-podman-create-argv"
MAX_CANONICAL_BYTES: Final = 1_048_576
_SIGNED_INT64_MIN: Final = -(1 << 63)
_SIGNED_INT64_MAX: Final = (1 << 63) - 1
_LIFECYCLE_ALLOWED_NEXT_V27: Final = MappingProxyType(
    {
        0: frozenset({0}),
        1: frozenset({1, 4}),
        3: frozenset({2, 4}),
        7: frozenset({3, 4}),
        15: frozenset({4}),
        17: frozenset({5}),
        19: frozenset({5}),
        23: frozenset({5}),
        31: frozenset({5}),
    }
)
_LIFECYCLE_TERMINAL_MASKS_V27: Final = frozenset(
    {1, 3, 7, 15, 31, 49, 51, 55, 63}
)
_LIFECYCLE_RECOVERY_MASKS_V27: Final = frozenset(
    {0, *_LIFECYCLE_ALLOWED_NEXT_V27, *_LIFECYCLE_TERMINAL_MASKS_V27}
)
_DELEGATED_CONTROLLERS_V27: Final = ("cpu", "memory", "pids")
_SPLIT_PAYLOAD_NAME_V27 = re.compile(r"\Alibpod-payload-[0-9a-f]{64}\Z")
_RESULT_ARENA_REQUEST_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/result-arena-request\0"
)
_CONTROLLER_RETIREMENT_DOMAINS_V27: Final = MappingProxyType(
    {
        "intent": b"startup-factory/beads/v27/controller-retirement-intent\0",
        "receipt": b"startup-factory/beads/v27/controller-retirement-receipt\0",
    }
)


def _lifecycle_placement_transition_allowed_v27(mask: int, ordinal: int) -> bool:
    return ordinal in _LIFECYCLE_ALLOWED_NEXT_V27.get(mask, frozenset())
_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_CONTEXT_INTERFACES: Final = MappingProxyType(
    {
        "proc-current-preexec": ("none", "beads_controller_t"),
        "proc-exec-preexec": ("empty", None),
        "file-xattr-supervisor-exec": (
            "one-trailing-nul",
            "beads_supervisor_exec_t",
        ),
        "proc-current-setupready": (
            "none",
            "startup_factory_beads_controller_t",
        ),
    }
)

HMAC_DOMAINS_V27: Final = MappingProxyType(
    {
        "StageCurrentV3": b"startup-factory/beads/stage-current/v3\0",
        "StageActionResultV1": b"startup-factory/beads/stage-action-result/v1\0",
        "StageActionReceiptV1": b"startup-factory/beads/stage-action-receipt/v1\0",
        "NativeOuterEventReceiptV1": b"startup-factory/beads/native-outer-event-receipt/v1\0",
        "NativeOuterEventIntentV1": b"startup-factory/beads/native-outer-event-intent/v1\0",
        "NativeCreatorCreationIntentV1": b"startup-factory/beads/native-creator-creation-intent/v1\0",
        "NativeCreatorPreCreateFailureV2": b"startup-factory/beads/native-creator-pre-create-failure/v2\0",
        "NativeCreatorCreationReceiptV1": b"startup-factory/beads/native-creator-creation-receipt/v1\0",
        "NativeCreatorJoinOwnershipReceiptV1": b"startup-factory/beads/native-creator-join-ownership-receipt/v1\0",
        "CreatorAbortWakeDecisionV1": b"startup-factory/beads/creator-abort-wake-decision/v1\0",
        "CreatorAbortWakeAttemptV1": b"startup-factory/beads/creator-abort-wake-attempt/v1\0",
        "CreatorAbortWakeReturnV1": b"startup-factory/beads/creator-abort-wake-return/v1\0",
        "CreatorAbortWakeReceiptV1": b"startup-factory/beads/creator-abort-wake-receipt/v1\0",
        "CreatorAbortJoinAttemptV1": b"startup-factory/beads/creator-abort-join-attempt/v1\0",
        "CreatorAbortJoinReturnV1": b"startup-factory/beads/creator-abort-join-return/v1\0",
        "CreatorAbortJoinReceiptV1": b"startup-factory/beads/creator-abort-join-receipt/v1\0",
        "CreatorReturnAuthorizationV2": b"startup-factory/beads/creator-return-authorization/v2\0",
        "CreatorReturnDepartureIntentV1": b"startup-factory/beads/creator-return-departure-intent/v1\0",
        "CreatorJoinAttemptV2": b"startup-factory/beads/creator-join-attempt/v2\0",
        "NativePostReturnCapturePreparationV1": b"startup-factory/beads/native-post-return-capture-preparation/v1\0",
        "NativePostReturnAtomicCaptureV1": b"startup-factory/beads/native-post-return-atomic-capture/v1\0",
        "CreatorJoinResultV2": b"startup-factory/beads/creator-join-result/v2\0",
        "CreatorPostReturnObservationV2": b"startup-factory/beads/creator-post-return-observation/v2\0",
        "NativeAllocationGateReleaseReceiptV1": b"startup-factory/beads/native-allocation-gate-release-receipt/v1\0",
        "CreatorThreadLifetimeReceiptV4": b"startup-factory/beads/creator-thread-lifetime-receipt/v4\0",
        "AuthenticatedSupervisorLossEvidenceV1": b"startup-factory/beads/authenticated-supervisor-loss-evidence/v1\0",
        "SupervisorLaunchPreEffectProofV1": b"startup-factory/beads/supervisor-launch-pre-effect-proof/v1\0",
        "AdmittedOuterRecoveryClosureV1": b"startup-factory/beads/admitted-outer-recovery-closure/v1\0",
        "SupervisorResultHandoffAuthorizationV1": b"startup-factory/beads/supervisor-result-handoff-authorization/v1\0",
        "SupervisorResultHandoffReceiptV1": b"startup-factory/beads/supervisor-result-handoff-receipt/v1\0",
        "SupervisorTerminalReceiptV1": b"startup-factory/beads/supervisor-terminal-receipt/v1\0",
        "SupervisorResultEnvelopeV4": b"startup-factory/beads/supervisor-result-envelope/v4\0",
        "SupervisorOuterLossQuarantinedCurrentV4": b"startup-factory/beads/supervisor-outer-loss-quarantined-current/v4\0",
        "PriorRecoveryAttemptPrefixV2": b"startup-factory/beads/prior-recovery-attempt-prefix/v2\0",
        "OldRecoveryAttemptInertReceiptV2": b"startup-factory/beads/old-recovery-attempt-inert-receipt/v2\0",
        "PriorRecoveryAttemptResultV3": b"startup-factory/beads/prior-recovery-attempt-result/v3\0",
        "RecoveryOperationLockAttemptV6": b"startup-factory/beads/recovery-operation-lock-attempt/v6\0",
        "NativeCreatorCreationConsumedCurrentV1": b"startup-factory/beads/native-creator-creation-consumed-current/v1\0",
        "ControllerRepositoryStageMaterializationIntentV1": b"startup-factory/beads/controller-repository-stage-materialization-intent/v1\0",
        "ControllerRepositoryStageV1": b"startup-factory/beads/controller-repository-stage/v1\0",
        "ControllerRepositoryAccessIntentV1": b"startup-factory/beads/controller-repository-access-intent/v1\0",
        "ControllerRepositoryPostManifestV1": b"startup-factory/beads/controller-repository-post-manifest/v1\0",
        "ControllerRepositoryReleaseReceiptV1": b"startup-factory/beads/controller-repository-release-receipt/v1\0",
        "ControllerReadSnapshotV1": b"startup-factory/beads/controller-read-snapshot/v1\0",
        "ControllerReadSnapshotMaterializationIntentV1": b"startup-factory/beads/controller-read-snapshot-materialization-intent/v1\0",
        "RepositoryPublicationCandidateV1": b"startup-factory/beads/repository-publication-candidate/v1\0",
        "RepositoryPublicationMaterializationV1": b"startup-factory/beads/repository-publication-materialization/v1\0",
        "RepositoryPublicationReceiptV1": b"startup-factory/beads/repository-publication-receipt/v1\0",
        "ControllerCleanupRetirementReceiptV1": b"startup-factory/beads/controller-cleanup-retirement-receipt/v1\0",
    }
)

CURRENT_UNION_V27: Final = (
    "StageCurrentV3",
    "SupervisorLaunchPreEffectFailedCurrentV1",
    "SupervisorLaunchSlotReservedCurrentV1",
    "SupervisorLaunchSlotConsumedCurrentV1",
    "SupervisorRunningCurrentV1",
    "SupervisorRunAuthorizationConsumedCurrentV1",
    "SupervisorRunAcknowledgedCurrentV1",
    "NativeCreatorCreationConsumedCurrentV1",
    "SupervisorPreCreateFailedCurrentV1",
    "SupervisorCreateFailedNoThreadCurrentV1",
    "NativeCreatorCreatedCurrentV1",
    "SupervisorCreatorCreatedStatusUncertainCurrentV2",
    "CreatorAbortWakeConsumedCurrentV1",
    "CreatorAbortWakeCompletedCurrentV1",
    "CreatorAbortJoinConsumedCurrentV1",
    "CreatorAbortFailureLifetimeCurrentV1",
    "SignalAttemptConsumedCurrentV1",
    "ReleaseIssuedCurrentV1",
    "ReleaseKnownLiveCurrentV1",
    "ReleaseTerminalCurrentV1",
    "RevokeDecisionCurrentV2",
    "RevokeIssuedCurrentV1",
    "RevokeTerminalCurrentV1",
    "TakeoverKillAttemptConsumedCurrentV1",
    "UnresolvedDrainPendingCurrentV1",
    "UnresolvedDrainProvedCurrentV3",
    "UnresolvedTerminalCurrentV3",
    "NormalMissPendingCurrentV4",
    "NormalMissResolvedCurrentV4",
    "BootChangedUnresolvedCurrentV2",
    "LateCutoffContinuationCurrentV2",
    "LateNormalPendingRawCurrentV1",
    "LateCutoffUnresolvedCurrentV3",
    "CreatorReturnReadyCurrentV2",
    "CreatorReturnPermanentlyQuarantinedCurrentV2",
    "CreatorLifetimeClosedCurrentV5",
    "SupervisorResultEnvelopeStoredCurrentV4",
    "SupervisorResultHandoffAttemptConsumedCurrentV4",
    "SupervisorResultHandoffReceiptedCurrentV4",
    "SupervisorTerminalReceiptStoredCurrentV4",
    "SupervisorTerminalCurrentV3",
    "SupervisorOuterLossDrainPendingCurrentV5",
    "SupervisorOuterLossQuarantinedCurrentV4",
)


def _current_hmac_domain_v27(kind: str) -> bytes:
    match = re.fullmatch(r"(.+)V([1-9][0-9]*)", kind)
    if match is None:
        raise AssertionError(f"V27 current kind has no version suffix: {kind}")
    stem = re.sub(r"(?<!^)(?=[A-Z])", "-", match.group(1)).lower()
    return f"startup-factory/beads/{stem}/v{match.group(2)}\0".encode("ascii")


# Each admitted current has its own literal versioned domain.  The explicit
# domains above remain the source of truth for non-current records and the
# round-48 recovery records; generated entries only close the round-45 current
# union and are asserted against their canonical spelling in tests.
HMAC_DOMAINS_V27 = MappingProxyType(
    {
        **dict(HMAC_DOMAINS_V27),
        **{
            kind: _current_hmac_domain_v27(kind)
            for kind in CURRENT_UNION_V27
            if kind not in HMAC_DOMAINS_V27
        },
    }
)

DONE_LOCATIONS_V27: Final = MappingProxyType(
    {
        "claim-cas": 76,
        "ordinary": 76,
        "receipt-comment": 77,
        "create-preparation": 63,
        "reattest-preparation": 24,
    }
)
INCOMPLETE_TAILS_V27: Final = MappingProxyType(
    {
        "claim-cas": tuple(range(70, 76)),
        "ordinary": tuple(range(70, 76)),
        "receipt-comment": tuple(range(70, 77)),
        "create-preparation": tuple(range(53, 63)),
        "reattest-preparation": tuple(range(14, 24)),
    }
)

_READ_BACK_CANDIDATE_DOMAIN_V27: Final = (
    b"startup-factory/beads-read-back-plan-candidate/v1\0"
)
_PREPARED_PAYLOAD_DOMAIN_V27: Final = (
    b"startup-factory/prepared-beads-store-payload/v1\0"
)
_READ_BACK_STAGE_PLAN_DOMAIN_V27: Final = (
    b"startup-factory/beads/read-back-stage-plan/v27\0"
)
_REPOSITORY_CUSTODY_LEAF_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/repository-custody-leaf\0"
)
_REPOSITORY_CUSTODY_BINDING_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/repository-custody-binding\0"
)
_REPOSITORY_CUSTODY_MANIFEST_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/repository-custody-manifest\0"
)
_REPOSITORY_CUSTODY_RELEASE_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/repository-custody-release\0"
)
_NATIVE_EVENT_DOMAIN_V27: Final = b"startup-factory/beads/v27/native-event\0"
_NATIVE_EVENT_ACK_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/native-event-ack\0"
)
_READ_BACK_STEP_SPECS_V27: Final = (
    (
        0,
        "terminal-mutation-process-group",
        (
            "$B", "--db", "$E", "--json", "--readonly", "--sandbox",
            "list", "--id", "$ID", "--all", "--limit", "0",
        ),
        "exact-one-issue-with-counts-v112",
    ),
    (
        1,
        "usable-ordinal-0-and-physical-equality",
        (
            "$B", "--db", "$E", "--json", "--readonly", "--sandbox",
            "label", "list", "$ID",
        ),
        "complete-label-string-array-v112",
    ),
    (
        2,
        "usable-ordinal-1-and-physical-equality",
        (
            "$B", "--db", "$E", "--json", "--readonly", "--sandbox",
            "comments", "$ID",
        ),
        "complete-comment-array-v112",
    ),
    (
        3,
        "usable-ordinal-2-and-physical-equality",
        (
            "$B", "--db", "$E", "--json", "--readonly", "--sandbox",
            "dep", "list", "$ID", "--direction", "down",
        ),
        "complete-one-id-dependency-projection-array-v112",
    ),
)


class NativeBoundaryV27Error(RuntimeError):
    """A closed native-boundary invariant failed."""


class _NativeLaunchPreEffectFailedV27(NativeBoundaryV27Error):
    """A closed setup gate failed before the sole ``Popen`` invocation."""

    def __init__(
        self,
        evidence_sha256: str,
        classification: Mapping[str, Any] | None = None,
        proof: Mapping[str, Any] | None = None,
    ) -> None:
        _digest(evidence_sha256, "launch pre-effect failure evidence")
        super().__init__("V27 native launcher failed before process creation")
        self.evidence_sha256 = evidence_sha256
        self.classification = None if classification is None else dict(classification)
        self.proof = None if proof is None else dict(proof)


class _NativeLaunchUnresolvedV27(NativeBoundaryV27Error):
    """A consumed launch could not prove the pre-effect terminal XOR."""

    def __init__(self, recovered: Mapping[str, Any]) -> None:
        if not _is_native_supervisor_loss_v27(recovered):
            raise NativeBoundaryV27Error(
                "V27 unresolved launch lacks authenticated loss evidence"
            )
        super().__init__("V27 native launch is authentically unresolved")
        self.recovered = dict(recovered)


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedProtectedReadBackCandidateV27:
    canonical_prepared_payload: bytes
    prepared_payload_sha256: str
    protected_raw_sha256: str
    candidate_plan_sha256: str
    payload: Mapping[str, Any]
    candidate: Mapping[str, Any]


@dataclasses.dataclass(frozen=True, slots=True)
class DescriptorPinnedReadBackPlanV27:
    candidate_plan_sha256: str
    prepared_payload_sha256: str
    binary_identity_sha256: str
    database_identity_sha256: str
    target_identity_sha256: str
    steps: tuple[Mapping[str, Any], ...]
    plan_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class LiteralStageV27:
    location: int
    stage_key: str
    stage_kind: str
    action_kind: str


_ORDINAL_STAGE_KINDS_V27: Final = (
    "create",
    "init",
    "prestart",
    "start-admission",
    "payload-terminal",
    "drain-verified",
    "raw-observation-a",
    "raw-observation-b",
    "cleanup",
    "remove",
    "post-proof",
    "ordinal-result-stored",
    "ordinal-done",
)
_TAILS_V27: Final = MappingProxyType(
    {
        "claim-cas": (
            "after-observation-a",
            "after-observation-b",
            "checkpoint-candidate-stored",
            "repository-current-cas",
            "public-result-stored",
            "combined-terminal-receipt-stored",
            "operation-done",
        ),
        "ordinary": (
            "after-observation-a",
            "after-observation-b",
            "checkpoint-candidate-stored",
            "repository-current-cas",
            "public-result-stored",
            "combined-terminal-receipt-stored",
            "operation-done",
        ),
        "receipt-comment": (
            "after-observation-a",
            "after-observation-b",
            "checkpoint-candidate-stored",
            "repository-current-cas",
            "claim-receipt-comment-stored",
            "public-result-stored",
            "combined-terminal-receipt-stored",
            "operation-done",
        ),
        "create-preparation": (
            "installation-intent-stored",
            "stage-identity-reopened",
            "host-install-transition",
            "installed-identity-observed",
            "host-cleanup-retired",
            "after-observation-a",
            "after-observation-b",
            "checkpoint-candidate-stored",
            "repository-current-cas",
            "preparation-receipt-stored",
            "preparation-done",
        ),
        "reattest-preparation": (
            "selector-store-reopened",
            "after-observation-a",
            "after-observation-b",
            "predecessor-checkpoint-reopened",
            "checkpoint-candidate-stored",
            "candidate-current-intent-stored",
            "repository-current-cas",
            "cas-receipt-stored",
            "activation-receipt-stored",
            "fresh-current-verified",
            "preparation-done",
        ),
    }
)


def _stage_action_kind_v27(stage_kind: str) -> str:
    if stage_kind in {"create", "init", "prestart", "start-admission", "cleanup", "remove"}:
        return "native-lifecycle-control"
    if stage_kind in {
        "payload-terminal", "drain-verified", "raw-observation-a",
        "raw-observation-b", "after-observation-a", "after-observation-b",
        "installed-identity-observed", "fresh-current-verified",
    }:
        return "independent-observation"
    if stage_kind == "snapshot":
        return "descriptor-snapshot"
    if stage_kind in {
        "repository-current-cas", "candidate-current-intent-stored",
    }:
        return "protected-current-cas"
    if "receipt" in stage_kind:
        return "protected-receipt-publication"
    if stage_kind in {"host-install-transition", "host-cleanup-retired"}:
        return "descriptor-publication"
    return "durable-evidence-publication"


def _build_literal_stage_schedules_v27() -> Mapping[str, tuple[LiteralStageV27, ...]]:
    schedules: dict[str, tuple[LiteralStageV27, ...]] = {}
    for operation_class in DONE_LOCATIONS_V27:
        rows: list[tuple[str, str]] = []
        if operation_class in {"claim-cas", "ordinary", "receipt-comment"}:
            rows.extend((f"effect-{kind}", kind) for kind in _ORDINAL_STAGE_KINDS_V27)
            for ordinal in range(4):
                rows.append((f"reader-{ordinal}-snapshot", "snapshot"))
                rows.extend(
                    (f"reader-{ordinal}-{kind}", kind)
                    for kind in _ORDINAL_STAGE_KINDS_V27
                )
        elif operation_class == "create-preparation":
            for prefix in ("binary-proof", "initialize", "status-write", "status-read"):
                rows.extend(
                    (f"{prefix}-{kind}", kind) for kind in _ORDINAL_STAGE_KINDS_V27
                )
        else:
            rows.extend(
                (f"status-read-{kind}", kind) for kind in _ORDINAL_STAGE_KINDS_V27
            )
        rows.extend((f"tail-{kind}", kind) for kind in _TAILS_V27[operation_class])
        expected = DONE_LOCATIONS_V27[operation_class]
        if len(rows) != expected:
            raise AssertionError(
                f"literal V27 schedule {operation_class} has {len(rows)} != {expected} rows"
            )
        schedules[operation_class] = tuple(
            LiteralStageV27(
                location=index,
                stage_key=key,
                stage_kind=kind,
                action_kind=_stage_action_kind_v27(kind),
            )
            for index, (key, kind) in enumerate(rows, 1)
        )
    return MappingProxyType(schedules)


_LITERAL_STAGE_SCHEDULES_V27: Final = _build_literal_stage_schedules_v27()


def literal_stage_schedule_v27(operation_class: str) -> tuple[LiteralStageV27, ...]:
    try:
        return _LITERAL_STAGE_SCHEDULES_V27[operation_class]
    except (KeyError, TypeError) as exc:
        raise NativeBoundaryV27Error("unknown V27 literal stage schedule") from exc


def canonical_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NativeBoundaryV27Error(
            f"native-boundary value is not canonical JSON: {exc}"
        ) from exc
    if not encoded or len(encoded) > MAX_CANONICAL_BYTES:
        raise NativeBoundaryV27Error(
            "native-boundary canonical bytes are empty or oversized"
        )
    return encoded


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _native_event_hmac_v27(key: bytes, value: Mapping[str, Any]) -> str:
    if type(key) is not bytes or len(key) != 32:
        raise NativeBoundaryV27Error("native event key identity changed")
    return "hmac-sha256:" + hmac.new(
        key, _NATIVE_EVENT_DOMAIN_V27 + canonical_bytes(dict(value)), hashlib.sha256
    ).hexdigest()


def _native_event_ack_hmac_v27(key: bytes, value: Mapping[str, Any]) -> str:
    if type(key) is not bytes or len(key) != 32:
        raise NativeBoundaryV27Error("native event ACK key identity changed")
    return "hmac-sha256:" + hmac.new(
        key,
        _NATIVE_EVENT_ACK_DOMAIN_V27 + canonical_bytes(dict(value)),
        hashlib.sha256,
    ).hexdigest()


def _expected_read_back_candidate_v27() -> dict[str, Any]:
    body: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "beads-read-back-plan-candidate-v1",
        "baselineVersion": "1.1.2",
        "sourceCommit": "20e493e569c922d1253bdeff068c5e56c94957fb",
        "envelope": {
            "outerKeys": ["data", "schema_version"],
            "schemaVersion": 1,
            "noExtras": True,
            "noDuplicates": True,
            "noTrailingValue": True,
        },
        "environmentProfile": "beads-protected-readback-env-v1",
        "aggregateDeadlineSeconds": 120,
        "maxSpawnCount": 4,
        "stdoutLimitBytesPerChild": MAX_CANONICAL_BYTES,
        "stderrLimitBytesPerChild": MAX_CANONICAL_BYTES,
        "maxArgvBytes": 65_536,
        "maxRecordBytes": 262_144,
        "maxStringBytes": 65_536,
        "steps": [
            {
                "ordinal": ordinal,
                "requires": requirement,
                "argvShape": list(argv),
                "dataShape": shape,
            }
            for ordinal, requirement, argv, shape in _READ_BACK_STEP_SPECS_V27
        ],
    }
    plan_digest = sha256(
        _READ_BACK_CANDIDATE_DOMAIN_V27 + canonical_bytes(body)
    )
    return {**body, "planSha256": plan_digest}


def verify_protected_read_back_candidate_v27(
    canonical_prepared_payload: bytes,
    *,
    protected_raw_sha256: str,
    protected_expected_bindings: Any,
) -> VerifiedProtectedReadBackCandidateV27:
    """Recompute task-2's inert candidate under task-3 protected bindings."""

    if (
        type(canonical_prepared_payload) is not bytes
        or not canonical_prepared_payload
        or len(canonical_prepared_payload) > 32_768
        or protected_raw_sha256 != sha256(canonical_prepared_payload)
    ):
        raise NativeBoundaryV27Error(
            "protected prepared payload raw-byte binding changed"
        )
    try:
        from bin import beads_contract

        verified = beads_contract.validate_prepared_beads_store_payload_v1(
            canonical_prepared_payload,
            protected_expected_bindings,
        )
    except (ImportError, ValueError) as exc:
        raise NativeBoundaryV27Error(
            f"protected prepared payload verification failed: {exc}"
        ) from exc
    prepared_digest = sha256(
        _PREPARED_PAYLOAD_DOMAIN_V27 + canonical_prepared_payload
    )
    if (
        verified.canonical_bytes != canonical_prepared_payload
        or verified.payload_sha256 != prepared_digest
    ):
        raise NativeBoundaryV27Error(
            "protected prepared payload domain binding changed"
        )
    try:
        payload = json.loads(canonical_prepared_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeBoundaryV27Error(
            "protected prepared payload is malformed"
        ) from exc
    if not isinstance(payload, dict):
        raise NativeBoundaryV27Error("protected prepared payload is not an object")
    candidate = payload.get("readBackPlanCandidate")
    carrier_digest = payload.get("readBackPlanCandidateSha256")
    expected = _expected_read_back_candidate_v27()
    if (
        not isinstance(candidate, dict)
        or canonical_bytes(candidate) != canonical_bytes(expected)
        or carrier_digest != expected["planSha256"]
        or candidate.get("planSha256") != expected["planSha256"]
    ):
        raise NativeBoundaryV27Error(
            "task-3 independent read-back candidate recomputation failed"
        )
    return VerifiedProtectedReadBackCandidateV27(
        canonical_prepared_payload=canonical_prepared_payload,
        prepared_payload_sha256=prepared_digest,
        protected_raw_sha256=protected_raw_sha256,
        candidate_plan_sha256=str(expected["planSha256"]),
        payload=MappingProxyType(dict(payload)),
        candidate=MappingProxyType(dict(candidate)),
    )


def _pread_exact_bounded_v27(descriptor: int, size: int, label: str) -> bytes:
    if type(descriptor) is not int or descriptor < 0 or not 0 <= size <= MAX_CANONICAL_BYTES:
        raise NativeBoundaryV27Error(f"{label} descriptor/size is invalid")
    blocks = bytearray()
    offset = 0
    while offset < size:
        try:
            block = os.pread(descriptor, min(65_536, size - offset), offset)
        except InterruptedError:
            continue
        except OSError as exc:
            raise NativeBoundaryV27Error(f"cannot read pinned {label}: {exc}") from exc
        if not block:
            raise NativeBoundaryV27Error(f"pinned {label} was truncated")
        blocks.extend(block)
        offset += len(block)
    try:
        extra = os.pread(descriptor, 1, size)
    except OSError as exc:
        raise NativeBoundaryV27Error(f"cannot prove pinned {label} EOF: {exc}") from exc
    if extra:
        raise NativeBoundaryV27Error(f"pinned {label} grew during verification")
    return bytes(blocks)


def _descriptor_stat_projection_v27(metadata: os.stat_result) -> dict[str, Any]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "linkCount": metadata.st_nlink,
        "size": metadata.st_size,
    }


def derive_descriptor_pinned_read_back_plan_v27(
    verified: VerifiedProtectedReadBackCandidateV27,
    *,
    binary_fd: int,
    database_fd: int,
    target_id_fd: int,
) -> DescriptorPinnedReadBackPlanV27:
    """Substitute only B/E/ID after reopening their exact protected objects."""

    if type(verified) is not VerifiedProtectedReadBackCandidateV27:
        raise NativeBoundaryV27Error("read-back derivation requires verified task-3 input")
    try:
        binary_stat = os.fstat(binary_fd)
        database_stat = os.fstat(database_fd)
        target_stat = os.fstat(target_id_fd)
    except OSError as exc:
        raise NativeBoundaryV27Error(
            f"cannot inspect descriptor-pinned read-back input: {exc}"
        ) from exc
    executable = verified.payload.get("executable")
    expected_database = verified.payload.get("databaseRootStat")
    if (
        not isinstance(executable, Mapping)
        or not stat.S_ISREG(binary_stat.st_mode)
        or binary_stat.st_nlink != 1
        or binary_stat.st_uid != os.geteuid()
        or stat.S_IMODE(binary_stat.st_mode) != 0o500
        or _descriptor_stat_projection_v27(binary_stat)
        != {
            key: executable[key]
            for key in ("device", "inode", "uid", "mode", "linkCount", "size")
        }
    ):
        raise NativeBoundaryV27Error("descriptor-pinned bd identity changed")
    binary_bytes = _pread_exact_bounded_v27(binary_fd, binary_stat.st_size, "bd executable")
    if sha256(binary_bytes) != executable.get("sha256"):
        raise NativeBoundaryV27Error("descriptor-pinned bd digest changed")
    if (
        not isinstance(expected_database, Mapping)
        or not stat.S_ISDIR(database_stat.st_mode)
        or database_stat.st_uid != os.geteuid()
        or stat.S_IMODE(database_stat.st_mode) != 0o700
        or _descriptor_stat_projection_v27(database_stat) != dict(expected_database)
    ):
        raise NativeBoundaryV27Error("descriptor-pinned database identity changed")
    if (
        not stat.S_ISREG(target_stat.st_mode)
        or target_stat.st_nlink != 1
        or target_stat.st_uid != os.geteuid()
        or stat.S_IMODE(target_stat.st_mode) != 0o600
        or not 2 <= target_stat.st_size <= 129
    ):
        raise NativeBoundaryV27Error("descriptor-pinned target identity is unsafe")
    target_raw = _pread_exact_bounded_v27(target_id_fd, target_stat.st_size, "target id")
    if target_raw.count(b"\n") != 1 or not target_raw.endswith(b"\n"):
        raise NativeBoundaryV27Error("descriptor-pinned target id is not one LF record")
    try:
        target_id = target_raw[:-1].decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise NativeBoundaryV27Error("descriptor-pinned target id is not UTF-8") from exc
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", target_id):
        raise NativeBoundaryV27Error("descriptor-pinned target id grammar is invalid")
    database_name = verified.payload.get("databaseName")
    if not isinstance(database_name, str) or not re.fullmatch(
        r"[a-z][a-z0-9_]{0,31}", database_name
    ):
        raise NativeBoundaryV27Error("prepared database name is invalid")
    substitutions = {
        "$B": "/usr/local/bin/bd",
        "$E": f"/run/startup-factory/store/embeddeddolt/{database_name}",
        "$ID": target_id,
    }
    steps: list[Mapping[str, Any]] = []
    for ordinal, requirement, shape, data_shape in _READ_BACK_STEP_SPECS_V27:
        argv = [substitutions.get(item, item) for item in shape]
        if any(item in substitutions for item in argv):
            raise NativeBoundaryV27Error("read-back placeholder substitution was incomplete")
        stage = {
            "schemaVersion": 27,
            "ordinal": ordinal,
            "requires": requirement,
            "argv": argv,
            "dataShape": data_shape,
            "candidatePlanSha256": verified.candidate_plan_sha256,
            "preparedPayloadSha256": verified.prepared_payload_sha256,
            "binaryIdentitySha256": sha256(
                canonical_bytes(_descriptor_stat_projection_v27(binary_stat))
            ),
            "databaseIdentitySha256": sha256(
                canonical_bytes(_descriptor_stat_projection_v27(database_stat))
            ),
            "targetIdentitySha256": sha256(
                canonical_bytes(
                    {
                        **_descriptor_stat_projection_v27(target_stat),
                        "valueSha256": sha256(target_raw),
                    }
                )
            ),
        }
        stage["stagePlanSha256"] = sha256(
            _READ_BACK_STAGE_PLAN_DOMAIN_V27 + canonical_bytes(stage)
        )
        steps.append(MappingProxyType(stage))
    summary = {
        "candidatePlanSha256": verified.candidate_plan_sha256,
        "preparedPayloadSha256": verified.prepared_payload_sha256,
        "steps": [dict(item) for item in steps],
    }
    return DescriptorPinnedReadBackPlanV27(
        candidate_plan_sha256=verified.candidate_plan_sha256,
        prepared_payload_sha256=verified.prepared_payload_sha256,
        binary_identity_sha256=str(steps[0]["binaryIdentitySha256"]),
        database_identity_sha256=str(steps[0]["databaseIdentitySha256"]),
        target_identity_sha256=str(steps[0]["targetIdentitySha256"]),
        steps=tuple(steps),
        plan_sha256=sha256(
            _READ_BACK_STAGE_PLAN_DOMAIN_V27 + canonical_bytes(summary)
        ),
    )


_DESCRIPTOR_READ_BACK_PLAN_FIELDS_V27: Final = {
    "candidatePlanSha256",
    "preparedPayloadSha256",
    "binaryIdentitySha256",
    "databaseIdentitySha256",
    "targetIdentitySha256",
    "steps",
    "planSha256",
}


def descriptor_pinned_read_back_plan_payload_v27(
    value: DescriptorPinnedReadBackPlanV27,
) -> dict[str, Any]:
    if type(value) is not DescriptorPinnedReadBackPlanV27:
        raise NativeBoundaryV27Error("descriptor read-back plan type changed")
    return {
        "candidatePlanSha256": value.candidate_plan_sha256,
        "preparedPayloadSha256": value.prepared_payload_sha256,
        "binaryIdentitySha256": value.binary_identity_sha256,
        "databaseIdentitySha256": value.database_identity_sha256,
        "targetIdentitySha256": value.target_identity_sha256,
        "steps": [dict(item) for item in value.steps],
        "planSha256": value.plan_sha256,
    }


def validate_descriptor_pinned_read_back_plan_v27(value: Any) -> dict[str, Any]:
    data = _closed(
        value, _DESCRIPTOR_READ_BACK_PLAN_FIELDS_V27, "descriptor read-back plan"
    )
    for field in _DESCRIPTOR_READ_BACK_PLAN_FIELDS_V27 - {"steps"}:
        _digest(data[field], f"descriptor read-back {field}")
    steps = data["steps"]
    if not isinstance(steps, list) or len(steps) != 4:
        raise NativeBoundaryV27Error("descriptor read-back plan must have four steps")
    normalized: list[dict[str, Any]] = []
    for ordinal, step in enumerate(steps):
        expected_fields = {
            "schemaVersion", "ordinal", "requires", "argv", "dataShape",
            "candidatePlanSha256", "preparedPayloadSha256",
            "binaryIdentitySha256", "databaseIdentitySha256",
            "targetIdentitySha256", "stagePlanSha256",
        }
        item = _closed(step, expected_fields, "descriptor read-back step")
        if (
            item["schemaVersion"] != 27
            or item["ordinal"] != ordinal
            or item["candidatePlanSha256"] != data["candidatePlanSha256"]
            or item["preparedPayloadSha256"] != data["preparedPayloadSha256"]
            or item["binaryIdentitySha256"] != data["binaryIdentitySha256"]
            or item["databaseIdentitySha256"] != data["databaseIdentitySha256"]
            or item["targetIdentitySha256"] != data["targetIdentitySha256"]
        ):
            raise NativeBoundaryV27Error("descriptor read-back step binding changed")
        expected_ordinal, requirement, _shape, data_shape = _READ_BACK_STEP_SPECS_V27[
            ordinal
        ]
        if (
            item["ordinal"] != expected_ordinal
            or item["requires"] != requirement
            or item["dataShape"] != data_shape
            or not isinstance(item["argv"], list)
            or not item["argv"]
            or item["argv"][0] != "/usr/local/bin/bd"
            or any(
                not isinstance(argument, str)
                or not argument
                or argument in {"$B", "$E", "$ID"}
                for argument in item["argv"]
            )
        ):
            raise NativeBoundaryV27Error("descriptor read-back step policy changed")
        candidate = dict(item)
        stage_digest = candidate.pop("stagePlanSha256")
        if stage_digest != sha256(
            _READ_BACK_STAGE_PLAN_DOMAIN_V27 + canonical_bytes(candidate)
        ):
            raise NativeBoundaryV27Error("descriptor read-back stage digest changed")
        normalized.append({**item, "argv": list(item["argv"])})
    summary = {
        "candidatePlanSha256": data["candidatePlanSha256"],
        "preparedPayloadSha256": data["preparedPayloadSha256"],
        "steps": normalized,
    }
    if data["planSha256"] != sha256(
        _READ_BACK_STAGE_PLAN_DOMAIN_V27 + canonical_bytes(summary)
    ):
        raise NativeBoundaryV27Error("descriptor read-back plan digest changed")
    return {**data, "steps": normalized}


_MAX_STAGED_TREE_FILES_V27: Final = 8192
_MAX_STAGED_TREE_BYTES_V27: Final = 268_435_456


def _capture_beads_tree_fd_v27(
    descriptor: int,
    *,
    relative: str = "",
    expected_uid: int,
    include_bytes: bool,
    require_private_modes: bool,
) -> tuple[list[dict[str, Any]], int]:
    entries: list[dict[str, Any]] = []
    total = 0
    try:
        names = sorted(os.listdir(descriptor), key=lambda value: os.fsencode(value))
    except OSError as exc:
        raise NativeBoundaryV27Error(f"cannot enumerate staged Beads tree: {exc}") from exc
    for name in names:
        if (
            not isinstance(name, str)
            or name in {"", ".", ".."}
            or "/" in name
            or "\0" in name
        ):
            raise NativeBoundaryV27Error("staged Beads tree has an unsafe leaf")
        child_relative = name if not relative else f"{relative}/{name}"
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as exc:
            raise NativeBoundaryV27Error(
                f"cannot inspect staged Beads entry {child_relative}: {exc}"
            ) from exc
        if metadata.st_uid != expected_uid:
            raise NativeBoundaryV27Error(
                f"staged Beads entry {child_relative} owner/link identity changed"
            )
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_nlink < 1 or (
                mode & (0o077 if require_private_modes else 0o022)
            ):
                raise NativeBoundaryV27Error(
                    f"staged Beads directory {child_relative} has unsafe permissions"
                )
            child = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                reopened = os.fstat(child)
                if (reopened.st_dev, reopened.st_ino) != (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    raise NativeBoundaryV27Error(
                        f"staged Beads directory {child_relative} changed during open"
                    )
                children, child_total = _capture_beads_tree_fd_v27(
                    child,
                    relative=child_relative,
                    expected_uid=expected_uid,
                    include_bytes=include_bytes,
                    require_private_modes=require_private_modes,
                )
            finally:
                os.close(child)
            entries.append(
                {
                    "relativePath": child_relative,
                    "kind": "directory",
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                    "mode": f"{mode:04o}",
                    "linkCount": metadata.st_nlink,
                }
            )
            entries.extend(children)
            total += child_total
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1 or (
                mode & (0o077 if require_private_modes else 0o022)
            ) or metadata.st_size > MAX_CANONICAL_BYTES:
                raise NativeBoundaryV27Error(
                    f"staged Beads file {child_relative} mode/size is unsafe"
                )
            child = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                reopened = os.fstat(child)
                if (
                    (reopened.st_dev, reopened.st_ino, reopened.st_size)
                    != (metadata.st_dev, metadata.st_ino, metadata.st_size)
                ):
                    raise NativeBoundaryV27Error(
                        f"staged Beads file {child_relative} changed during open"
                    )
                raw = _pread_exact_bounded_v27(
                    child, metadata.st_size, f"staged Beads file {child_relative}"
                )
            finally:
                os.close(child)
            total += len(raw)
            entry: dict[str, Any] = {
                "relativePath": child_relative,
                "kind": "regular",
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "mode": f"{mode:04o}",
                "linkCount": metadata.st_nlink,
                "size": len(raw),
                "sha256": sha256(raw),
            }
            if include_bytes:
                entry["bytesBase64"] = base64.b64encode(raw).decode("ascii")
            entries.append(entry)
        else:
            raise NativeBoundaryV27Error(
                f"staged Beads entry {child_relative} is symlinked or special"
            )
        if len(entries) > _MAX_STAGED_TREE_FILES_V27 or total > _MAX_STAGED_TREE_BYTES_V27:
            raise NativeBoundaryV27Error("staged Beads tree exceeds fixed resource bounds")
    return entries, total


def _capture_opened_beads_tree_v27(
    descriptor: int,
    *,
    expected_uid: int,
    include_bytes: bool = False,
    require_private_modes: bool = True,
) -> dict[str, Any]:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_nlink < 1
        or stat.S_IMODE(metadata.st_mode)
        & (0o077 if require_private_modes else 0o022)
    ):
        raise NativeBoundaryV27Error(
            "staged Beads root owner/link/mode identity is unsafe"
        )
    entries, total = _capture_beads_tree_fd_v27(
        descriptor,
        expected_uid=expected_uid,
        include_bytes=include_bytes,
        require_private_modes=require_private_modes,
    )
    digest_entries = [
        {key: value for key, value in entry.items() if key != "bytesBase64"}
        for entry in entries
    ]
    content_entries = [
        {
            key: value
            for key, value in entry.items()
            if key not in {
                "bytesBase64", "device", "inode", "uid", "gid", "mode",
                "linkCount",
            }
        }
        for entry in entries
    ]
    root_identity = {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "linkCount": metadata.st_nlink,
    }
    return {
        "schemaVersion": 27,
        "entryCount": len(entries),
        "totalBytes": total,
        "entries": entries,
        "rootIdentity": root_identity,
        "rootIdentitySha256": sha256(canonical_bytes(root_identity)),
        "treeSha256": sha256(
            b"startup-factory/beads/v27/staged-tree\0"
            + canonical_bytes(digest_entries)
        ),
        "contentSha256": sha256(
            b"startup-factory/beads/v27/staged-tree-content\0"
            + canonical_bytes(content_entries)
        ),
    }


def capture_beads_tree_v27(
    root: Path,
    *,
    expected_uid: int | None = None,
    include_bytes: bool = False,
    require_private_modes: bool = True,
) -> dict[str, Any]:
    if not isinstance(root, Path) or not root.is_absolute():
        raise NativeBoundaryV27Error("staged Beads root must be absolute")
    uid = os.geteuid() if expected_uid is None else expected_uid
    descriptor = os.open(
        root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        return _capture_opened_beads_tree_v27(
            descriptor,
            expected_uid=uid,
            include_bytes=include_bytes,
            require_private_modes=require_private_modes,
        )
    finally:
        os.close(descriptor)


def _capture_pinned_repository_beads_tree_v27(
    repository: Path,
    *,
    expected_uid: int | None = None,
    include_bytes: bool = False,
    require_private_modes: bool = True,
) -> dict[str, Any]:
    """Capture `.beads` without following any repository ancestry name."""

    uid = os.geteuid() if expected_uid is None else expected_uid
    repository_fd, ancestry = _open_pinned_repository_v27(repository)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        beads_fd = os.open(".beads", flags, dir_fd=repository_fd)
        try:
            before = os.fstat(beads_fd)
            captured = _capture_opened_beads_tree_v27(
                beads_fd,
                expected_uid=uid,
                include_bytes=include_bytes,
                require_private_modes=require_private_modes,
            )
            after = os.fstat(beads_fd)
            if not _same_physical_identity_v27(before, after):
                raise NativeBoundaryV27Error(
                    "producer Beads root changed during descriptor capture"
                )
        finally:
            os.close(beads_fd)
    finally:
        os.close(repository_fd)
    rebound_repository_fd = _rebind_physical_ancestry_v27(repository, ancestry)
    try:
        rebound_beads_fd = os.open(".beads", flags, dir_fd=rebound_repository_fd)
        try:
            if not _same_physical_identity_v27(
                before, os.fstat(rebound_beads_fd)
            ):
                raise NativeBoundaryV27Error(
                    "producer Beads root changed after descriptor capture"
                )
        finally:
            os.close(rebound_beads_fd)
    finally:
        os.close(rebound_repository_fd)
    return captured


def _repository_path_binding_from_ancestry_v27(
    ancestry: list[dict[str, Any]],
) -> dict[str, str]:
    if not ancestry:
        raise NativeBoundaryV27Error("V27 repository ancestry is empty")
    stable = [
        {key: value for key, value in item.items() if key != "linkCount"}
        for item in ancestry
    ]
    return {
        "repositoryPathIdentitySha256": sha256(canonical_bytes(stable[-1])),
        "repositoryAncestrySha256": sha256(canonical_bytes(stable)),
    }


def _repository_path_binding_v27(repository: Path) -> dict[str, str]:
    descriptor, ancestry = _open_pinned_repository_v27(repository)
    try:
        return _repository_path_binding_from_ancestry_v27(ancestry)
    finally:
        os.close(descriptor)


def _require_repository_path_binding_v27(
    observed: Mapping[str, str], stage_payload: Mapping[str, Any]
) -> None:
    if any(
        observed.get(field) != stage_payload.get(f"producer{field[0].upper()}{field[1:]}")
        for field in (
            "repositoryPathIdentitySha256", "repositoryAncestrySha256"
        )
    ):
        raise NativeBoundaryV27Error(
            "V27 producer repository path identity changed"
        )


def materialize_controller_owned_beads_tree_v27(
    source: Path,
    destination: Path,
    *,
    source_uid: int | None = None,
    source_requires_private_modes: bool = False,
    destination_parent_requires_private_modes: bool = True,
    fault_prefix: str | None = None,
    source_repository: Path | None = None,
) -> dict[str, Any]:
    """Copy one validated `.beads` tree without following producer names."""

    parent = destination.parent
    parent_metadata = os.lstat(parent)
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode)
        & (0o077 if destination_parent_requires_private_modes else 0o022)
    ):
        raise NativeBoundaryV27Error("staged destination parent is unsafe")
    if source_repository is not None and source != source_repository / ".beads":
        raise NativeBoundaryV27Error(
            "pinned source repository does not own the staged Beads path"
        )

    def capture_source(*, include_bytes: bool) -> dict[str, Any]:
        if source_repository is not None:
            return _capture_pinned_repository_beads_tree_v27(
                source_repository,
                expected_uid=source_uid,
                include_bytes=include_bytes,
                require_private_modes=source_requires_private_modes,
            )
        return capture_beads_tree_v27(
            source,
            expected_uid=source_uid,
            include_bytes=include_bytes,
            require_private_modes=source_requires_private_modes,
        )

    captured = capture_source(include_bytes=True)
    try:
        os.mkdir(destination, 0o700)
        if fault_prefix is not None:
            _effect_fault(f"{fault_prefix}-root-created")
    except FileExistsError:
        metadata = os.lstat(destination)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise NativeBoundaryV27Error(
                "staged destination is substituted or unsafe"
            )
    root_fd = os.open(
        destination,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    directories: dict[str, int] = {"": root_fd}
    try:
        for entry_index, entry in enumerate(captured["entries"]):
            relative = str(entry["relativePath"])
            parent_relative, _, leaf = relative.rpartition("/")
            parent_fd = directories.get(parent_relative)
            if parent_fd is None:
                raise NativeBoundaryV27Error("staged tree ordering lost its parent")
            if entry["kind"] == "directory":
                try:
                    os.mkdir(leaf, 0o700, dir_fd=parent_fd)
                    if fault_prefix is not None:
                        _effect_fault(
                            f"{fault_prefix}-entry-{entry_index}-directory-created"
                        )
                except FileExistsError:
                    metadata = os.stat(
                        leaf, dir_fd=parent_fd, follow_symlinks=False
                    )
                    if (
                        not stat.S_ISDIR(metadata.st_mode)
                        or metadata.st_uid != os.geteuid()
                        or stat.S_IMODE(metadata.st_mode) != 0o700
                    ):
                        raise NativeBoundaryV27Error(
                            "staged directory prefix is substituted or unsafe"
                        )
                child_fd = os.open(
                    leaf,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
                directories[relative] = child_fd
            else:
                raw = base64.b64decode(entry["bytesBase64"], validate=True)
                try:
                    child_fd = os.open(
                        leaf,
                        os.O_RDWR
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=parent_fd,
                    )
                    prefix = b""
                    if fault_prefix is not None:
                        _effect_fault(
                            f"{fault_prefix}-entry-{entry_index}-file-created"
                        )
                except FileExistsError:
                    child_fd = os.open(
                        leaf,
                        os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=parent_fd,
                    )
                    metadata = os.fstat(child_fd)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.geteuid()
                        or metadata.st_nlink != 1
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or metadata.st_size > len(raw)
                    ):
                        os.close(child_fd)
                        raise NativeBoundaryV27Error(
                            "staged file prefix is substituted or unsafe"
                        )
                    prefix = _pread_exact_bounded_v27(
                        child_fd, metadata.st_size, "staged file prefix"
                    )
                    if not raw.startswith(prefix):
                        os.close(child_fd)
                        raise NativeBoundaryV27Error(
                            "staged file prefix conflicts with the source"
                        )
                try:
                    if len(prefix) < len(raw):
                        os.lseek(child_fd, len(prefix), os.SEEK_SET)
                        _write_all_v27(child_fd, raw[len(prefix):])
                        if fault_prefix is not None:
                            _effect_fault(
                                f"{fault_prefix}-entry-{entry_index}-bytes-written"
                            )
                    os.fsync(child_fd)
                    if fault_prefix is not None:
                        _effect_fault(
                            f"{fault_prefix}-entry-{entry_index}-file-fsynced"
                        )
                finally:
                    os.close(child_fd)
                os.fsync(parent_fd)
                if fault_prefix is not None:
                    _effect_fault(
                        f"{fault_prefix}-entry-{entry_index}-parent-fsynced"
                    )
        for directory_index, descriptor in enumerate(
            reversed(tuple(directories.values()))
        ):
            os.fsync(descriptor)
            if fault_prefix is not None:
                _effect_fault(
                    f"{fault_prefix}-directory-{directory_index}-fsynced"
                )
    finally:
        for relative, descriptor in tuple(directories.items()):
            if relative:
                os.close(descriptor)
        os.close(root_fd)
    after_source = capture_source(include_bytes=False)
    staged = capture_beads_tree_v27(destination, include_bytes=False)
    if (
        after_source["treeSha256"] != captured["treeSha256"]
        or after_source["rootIdentitySha256"]
        != captured["rootIdentitySha256"]
        or staged["contentSha256"] != captured["contentSha256"]
    ):
        raise NativeBoundaryV27Error(
            "producer or controller-owned staged Beads tree changed during copy"
        )
    if fault_prefix is not None:
        _effect_fault(f"{fault_prefix}-source-revalidated")
    return staged


def _same_captured_tree_v27(
    left: Mapping[str, Any], right: Mapping[str, Any], *, physical: bool
) -> bool:
    fields = (
        ("treeSha256", "contentSha256", "rootIdentitySha256")
        if physical
        else ("contentSha256",)
    )
    return all(left.get(field) == right.get(field) for field in fields)


def _load_or_publish_controller_record_v27(
    path: Path,
    key: bytes,
    kind: str,
    payload: Mapping[str, Any],
    *,
    phase: str,
) -> dict[str, Any]:
    envelope = _effect_sign(kind, payload, key)
    _publish_controller_record_atomic_v27(
        path, envelope, key, expected_kind=kind, phase=phase
    )
    return envelope


def _publish_controller_record_atomic_v27(
    path: Path,
    envelope: Mapping[str, Any],
    key: bytes,
    *,
    expected_kind: str,
    phase: str,
) -> None:
    """Crash-close a fixed controller record without replacing any name."""

    raw = canonical_bytes(dict(envelope))
    temporary = path.with_name(f".{path.name}.tmp")
    final_metadata: os.stat_result | None = None
    temporary_metadata: os.stat_result | None = None
    try:
        final_metadata = os.lstat(path)
    except FileNotFoundError:
        pass
    try:
        temporary_metadata = os.lstat(temporary)
    except FileNotFoundError:
        pass

    if final_metadata is not None:
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(final_metadata.st_mode) != 0o600
            or final_metadata.st_size != len(raw)
            or final_metadata.st_nlink not in {1, 2}
        ):
            raise NativeBoundaryV27Error(
                "V27 controller custody final metadata is unsafe"
            )
        final_fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if _pread_exact_bounded_v27(
                final_fd, final_metadata.st_size, "controller custody final"
            ) != raw:
                raise NativeBoundaryV27Error(
                    "V27 controller custody final bytes conflict"
                )
            os.fsync(final_fd)
        finally:
            os.close(final_fd)
        if temporary_metadata is not None:
            if (
                temporary_metadata.st_dev,
                temporary_metadata.st_ino,
            ) != (final_metadata.st_dev, final_metadata.st_ino):
                raise NativeBoundaryV27Error(
                    "V27 controller custody temporary conflicts with final"
                )
            os.unlink(temporary)
            _effect_fault(f"{phase}-temporary-unlinked")
        _fsync_directory_v27(path.parent)
        existing = _read_effect_record(path, key, expected_kind=expected_kind)
        if canonical_bytes(existing) != raw:
            raise NativeBoundaryV27Error(
                "V27 controller custody authenticated final conflicts"
            )
        return

    try:
        descriptor = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        prefix = b""
    except FileExistsError:
        descriptor = os.open(
            temporary, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > len(raw)
        ):
            os.close(descriptor)
            raise NativeBoundaryV27Error(
                "V27 controller custody temporary metadata is unsafe"
            )
        prefix = _pread_exact_bounded_v27(
            descriptor, metadata.st_size, "controller custody temporary"
        )
        if not raw.startswith(prefix):
            os.close(descriptor)
            raise NativeBoundaryV27Error(
                "V27 controller custody temporary bytes conflict"
            )
    try:
        if len(prefix) < len(raw):
            os.lseek(descriptor, len(prefix), os.SEEK_SET)
            _write_all_v27(descriptor, raw[len(prefix):])
        _effect_fault(f"{phase}-temporary-bytes-written")
        os.fsync(descriptor)
        _effect_fault(f"{phase}-temporary-file-fsynced")
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError:
        raise NativeBoundaryV27Error(
            "V27 controller custody final appeared concurrently"
        )
    _effect_fault(f"{phase}-installed")
    _fsync_directory_v27(path.parent)
    _effect_fault(f"{phase}-install-directory-fsynced")
    os.unlink(temporary)
    _effect_fault(f"{phase}-temporary-unlinked")
    _fsync_directory_v27(path.parent)
    _effect_fault(f"{phase}-directory-fsynced")
    existing = _read_effect_record(path, key, expected_kind=expected_kind)
    if canonical_bytes(existing) != raw:
        raise NativeBoundaryV27Error(
            "V27 controller custody authenticated final conflicts"
        )


def _finalize_controller_record_link_prefix_v27(path: Path) -> None:
    """Finish only the exact final+temporary hardlink crash prefix."""

    temporary = path.with_name(f".{path.name}.tmp")
    try:
        final = os.lstat(path)
    except FileNotFoundError:
        return
    try:
        prefix = os.lstat(temporary)
    except FileNotFoundError:
        prefix = None
    if prefix is None:
        return
    if (
        not stat.S_ISREG(final.st_mode)
        or not stat.S_ISREG(prefix.st_mode)
        or (final.st_dev, final.st_ino) != (prefix.st_dev, prefix.st_ino)
        or final.st_uid != os.geteuid()
        or stat.S_IMODE(final.st_mode) != 0o600
        or final.st_nlink != 2
        or prefix.st_nlink != 2
    ):
        raise NativeBoundaryV27Error(
            "V27 controller custody installed prefix was substituted"
        )
    os.unlink(temporary)
    _fsync_directory_v27(path.parent)


def _persist_repository_post_manifest_v27(
    *,
    custody: Path,
    key: bytes,
    plan: Mapping[str, Any],
    repository_custody: Mapping[str, Any],
    release_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    directory_mode, file_mode = (
        (0o550, 0o440)
        if repository_custody["accessMode"] == "read-only"
        else (0o770, 0o660)
    )
    post = _repository_custody_manifest_v27(
        Path(str(repository_custody["leafPath"])),
        controller_uid=int(repository_custody["controllerUid"]),
        worker_gid=int(repository_custody["workerGid"]),
        directory_mode=directory_mode,
        file_mode=file_mode,
    )
    if post["manifestSha256"] != release_receipt.get(
        "postRepositoryManifestSha256"
    ):
        raise NativeBoundaryV27Error(
            "V27 repository post manifest differs from release probe"
        )
    return _load_or_publish_controller_record_v27(
        custody / f"repository-post-{plan['stageLocation']}.json",
        key,
        "ControllerRepositoryPostManifestV1",
        {
            "schemaVersion": 27,
            "profile": PROFILE,
            "operationId": plan["operationId"],
            "stageLocation": plan["stageLocation"],
            "stagePlanSha256": plan["stagePlanSha256"],
            "repositoryCustodyBindingSha256": repository_custody[
                "bindingSha256"
            ],
            "postManifest": post,
            "postManifestSha256": post["manifestSha256"],
        },
        phase=f"repository-access-{plan['stageLocation']}-post-manifest",
    )


def _controller_stage_paths_v27(
    operation: Path,
    key: bytes,
    plan: Mapping[str, Any],
    profile: Mapping[str, Any] | None,
) -> tuple[Path, Path, tuple[Path, ...], Path, dict[str, Any] | None]:
    custody = _safe_effect_directory(operation, "custody")
    retained = _safe_effect_directory(custody, "retained")
    if profile is None:
        effect = _safe_effect_directory(custody, "effect")
        snapshots_root = _safe_effect_directory(custody, "snapshots")
        snapshots = tuple(
            _safe_effect_directory(snapshots_root, f"reader-{ordinal}")
            for ordinal in range(4)
        )
        return custody, effect, snapshots, retained, None
    fields = {
        "rootPath", "controllerUid", "workerGid", "workerSessionNonce"
    }
    if not isinstance(profile, Mapping) or set(profile) != fields:
        raise NativeBoundaryV27Error(
            "V27 repository custody profile shape changed"
        )
    root = Path(str(profile["rootPath"]))
    if (
        not root.is_absolute()
        or profile["controllerUid"] != os.geteuid()
        or type(profile["workerGid"]) is not int
        or profile["workerGid"] <= 0
        or not isinstance(profile["workerSessionNonce"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", profile["workerSessionNonce"])
    ):
        raise NativeBoundaryV27Error(
            "V27 repository custody profile identity changed"
        )
    metadata = os.lstat(root)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != profile["controllerUid"]
        or metadata.st_gid != profile["workerGid"]
        or stat.S_IMODE(metadata.st_mode) != 0o2710
    ):
        raise NativeBoundaryV27Error(
            "V27 repository custody root is not controller-owned 2710"
        )

    def leaf(role: str, ordinal: int | None) -> Path:
        body = {
            "operationId": plan["operationId"],
            "operationClass": plan["operationClass"],
            "planSha256": plan["planSha256"],
            "workerSessionNonce": profile["workerSessionNonce"],
            "role": role,
            "ordinal": ordinal,
        }
        token = hmac.new(
            key,
            _REPOSITORY_CUSTODY_LEAF_DOMAIN_V27 + canonical_bytes(body),
            hashlib.sha256,
        ).hexdigest()
        destination = root / f"v27-{token}"
        try:
            os.mkdir(destination, 0o700)
            os.chmod(destination, 0o700, follow_symlinks=False)
        except FileExistsError:
            pass
        observed = os.lstat(destination)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or observed.st_uid != profile["controllerUid"]
            or observed.st_gid != profile["workerGid"]
            or stat.S_IMODE(observed.st_mode) != 0o700
        ):
            raise NativeBoundaryV27Error(
                "V27 repository custody leaf is substituted or still granted"
            )
        return destination

    effect = leaf("effect-preparation", None)
    snapshots = tuple(leaf("reader-snapshot", ordinal) for ordinal in range(4))
    metadata = os.lstat(root)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != profile["controllerUid"]
        or metadata.st_gid != profile["workerGid"]
        or stat.S_IMODE(metadata.st_mode) != 0o2710
    ):
        raise NativeBoundaryV27Error(
            "V27 repository custody root changed while leaves were created"
        )
    root_identity = {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": "2710",
    }
    binding = {
        **dict(profile),
        "rootIdentitySha256": sha256(canonical_bytes(root_identity)),
        "effectLeaf": effect.name,
        "snapshotLeaves": [item.name for item in snapshots],
    }
    binding["bindingSha256"] = sha256(
        _REPOSITORY_CUSTODY_BINDING_DOMAIN_V27 + canonical_bytes(binding)
    )
    return custody, effect, snapshots, retained, binding


def _ensure_controller_repository_stage_v27(
    operation: Path,
    objects: Path,
    key: bytes,
    plan: Mapping[str, Any],
    profile: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], Path, tuple[Path, ...], Path, Path]:
    """Create/reopen the one controller-owned mutation repository.

    The authenticated stage record is immutable and records the producer
    prestate before any worker-visible path exists.  Later calls deliberately
    do not re-copy from the producer: all payload and read activity is derived
    from this controller-owned root.
    """

    del objects  # Kept in the call signature to make custody ownership explicit.
    custody, effect, snapshots, retained, custody_binding = (
        _controller_stage_paths_v27(operation, key, plan, profile)
    )
    intent_path = custody / "repository-stage-materialization-intent.json"
    record_path = custody / "repository-stage.json"
    repository = Path(str(plan["repositoryPath"]))
    source = repository / ".beads"
    if record_path.exists() or record_path.is_symlink():
        _finalize_controller_record_link_prefix_v27(record_path)
        intent = _read_effect_record(
            intent_path,
            key,
            expected_kind="ControllerRepositoryStageMaterializationIntentV1",
        )
        record = _read_effect_record(
            record_path, key, expected_kind="ControllerRepositoryStageV1"
        )
        payload = record["payload"]
        expected = {
            "schemaVersion": 27,
            "profile": PROFILE,
            "operationId": plan["operationId"],
            "operationClass": plan["operationClass"],
            "planSha256": plan["planSha256"],
            "producerRepositoryPath": str(repository),
            "controllerRepositoryPath": str(effect),
            "repositoryCustodyBinding": custody_binding,
            "materializationIntentRecordSha256": intent["recordSha256"],
            **{
                field: intent["payload"][field]
                for field in (
                    "producerPrestateTreeSha256",
                    "producerPrestateContentSha256",
                    "producerPrestateRootIdentitySha256",
                    "producerRepositoryPathIdentitySha256",
                    "producerRepositoryAncestrySha256",
                )
            },
        }
        if any(payload.get(field) != value for field, value in expected.items()):
            raise NativeBoundaryV27Error(
                "V27 controller repository stage binding changed"
            )
        staged = capture_beads_tree_v27(
            effect / ".beads", require_private_modes=True
        )
        if (
            staged["rootIdentitySha256"]
            != payload.get("initialStageRootIdentitySha256")
        ):
            # The root identity never changes when bd mutates files beneath it.
            raise NativeBoundaryV27Error(
                "V27 controller repository stage root was substituted"
            )
        return record, effect, snapshots, retained, custody

    repository_binding_before = _repository_path_binding_v27(repository)
    source_before = _capture_pinned_repository_beads_tree_v27(
        repository, include_bytes=False, require_private_modes=False
    )
    intent = _load_or_publish_controller_record_v27(
        intent_path,
        key,
        "ControllerRepositoryStageMaterializationIntentV1",
        {
            "schemaVersion": 27,
            "profile": PROFILE,
            "operationId": plan["operationId"],
            "operationClass": plan["operationClass"],
            "planSha256": plan["planSha256"],
            "producerRepositoryPath": str(repository),
            "producerBeadsPath": str(source),
            "controllerRepositoryPath": str(effect),
            "controllerBeadsPath": str(effect / ".beads"),
            "repositoryCustodyBinding": custody_binding,
            "producerPrestateTreeSha256": source_before["treeSha256"],
            "producerPrestateContentSha256": source_before["contentSha256"],
            "producerPrestateRootIdentitySha256": source_before[
                "rootIdentitySha256"
            ],
            "producerRepositoryPathIdentitySha256": repository_binding_before[
                "repositoryPathIdentitySha256"
            ],
            "producerRepositoryAncestrySha256": repository_binding_before[
                "repositoryAncestrySha256"
            ],
        },
        phase="controller-repository-stage-materialization-intent",
    )
    staged = materialize_controller_owned_beads_tree_v27(
        source,
        effect / ".beads",
        source_requires_private_modes=False,
        fault_prefix="controller-repository-stage-copy",
        source_repository=repository,
    )
    source_after = _capture_pinned_repository_beads_tree_v27(
        repository, include_bytes=False, require_private_modes=False
    )
    repository_binding_after = _repository_path_binding_v27(repository)
    if (
        not _same_captured_tree_v27(source_before, source_after, physical=True)
        or repository_binding_after != repository_binding_before
    ):
        raise NativeBoundaryV27Error(
            "producer Beads tree changed while controller custody was created"
        )
    payload = {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "planSha256": plan["planSha256"],
        "producerRepositoryPath": str(repository),
        "controllerRepositoryPath": str(effect),
        "repositoryCustodyBinding": custody_binding,
        "materializationIntentRecordSha256": intent["recordSha256"],
        "producerPrestateTreeSha256": source_before["treeSha256"],
        "producerPrestateContentSha256": source_before["contentSha256"],
        "producerPrestateRootIdentitySha256": source_before[
            "rootIdentitySha256"
        ],
        "producerRepositoryPathIdentitySha256": repository_binding_before[
            "repositoryPathIdentitySha256"
        ],
        "producerRepositoryAncestrySha256": repository_binding_before[
            "repositoryAncestrySha256"
        ],
        "initialStageTreeSha256": staged["treeSha256"],
        "initialStageContentSha256": staged["contentSha256"],
        "initialStageRootIdentitySha256": staged["rootIdentitySha256"],
    }
    record = _load_or_publish_controller_record_v27(
        record_path,
        key,
        "ControllerRepositoryStageV1",
        payload,
        phase="controller-repository-stage",
    )
    return record, effect, snapshots, retained, custody


def _repository_custody_manifest_fd_v27(
    descriptor: int,
    *,
    relative: str,
    controller_uid: int,
    worker_gid: int,
    directory_mode: int | frozenset[int],
    file_mode: int | frozenset[int],
) -> list[dict[str, Any]]:
    """Capture every identity in one granted/revoked custody leaf by dirfd."""

    entries: list[dict[str, Any]] = []
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != controller_uid
        or metadata.st_gid != worker_gid
        or (
            stat.S_IMODE(metadata.st_mode) not in directory_mode
            if isinstance(directory_mode, frozenset)
            else stat.S_IMODE(metadata.st_mode) != directory_mode
        )
        or metadata.st_nlink < 1
    ):
        raise NativeBoundaryV27Error(
            "V27 repository custody directory identity or mode changed"
        )
    entries.append(
        {
            "relativePath": relative,
            "kind": "directory",
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "linkCount": metadata.st_nlink,
            "size": None,
            "sha256": None,
        }
    )
    try:
        names = sorted(os.listdir(descriptor), key=os.fsencode)
    except OSError as exc:
        raise NativeBoundaryV27Error(
            f"cannot enumerate repository custody: {exc}"
        ) from exc
    for name in names:
        if not isinstance(name, str) or not name or name in {".", ".."} or "/" in name:
            raise NativeBoundaryV27Error("V27 repository custody leaf name changed")
        child_relative = name if relative == "." else f"{relative}/{name}"
        observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(observed.st_mode):
            child = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                reopened = os.fstat(child)
                if (reopened.st_dev, reopened.st_ino) != (
                    observed.st_dev,
                    observed.st_ino,
                ):
                    raise NativeBoundaryV27Error(
                        "V27 repository custody directory changed during open"
                    )
                entries.extend(
                    _repository_custody_manifest_fd_v27(
                        child,
                        relative=child_relative,
                        controller_uid=controller_uid,
                        worker_gid=worker_gid,
                        directory_mode=directory_mode,
                        file_mode=file_mode,
                    )
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(observed.st_mode):
            if (
                observed.st_uid != controller_uid
                or observed.st_gid != worker_gid
                or (
                    stat.S_IMODE(observed.st_mode) not in file_mode
                    if isinstance(file_mode, frozenset)
                    else stat.S_IMODE(observed.st_mode) != file_mode
                )
                or observed.st_nlink != 1
                or observed.st_size > MAX_CANONICAL_BYTES
            ):
                raise NativeBoundaryV27Error(
                    "V27 repository custody file identity or mode changed"
                )
            child = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                reopened = os.fstat(child)
                if (reopened.st_dev, reopened.st_ino, reopened.st_size) != (
                    observed.st_dev,
                    observed.st_ino,
                    observed.st_size,
                ):
                    raise NativeBoundaryV27Error(
                        "V27 repository custody file changed during open"
                    )
                raw = _pread_exact_bounded_v27(
                    child, observed.st_size, "repository custody file"
                )
            finally:
                os.close(child)
            entries.append(
                {
                    "relativePath": child_relative,
                    "kind": "regular",
                    "device": observed.st_dev,
                    "inode": observed.st_ino,
                    "uid": observed.st_uid,
                    "gid": observed.st_gid,
                    "mode": f"{stat.S_IMODE(observed.st_mode):04o}",
                    "linkCount": observed.st_nlink,
                    "size": observed.st_size,
                    "sha256": sha256(raw),
                }
            )
        else:
            raise NativeBoundaryV27Error(
                "V27 repository custody contains a symlink or special file"
            )
        if len(entries) > _MAX_STAGED_TREE_FILES_V27:
            raise NativeBoundaryV27Error(
                "V27 repository custody exceeds the fixed entry bound"
            )
    return entries


def _repository_custody_manifest_v27(
    path: Path,
    *,
    controller_uid: int,
    worker_gid: int,
    directory_mode: int | frozenset[int],
    file_mode: int | frozenset[int],
) -> dict[str, Any]:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        entries = _repository_custody_manifest_fd_v27(
            descriptor,
            relative=".",
            controller_uid=controller_uid,
            worker_gid=worker_gid,
            directory_mode=directory_mode,
            file_mode=file_mode,
        )
    finally:
        os.close(descriptor)
    body = {"schemaVersion": 27, "entries": entries}
    body["manifestSha256"] = sha256(
        _REPOSITORY_CUSTODY_MANIFEST_DOMAIN_V27 + canonical_bytes(body)
    )
    return body


def _chmod_repository_custody_fd_v27(
    descriptor: int,
    *,
    directory_mode: int,
    file_mode: int,
    revoke: bool,
    fault_prefix: str | None = None,
    fault_counter: list[int] | None = None,
) -> None:
    """Change an exact tree while the leaf itself remains the access gate."""

    if revoke:
        os.fchmod(descriptor, directory_mode)
        os.fsync(descriptor)
        if fault_prefix is not None and fault_counter is not None:
            _effect_fault(f"{fault_prefix}-mode-{fault_counter[0]}")
            fault_counter[0] += 1
    for name in sorted(os.listdir(descriptor), key=os.fsencode):
        observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(observed.st_mode):
            child = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                _chmod_repository_custody_fd_v27(
                    child,
                    directory_mode=directory_mode,
                    file_mode=file_mode,
                    revoke=revoke,
                    fault_prefix=fault_prefix,
                    fault_counter=fault_counter,
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(observed.st_mode):
            child = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                os.fchmod(child, file_mode)
                os.fsync(child)
                if fault_prefix is not None and fault_counter is not None:
                    _effect_fault(f"{fault_prefix}-mode-{fault_counter[0]}")
                    fault_counter[0] += 1
            finally:
                os.close(child)
        else:
            raise NativeBoundaryV27Error(
                "V27 repository custody contains a symlink or special file"
            )
    if not revoke:
        os.fchmod(descriptor, directory_mode)
        os.fsync(descriptor)
        if fault_prefix is not None and fault_counter is not None:
            _effect_fault(f"{fault_prefix}-mode-{fault_counter[0]}")
            fault_counter[0] += 1


def _grant_repository_custody_v27(
    *,
    path: Path,
    stage_record: Mapping[str, Any],
    stage: "LiteralStageV27",
    before_grant: Any = None,
    admitted_leaf_names: set[str] | None = None,
) -> dict[str, Any] | None:
    binding = stage_record["payload"].get("repositoryCustodyBinding")
    if binding is None:
        return None
    root = Path(str(binding["rootPath"]))
    root_fd = os.open(
        root,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        local_names = {
            str(binding["effectLeaf"]),
            *(str(item) for item in binding["snapshotLeaves"]),
        }
        admitted_names = local_names if admitted_leaf_names is None else admitted_leaf_names
        observed_names = set(os.listdir(root_fd))
        if not local_names <= observed_names or not observed_names <= admitted_names:
            raise NativeBoundaryV27Error(
                "V27 repository custody root contains a guessed or missing leaf"
            )
        for name in observed_names:
            observed = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
                raise NativeBoundaryV27Error(
                    "V27 repository custody root contains unexpected evidence"
                )
            if stat.S_IMODE(observed.st_mode) & 0o070:
                raise NativeBoundaryV27Error(
                    "V27 worker/session already has an accessible custody leaf"
                )
    finally:
        os.close(root_fd)
    reader = re.fullmatch(r"reader-([0-3])-payload-terminal", stage.stage_key)
    access = "read-only" if reader is not None else "read-write"
    ordinal = int(reader.group(1)) if reader is not None else None
    expected_leaf = (
        binding["snapshotLeaves"][ordinal]
        if ordinal is not None
        else binding["effectLeaf"]
    )
    if path.parent != root or path.name != expected_leaf:
        raise NativeBoundaryV27Error("V27 repository custody leaf binding changed")
    controller_uid = int(binding["controllerUid"])
    worker_gid = int(binding["workerGid"])
    before = _repository_custody_manifest_v27(
        path,
        controller_uid=controller_uid,
        worker_gid=worker_gid,
        directory_mode=0o700,
        file_mode=0o600,
    )
    directory_mode, file_mode = (
        (0o550, 0o440) if access == "read-only" else (0o770, 0o660)
    )
    predicted_entries = [
        {
            **item,
            "mode": (
                f"{directory_mode:04o}"
                if item["kind"] == "directory"
                else f"{file_mode:04o}"
            ),
        }
        for item in before["entries"]
    ]
    predicted: dict[str, Any] = {
        "schemaVersion": 27,
        "entries": predicted_entries,
    }
    predicted["manifestSha256"] = sha256(
        _REPOSITORY_CUSTODY_MANIFEST_DOMAIN_V27
        + canonical_bytes(predicted)
    )
    result = {
        "schemaVersion": 27,
        "rootBindingSha256": binding["bindingSha256"],
        "stageRecordSha256": stage_record["recordSha256"],
        "workerSessionNonce": binding["workerSessionNonce"],
        "controllerUid": controller_uid,
        "workerGid": worker_gid,
        "leafPath": str(path),
        "leafName": path.name,
        "accessMode": access,
        "readerOrdinal": ordinal,
        "manifest": predicted,
        "manifestSha256": predicted["manifestSha256"],
    }
    result["bindingSha256"] = sha256(
        _REPOSITORY_CUSTODY_BINDING_DOMAIN_V27 + canonical_bytes(result)
    )
    if before_grant is not None:
        if not callable(before_grant):
            raise NativeBoundaryV27Error(
                "V27 repository custody pre-grant authority changed"
            )
        before_grant(result, before)
    _effect_fault(f"repository-access-{stage.location}-intent-durable")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        _chmod_repository_custody_fd_v27(
            descriptor,
            directory_mode=directory_mode,
            file_mode=file_mode,
            revoke=False,
            fault_prefix=f"repository-access-{stage.location}-grant",
            fault_counter=[0],
        )
    finally:
        os.close(descriptor)
    granted = _repository_custody_manifest_v27(
        path,
        controller_uid=controller_uid,
        worker_gid=worker_gid,
        directory_mode=directory_mode,
        file_mode=file_mode,
    )
    if granted != predicted:
        raise NativeBoundaryV27Error(
            "V27 repository custody changed while access was granted"
        )
    _effect_fault(f"repository-access-{stage.location}-grant-verified")
    return result


def _authenticated_repository_custody_leaf_names_v27(
    state_root: Path, key: bytes
) -> set[str]:
    namespace = state_root / "native-effects-v27"
    if not namespace.exists() and not namespace.is_symlink():
        return set()
    names: set[str] = set()
    for operation in sorted(namespace.iterdir(), key=lambda item: os.fsencode(item.name)):
        info = os.lstat(operation)
        if (
            not _EFFECT_OPERATION_ID.fullmatch(operation.name)
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise NativeBoundaryV27Error(
                "V27 repository custody operation registry changed"
            )
        stage_path = operation / "custody/repository-stage.json"
        if not stage_path.exists() and not stage_path.is_symlink():
            continue
        stage_record = _read_effect_record(
            stage_path, key, expected_kind="ControllerRepositoryStageV1"
        )
        binding = stage_record["payload"].get("repositoryCustodyBinding")
        if binding is None:
            continue
        candidates = {
            str(binding.get("effectLeaf")),
            *(str(item) for item in binding.get("snapshotLeaves", [])),
        }
        if len(candidates) != 5 or any(
            re.fullmatch(r"v27-[0-9a-f]{64}", name) is None
            for name in candidates
        ):
            raise NativeBoundaryV27Error(
                "V27 repository custody leaf registry changed"
            )
        if names & candidates:
            raise NativeBoundaryV27Error(
                "V27 repository custody leaf registry collided"
            )
        names.update(candidates)
    return names


def validate_repository_custody_binding_v27(
    value: Any, *, repository_path: str
) -> dict[str, Any]:
    fields = {
        "schemaVersion", "rootBindingSha256", "stageRecordSha256",
        "workerSessionNonce", "controllerUid", "workerGid", "leafPath",
        "leafName", "accessMode", "readerOrdinal", "manifest",
        "manifestSha256", "bindingSha256",
    }
    data = _closed(value, fields, "V27 repository custody binding")
    manifest = data["manifest"]
    if (
        data["schemaVersion"] != 27
        or data["leafPath"] != repository_path
        or Path(repository_path).name != data["leafName"]
        or not re.fullmatch(r"v27-[0-9a-f]{64}", str(data["leafName"]))
        or data["accessMode"] not in {"read-only", "read-write"}
        or (
            data["accessMode"] == "read-only"
            and type(data["readerOrdinal"]) is not int
        )
        or (
            data["accessMode"] == "read-write"
            and data["readerOrdinal"] is not None
        )
        or type(data["controllerUid"]) is not int
        or type(data["workerGid"]) is not int
        or not isinstance(manifest, Mapping)
        or set(manifest) != {"schemaVersion", "entries", "manifestSha256"}
        or manifest.get("schemaVersion") != 27
        or manifest.get("manifestSha256") != data["manifestSha256"]
    ):
        raise NativeBoundaryV27Error("V27 repository custody binding changed")
    manifest_body = {"schemaVersion": 27, "entries": manifest["entries"]}
    if data["manifestSha256"] != sha256(
        _REPOSITORY_CUSTODY_MANIFEST_DOMAIN_V27 + canonical_bytes(manifest_body)
    ):
        raise NativeBoundaryV27Error("V27 repository custody manifest changed")
    entries = manifest["entries"]
    expected_directory_mode, expected_file_mode = (
        ("0550", "0440")
        if data["accessMode"] == "read-only"
        else ("0770", "0660")
    )
    if (
        not isinstance(entries, list)
        or not 2 <= len(entries) <= _MAX_STAGED_TREE_FILES_V27
        or not isinstance(entries[0], Mapping)
        or entries[0].get("relativePath") != "."
    ):
        raise NativeBoundaryV27Error("V27 repository custody entries changed")
    paths: set[str] = set()
    identities: set[tuple[int, int]] = set()
    for item in entries:
        item_fields = {
            "relativePath", "kind", "device", "inode", "uid", "gid",
            "mode", "linkCount", "size", "sha256",
        }
        if not isinstance(item, Mapping) or set(item) != item_fields:
            raise NativeBoundaryV27Error(
                "V27 repository custody entry shape changed"
            )
        relative = item["relativePath"]
        identity = (item["device"], item["inode"])
        if (
            not isinstance(relative, str)
            or relative in paths
            or relative.startswith("/")
            or ".." in relative.split("/")
            or type(item["device"]) is not int
            or type(item["inode"]) is not int
            or identity in identities
            or item["uid"] != data["controllerUid"]
            or item["gid"] != data["workerGid"]
            or type(item["linkCount"]) is not int
            or item["linkCount"] < 1
        ):
            raise NativeBoundaryV27Error(
                "V27 repository custody entry identity changed"
            )
        paths.add(relative)
        identities.add(identity)
        if item["kind"] == "directory":
            if (
                item["mode"] != expected_directory_mode
                or item["size"] is not None
                or item["sha256"] is not None
            ):
                raise NativeBoundaryV27Error(
                    "V27 repository custody directory policy changed"
                )
        elif item["kind"] == "regular":
            if (
                item["mode"] != expected_file_mode
                or item["linkCount"] != 1
                or type(item["size"]) is not int
                or not 0 <= item["size"] <= MAX_CANONICAL_BYTES
                or not isinstance(item["sha256"], str)
                or not _DIGEST.fullmatch(item["sha256"])
            ):
                raise NativeBoundaryV27Error(
                    "V27 repository custody file policy changed"
                )
        else:
            raise NativeBoundaryV27Error(
                "V27 repository custody entry type changed"
            )
    for field in (
        "rootBindingSha256", "stageRecordSha256", "manifestSha256"
    ):
        _digest(data[field], f"repository custody {field}")
    candidate = dict(data)
    digest = candidate.pop("bindingSha256")
    if digest != sha256(
        _REPOSITORY_CUSTODY_BINDING_DOMAIN_V27 + canonical_bytes(candidate)
    ):
        raise NativeBoundaryV27Error("V27 repository custody digest changed")
    return {**data, "manifest": {**manifest, "entries": list(manifest["entries"])}}


def _revoke_repository_custody_v27(
    value: Mapping[str, Any], release_receipt: Any, request_key: bytes
) -> dict[str, Any]:
    binding = validate_repository_custody_binding_v27(
        value, repository_path=str(value.get("leafPath"))
    )
    if not isinstance(release_receipt, Mapping):
        raise NativeBoundaryV27Error(
            "V27 repository custody lacks a release receipt"
        )
    required = {
        "schemaVersion", "operationId", "stageLocation", "stagePlanSha256",
        "workerSessionNonce", "grantWorkerSessionNonce", "probeNonce", "repositoryBindingSha256",
        "repositoryManifestSha256", "postRepositoryManifestSha256", "descriptorCount",
        "descriptorInventorySha256", "descriptorMatches", "mountCount",
        "mountInfoSha256", "mountMatches", "releaseHmac",
    }
    if set(release_receipt) != required:
        raise NativeBoundaryV27Error(
            "V27 repository custody release receipt shape changed"
        )
    release_body = {
        key: release_receipt[key] for key in required if key != "releaseHmac"
    }
    expected_hmac = "hmac-sha256:" + hmac.new(
        request_key,
        _REPOSITORY_CUSTODY_RELEASE_DOMAIN_V27 + canonical_bytes(release_body),
        hashlib.sha256,
    ).hexdigest()
    if (
        release_receipt["schemaVersion"] != 27
        or release_receipt["grantWorkerSessionNonce"]
        != binding["workerSessionNonce"]
        or not isinstance(release_receipt["workerSessionNonce"], str)
        or not re.fullmatch(
            r"[0-9a-f]{64}", release_receipt["workerSessionNonce"]
        )
        or release_receipt["repositoryBindingSha256"] != binding["bindingSha256"]
        or release_receipt["repositoryManifestSha256"]
        != binding["manifestSha256"]
        or release_receipt["descriptorMatches"] != []
        or release_receipt["mountMatches"] != []
        or not hmac.compare_digest(
            str(release_receipt["releaseHmac"]), expected_hmac
        )
    ):
        raise NativeBoundaryV27Error(
            "V27 repository custody release evidence changed"
        )
    path = Path(str(binding["leafPath"]))
    expected_directory_mode, expected_file_mode = (
        (0o550, 0o440)
        if binding["accessMode"] == "read-only"
        else (0o770, 0o660)
    )
    current = _repository_custody_manifest_v27(
        path,
        controller_uid=int(binding["controllerUid"]),
        worker_gid=int(binding["workerGid"]),
        directory_mode=expected_directory_mode,
        file_mode=expected_file_mode,
    )
    if current["manifestSha256"] != release_receipt[
        "postRepositoryManifestSha256"
    ]:
        raise NativeBoundaryV27Error(
            "V27 repository custody changed before revocation"
        )
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        _chmod_repository_custody_fd_v27(
            descriptor,
            directory_mode=0o700,
            file_mode=0o600,
            revoke=True,
            fault_prefix=(
                f"repository-access-{release_receipt['stageLocation']}-revoke"
            ),
            fault_counter=[0],
        )
    finally:
        os.close(descriptor)
    revoked = _repository_custody_manifest_v27(
        path,
        controller_uid=int(binding["controllerUid"]),
        worker_gid=int(binding["workerGid"]),
        directory_mode=0o700,
        file_mode=0o600,
    )
    if [
        (item["relativePath"], item["kind"], item["device"], item["inode"], item["sha256"])
        for item in current["entries"]
    ] != [
        (item["relativePath"], item["kind"], item["device"], item["inode"], item["sha256"])
        for item in revoked["entries"]
    ]:
        raise NativeBoundaryV27Error(
            "V27 repository custody changed during revocation"
        )
    _effect_fault(
        f"repository-access-{release_receipt['stageLocation']}-revoke-verified"
    )
    return revoked


def recover_repository_custody_v27(
    state_root: Path,
    key: bytes,
    manifest: NativeBoundaryManifestV27,
    profile: Mapping[str, Any],
    *,
    release_probe: Any,
) -> dict[str, int]:
    """Revoke only authenticated grants after service-cgroup recovery.

    This function must be called by the controller after the old delegated
    service cgroup has been drained and after the fresh worker is ready.  A
    granted leaf without an exact controller-HMAC access intent is preserved
    as substituted evidence and startup fails closed.
    """

    if not callable(release_probe):
        raise NativeBoundaryV27Error(
            "V27 repository custody recovery lacks a release probe"
        )
    profile_fields = {
        "rootPath", "controllerUid", "workerGid", "workerSessionNonce"
    }
    if not isinstance(profile, Mapping) or set(profile) != profile_fields:
        raise NativeBoundaryV27Error(
            "V27 repository custody recovery profile changed"
        )
    root = Path(str(profile["rootPath"]))
    root_info = os.lstat(root)
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or root_info.st_uid != profile["controllerUid"]
        or root_info.st_gid != profile["workerGid"]
        or stat.S_IMODE(root_info.st_mode) != 0o2710
    ):
        raise NativeBoundaryV27Error(
            "V27 repository custody recovery root changed"
        )
    namespace = state_root / "native-effects-v27"
    allowed_leaves: set[str] = set()
    pending_by_leaf: dict[str, tuple[Path, dict[str, Any]]] = {}
    if namespace.exists() or namespace.is_symlink():
        namespace_info = os.lstat(namespace)
        if (
            not stat.S_ISDIR(namespace_info.st_mode)
            or stat.S_ISLNK(namespace_info.st_mode)
            or namespace_info.st_uid != os.geteuid()
            or stat.S_IMODE(namespace_info.st_mode) != 0o700
        ):
            raise NativeBoundaryV27Error(
                "V27 repository custody state namespace changed"
            )
        for operation in sorted(namespace.iterdir(), key=lambda item: os.fsencode(item.name)):
            operation_info = os.lstat(operation)
            if (
                not _EFFECT_OPERATION_ID.fullmatch(operation.name)
                or not stat.S_ISDIR(operation_info.st_mode)
                or stat.S_ISLNK(operation_info.st_mode)
                or operation_info.st_uid != os.geteuid()
                or stat.S_IMODE(operation_info.st_mode) != 0o700
            ):
                raise NativeBoundaryV27Error(
                    "V27 repository custody operation namespace changed"
                )
            custody = operation / "custody"
            stage_path = custody / "repository-stage.json"
            if not stage_path.exists() and not stage_path.is_symlink():
                continue
            stage_record = _read_effect_record(
                stage_path, key, expected_kind="ControllerRepositoryStageV1"
            )
            binding = stage_record["payload"].get("repositoryCustodyBinding")
            if not isinstance(binding, Mapping):
                continue
            expected_profile = {
                field: profile[field]
                for field in {"rootPath", "controllerUid", "workerGid"}
            }
            if any(binding.get(field) != value for field, value in expected_profile.items()):
                raise NativeBoundaryV27Error(
                    "V27 repository custody recovery binding changed"
                )
            binding_body = {
                key_name: item
                for key_name, item in binding.items()
                if key_name != "bindingSha256"
            }
            if binding.get("bindingSha256") != sha256(
                _REPOSITORY_CUSTODY_BINDING_DOMAIN_V27
                + canonical_bytes(binding_body)
            ):
                raise NativeBoundaryV27Error(
                    "V27 repository custody recovery binding digest changed"
                )
            names = {
                str(binding.get("effectLeaf")),
                *(str(item) for item in binding.get("snapshotLeaves", [])),
            }
            if len(names) != 5 or any(
                re.fullmatch(r"v27-[0-9a-f]{64}", name) is None
                for name in names
            ):
                raise NativeBoundaryV27Error(
                    "V27 repository custody recovery leaf set changed"
                )
            allowed_leaves.update(names)
            for intent_path in sorted(custody.glob("repository-access-*.json")):
                match = re.fullmatch(r"repository-access-([0-9]+)\.json", intent_path.name)
                if match is None:
                    raise NativeBoundaryV27Error(
                        "V27 repository custody access record name changed"
                    )
                _finalize_controller_record_link_prefix_v27(intent_path)
                intent = _read_effect_record(
                    intent_path,
                    key,
                    expected_kind="ControllerRepositoryAccessIntentV1",
                )
                payload = intent["payload"]
                required = {
                    "schemaVersion", "profile", "operationId", "operationClass",
                    "planSha256", "stageLocation", "stageKey", "stagePlan",
                    "stagePlanSha256", "repositoryCustodyBindingSha256",
                    "privateManifestSha256", "grantedManifestSha256",
                    "requestKeyDerivation",
                }
                if set(payload) != required:
                    raise NativeBoundaryV27Error(
                        "V27 repository custody access intent shape changed"
                    )
                stage_plan = validate_native_stage_action_plan_v27(
                    payload["stagePlan"], manifest
                )
                custody_binding = stage_plan["repositoryCustody"]
                assert custody_binding is not None
                private_projection: dict[str, Any] = {
                    "schemaVersion": 27,
                    "entries": [
                        {
                            **item,
                            "mode": (
                                "0700" if item["kind"] == "directory" else "0600"
                            ),
                        }
                        for item in custody_binding["manifest"]["entries"]
                    ],
                }
                private_projection["manifestSha256"] = sha256(
                    _REPOSITORY_CUSTODY_MANIFEST_DOMAIN_V27
                    + canonical_bytes(private_projection)
                )
                derivation = payload["requestKeyDerivation"]
                expected_derivation = {
                    "launchCoreSha256", "operatorGeneration", "configEpoch",
                    "keyEpoch", "operationId", "effectPlanSha256",
                    "stageLocation", "stageKey",
                }
                if (
                    payload["schemaVersion"] != 27
                    or payload["profile"] != PROFILE
                    or payload["operationId"] != operation.name
                    or payload["stageLocation"] != int(match.group(1))
                    or payload["stageLocation"] != stage_plan["stageLocation"]
                    or payload["stageKey"] != stage_plan["stageKey"]
                    or payload["stagePlanSha256"] != stage_plan["stagePlanSha256"]
                    or payload["repositoryCustodyBindingSha256"]
                    != custody_binding["bindingSha256"]
                    or payload["grantedManifestSha256"]
                    != custody_binding["manifestSha256"]
                    or payload["privateManifestSha256"]
                    != private_projection["manifestSha256"]
                    or not isinstance(derivation, Mapping)
                    or set(derivation) != expected_derivation
                    or derivation.get("operationId") != payload["operationId"]
                    or derivation.get("effectPlanSha256") != payload["planSha256"]
                    or derivation.get("stageLocation") != payload["stageLocation"]
                    or derivation.get("stageKey") != payload["stageKey"]
                    or any(
                        type(derivation.get(field)) is not int
                        for field in (
                            "operatorGeneration", "configEpoch", "keyEpoch"
                        )
                    )
                ):
                    raise NativeBoundaryV27Error(
                        "V27 repository custody access intent identity changed"
                    )
                leaf_name = str(custody_binding["leafName"])
                release_path = custody / f"repository-release-{payload['stageLocation']}.json"
                if release_path.exists() or release_path.is_symlink():
                    _finalize_controller_record_link_prefix_v27(release_path)
                    release = _read_effect_record(
                        release_path,
                        key,
                        expected_kind="ControllerRepositoryReleaseReceiptV1",
                    )
                    release_payload = release["payload"]
                    required_release_fields = {
                        "schemaVersion", "profile", "operationId",
                        "planSha256", "stageLocation", "stagePlanSha256",
                        "repositoryCustodyBindingSha256",
                        "postManifestSha256", "revokedManifestSha256",
                    }
                    if (
                        set(release_payload) != required_release_fields
                        or release_payload.get("schemaVersion") != 27
                        or release_payload.get("profile") != PROFILE
                        or release_payload.get("operationId") != payload["operationId"]
                        or release_payload.get("planSha256") != payload["planSha256"]
                        or release_payload.get("stageLocation")
                        != payload["stageLocation"]
                        or release_payload.get("stagePlanSha256")
                        != payload["stagePlanSha256"]
                        or release_payload.get(
                            "repositoryCustodyBindingSha256"
                        ) != payload["repositoryCustodyBindingSha256"]
                        or any(
                            not isinstance(release_payload.get(field), str)
                            or _DIGEST.fullmatch(release_payload[field]) is None
                            for field in (
                                "postManifestSha256", "revokedManifestSha256"
                            )
                        )
                    ):
                        raise NativeBoundaryV27Error(
                            "V27 repository custody release record changed"
                        )
                else:
                    if leaf_name in pending_by_leaf:
                        raise NativeBoundaryV27Error(
                            "V27 repository custody has multiple pending grants"
                        )
                    pending_by_leaf[leaf_name] = (custody, intent)

    observed_leaves: dict[str, int] = {}
    for leaf in sorted(root.iterdir(), key=lambda item: os.fsencode(item.name)):
        metadata = os.lstat(leaf)
        if (
            leaf.name not in allowed_leaves
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != profile["controllerUid"]
            or metadata.st_gid != profile["workerGid"]
        ):
            raise NativeBoundaryV27Error(
                "V27 repository custody recovery found substituted evidence"
            )
        mode = stat.S_IMODE(metadata.st_mode)
        if mode not in {0o700, 0o550, 0o770}:
            raise NativeBoundaryV27Error(
                "V27 repository custody recovery found a widened mode"
            )
        observed_leaves[leaf.name] = mode

    recovered = 0
    normalized = 0
    for leaf_name, mode in observed_leaves.items():
        if mode != 0o700 or leaf_name not in pending_by_leaf:
            continue
        _custody, intent = pending_by_leaf[leaf_name]
        payload = intent["payload"]
        binding = payload["stagePlan"]["repositoryCustody"]
        directory_modes = (
            frozenset({0o700, 0o550})
            if binding["accessMode"] == "read-only"
            else frozenset({0o700, 0o770})
        )
        file_modes = (
            frozenset({0o600, 0o440})
            if binding["accessMode"] == "read-only"
            else frozenset({0o600, 0o660})
        )
        leaf = root / leaf_name
        partial = _repository_custody_manifest_v27(
            leaf,
            controller_uid=int(profile["controllerUid"]),
            worker_gid=int(profile["workerGid"]),
            directory_mode=directory_modes,
            file_mode=file_modes,
        )
        post_path = _custody / f"repository-post-{payload['stageLocation']}.json"
        post_payload: Mapping[str, Any] | None = None
        expected_entries = binding["manifest"]["entries"]
        if post_path.exists() or post_path.is_symlink():
            _finalize_controller_record_link_prefix_v27(post_path)
            post_record = _read_effect_record(
                post_path,
                key,
                expected_kind="ControllerRepositoryPostManifestV1",
            )
            post_payload = post_record["payload"]
            if (
                post_payload.get("operationId") != payload["operationId"]
                or post_payload.get("stageLocation") != payload["stageLocation"]
                or post_payload.get("stagePlanSha256")
                != payload["stagePlanSha256"]
                or post_payload.get("repositoryCustodyBindingSha256")
                != payload["repositoryCustodyBindingSha256"]
                or not isinstance(post_payload.get("postManifest"), Mapping)
                or post_payload.get("postManifestSha256")
                != post_payload["postManifest"].get("manifestSha256")
            ):
                raise NativeBoundaryV27Error(
                    "V27 repository custody post manifest changed"
                )
            expected_entries = post_payload["postManifest"]["entries"]
        expected_private: dict[str, Any] = {
            "schemaVersion": 27,
            "entries": [
                {
                    **entry,
                    "mode": (
                        "0700" if entry["kind"] == "directory" else "0600"
                    ),
                }
                for entry in expected_entries
            ],
        }
        expected_private["manifestSha256"] = sha256(
            _REPOSITORY_CUSTODY_MANIFEST_DOMAIN_V27
            + canonical_bytes(expected_private)
        )
        if [
            {key_name: item for key_name, item in entry.items() if key_name != "mode"}
            for entry in partial["entries"]
        ] != [
            {key_name: item for key_name, item in entry.items() if key_name != "mode"}
            for entry in expected_entries
        ]:
            raise NativeBoundaryV27Error(
                "V27 repository custody partial grant was substituted"
            )
        descriptor = os.open(
            leaf,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            _chmod_repository_custody_fd_v27(
                descriptor,
                directory_mode=0o700,
                file_mode=0o600,
                revoke=True,
                fault_prefix=(
                    f"repository-access-{payload['stageLocation']}-recovery-fence"
                ),
                fault_counter=[0],
            )
        finally:
            os.close(descriptor)
        private = _repository_custody_manifest_v27(
            leaf,
            controller_uid=int(profile["controllerUid"]),
            worker_gid=int(profile["workerGid"]),
            directory_mode=0o700,
            file_mode=0o600,
        )
        if private["manifestSha256"] != expected_private["manifestSha256"]:
            raise NativeBoundaryV27Error(
                "V27 repository custody partial grant did not normalize"
            )
        if post_payload is not None:
            _load_or_publish_controller_record_v27(
                _custody
                / f"repository-release-{payload['stageLocation']}.json",
                key,
                "ControllerRepositoryReleaseReceiptV1",
                {
                    "schemaVersion": 27,
                    "profile": PROFILE,
                    "operationId": payload["operationId"],
                    "planSha256": payload["planSha256"],
                    "stageLocation": payload["stageLocation"],
                    "stagePlanSha256": payload["stagePlanSha256"],
                    "repositoryCustodyBindingSha256": payload[
                        "repositoryCustodyBindingSha256"
                    ],
                    "postManifestSha256": post_payload[
                        "postManifestSha256"
                    ],
                    "revokedManifestSha256": private["manifestSha256"],
                },
                phase=f"repository-access-{payload['stageLocation']}-release",
            )
        normalized += 1
    for leaf_name, mode in observed_leaves.items():
        if mode == 0o700:
            continue
        pending = pending_by_leaf.get(leaf_name)
        if pending is None:
            raise NativeBoundaryV27Error(
                "V27 granted repository custody has no authenticated intent"
            )
        custody, intent = pending
        payload = intent["payload"]
        plan = payload["stagePlan"]
        derivation = payload["requestKeyDerivation"]
        expected_derivation = {
            "launchCoreSha256", "operatorGeneration", "configEpoch", "keyEpoch",
            "operationId", "effectPlanSha256", "stageLocation", "stageKey",
        }
        if not isinstance(derivation, Mapping) or set(derivation) != expected_derivation:
            raise NativeBoundaryV27Error(
                "V27 repository custody request-key derivation changed"
            )
        request_key = hmac.new(
            key,
            b"startup-factory/beads/v27/request-key\0"
            + canonical_bytes(dict(derivation)),
            hashlib.sha256,
        ).digest()
        if sha256(request_key) != plan["requestKeyId"]:
            raise NativeBoundaryV27Error(
                "V27 repository custody request key changed"
            )
        receipt = release_probe(plan, request_key)
        _persist_repository_post_manifest_v27(
            custody=custody,
            key=key,
            plan=plan,
            repository_custody=plan["repositoryCustody"],
            release_receipt=receipt,
        )
        revoked = _revoke_repository_custody_v27(
            plan["repositoryCustody"], receipt, request_key
        )
        _load_or_publish_controller_record_v27(
            custody / f"repository-release-{payload['stageLocation']}.json",
            key,
            "ControllerRepositoryReleaseReceiptV1",
            {
                "schemaVersion": 27,
                "profile": PROFILE,
                "operationId": payload["operationId"],
                "planSha256": payload["planSha256"],
                "stageLocation": payload["stageLocation"],
                "stagePlanSha256": payload["stagePlanSha256"],
                "repositoryCustodyBindingSha256": payload[
                    "repositoryCustodyBindingSha256"
                ],
                "postManifestSha256": receipt[
                    "postRepositoryManifestSha256"
                ],
                "revokedManifestSha256": revoked["manifestSha256"],
            },
            phase=f"repository-access-{payload['stageLocation']}-release",
        )
        recovered += 1
    return {
        "admittedLeaves": len(observed_leaves),
        "normalizedPartialGrants": normalized,
        "recoveredGrants": recovered,
    }


def _ensure_controller_read_snapshot_v27(
    *,
    custody: Path,
    effect: Path,
    snapshots: tuple[Path, ...],
    key: bytes,
    plan: Mapping[str, Any],
    stage_record: Mapping[str, Any],
    ordinal: int,
) -> tuple[dict[str, Any], Path]:
    if type(ordinal) is not int or not 0 <= ordinal <= 3:
        raise NativeBoundaryV27Error("V27 controller snapshot ordinal is invalid")
    if len(snapshots) != 4:
        raise NativeBoundaryV27Error("V27 snapshot custody count changed")
    destination = snapshots[ordinal]
    intent_path = custody / f"reader-{ordinal}-snapshot-materialization-intent.json"
    record_path = custody / f"reader-{ordinal}-snapshot.json"
    source_before = capture_beads_tree_v27(
        effect / ".beads", require_private_modes=True
    )
    intent = _load_or_publish_controller_record_v27(
        intent_path,
        key,
        "ControllerReadSnapshotMaterializationIntentV1",
        {
            "schemaVersion": 27,
            "profile": PROFILE,
            "operationId": plan["operationId"],
            "operationClass": plan["operationClass"],
            "planSha256": plan["planSha256"],
            "repositoryStageRecordSha256": stage_record["recordSha256"],
            "ordinal": ordinal,
            "sourceRepositoryPath": str(effect),
            "snapshotRepositoryPath": str(destination),
            "sourceStageTreeSha256": source_before["treeSha256"],
            "sourceStageContentSha256": source_before["contentSha256"],
            "sourceStageRootIdentitySha256": source_before[
                "rootIdentitySha256"
            ],
        },
        phase=f"controller-reader-{ordinal}-snapshot-materialization-intent",
    )
    if record_path.exists() or record_path.is_symlink():
        _finalize_controller_record_link_prefix_v27(record_path)
        record = _read_effect_record(
            record_path, key, expected_kind="ControllerReadSnapshotV1"
        )
        snap = capture_beads_tree_v27(
            destination / ".beads", require_private_modes=True
        )
        payload = record["payload"]
        if not (
            payload.get("operationId") == plan["operationId"]
            and payload.get("planSha256") == plan["planSha256"]
            and payload.get("repositoryStageRecordSha256")
            == stage_record["recordSha256"]
            and payload.get("materializationIntentRecordSha256")
            == intent["recordSha256"]
            and payload.get("ordinal") == ordinal
            and payload.get("sourceStageTreeSha256")
            == source_before["treeSha256"]
            and payload.get("sourceStageRootIdentitySha256")
            == source_before["rootIdentitySha256"]
            and payload.get("snapshotTreeSha256") == snap["treeSha256"]
            and payload.get("snapshotRootIdentitySha256")
            == snap["rootIdentitySha256"]
        ):
            raise NativeBoundaryV27Error(
                "V27 controller snapshot binding changed"
            )
        return record, destination

    snap = materialize_controller_owned_beads_tree_v27(
        effect / ".beads",
        destination / ".beads",
        source_requires_private_modes=True,
        fault_prefix=f"controller-reader-{ordinal}-snapshot-copy",
    )
    source_after = capture_beads_tree_v27(
        effect / ".beads", require_private_modes=True
    )
    if not _same_captured_tree_v27(source_before, source_after, physical=True):
        raise NativeBoundaryV27Error(
            "controller mutation stage changed while a read snapshot was materialized"
        )
    identity = {
        "operationId": plan["operationId"],
        "ordinal": ordinal,
        "snapshotTreeSha256": snap["treeSha256"],
        "snapshotRootIdentitySha256": snap["rootIdentitySha256"],
    }
    payload = {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "planSha256": plan["planSha256"],
        "repositoryStageRecordSha256": stage_record["recordSha256"],
        "materializationIntentRecordSha256": intent["recordSha256"],
        "ordinal": ordinal,
        "snapshotRepositoryPath": str(destination),
        "sourceStageTreeSha256": source_before["treeSha256"],
        "sourceStageContentSha256": source_before["contentSha256"],
        "sourceStageRootIdentitySha256": source_before["rootIdentitySha256"],
        "snapshotTreeSha256": snap["treeSha256"],
        "snapshotContentSha256": snap["contentSha256"],
        "snapshotRootIdentitySha256": snap["rootIdentitySha256"],
        "snapshotIdentitySha256": sha256(
            b"startup-factory/beads/v27/controller-snapshot-identity\0"
            + canonical_bytes(identity)
        ),
    }
    record = _load_or_publish_controller_record_v27(
        record_path,
        key,
        "ControllerReadSnapshotV1",
        payload,
        phase=f"controller-reader-{ordinal}-snapshot",
    )
    return record, destination


def _reopen_controller_read_snapshot_v27(
    *,
    custody: Path,
    snapshots: tuple[Path, ...],
    key: bytes,
    plan: Mapping[str, Any],
    stage_record: Mapping[str, Any],
    ordinal: int,
) -> tuple[dict[str, Any], Path]:
    if type(ordinal) is not int or not 0 <= ordinal <= 3:
        raise NativeBoundaryV27Error("V27 controller snapshot ordinal is invalid")
    intent = _read_effect_record(
        custody / f"reader-{ordinal}-snapshot-materialization-intent.json",
        key,
        expected_kind="ControllerReadSnapshotMaterializationIntentV1",
    )
    record = _read_effect_record(
        custody / f"reader-{ordinal}-snapshot.json",
        key,
        expected_kind="ControllerReadSnapshotV1",
    )
    if len(snapshots) != 4:
        raise NativeBoundaryV27Error("V27 snapshot custody count changed")
    destination = snapshots[ordinal]
    captured = capture_beads_tree_v27(
        destination / ".beads", require_private_modes=True
    )
    payload = record["payload"]
    if not (
        payload.get("operationId") == plan["operationId"]
        and payload.get("planSha256") == plan["planSha256"]
        and payload.get("repositoryStageRecordSha256")
        == stage_record["recordSha256"]
        and payload.get("materializationIntentRecordSha256")
        == intent["recordSha256"]
        and payload.get("ordinal") == ordinal
        and payload.get("snapshotRepositoryPath") == str(destination)
        and payload.get("snapshotTreeSha256") == captured["treeSha256"]
        and payload.get("snapshotContentSha256") == captured["contentSha256"]
        and payload.get("snapshotRootIdentitySha256")
        == captured["rootIdentitySha256"]
    ):
        raise NativeBoundaryV27Error("V27 controller snapshot was substituted")
    return record, destination


def _capture_optional_beads_tree_v27(
    path: Path, *, require_private_modes: bool
) -> dict[str, Any] | None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode):
        raise NativeBoundaryV27Error("V27 repository publication path is symlinked")
    return capture_beads_tree_v27(
        path, require_private_modes=require_private_modes
    )


def _tree_matches_stage_payload_v27(
    captured: Mapping[str, Any], payload: Mapping[str, Any], prefix: str
) -> bool:
    return (
        captured.get("treeSha256") == payload.get(f"{prefix}TreeSha256")
        and captured.get("contentSha256")
        == payload.get(f"{prefix}ContentSha256")
        and captured.get("rootIdentitySha256")
        == payload.get(f"{prefix}RootIdentitySha256")
    )


def _ensure_repository_publication_candidate_v27(
    *,
    custody: Path,
    effect: Path,
    key: bytes,
    plan: Mapping[str, Any],
    stage_record: Mapping[str, Any],
    publication_prerequisite_sha256: str | None,
) -> dict[str, Any]:
    record_path = custody / "publication-candidate.json"
    stage = capture_beads_tree_v27(
        effect / ".beads", require_private_modes=True
    )
    payload = {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "planSha256": plan["planSha256"],
        "repositoryStageRecordSha256": stage_record["recordSha256"],
        "publicationPrerequisiteSha256": publication_prerequisite_sha256,
        "producerRepositoryPath": stage_record["payload"][
            "producerRepositoryPath"
        ],
        "candidateLeaf": (
            f".startup-factory-beads-candidate-{plan['operationId']}"
        ),
        "previousLeaf": (
            f".startup-factory-beads-previous-{plan['operationId']}"
        ),
        "candidateStageTreeSha256": stage["treeSha256"],
        "candidateStageContentSha256": stage["contentSha256"],
        "candidateStageRootIdentitySha256": stage["rootIdentitySha256"],
    }
    return _load_or_publish_controller_record_v27(
        record_path,
        key,
        "RepositoryPublicationCandidateV1",
        payload,
        phase="repository-publication-candidate",
    )


def _reopen_repository_publication_candidate_v27(
    *,
    custody: Path,
    effect: Path,
    key: bytes,
    plan: Mapping[str, Any],
    stage_record: Mapping[str, Any],
    publication_prerequisite_sha256: str | None,
) -> dict[str, Any]:
    record = _read_effect_record(
        custody / "publication-candidate.json",
        key,
        expected_kind="RepositoryPublicationCandidateV1",
    )
    payload = record["payload"]
    stage = capture_beads_tree_v27(
        effect / ".beads", require_private_modes=True
    )
    if not (
        payload.get("operationId") == plan["operationId"]
        and payload.get("operationClass") == plan["operationClass"]
        and payload.get("planSha256") == plan["planSha256"]
        and payload.get("repositoryStageRecordSha256")
        == stage_record["recordSha256"]
        and payload.get("publicationPrerequisiteSha256")
        == publication_prerequisite_sha256
        and payload.get("producerRepositoryPath")
        == stage_record["payload"].get("producerRepositoryPath")
        and _tree_matches_stage_payload_v27(
            stage, payload, "candidateStage"
        )
    ):
        raise NativeBoundaryV27Error(
            "V27 repository publication candidate binding changed"
        )
    return record


def _repository_prestate_matches_v27(
    captured: Mapping[str, Any], stage_payload: Mapping[str, Any]
) -> bool:
    return (
        captured.get("treeSha256")
        == stage_payload.get("producerPrestateTreeSha256")
        and captured.get("contentSha256")
        == stage_payload.get("producerPrestateContentSha256")
        and captured.get("rootIdentitySha256")
        == stage_payload.get("producerPrestateRootIdentitySha256")
    )


def _reopen_repository_publication_materialization_v27(
    *,
    custody: Path,
    key: bytes,
    plan: Mapping[str, Any],
    candidate_record: Mapping[str, Any],
    captured: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a renamed candidate to the exact controller-created inode tree."""

    path = custody / "publication-materialization.json"
    _finalize_controller_record_link_prefix_v27(path)
    record = _read_effect_record(
        path, key, expected_kind="RepositoryPublicationMaterializationV1"
    )
    payload = record["payload"]
    required = {
        "schemaVersion", "profile", "operationId", "operationClass",
        "planSha256", "candidateRecordSha256", "candidateLeaf",
        "candidateTreeSha256", "candidateContentSha256",
        "candidateRootIdentitySha256",
    }
    if (
        set(payload) != required
        or payload.get("schemaVersion") != 27
        or payload.get("profile") != PROFILE
        or payload.get("operationId") != plan["operationId"]
        or payload.get("operationClass") != plan["operationClass"]
        or payload.get("planSha256") != plan["planSha256"]
        or payload.get("candidateRecordSha256")
        != candidate_record["recordSha256"]
        or payload.get("candidateLeaf")
        != candidate_record["payload"]["candidateLeaf"]
        or not _tree_matches_stage_payload_v27(captured, payload, "candidate")
    ):
        raise NativeBoundaryV27Error(
            "V27 repository publication materialization was substituted"
        )
    return record


def _fsync_directory_v27(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_controller_repository_candidate_v27(
    *,
    custody: Path,
    effect: Path,
    key: bytes,
    plan: Mapping[str, Any],
    stage_record: Mapping[str, Any],
    publication_prerequisite_sha256: str | None,
) -> dict[str, Any]:
    candidate_record = _reopen_repository_publication_candidate_v27(
        custody=custody,
        effect=effect,
        key=key,
        plan=plan,
        stage_record=stage_record,
        publication_prerequisite_sha256=publication_prerequisite_sha256,
    )
    receipt_path = custody / "publication-receipt.json"
    repository = Path(str(stage_record["payload"]["producerRepositoryPath"]))
    _require_repository_path_binding_v27(
        _repository_path_binding_v27(repository), stage_record["payload"]
    )
    candidate_leaf = str(candidate_record["payload"]["candidateLeaf"])
    previous_leaf = str(candidate_record["payload"]["previousLeaf"])
    candidate_path = repository / candidate_leaf
    previous_path = repository / previous_leaf
    source_path = repository / ".beads"

    source = _capture_optional_beads_tree_v27(
        source_path, require_private_modes=False
    )
    previous = _capture_optional_beads_tree_v27(
        previous_path, require_private_modes=False
    )
    materialized = _capture_optional_beads_tree_v27(
        candidate_path, require_private_modes=True
    )
    candidate_payload = candidate_record["payload"]
    source_is_new = source is not None and (
        source["contentSha256"]
        == candidate_payload["candidateStageContentSha256"]
    )
    source_is_old = source is not None and _repository_prestate_matches_v27(
        source, stage_record["payload"]
    )
    previous_is_old = previous is not None and _repository_prestate_matches_v27(
        previous, stage_record["payload"]
    )

    if receipt_path.exists() or receipt_path.is_symlink():
        _finalize_controller_record_link_prefix_v27(receipt_path)
        receipt = _read_effect_record(
            receipt_path, key, expected_kind="RepositoryPublicationReceiptV1"
        )
        payload = receipt["payload"]
        required_receipt = {
            "schemaVersion", "profile", "operationId", "operationClass",
            "planSha256", "repositoryStageRecordSha256",
            "candidateRecordSha256", "publishedTreeSha256",
            "publishedContentSha256", "publishedRootIdentitySha256",
            "retainedPreviousTreeSha256", "retainedPreviousContentSha256",
            "retainedPreviousRootIdentitySha256", "previousLeaf",
        }
        if (
            set(payload) != required_receipt
            or payload.get("schemaVersion") != 27
            or payload.get("profile") != PROFILE
            or payload.get("operationId") != plan["operationId"]
            or payload.get("operationClass") != plan["operationClass"]
            or payload.get("planSha256") != plan["planSha256"]
            or payload.get("repositoryStageRecordSha256")
            != stage_record["recordSha256"]
            or payload.get("candidateRecordSha256")
            != candidate_record["recordSha256"]
            or payload.get("previousLeaf") != previous_leaf
            or source is None
            or previous is None
            or not _tree_matches_stage_payload_v27(source, payload, "published")
            or not _tree_matches_stage_payload_v27(
                previous, payload, "retainedPrevious"
            )
        ):
            raise NativeBoundaryV27Error(
                "V27 repository publication receipt or installed tree changed"
            )
        _reopen_repository_publication_materialization_v27(
            custody=custody,
            key=key,
            plan=plan,
            candidate_record=candidate_record,
            captured=source,
        )
        return receipt

    if source is not None and not source_is_old and not source_is_new:
        raise NativeBoundaryV27Error(
            "repository prestate changed before publication"
        )
    if previous is not None and not previous_is_old:
        raise NativeBoundaryV27Error(
            "V27 repository rollback tree was substituted"
        )
    materialized_is_complete = materialized is not None and (
        materialized["contentSha256"]
        == candidate_payload["candidateStageContentSha256"]
    )
    if materialized is not None and not materialized_is_complete and not (
        source_is_old and previous is None
    ):
        raise NativeBoundaryV27Error(
            "V27 materialized repository candidate changed"
        )

    if source_is_old and previous is None:
        if not materialized_is_complete:
            materialized = materialize_controller_owned_beads_tree_v27(
                effect / ".beads",
                candidate_path,
                source_requires_private_modes=True,
                destination_parent_requires_private_modes=False,
                fault_prefix="repository-publication-candidate-copy",
            )
        materialization_payload = {
            "schemaVersion": 27,
            "profile": PROFILE,
            "operationId": plan["operationId"],
            "operationClass": plan["operationClass"],
            "planSha256": plan["planSha256"],
            "candidateRecordSha256": candidate_record["recordSha256"],
            "candidateLeaf": candidate_leaf,
            "candidateTreeSha256": materialized["treeSha256"],
            "candidateContentSha256": materialized["contentSha256"],
            "candidateRootIdentitySha256": materialized[
                "rootIdentitySha256"
            ],
        }
        _load_or_publish_controller_record_v27(
            custody / "publication-materialization.json",
            key,
            "RepositoryPublicationMaterializationV1",
            materialization_payload,
            phase="repository-publication-materialization",
        )
        repository_fd, ancestry = _open_pinned_repository_v27(repository)
        try:
            _require_repository_path_binding_v27(
                _repository_path_binding_from_ancestry_v27(ancestry),
                stage_record["payload"],
            )
            os.rename(
                ".beads",
                previous_leaf,
                src_dir_fd=repository_fd,
                dst_dir_fd=repository_fd,
            )
            os.fsync(repository_fd)
            _effect_fault("repository-publication-previous-installed")
        finally:
            os.close(repository_fd)
        source = None
        previous = _capture_optional_beads_tree_v27(
            previous_path, require_private_modes=False
        )
        previous_is_old = previous is not None and _repository_prestate_matches_v27(
            previous, stage_record["payload"]
        )

    if source is None and previous_is_old:
        materialized = _capture_optional_beads_tree_v27(
            candidate_path, require_private_modes=True
        )
        if materialized is None or (
            materialized["contentSha256"]
            != candidate_payload["candidateStageContentSha256"]
        ):
            raise NativeBoundaryV27Error(
                "V27 repository publication suffix lost its candidate"
            )
        _reopen_repository_publication_materialization_v27(
            custody=custody,
            key=key,
            plan=plan,
            candidate_record=candidate_record,
            captured=materialized,
        )
        repository_fd, ancestry = _open_pinned_repository_v27(repository)
        try:
            _require_repository_path_binding_v27(
                _repository_path_binding_from_ancestry_v27(ancestry),
                stage_record["payload"],
            )
            os.rename(
                candidate_leaf,
                ".beads",
                src_dir_fd=repository_fd,
                dst_dir_fd=repository_fd,
            )
            os.fsync(repository_fd)
            _effect_fault("repository-publication-candidate-installed")
        finally:
            os.close(repository_fd)

    source = _capture_optional_beads_tree_v27(
        source_path, require_private_modes=True
    )
    previous = _capture_optional_beads_tree_v27(
        previous_path, require_private_modes=False
    )
    if source is None or previous is None or not (
        source["contentSha256"]
        == candidate_payload["candidateStageContentSha256"]
        and _repository_prestate_matches_v27(previous, stage_record["payload"])
    ):
        raise NativeBoundaryV27Error(
            "V27 repository publication did not reach its exact installed suffix"
        )
    _reopen_repository_publication_materialization_v27(
        custody=custody,
        key=key,
        plan=plan,
        candidate_record=candidate_record,
        captured=source,
    )
    receipt_payload = {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "planSha256": plan["planSha256"],
        "repositoryStageRecordSha256": stage_record["recordSha256"],
        "candidateRecordSha256": candidate_record["recordSha256"],
        "publishedTreeSha256": source["treeSha256"],
        "publishedContentSha256": source["contentSha256"],
        "publishedRootIdentitySha256": source["rootIdentitySha256"],
        "retainedPreviousTreeSha256": previous["treeSha256"],
        "retainedPreviousContentSha256": previous["contentSha256"],
        "retainedPreviousRootIdentitySha256": previous["rootIdentitySha256"],
        "previousLeaf": previous_leaf,
    }
    return _load_or_publish_controller_record_v27(
        receipt_path,
        key,
        "RepositoryPublicationReceiptV1",
        receipt_payload,
        phase="repository-publication-receipt",
    )


def _retire_controller_previous_tree_v27(
    *,
    custody: Path,
    retained: Path,
    key: bytes,
    plan: Mapping[str, Any],
    stage_record: Mapping[str, Any],
) -> dict[str, Any]:
    publication = _read_effect_record(
        custody / "publication-receipt.json",
        key,
        expected_kind="RepositoryPublicationReceiptV1",
    )
    publication_payload = publication["payload"]
    repository = Path(str(stage_record["payload"]["producerRepositoryPath"]))
    previous_leaf = str(publication_payload["previousLeaf"])
    previous = repository / previous_leaf
    destination = retained / f"previous-{plan['operationId']}"
    source_capture = _capture_optional_beads_tree_v27(
        previous, require_private_modes=False
    )
    retained_capture = _capture_optional_beads_tree_v27(
        destination, require_private_modes=False
    )
    expected = {
        "treeSha256": publication_payload["retainedPreviousTreeSha256"],
        "contentSha256": publication_payload["retainedPreviousContentSha256"],
        "rootIdentitySha256": publication_payload[
            "retainedPreviousRootIdentitySha256"
        ],
    }
    if source_capture is not None and not _same_captured_tree_v27(
        source_capture, expected, physical=True
    ):
        raise NativeBoundaryV27Error("V27 cleanup source tree changed")
    if retained_capture is not None and not _same_captured_tree_v27(
        retained_capture, expected, physical=True
    ):
        raise NativeBoundaryV27Error("V27 retained cleanup tree changed")
    if source_capture is not None and retained_capture is None:
        repository_fd, ancestry = _open_pinned_repository_v27(repository)
        retained_fd = os.open(
            retained,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            _require_repository_path_binding_v27(
                _repository_path_binding_from_ancestry_v27(ancestry),
                stage_record["payload"],
            )
            source_metadata = os.stat(
                previous_leaf, dir_fd=repository_fd, follow_symlinks=False
            )
            source_identity = {
                "device": source_metadata.st_dev,
                "inode": source_metadata.st_ino,
                "uid": source_metadata.st_uid,
                "gid": source_metadata.st_gid,
                "mode": f"{stat.S_IMODE(source_metadata.st_mode):04o}",
                "linkCount": source_metadata.st_nlink,
            }
            if (
                not stat.S_ISDIR(source_metadata.st_mode)
                or source_identity != source_capture["rootIdentity"]
            ):
                raise NativeBoundaryV27Error(
                    "V27 cleanup source changed before descriptor rename"
                )
            try:
                os.stat(destination.name, dir_fd=retained_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise NativeBoundaryV27Error(
                    "V27 cleanup destination appeared before descriptor rename"
                )
            try:
                os.rename(
                    previous_leaf,
                    destination.name,
                    src_dir_fd=repository_fd,
                    dst_dir_fd=retained_fd,
                )
            except OSError as exc:
                if exc.errno == errno.EXDEV:
                    raise NativeBoundaryV27Error(
                        "V27 cleanup requires producer and custody on one filesystem"
                    ) from exc
                raise
            os.fsync(repository_fd)
            os.fsync(retained_fd)
        finally:
            os.close(retained_fd)
            os.close(repository_fd)
        _effect_fault("controller-cleanup-previous-retired")
        retained_capture = _capture_optional_beads_tree_v27(
            destination, require_private_modes=False
        )
    if source_capture is None and retained_capture is None:
        raise NativeBoundaryV27Error("V27 cleanup lost its retained rollback tree")
    assert retained_capture is not None
    payload = {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "planSha256": plan["planSha256"],
        "repositoryStageRecordSha256": stage_record["recordSha256"],
        "publicationReceiptSha256": publication["recordSha256"],
        "retainedTreeSha256": retained_capture["treeSha256"],
        "retainedContentSha256": retained_capture["contentSha256"],
        "retainedRootIdentitySha256": retained_capture[
            "rootIdentitySha256"
        ],
        "retainedPath": str(destination),
    }
    return _load_or_publish_controller_record_v27(
        custody / "cleanup-retirement.json",
        key,
        "ControllerCleanupRetirementReceiptV1",
        payload,
        phase="controller-cleanup-retirement",
    )


def _write_all_v27(
    descriptor: int,
    value: bytes,
    *,
    writer: Any = os.write,
) -> None:
    """Write an exact bounded buffer, handling EINTR and short writes."""

    if not isinstance(value, bytes) or len(value) > MAX_CANONICAL_BYTES:
        raise NativeBoundaryV27Error("V27 durable write buffer is invalid")
    view = memoryview(value)
    offset = 0
    while offset < len(view):
        try:
            written = writer(descriptor, view[offset:])
        except InterruptedError:
            continue
        except OSError as exc:
            name = errno.errorcode.get(exc.errno, f"errno-{exc.errno}")
            raise NativeBoundaryV27Error(
                f"V27 durable write failed closed ({name})"
            ) from exc
        if type(written) is not int or written <= 0 or written > len(view) - offset:
            raise NativeBoundaryV27Error("V27 durable write made invalid progress")
        offset += written


def _closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeBoundaryV27Error(f"{label} has an unknown or missing field")
    return value


def _digest(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise NativeBoundaryV27Error(f"{label} must be a lowercase SHA-256 digest")
    return value


def _absolute(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise NativeBoundaryV27Error(f"{label} must be a normalized absolute path")
    path = Path(value)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise NativeBoundaryV27Error(f"{label} must be a normalized absolute path")
    return path


@dataclasses.dataclass(frozen=True, slots=True)
class SELinuxRawContextExpectationV1:
    interface: str
    raw_bytes: bytes
    terminator_kind: str
    raw_bytes_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class NativeBoundaryManifestV27:
    launcher_path: Path
    launcher_source_sha256: str
    launcher_sha256: str
    supervisor_path: Path
    supervisor_source_sha256: str
    supervisor_sha256: str
    podman_path: Path
    podman_sha256: str
    conmon_path: Path
    conmon_sha256: str
    oci_runtime_path: Path
    oci_runtime_sha256: str
    oci_runtime_version: str
    oci_runtime_version_output_sha256: str
    selinux_policy_sha256: str
    selinux_contexts: Mapping[str, SELinuxRawContextExpectationV1]
    image_reference: str
    image_digest: str
    systemd_version: str = SYSTEMD_VERSION
    podman_version: str = PODMAN_VERSION
    conmon_version: str = CONMON_VERSION
    oci_runtime_name: str = OCI_RUNTIME_NAME
    oci_runtime_selection_source: str = OCI_RUNTIME_SELECTION_SOURCE
    selinux_mode: str = "enforcing"


_MANIFEST_FIELDS = {
    "schemaVersion",
    "profile",
    "systemdVersion",
    "podmanVersion",
    "conmonVersion",
    "ociRuntimeName",
    "ociRuntimeVersion",
    "ociRuntimeVersionOutputSha256",
    "ociRuntimeSelectionSource",
    "selinuxMode",
    "launcherPath",
    "launcherSourceSha256",
    "launcherSha256",
    "supervisorPath",
    "supervisorSourceSha256",
    "supervisorSha256",
    "podmanPath",
    "podmanSha256",
    "conmonPath",
    "conmonSha256",
    "ociRuntimePath",
    "ociRuntimeSha256",
    "selinuxPolicySha256",
    "selinuxContexts",
    "imageReference",
    "imageDigest",
}
_RAW_CONTEXT_FIELDS = {
    "rawBytesBase64",
    "byteLength",
    "terminatorKind",
    "rawBytesSha256",
}


def _parse_raw_context(
    interface: str, value: Any
) -> SELinuxRawContextExpectationV1:
    data = _closed(value, _RAW_CONTEXT_FIELDS, f"SELinux context {interface}")
    if type(data["byteLength"]) is not int or not 0 <= data["byteLength"] <= 65_535:
        raise NativeBoundaryV27Error(
            f"SELinux context {interface} byteLength is invalid"
        )
    if not isinstance(data["rawBytesBase64"], str):
        raise NativeBoundaryV27Error(
            f"SELinux context {interface} base64 must be a string"
        )
    try:
        raw = base64.b64decode(data["rawBytesBase64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise NativeBoundaryV27Error(
            f"SELinux context {interface} base64 is invalid"
        ) from exc
    if len(raw) != data["byteLength"]:
        raise NativeBoundaryV27Error(
            f"SELinux context {interface} length differs from raw bytes"
        )
    expected_terminator, expected_type = _CONTEXT_INTERFACES[interface]
    if data["terminatorKind"] != expected_terminator:
        raise NativeBoundaryV27Error(
            f"SELinux context {interface} terminator contract changed"
        )
    if expected_terminator == "empty":
        if raw:
            raise NativeBoundaryV27Error(
                f"SELinux context {interface} must be exactly empty"
            )
    elif expected_terminator == "none":
        if not raw or b"\0" in raw:
            raise NativeBoundaryV27Error(
                f"SELinux context {interface} must be nonempty without NUL"
            )
    elif expected_terminator == "one-trailing-nul":
        if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
            raise NativeBoundaryV27Error(
                f"SELinux context {interface} requires exactly one trailing NUL"
            )
    content = raw[:-1] if raw.endswith(b"\0") else raw
    if expected_type is not None:
        try:
            text = content.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise NativeBoundaryV27Error(
                f"SELinux context {interface} is not strict UTF-8"
            ) from exc
        parts = text.split(":", 3)
        if len(parts) != 4 or parts[2] != expected_type or not all(parts):
            raise NativeBoundaryV27Error(
                f"SELinux context {interface} is not the complete registered user:role:type:range"
            )
    expected_digest = _digest(
        data["rawBytesSha256"], f"SELinux context {interface} digest"
    )
    if expected_digest != sha256(raw):
        raise NativeBoundaryV27Error(
            f"SELinux context {interface} digest differs from raw bytes"
        )
    assert expected_digest is not None
    return SELinuxRawContextExpectationV1(
        interface=interface,
        raw_bytes=raw,
        terminator_kind=expected_terminator,
        raw_bytes_sha256=expected_digest,
    )


def parse_native_boundary_manifest_v27(value: Any) -> NativeBoundaryManifestV27:
    data = _closed(value, _MANIFEST_FIELDS, "native-boundary manifest")
    if type(data["schemaVersion"]) is not int or data["schemaVersion"] != 27:
        raise NativeBoundaryV27Error("native-boundary schemaVersion must be 27")
    exact_scalars = {
        "profile": PROFILE,
        "systemdVersion": SYSTEMD_VERSION,
        "podmanVersion": PODMAN_VERSION,
        "conmonVersion": CONMON_VERSION,
        "ociRuntimeName": OCI_RUNTIME_NAME,
        "ociRuntimeSelectionSource": OCI_RUNTIME_SELECTION_SOURCE,
        "selinuxMode": "enforcing",
    }
    for field, expected in exact_scalars.items():
        if type(data[field]) is not str or data[field] != expected:
            raise NativeBoundaryV27Error(
                f"native-boundary {field} differs from the closed profile"
            )
    if (
        type(data["ociRuntimeVersion"]) is not str
        or re.fullmatch(
            r"crun version (?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
            data["ociRuntimeVersion"],
        )
        is None
    ):
        raise NativeBoundaryV27Error(
            "native-boundary ociRuntimeVersion is not an exact crun release"
        )
    contexts = data["selinuxContexts"]
    if not isinstance(contexts, dict) or set(contexts) != set(_CONTEXT_INTERFACES):
        raise NativeBoundaryV27Error(
            "native-boundary manifest must contain the exact four SELinux interfaces"
        )
    parsed_contexts = MappingProxyType(
        {
            interface: _parse_raw_context(interface, contexts[interface])
            for interface in sorted(contexts)
        }
    )
    paths = (
        _absolute(data["launcherPath"], "launcherPath"),
        _absolute(data["supervisorPath"], "supervisorPath"),
        _absolute(data["podmanPath"], "podmanPath"),
        _absolute(data["conmonPath"], "conmonPath"),
        _absolute(data["ociRuntimePath"], "ociRuntimePath"),
    )
    if len(set(paths)) != 5 or paths[4] != Path("/usr/bin/crun"):
        raise NativeBoundaryV27Error(
            "launcher, supervisor, Podman, conmon and the fixed crun path must be distinct"
        )
    image_digest = str(_digest(data["imageDigest"], "imageDigest"))
    if (
        not isinstance(data["imageReference"], str)
        or data["imageReference"]
        != f"localhost/startup-factory/beads-v27@{image_digest}"
    ):
        raise NativeBoundaryV27Error(
            "native-boundary imageReference must bind the exact local image digest"
        )
    return NativeBoundaryManifestV27(
        launcher_path=paths[0],
        launcher_source_sha256=str(
            _digest(data["launcherSourceSha256"], "launcherSourceSha256")
        ),
        launcher_sha256=str(_digest(data["launcherSha256"], "launcherSha256")),
        supervisor_path=paths[1],
        supervisor_source_sha256=str(
            _digest(data["supervisorSourceSha256"], "supervisorSourceSha256")
        ),
        supervisor_sha256=str(_digest(data["supervisorSha256"], "supervisorSha256")),
        podman_path=paths[2],
        podman_sha256=str(_digest(data["podmanSha256"], "podmanSha256")),
        conmon_path=paths[3],
        conmon_sha256=str(_digest(data["conmonSha256"], "conmonSha256")),
        oci_runtime_path=paths[4],
        oci_runtime_sha256=str(
            _digest(data["ociRuntimeSha256"], "ociRuntimeSha256")
        ),
        oci_runtime_version=data["ociRuntimeVersion"],
        oci_runtime_version_output_sha256=str(
            _digest(
                data["ociRuntimeVersionOutputSha256"],
                "ociRuntimeVersionOutputSha256",
            )
        ),
        selinux_policy_sha256=str(
            _digest(data["selinuxPolicySha256"], "selinuxPolicySha256")
        ),
        selinux_contexts=parsed_contexts,
        image_reference=data["imageReference"],
        image_digest=image_digest,
    )


def verify_selinux_raw_context_v27(
    interface: str, observed: bytes, manifest: NativeBoundaryManifestV27
) -> None:
    if interface not in manifest.selinux_contexts:
        raise NativeBoundaryV27Error("unknown SELinux interface")
    expectation = manifest.selinux_contexts[interface]
    if not isinstance(observed, bytes) or observed != expectation.raw_bytes:
        raise NativeBoundaryV27Error(
            f"SELinux interface {interface} raw bytes differ from the manifest"
        )
    if sha256(observed) != expectation.raw_bytes_sha256:
        raise NativeBoundaryV27Error(
            f"SELinux interface {interface} raw digest changed"
        )


@dataclasses.dataclass(frozen=True, slots=True)
class LaunchPlanV27:
    controller_source_fd: int
    child_source_fd: int
    child_socket_fd: int
    child_close_range_starts_at: int
    parent_closes_child_source_before_release: bool
    retained_through_create: tuple[int, ...]
    fixed_fd_roles: Mapping[int, str]


_FD_ROLES: Final = MappingProxyType(
    {
        0: "null",
        1: "stdout",
        2: "stderr",
        3: "sealed-plan",
        4: "sealed-request-key",
        5: "supervisor-shared-ofd",
        6: "child-seqpacket",
        7: "controller-pidfd",
        8: "supervisor-cgroup",
        9: "repository-cgroup",
        10: "result-state-directory",
        11: "launcher-tid-stat",
        12: "evidence-ledger",
        13: "supervisor-executable",
    }
)
_LAUNCH_PLAN_FIELDS = {
    "controllerSourceFd",
    "childSourceFd",
    "childSocketFd",
    "childCloseRangeStartsAt",
    "parentClosesChildSourceBeforeRelease",
    "retainedThroughCreate",
    "fixedFdRoles",
}


def reference_launch_plan_v27() -> dict[str, Any]:
    return {
        "controllerSourceFd": 70,
        "childSourceFd": 71,
        "childSocketFd": 6,
        "childCloseRangeStartsAt": 14,
        "parentClosesChildSourceBeforeRelease": True,
        "retainedThroughCreate": [7, 11],
        "fixedFdRoles": {str(number): role for number, role in _FD_ROLES.items()},
    }


def validate_launch_plan_v27(value: Any) -> LaunchPlanV27:
    data = _closed(value, _LAUNCH_PLAN_FIELDS, "V27 launch plan")
    expected = reference_launch_plan_v27()
    if data != expected:
        raise NativeBoundaryV27Error(
            "V27 launch plan differs from the fixed FD/socket custody contract"
        )
    return LaunchPlanV27(
        controller_source_fd=70,
        child_source_fd=71,
        child_socket_fd=6,
        child_close_range_starts_at=14,
        parent_closes_child_source_before_release=True,
        retained_through_create=(7, 11),
        fixed_fd_roles=_FD_ROLES,
    )


def verify_sealed_key_material_v27(
    descriptor: int, *, expected_sha256: str, seals_verified: bool
) -> None:
    expected = _digest(expected_sha256, "sealed request-key digest")
    if type(descriptor) is not int or descriptor < 0 or seals_verified is not True:
        raise NativeBoundaryV27Error(
            "FD4 requires a valid descriptor and the exact four memfd seals"
        )
    try:
        offset_before = os.lseek(descriptor, 0, os.SEEK_CUR)
        material = bytearray(os.pread(descriptor, 32, 0))
        eof = os.pread(descriptor, 1, 32)
        offset_after = os.lseek(descriptor, 0, os.SEEK_CUR)
    except OSError as exc:
        raise NativeBoundaryV27Error(f"FD4 sealed pread failed: {exc}") from exc
    try:
        if (
            len(material) != 32
            or eof != b""
            or offset_before != 0
            or offset_after != 0
            or sha256(bytes(material)) != expected
        ):
            raise NativeBoundaryV27Error(
                "FD4 key bytes, EOF, offset or commitment differ from the fixed contract"
            )
    finally:
        for index in range(len(material)):
            material[index] = 0


def verify_live_sealed_key_material_v27(
    descriptor: int, *, expected_sha256: str
) -> None:
    """Linux-only FD4 gate that observes the exact memfd seals and identity."""

    if not sys.platform.startswith("linux") or not hasattr(fcntl, "F_GET_SEALS"):
        raise NativeBoundaryV27Error("live V27 sealed-key proof requires Linux memfd seals")
    try:
        metadata = os.fstat(descriptor)
        observed_seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as exc:
        raise NativeBoundaryV27Error(f"live FD4 identity/seal observation failed: {exc}") from exc
    expected_seals = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != 32
        or observed_seals != expected_seals
    ):
        raise NativeBoundaryV27Error(
            "live FD4 must be one exact length-32 regular memfd with all four seals"
        )
    verify_sealed_key_material_v27(
        descriptor, expected_sha256=expected_sha256, seals_verified=True
    )


_SEQUENCE_TOKEN = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9._:-]{15,255}\Z")


class OneUseSequenceV27:
    """Deterministic fixture for the no-skip, one-use stage admission rule."""

    __slots__ = ("_consumed",)

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def consume(self, token: str, operation_class: str, current_location: int) -> int:
        if not isinstance(token, str) or not _SEQUENCE_TOKEN.fullmatch(token):
            raise NativeBoundaryV27Error("V27 sequence token is invalid")
        if token in self._consumed:
            raise NativeBoundaryV27Error("V27 sequence token was already consumed")
        done = DONE_LOCATIONS_V27.get(operation_class)
        if (
            done is None
            or type(current_location) is not int
            or not 0 <= current_location < done
        ):
            raise NativeBoundaryV27Error(
                "V27 sequence cannot skip, cross, or advance a Done current"
            )
        self._consumed.add(token)
        return current_location + 1


_RECOVERY_SUFFIX_FIELDS = {
    "operationClass",
    "targetLocation",
    "suffixKind",
    "objectPair",
    "candidateCurrentPair",
    "parentFsyncPair",
    "receiptPair",
    "suffixIntentSha256",
}


def reference_recovery_suffix_v27(
    operation_class: str, target_location: int, suffix_kind: str
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "operationClass": operation_class,
        "targetLocation": target_location,
        "suffixKind": suffix_kind,
        "objectPair": digest_pair("already-durable-object"),
        "candidateCurrentPair": None,
        "parentFsyncPair": None,
        "receiptPair": None,
        "suffixIntentSha256": None,
    }
    if suffix_kind in {
        "cas-return-before-parent-fsync",
        "parent-fsync-before-receipt",
    }:
        value["candidateCurrentPair"] = digest_pair("installed-candidate")
    if suffix_kind == "parent-fsync-before-receipt":
        value["parentFsyncPair"] = digest_pair("parent-fsync")
    value["suffixIntentSha256"] = sha256(
        canonical_bytes({key: item for key, item in value.items() if key != "suffixIntentSha256"})
    )
    return value


def validate_recovery_suffix_v27(value: Any) -> dict[str, Any]:
    data = _closed(value, _RECOVERY_SUFFIX_FIELDS, "V27 recovery suffix")
    operation_class = data["operationClass"]
    target = data["targetLocation"]
    if (
        type(operation_class) is not str
        or operation_class not in INCOMPLETE_TAILS_V27
        or type(target) is not int
        or target not in INCOMPLETE_TAILS_V27[operation_class]
    ):
        raise NativeBoundaryV27Error(
            "V27 recovery suffix is outside the exact incomplete publication tail"
        )
    kind = data["suffixKind"]
    shapes = {
        "object-before-current": (True, False, False, False),
        "cas-return-before-parent-fsync": (True, True, False, False),
        "parent-fsync-before-receipt": (True, True, True, False),
    }
    if type(kind) is not str or kind not in shapes:
        raise NativeBoundaryV27Error("V27 recovery suffix kind is invalid")
    for field, required in zip(
        ("objectPair", "candidateCurrentPair", "parentFsyncPair", "receiptPair"),
        shapes[kind],
    ):
        _pair(data[field], field, required=required)
    expected = sha256(
        canonical_bytes(
            {key: item for key, item in data.items() if key != "suffixIntentSha256"}
        )
    )
    if data["suffixIntentSha256"] != expected:
        raise NativeBoundaryV27Error(
            "V27 recovery suffix changed after its exact durable intent binding"
        )
    return dict(data)


_PACKET_OBSERVATION_FIELDS = {
    "packetLength",
    "msgTrunc",
    "msgCtrunc",
    "zeroLengthRecord",
    "credentialsCount",
    "rightsCount",
    "extraQueuedRecord",
    "peerEof",
}


def validate_seqpacket_observation_v27(
    value: Any, *, expected_length: int
) -> dict[str, Any]:
    data = _closed(value, _PACKET_OBSERVATION_FIELDS, "V27 seqpacket observation")
    if type(expected_length) is not int or not 1 <= expected_length <= MAX_CANONICAL_BYTES:
        raise NativeBoundaryV27Error("V27 expected packet length is invalid")
    expected = {
        "packetLength": expected_length,
        "msgTrunc": False,
        "msgCtrunc": False,
        "zeroLengthRecord": False,
        "credentialsCount": 1,
        "rightsCount": 0,
        "extraQueuedRecord": False,
        "peerEof": False,
    }
    if any(type(data[field]) is not type(item) or data[field] != item for field, item in expected.items()):
        raise NativeBoundaryV27Error(
            "V27 seqpacket record length/flags/credentials/rights/queue/EOF is unsafe"
        )
    return dict(data)


_CREATOR_GATE_FIELDS = {
    "controllerPidfdReadable",
    "launcherTidIdentityMatches",
    "controllerIdentityMatches",
    "childSocketPeek",
    "fd7Open",
    "fd11Open",
    "supervisorCgroupFd",
    "repositoryCgroupFd",
    "pthreadCreateAdjacent",
    "runAuthorizationUseCount",
    "podmanSocketMounted",
    "sudoAvailableToWorker",
    "agentRunsAsRoot",
}


def reference_creator_gate_observation_v27() -> dict[str, Any]:
    return {
        "controllerPidfdReadable": False,
        "launcherTidIdentityMatches": True,
        "controllerIdentityMatches": True,
        "childSocketPeek": "eagain",
        "fd7Open": True,
        "fd11Open": True,
        "supervisorCgroupFd": 8,
        "repositoryCgroupFd": 9,
        "pthreadCreateAdjacent": True,
        "runAuthorizationUseCount": 1,
        "podmanSocketMounted": False,
        "sudoAvailableToWorker": False,
        "agentRunsAsRoot": False,
    }


def validate_creator_gate_observation_v27(value: Any) -> dict[str, Any]:
    data = _closed(value, _CREATOR_GATE_FIELDS, "V27 creator gate observation")
    expected = reference_creator_gate_observation_v27()
    if any(type(data[field]) is not type(item) or data[field] != item for field, item in expected.items()):
        raise NativeBoundaryV27Error(
            "V27 creator gate lost one-use FD/socket/cgroup or least-authority custody"
        )
    return dict(data)


_RESULT_KINDS: Final = {
    "success": "creator-lifetime-closed-positive",
    "precreate-failed": "supervisor-precreate-failed",
    "create-failed-no-thread": "supervisor-create-failed-no-thread",
    "controlled-abort-failed": "creator-abort-failure-lifetime",
    "revoke-verified-no-effect": "creator-lifetime-closed-revoke-verified-no-effect",
}
_ZERO_PLACEMENT_RESULT_KINDS_V27: Final = frozenset(
    {
        "precreate-failed",
        "create-failed-no-thread",
        "controlled-abort-failed",
        "revoke-verified-no-effect",
    }
)


def _placement_mask_matches_result_v27(mask: Any, result_kind: Any) -> bool:
    """Bind the terminal placement mask to one authenticated V4 result kind."""

    if type(mask) is not int or result_kind not in _RESULT_KINDS:
        return False
    if result_kind == "success":
        return mask == 63
    # V4 failure envelopes are a known-no-lifecycle-child terminal outcome.
    # Partial masks belong exclusively to loss/unresolved recovery evidence;
    # admitting one here would let uncertainty masquerade as a failure result.
    return mask == 0


def validate_result_envelope_v4(value: Any) -> dict[str, Any]:
    data = _closed(
        value,
        {"resultKind", "predecessorKind", "failureEvidenceSha256"},
        "SupervisorResultEnvelopeV4",
    )
    kind = data["resultKind"]
    if type(kind) is not str or kind not in _RESULT_KINDS:
        raise NativeBoundaryV27Error("SupervisorResultEnvelopeV4 resultKind is invalid")
    if data["predecessorKind"] != _RESULT_KINDS[kind]:
        raise NativeBoundaryV27Error(
            "SupervisorResultEnvelopeV4 predecessor does not match resultKind"
        )
    evidence = data["failureEvidenceSha256"]
    if kind == "success":
        if evidence is not None:
            raise NativeBoundaryV27Error("success envelope cannot carry failure evidence")
    else:
        _digest(evidence, "failureEvidenceSha256")
    return dict(data)


def validate_supervisor_terminal_current_v3(value: Any) -> dict[str, Any]:
    data = _closed(
        value,
        {
            "terminalBranch",
            "resultEnvelopeSha256",
            "launchPreEffectFailedSha256",
        },
        "SupervisorTerminalCurrentV3",
    )
    branch = data["terminalBranch"]
    if branch == "result-handoff-terminal":
        _digest(data["resultEnvelopeSha256"], "resultEnvelopeSha256")
        if data["launchPreEffectFailedSha256"] is not None:
            raise NativeBoundaryV27Error("terminal result branch violates its XOR")
    elif branch == "launch-pre-effect-never-created":
        _digest(
            data["launchPreEffectFailedSha256"],
            "launchPreEffectFailedSha256",
        )
        if data["resultEnvelopeSha256"] is not None:
            raise NativeBoundaryV27Error("terminal pre-effect branch violates its XOR")
    else:
        raise NativeBoundaryV27Error("SupervisorTerminalCurrentV3 branch is invalid")
    return dict(data)


def digest_pair(label: str) -> dict[str, str]:
    return {
        "recordSha256": sha256((label + ":record").encode()),
        "fullBytesSha256": sha256((label + ":full").encode()),
    }


_PRIOR_FIELDS = {
    "kind",
    "attemptLocatorPair",
    "attemptGeneration",
    "operationCurrentLocator",
    "callIntentPair",
    "durablePrefixKind",
    "callConsumedCurrentPair",
    "callResultPair",
    "callResultKind",
    "acquisitionPair",
    "dispositionState",
    "dispositionPair",
    "releasePair",
    "closeReceiptPair",
    "closedCurrentPair",
    "holderAbsencePair",
    "oldAttemptInertReceiptPair",
}


def _pair(value: Any, label: str, *, required: bool) -> None:
    if value is None:
        if required:
            raise NativeBoundaryV27Error(f"{label} is required")
        return
    if not required:
        raise NativeBoundaryV27Error(f"{label} is forbidden")
    data = _closed(value, {"recordSha256", "fullBytesSha256"}, label)
    _digest(data["recordSha256"], f"{label}.recordSha256")
    _digest(data["fullBytesSha256"], f"{label}.fullBytesSha256")


def reference_prior_recovery_attempt_result_v3(
    kind: str,
    prefix: str,
    *,
    disposition_state: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {field: None for field in _PRIOR_FIELDS}
    value.update(
        {
            "kind": kind,
            "attemptLocatorPair": digest_pair("attempt-locator"),
            "attemptGeneration": 7,
            "operationCurrentLocator": "operation-current-v27.json",
            "callIntentPair": digest_pair("call-intent"),
            "durablePrefixKind": prefix,
        }
    )
    if kind == "acquired-holder-lost":
        state = disposition_state
        if state is None:
            state = "reached" if prefix == "disposition-receipt" else "not-reached"
        value.update(
            {
                "callConsumedCurrentPair": digest_pair("call-consumed"),
                "callResultPair": digest_pair("call-result-acquired-zero"),
                "callResultKind": "acquired-zero",
                "acquisitionPair": digest_pair("acquisition"),
                "dispositionState": state,
                "dispositionPair": (
                    digest_pair("disposition") if state == "reached" else None
                ),
                "releasePair": (
                    digest_pair("release")
                    if prefix
                    in {"release-durable-close-unreceipted", "close-receipt"}
                    else None
                ),
                "closeReceiptPair": (
                    digest_pair("close") if prefix == "close-receipt" else None
                ),
                "holderAbsencePair": digest_pair("holder-absence"),
                "oldAttemptInertReceiptPair": digest_pair("inert"),
            }
        )
    else:
        nonacquired = kind in {
            "nonacquired-clean-closed",
            "lost-after-nonacquired-result",
        }
        acquired = kind in {
            "acquired-clean-closed",
            "lost-after-acquired-result-before-acquisition",
        }
        if prefix != "intent-current-no-call-consume":
            value["callConsumedCurrentPair"] = digest_pair("call-consumed")
        if nonacquired or acquired:
            value["callResultPair"] = digest_pair("call-result")
            value["callResultKind"] = (
                "contended-eagain" if nonacquired else "acquired-zero"
            )
        if kind == "nonacquired-clean-closed":
            value["closeReceiptPair"] = digest_pair("close")
            value["closedCurrentPair"] = digest_pair("closed")
        elif kind == "acquired-clean-closed":
            value["acquisitionPair"] = digest_pair("acquisition")
            if prefix == "acquired-closed-after-disposition":
                value["dispositionPair"] = digest_pair("disposition")
            value["releasePair"] = digest_pair("release")
            value["closeReceiptPair"] = digest_pair("close")
            value["closedCurrentPair"] = digest_pair("closed")
        elif kind.startswith("lost-"):
            value["holderAbsencePair"] = digest_pair("holder-absence")
            value["oldAttemptInertReceiptPair"] = digest_pair("inert")
            if prefix == "nonacquired-close-receipt":
                value["closeReceiptPair"] = digest_pair("close")
    return value


def validate_prior_recovery_attempt_result_v3(value: Any) -> dict[str, Any]:
    data = _closed(value, _PRIOR_FIELDS, "PriorRecoveryAttemptResultV3")
    for field in ("attemptLocatorPair", "callIntentPair"):
        _pair(data[field], field, required=True)
    if (
        type(data["attemptGeneration"]) is not int
        or not 1 <= data["attemptGeneration"] <= 99_999_999_999_999_999_999
    ):
        raise NativeBoundaryV27Error(
            "PriorRecoveryAttemptResultV3 attemptGeneration is invalid"
        )
    locator = data["operationCurrentLocator"]
    if (
        not isinstance(locator, str)
        or not locator
        or locator in {".", ".."}
        or "/" in locator
        or "\0" in locator
    ):
        raise NativeBoundaryV27Error(
            "PriorRecoveryAttemptResultV3 operationCurrentLocator is invalid"
        )
    kind = data["kind"]
    prefixes = {
        "nonacquired-clean-closed": {"nonacquired-closed-current"},
        "acquired-clean-closed": {
            "acquired-closed-before-disposition",
            "acquired-closed-after-disposition",
        },
        "lost-before-call-result": {
            "intent-current-no-call-consume",
            "call-consumed-no-result",
        },
        "lost-after-nonacquired-result": {
            "nonacquired-result-close-unreceipted",
            "nonacquired-close-receipt",
        },
        "lost-after-acquired-result-before-acquisition": {
            "acquired-result-no-acquisition-receipt"
        },
        "acquired-holder-lost": {
            "acquisition-receipt",
            "disposition-receipt",
            "release-durable-close-unreceipted",
            "close-receipt",
        },
    }
    if type(kind) is not str or kind not in prefixes:
        raise NativeBoundaryV27Error("PriorRecoveryAttemptResultV3 kind is invalid")
    prefix = data["durablePrefixKind"]
    if type(prefix) is not str or prefix not in prefixes[kind]:
        raise NativeBoundaryV27Error(
            "PriorRecoveryAttemptResultV3 durable prefix is invalid"
        )
    if kind != "acquired-holder-lost":
        if data["dispositionState"] is not None:
            raise NativeBoundaryV27Error(
                "dispositionState is reserved for acquired-holder-lost"
            )
        # The complete non-holder-lost matrix is closed in the fixture schema;
        # no loose pair can be smuggled through this compact validator.
        allowed_pairs: dict[str, set[str]] = {
            "nonacquired-clean-closed": {
                "callConsumedCurrentPair",
                "callResultPair",
                "closeReceiptPair",
                "closedCurrentPair",
            },
            "acquired-clean-closed": {
                "callConsumedCurrentPair",
                "callResultPair",
                "acquisitionPair",
                "releasePair",
                "closeReceiptPair",
                "closedCurrentPair",
            }
            | (
                {"dispositionPair"}
                if prefix == "acquired-closed-after-disposition"
                else set()
            ),
            "lost-before-call-result": {
                "callConsumedCurrentPair"
                if prefix == "call-consumed-no-result"
                else ""
            }
            | {"holderAbsencePair", "oldAttemptInertReceiptPair"},
            "lost-after-nonacquired-result": {
                "callConsumedCurrentPair",
                "callResultPair",
                "holderAbsencePair",
                "oldAttemptInertReceiptPair",
            }
            | ({"closeReceiptPair"} if prefix == "nonacquired-close-receipt" else set()),
            "lost-after-acquired-result-before-acquisition": {
                "callConsumedCurrentPair",
                "callResultPair",
                "holderAbsencePair",
                "oldAttemptInertReceiptPair",
            },
        }[kind]
        allowed_pairs.discard("")
        expected_result_kind: set[str] | None
        if kind in {"nonacquired-clean-closed", "lost-after-nonacquired-result"}:
            expected_result_kind = {
                "contended-eagain",
                "contended-eacces",
                "interrupted-eintr",
                "failed-other-errno",
            }
        elif kind in {
            "acquired-clean-closed",
            "lost-after-acquired-result-before-acquisition",
        }:
            expected_result_kind = {"acquired-zero"}
        else:
            expected_result_kind = None
        if expected_result_kind is None:
            if data["callResultKind"] is not None:
                raise NativeBoundaryV27Error(
                    "callResultKind is forbidden without a durable call result"
                )
        elif data["callResultKind"] not in expected_result_kind:
            raise NativeBoundaryV27Error(
                "callResultKind differs from the recovery-result branch"
            )
        common = {
            "attemptLocatorPair",
            "callIntentPair",
        }
        for field in _PRIOR_FIELDS - {
            "kind",
            "attemptGeneration",
            "operationCurrentLocator",
            "durablePrefixKind",
            "dispositionState",
            "callResultKind",
        }:
            if field in common:
                continue
            _pair(data[field], field, required=field in allowed_pairs)
        return dict(data)

    state = data["dispositionState"]
    if data["callResultKind"] != "acquired-zero":
        raise NativeBoundaryV27Error(
            "acquired-holder-lost requires acquired-zero callResultKind"
        )
    if state not in {"not-reached", "reached"}:
        raise NativeBoundaryV27Error(
            "acquired-holder-lost dispositionState is invalid"
        )
    if prefix == "acquisition-receipt" and state != "not-reached":
        raise NativeBoundaryV27Error(
            "acquisition-receipt accepts only disposition not-reached"
        )
    if prefix == "disposition-receipt" and state != "reached":
        raise NativeBoundaryV27Error(
            "disposition-receipt accepts only disposition reached"
        )
    required = {
        "callConsumedCurrentPair",
        "callResultPair",
        "acquisitionPair",
        "holderAbsencePair",
        "oldAttemptInertReceiptPair",
    }
    if state == "reached":
        required.add("dispositionPair")
    if prefix in {"release-durable-close-unreceipted", "close-receipt"}:
        required.add("releasePair")
    if prefix == "close-receipt":
        required.add("closeReceiptPair")
    for field in _PRIOR_FIELDS - {
        "kind",
        "attemptGeneration",
        "operationCurrentLocator",
        "durablePrefixKind",
        "dispositionState",
        "callResultKind",
        "attemptLocatorPair",
        "callIntentPair",
    }:
        _pair(data[field], field, required=field in required)
    return dict(data)


def operation_lock_contract_v27() -> dict[str, Any]:
    return {
        "openFlags": ["O_RDWR", "O_CLOEXEC", "O_NOFOLLOW"],
        "lockCommand": "F_OFD_SETLK",
        "l_type": "F_WRLCK",
        "l_whence": "SEEK_SET",
        "l_start": 0,
        "l_len": 0,
        "l_pid": 0,
    }


def try_operation_lock_v27(descriptor: int) -> tuple[str, int]:
    """Issue the sole nonblocking whole-file OFD write-lock call on Linux."""

    if not sys.platform.startswith("linux") or not hasattr(fcntl, "F_OFD_SETLK"):
        raise NativeBoundaryV27Error("V27 OperationLock requires Linux OFD locks")
    if type(descriptor) is not int or descriptor < 0:
        raise NativeBoundaryV27Error("V27 OperationLock descriptor is invalid")
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    if flags & os.O_ACCMODE != os.O_RDWR:
        raise NativeBoundaryV27Error("V27 OperationLock must be opened O_RDWR")
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise NativeBoundaryV27Error("V27 OperationLock must be a regular file")
    # Linux native struct flock for the supported 64-bit profile: two shorts,
    # 4-byte alignment, two off_t values, pid_t and tail padding.  The buffer is
    # zero-initialized before the six approved fields are assigned.
    layout = bytearray(struct.calcsize("hh4xqqi4x"))
    struct.pack_into(
        "hh4xqqi4x",
        layout,
        0,
        fcntl.F_WRLCK,
        os.SEEK_SET,
        0,
        0,
        0,
    )
    try:
        fcntl.fcntl(descriptor, fcntl.F_OFD_SETLK, bytes(layout))
    except OSError as exc:
        captured = int(exc.errno or 0)
        if captured in {errno.EAGAIN, errno.EACCES}:
            return "contended", captured
        if captured == errno.EINTR:
            return "interrupted", captured
        return "failed", captured
    return "acquired", 0


_PLATFORM_FIELDS = {
    "platform",
    "systemdVersion",
    "podmanVersion",
    "podmanRootless",
    "conmonVersion",
    "ociRuntimeName",
    "ociRuntimeVersion",
    "ociRuntimeVersionOutputSha256",
    "ociRuntimeSelectionSource",
    "selinuxMode",
    "supervisorSha256",
    "podmanSha256",
    "conmonSha256",
    "ociRuntimeSha256",
    "selinuxPolicySha256",
    "podmanSocketMounted",
    "sudoAvailableToWorker",
    "agentRunsAsRoot",
}


def validate_platform_observation_v27(
    value: Any, manifest: NativeBoundaryManifestV27
) -> dict[str, Any]:
    data = _closed(value, _PLATFORM_FIELDS, "V27 platform observation")
    expected = {
        "platform": "linux",
        "systemdVersion": manifest.systemd_version,
        "podmanVersion": manifest.podman_version,
        "podmanRootless": True,
        "conmonVersion": manifest.conmon_version,
        "ociRuntimeName": manifest.oci_runtime_name,
        "ociRuntimeVersion": manifest.oci_runtime_version,
        "ociRuntimeVersionOutputSha256": manifest.oci_runtime_version_output_sha256,
        "ociRuntimeSelectionSource": manifest.oci_runtime_selection_source,
        "selinuxMode": manifest.selinux_mode,
        "supervisorSha256": manifest.supervisor_sha256,
        "podmanSha256": manifest.podman_sha256,
        "conmonSha256": manifest.conmon_sha256,
        "ociRuntimeSha256": manifest.oci_runtime_sha256,
        "selinuxPolicySha256": manifest.selinux_policy_sha256,
        "podmanSocketMounted": False,
        "sudoAvailableToWorker": False,
        "agentRunsAsRoot": False,
    }
    for field, expected_value in expected.items():
        if type(data[field]) is not type(expected_value) or data[field] != expected_value:
            raise NativeBoundaryV27Error(
                f"V27 platform observation {field} differs from the closed profile"
            )
    return dict(data)


_SUPERVISOR_PROBE_FIELDS = {
    "platformObservation",
    "rawSELinuxContexts",
    "launchPlan",
    "creatorGateObservation",
    "operationLockContract",
    "agentBoundary",
}
_AGENT_BOUNDARY_V27: Final = MappingProxyType(
    {
        "task2CanMintAuthority": False,
        "podmanSocketMounted": False,
        "sudoAvailableToWorker": False,
        "agentRunsAsRoot": False,
        "trackerCredentialsMounted": False,
        "cloudCredentialsMounted": False,
        "releaseAuthorityMounted": False,
        "controllerLifecycleMounted": False,
    }
)


def reference_native_supervisor_probe_v27(
    manifest: NativeBoundaryManifestV27,
) -> dict[str, Any]:
    return {
        "platformObservation": {
            "platform": "linux",
            "systemdVersion": manifest.systemd_version,
            "podmanVersion": manifest.podman_version,
            "podmanRootless": True,
            "conmonVersion": manifest.conmon_version,
            "ociRuntimeName": manifest.oci_runtime_name,
            "ociRuntimeVersion": manifest.oci_runtime_version,
            "ociRuntimeVersionOutputSha256": manifest.oci_runtime_version_output_sha256,
            "ociRuntimeSelectionSource": manifest.oci_runtime_selection_source,
            "selinuxMode": manifest.selinux_mode,
            "supervisorSha256": manifest.supervisor_sha256,
            "podmanSha256": manifest.podman_sha256,
            "conmonSha256": manifest.conmon_sha256,
            "ociRuntimeSha256": manifest.oci_runtime_sha256,
            "selinuxPolicySha256": manifest.selinux_policy_sha256,
            "podmanSocketMounted": False,
            "sudoAvailableToWorker": False,
            "agentRunsAsRoot": False,
        },
        "rawSELinuxContexts": {
            interface: {
                "rawBytesBase64": base64.b64encode(expectation.raw_bytes).decode(
                    "ascii"
                ),
                "byteLength": len(expectation.raw_bytes),
                "terminatorKind": expectation.terminator_kind,
                "rawBytesSha256": expectation.raw_bytes_sha256,
            }
            for interface, expectation in manifest.selinux_contexts.items()
        },
        "launchPlan": reference_launch_plan_v27(),
        "creatorGateObservation": reference_creator_gate_observation_v27(),
        "operationLockContract": operation_lock_contract_v27(),
        "agentBoundary": dict(_AGENT_BOUNDARY_V27),
    }


def validate_native_supervisor_probe_v27(
    value: Any, manifest: NativeBoundaryManifestV27
) -> dict[str, Any]:
    data = _closed(value, _SUPERVISOR_PROBE_FIELDS, "V27 native supervisor probe")
    validate_platform_observation_v27(data["platformObservation"], manifest)
    raw_contexts = data["rawSELinuxContexts"]
    if not isinstance(raw_contexts, dict) or set(raw_contexts) != set(
        manifest.selinux_contexts
    ):
        raise NativeBoundaryV27Error(
            "V27 supervisor probe SELinux interface set changed"
        )
    for interface, raw_value in raw_contexts.items():
        parsed = _parse_raw_context(interface, raw_value)
        expected = manifest.selinux_contexts[interface]
        if parsed != expected:
            raise NativeBoundaryV27Error(
                f"V27 supervisor probe SELinux bytes changed for {interface}"
            )
    validate_launch_plan_v27(data["launchPlan"])
    validate_creator_gate_observation_v27(data["creatorGateObservation"])
    if data["operationLockContract"] != operation_lock_contract_v27():
        raise NativeBoundaryV27Error(
            "V27 supervisor probe OperationLock ABI changed"
        )
    boundary = data["agentBoundary"]
    if (
        not isinstance(boundary, dict)
        or set(boundary) != set(_AGENT_BOUNDARY_V27)
        or any(
            type(boundary[field]) is not bool
            or boundary[field] is not expected
            for field, expected in _AGENT_BOUNDARY_V27.items()
        )
    ):
        raise NativeBoundaryV27Error(
            "V27 supervisor probe exposed agent authority or protected mounts"
        )
    return dict(data)


def _unified_cgroup_relative_v27(raw: bytes) -> str:
    lines = raw.splitlines()
    if len(lines) != 1 or not lines[0].startswith(b"0::/"):
        raise NativeBoundaryV27Error("process is not in one exact cgroup-v2 node")
    try:
        relative = lines[0][3:].decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise NativeBoundaryV27Error("process cgroup path is not UTF-8") from exc
    path = Path("/") / relative.lstrip("/")
    if (
        not relative
        or relative != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise NativeBoundaryV27Error("process cgroup path is unsafe")
    return relative


def _delegated_supervisor_path_v27(
    relative: str, *, cgroup_root: Path = Path("/sys/fs/cgroup")
) -> Path:
    path = Path(relative)
    if not path.is_absolute() or ".." in path.parts or path.name not in {
        "controller",
        "supervisor",
    }:
        raise NativeBoundaryV27Error("process is outside the closed V27 cgroup roles")
    parent = path.parent
    if parent.name in {"controller", "supervisor"}:
        raise NativeBoundaryV27Error("nested V27 delegated subgroup is forbidden")
    return cgroup_root.joinpath(*parent.parts[1:], "supervisor")


def _drain_delegated_supervisor_cgroup_v27() -> None:
    """Kill and prove empty the service's fixed delegated supervisor subgroup."""

    if not sys.platform.startswith("linux"):
        raise NativeBoundaryV27Error("V27 descendant drain requires Linux cgroup v2")
    try:
        raw = Path("/proc/self/cgroup").read_bytes()
        relative = _unified_cgroup_relative_v27(raw)
        subgroup = _delegated_supervisor_path_v27(relative)
        kill_path = subgroup / "cgroup.kill"
        events_path = subgroup / "cgroup.events"
        kill_fd = os.open(kill_path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            _write_all_v27(kill_fd, b"1\n")
        finally:
            os.close(kill_fd)
        deadline = __import__("time").monotonic() + 5.0
        while __import__("time").monotonic() < deadline:
            events_fd = os.open(
                events_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                events = os.read(events_fd, 4096)
            finally:
                os.close(events_fd)
            if b"populated 0\n" in events:
                return
            __import__("time").sleep(0.02)
    except NativeBoundaryV27Error:
        raise
    except OSError as exc:
        raise NativeBoundaryV27Error(
            f"cannot drain the V27 delegated supervisor cgroup: {exc}"
        ) from exc
    raise NativeBoundaryV27Error("V27 delegated supervisor cgroup remained populated")


def _run_bounded_process_v27(
    argv: list[str],
    *,
    timeout: int,
    pass_fds: tuple[int, ...] = (),
    preexec_fn: Any = None,
    drain_on_failure: bool = False,
    after_start: Any = None,
    executable: str | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Stream both pipes with a hard cap; never buffer an unbounded child."""

    if not argv or any(not isinstance(item, str) or not item or "\0" in item for item in argv):
        raise NativeBoundaryV27Error("V27 bounded runner argv is invalid")
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env=_fixed_worker_environment_v27(),
            pass_fds=pass_fds,
            preexec_fn=preexec_fn,
            start_new_session=True,
            executable=executable,
        )
    except OSError as exc:
        # CPython may fork and run preexec code before reporting exec failure
        # through its error pipe.  Therefore a missing/non-executable launcher
        # is never proof that no process existed.
        classification = {
            "classification": "popen-oserror-process-state-unresolved",
            "executablePathSha256": sha256(
                (executable or argv[0]).encode("utf-8")
            ),
            "errno": exc.errno,
            "processCreated": "unknown",
        }
        evidence_sha256 = sha256(
            b"startup-factory/beads/v27/popen-process-state-unresolved\0"
            + canonical_bytes(classification)
        )
        raise _NativeLaunchUnresolvedV27(
            _native_supervisor_loss_v27(
                reason="dead-holder-without-terminal",
                evidence_sha256=evidence_sha256,
            )
        ) from exc
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout.fileno(): ("stdout", bytearray()),
        process.stderr.fileno(): ("stderr", bytearray()),
    }
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = __import__("time").monotonic() + timeout
    failed = False
    failure = ""
    try:
        if after_start is not None:
            try:
                after_start(process)
            except Exception:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                process.wait(timeout=5)
                if drain_on_failure:
                    _drain_delegated_supervisor_cgroup_v27()
                raise
        while selector.get_map():
            if __import__("time").monotonic() >= deadline:
                failed = True
                failure = "timed out"
                break
            for key, _ in selector.select(0.05):
                descriptor = int(key.fd)
                try:
                    block = os.read(descriptor, 65536)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(descriptor)
                    continue
                target = streams[descriptor][1]
                if len(target) + len(block) > MAX_CANONICAL_BYTES:
                    failed = True
                    failure = f"{streams[descriptor][0]} exceeded {MAX_CANONICAL_BYTES} bytes"
                    break
                target.extend(block)
            if failed:
                break
        if failed:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            process.wait(timeout=5)
            if drain_on_failure:
                _drain_delegated_supervisor_cgroup_v27()
            raise NativeBoundaryV27Error(f"V27 child {failure}; descendants were drained")
        return_code = process.wait(timeout=max(1, int(deadline - __import__("time").monotonic()) + 1))
        return subprocess.CompletedProcess(
            argv,
            return_code,
            bytes(streams[process.stdout.fileno()][1]),
            bytes(streams[process.stderr.fileno()][1]),
        )
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


def _fixed_probe_run(argv: list[str]) -> bytes:
    completed = _run_bounded_process_v27(argv, timeout=30)
    if completed.returncode != 0:
        raise NativeBoundaryV27Error(
            f"fixed local V27 probe failed rc={completed.returncode}"
        )
    if not completed.stdout or len(completed.stdout) > MAX_CANONICAL_BYTES:
        raise NativeBoundaryV27Error(
            "fixed local V27 probe output is empty or oversized"
        )
    return completed.stdout


def _fixed_worker_environment_v27() -> dict[str, str]:
    try:
        account = pwd.getpwuid(os.geteuid())
    except KeyError as exc:
        raise NativeBoundaryV27Error(
            "native V27 worker UID has no local account"
        ) from exc
    return {
        "BD_JSON_ENVELOPE": "1",
        "HOME": account.pw_dir,
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": account.pw_name,
        "PATH": "/usr/bin:/bin",
        "USER": account.pw_name,
        "XDG_RUNTIME_DIR": f"/run/user/{os.geteuid()}",
    }


def _selinux_enforce_bytes() -> bytes:
    path = "/sys/fs/selinux/enforce"
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            raw = os.read(descriptor, 4)
            extra = os.read(descriptor, 1)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise NativeBoundaryV27Error(
            f"cannot observe enforcing SELinux state: {exc}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or extra:
        raise NativeBoundaryV27Error("SELinux enforcing interface is unsafe")
    return raw


def _selinux_policy_bytes() -> bytes:
    path = "/sys/fs/selinux/policy"
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            blocks = bytearray()
            while True:
                try:
                    block = os.read(descriptor, 65_536)
                except InterruptedError:
                    continue
                if not block:
                    break
                if len(blocks) + len(block) > 64 * 1024 * 1024:
                    raise NativeBoundaryV27Error(
                        "loaded SELinux policy exceeds the fixed byte cap"
                    )
                blocks.extend(block)
            raw = bytes(blocks)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise NativeBoundaryV27Error(
            f"cannot observe loaded SELinux policy: {exc}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or not raw:
        raise NativeBoundaryV27Error("loaded SELinux policy interface is unsafe")
    return raw


def _strict_probe_value(raw: bytes) -> Any:
    if not raw or len(raw) > MAX_CANONICAL_BYTES:
        raise NativeBoundaryV27Error(
            "native supervisor probe output is empty or oversized"
        )
    duplicate = False

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal duplicate
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                duplicate = True
            result[key] = item
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeBoundaryV27Error(
            f"native supervisor probe returned malformed JSON: {exc}"
        ) from exc
    if duplicate or raw != canonical_bytes(value) + b"\n":
        raise NativeBoundaryV27Error(
            "native supervisor probe is duplicate-key or noncanonical JSON"
        )
    return value


def _strict_probe_json(raw: bytes) -> dict[str, Any]:
    value = _strict_probe_value(raw)
    if not isinstance(value, dict):
        raise NativeBoundaryV27Error(
            "native supervisor probe did not return one JSON object"
        )
    return value


def _beads_wire_value_v112(raw: bytes, label: str) -> Any:
    """Parse one official bd envelope without assuming Go's presentation order.

    The protected environment forces ``BD_JSON_ENVELOPE=1``.  Go indentation
    and struct key order are presentation details, so the wire is canonicalized
    only after strict UTF-8, framing, duplicate-key and single-value checks.
    """

    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > MAX_CANONICAL_BYTES
        or raw.startswith(b"\xef\xbb\xbf")
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
    ):
        raise NativeBoundaryV27Error(
            f"V27 {label} is not one bounded BOM-free JSON value plus LF"
        )
    body = raw[:-1]
    duplicate = False

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal duplicate
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                duplicate = True
            result[key] = item
        return result

    def reject_constant(value: str) -> Any:
        raise ValueError(f"non-JSON numeric constant {value}")

    try:
        text = body.decode("utf-8", "strict")
        decoder = json.JSONDecoder(
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
        value, end = decoder.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise NativeBoundaryV27Error(
            f"V27 {label} returned malformed JSON: {exc}"
        ) from exc
    if duplicate or end != len(text):
        raise NativeBoundaryV27Error(
            f"V27 {label} has duplicate keys or trailing bytes/value"
        )
    # Constructing the canonical form here is intentional: it is derived
    # evidence after the original Go wire has been accepted, never a framing
    # shortcut.  It also rejects values outside this runtime's byte budget.
    if len(canonical_bytes(value)) > MAX_CANONICAL_BYTES:
        raise NativeBoundaryV27Error(f"V27 {label} canonical value is oversized")
    return value


def _validate_rootless_podman_info_v27(
    value: Any,
    manifest: NativeBoundaryManifestV27,
    *,
    expected_worker_uid: int | None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NativeBoundaryV27Error("Podman info is not one JSON object")
    host = value.get("host")
    if not isinstance(host, dict):
        raise NativeBoundaryV27Error("Podman info has no host observation")
    security = host.get("security")
    mappings = host.get("idMappings")
    oci_runtime = host.get("ociRuntime")
    if (
        not isinstance(security, dict)
        or security.get("rootless") is not True
        or host.get("cgroupVersion") != "v2"
        or host.get("cgroupManager") != "systemd"
        or not isinstance(mappings, dict)
        or set(mappings) != {"uidmap", "gidmap"}
        or not isinstance(oci_runtime, dict)
        or set(oci_runtime) != {"name", "path", "version"}
        or oci_runtime["name"] != manifest.oci_runtime_name
        or oci_runtime["path"] != str(manifest.oci_runtime_path)
        or type(oci_runtime["version"]) is not str
        or not oci_runtime["version"].startswith(manifest.oci_runtime_version + "\n")
        or sha256((oci_runtime["version"] + "\n").encode("utf-8"))
        != manifest.oci_runtime_version_output_sha256
    ):
        raise NativeBoundaryV27Error(
            "Podman info does not prove rootless systemd cgroup-v2 execution"
        )
    normalized: dict[str, list[dict[str, int]]] = {}
    for name in ("uidmap", "gidmap"):
        entries = mappings[name]
        if not isinstance(entries, list) or not 1 <= len(entries) <= 2:
            raise NativeBoundaryV27Error(
                f"Podman {name} cardinality is outside the closed V27 profile"
            )
        observed: list[dict[str, int]] = []
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "container_id",
                "host_id",
                "size",
            }:
                raise NativeBoundaryV27Error(
                    f"Podman {name} entry has unknown or missing fields"
                )
            if any(type(entry[field]) is not int for field in entry):
                raise NativeBoundaryV27Error(f"Podman {name} entry is not integral")
            if (
                entry["container_id"] < 0
                or entry["host_id"] < 0
                or entry["size"] < 1
            ):
                raise NativeBoundaryV27Error(f"Podman {name} entry is invalid")
            observed.append(dict(entry))
        if observed[0]["container_id"] != 0:
            raise NativeBoundaryV27Error(
                f"Podman {name} does not map container identity zero first"
            )
        normalized[name] = observed
    if (
        expected_worker_uid is not None
        and normalized["uidmap"][0]["host_id"] != expected_worker_uid
    ):
        raise NativeBoundaryV27Error(
            "rootless Podman uidmap does not bind the configured worker UID"
        )
    return {
        "rootless": True,
        "idMappings": normalized,
        "ociRuntime": dict(oci_runtime),
        "ociRuntimeSelectionSource": manifest.oci_runtime_selection_source,
    }


def _validate_local_image_v27(value: Any, manifest: NativeBoundaryManifestV27) -> None:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise NativeBoundaryV27Error(
            "Podman image inspection must return exactly one local image"
        )
    image = value[0]
    observed_id = image.get("Id")
    repo_digests = image.get("RepoDigests")
    if (
        observed_id != manifest.image_digest
        or not isinstance(repo_digests, list)
        or repo_digests != [manifest.image_reference]
    ):
        raise NativeBoundaryV27Error(
            "local Podman image identity differs from the pinned digest/reference"
        )


def verify_local_platform_gate_v27(
    manifest: NativeBoundaryManifestV27,
    *,
    runner: Any = _fixed_probe_run,
    selinux_enforce_reader: Any = _selinux_enforce_bytes,
    selinux_policy_reader: Any = _selinux_policy_bytes,
    platform_name: str | None = None,
    expected_worker_uid: int | None = None,
) -> dict[str, Any]:
    """Run the fixed, offline local V27 readiness gate; never promote readiness."""

    observed_platform = sys.platform if platform_name is None else platform_name
    if not observed_platform.startswith("linux"):
        raise NativeBoundaryV27Error("native Beads V27 boundary requires Linux")
    if expected_worker_uid is not None and os.geteuid() != expected_worker_uid:
        raise NativeBoundaryV27Error(
            "native Beads V27 probe is not running as the configured worker UID"
        )
    if selinux_enforce_reader() not in {b"1", b"1\n"}:
        raise NativeBoundaryV27Error("native Beads V27 boundary requires enforcing SELinux")
    if sha256(selinux_policy_reader()) != manifest.selinux_policy_sha256:
        raise NativeBoundaryV27Error(
            "loaded SELinux policy differs from the pinned binary identity"
        )
    systemd = runner(["/usr/bin/systemd", "--version"]).splitlines()
    if (
        not systemd
        or re.fullmatch(
            rb"systemd 254 \(254(?:\.[0-9]+)?(?:-[0-9A-Za-z.+~]+)?\)",
            systemd[0],
        )
        is None
    ):
        raise NativeBoundaryV27Error("native Beads V27 boundary requires exact systemd 254")
    if runner([str(manifest.podman_path), "--version"]).strip() != b"podman version 5.4.1":
        raise NativeBoundaryV27Error("native Beads V27 boundary requires exact Podman 5.4.1")
    _validate_rootless_podman_info_v27(
        _strict_probe_value(
            runner([str(manifest.podman_path), "info", "--format", "json"])
        ),
        manifest,
        expected_worker_uid=expected_worker_uid,
    )
    _validate_local_image_v27(
        _strict_probe_value(
            runner(
                [
                    str(manifest.podman_path),
                    "image",
                    "inspect",
                    "--format",
                    "json",
                    manifest.image_reference,
                ]
            )
        ),
        manifest,
    )
    conmon = runner([str(manifest.conmon_path), "--version"]).splitlines()
    if not conmon or conmon[0] != b"conmon version 2.1.12":
        raise NativeBoundaryV27Error("native Beads V27 boundary requires exact conmon 2.1.12")
    runtime_version = runner([str(manifest.oci_runtime_path), "--version"])
    if (
        sha256(runtime_version) != manifest.oci_runtime_version_output_sha256
        or not runtime_version.startswith(
            (manifest.oci_runtime_version + "\n").encode("ascii")
        )
    ):
        raise NativeBoundaryV27Error(
            "native Beads V27 boundary OCI runtime version changed"
        )
    probe = _strict_probe_json(
        runner([str(manifest.supervisor_path), "--startup-factory-probe-v27"])
    )
    return validate_native_supervisor_probe_v27(probe, manifest)


# Production V27 execution is deliberately internal.  The broker never spawns
# bd and never accepts caller-asserted exit/output observations.  It sends one
# digest-bound plan to the controller; only this controller-side state machine
# may consume the launch and invoke the pinned native supervisor.
_EFFECT_OPERATION_ID = re.compile(r"\A[0-9a-f]{64}\Z")
_EFFECT_CLASSES: Final = frozenset(DONE_LOCATIONS_V27)
_EFFECT_PLAN_FIELDS: Final = {
    "schemaVersion",
    "profile",
    "operationId",
    "operationClass",
    "repositoryPath",
    "argv",
    "imageReference",
    "imageDigest",
    "networkMode",
    "pullPolicy",
    "environment",
    "readBackPlan",
    "preparationCommands",
    "launchCoreSha256",
    "operatorGeneration",
    "configEpoch",
    "keyEpoch",
    "planSha256",
}
_EFFECT_LIFECYCLE: Final = (
    "create",
    "init",
    "start-attach",
    "terminal",
    "cleanup",
    "rm",
)
_EFFECT_FAULT: ContextVar[str | None] = ContextVar(
    "beads-native-effect-v27-fault", default=None
)
_EFFECT_FAULT_SIGKILL: ContextVar[bool] = ContextVar(
    "beads-native-effect-v27-fault-sigkill", default=False
)
_NATIVE_REQUEST_KEY_V27: ContextVar[bytes | None] = ContextVar(
    "beads-native-request-key-v27", default=None
)
_NATIVE_OUTER_EVENT_HANDLER_V27: ContextVar[Any | None] = ContextVar(
    "beads-native-outer-event-handler-v27", default=None
)
_NATIVE_RESULT_OFFER_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/worker-result-offer\0"
)
_NATIVE_RESULT_OFFER_ACK_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/worker-result-offer-ack\0"
)


def _derive_native_request_key_v27(
    key: bytes, plan: Mapping[str, Any], stage: LiteralStageV27
) -> bytes:
    if not isinstance(key, bytes) or not 32 <= len(key) <= 4096:
        raise NativeBoundaryV27Error("V27 retained controller key is invalid")
    binding = {
        "launchCoreSha256": plan["launchCoreSha256"],
        "operatorGeneration": plan["operatorGeneration"],
        "configEpoch": plan["configEpoch"],
        "keyEpoch": plan["keyEpoch"],
        "operationId": plan["operationId"],
        "effectPlanSha256": plan["planSha256"],
        "stageLocation": stage.location,
        "stageKey": stage.stage_key,
    }
    return hmac.new(
        key,
        b"startup-factory/beads/v27/request-key\0" + canonical_bytes(binding),
        hashlib.sha256,
    ).digest()


def _effect_plan_digest(value: Mapping[str, Any]) -> str:
    return sha256(
        canonical_bytes(
            {key: item for key, item in value.items() if key != "planSha256"}
        )
    )


def reference_supervised_effect_plan_v27(
    manifest: NativeBoundaryManifestV27,
    *,
    operation_id: str,
    operation_class: str,
    argv: list[str],
    repository_path: str,
    read_back_plan: Mapping[str, Any] | None = None,
    preparation_commands: Sequence[Sequence[str]] | None = None,
    launch_core_sha256: str | None = None,
    operator_generation: int = 0,
    config_epoch: int = 1,
    key_epoch: int = 1,
) -> dict[str, Any]:
    if launch_core_sha256 is None:
        launch_core_sha256 = sha256(
            b"startup-factory/beads/v27/reference-launch-core\0"
            + operation_id.encode("ascii")
        )
    value: dict[str, Any] = {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": operation_id,
        "operationClass": operation_class,
        "repositoryPath": repository_path,
        "argv": list(argv),
        "imageReference": manifest.image_reference,
        "imageDigest": manifest.image_digest,
        "networkMode": "none",
        "pullPolicy": "never",
        "environment": {
            "BD_JSON_ENVELOPE": "1",
            "HOME": "/run/startup-factory/home",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        },
        "readBackPlan": None if read_back_plan is None else dict(read_back_plan),
        "preparationCommands": (
            None
            if preparation_commands is None
            else [list(command) for command in preparation_commands]
        ),
        "launchCoreSha256": launch_core_sha256,
        "operatorGeneration": operator_generation,
        "configEpoch": config_epoch,
        "keyEpoch": key_epoch,
        "planSha256": None,
    }
    value["planSha256"] = _effect_plan_digest(value)
    return value


def validate_supervised_effect_plan_v27(
    value: Any, manifest: NativeBoundaryManifestV27
) -> dict[str, Any]:
    data = _closed(value, _EFFECT_PLAN_FIELDS, "V27 supervised-effect plan")
    if data["schemaVersion"] != 27 or data["profile"] != PROFILE:
        raise NativeBoundaryV27Error("V27 supervised-effect profile changed")
    if not isinstance(data["operationId"], str) or not _EFFECT_OPERATION_ID.fullmatch(
        data["operationId"]
    ):
        raise NativeBoundaryV27Error("V27 supervised-effect operationId is invalid")
    if data["operationClass"] not in _EFFECT_CLASSES:
        raise NativeBoundaryV27Error("V27 supervised-effect operation class is invalid")
    _digest(data["launchCoreSha256"], "supervised-effect launchCoreSha256")
    if (
        type(data["operatorGeneration"]) is not int
        or data["operatorGeneration"] < 0
        or type(data["configEpoch"]) is not int
        or data["configEpoch"] < 1
        or type(data["keyEpoch"]) is not int
        or data["keyEpoch"] < 1
    ):
        raise NativeBoundaryV27Error(
            "V27 supervised-effect generation/epoch binding changed"
        )
    repository = _absolute(data["repositoryPath"], "repositoryPath")
    argv = data["argv"]
    if (
        not isinstance(argv, list)
        or not 1 <= len(argv) <= 64
        or argv[0] != "/usr/local/bin/bd"
        or any(
            not isinstance(item, str)
            or not item
            or "\0" in item
            or len(item.encode("utf-8")) > 4096
            for item in argv
        )
    ):
        raise NativeBoundaryV27Error(
            "V27 supervised-effect argv must use the fixed container bd executable"
        )
    if (
        data["imageReference"] != manifest.image_reference
        or data["imageDigest"] != manifest.image_digest
        or data["networkMode"] != "none"
        or data["pullPolicy"] != "never"
        or data["environment"]
        != {
            "BD_JSON_ENVELOPE": "1",
            "HOME": "/run/startup-factory/home",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        }
    ):
        raise NativeBoundaryV27Error(
            "V27 supervised-effect changed the image, network, pull or environment policy"
        )
    if data["readBackPlan"] is not None:
        data["readBackPlan"] = validate_descriptor_pinned_read_back_plan_v27(
            data["readBackPlan"]
        )
    commands = data["preparationCommands"]
    if data["operationClass"] in {"create-preparation", "reattest-preparation"}:
        expected_count = 4 if data["operationClass"] == "create-preparation" else 1
        if (
            not isinstance(commands, list)
            or len(commands) != expected_count
            or any(
                not isinstance(command, list)
                or not command
                or command[0] != "/usr/local/bin/bd"
                or len(command) > 16
                or any(
                    not isinstance(argument, str)
                    or not argument
                    or "\0" in argument
                    or len(argument.encode("utf-8")) > 4096
                    for argument in command
                )
                for command in commands
            )
        ):
            raise NativeBoundaryV27Error(
                "V27 preparation plan lacks its exact protected command sequence"
            )
        commands = [list(command) for command in commands]
    elif commands is not None:
        raise NativeBoundaryV27Error(
            "non-preparation V27 plan cannot carry preparation commands"
        )
    if data["planSha256"] != _effect_plan_digest(data):
        raise NativeBoundaryV27Error("V27 supervised-effect plan digest mismatch")
    return {
        **data,
        "repositoryPath": str(repository),
        "argv": list(argv),
        "environment": dict(data["environment"]),
        "readBackPlan": data["readBackPlan"],
        "preparationCommands": commands,
    }


def _effect_fault(phase: str) -> None:
    if _EFFECT_FAULT.get() == phase:
        if _EFFECT_FAULT_SIGKILL.get():
            os.kill(os.getpid(), signal.SIGKILL)
        raise SystemExit(f"intentional V27 native-effect fault after {phase}")


@contextmanager
def inject_native_effect_fault_v27(phase: str):
    token = _EFFECT_FAULT.set(phase)
    try:
        yield
    finally:
        _EFFECT_FAULT.reset(token)


@contextmanager
def inject_native_effect_sigkill_v27(phase: str):
    fault_token = _EFFECT_FAULT.set(phase)
    kill_token = _EFFECT_FAULT_SIGKILL.set(True)
    try:
        yield
    finally:
        _EFFECT_FAULT_SIGKILL.reset(kill_token)
        _EFFECT_FAULT.reset(fault_token)


def _safe_effect_root(root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise NativeBoundaryV27Error("V27 effect state root must be absolute")
    try:
        metadata = os.lstat(root)
    except OSError as exc:
        raise NativeBoundaryV27Error(f"cannot inspect V27 effect state root: {exc}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise NativeBoundaryV27Error(
            "V27 effect state root must be caller-owned, private and non-symlinked"
        )
    return root


def _safe_effect_directory(parent: Path, leaf: str) -> Path:
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", leaf):
        raise NativeBoundaryV27Error("V27 effect directory name is invalid")
    destination = parent / leaf
    try:
        os.mkdir(destination, 0o700)
    except FileExistsError:
        pass
    metadata = os.lstat(destination)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise NativeBoundaryV27Error("V27 effect directory is substituted or unsafe")
    return destination


def _effect_sign(kind: str, payload: Mapping[str, Any], key: bytes) -> dict[str, Any]:
    domain = HMAC_DOMAINS_V27.get(kind)
    if domain is None or not isinstance(key, bytes) or not 32 <= len(key) <= 4096:
        raise NativeBoundaryV27Error("V27 effect HMAC key/domain is invalid")
    body = canonical_bytes(dict(payload))
    auth = "hmac-sha256:" + __import__("hmac").new(
        key, domain + body, hashlib.sha256
    ).hexdigest()
    unsigned = {"kind": kind, "payload": dict(payload), "auth": auth}
    record = sha256(canonical_bytes(unsigned))
    return {**unsigned, "recordSha256": record}


def _effect_verify(
    envelope: Any, key: bytes, *, expected_kind: str | None = None
) -> dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != {
        "kind",
        "payload",
        "auth",
        "recordSha256",
    }:
        raise NativeBoundaryV27Error("V27 effect record is malformed")
    kind = envelope["kind"]
    if expected_kind is not None and kind != expected_kind:
        raise NativeBoundaryV27Error("V27 effect record kind mismatch")
    signed = _effect_sign(kind, envelope["payload"], key)
    if not __import__("hmac").compare_digest(
        canonical_bytes(signed), canonical_bytes(envelope)
    ):
        raise NativeBoundaryV27Error("V27 effect record authentication failed")
    return dict(envelope)


def _read_effect_record(path: Path, key: bytes, *, expected_kind: str | None = None) -> dict[str, Any]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_size <= 0
                or metadata.st_size > MAX_CANONICAL_BYTES
            ):
                raise NativeBoundaryV27Error("V27 effect record metadata is unsafe")
            raw = os.read(descriptor, metadata.st_size + 1)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise NativeBoundaryV27Error(f"cannot read V27 effect record: {exc}") from exc
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeBoundaryV27Error("V27 effect record contains malformed JSON") from exc
    if raw != canonical_bytes(value):
        raise NativeBoundaryV27Error("V27 effect record is not canonical JSON")
    return _effect_verify(value, key, expected_kind=expected_kind)


def _write_effect_immutable(
    path: Path, value: Mapping[str, Any], *, phase: str | None = None
) -> None:
    raw = canonical_bytes(dict(value))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            _write_all_v27(descriptor, raw)
            if phase is not None:
                _effect_fault(f"{phase}-bytes-written")
            os.fsync(descriptor)
            if phase is not None:
                _effect_fault(f"{phase}-file-fsynced")
        finally:
            os.close(descriptor)
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
            if phase is not None:
                _effect_fault(f"{phase}-directory-fsynced")
        finally:
            os.close(parent)
    except FileExistsError:
        raise NativeBoundaryV27Error("V27 immutable effect object appeared concurrently")


def _publish_effect_object(
    path: Path,
    envelope: Mapping[str, Any],
    key: bytes,
    *,
    phase: str | None = None,
) -> None:
    if path.exists():
        existing = _read_effect_record(path, key, expected_kind=str(envelope["kind"]))
        if canonical_bytes(existing) != canonical_bytes(dict(envelope)):
            raise NativeBoundaryV27Error("V27 immutable effect object conflicts")
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return
    _write_effect_immutable(path, envelope, phase=phase)


def _replace_effect_current(
    path: Path,
    envelope: Mapping[str, Any],
    *,
    expected: bytes | None,
    phase: str | None = None,
) -> None:
    try:
        current = path.read_bytes()
    except FileNotFoundError:
        current = None
    raw = canonical_bytes(dict(envelope))
    if current == raw:
        parent = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return
    if current != expected:
        raise NativeBoundaryV27Error("V27 StageCurrent predecessor changed")
    temporary = path.with_name(
        f".{path.name}.tmp.{str(envelope['recordSha256']).removeprefix('sha256:')}"
    )
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        try:
            descriptor = os.open(
                temporary, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size != len(raw)
                ):
                    raise NativeBoundaryV27Error(
                        "V27 current temporary metadata conflicts"
                    )
                existing = _pread_exact_bounded_v27(
                    descriptor, metadata.st_size, "current temporary"
                )
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise NativeBoundaryV27Error(
                f"cannot recover V27 current temporary: {exc}"
            ) from exc
        if existing != raw:
            raise NativeBoundaryV27Error("V27 current temporary conflicts")
        descriptor = os.open(
            temporary, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    else:
        try:
            _write_all_v27(descriptor, raw)
            if phase is not None:
                _effect_fault(f"{phase}-temporary-bytes-written")
            os.fsync(descriptor)
            if phase is not None:
                _effect_fault(f"{phase}-temporary-file-fsynced")
        finally:
            os.close(descriptor)
    os.replace(temporary, path)
    if phase is not None:
        _effect_fault(f"{phase}-cas-replaced")
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
        if phase is not None:
            _effect_fault(f"{phase}-cas-directory-fsynced")
    finally:
        os.close(parent)


def _effect_state_paths(root: Path, operation_id: str) -> tuple[Path, Path, Path]:
    root = _safe_effect_root(root)
    namespace = _safe_effect_directory(root, "native-effects-v27")
    operation = _safe_effect_directory(namespace, operation_id)
    history = _safe_effect_directory(operation, "history")
    objects = _safe_effect_directory(operation, "objects")
    lock_path = operation / "operation.lock"
    if not lock_path.exists():
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(descriptor)
    metadata = os.lstat(lock_path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise NativeBoundaryV27Error("V27 operation lock is substituted or unsafe")
    return operation, history, objects


@contextmanager
def _effect_lock(path: Path):
    descriptor = os.open(
        path,
        os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        if sys.platform.startswith("linux"):
            result, captured = try_operation_lock_v27(descriptor)
            if (result, captured) != ("acquired", 0):
                raise NativeBoundaryV27Error(
                    f"V27 operation lock is unavailable ({result}/{captured})"
                )
        else:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def _stage_current_payload(
    plan: Mapping[str, Any],
    *,
    generation: int,
    location: int,
    state: str,
    predecessor: Mapping[str, Any] | None,
    result_record_sha256: str | None,
) -> dict[str, Any]:
    return {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "planSha256": plan["planSha256"],
        "generation": generation,
        "location": location,
        "state": state,
        "predecessorRecordSha256": (
            None if predecessor is None else predecessor["recordSha256"]
        ),
        "resultRecordSha256": result_record_sha256,
    }


def _install_stage_current(
    current_path: Path,
    history: Path,
    key: bytes,
    payload: Mapping[str, Any],
    *,
    expected: Mapping[str, Any] | None,
) -> dict[str, Any]:
    envelope = _effect_sign("StageCurrentV3", payload, key)
    history_path = history / f"{envelope['recordSha256'].removeprefix('sha256:')}.json"
    _publish_effect_object(history_path, envelope, key)
    expected_raw = None if expected is None else canonical_bytes(dict(expected))
    _replace_effect_current(current_path, envelope, expected=expected_raw)
    return envelope


def _decode_supervisor_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"nativeObservation"}:
        raise NativeBoundaryV27Error("native supervisor result shape is invalid")
    observation = value["nativeObservation"]
    if not isinstance(observation, Mapping) or set(observation) != {
        "exitCode",
        "stdoutSha256",
        "stderrSha256",
        "readBackSha256",
        "readBackProjection",
        "readBacksSha256",
        "physicalEqualityPasses",
        "repeatabilityPasses",
        "repeatabilityEvidenceSha256",
        "rollingJoinPasses",
        "rollingJoinEvidenceSha256",
        "crossWindowNoEffect",
        "crossWindowNoEffectEvidenceSha256",
        "independentReadCount",
        "lifecycle",
        "observedByNativeSupervisor",
    }:
        raise NativeBoundaryV27Error(
            "native supervisor observation shape is invalid"
        )
    if (
        type(observation["exitCode"]) is not int
        or not -255 <= observation["exitCode"] <= 255
        or list(observation["lifecycle"]) != list(_EFFECT_LIFECYCLE)
        or observation["observedByNativeSupervisor"] is not True
        or observation["independentReadCount"] != 4
        or observation["physicalEqualityPasses"] != [True, True]
        or observation["repeatabilityPasses"] != [True] * 6
        or observation["rollingJoinPasses"] != [True] * 5
        or observation["crossWindowNoEffect"] is not True
    ):
        raise NativeBoundaryV27Error(
            "native supervisor observation is outside the closed lifecycle"
        )
    for field in (
        "stdoutSha256", "stderrSha256", "readBackSha256",
        "repeatabilityEvidenceSha256", "rollingJoinEvidenceSha256",
        "crossWindowNoEffectEvidenceSha256",
    ):
        _digest(observation[field], field)
    if (
        not isinstance(observation["readBacksSha256"], list)
        or len(observation["readBacksSha256"]) != 4
    ):
        raise NativeBoundaryV27Error("native supervisor four-read digest set is invalid")
    for item in observation["readBacksSha256"]:
        _digest(item, "readBacksSha256")
    projection = observation["readBackProjection"]
    if not isinstance(projection, dict) or set(projection) != {
        "id", "revision", "status"
    }:
        raise NativeBoundaryV27Error(
            "native supervisor read-back projection is not the exact mapping"
        )
    _bounded_v112_string(projection["id"], "result projection id", maximum=128)
    _timestamp_v112(projection["revision"], "result projection revision")
    _bounded_v112_string(projection["status"], "result projection status")
    return dict(observation)


def inspect_supervised_effect_v27(
    state_root: Path, key: bytes, operation_id: str
) -> dict[str, Any]:
    operation, _, _ = _effect_state_paths(state_root, operation_id)
    return _read_effect_record(operation / "current.json", key)


def _literal_stage_current_payload_v27(
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    *,
    state: str,
    predecessor: Mapping[str, Any] | None,
    result_record_sha256: str | None = None,
    receipt_record_sha256: str | None = None,
) -> dict[str, Any]:
    predecessor_generation = (
        0 if predecessor is None else int(predecessor["payload"]["generation"])
    )
    return {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "planSha256": plan["planSha256"],
        "generation": predecessor_generation + 1,
        "location": stage.location,
        "stageKey": stage.stage_key,
        "stageKind": stage.stage_kind,
        "actionKind": stage.action_kind,
        "state": state,
        "predecessorRecordSha256": (
            None if predecessor is None else predecessor["recordSha256"]
        ),
        "resultRecordSha256": result_record_sha256,
        "receiptRecordSha256": receipt_record_sha256,
    }


def _bootstrap_stage_current_payload_v27(plan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "planSha256": plan["planSha256"],
        "generation": 1,
        "location": 0,
        "stageKey": "operation-bootstrap",
        "stageKind": "operation-bootstrap",
        "actionKind": "durable-evidence-publication",
        "state": "bootstrap-terminal",
        "predecessorRecordSha256": None,
        "resultRecordSha256": None,
        "receiptRecordSha256": None,
    }


_SUCCESS_OUTER_CHAIN_V27: Final = (
    ("SupervisorLaunchSlotReservedCurrentV1", "launch-slot-reserved"),
    ("SupervisorLaunchSlotConsumedCurrentV1", "launch-slot-consumed"),
    ("SupervisorRunningCurrentV1", "supervisor-running"),
    ("SupervisorRunAuthorizationConsumedCurrentV1", "run-authorization-consumed"),
    ("SupervisorRunAcknowledgedCurrentV1", "run-acknowledged"),
    ("NativeCreatorCreationConsumedCurrentV1", "creator-creation-consumed"),
    ("NativeCreatorCreatedCurrentV1", "native-creator-created"),
    ("StageCurrentV3", "release-consumed-current"),
    ("SignalAttemptConsumedCurrentV1", "signal-attempt-consumed"),
    ("ReleaseIssuedCurrentV1", "release-issued"),
    ("ReleaseKnownLiveCurrentV1", "release-known-live"),
    ("ReleaseTerminalCurrentV1", "release-terminal"),
    ("CreatorReturnReadyCurrentV2", "creator-return-ready"),
    ("CreatorLifetimeClosedCurrentV5", "creator-lifetime-closed"),
    ("SupervisorResultEnvelopeStoredCurrentV4", "result-envelope-stored"),
    ("SupervisorResultHandoffAttemptConsumedCurrentV4", "result-handoff-consumed"),
    ("SupervisorResultHandoffReceiptedCurrentV4", "result-handoff-receipted"),
    ("SupervisorTerminalReceiptStoredCurrentV4", "terminal-receipt-stored"),
    ("SupervisorTerminalCurrentV3", "supervisor-terminal"),
)

_FAILURE_OUTER_PREFIX_V27: Final = MappingProxyType(
    {
        "precreate-failed": (
            ("SupervisorPreCreateFailedCurrentV1", "supervisor-precreate-failed"),
        ),
        "create-failed-no-thread": (
            ("SupervisorCreateFailedNoThreadCurrentV1", "supervisor-create-failed-no-thread"),
        ),
        "controlled-abort-failed": (
            (
                "SupervisorCreatorCreatedStatusUncertainCurrentV2",
                "creator-status-uncertain",
            ),
            ("CreatorAbortWakeConsumedCurrentV1", "abort-wake-consumed"),
            ("CreatorAbortWakeCompletedCurrentV1", "abort-wake-completed"),
            ("CreatorAbortJoinConsumedCurrentV1", "abort-join-consumed"),
            ("CreatorAbortFailureLifetimeCurrentV1", "abort-failure-lifetime"),
        ),
        "revoke-verified-no-effect": (
            ("NativeCreatorCreatedCurrentV1", "native-creator-created"),
            ("RevokeDecisionCurrentV2", "revoke-decision"),
            ("RevokeIssuedCurrentV1", "revoke-issued"),
            ("RevokeTerminalCurrentV1", "revoke-terminal"),
            ("CreatorReturnReadyCurrentV2", "creator-return-ready"),
            ("CreatorLifetimeClosedCurrentV5", "creator-lifetime-closed"),
        ),
    }
)

_RESULT_HANDOFF_CHAIN_V27: Final = _SUCCESS_OUTER_CHAIN_V27[14:]
_SUCCESS_NATIVE_EVENT_CHAIN_V27: Final = _SUCCESS_OUTER_CHAIN_V27[2:14]
_SUCCESS_NATIVE_EVENTS_V27: Final = tuple(
    state for _kind, state in _SUCCESS_NATIVE_EVENT_CHAIN_V27
)
_COMMON_NATIVE_EVENT_PREFIX_V27: Final = _SUCCESS_OUTER_CHAIN_V27[2:5]
_CREATION_CALL_PREFIX_V27: Final = (_SUCCESS_OUTER_CHAIN_V27[5],)
_NATIVE_EVENT_CHAINS_V27: Final = MappingProxyType(
    {
        "success": _SUCCESS_NATIVE_EVENT_CHAIN_V27,
        **{
            result_kind: (
                *_COMMON_NATIVE_EVENT_PREFIX_V27,
                *(
                    ()
                    if result_kind == "precreate-failed"
                    else _CREATION_CALL_PREFIX_V27
                ),
                *_FAILURE_OUTER_PREFIX_V27[result_kind],
            )
            for result_kind in _FAILURE_OUTER_PREFIX_V27
        },
    }
)
_NATIVE_EVENT_CURRENT_KIND_V27: Final = MappingProxyType(
    {
        state: kind
        for chain in _NATIVE_EVENT_CHAINS_V27.values()
        for kind, state in chain
    }
)
_NATIVE_EVENT_CURRENT_BINDING_FIELDS_V27: Final = frozenset(
    {
        "nativeEventSequence", "nativeEvent", "nativeEventTiming",
        "nativeEventIntentRecordSha256", "nativeEventBeforeEvidenceSha256",
        "nativeEventBeforeObservationSha256",
        "nativeEventAfterEvidenceSha256",
        "nativeEventAfterObservationSha256",
        "nativeExactOutcomeRecordSha256",
        "nativeExactAuxiliaryRecordSha256",
    }
)
_NATIVE_EXACT_INTENT_KINDS_V27: Final = MappingProxyType(
    {
        "creator-creation-consumed": ("NativeCreatorCreationIntentV1",),
        "abort-wake-consumed": ("CreatorAbortWakeAttemptV1",),
        "abort-join-consumed": ("CreatorAbortJoinAttemptV1",),
        "creator-return-ready": (
            "NativePostReturnCapturePreparationV1",
            "CreatorReturnDepartureIntentV1",
            "CreatorJoinAttemptV2",
        ),
    }
)
_NATIVE_EXACT_OUTCOME_KINDS_V27: Final = MappingProxyType(
    {
        "supervisor-create-failed-no-thread": (
            "NativeCreatorPreCreateFailureV2",
        ),
        "native-creator-created": (
            "NativeCreatorCreationReceiptV1",
            "NativeCreatorJoinOwnershipReceiptV1",
        ),
        "creator-status-uncertain": (
            "NativeCreatorCreationReceiptV1",
            "NativeCreatorJoinOwnershipReceiptV1",
        ),
        "abort-wake-consumed": (
            "CreatorAbortWakeReturnV1", "CreatorAbortWakeReceiptV1",
        ),
        "abort-join-consumed": (
            "CreatorAbortJoinReturnV1", "CreatorAbortJoinReceiptV1",
        ),
        "creator-lifetime-closed": (
            "NativeAllocationGateReleaseReceiptV1",
        ),
    }
)
_NATIVE_EXACT_BEFORE_OUTCOME_KINDS_V27: Final = MappingProxyType(
    {
        "creator-lifetime-closed": (
            "NativePostReturnAtomicCaptureV1", "CreatorJoinResultV2",
            "CreatorPostReturnObservationV2", "CreatorThreadLifetimeReceiptV4",
        ),
    }
)
_NATIVE_PRE_ACTION_CURRENT_EVENTS_V27: Final = frozenset(
    {
        "run-authorization-consumed",
        "run-acknowledged",
        "creator-creation-consumed",
        "release-consumed-current",
        "signal-attempt-consumed",
        "abort-wake-consumed",
        "abort-join-consumed",
        "revoke-decision",
        "creator-return-ready",
    }
)
_NATIVE_EVENT_OBSERVATION_FIELDS_V27: Final = MappingProxyType(
    {
        "supervisor-running": {
            "supervisorPid", "pidfdTerminal", "fd11IdentityRevalidated",
            "controlPeek",
        },
        "run-authorization-consumed": {
            "releaseSendCount", "cgroupDescriptorCount", "sendmsgReturn",
        },
        "run-acknowledged": {
            "ackSendCount", "sendReturn", "pidfdTerminal",
            "fd11IdentityRevalidated", "controlPeek",
        },
        "creator-creation-consumed": {
            "slotId", "slotGeneration", "creationNonceSha256",
            "creatorPlanSha256",
            "joinOwnerTid", "joinOwnerStartTicks",
            "pthreadDetachState", "pthreadAttrStackSize",
            "pthreadAttrGuardSize", "pthreadAttrScheduling",
            "pthreadCreateCalled", "slotAllocated", "pthreadAttrInitRc",
            "pthreadAttrSetDetachStateRc", "pthreadAttrGetDetachStateRc",
            "pthreadAttrDetachStateReadback", "pthreadAttrSetGuardSizeRc",
            "pthreadAttrSetStackSizeRc", "pthreadAttrDestroyRc",
        },
        "supervisor-precreate-failed": {
            "mutexInitRc", "conditionInitRc", "partialCleanupRc",
            "fd7CloseRc", "fd11CloseRc", "proofFdsClosed",
        },
        "supervisor-create-failed-no-thread": {
            "pthreadCreateRc", "creatorHandleCaptured", "fd7CloseRc",
            "fd11CloseRc", "proofFdsClosed", "pidfdPreCloseTerminal",
            "fd11PreCloseIdentityRevalidated", "pthreadAttrDestroyRc",
            "slotId", "slotGeneration", "creationNonceSha256",
            "pthreadAttrInitRc", "pthreadAttrSetDetachStateRc",
            "pthreadAttrGetDetachStateRc", "pthreadAttrDetachStateReadback",
            "pthreadAttrSetGuardSizeRc", "pthreadAttrSetStackSizeRc",
            "pthreadAttrDestroyRc", "createCalled", "slotAllocated",
            "failurePhase",
        },
        "native-creator-created": {
            "pthreadCreateRc", "creatorHandleCaptured",
            "fd7CloseRc", "fd11CloseRc", "proofFdsClosed",
            "pidfdPreCloseTerminal", "fd11PreCloseIdentityRevalidated",
            "pthreadAttrDestroyRc", "pthreadDetachState", "slotId",
            "slotGeneration", "creationNonceSha256", "creatorTid",
            "creatorStartTicks", "creatorHandshakeComplete",
            "joinOwnerTid", "joinOwnerStartTicks", "joinOwnerTokenSha256",
            "joinOwnerTokenRetained",
            "pthreadAttrInitRc", "pthreadAttrSetDetachStateRc",
            "pthreadAttrGetDetachStateRc", "pthreadAttrDetachStateReadback",
            "pthreadAttrSetGuardSizeRc", "pthreadAttrSetStackSizeRc",
            "createCalled", "slotAllocated", "creatorHandshakePresent",
            "creatorHandshakeStatus", "parentIdentityVerified",
            "creatorPlanSha256", "supervisorPid", "supervisorStartTicks",
            "creatorCancelDisableRc", "creatorSignalMaskRc",
            "handshakeFutexValue", "handshakeFutexWakeReturn",
            "handshakeFutexWaitReturn", "handshakeFutexWaitErrno",
            "creationNoncePresent", "creatorCancelDisablePresent",
            "creatorPlanPresent", "creatorSignalMaskPresent",
            "creatorStartTicksPresent", "creatorTidPresent",
            "handshakeFutexPresent", "parentIdentityPresent",
            "supervisorPidPresent", "supervisorStartTicksPresent",
        },
        "creator-status-uncertain": {
            "pthreadCreateRc", "creatorHandleCaptured", "readinessObserved",
            "pthreadAttrInitRc", "pthreadAttrSetDetachStateRc",
            "pthreadAttrGetDetachStateRc", "pthreadAttrDetachStateReadback",
            "pthreadAttrSetGuardSizeRc", "pthreadAttrSetStackSizeRc",
            "pthreadAttrDestroyRc", "createCalled", "slotAllocated",
            "slotId", "slotGeneration", "creationNonceSha256",
            "creatorTid", "creatorStartTicks", "creatorHandshakePresent",
            "creatorHandshakeStatus", "parentIdentityVerified",
            "creatorPlanSha256", "supervisorPid", "supervisorStartTicks",
            "joinOwnerTid", "joinOwnerStartTicks", "joinOwnerTokenSha256",
            "joinOwnerTokenRetained",
            "creatorCancelDisableRc", "creatorSignalMaskRc",
            "handshakeFutexValue", "handshakeFutexWakeReturn",
            "handshakeFutexWaitReturn", "handshakeFutexWaitErrno",
            "failurePhase",
            "creationNoncePresent", "creatorCancelDisablePresent",
            "creatorPlanPresent", "creatorSignalMaskPresent",
            "creatorStartTicksPresent", "creatorTidPresent",
            "handshakeFutexPresent", "parentIdentityPresent",
            "supervisorPidPresent", "supervisorStartTicksPresent",
        },
        "abort-wake-consumed": {
            "abortDecision", "attemptNonceSha256", "slotGeneration",
            "abortStoreCount", "futexWakeCount",
        },
        "abort-wake-completed": {
            "abortStoreReturn", "futexWakeReturn", "conditionBroadcastRc",
            "slotGeneration",
        },
        "abort-join-consumed": {
            "joinAttemptNonceSha256",
            "slotGeneration", "pthreadJoinCount", "creatorHandleConsumed",
        },
        "abort-failure-lifetime": {
            "pthreadJoinRc", "returnSentinel", "creatorTaskAbsent",
            "creatorHandleConsumed", "creatorTid", "creatorStartTicks",
            "creatorTidPresent", "creatorStartTicksPresent",
            "creatorHandshakeStatus", "failurePhase", "slotGeneration",
            "payloadReleaseCount",
        },
        "release-consumed-current": {"releaseStoreCount", "futexWakeCount"},
        "signal-attempt-consumed": {
            "releaseStoreReturn", "futexWakeReturn", "conditionBroadcastRc",
        },
        "release-issued": {
            "releaseAuthorized", "releaseStoreReturn", "futexWakeReturn",
        },
        "release-known-live": {
            "releaseKnownLive", "creatorTaskObserved", "creatorTid",
            "creatorStartTicks", "slotGeneration", "joinOwnerTokenSha256",
            "secondAckBarrierHeld",
        },
        "release-terminal": {
            "creatorHandleConsumed", "creatorReturnWaiting",
            "creatorTaskObserved", "creatorTid", "creatorStartTicks",
            "slotGeneration", "payloadTerminalObserved",
            "terminalObservationPhase",
        },
        "creator-return-ready": {
            "capturePreparationSha256", "atomicCaptureSha256",
            "postReturnObservationSha256", "creatorTid", "creatorStartTicks",
            "slotGeneration", "joinOwnerTokenSha256", "returnSignalCount",
            "pthreadJoinCount", "pthreadJoinRc", "returnSentinel",
            "creatorHandleConsumed", "creatorTaskAbsent",
            "departureIntentSha256", "joinAttemptNonceSha256",
        },
        "creator-lifetime-closed": {
            "creatorTaskAbsent", "proofFd7Closed", "proofFd11Closed",
            "payloadDrained", "closureFlagsSha256", "creatorHandleConsumed",
            "creatorTid", "creatorStartTicks", "slotGeneration",
            "joinOwnerTokenSha256", "pthreadJoinRc", "returnSentinel",
            "capturePreparationSha256", "atomicCaptureSha256",
            "postReturnObservationSha256", "taskSetSha256",
            "allocationGateHeld", "allocationGateReleaseCount",
            "allocationGateReleaseReceiptSha256", "bootIdSha256",
            "captureMonotonicNs", "capturePrepareMonotonicNs",
            "captureWritersSha256", "creatorTaskBytesSha256",
            "joinResultSha256", "lifetimeRecordSha256",
            "resultFdIdentitySha256", "fd7GetfdErrno",
            "fd11GetfdErrno", "pthreadJoinCount",
            "allocationGateReleaseMonotonicNs", "creatorTidPresent",
            "creatorStartTicksPresent",
        },
        "revoke-decision": {"revokeAuthorized", "releaseNotIssued"},
        "revoke-issued": {
            "abortStoreReturn", "futexWakeReturn", "conditionBroadcastRc",
        },
        "revoke-terminal": {
            "abortAuthorized", "creatorHandleConsumed", "creatorTaskObserved",
            "creatorTid", "creatorStartTicks", "slotGeneration",
        },
    }
)


def _creator_handshake_futex_value_v27(nonce_sha256: Any) -> int:
    """Derive the exact C futex token from the protected nonce digest."""

    _digest(nonce_sha256, "native creator creation nonce")
    raw = int(str(nonce_sha256)[7:15], 16) & 0x7FFFFFFF
    return raw or 1


def _validate_native_event_observation_v27(
    event: Any, phase: Any, value: Any
) -> dict[str, Any]:
    """Validate the closed action-specific observation carried by one event."""

    if event not in _NATIVE_EVENT_OBSERVATION_FIELDS_V27 or phase not in {
        "before", "after"
    }:
        raise NativeBoundaryV27Error("V27 native event discriminator changed")
    fields = _NATIVE_EVENT_OBSERVATION_FIELDS_V27[event]
    data = _closed(value, fields, f"V27 {event}/{phase} observation")
    string_fields = {
        "controlPeek", "returnSentinel", "closureFlagsSha256", "slotId",
        "creationNonceSha256", "joinOwnerStartTicks", "joinOwnerTokenSha256",
        "pthreadDetachState", "pthreadAttrScheduling", "creatorStartTicks",
        "pthreadAttrDetachStateReadback", "failurePhase",
        "creatorHandshakeStatus", "creatorPlanSha256", "supervisorStartTicks",
        "abortDecision", "attemptNonceSha256", "joinAttemptNonceSha256",
        "capturePreparationSha256", "atomicCaptureSha256",
        "postReturnObservationSha256", "terminalObservationPhase",
        "departureIntentSha256", "joinAttemptNonceSha256", "taskSetSha256",
        "allocationGateReleaseReceiptSha256", "bootIdSha256",
        "captureWritersSha256", "creatorTaskBytesSha256",
        "joinResultSha256", "lifetimeRecordSha256",
        "resultFdIdentitySha256",
    }
    boolean_fields = {
        "pidfdTerminal", "readinessObserved", "creatorTaskAbsent",
        "creatorTaskObserved", "releaseAuthorized", "releaseKnownLive",
        "proofFd7Closed", "proofFd11Closed", "payloadDrained",
        "revokeAuthorized", "releaseNotIssued", "proofFdsClosed",
        "pidfdPreCloseTerminal", "creatorHandleCaptured",
        "fd11IdentityRevalidated", "fd11PreCloseIdentityRevalidated",
        "pthreadCreateCalled", "createCalled", "slotAllocated",
        "creatorHandshakeComplete", "creatorHandshakePresent",
        "parentIdentityVerified",
        "joinOwnerTokenRetained", "creatorHandleConsumed",
        "secondAckBarrierHeld", "creatorReturnWaiting",
        "payloadTerminalObserved",
        "abortAuthorized",
        "allocationGateHeld",
        "creationNoncePresent", "creatorCancelDisablePresent",
        "creatorPlanPresent", "creatorSignalMaskPresent",
        "creatorStartTicksPresent", "creatorTidPresent",
        "handshakeFutexPresent", "parentIdentityPresent",
        "supervisorPidPresent", "supervisorStartTicksPresent",
    }
    nullable_uncertain_fields = {
        "creationNonceSha256", "creatorPlanSha256", "creatorTid",
        "creatorStartTicks", "parentIdentityVerified", "supervisorPid",
        "supervisorStartTicks", "creatorCancelDisableRc",
        "creatorSignalMaskRc", "handshakeFutexValue",
        "handshakeFutexWakeReturn",
    }
    for field, item in data.items():
        if item is None and (
            (
                event == "creator-status-uncertain"
                and field in nullable_uncertain_fields
            )
            or (
                event == "abort-failure-lifetime"
                and field in {
                    "creatorTid", "creatorStartTicks", "creatorTaskAbsent"
                }
            )
        ):
            continue
        if field in string_fields:
            if item is not None and not isinstance(item, str):
                raise NativeBoundaryV27Error(
                    f"V27 {event}/{phase} {field} type changed"
                )
        elif field in boolean_fields:
            if type(item) is not bool:
                raise NativeBoundaryV27Error(
                    f"V27 {event}/{phase} {field} type changed"
                )
        elif item is not None and type(item) is not int:
            raise NativeBoundaryV27Error(
                f"V27 {event}/{phase} {field} type changed"
            )
    for digest_field in {
        "closureFlagsSha256", "creationNonceSha256", "joinOwnerTokenSha256",
        "attemptNonceSha256", "joinAttemptNonceSha256",
        "capturePreparationSha256", "atomicCaptureSha256",
        "postReturnObservationSha256", "departureIntentSha256",
        "taskSetSha256",
        "creatorPlanSha256",
        "allocationGateReleaseReceiptSha256", "bootIdSha256",
        "captureWritersSha256", "creatorTaskBytesSha256",
        "joinResultSha256", "lifetimeRecordSha256",
        "resultFdIdentitySha256",
    }:
        if data.get(digest_field) is not None:
            _digest(data[digest_field], f"native event {digest_field}")
    for identity_field in {"creatorStartTicks", "joinOwnerStartTicks"}:
        if data.get(identity_field) is not None and not re.fullmatch(
            r"[1-9][0-9]*", str(data[identity_field])
        ):
            raise NativeBoundaryV27Error(
                f"V27 {event}/{phase} {identity_field} changed"
            )
    if "slotGeneration" in data and not (
        type(data["slotGeneration"]) is int and 0 < data["slotGeneration"] < 2**63
    ):
        raise NativeBoundaryV27Error(
            f"V27 {event}/{phase} slot generation changed"
        )
    for tid_field in {"creatorTid", "joinOwnerTid", "supervisorPid"}:
        if tid_field in data and data[tid_field] is not None and not (
            type(data[tid_field]) is int and data[tid_field] > 1
        ):
            raise NativeBoundaryV27Error(
                f"V27 {event}/{phase} {tid_field} changed"
            )
    before = phase == "before"

    exact: dict[str, dict[str, Any]] = {
        "run-authorization-consumed": {
            "releaseSendCount": 0 if before else 1,
            "cgroupDescriptorCount": 2,
            "sendmsgReturn": None if before else len(b"RELEASE\n"),
        },
        "run-acknowledged": {
            "ackSendCount": 0 if before else 1,
            "sendReturn": None if before else len(b"ACK\n"),
            "pidfdTerminal": False,
            "fd11IdentityRevalidated": True,
            "controlPeek": "eagain",
        },
        "creator-creation-consumed": {
            "slotId": "payload-terminal-creator",
            "slotGeneration": 1,
            "pthreadDetachState": "joinable",
            "pthreadAttrStackSize": 1048576,
            "pthreadAttrGuardSize": 65536,
            "pthreadAttrScheduling": "inherited-default",
            "pthreadCreateCalled": False,
            "slotAllocated": False,
            "pthreadAttrInitRc": None,
            "pthreadAttrSetDetachStateRc": None,
            "pthreadAttrGetDetachStateRc": None,
            "pthreadAttrDetachStateReadback": None,
            "pthreadAttrSetGuardSizeRc": None,
            "pthreadAttrSetStackSizeRc": None,
            "pthreadAttrDestroyRc": None,
        },
        "native-creator-created": {
            "pthreadCreateRc": 0,
            "creatorHandleCaptured": True,
            "fd7CloseRc": 0,
            "fd11CloseRc": 0,
            "proofFdsClosed": True,
            "pidfdPreCloseTerminal": False,
            "fd11PreCloseIdentityRevalidated": True,
            "pthreadAttrDestroyRc": 0,
            "pthreadDetachState": "joinable",
            "slotId": "payload-terminal-creator",
            "slotGeneration": 1,
            "creatorHandshakeComplete": True,
            "joinOwnerTokenRetained": True,
            "pthreadAttrInitRc": 0,
            "pthreadAttrSetDetachStateRc": 0,
            "pthreadAttrGetDetachStateRc": 0,
            "pthreadAttrDetachStateReadback": "joinable",
            "pthreadAttrSetGuardSizeRc": 0,
            "pthreadAttrSetStackSizeRc": 0,
            "createCalled": True,
            "slotAllocated": True,
            "creatorHandshakePresent": True,
            "creatorHandshakeStatus": "valid",
            "parentIdentityVerified": True,
            "creatorCancelDisableRc": 0,
            "creatorSignalMaskRc": 0,
            "handshakeFutexValue": data.get("handshakeFutexValue"),
            "handshakeFutexWakeReturn": data.get("handshakeFutexWakeReturn"),
            "handshakeFutexWaitReturn": 0,
            "handshakeFutexWaitErrno": 0,
            "creationNoncePresent": True,
            "creatorCancelDisablePresent": True,
            "creatorPlanPresent": True,
            "creatorSignalMaskPresent": True,
            "creatorStartTicksPresent": True,
            "creatorTidPresent": True,
            "handshakeFutexPresent": True,
            "parentIdentityPresent": True,
            "supervisorPidPresent": True,
            "supervisorStartTicksPresent": True,
        },
        "abort-wake-consumed": {
            "abortStoreCount": 0 if before else 1,
            "futexWakeCount": 0 if before else 1,
            "abortDecision": "wake-abort-and-join",
            "slotGeneration": 1,
        },
        "abort-join-consumed": {
            "pthreadJoinCount": 0 if before else 1,
            "creatorHandleConsumed": not before,
            "slotGeneration": 1,
        },
        "abort-failure-lifetime": {
            "pthreadJoinRc": 0,
            "returnSentinel": "creator-abort-sentinel",
            "creatorHandleConsumed": True,
            "slotGeneration": 1,
            "payloadReleaseCount": 0,
        },
        "release-consumed-current": {
            "releaseStoreCount": 0,
            "futexWakeCount": 0,
        },
        "signal-attempt-consumed": {
            "releaseStoreReturn": None if before else 0,
            "futexWakeReturn": None if before else data.get("futexWakeReturn"),
            "conditionBroadcastRc": None if before else 0,
        },
        "release-issued": {
            "releaseAuthorized": True,
            "releaseStoreReturn": 0,
            "futexWakeReturn": data.get("futexWakeReturn"),
        },
        "release-known-live": {
            "releaseKnownLive": True,
            "creatorTaskObserved": True,
            "slotGeneration": 1,
            "secondAckBarrierHeld": True,
        },
        "release-terminal": {
            "creatorHandleConsumed": False,
            "creatorReturnWaiting": True,
            "creatorTaskObserved": True,
            "slotGeneration": 1,
            "payloadTerminalObserved": True,
            "terminalObservationPhase": (
                "pre-terminal" if before else "terminal-waiter"
            ),
        },
        "creator-return-ready": {
            "returnSignalCount": 0 if before else 1,
            "pthreadJoinCount": 0,
            "pthreadJoinRc": None,
            "returnSentinel": None,
            "creatorHandleConsumed": False,
            "creatorTaskAbsent": not before,
            "slotGeneration": 1,
        },
        "revoke-decision": {
            "revokeAuthorized": True,
            "releaseNotIssued": True,
        },
        "revoke-issued": {
            "abortStoreReturn": None if before else 0,
            "futexWakeReturn": None if before else data.get("futexWakeReturn"),
            "conditionBroadcastRc": None if before else 0,
        },
        "revoke-terminal": {
            "abortAuthorized": True,
            "creatorHandleConsumed": False,
            "creatorTaskObserved": True,
            "slotGeneration": 1,
        },
    }
    if event == "supervisor-running" and not (
        type(data["supervisorPid"]) is int
        and data["supervisorPid"] > 1
        and data["pidfdTerminal"] is False
        and data["fd11IdentityRevalidated"] is True
        and data["controlPeek"] == "eagain"
    ):
        raise NativeBoundaryV27Error(
            "V27 supervisor-running observation is not a live bound supervisor"
        )
    if event == "supervisor-precreate-failed" and not (
        (data["mutexInitRc"] != 0 or data["conditionInitRc"] != 0)
        and data["partialCleanupRc"] == 0
        and data["fd7CloseRc"] == 0
        and data["fd11CloseRc"] == 0
        and data["proofFdsClosed"] is True
    ):
        raise NativeBoundaryV27Error(
            "V27 precreate failure observation does not prove safe cleanup"
        )
    if event == "supervisor-create-failed-no-thread":
        phase_fields = (
            "pthreadAttrInitRc", "pthreadAttrSetDetachStateRc",
            "pthreadAttrGetDetachStateRc", "pthreadAttrSetGuardSizeRc",
            "pthreadAttrSetStackSizeRc",
        )
        phase_names = (
            "attr-init", "attr-setdetach", "attr-getdetach", "attr-guard",
            "attr-stack",
        )
        failure_phase = data["failurePhase"]
        valid = (
            data["creatorHandleCaptured"] is False
            and data["fd7CloseRc"] == 0
            and data["fd11CloseRc"] == 0
            and data["proofFdsClosed"] is True
            and data["pidfdPreCloseTerminal"] is False
            and data["fd11PreCloseIdentityRevalidated"] is True
            and data["slotId"] == "payload-terminal-creator"
            and data["slotGeneration"] == 1
            and data["slotAllocated"] is False
            and isinstance(data["creationNonceSha256"], str)
        )
        if failure_phase in phase_names:
            failed_at = phase_names.index(failure_phase)
            valid = valid and data["createCalled"] is False
            valid = valid and data["pthreadCreateRc"] is None
            valid = valid and all(
                data[field] == 0 for field in phase_fields[:failed_at]
            )
            valid = valid and type(data[phase_fields[failed_at]]) is int
            valid = valid and data[phase_fields[failed_at]] != 0
            valid = valid and all(
                data[field] is None for field in phase_fields[failed_at + 1:]
            )
            valid = valid and data["pthreadAttrDestroyRc"] == (
                None if failed_at == 0 else 0
            )
            getdetach_succeeded = failed_at > 2
            valid = valid and data["pthreadAttrDetachStateReadback"] == (
                "joinable" if getdetach_succeeded else None
            )
        elif failure_phase == "pthread-create":
            valid = valid and data["createCalled"] is True
            valid = valid and type(data["pthreadCreateRc"]) is int
            valid = valid and data["pthreadCreateRc"] != 0
            valid = valid and all(data[field] == 0 for field in phase_fields)
            valid = valid and data["pthreadAttrDestroyRc"] == 0
            valid = valid and data["pthreadAttrDetachStateReadback"] == "joinable"
        else:
            valid = False
        if not valid:
            raise NativeBoundaryV27Error(
                "V27 create failure observation does not prove the exact pthread phase"
            )
    if event in {"abort-wake-completed", "signal-attempt-consumed",
                 "release-issued", "revoke-issued"} and not before:
        if type(data["futexWakeReturn"]) is not int or not (
            0 <= data["futexWakeReturn"] <= 1
        ):
            raise NativeBoundaryV27Error(
                f"V27 {event} futex wake result changed"
            )
    if event == "abort-wake-completed" and not (
        data["abortStoreReturn"] == 0
        and data["conditionBroadcastRc"] == 0
        and data["slotGeneration"] == 1
    ):
        raise NativeBoundaryV27Error(
            "V27 abort wake observation does not prove the store/broadcast"
        )
    if event == "creator-lifetime-closed" and not (
        data["creatorTaskAbsent"] is True
        and data["creatorHandleConsumed"] is True
        and data["proofFd7Closed"] is True
        and data["proofFd11Closed"] is True
        and data["payloadDrained"] is True
        and data["pthreadJoinRc"] == 0
        and data["returnSentinel"] in {
            "creator-positive-sentinel", "creator-abort-sentinel"
        }
        and isinstance(data["closureFlagsSha256"], str)
        and isinstance(data["capturePreparationSha256"], str)
        and isinstance(data["atomicCaptureSha256"], str)
        and isinstance(data["postReturnObservationSha256"], str)
        and isinstance(data["taskSetSha256"], str)
        and data["allocationGateHeld"] is before
        and data["allocationGateReleaseCount"] == (0 if before else 1)
        and (
            data["allocationGateReleaseReceiptSha256"] is None
            if before
            else isinstance(data["allocationGateReleaseReceiptSha256"], str)
        )
        and type(data["capturePrepareMonotonicNs"]) is int
        and type(data["captureMonotonicNs"]) is int
        and 0 < data["capturePrepareMonotonicNs"] <= data["captureMonotonicNs"]
        and data["fd7GetfdErrno"] == errno.EBADF
        and data["fd11GetfdErrno"] == errno.EBADF
        and data["pthreadJoinCount"] == 1
        and data["creatorTidPresent"] is True
        and data["creatorStartTicksPresent"] is True
        and (
            data["allocationGateReleaseMonotonicNs"] is None
            if before
            else (
                type(data["allocationGateReleaseMonotonicNs"]) is int
                and data["allocationGateReleaseMonotonicNs"]
                >= data["captureMonotonicNs"]
            )
        )
        and all(
            isinstance(data[field], str)
            for field in (
                "bootIdSha256", "captureWritersSha256",
                "creatorTaskBytesSha256", "joinResultSha256",
                "lifetimeRecordSha256", "resultFdIdentitySha256",
            )
        )
    ):
        raise NativeBoundaryV27Error(
            "V27 creator lifetime observation is not terminal"
        )
    if event == "native-creator-created" and not (
        data["creatorTid"] != data["joinOwnerTid"]
        and data["creatorHandshakeComplete"] is True
        and data["joinOwnerTokenRetained"] is True
        and isinstance(data["creationNonceSha256"], str)
        and isinstance(data["joinOwnerTokenSha256"], str)
        and data["createCalled"] is True
        and data["slotAllocated"] is True
        and data["creatorHandshakePresent"] is True
        and data["creatorHandshakeStatus"] == "valid"
        and data["parentIdentityVerified"] is True
        and data["pthreadAttrGetDetachStateRc"] == 0
        and data["pthreadAttrDetachStateReadback"] == "joinable"
        and isinstance(data["creatorPlanSha256"], str)
        and data["creatorCancelDisableRc"] == 0
        and data["creatorSignalMaskRc"] == 0
        and data["handshakeFutexValue"]
        == _creator_handshake_futex_value_v27(data["creationNonceSha256"])
        and type(data["handshakeFutexWakeReturn"]) is int
        and 0 <= data["handshakeFutexWakeReturn"] <= 1
    ):
        raise NativeBoundaryV27Error(
            "V27 creator creation receipt identity is incomplete"
        )
    if event == "creator-status-uncertain":
        common = (
            data["pthreadCreateRc"] == 0
            and data["creatorHandleCaptured"] is True
            and data["pthreadAttrInitRc"] == 0
            and data["pthreadAttrSetDetachStateRc"] == 0
            and data["pthreadAttrGetDetachStateRc"] == 0
            and data["pthreadAttrDetachStateReadback"] == "joinable"
            and data["pthreadAttrSetGuardSizeRc"] == 0
            and data["pthreadAttrSetStackSizeRc"] == 0
            and data["createCalled"] is True
            and data["slotAllocated"] is True
            and data["slotId"] == "payload-terminal-creator"
            and data["slotGeneration"] == 1
            and data["joinOwnerTokenRetained"] is True
        )
        present = data["creatorHandshakePresent"]
        status = data["creatorHandshakeStatus"]
        allowed_statuses = {
            "valid", "cancellation-disable-failed", "signal-mask-failed",
            "creator-tid-invalid", "creator-start-unreadable",
            "supervisor-start-unreadable", "parent-identity-mismatch",
            "creation-nonce-echo-failed", "plan-digest-echo-failed",
            "handshake-timeout",
        }
        valid = common and status in allowed_statuses
        presence_by_status = {
            "cancellation-disable-failed": (1, 0, 0, 0, 0, 0, 0, 0),
            "signal-mask-failed": (1, 1, 0, 0, 0, 0, 0, 0),
            "creator-tid-invalid": (1, 1, 0, 0, 0, 0, 0, 0),
            "creator-start-unreadable": (1, 1, 1, 0, 0, 0, 0, 0),
            "supervisor-start-unreadable": (1, 1, 1, 1, 1, 0, 0, 0),
            "parent-identity-mismatch": (1, 1, 1, 1, 1, 1, 1, 0),
            "creation-nonce-echo-failed": (1, 1, 1, 1, 1, 1, 1, 1),
            "plan-digest-echo-failed": (1, 1, 1, 1, 1, 1, 1, 1),
            "valid": (1, 1, 1, 1, 1, 1, 1, 1),
            "handshake-timeout": (0, 0, 0, 0, 0, 0, 0, 0),
        }
        expected_presence = presence_by_status[status]
        observed_presence = tuple(
            int(data[field])
            for field in (
                "creatorCancelDisablePresent", "creatorSignalMaskPresent",
                "creatorTidPresent", "creatorStartTicksPresent",
                "supervisorPidPresent", "supervisorStartTicksPresent",
                "parentIdentityPresent", "creationNoncePresent",
            )
        )
        valid = valid and observed_presence == expected_presence
        valid = valid and data["creatorPlanPresent"] is (
            status in {"valid", "plan-digest-echo-failed"}
        )
        valid = valid and data["handshakeFutexPresent"] is present
        field_presence = {
            "creatorCancelDisableRc": "creatorCancelDisablePresent",
            "creatorSignalMaskRc": "creatorSignalMaskPresent",
            "creatorTid": "creatorTidPresent",
            "creatorStartTicks": "creatorStartTicksPresent",
            "supervisorPid": "supervisorPidPresent",
            "supervisorStartTicks": "supervisorStartTicksPresent",
            "parentIdentityVerified": "parentIdentityPresent",
            "creationNonceSha256": "creationNoncePresent",
            "creatorPlanSha256": "creatorPlanPresent",
            "handshakeFutexValue": "handshakeFutexPresent",
            "handshakeFutexWakeReturn": "handshakeFutexPresent",
        }
        valid = valid and all(
            (data[field] is not None) is data[presence_field]
            for field, presence_field in field_presence.items()
        )
        if not present:
            valid = valid and (
                data["failurePhase"] == "creator-handshake-timeout"
                and status == "handshake-timeout"
                and data["readinessObserved"] is False
                and data["pthreadAttrDestroyRc"] == 0
                and data["handshakeFutexWaitReturn"] == -1
                and data["handshakeFutexWaitErrno"] == 110
                and all(data[field] is None for field in nullable_uncertain_fields)
            )
        else:
            valid = valid and (
                type(data["handshakeFutexValue"]) is int
                and data["handshakeFutexValue"] > 0
                and type(data["handshakeFutexWakeReturn"]) is int
                and 0 <= data["handshakeFutexWakeReturn"] <= 1
                and data["handshakeFutexWaitReturn"] == 0
                and data["handshakeFutexWaitErrno"] == 0
            )
            if data["failurePhase"] == "attr-destroy":
                valid = valid and (
                    data["pthreadAttrDestroyRc"] != 0
                    and status == "valid"
                    and data["readinessObserved"] is True
                )
            elif data["failurePhase"] == "creator-handshake":
                valid = valid and (
                    data["pthreadAttrDestroyRc"] == 0
                    and status != "valid"
                    and data["readinessObserved"] is False
                )
                if status == "cancellation-disable-failed":
                    valid = valid and (
                        type(data["creatorCancelDisableRc"]) is int
                        and data["creatorCancelDisableRc"] != 0
                        and data["creatorSignalMaskRc"] is None
                    )
                elif status == "signal-mask-failed":
                    valid = valid and (
                        data["creatorCancelDisableRc"] == 0
                        and type(data["creatorSignalMaskRc"]) is int
                        and data["creatorSignalMaskRc"] != 0
                    )
                else:
                    valid = valid and (
                        data["creatorCancelDisableRc"] == 0
                        and data["creatorSignalMaskRc"] == 0
                    )
            else:
                valid = False
        if not valid:
            raise NativeBoundaryV27Error(
                "V27 creator uncertainty does not match a closed handshake phase"
            )
    if event == "abort-failure-lifetime":
        identity_observed = (
            data["creatorTidPresent"] is True
            and data["creatorStartTicksPresent"] is True
        )
        if not (
            data["pthreadJoinRc"] == 0
            and data["returnSentinel"] == "creator-abort-sentinel"
            and data["creatorHandleConsumed"] is True
            and data["slotGeneration"] == 1
            and data["payloadReleaseCount"] == 0
            and data["creatorHandshakeStatus"] in {
                "valid", "cancellation-disable-failed",
                "signal-mask-failed", "creator-tid-invalid",
                "creator-start-unreadable", "supervisor-start-unreadable",
                "parent-identity-mismatch", "creation-nonce-echo-failed",
                "plan-digest-echo-failed", "handshake-timeout",
            }
            and data["failurePhase"] in {
                "attr-destroy", "creator-handshake",
                "creator-handshake-timeout",
            }
            and (data["creatorTid"] is not None)
            is data["creatorTidPresent"]
            and (data["creatorStartTicks"] is not None)
            is data["creatorStartTicksPresent"]
            and data["creatorTaskAbsent"] is (
                True if identity_observed else None
            )
        ):
            raise NativeBoundaryV27Error(
                "V27 abort lifetime does not prove its exact join basis"
            )
    if event == "creator-return-ready" and not before and not (
        data["returnSignalCount"] == 1
        and data["pthreadJoinCount"] == 0
        and data["pthreadJoinRc"] is None
        and data["returnSentinel"] is None
        and data["creatorHandleConsumed"] is False
        and data["creatorTaskAbsent"] is True
        and data["atomicCaptureSha256"] is None
        and data["postReturnObservationSha256"] is None
        and isinstance(data["departureIntentSha256"], str)
        and isinstance(data["joinAttemptNonceSha256"], str)
    ):
        raise NativeBoundaryV27Error(
            "V27 creator departure/join attempt is incomplete"
        )
    if event == "creator-return-ready" and before and not (
        data["returnSignalCount"] == 0
        and data["creatorTaskAbsent"] is False
        and isinstance(data["departureIntentSha256"], str)
        and isinstance(data["joinAttemptNonceSha256"], str)
    ):
        raise NativeBoundaryV27Error(
            "V27 creator return authority lacks departure/join intent"
        )
    expected = exact.get(event)
    if expected is not None and any(data[field] != item for field, item in expected.items()):
        raise NativeBoundaryV27Error(
            f"V27 {event}/{phase} observation values changed"
        )
    return dict(data)


def _native_event_evidence_v27(
    *, stage_plan_sha256: str, sequence: int, event: str, phase: str,
    observation: Mapping[str, Any],
) -> str:
    return sha256(
        b"startup-factory/beads/v27/native-event-evidence/v2\0"
        + canonical_bytes(
            {
                "stagePlanSha256": stage_plan_sha256,
                "sequence": sequence,
                "event": event,
                "phase": phase,
                "eventObservation": dict(observation),
            }
        )
    )


def _reference_native_event_observation_v27(
    event: str, phase: str, *, supervisor_pid: int = 4242
) -> dict[str, Any]:
    """Deterministic fixture values matching the closed live observation ABI."""

    before = phase == "before"
    values: dict[str, dict[str, Any]] = {
        "supervisor-running": {
            "supervisorPid": supervisor_pid, "pidfdTerminal": False,
            "fd11IdentityRevalidated": True, "controlPeek": "eagain",
        },
        "run-authorization-consumed": {
            "releaseSendCount": 0 if before else 1,
            "cgroupDescriptorCount": 2,
            "sendmsgReturn": None if before else 8,
        },
        "run-acknowledged": {
            "ackSendCount": 0 if before else 1,
            "sendReturn": None if before else 4,
            "pidfdTerminal": False, "fd11IdentityRevalidated": True,
            "controlPeek": "eagain",
        },
        "creator-creation-consumed": {
            "slotId": "payload-terminal-creator", "slotGeneration": 1,
            "creationNonceSha256": sha256(b"reference-creation-nonce"),
            "creatorPlanSha256": sha256(b"reference-creator-plan"),
            "joinOwnerTid": supervisor_pid,
            "joinOwnerStartTicks": "4242",
            "pthreadDetachState": "joinable",
            "pthreadAttrStackSize": 1048576,
            "pthreadAttrGuardSize": 65536,
            "pthreadAttrScheduling": "inherited-default",
            "pthreadCreateCalled": False,
            "slotAllocated": False,
            "pthreadAttrInitRc": None,
            "pthreadAttrSetDetachStateRc": None,
            "pthreadAttrGetDetachStateRc": None,
            "pthreadAttrDetachStateReadback": None,
            "pthreadAttrSetGuardSizeRc": None,
            "pthreadAttrSetStackSizeRc": None,
            "pthreadAttrDestroyRc": None,
        },
        "supervisor-precreate-failed": {
            "mutexInitRc": 22, "conditionInitRc": 22, "partialCleanupRc": 0,
            "fd7CloseRc": 0, "fd11CloseRc": 0, "proofFdsClosed": True,
        },
        "supervisor-create-failed-no-thread": {
            "pthreadCreateRc": None, "creatorHandleCaptured": False,
            "fd7CloseRc": 0, "fd11CloseRc": 0, "proofFdsClosed": True,
            "pidfdPreCloseTerminal": False,
            "fd11PreCloseIdentityRevalidated": True,
            "pthreadAttrDestroyRc": 0,
            "slotId": "payload-terminal-creator", "slotGeneration": 1,
            "creationNonceSha256": sha256(b"reference-creation-nonce"),
            "pthreadAttrInitRc": 0,
            "pthreadAttrSetDetachStateRc": 0,
            "pthreadAttrGetDetachStateRc": 0,
            "pthreadAttrDetachStateReadback": "joinable",
            "pthreadAttrSetGuardSizeRc": 0,
            "pthreadAttrSetStackSizeRc": 22,
            "createCalled": False, "slotAllocated": False,
            "failurePhase": "attr-stack",
        },
        "native-creator-created": {
            "pthreadCreateRc": 0, "creatorHandleCaptured": True,
            "fd7CloseRc": 0, "fd11CloseRc": 0,
            "proofFdsClosed": True, "pidfdPreCloseTerminal": False,
            "fd11PreCloseIdentityRevalidated": True,
            "pthreadAttrDestroyRc": 0, "pthreadDetachState": "joinable",
            "slotId": "payload-terminal-creator", "slotGeneration": 1,
            "creationNonceSha256": sha256(b"reference-creation-nonce"),
            "creatorTid": supervisor_pid + 1, "creatorStartTicks": "4343",
            "creatorHandshakeComplete": True,
            "joinOwnerTid": supervisor_pid, "joinOwnerStartTicks": "4242",
            "joinOwnerTokenSha256": sha256(b"reference-join-owner-token"),
            "joinOwnerTokenRetained": True,
            "pthreadAttrInitRc": 0,
            "pthreadAttrSetDetachStateRc": 0,
            "pthreadAttrGetDetachStateRc": 0,
            "pthreadAttrDetachStateReadback": "joinable",
            "pthreadAttrSetGuardSizeRc": 0,
            "pthreadAttrSetStackSizeRc": 0,
            "createCalled": True, "slotAllocated": True,
            "creatorHandshakePresent": True,
            "creatorHandshakeStatus": "valid",
            "parentIdentityVerified": True,
            "creatorPlanSha256": sha256(b"reference-creator-plan"),
            "supervisorPid": supervisor_pid,
            "supervisorStartTicks": "4242",
            "creatorCancelDisableRc": 0,
            "creatorSignalMaskRc": 0,
            "handshakeFutexValue": _creator_handshake_futex_value_v27(
                sha256(b"reference-creation-nonce")
            ),
            "handshakeFutexWakeReturn": 1,
            "handshakeFutexWaitReturn": 0,
            "handshakeFutexWaitErrno": 0,
            "creationNoncePresent": True,
            "creatorCancelDisablePresent": True,
            "creatorPlanPresent": True,
            "creatorSignalMaskPresent": True,
            "creatorStartTicksPresent": True,
            "creatorTidPresent": True,
            "handshakeFutexPresent": True,
            "parentIdentityPresent": True,
            "supervisorPidPresent": True,
            "supervisorStartTicksPresent": True,
        },
        "creator-status-uncertain": {
            "pthreadCreateRc": 0, "creatorHandleCaptured": True,
            "readinessObserved": True,
            "pthreadAttrInitRc": 0,
            "pthreadAttrSetDetachStateRc": 0,
            "pthreadAttrGetDetachStateRc": 0,
            "pthreadAttrDetachStateReadback": "joinable",
            "pthreadAttrSetGuardSizeRc": 0,
            "pthreadAttrSetStackSizeRc": 0,
            "pthreadAttrDestroyRc": 22,
            "createCalled": True, "slotAllocated": True,
            "slotId": "payload-terminal-creator", "slotGeneration": 1,
            "creationNonceSha256": sha256(b"reference-creation-nonce"),
            "creatorTid": supervisor_pid + 1, "creatorStartTicks": "4343",
            "creatorHandshakePresent": True,
            "creatorHandshakeStatus": "valid",
            "parentIdentityVerified": True,
            "creatorPlanSha256": sha256(b"reference-creator-plan"),
            "supervisorPid": supervisor_pid,
            "supervisorStartTicks": "4242",
            "joinOwnerTid": supervisor_pid, "joinOwnerStartTicks": "4242",
            "joinOwnerTokenSha256": sha256(b"reference-join-owner-token"),
            "joinOwnerTokenRetained": True,
            "creatorCancelDisableRc": 0,
            "creatorSignalMaskRc": 0,
            "handshakeFutexValue": _creator_handshake_futex_value_v27(
                sha256(b"reference-creation-nonce")
            ),
            "handshakeFutexWakeReturn": 1,
            "handshakeFutexWaitReturn": 0,
            "handshakeFutexWaitErrno": 0,
            "failurePhase": "attr-destroy",
            "creationNoncePresent": True,
            "creatorCancelDisablePresent": True,
            "creatorPlanPresent": True,
            "creatorSignalMaskPresent": True,
            "creatorStartTicksPresent": True,
            "creatorTidPresent": True,
            "handshakeFutexPresent": True,
            "parentIdentityPresent": True,
            "supervisorPidPresent": True,
            "supervisorStartTicksPresent": True,
        },
        "abort-wake-consumed": {
            "abortStoreCount": 0 if before else 1,
            "futexWakeCount": 0 if before else 1,
            "abortDecision": "wake-abort-and-join",
            "attemptNonceSha256": sha256(b"reference-creation-nonce"),
            "slotGeneration": 1,
        },
        "abort-wake-completed": {
            "abortStoreReturn": 0, "futexWakeReturn": 0,
            "conditionBroadcastRc": 0, "slotGeneration": 1,
        },
        "abort-join-consumed": {
            "pthreadJoinCount": 0 if before else 1,
            "creatorHandleConsumed": not before,
            "joinAttemptNonceSha256": sha256(b"reference-creation-nonce"),
            "slotGeneration": 1,
        },
        "abort-failure-lifetime": {
            "pthreadJoinRc": 0, "returnSentinel": "creator-abort-sentinel",
            "creatorTaskAbsent": True, "creatorHandleConsumed": True,
            "creatorTid": supervisor_pid + 1, "creatorStartTicks": "4343",
            "creatorTidPresent": True, "creatorStartTicksPresent": True,
            "creatorHandshakeStatus": "valid", "failurePhase": "attr-destroy",
            "slotGeneration": 1,
            "payloadReleaseCount": 0,
        },
        "release-consumed-current": {
            "releaseStoreCount": 0, "futexWakeCount": 0,
        },
        "signal-attempt-consumed": {
            "releaseStoreReturn": None if before else 0,
            "futexWakeReturn": None if before else 0,
            "conditionBroadcastRc": None if before else 0,
        },
        "release-issued": {
            "releaseAuthorized": True, "releaseStoreReturn": 0,
            "futexWakeReturn": 0,
        },
        "release-known-live": {
            "releaseKnownLive": True, "creatorTaskObserved": True,
            "creatorTid": supervisor_pid + 1, "creatorStartTicks": "4343",
            "slotGeneration": 1,
            "joinOwnerTokenSha256": sha256(b"reference-join-owner-token"),
            "secondAckBarrierHeld": True,
        },
        "release-terminal": {
            "creatorHandleConsumed": False, "creatorReturnWaiting": True,
            "creatorTaskObserved": True, "creatorTid": supervisor_pid + 1,
            "creatorStartTicks": "4343", "slotGeneration": 1,
            "payloadTerminalObserved": True,
            "terminalObservationPhase": (
                "pre-terminal" if before else "terminal-waiter"
            ),
        },
        "creator-return-ready": {
            "capturePreparationSha256": sha256(b"reference-capture-preparation"),
            "atomicCaptureSha256": None,
            "postReturnObservationSha256": None,
            "creatorTid": supervisor_pid + 1, "creatorStartTicks": "4343",
            "slotGeneration": 1,
            "joinOwnerTokenSha256": sha256(b"reference-join-owner-token"),
            "returnSignalCount": 0 if before else 1,
            "pthreadJoinCount": 0,
            "pthreadJoinRc": None,
            "returnSentinel": None,
            "creatorHandleConsumed": False,
            "creatorTaskAbsent": not before,
            "departureIntentSha256": (
                sha256(b"reference-departure-intent")
            ),
            "joinAttemptNonceSha256": (
                sha256(b"reference-join-attempt")
            ),
        },
        "creator-lifetime-closed": {
            "creatorTaskAbsent": True, "proofFd7Closed": True,
            "proofFd11Closed": True, "payloadDrained": True,
            "closureFlagsSha256": sha256(b"reference-closure-flags"),
            "creatorHandleConsumed": True, "creatorTid": supervisor_pid + 1,
            "creatorStartTicks": "4343", "slotGeneration": 1,
            "joinOwnerTokenSha256": sha256(b"reference-join-owner-token"),
            "pthreadJoinRc": 0, "returnSentinel": "creator-positive-sentinel",
            "capturePreparationSha256": sha256(b"reference-capture-preparation"),
            "atomicCaptureSha256": sha256(b"reference-atomic-capture"),
            "postReturnObservationSha256": sha256(b"reference-post-return"),
            "taskSetSha256": sha256(b"reference-task-set"),
            "allocationGateHeld": before,
            "allocationGateReleaseCount": 0 if before else 1,
            "allocationGateReleaseReceiptSha256": (
                None if before else sha256(b"reference-gate-release")
            ),
            "bootIdSha256": sha256(b"reference-boot-id"),
            "captureMonotonicNs": 200,
            "capturePrepareMonotonicNs": 100,
            "captureWritersSha256": sha256(b"reference-capture-writers"),
            "creatorTaskBytesSha256": sha256(b"reference-task-bytes"),
            "joinResultSha256": sha256(b"reference-join-result"),
            "lifetimeRecordSha256": sha256(b"reference-lifetime"),
            "resultFdIdentitySha256": sha256(b"reference-result-fd"),
            "fd7GetfdErrno": errno.EBADF,
            "fd11GetfdErrno": errno.EBADF,
            "pthreadJoinCount": 1,
            "allocationGateReleaseMonotonicNs": None if before else 201,
            "creatorTidPresent": True,
            "creatorStartTicksPresent": True,
        },
        "revoke-decision": {
            "revokeAuthorized": True, "releaseNotIssued": True,
        },
        "revoke-issued": {
            "abortStoreReturn": None if before else 0,
            "futexWakeReturn": None if before else 0,
            "conditionBroadcastRc": None if before else 0,
        },
        "revoke-terminal": {
            "abortAuthorized": True,
            "creatorHandleConsumed": False,
            "creatorTaskObserved": True,
            "creatorTid": supervisor_pid + 1, "creatorStartTicks": "4343",
            "slotGeneration": 1,
        },
    }
    try:
        return _validate_native_event_observation_v27(
            event, phase, values[event]
        )
    except KeyError as exc:
        raise NativeBoundaryV27Error(
            "V27 reference native event is unknown"
        ) from exc
_LAUNCH_PRE_EFFECT_CHAIN_V27: Final = (
    ("SupervisorLaunchPreEffectFailedCurrentV1", "launch-pre-effect-failed"),
    ("SupervisorTerminalCurrentV3", "supervisor-terminal"),
)
_AUTHENTICATED_UNRESOLVED_CHAIN_V27: Final = (
    ("UnresolvedDrainPendingCurrentV1", "unresolved-drain-pending"),
    ("UnresolvedDrainProvedCurrentV3", "unresolved-drain-proved"),
    ("UnresolvedTerminalCurrentV3", "unresolved-terminal"),
)
_NONPUBLIC_RECOVERY_STATES_V27: Final = MappingProxyType(
    {
        "TakeoverKillAttemptConsumedCurrentV1": "takeover-kill-attempt-consumed",
        "NormalMissPendingCurrentV4": "normal-miss-pending",
        "NormalMissResolvedCurrentV4": "normal-miss-resolved",
        "BootChangedUnresolvedCurrentV2": "boot-changed-unresolved",
        "LateCutoffContinuationCurrentV2": "late-cutoff-continuation",
        "LateNormalPendingRawCurrentV1": "late-normal-pending-raw",
        "LateCutoffUnresolvedCurrentV3": "late-cutoff-unresolved",
        "CreatorReturnPermanentlyQuarantinedCurrentV2": (
            "creator-return-permanently-quarantined"
        ),
    }
)
_NONPUBLIC_TERMINAL_CURRENT_KINDS_V27: Final = frozenset(
    {
        "NormalMissResolvedCurrentV4",
        "LateCutoffUnresolvedCurrentV3",
        "CreatorReturnPermanentlyQuarantinedCurrentV2",
    }
)
_ACTIVE_OUTER_STATES_V27: Final = MappingProxyType(
    {
        kind: frozenset(
            state
            for chain in (
                _SUCCESS_OUTER_CHAIN_V27,
                *(_outer for _outer in _FAILURE_OUTER_PREFIX_V27.values()),
                _RESULT_HANDOFF_CHAIN_V27,
                _LAUNCH_PRE_EFFECT_CHAIN_V27,
                _AUTHENTICATED_UNRESOLVED_CHAIN_V27,
                tuple(_NONPUBLIC_RECOVERY_STATES_V27.items()),
            )
            for current_kind, state in chain
            if current_kind == kind
        )
        for kind in {
            current_kind
            for chain in (
                _SUCCESS_OUTER_CHAIN_V27,
                *(_outer for _outer in _FAILURE_OUTER_PREFIX_V27.values()),
                _RESULT_HANDOFF_CHAIN_V27,
                _LAUNCH_PRE_EFFECT_CHAIN_V27,
                _AUTHENTICATED_UNRESOLVED_CHAIN_V27,
                tuple(_NONPUBLIC_RECOVERY_STATES_V27.items()),
            )
            for current_kind, _state in chain
            if current_kind != "StageCurrentV3"
        }
    }
)


def _native_handoff_sha256_v27(observation: Mapping[str, Any]) -> str:
    """Bind native bytes while keeping controller retirement as a later receipt."""

    return sha256(
        canonical_bytes(
            {
                key: value
                for key, value in observation.items()
                if key != "controllerRetirement"
            }
        )
    )


def _outer_chain_v27(result_kind: str) -> tuple[tuple[str, str], ...]:
    if result_kind == "success":
        return _SUCCESS_OUTER_CHAIN_V27
    try:
        prefix = _FAILURE_OUTER_PREFIX_V27[result_kind]
    except KeyError as exc:
        raise NativeBoundaryV27Error("V27 stage result kind is invalid") from exc
    creation_prefix = () if result_kind == "precreate-failed" else _CREATION_CALL_PREFIX_V27
    return (
        *_COMMON_NATIVE_EVENT_PREFIX_V27,
        *creation_prefix,
        *prefix,
        *_RESULT_HANDOFF_CHAIN_V27,
    )


class _NativeOuterEventSequencerV27:
    """CAS truthful native currents before action and receipt each action after.

    The callable is deliberately carried through a ContextVar only for the
    duration of one payload-terminal runner invocation.  Production forwards
    the same two-phase events over credentialed seqpacket; tests may use the
    callable directly, but neither path can choose a current discriminator.
    """

    def __init__(
        self,
        *,
        current_path: Path,
        history: Path,
        objects: Path,
        key: bytes,
        plan: Mapping[str, Any],
        stage: LiteralStageV27,
        consumed: Mapping[str, Any],
    ) -> None:
        self.current_path = current_path
        self.history = history
        self.objects = objects
        self.key = key
        self.plan = plan
        self.stage = stage
        self.consumed_record_sha256 = str(consumed["recordSha256"])
        self.current: dict[str, Any] = dict(consumed)
        self.next_index = 0
        self.candidate_result_kinds = set(_NATIVE_EVENT_CHAINS_V27)
        self.pending: dict[str, Any] | None = None
        self.receipts: list[str] = []
        self.native_result_sha256: str | None = None
        self.result_envelope_record_sha256: str | None = None
        self.handoff_authorization_record_sha256: str | None = None
        self.handoff_receipt_record_sha256: str | None = None
        self.terminal_receipt_record_sha256: str | None = None
        self.creator_creation_intent: dict[str, Any] | None = None
        self.creator_creation_intent_record_sha256: str | None = None
        self.creator_created_receipt: dict[str, Any] | None = None
        self.creator_creation_receipt_record_sha256: str | None = None
        self.creator_join_ownership_record_sha256: str | None = None
        self.creator_return_authorization_record_sha256: str | None = None
        self.creator_return_ready_receipt_record_sha256: str | None = None
        self.native_stage_plan_sha256: str | None = None
        self.native_request_key_id: str | None = None
        self.lock = threading.Lock()

    def bind_native_stage_authority_v27(self, value: Mapping[str, Any]) -> None:
        """Bind the exact protected stage plan before accepting native events."""

        with self.lock:
            if (
                value.get("operationId") != self.plan["operationId"]
                or value.get("effectPlanSha256") != self.plan["planSha256"]
                or value.get("stageLocation") != self.stage.location
                or not isinstance(value.get("stagePlanSha256"), str)
                or not _DIGEST.fullmatch(value["stagePlanSha256"])
                or not isinstance(value.get("requestKeyId"), str)
                or not _DIGEST.fullmatch(value["requestKeyId"])
            ):
                raise NativeBoundaryV27Error(
                    "V27 native stage authority differs from outer current"
                )
            candidate = (
                str(value["stagePlanSha256"]), str(value["requestKeyId"])
            )
            existing = (
                self.native_stage_plan_sha256, self.native_request_key_id
            )
            if existing != (None, None) and existing != candidate:
                raise NativeBoundaryV27Error(
                    "V27 native stage authority was rebound"
                )
            (
                self.native_stage_plan_sha256,
                self.native_request_key_id,
            ) = candidate

    def creator_capture_binding_v27(self) -> dict[str, str] | None:
        """Expose only the controller-signed pre-return roots for the C writer."""

        with self.lock:
            if (
                self.native_stage_plan_sha256 is None
                or self.native_request_key_id is None
                or self.pending is None
                or self.pending.get("event") != "creator-return-ready"
                or self.creator_return_authorization_record_sha256 is None
                or self.current.get("kind") != "CreatorReturnReadyCurrentV2"
            ):
                return None
            exact_intents = self.pending.get("exactIntentRecordSha256s")
            if not isinstance(exact_intents, list) or len(exact_intents) != 3:
                raise NativeBoundaryV27Error(
                    "V27 creator capture intent chain changed"
                )
            return {
                "capturePreparationRecordSha256": str(exact_intents[0]),
                "returnAuthorizationRecordSha256": (
                    self.creator_return_authorization_record_sha256
                ),
                "creatorReturnCurrentRecordSha256": str(
                    self.current["recordSha256"]
                ),
            }

    def verify_creator_artifact_binding_v27(
        self, value: Any, result_kind: str
    ) -> None:
        """Reopen controller-signed roots; worker-relayed bytes are not authority."""

        fields = {
            "capturePreparationRecordSha256", "capturePreparationSha256",
            "creationNonceSha256", "creatorHandleConsumed",
            "creatorReturnCurrentRecordSha256", "joinOwnerTokenSha256",
            "operationId", "requestKeyId", "returnAuthorizationRecordSha256",
            "returnSentinel", "slotGeneration", "stageLocation",
            "stagePlanSha256", "taskSetSha256", "artifactDigests",
            "atomicCapture", "joinResult", "postReturnObservation",
            "lifetime", "gateReleaseReceipt", "creatorIdentity",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise NativeBoundaryV27Error(
                "V27 native creator artifact binding shape changed"
            )
        binding = dict(value)
        expected_sentinel = {
            "success": "creator-positive-sentinel",
            "revoke-verified-no-effect": "creator-abort-sentinel",
        }.get(result_kind)
        if (
            expected_sentinel is None
            or binding["returnSentinel"] != expected_sentinel
            or binding["creatorHandleConsumed"] is not True
            or binding["operationId"] != self.plan["operationId"]
            or binding["stageLocation"] != self.stage.location
            or binding["stagePlanSha256"] != self.native_stage_plan_sha256
            or binding["requestKeyId"] != self.native_request_key_id
            or binding["slotGeneration"] != 1
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact terminal semantics changed"
            )

        def read_object(digest: str, kind: str) -> dict[str, Any]:
            _digest(digest, f"native creator {kind} digest")
            return _read_effect_record(
                self.objects / (digest.removeprefix("sha256:") + ".json"),
                self.key,
                expected_kind=kind,
            )

        capture = read_object(
            binding["capturePreparationRecordSha256"],
            "NativePostReturnCapturePreparationV1",
        )
        authorization = read_object(
            binding["returnAuthorizationRecordSha256"],
            "CreatorReturnAuthorizationV2",
        )
        current = _read_effect_record(
            self.history
            / (
                str(binding["creatorReturnCurrentRecordSha256"])
                .removeprefix("sha256:")
                + ".json"
            ),
            self.key,
            expected_kind="CreatorReturnReadyCurrentV2",
        )
        capture_payload = capture["payload"]
        authorization_payload = authorization["payload"]
        current_payload = current["payload"]
        join_attempt = read_object(
            current_payload.get("nativeEventIntentRecordSha256"),
            "CreatorJoinAttemptV2",
        )
        departure = read_object(
            join_attempt["payload"].get("predecessorExactRecordSha256"),
            "CreatorReturnDepartureIntentV1",
        )
        if (
            capture_payload.get("operationId") != self.plan["operationId"]
            or capture_payload.get("planSha256") != self.plan["planSha256"]
            or capture_payload.get("location") != self.stage.location
            or capture_payload.get("event") != "creator-return-ready"
            or capture_payload.get("phase") != "before"
            or authorization_payload.get("operationId")
            != self.plan["operationId"]
            or authorization_payload.get("planSha256")
            != self.plan["planSha256"]
            or authorization_payload.get("location") != self.stage.location
            or authorization_payload.get("terminalKind")
            != ("positive" if result_kind == "success" else "revoke")
            or current_payload.get("operationId") != self.plan["operationId"]
            or current_payload.get("planSha256") != self.plan["planSha256"]
            or current_payload.get("location") != self.stage.location
            or current_payload.get("state") != "creator-return-ready"
            or current_payload.get("nativeEvent") != "creator-return-ready"
            or current_payload.get("nativeEventTiming") != "before-action"
            or departure["payload"].get("predecessorExactRecordSha256")
            != capture["recordSha256"]
            or join_attempt["payload"].get("returnAuthorizationRecordSha256")
            != authorization["recordSha256"]
            or departure["payload"].get("returnAuthorizationRecordSha256")
            != authorization["recordSha256"]
            or capture_payload.get("returnAuthorizationRecordSha256")
            != authorization["recordSha256"]
            or capture_payload.get("capturePreparationSha256")
            != binding["capturePreparationSha256"]
            or authorization_payload.get("capturePreparationSha256")
            != binding["capturePreparationSha256"]
            or capture_payload.get("joinOwnerTokenSha256")
            != binding["joinOwnerTokenSha256"]
            or authorization_payload.get("joinOwnerTokenSha256")
            != binding["joinOwnerTokenSha256"]
            or capture_payload.get("slotGeneration") != binding["slotGeneration"]
            or capture_payload.get("nativeStagePlanSha256")
            != binding["stagePlanSha256"]
            or authorization_payload.get("nativeStagePlanSha256")
            != binding["stagePlanSha256"]
            or capture_payload.get("nativeRequestKeyId")
            != binding["requestKeyId"]
            or authorization_payload.get("nativeRequestKeyId")
            != binding["requestKeyId"]
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact signed-root join changed"
            )
        creation_receipt = read_object(
            authorization_payload["creationReceiptRecordSha256"],
            "NativeCreatorCreationReceiptV1",
        )
        creation_payload = creation_receipt["payload"]
        if (
            creation_payload.get("operationId") != self.plan["operationId"]
            or creation_payload.get("planSha256") != self.plan["planSha256"]
            or creation_payload.get("location") != self.stage.location
            or creation_payload.get("creationNonceSha256")
            != binding["creationNonceSha256"]
            or creation_payload.get("creatorPlanSha256")
            != binding["stagePlanSha256"]
            or creation_payload.get("joinOwnerTokenSha256")
            != binding["joinOwnerTokenSha256"]
            or creation_payload.get("slotGeneration")
            != binding["slotGeneration"]
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact creation receipt changed"
            )
        exact_artifacts: dict[str, list[dict[str, Any]]] = {
            kind: []
            for kind in (
                "NativePostReturnAtomicCaptureV1", "CreatorJoinResultV2",
                "CreatorPostReturnObservationV2",
                "CreatorThreadLifetimeReceiptV4",
                "NativeAllocationGateReleaseReceiptV1",
            )
        }
        for candidate_path in sorted(self.objects.glob("*.json")):
            candidate = _read_effect_record(candidate_path, self.key)
            payload = candidate.get("payload", {})
            if (
                candidate.get("kind") in exact_artifacts
                and payload.get("operationId") == self.plan["operationId"]
                and payload.get("location") == self.stage.location
                and payload.get("event") == "creator-lifetime-closed"
            ):
                exact_artifacts[str(candidate["kind"])].append(candidate)
        if any(len(items) != 1 for items in exact_artifacts.values()):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact lacks one exact signed chain"
            )
        atomic = exact_artifacts["NativePostReturnAtomicCaptureV1"][0]
        join_result = exact_artifacts["CreatorJoinResultV2"][0]
        post_return = exact_artifacts["CreatorPostReturnObservationV2"][0]
        lifetime = exact_artifacts["CreatorThreadLifetimeReceiptV4"][0]
        gate_release = exact_artifacts[
            "NativeAllocationGateReleaseReceiptV1"
        ][0]
        signed_chain = (atomic, join_result, post_return, lifetime, gate_release)
        if any(
            signed_chain[index]["payload"].get(
                "predecessorExactRecordSha256"
            ) != signed_chain[index - 1]["recordSha256"]
            for index in range(1, len(signed_chain))
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator signed artifact predecessor changed"
            )
        before = atomic["payload"]
        after = gate_release["payload"]
        if (
            before.get("phase") != "before"
            or before.get("returnSentinel") != expected_sentinel
            or after.get("returnSentinel") != expected_sentinel
            or before.get("capturePreparationSha256")
            != binding["capturePreparationSha256"]
            or before.get("joinOwnerTokenSha256")
            != binding["joinOwnerTokenSha256"]
            or before.get("taskSetSha256") != binding["taskSetSha256"]
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator signed security root changed"
            )

        expected_digests = [
            before.get("atomicCaptureSha256"),
            before.get("joinResultSha256"),
            before.get("postReturnObservationSha256"),
            before.get("lifetimeRecordSha256"),
            after.get("allocationGateReleaseReceiptSha256"),
        ]
        if binding["artifactDigests"] != expected_digests:
            raise NativeBoundaryV27Error(
                "V27 native creator artifact byte digests changed"
            )
        atomic_payload = binding["atomicCapture"]
        join_payload = binding["joinResult"]
        post_payload = binding["postReturnObservation"]
        lifetime_payload = binding["lifetime"]
        gate_payload = binding["gateReleaseReceipt"]
        expected_atomic = {
            "allocationGateHeld": before.get("allocationGateHeld"),
            "bootIdSha256": before.get("bootIdSha256"),
            "captureMonotonicNs": before.get("captureMonotonicNs"),
            "capturePreparationSha256": before.get(
                "capturePreparationSha256"
            ),
            "capturePrepareMonotonicNs": before.get(
                "capturePrepareMonotonicNs"
            ),
            "captureWritersSha256": before.get("captureWritersSha256"),
            "creatorStartTicks": before.get("creatorStartTicks"),
            "creatorTaskBytesSha256": before.get(
                "creatorTaskBytesSha256"
            ),
            "creatorTid": before.get("creatorTid"),
            "fd11GetfdErrno": before.get("fd11GetfdErrno"),
            "fd7GetfdErrno": before.get("fd7GetfdErrno"),
            "joinOwnerTokenSha256": before.get("joinOwnerTokenSha256"),
            "pthreadJoinRc": before.get("pthreadJoinRc"),
            "resultFdIdentitySha256": before.get(
                "resultFdIdentitySha256"
            ),
            "returnSentinel": before.get("returnSentinel"),
            "slotGeneration": before.get("slotGeneration"),
            "taskSetSha256": before.get("taskSetSha256"),
        }
        expected_join = {
            "atomicCaptureSha256": before.get("atomicCaptureSha256"),
            "creatorHandleConsumed": before.get("creatorHandleConsumed"),
            "joinOwnerTokenSha256": before.get("joinOwnerTokenSha256"),
            "pthreadJoinCount": before.get("pthreadJoinCount"),
            "pthreadJoinRc": before.get("pthreadJoinRc"),
            "returnSentinel": before.get("returnSentinel"),
            "slotGeneration": before.get("slotGeneration"),
        }
        expected_post = {
            "atomicCaptureSha256": before.get("atomicCaptureSha256"),
            "capturePreparationSha256": before.get(
                "capturePreparationSha256"
            ),
            "creatorHandleConsumed": before.get("creatorHandleConsumed"),
            "joinResultSha256": before.get("joinResultSha256"),
            "taskSetSha256": before.get("taskSetSha256"),
        }
        expected_lifetime = {
            "allocationGateHeld": before.get("allocationGateHeld"),
            "atomicCaptureSha256": before.get("atomicCaptureSha256"),
            "creatorHandleConsumed": before.get("creatorHandleConsumed"),
            "creatorTaskAbsent": before.get("creatorTaskAbsent"),
            "joinResultSha256": before.get("joinResultSha256"),
            "postReturnObservationSha256": before.get(
                "postReturnObservationSha256"
            ),
            "proofFd11Closed": before.get("proofFd11Closed"),
            "proofFd7Closed": before.get("proofFd7Closed"),
            "pthreadJoinRc": before.get("pthreadJoinRc"),
            "returnSentinel": before.get("returnSentinel"),
        }
        expected_gate = {
            "allocationGateHeld": after.get("allocationGateHeld"),
            "allocationGateReleaseCount": after.get(
                "allocationGateReleaseCount"
            ),
            "lifetimeSha256": after.get("lifetimeRecordSha256"),
            "releaseMonotonicNs": after.get(
                "allocationGateReleaseMonotonicNs"
            ),
        }
        if (
            binding["creatorIdentity"] != {
                "creatorTidPresent": before.get("creatorTidPresent"),
                "creatorTid": before.get("creatorTid"),
                "creatorStartTicksPresent": before.get(
                    "creatorStartTicksPresent"
                ),
                "creatorStartTicks": before.get("creatorStartTicks"),
            }
            or
            atomic_payload != expected_atomic
            or join_payload != expected_join
            or post_payload != expected_post
            or lifetime_payload != expected_lifetime
            or gate_payload != expected_gate
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact security projection changed"
            )

    def _validate_creator_continuity_v27(
        self, event: str, phase: str, observation: Mapping[str, Any]
    ) -> None:
        """Join every creator event to one slot, owner token, and task identity."""

        data = dict(observation)
        if event == "creator-creation-consumed":
            if phase == "before":
                self.creator_creation_intent = data
            elif self.creator_creation_intent != data:
                raise NativeBoundaryV27Error(
                    "V27 creator creation intent changed across its gate"
                )
            return
        intent = self.creator_creation_intent
        if event in {
            "supervisor-create-failed-no-thread", "native-creator-created",
            "creator-status-uncertain", "abort-wake-consumed",
            "abort-wake-completed", "abort-join-consumed",
            "abort-failure-lifetime", "release-known-live",
            "release-terminal", "creator-return-ready",
            "creator-lifetime-closed", "revoke-terminal",
        } and intent is None:
            raise NativeBoundaryV27Error(
                "V27 creator event lacks its creation intent"
            )
        if intent is not None:
            for field in ("slotGeneration",):
                if field in data and data[field] != intent[field]:
                    raise NativeBoundaryV27Error(
                        f"V27 creator {field} changed across the native lifetime"
                    )
            if (
                "creationNonceSha256" in data
                and data.get("creationNoncePresent", True)
                and (
                    data["creationNonceSha256"]
                    == intent["creationNonceSha256"]
                )
                is (
                    data.get("creatorHandshakeStatus")
                    == "creation-nonce-echo-failed"
                )
            ):
                raise NativeBoundaryV27Error(
                    "V27 creator nonce echo does not match its discriminant"
                )
            if (
                event in {"native-creator-created", "creator-status-uncertain"}
                and data.get("handshakeFutexPresent") is True
                and data.get("handshakeFutexValue")
                != _creator_handshake_futex_value_v27(
                    intent["creationNonceSha256"]
                )
            ):
                raise NativeBoundaryV27Error(
                    "V27 creator handshake futex token changed"
                )
            if (
                event in {"native-creator-created", "creator-status-uncertain"}
                and data.get("creatorPlanPresent") is True
                and (
                    data.get("creatorPlanSha256") == intent["creatorPlanSha256"]
                )
                is (
                    data.get("creatorHandshakeStatus")
                    == "plan-digest-echo-failed"
                )
            ):
                raise NativeBoundaryV27Error(
                    "V27 creator plan echo does not match its discriminant"
                )
            for field in ("joinOwnerTid", "joinOwnerStartTicks"):
                if field in data and data[field] != intent[field]:
                    raise NativeBoundaryV27Error(
                        f"V27 creator {field} changed across the native lifetime"
                    )
        if event in {"native-creator-created", "creator-status-uncertain"}:
            if phase == "before":
                self.creator_created_receipt = data
            elif self.creator_created_receipt != data:
                raise NativeBoundaryV27Error(
                    "V27 creator creation receipt changed across its gate"
                )
        created = self.creator_created_receipt
        if created is not None and event in {
            "abort-failure-lifetime",
            "release-known-live", "release-terminal", "creator-return-ready",
            "creator-lifetime-closed", "revoke-terminal",
        }:
            presence = {
                "creatorTid": "creatorTidPresent",
                "creatorStartTicks": "creatorStartTicksPresent",
            }
            for field in ("creatorTid", "creatorStartTicks", "slotGeneration"):
                if (
                    field in presence
                    and created.get(presence[field]) is not True
                ):
                    continue
                if data[field] != created[field]:
                    raise NativeBoundaryV27Error(
                        f"V27 creator {field} changed after creation receipt"
                    )
            if event == "abort-failure-lifetime" and (
                data["creatorTidPresent"]
                is not created["creatorTidPresent"]
                or data["creatorStartTicksPresent"]
                is not created["creatorStartTicksPresent"]
                or data["creatorHandshakeStatus"]
                != created["creatorHandshakeStatus"]
                or data["failurePhase"] != created["failurePhase"]
            ):
                raise NativeBoundaryV27Error(
                    "V27 abort lifetime handshake discriminant changed"
                )
            if (
                "joinOwnerTokenSha256" in data
                and data["joinOwnerTokenSha256"]
                != created["joinOwnerTokenSha256"]
            ):
                raise NativeBoundaryV27Error(
                    "V27 creator join-owner token changed after creation receipt"
                )

    def __call__(
        self,
        event: str,
        phase: str,
        evidence_sha256: str,
        observation: Mapping[str, Any],
    ) -> str:
        _digest(evidence_sha256, "native outer event evidenceSha256")
        event_observation = _validate_native_event_observation_v27(
            event, phase, observation
        )
        with self.lock:
            self._validate_creator_continuity_v27(
                event, phase, event_observation
            )
            if phase == "before":
                if self.pending is not None:
                    raise NativeBoundaryV27Error(
                        "V27 native outer event was reordered or replayed"
                    )
                matching = {
                    result_kind
                    for result_kind in self.candidate_result_kinds
                    if self.next_index < len(_NATIVE_EVENT_CHAINS_V27[result_kind])
                    and _NATIVE_EVENT_CHAINS_V27[result_kind][self.next_index][1]
                    == event
                }
                kinds = {
                    _NATIVE_EVENT_CHAINS_V27[result_kind][self.next_index][0]
                    for result_kind in matching
                }
                if not matching or len(kinds) != 1:
                    raise NativeBoundaryV27Error(
                        "V27 native outer event differs from the literal chain"
                    )
                self.candidate_result_kinds = matching
                kind = next(iter(kinds))
                predecessor = self.current
                decision_record_sha256: str | None = None
                return_authorization_record_sha256: str | None = None
                if event == "abort-wake-consumed":
                    decision = _effect_sign(
                        "CreatorAbortWakeDecisionV1",
                        {
                            "schemaVersion": 27,
                            "profile": PROFILE,
                            "operationId": self.plan["operationId"],
                            "planSha256": self.plan["planSha256"],
                            "location": self.stage.location,
                            "decision": "wake-abort-and-join",
                            "slotGeneration": event_observation["slotGeneration"],
                            "attemptNonceSha256": event_observation[
                                "attemptNonceSha256"
                            ],
                            "predecessorCurrentRecordSha256": predecessor[
                                "recordSha256"
                            ],
                        },
                        self.key,
                    )
                    _publish_effect_object(
                        self.objects
                        / (
                            str(decision["recordSha256"]).removeprefix(
                                "sha256:"
                            )
                            + ".json"
                        ),
                        decision,
                        self.key,
                        phase=(
                            f"location-{self.stage.location}-native-event-"
                            f"{event}-decision"
                        ),
                    )
                    decision_record_sha256 = str(decision["recordSha256"])
                if event == "creator-return-ready":
                    if (
                        self.creator_creation_receipt_record_sha256 is None
                        or self.creator_join_ownership_record_sha256 is None
                    ):
                        raise NativeBoundaryV27Error(
                            "V27 creator return lacks creation/ownership receipts"
                        )
                    return_terminal_kind = (
                        "revoke"
                        if self.candidate_result_kinds
                        == {"revoke-verified-no-effect"}
                        else "positive"
                    )
                    return_authorization = _effect_sign(
                        "CreatorReturnAuthorizationV2",
                        {
                            "schemaVersion": 27,
                            "profile": PROFILE,
                            "operationId": self.plan["operationId"],
                            "operationClass": self.plan["operationClass"],
                            "planSha256": self.plan["planSha256"],
                            "location": self.stage.location,
                            "stageKey": self.stage.stage_key,
                            "terminalKind": return_terminal_kind,
                            "terminalCurrentRecordSha256": predecessor[
                                "recordSha256"
                            ],
                            "creationReceiptRecordSha256": (
                                self.creator_creation_receipt_record_sha256
                            ),
                            "joinOwnershipReceiptRecordSha256": (
                                self.creator_join_ownership_record_sha256
                            ),
                            "capturePreparationSha256": event_observation[
                                "capturePreparationSha256"
                            ],
                            "nativeStagePlanSha256": (
                                self.native_stage_plan_sha256
                            ),
                            "nativeRequestKeyId": self.native_request_key_id,
                            "creatorTid": event_observation["creatorTid"],
                            "creatorStartTicks": event_observation[
                                "creatorStartTicks"
                            ],
                            "slotGeneration": event_observation[
                                "slotGeneration"
                            ],
                            "joinOwnerTokenSha256": event_observation[
                                "joinOwnerTokenSha256"
                            ],
                            "authorizationDisposition": (
                                "ready-to-return-on-winning-current"
                            ),
                        },
                        self.key,
                    )
                    _publish_effect_object(
                        self.objects
                        / (
                            str(return_authorization["recordSha256"])
                            .removeprefix("sha256:")
                            + ".json"
                        ),
                        return_authorization,
                        self.key,
                        phase=(
                            f"location-{self.stage.location}-native-event-"
                            f"{event}-CreatorReturnAuthorizationV2"
                        ),
                    )
                    return_authorization_record_sha256 = str(
                        return_authorization["recordSha256"]
                    )
                    self.creator_return_authorization_record_sha256 = (
                        return_authorization_record_sha256
                    )
                intent_kinds = _NATIVE_EXACT_INTENT_KINDS_V27.get(
                    event, ("NativeOuterEventIntentV1",)
                )
                intent: dict[str, Any] | None = None
                exact_intent_predecessor: str | None = None
                exact_intent_record_sha256s: list[str] = []
                for intent_kind in intent_kinds:
                    intent_payload: dict[str, Any] = {
                        "schemaVersion": 27,
                        "profile": PROFILE,
                        "operationId": self.plan["operationId"],
                        "operationClass": self.plan["operationClass"],
                        "planSha256": self.plan["planSha256"],
                        "location": self.stage.location,
                        "stageKey": self.stage.stage_key,
                        "sequence": self.next_index + 1,
                        "event": event,
                        "phase": "before",
                        "eventObservation": event_observation,
                        "eventEvidenceSha256": evidence_sha256,
                        "predecessorCurrentRecordSha256": predecessor[
                            "recordSha256"
                        ],
                        "currentTiming": (
                            "before-action"
                            if event in _NATIVE_PRE_ACTION_CURRENT_EVENTS_V27
                            else "after-outcome"
                        ),
                        "decisionRecordSha256": decision_record_sha256,
                        "returnAuthorizationRecordSha256": (
                            return_authorization_record_sha256
                        ),
                        **(
                            dict(event_observation)
                            if event in _NATIVE_EXACT_INTENT_KINDS_V27
                            else {}
                        ),
                    }
                    if exact_intent_predecessor is not None:
                        intent_payload["predecessorExactRecordSha256"] = (
                            exact_intent_predecessor
                        )
                    if event == "creator-return-ready":
                        intent_payload["returnAuthorizationRecordSha256"] = (
                            self.creator_return_authorization_record_sha256
                        )
                        intent_payload["nativeStagePlanSha256"] = (
                            self.native_stage_plan_sha256
                        )
                        intent_payload["nativeRequestKeyId"] = (
                            self.native_request_key_id
                        )
                        if intent_kind == "CreatorJoinAttemptV2":
                            intent_payload["joinCountMax"] = 1
                    intent = _effect_sign(intent_kind, intent_payload, self.key)
                    _publish_effect_object(
                        self.objects
                        / (
                            str(intent["recordSha256"]).removeprefix("sha256:")
                            + ".json"
                        ),
                        intent,
                        self.key,
                        phase=(
                            f"location-{self.stage.location}-native-event-"
                            f"{event}-{intent_kind}"
                        ),
                    )
                    exact_intent_predecessor = str(intent["recordSha256"])
                    exact_intent_record_sha256s.append(exact_intent_predecessor)
                    if intent_kind == "NativeCreatorCreationIntentV1":
                        self.creator_creation_intent_record_sha256 = (
                            exact_intent_predecessor
                        )
                assert intent is not None
                before_exact_outcome_record_sha256s: list[str] = []
                if event in _NATIVE_EXACT_BEFORE_OUTCOME_KINDS_V27:
                    if self.creator_return_ready_receipt_record_sha256 is None:
                        raise NativeBoundaryV27Error(
                            "V27 held creator capture lacks return-ready receipt"
                        )
                    held_predecessor = (
                        self.creator_return_ready_receipt_record_sha256
                    )
                    for held_kind in _NATIVE_EXACT_BEFORE_OUTCOME_KINDS_V27[
                        event
                    ]:
                        held_payload: dict[str, Any] = {
                            "schemaVersion": 27,
                            "profile": PROFILE,
                            "operationId": self.plan["operationId"],
                            "operationClass": self.plan["operationClass"],
                            "planSha256": self.plan["planSha256"],
                            "location": self.stage.location,
                            "stageKey": self.stage.stage_key,
                            "event": event,
                            "phase": "before",
                            "intentRecordSha256": intent["recordSha256"],
                            "predecessorExactRecordSha256": held_predecessor,
                            "creatorReturnReadyReceiptRecordSha256": (
                                self.creator_return_ready_receipt_record_sha256
                            ),
                            "eventEvidenceSha256": evidence_sha256,
                            **dict(event_observation),
                        }
                        if held_kind == "CreatorThreadLifetimeReceiptV4":
                            held_payload["terminalKind"] = (
                                "positive"
                                if event_observation["returnSentinel"]
                                == "creator-positive-sentinel"
                                else "revoke"
                            )
                        held_record = _effect_sign(
                            held_kind, held_payload, self.key
                        )
                        _publish_effect_object(
                            self.objects
                            / (
                                str(held_record["recordSha256"])
                                .removeprefix("sha256:")
                                + ".json"
                            ),
                            held_record,
                            self.key,
                            phase=(
                                f"location-{self.stage.location}-native-event-"
                                f"{event}-{held_kind}"
                            ),
                        )
                        held_predecessor = str(held_record["recordSha256"])
                        before_exact_outcome_record_sha256s.append(
                            held_predecessor
                        )
                if event in _NATIVE_PRE_ACTION_CURRENT_EVENTS_V27:
                    self.current = _install_effect_current_kind_v27(
                        self.current_path,
                        self.history,
                        self.key,
                        kind,
                        _outer_current_payload_v27(
                            self.plan,
                            self.stage,
                            state=event,
                            predecessor=predecessor,
                            consumed_record_sha256=self.consumed_record_sha256,
                            result=None,
                            result_kind=None,
                            failure_evidence_sha256=None,
                            native_event_binding={
                                "nativeEventSequence": self.next_index + 1,
                                "nativeEvent": event,
                                "nativeEventTiming": "before-action",
                                "nativeEventIntentRecordSha256": intent[
                                    "recordSha256"
                                ],
                                "nativeEventBeforeEvidenceSha256": (
                                    evidence_sha256
                                ),
                                "nativeEventBeforeObservationSha256": sha256(
                                    canonical_bytes(event_observation)
                                ),
                                "nativeEventAfterEvidenceSha256": None,
                                "nativeEventAfterObservationSha256": None,
                                "nativeExactOutcomeRecordSha256": None,
                                "nativeExactAuxiliaryRecordSha256": None,
                            },
                        ),
                        expected=predecessor,
                    )
                    authority_record_sha256 = str(self.current["recordSha256"])
                else:
                    authority_record_sha256 = str(intent["recordSha256"])
                self.pending = {
                    "event": event,
                    "kind": kind,
                    "intentRecordSha256": intent["recordSha256"],
                    "beforeEvidenceSha256": evidence_sha256,
                    "beforeObservation": event_observation,
                    "predecessorCurrentRecordSha256": predecessor[
                        "recordSha256"
                    ],
                    "authorizationRecordSha256": authority_record_sha256,
                    "exactIntentRecordSha256s": exact_intent_record_sha256s,
                    "beforeExactOutcomeRecordSha256s": (
                        before_exact_outcome_record_sha256s
                    ),
                }
                _effect_fault(
                    f"location-{self.stage.location}-native-event-{event}-authorized"
                )
                return authority_record_sha256
            if phase != "after" or self.pending is None:
                raise NativeBoundaryV27Error(
                    "V27 native outer event receipt has no authorization"
                )
            pending = dict(self.pending)
            if event != pending["event"]:
                raise NativeBoundaryV27Error(
                    "V27 native outer event receipt changed its authorization"
                )
            exact_outcome_record_sha256s: list[str] = list(
                pending["beforeExactOutcomeRecordSha256s"]
            )
            exact_predecessor = (
                exact_outcome_record_sha256s[-1]
                if exact_outcome_record_sha256s
                else str(pending["intentRecordSha256"])
            )
            for exact_kind in _NATIVE_EXACT_OUTCOME_KINDS_V27.get(event, ()):
                exact_payload: dict[str, Any] = {
                    "schemaVersion": 27,
                    "profile": PROFILE,
                    "operationId": self.plan["operationId"],
                    "operationClass": self.plan["operationClass"],
                    "planSha256": self.plan["planSha256"],
                    "location": self.stage.location,
                    "stageKey": self.stage.stage_key,
                    "event": event,
                    "intentRecordSha256": pending["intentRecordSha256"],
                    "predecessorExactRecordSha256": exact_predecessor,
                    "eventEvidenceSha256": evidence_sha256,
                    **dict(event_observation),
                }
                if event == "creator-return-ready":
                    exact_payload["returnAuthorizationRecordSha256"] = (
                        self.creator_return_authorization_record_sha256
                    )
                    exact_payload["capturePreparationRecordSha256"] = pending[
                        "intentRecordSha256"
                    ]
                    if exact_kind == "CreatorJoinAttemptV2":
                        exact_payload["joinCountMax"] = 1
                if event == "creator-lifetime-closed":
                    if self.creator_return_ready_receipt_record_sha256 is None:
                        raise NativeBoundaryV27Error(
                            "V27 creator lifetime lacks departure/join attempt receipt"
                        )
                    exact_payload["creatorReturnReadyReceiptRecordSha256"] = (
                        self.creator_return_ready_receipt_record_sha256
                    )
                if exact_kind == "NativeCreatorCreationReceiptV1":
                    if self.creator_creation_intent_record_sha256 is None:
                        raise NativeBoundaryV27Error(
                            "V27 creator creation receipt lacks its direct intent"
                        )
                    exact_payload["intentRecordSha256"] = (
                        self.creator_creation_intent_record_sha256
                    )
                if exact_kind == "NativeCreatorJoinOwnershipReceiptV1":
                    exact_payload.update(
                        {
                            "ownershipKind": "creation-caller-retains",
                            "transferCount": 0,
                            "joinHandleDisposition": (
                                "opaque-same-live-retained"
                            ),
                        }
                    )
                if exact_kind == "CreatorThreadLifetimeReceiptV4":
                    exact_payload["terminalKind"] = (
                        "positive"
                        if event_observation["returnSentinel"]
                        == "creator-positive-sentinel"
                        else "revoke"
                    )
                exact_record = _effect_sign(exact_kind, exact_payload, self.key)
                _publish_effect_object(
                    self.objects
                    / (
                        str(exact_record["recordSha256"]).removeprefix(
                            "sha256:"
                        )
                        + ".json"
                    ),
                    exact_record,
                    self.key,
                    phase=(
                        f"location-{self.stage.location}-native-event-{event}-"
                        f"{exact_kind}"
                    ),
                )
                exact_predecessor = str(exact_record["recordSha256"])
                exact_outcome_record_sha256s.append(exact_predecessor)
                if exact_kind == "NativeCreatorCreationReceiptV1":
                    self.creator_creation_receipt_record_sha256 = exact_predecessor
                if exact_kind == "NativeCreatorJoinOwnershipReceiptV1":
                    self.creator_join_ownership_record_sha256 = exact_predecessor
            if event not in _NATIVE_PRE_ACTION_CURRENT_EVENTS_V27:
                predecessor = self.current
                if predecessor["recordSha256"] != pending[
                    "predecessorCurrentRecordSha256"
                ]:
                    raise NativeBoundaryV27Error(
                        "V27 post-outcome current predecessor changed"
                    )
                self.current = _install_effect_current_kind_v27(
                    self.current_path,
                    self.history,
                    self.key,
                    str(pending["kind"]),
                    _outer_current_payload_v27(
                        self.plan,
                        self.stage,
                        state=event,
                        predecessor=predecessor,
                        consumed_record_sha256=self.consumed_record_sha256,
                        result=None,
                        result_kind=None,
                        failure_evidence_sha256=None,
                        native_event_binding={
                            "nativeEventSequence": self.next_index + 1,
                            "nativeEvent": event,
                            "nativeEventTiming": "after-outcome",
                            "nativeEventIntentRecordSha256": pending[
                                "intentRecordSha256"
                            ],
                            "nativeEventBeforeEvidenceSha256": pending[
                                "beforeEvidenceSha256"
                            ],
                            "nativeEventBeforeObservationSha256": sha256(
                                canonical_bytes(pending["beforeObservation"])
                            ),
                            "nativeEventAfterEvidenceSha256": evidence_sha256,
                            "nativeEventAfterObservationSha256": sha256(
                                canonical_bytes(event_observation)
                            ),
                            "nativeExactOutcomeRecordSha256": (
                                None
                                if not exact_outcome_record_sha256s
                                else exact_outcome_record_sha256s[0]
                            ),
                            "nativeExactAuxiliaryRecordSha256": (
                                None
                                if len(exact_outcome_record_sha256s) < 2
                                else exact_outcome_record_sha256s[-1]
                            ),
                        },
                    ),
                    expected=predecessor,
                )
            receipt = _effect_sign(
                "NativeOuterEventReceiptV1",
                {
                    "schemaVersion": 27,
                    "profile": PROFILE,
                    "operationId": self.plan["operationId"],
                    "operationClass": self.plan["operationClass"],
                    "planSha256": self.plan["planSha256"],
                    "location": self.stage.location,
                    "stageKey": self.stage.stage_key,
                    "sequence": self.next_index + 1,
                    "event": event,
                    "phase": "after",
                    "currentTiming": (
                        "before-action"
                        if event in _NATIVE_PRE_ACTION_CURRENT_EVENTS_V27
                        else "after-outcome"
                    ),
                    "intentRecordSha256": pending["intentRecordSha256"],
                    "authorizationRecordSha256": pending[
                        "authorizationRecordSha256"
                    ],
                    "actionCurrentRecordSha256": self.current[
                        "recordSha256"
                    ],
                    "beforeEvidenceSha256": pending[
                        "beforeEvidenceSha256"
                    ],
                    "afterEvidenceSha256": evidence_sha256,
                    "beforeObservation": pending["beforeObservation"],
                    "afterObservation": event_observation,
                    "predecessorReceiptRecordSha256": (
                        None if not self.receipts else self.receipts[-1]
                    ),
                    "exactOutcomeRecordSha256s": exact_outcome_record_sha256s,
                },
                self.key,
            )
            receipt_path = self.objects / (
                str(receipt["recordSha256"]).removeprefix("sha256:") + ".json"
            )
            _publish_effect_object(
                receipt_path,
                receipt,
                self.key,
                phase=(
                    f"location-{self.stage.location}-native-event-{event}-receipt"
                ),
            )
            self.receipts.append(str(receipt["recordSha256"]))
            if event == "creator-return-ready":
                self.creator_return_ready_receipt_record_sha256 = str(
                    receipt["recordSha256"]
                )
            self.pending = None
            self.next_index += 1
            _effect_fault(
                f"location-{self.stage.location}-native-event-{event}-receipted"
            )
            return str(receipt["recordSha256"])

    def require_complete(self, result_kind: str) -> dict[str, Any]:
        with self.lock:
            if (
                self.pending is not None
                or result_kind not in self.candidate_result_kinds
                or self.next_index != len(_NATIVE_EVENT_CHAINS_V27[result_kind])
                or self.current.get("kind") != "SupervisorTerminalCurrentV3"
                or self.native_result_sha256 is None
                or self.handoff_receipt_record_sha256 is None
                or self.terminal_receipt_record_sha256 is None
            ):
                raise NativeBoundaryV27Error(
                    "V27 native supervisor omitted a required causal event"
                )
            return dict(self.current)

    def authorize_result_offer(self, observation: Mapping[str, Any]) -> str:
        """Persist the result envelope and consume one handoff authorization."""

        with self.lock:
            result_kind = str(observation.get("resultKind"))
            if (
                self.pending is not None
                or result_kind not in self.candidate_result_kinds
                or self.next_index != len(_NATIVE_EVENT_CHAINS_V27[result_kind])
                or self.native_result_sha256 is not None
            ):
                raise NativeBoundaryV27Error(
                    "V27 native result offer preceded its exact causal prefix"
                )
            offered_sha256 = observation.get("nativeResultSha256")
            if offered_sha256 is None:
                native_result_sha256 = _native_handoff_sha256_v27(observation)
            else:
                _digest(offered_sha256, "nativeResultSha256")
                native_result_sha256 = str(offered_sha256)
            predecessor_kind = str(observation.get("resultPredecessorKind"))
            failure_evidence = observation.get("failureEvidenceSha256")
            validate_result_envelope_v4(
                {
                    "resultKind": result_kind,
                    "predecessorKind": predecessor_kind,
                    "failureEvidenceSha256": failure_evidence,
                }
            )
            envelope = _effect_sign(
                "SupervisorResultEnvelopeV4",
                {
                    "schemaVersion": 27,
                    "profile": PROFILE,
                    "operationId": self.plan["operationId"],
                    "operationClass": self.plan["operationClass"],
                    "planSha256": self.plan["planSha256"],
                    "location": self.stage.location,
                    "stageKey": self.stage.stage_key,
                    "stageKind": self.stage.stage_kind,
                    "actionKind": self.stage.action_kind,
                    "resultKind": result_kind,
                    "predecessorKind": predecessor_kind,
                    "failureEvidenceSha256": failure_evidence,
                    "nativeResultSha256": native_result_sha256,
                },
                self.key,
            )
            _publish_effect_object(
                self.objects
                / f"{str(envelope['recordSha256']).removeprefix('sha256:')}.json",
                envelope,
                self.key,
                phase=f"location-{self.stage.location}-result-envelope",
            )
            predecessor = self.current
            envelope_payload = {
                **_outer_current_payload_v27(
                    self.plan,
                    self.stage,
                    state="result-envelope-stored",
                    predecessor=predecessor,
                    consumed_record_sha256=self.consumed_record_sha256,
                    result=None,
                    result_kind=result_kind,
                    failure_evidence_sha256=failure_evidence,
                    result_envelope_record_sha256=str(envelope["recordSha256"]),
                ),
                "nativeResultSha256": native_result_sha256,
                "handoffAuthorizationRecordSha256": None,
                "handoffReceiptRecordSha256": None,
                "terminalReceiptRecordSha256": None,
            }
            envelope_current_candidate = _effect_sign(
                "SupervisorResultEnvelopeStoredCurrentV4",
                envelope_payload,
                self.key,
            )
            authorization = _effect_sign(
                "SupervisorResultHandoffAuthorizationV1",
                {
                    "schemaVersion": 27,
                    "profile": PROFILE,
                    "operationId": self.plan["operationId"],
                    "location": self.stage.location,
                    "nativeResultSha256": native_result_sha256,
                    "resultEnvelopeRecordSha256": envelope["recordSha256"],
                    "authorizationCurrentRecordSha256": envelope_current_candidate[
                        "recordSha256"
                    ],
                },
                self.key,
            )
            _publish_effect_object(
                self.objects
                / f"{str(authorization['recordSha256']).removeprefix('sha256:')}.json",
                authorization,
                self.key,
                phase=f"location-{self.stage.location}-result-handoff-authorization",
            )
            self.current = _install_effect_current_kind_v27(
                self.current_path,
                self.history,
                self.key,
                "SupervisorResultEnvelopeStoredCurrentV4",
                envelope_payload,
                expected=predecessor,
            )
            if (
                self.current["recordSha256"]
                != envelope_current_candidate["recordSha256"]
            ):
                raise NativeBoundaryV27Error(
                    "V27 result-envelope current candidate changed"
                )
            predecessor = self.current
            attempt_payload = {
                **envelope_payload,
                "generation": int(predecessor["payload"]["generation"]) + 1,
                "state": "result-handoff-consumed",
                "predecessorRecordSha256": predecessor["recordSha256"],
                "handoffAuthorizationRecordSha256": authorization[
                    "recordSha256"
                ],
            }
            self.current = _install_effect_current_kind_v27(
                self.current_path,
                self.history,
                self.key,
                "SupervisorResultHandoffAttemptConsumedCurrentV4",
                attempt_payload,
                expected=predecessor,
            )
            self.native_result_sha256 = native_result_sha256
            self.result_envelope_record_sha256 = str(envelope["recordSha256"])
            self.handoff_authorization_record_sha256 = str(
                authorization["recordSha256"]
            )
            return str(self.current["recordSha256"])

    def receipt_result_handoff(self, observation: Mapping[str, Any]) -> str:
        """Receipt the exact offered bytes only after their credentialed send."""

        with self.lock:
            observed_sha256 = _native_handoff_sha256_v27(observation)
            if (
                self.current.get("kind")
                != "SupervisorResultHandoffAttemptConsumedCurrentV4"
                or observed_sha256 != self.native_result_sha256
                or self.handoff_authorization_record_sha256 is None
            ):
                raise NativeBoundaryV27Error(
                    "V27 result handoff receipt differs from its one-use offer"
                )
            receipt = _effect_sign(
                "SupervisorResultHandoffReceiptV1",
                {
                    "schemaVersion": 27,
                    "profile": PROFILE,
                    "operationId": self.plan["operationId"],
                    "location": self.stage.location,
                    "nativeResultSha256": observed_sha256,
                    "handoffAuthorizationRecordSha256": self.handoff_authorization_record_sha256,
                    "handoffAttemptCurrentRecordSha256": self.current[
                        "recordSha256"
                    ],
                },
                self.key,
            )
            _publish_effect_object(
                self.objects
                / f"{str(receipt['recordSha256']).removeprefix('sha256:')}.json",
                receipt,
                self.key,
                phase=f"location-{self.stage.location}-result-handoff-receipt",
            )
            predecessor = self.current
            payload = {
                **dict(predecessor["payload"]),
                "generation": int(predecessor["payload"]["generation"]) + 1,
                "state": "result-handoff-receipted",
                "predecessorRecordSha256": predecessor["recordSha256"],
                "handoffReceiptRecordSha256": receipt["recordSha256"],
            }
            self.current = _install_effect_current_kind_v27(
                self.current_path,
                self.history,
                self.key,
                "SupervisorResultHandoffReceiptedCurrentV4",
                payload,
                expected=predecessor,
            )
            self.handoff_receipt_record_sha256 = str(receipt["recordSha256"])
            return str(self.current["recordSha256"])

    def terminalize_result_handoff(self, retirement: Mapping[str, Any]) -> str:
        """Store a distinct retirement-bound terminal receipt before Terminal."""

        with self.lock:
            if (
                self.current.get("kind")
                != "SupervisorResultHandoffReceiptedCurrentV4"
                or self.handoff_receipt_record_sha256 is None
            ):
                raise NativeBoundaryV27Error(
                    "V27 terminal receipt preceded the result handoff receipt"
                )
            retirement_sha256 = sha256(canonical_bytes(dict(retirement)))
            terminal_receipt = _effect_sign(
                "SupervisorTerminalReceiptV1",
                {
                    "schemaVersion": 27,
                    "profile": PROFILE,
                    "operationId": self.plan["operationId"],
                    "location": self.stage.location,
                    "nativeResultSha256": self.native_result_sha256,
                    "handoffReceiptRecordSha256": self.handoff_receipt_record_sha256,
                    "controllerRetirementSha256": retirement_sha256,
                    "terminalPredecessorCurrentRecordSha256": self.current[
                        "recordSha256"
                    ],
                },
                self.key,
            )
            _publish_effect_object(
                self.objects
                / f"{str(terminal_receipt['recordSha256']).removeprefix('sha256:')}.json",
                terminal_receipt,
                self.key,
                phase=f"location-{self.stage.location}-terminal-receipt",
            )
            predecessor = self.current
            receipt_payload = {
                **dict(predecessor["payload"]),
                "generation": int(predecessor["payload"]["generation"]) + 1,
                "state": "terminal-receipt-stored",
                "predecessorRecordSha256": predecessor["recordSha256"],
                "terminalReceiptRecordSha256": terminal_receipt[
                    "recordSha256"
                ],
                "controllerRetirementSha256": retirement_sha256,
            }
            self.current = _install_effect_current_kind_v27(
                self.current_path,
                self.history,
                self.key,
                "SupervisorTerminalReceiptStoredCurrentV4",
                receipt_payload,
                expected=predecessor,
            )
            predecessor = self.current
            terminal_payload = {
                **dict(predecessor["payload"]),
                "generation": int(predecessor["payload"]["generation"]) + 1,
                "state": "supervisor-terminal",
                "predecessorRecordSha256": predecessor["recordSha256"],
                "terminalBranch": "result-handoff-terminal",
            }
            self.current = _install_effect_current_kind_v27(
                self.current_path,
                self.history,
                self.key,
                "SupervisorTerminalCurrentV3",
                terminal_payload,
                expected=predecessor,
            )
            self.terminal_receipt_record_sha256 = str(
                terminal_receipt["recordSha256"]
            )
            return str(self.current["recordSha256"])


def _outer_current_payload_v27(
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    *,
    state: str,
    predecessor: Mapping[str, Any],
    consumed_record_sha256: str,
    result: Mapping[str, Any] | None,
    result_kind: str | None,
    failure_evidence_sha256: str | None,
    result_envelope_record_sha256: str | None = None,
    terminal_branch: str | None = None,
    launch_pre_effect_failed_sha256: str | None = None,
    native_event_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "planSha256": plan["planSha256"],
        "generation": int(predecessor["payload"]["generation"]) + 1,
        "location": stage.location,
        "stageKey": stage.stage_key,
        "stageKind": stage.stage_kind,
        "actionKind": stage.action_kind,
        "state": state,
        "predecessorRecordSha256": predecessor["recordSha256"],
        "consumedCurrentRecordSha256": consumed_record_sha256,
        "resultRecordSha256": None if result is None else result["recordSha256"],
        "resultKind": result_kind,
        "failureEvidenceSha256": failure_evidence_sha256,
        "resultEnvelopeRecordSha256": result_envelope_record_sha256,
        "terminalBranch": (
            terminal_branch
            if terminal_branch is not None
            else "result-handoff-terminal"
            if state == "supervisor-terminal"
            else None
        ),
        "launchPreEffectFailedSha256": launch_pre_effect_failed_sha256,
    }
    if native_event_binding is not None:
        payload.update(dict(native_event_binding))
    return payload


def _install_effect_current_kind_v27(
    current_path: Path,
    history: Path,
    key: bytes,
    kind: str,
    payload: Mapping[str, Any],
    *,
    expected: Mapping[str, Any] | None,
) -> dict[str, Any]:
    envelope = _effect_sign(kind, payload, key)
    location = payload.get("location")
    state = payload.get("state")
    phase = (
        f"location-{location}-{state}"
        if type(location) is int and isinstance(state, str)
        else f"{kind}-current"
    )
    history_path = history / f"{envelope['recordSha256'].removeprefix('sha256:')}.json"
    _publish_effect_object(
        history_path, envelope, key, phase=f"{phase}-history"
    )
    expected_raw = None if expected is None else canonical_bytes(dict(expected))
    _replace_effect_current(
        current_path, envelope, expected=expected_raw, phase=f"{phase}-current"
    )
    return envelope


def _validate_literal_stage_current_v27(
    current: Mapping[str, Any],
    plan: Mapping[str, Any],
    schedule: tuple[LiteralStageV27, ...],
) -> tuple[LiteralStageV27, str]:
    if current.get("kind") == "SupervisorOuterLossQuarantinedCurrentV4":
        payload = current.get("payload")
        if not isinstance(payload, Mapping):
            raise NativeBoundaryV27Error("V27 quarantined current payload is malformed")
        if (
            payload.get("operationId") != plan["operationId"]
            or payload.get("operationClass") != plan["operationClass"]
            or payload.get("planSha256") != plan["planSha256"]
        ):
            raise NativeBoundaryV27Error("V27 quarantined current was rebound")
        raise NativeBoundaryV27Error(
            "V27 consumed stage remains durably quarantined and cannot replay"
        )
    kind = current.get("kind")
    if kind not in CURRENT_UNION_V27 or not isinstance(current.get("payload"), Mapping):
        raise NativeBoundaryV27Error("V27 literal schedule current kind is invalid")
    payload = current["payload"]
    if kind == "StageCurrentV3" and payload.get("state") == "bootstrap-terminal":
        if (
            payload.get("operationId") != plan["operationId"]
            or payload.get("operationClass") != plan["operationClass"]
            or payload.get("planSha256") != plan["planSha256"]
            or payload.get("generation") != 1
            or payload.get("location") != 0
            or payload.get("stageKey") != "operation-bootstrap"
            or payload.get("stageKind") != "operation-bootstrap"
            or payload.get("predecessorRecordSha256") is not None
        ):
            raise NativeBoundaryV27Error("V27 bootstrap current binding changed")
        return LiteralStageV27(
            0,
            "operation-bootstrap",
            "operation-bootstrap",
            "durable-evidence-publication",
        ), "bootstrap-terminal"
    if (
        payload.get("operationId") != plan["operationId"]
        or payload.get("operationClass") != plan["operationClass"]
        or payload.get("planSha256") != plan["planSha256"]
        or type(payload.get("generation")) is not int
        or payload["generation"] < 1
        or type(payload.get("location")) is not int
        or not 1 <= payload["location"] <= len(schedule)
    ):
        raise NativeBoundaryV27Error("V27 literal schedule current binding changed")
    stage = schedule[payload["location"] - 1]
    if (
        payload.get("stageKey") != stage.stage_key
        or payload.get("stageKind") != stage.stage_kind
        or payload.get("actionKind") != stage.action_kind
    ):
        raise NativeBoundaryV27Error("V27 literal schedule coordinate changed")
    state = payload.get("state")
    present_native_fields = (
        _NATIVE_EVENT_CURRENT_BINDING_FIELDS_V27.intersection(payload)
    )
    if (
        state in _NATIVE_EVENT_CURRENT_KIND_V27
        and not present_native_fields
        and payload.get("resultRecordSha256") is None
    ):
        raise NativeBoundaryV27Error(
            "V27 pre-result native event current lacks authenticated event evidence"
        )
    if present_native_fields:
        binding_event = payload.get("nativeEvent")
        before_action = binding_event in _NATIVE_PRE_ACTION_CURRENT_EVENTS_V27
        if (
            present_native_fields
            != _NATIVE_EVENT_CURRENT_BINDING_FIELDS_V27
            or binding_event not in _NATIVE_EVENT_CURRENT_KIND_V27
            or payload.get("nativeEventTiming")
            != ("before-action" if before_action else "after-outcome")
            or type(payload.get("nativeEventSequence")) is not int
            or payload["nativeEventSequence"] < 1
            or (
                state in _NATIVE_EVENT_CURRENT_KIND_V27
                and (
                    binding_event != state
                    or kind != _NATIVE_EVENT_CURRENT_KIND_V27[state]
                )
            )
            or (
                state not in _NATIVE_EVENT_CURRENT_KIND_V27
                and kind not in {
                    item_kind for item_kind, _item_state
                    in _RESULT_HANDOFF_CHAIN_V27
                }
            )
        ):
            raise NativeBoundaryV27Error(
                f"V27 native event current binding changed for {kind}/{state} "
                f"retaining {binding_event!r}"
            )
        for field in (
            "nativeEventIntentRecordSha256",
            "nativeEventBeforeEvidenceSha256",
            "nativeEventBeforeObservationSha256",
        ):
            _digest(payload.get(field), field)
        for field in (
            "nativeEventAfterEvidenceSha256",
            "nativeEventAfterObservationSha256",
        ):
            if before_action:
                if payload.get(field) is not None:
                    raise NativeBoundaryV27Error(
                        "V27 before-action current carries future outcome evidence"
                    )
            else:
                _digest(payload.get(field), field)
        for field in (
            "nativeExactOutcomeRecordSha256",
            "nativeExactAuxiliaryRecordSha256",
        ):
            if payload.get(field) is not None:
                _digest(payload[field], field)
        if (
            not before_action
            and binding_event in _NATIVE_EXACT_OUTCOME_KINDS_V27
            and payload.get("nativeExactOutcomeRecordSha256") is None
        ):
            raise NativeBoundaryV27Error(
                "V27 exact native outcome current omitted its typed receipt"
            )
    if kind != "StageCurrentV3":
        state = payload.get("state")
        allowed_states = _ACTIVE_OUTER_STATES_V27.get(str(kind))
        if kind == "SupervisorOuterLossDrainPendingCurrentV5":
            allowed_states = frozenset({"outer-loss-drain-pending"})
        if (
            not isinstance(state, str)
            or allowed_states is None
            or state not in allowed_states
            or payload.get("consumedCurrentRecordSha256") is None
            or payload.get("predecessorRecordSha256") is None
        ):
            raise NativeBoundaryV27Error("V27 named outer current binding changed")
        if kind in {item_kind for item_kind, _ in _RESULT_HANDOFF_CHAIN_V27} and (
            payload.get("nativeResultSha256") is not None
        ):
            for field in (
                "nativeResultSha256",
                "resultEnvelopeRecordSha256",
            ):
                _digest(payload.get(field), field)
            if kind != "SupervisorResultEnvelopeStoredCurrentV4":
                _digest(
                    payload.get("handoffAuthorizationRecordSha256"),
                    "handoffAuthorizationRecordSha256",
                )
            if kind in {
                "SupervisorResultHandoffReceiptedCurrentV4",
                "SupervisorTerminalReceiptStoredCurrentV4",
                "SupervisorTerminalCurrentV3",
            }:
                _digest(
                    payload.get("handoffReceiptRecordSha256"),
                    "handoffReceiptRecordSha256",
                )
            if kind in {
                "SupervisorTerminalReceiptStoredCurrentV4",
                "SupervisorTerminalCurrentV3",
            }:
                _digest(
                    payload.get("terminalReceiptRecordSha256"),
                    "terminalReceiptRecordSha256",
                )
                _digest(
                    payload.get("controllerRetirementSha256"),
                    "controllerRetirementSha256",
                )
            if (
                payload.get("resultRecordSha256") is not None
                or payload.get("launchPreEffectFailedSha256") is not None
                or (state == "supervisor-terminal")
                != (payload.get("terminalBranch") == "result-handoff-terminal")
            ):
                raise NativeBoundaryV27Error(
                    "V27 credentialed result handoff current changed"
                )
            validate_result_envelope_v4(
                {
                    "resultKind": payload.get("resultKind"),
                    "predecessorKind": _RESULT_KINDS.get(
                        str(payload.get("resultKind"))
                    ),
                    "failureEvidenceSha256": payload.get(
                        "failureEvidenceSha256"
                    ),
                }
            )
            return stage, str(state)
        if kind in {item_kind for item_kind, _ in _AUTHENTICATED_UNRESOLVED_CHAIN_V27}:
            if (
                payload.get("resultRecordSha256") is not None
                or payload.get("resultKind") is not None
                or payload.get("failureEvidenceSha256") is not None
                or payload.get("resultEnvelopeRecordSha256") is not None
                or payload.get("terminalBranch") is not None
                or payload.get("launchPreEffectFailedSha256") is not None
                or payload.get("lossReason") not in {
                    "authenticated-controller-loss",
                    "dead-holder-without-terminal",
                }
                or not isinstance(payload.get("placementMask"), int)
                or isinstance(payload.get("placementMask"), bool)
                or not 0 <= payload["placementMask"] <= 63
            ):
                raise NativeBoundaryV27Error(
                    "V27 authenticated unresolved terminal binding changed"
                )
            for field in (
                "lossEvidenceSha256",
                "lossEvidenceRecordSha256",
                "controllerRetirementSha256",
            ):
                _digest(payload.get(field), field)
            return stage, str(state)
        if kind in _NONPUBLIC_RECOVERY_STATES_V27:
            if (
                state != _NONPUBLIC_RECOVERY_STATES_V27[kind]
                or payload.get("resultRecordSha256") is not None
                or payload.get("resultKind") is not None
                or payload.get("failureEvidenceSha256") is not None
                or payload.get("resultEnvelopeRecordSha256") is not None
                or payload.get("terminalBranch") is not None
                or payload.get("launchPreEffectFailedSha256") is not None
            ):
                raise NativeBoundaryV27Error(
                    "V27 admitted non-public recovery current changed"
                )
            closure_digest = payload.get("nonPublicClosureRecordSha256")
            if closure_digest is not None:
                _digest(closure_digest, "nonPublicClosureRecordSha256")
            return stage, str(state)
        launch_failure = payload.get("launchPreEffectFailedSha256")
        if launch_failure is not None:
            _digest(launch_failure, "launchPreEffectFailedSha256")
            if (
                kind not in {
                    "SupervisorLaunchPreEffectFailedCurrentV1",
                    "SupervisorTerminalCurrentV3",
                    "SupervisorOuterLossDrainPendingCurrentV5",
                }
                or payload.get("resultRecordSha256") is not None
                or payload.get("resultKind") is not None
                or payload.get("failureEvidenceSha256") is not None
                or payload.get("resultEnvelopeRecordSha256") is not None
                or (
                    kind == "SupervisorTerminalCurrentV3"
                    and payload.get("terminalBranch")
                    != "launch-pre-effect-never-created"
                )
                or (
                    kind != "SupervisorTerminalCurrentV3"
                    and payload.get("terminalBranch") is not None
                )
            ):
                raise NativeBoundaryV27Error(
                    "V27 launch-pre-effect terminal XOR changed"
                )
            return stage, str(state)
        result_digest = payload.get("resultRecordSha256")
        pre_result = kind in {
            "SupervisorLaunchSlotReservedCurrentV1",
            "SupervisorLaunchSlotConsumedCurrentV1",
            *(item_kind for item_kind, _state in _SUCCESS_NATIVE_EVENT_CHAIN_V27),
            *(
                item_kind
                for chain in _FAILURE_OUTER_PREFIX_V27.values()
                for item_kind, _state in chain
            ),
        }
        strict_pre_result = kind in {
            "SupervisorLaunchSlotReservedCurrentV1",
            "SupervisorLaunchSlotConsumedCurrentV1",
        }
        if pre_result and result_digest is None:
            if (
                payload.get("resultKind") is not None
                or payload.get("failureEvidenceSha256") is not None
                or payload.get("resultEnvelopeRecordSha256") is not None
            ):
                raise NativeBoundaryV27Error(
                    "V27 pre-result outer current carries future evidence"
                )
        elif strict_pre_result:
            raise NativeBoundaryV27Error(
                "V27 launch reservation carries future result evidence"
            )
        else:
            if not isinstance(result_digest, str) or not _DIGEST.fullmatch(result_digest):
                raise NativeBoundaryV27Error(
                    "V27 post-result outer current has no exact result"
                )
            validate_result_envelope_v4(
                {
                    "resultKind": payload.get("resultKind"),
                    "predecessorKind": _RESULT_KINDS.get(
                        str(payload.get("resultKind"))
                    ),
                    "failureEvidenceSha256": payload.get("failureEvidenceSha256"),
                }
            )
        if (state == "supervisor-terminal") != (
            payload.get("terminalBranch") == "result-handoff-terminal"
        ):
            raise NativeBoundaryV27Error("V27 terminal branch XOR changed")
        if payload.get("launchPreEffectFailedSha256") is not None:
            raise NativeBoundaryV27Error("V27 result terminal smuggles launch failure")
        return stage, str(state)
    required = {
        "ready": (None, None),
        "intent-current": (None, None),
        "release-consumed-current": (None, None),
        "completion": ("digest", "digest"),
    }
    if state not in required:
        raise NativeBoundaryV27Error("V27 literal schedule current state is invalid")
    result = payload.get("resultRecordSha256")
    receipt = payload.get("receiptRecordSha256")
    expected_result, expected_receipt = required[state]
    if (expected_result is None and result is not None) or (
        expected_result == "digest" and (not isinstance(result, str) or not _DIGEST.fullmatch(result))
    ):
        raise NativeBoundaryV27Error("V27 literal stage result binding changed")
    if (expected_receipt is None and receipt is not None) or (
        expected_receipt == "digest" and (not isinstance(receipt, str) or not _DIGEST.fullmatch(receipt))
    ):
        raise NativeBoundaryV27Error("V27 literal stage receipt binding changed")
    return stage, str(state)


def _matching_stage_action_result_v27(
    objects: Path,
    key: bytes,
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    consumed_record_sha256: str,
) -> dict[str, Any] | None:
    matches: list[dict[str, Any]] = []
    try:
        names = tuple(os.listdir(objects))
    except OSError as exc:
        raise NativeBoundaryV27Error(f"cannot inspect V27 stage objects: {exc}") from exc
    for name in names:
        if not re.fullmatch(r"[0-9a-f]{64}\.json", name):
            raise NativeBoundaryV27Error("V27 stage-object directory has an unexpected entry")
        record = _read_effect_record(objects / name, key)
        if record["kind"] != "StageActionResultV1":
            continue
        payload = record["payload"]
        if (
            payload.get("operationId") == plan["operationId"]
            and payload.get("operationClass") == plan["operationClass"]
            and payload.get("planSha256") == plan["planSha256"]
            and payload.get("location") == stage.location
            and payload.get("stageKey") == stage.stage_key
            and payload.get("predecessorCurrentRecordSha256")
            == consumed_record_sha256
        ):
            matches.append(record)
    if len(matches) > 1:
        raise NativeBoundaryV27Error("multiple V27 stage results bind one consumed action")
    return None if not matches else matches[0]


def _stage_result_discriminants_v27(value: Mapping[str, Any]) -> tuple[str, str, str | None]:
    result_kind = value.get("resultKind", "success")
    predecessor_kind = value.get(
        "resultPredecessorKind", _RESULT_KINDS.get(str(result_kind))
    )
    failure_evidence = value.get("failureEvidenceSha256")
    validated = validate_result_envelope_v4(
        {
            "resultKind": result_kind,
            "predecessorKind": predecessor_kind,
            "failureEvidenceSha256": failure_evidence,
        }
    )
    return (
        str(validated["resultKind"]),
        str(validated["predecessorKind"]),
        validated["failureEvidenceSha256"],
    )


def _supervisor_result_envelope_v27(
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    result: Mapping[str, Any],
    *,
    result_kind: str,
    predecessor_kind: str,
    failure_evidence_sha256: str | None,
    key: bytes,
) -> dict[str, Any]:
    return _effect_sign(
        "SupervisorResultEnvelopeV4",
        {
            "schemaVersion": 27,
            "profile": PROFILE,
            "operationId": plan["operationId"],
            "operationClass": plan["operationClass"],
            "planSha256": plan["planSha256"],
            "location": stage.location,
            "stageKey": stage.stage_key,
            "stageKind": stage.stage_kind,
            "actionKind": stage.action_kind,
            "resultKind": result_kind,
            "predecessorKind": predecessor_kind,
            "failureEvidenceSha256": failure_evidence_sha256,
            "stageActionResultRecordSha256": result["recordSha256"],
        },
        key,
    )


def _matching_handoff_artifact_v27(
    objects: Path,
    key: bytes,
    *,
    kind: str,
    operation_id: str,
    location: int,
    native_result_sha256: str,
    predecessor_field: str,
    predecessor_sha256: str,
) -> dict[str, Any] | None:
    matches: list[dict[str, Any]] = []
    for name in os.listdir(objects):
        if not re.fullmatch(r"[0-9a-f]{64}\.json", name):
            raise NativeBoundaryV27Error(
                "V27 handoff-object directory has an unexpected entry"
            )
        record = _read_effect_record(objects / name, key)
        if record["kind"] != kind:
            continue
        payload = record["payload"]
        if (
            payload.get("operationId") == operation_id
            and payload.get("location") == location
            and payload.get("nativeResultSha256") == native_result_sha256
            and payload.get(predecessor_field) == predecessor_sha256
        ):
            matches.append(record)
    if len(matches) > 1:
        raise NativeBoundaryV27Error(
            f"multiple V27 {kind} objects bind one handoff prefix"
        )
    return None if not matches else matches[0]


def _repair_credentialed_handoff_suffix_v27(
    *,
    current_path: Path,
    history: Path,
    objects: Path,
    key: bytes,
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    current: Mapping[str, Any],
    observation: Mapping[str, Any],
) -> dict[str, Any]:
    """Repair only the effect-free suffix of an authenticated result offer."""

    if not isinstance(observation, Mapping):
        raise NativeBoundaryV27Error(
            "V27 handoff recovery lacks the authenticated native observation"
        )
    native_result_sha256 = _native_handoff_sha256_v27(observation)
    current_payload = current["payload"]
    if current_payload.get("nativeResultSha256") != native_result_sha256:
        raise NativeBoundaryV27Error(
            "V27 handoff recovery observation differs from the offer"
        )
    while current["kind"] != "SupervisorTerminalCurrentV3":
        if current["kind"] == "SupervisorResultEnvelopeStoredCurrentV4":
            authorization = _matching_handoff_artifact_v27(
                objects,
                key,
                kind="SupervisorResultHandoffAuthorizationV1",
                operation_id=str(plan["operationId"]),
                location=stage.location,
                native_result_sha256=native_result_sha256,
                predecessor_field="authorizationCurrentRecordSha256",
                predecessor_sha256=str(current["recordSha256"]),
            )
            if authorization is None:
                raise NativeBoundaryV27Error(
                    "V27 handoff recovery cannot synthesize a missing authorization"
                )
            predecessor = current
            payload = {
                **dict(predecessor["payload"]),
                "generation": int(predecessor["payload"]["generation"]) + 1,
                "state": "result-handoff-consumed",
                "predecessorRecordSha256": predecessor["recordSha256"],
                "handoffAuthorizationRecordSha256": authorization[
                    "recordSha256"
                ],
            }
            current = _install_effect_current_kind_v27(
                current_path,
                history,
                key,
                "SupervisorResultHandoffAttemptConsumedCurrentV4",
                payload,
                expected=predecessor,
            )
            _effect_fault(f"location-{stage.location}-result-handoff-consumed")
            continue
        if current["kind"] == "SupervisorResultHandoffAttemptConsumedCurrentV4":
            receipt = _matching_handoff_artifact_v27(
                objects,
                key,
                kind="SupervisorResultHandoffReceiptV1",
                operation_id=str(plan["operationId"]),
                location=stage.location,
                native_result_sha256=native_result_sha256,
                predecessor_field="handoffAttemptCurrentRecordSha256",
                predecessor_sha256=str(current["recordSha256"]),
            )
            if receipt is None:
                receipt = _effect_sign(
                    "SupervisorResultHandoffReceiptV1",
                    {
                        "schemaVersion": 27,
                        "profile": PROFILE,
                        "operationId": plan["operationId"],
                        "location": stage.location,
                        "nativeResultSha256": native_result_sha256,
                        "handoffAuthorizationRecordSha256": current["payload"][
                            "handoffAuthorizationRecordSha256"
                        ],
                        "handoffAttemptCurrentRecordSha256": current[
                            "recordSha256"
                        ],
                    },
                    key,
                )
                _publish_effect_object(
                    objects
                    / f"{str(receipt['recordSha256']).removeprefix('sha256:')}.json",
                    receipt,
                    key,
                    phase=f"location-{stage.location}-result-handoff-recovery-receipt",
                )
            predecessor = current
            payload = {
                **dict(predecessor["payload"]),
                "generation": int(predecessor["payload"]["generation"]) + 1,
                "state": "result-handoff-receipted",
                "predecessorRecordSha256": predecessor["recordSha256"],
                "handoffReceiptRecordSha256": receipt["recordSha256"],
            }
            current = _install_effect_current_kind_v27(
                current_path,
                history,
                key,
                "SupervisorResultHandoffReceiptedCurrentV4",
                payload,
                expected=predecessor,
            )
            _effect_fault(f"location-{stage.location}-result-handoff-receipted")
            continue
        if current["kind"] == "SupervisorResultHandoffReceiptedCurrentV4":
            retirement = observation.get("controllerRetirement")
            if not isinstance(retirement, Mapping):
                raise NativeBoundaryV27Error(
                    "V27 terminal recovery lacks controller retirement evidence"
                )
            retirement_sha256 = sha256(canonical_bytes(dict(retirement)))
            terminal_receipt = _matching_handoff_artifact_v27(
                objects,
                key,
                kind="SupervisorTerminalReceiptV1",
                operation_id=str(plan["operationId"]),
                location=stage.location,
                native_result_sha256=native_result_sha256,
                predecessor_field="terminalPredecessorCurrentRecordSha256",
                predecessor_sha256=str(current["recordSha256"]),
            )
            if terminal_receipt is None:
                terminal_receipt = _effect_sign(
                    "SupervisorTerminalReceiptV1",
                    {
                        "schemaVersion": 27,
                        "profile": PROFILE,
                        "operationId": plan["operationId"],
                        "location": stage.location,
                        "nativeResultSha256": native_result_sha256,
                        "handoffReceiptRecordSha256": current["payload"][
                            "handoffReceiptRecordSha256"
                        ],
                        "controllerRetirementSha256": retirement_sha256,
                        "terminalPredecessorCurrentRecordSha256": current[
                            "recordSha256"
                        ],
                    },
                    key,
                )
                _publish_effect_object(
                    objects
                    / f"{str(terminal_receipt['recordSha256']).removeprefix('sha256:')}.json",
                    terminal_receipt,
                    key,
                    phase=f"location-{stage.location}-terminal-recovery-receipt",
                )
            predecessor = current
            payload = {
                **dict(predecessor["payload"]),
                "generation": int(predecessor["payload"]["generation"]) + 1,
                "state": "terminal-receipt-stored",
                "predecessorRecordSha256": predecessor["recordSha256"],
                "terminalReceiptRecordSha256": terminal_receipt[
                    "recordSha256"
                ],
                "controllerRetirementSha256": retirement_sha256,
            }
            current = _install_effect_current_kind_v27(
                current_path,
                history,
                key,
                "SupervisorTerminalReceiptStoredCurrentV4",
                payload,
                expected=predecessor,
            )
            _effect_fault(f"location-{stage.location}-terminal-receipt-stored")
            continue
        if current["kind"] == "SupervisorTerminalReceiptStoredCurrentV4":
            predecessor = current
            payload = {
                **dict(predecessor["payload"]),
                "generation": int(predecessor["payload"]["generation"]) + 1,
                "state": "supervisor-terminal",
                "predecessorRecordSha256": predecessor["recordSha256"],
                "terminalBranch": "result-handoff-terminal",
            }
            current = _install_effect_current_kind_v27(
                current_path,
                history,
                key,
                "SupervisorTerminalCurrentV3",
                payload,
                expected=predecessor,
            )
            _effect_fault(f"location-{stage.location}-supervisor-terminal")
            continue
        raise NativeBoundaryV27Error(
            "V27 credentialed handoff recovery current is not admitted"
        )
    return dict(current)


def _advance_outer_result_chain_v27(
    *,
    current_path: Path,
    history: Path,
    objects: Path,
    key: bytes,
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    current: Mapping[str, Any],
    result: Mapping[str, Any],
    require_native_events: bool = False,
) -> dict[str, Any]:
    payload = result["payload"]
    result_kind, predecessor_kind, failure_evidence = _stage_result_discriminants_v27(
        payload
    )
    consumed_digest = str(payload["predecessorCurrentRecordSha256"])
    if require_native_events and current.get("kind") in {
        "SupervisorResultEnvelopeStoredCurrentV4",
        "SupervisorResultHandoffAttemptConsumedCurrentV4",
        "SupervisorResultHandoffReceiptedCurrentV4",
        "SupervisorTerminalReceiptStoredCurrentV4",
    }:
        current = _repair_credentialed_handoff_suffix_v27(
            current_path=current_path,
            history=history,
            objects=objects,
            key=key,
            plan=plan,
            stage=stage,
            current=current,
            observation=result["payload"].get("observation"),
        )
    if (
        require_native_events
        and current.get("kind") == "SupervisorTerminalCurrentV3"
        and current.get("payload", {}).get("nativeResultSha256") is not None
    ):
        current_payload = current["payload"]
        observation = payload.get("observation")
        if (
            not isinstance(observation, Mapping)
            or _native_handoff_sha256_v27(observation)
            != current_payload.get("nativeResultSha256")
            or current_payload.get("resultKind") != result_kind
            or current_payload.get("failureEvidenceSha256") != failure_evidence
        ):
            raise NativeBoundaryV27Error(
                "V27 credentialed result handoff differs from StageActionResult"
            )
        envelope_digest = current_payload.get("resultEnvelopeRecordSha256")
        _digest(envelope_digest, "resultEnvelopeRecordSha256")
        envelope = _read_effect_record(
            objects / f"{str(envelope_digest).removeprefix('sha256:')}.json",
            key,
            expected_kind="SupervisorResultEnvelopeV4",
        )
        envelope_payload = envelope["payload"]
        if (
            envelope_payload.get("nativeResultSha256")
            != current_payload.get("nativeResultSha256")
            or envelope_payload.get("resultKind") != result_kind
            or envelope_payload.get("predecessorKind") != predecessor_kind
            or envelope_payload.get("failureEvidenceSha256") != failure_evidence
        ):
            raise NativeBoundaryV27Error(
                "V27 durable result offer envelope was rebound"
            )
        if result_kind == "success":
            return dict(current)
        pending = _install_effect_current_kind_v27(
            current_path,
            history,
            key,
            "SupervisorOuterLossDrainPendingCurrentV5",
            _outer_current_payload_v27(
                plan,
                stage,
                state="outer-loss-drain-pending",
                predecessor=current,
                consumed_record_sha256=str(
                    current_payload["consumedCurrentRecordSha256"]
                ),
                result=result,
                result_kind=result_kind,
                failure_evidence_sha256=failure_evidence,
                result_envelope_record_sha256=str(envelope_digest),
            ),
            expected=current,
        )
        _install_effect_current_kind_v27(
            current_path,
            history,
            key,
            "SupervisorOuterLossQuarantinedCurrentV4",
            _outer_current_payload_v27(
                plan,
                stage,
                state="outer-loss-quarantined-current",
                predecessor=pending,
                consumed_record_sha256=str(
                    current_payload["consumedCurrentRecordSha256"]
                ),
                result=result,
                result_kind=result_kind,
                failure_evidence_sha256=failure_evidence,
                result_envelope_record_sha256=str(envelope_digest),
            ),
            expected=pending,
        )
        raise NativeBoundaryV27Error(
            f"V27 stage {stage.stage_key} failure is durably quarantined and non-public"
        )
    chain = _outer_chain_v27(result_kind)
    current_kind = str(current["kind"])
    current_state = str(current["payload"].get("state"))
    if current_kind == "SupervisorLaunchSlotConsumedCurrentV1":
        index = 1 if result_kind == "success" else -1
    else:
        matches = [
            index
            for index, (kind, state) in enumerate(chain)
            if kind == current_kind and state == current_state
        ]
        if len(matches) != 1:
            raise NativeBoundaryV27Error(
                "V27 named outer current is not on the exact result chain"
            )
        index = matches[0]
    result_envelope_index = next(
        chain_index
        for chain_index, (kind, _state) in enumerate(chain)
        if kind == "SupervisorResultEnvelopeStoredCurrentV4"
    )
    if require_native_events and index != result_envelope_index - 1:
        raise NativeBoundaryV27Error(
            "V27 durable result cannot synthesize a missing native event prefix"
        )
    result_envelope: dict[str, Any] | None = None
    result_envelope_digest = current["payload"].get(
        "resultEnvelopeRecordSha256"
    )
    while index + 1 < len(chain):
        next_kind, next_state = chain[index + 1]
        if next_kind == "SupervisorResultEnvelopeStoredCurrentV4":
            result_envelope = _supervisor_result_envelope_v27(
                plan,
                stage,
                result,
                result_kind=result_kind,
                predecessor_kind=predecessor_kind,
                failure_evidence_sha256=failure_evidence,
                key=key,
            )
            result_envelope_path = objects / (
                str(result_envelope["recordSha256"]).removeprefix("sha256:")
                + ".json"
            )
            _publish_effect_object(
                result_envelope_path,
                result_envelope,
                key,
                phase=f"location-{stage.location}-result-envelope",
            )
            _effect_fault(f"location-{stage.location}-result-envelope-written")
            result_envelope_digest = result_envelope["recordSha256"]
        elif next_kind in {
            "SupervisorResultHandoffAttemptConsumedCurrentV4",
            "SupervisorResultHandoffReceiptedCurrentV4",
            "SupervisorTerminalReceiptStoredCurrentV4",
            "SupervisorTerminalCurrentV3",
        } and not isinstance(result_envelope_digest, str):
            raise NativeBoundaryV27Error(
                "V27 result handoff has no durable result envelope"
            )
        next_payload = _outer_current_payload_v27(
            plan,
            stage,
            state=next_state,
            predecessor=current,
            consumed_record_sha256=consumed_digest,
            result=result,
            result_kind=result_kind,
            failure_evidence_sha256=failure_evidence,
            result_envelope_record_sha256=(
                None if not isinstance(result_envelope_digest, str)
                else result_envelope_digest
            ),
        )
        current = _install_effect_current_kind_v27(
            current_path,
            history,
            key,
            next_kind,
            next_payload,
            expected=current,
        )
        _effect_fault(f"location-{stage.location}-{next_state}")
        index += 1
    if current["kind"] != "SupervisorTerminalCurrentV3":
        raise NativeBoundaryV27Error("V27 result chain did not reach TerminalCurrent")
    if result_kind != "success":
        pending = _install_effect_current_kind_v27(
            current_path,
            history,
            key,
            "SupervisorOuterLossDrainPendingCurrentV5",
            _outer_current_payload_v27(
                plan,
                stage,
                state="outer-loss-drain-pending",
                predecessor=current,
                consumed_record_sha256=consumed_digest,
                result=result,
                result_kind=result_kind,
                failure_evidence_sha256=failure_evidence,
                result_envelope_record_sha256=str(result_envelope_digest),
            ),
            expected=current,
        )
        current = _install_effect_current_kind_v27(
            current_path,
            history,
            key,
            "SupervisorOuterLossQuarantinedCurrentV4",
            _outer_current_payload_v27(
                plan,
                stage,
                state="outer-loss-quarantined-current",
                predecessor=pending,
                consumed_record_sha256=consumed_digest,
                result=result,
                result_kind=result_kind,
                failure_evidence_sha256=failure_evidence,
                result_envelope_record_sha256=str(result_envelope_digest),
            ),
            expected=pending,
        )
        raise NativeBoundaryV27Error(
            f"V27 stage {stage.stage_key} failure is durably quarantined and non-public"
        )
    return current


def _advance_launch_pre_effect_failure_v27(
    *,
    current_path: Path,
    history: Path,
    objects: Path,
    key: bytes,
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    current: Mapping[str, Any],
    proof: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Close a proved-never-created launch without a result-envelope branch."""

    consumed_digest = str(
        current["recordSha256"]
        if current["kind"] == "SupervisorLaunchSlotConsumedCurrentV1"
        else current["payload"].get("consumedCurrentRecordSha256")
    )
    if current["kind"] == "SupervisorLaunchSlotConsumedCurrentV1":
        if (
            not isinstance(proof, Mapping)
            or set(proof) != {"proof", "controllerHmac"}
            or not isinstance(proof["proof"], Mapping)
        ):
            raise NativeBoundaryV27Error(
                "V27 launch-pre-effect transition lacks a controller proof"
            )
        controller_proof = dict(proof["proof"])
        if (
            controller_proof.get("operationId") != plan["operationId"]
            or controller_proof.get("stageLocation") != stage.location
            or not _DIGEST.fullmatch(
                str(controller_proof.get("stagePlanSha256"))
            )
            or controller_proof.get("consumedCurrentRecordSha256")
            != consumed_digest
            or controller_proof.get("controllerRetirement", {}).get(
                "placementMask"
            ) != 0
            or not re.fullmatch(
                r"hmac-sha256:[0-9a-f]{64}", str(proof["controllerHmac"])
            )
        ):
            raise NativeBoundaryV27Error(
                "V27 launch-pre-effect controller proof binding changed"
            )
        proof_record = _effect_sign(
            "SupervisorLaunchPreEffectProofV1",
            {
                "schemaVersion": 27,
                "profile": PROFILE,
                "operationId": plan["operationId"],
                "operationClass": plan["operationClass"],
                "planSha256": plan["planSha256"],
                "location": stage.location,
                "stageKey": stage.stage_key,
                "stageKind": stage.stage_kind,
                "consumedCurrentRecordSha256": consumed_digest,
                "controllerProofSha256": sha256(
                    canonical_bytes(dict(proof))
                ),
                "controllerProof": dict(proof),
            },
            key,
        )
        _publish_effect_object(
            objects
            / f"{str(proof_record['recordSha256']).removeprefix('sha256:')}.json",
            proof_record,
            key,
            phase=f"location-{stage.location}-launch-pre-effect-proof",
        )
        _effect_fault(
            f"location-{stage.location}-launch-pre-effect-proof-written"
        )
        proof_record_sha256 = str(proof_record["recordSha256"])
    else:
        proof_record_sha256 = str(
            current["payload"].get("launchPreEffectFailedSha256")
        )
        _digest(
            proof_record_sha256,
            "launch pre-effect proof record digest",
        )
        proof_record = _read_effect_record(
            objects
            / f"{proof_record_sha256.removeprefix('sha256:')}.json",
            key,
            expected_kind="SupervisorLaunchPreEffectProofV1",
        )
        proof_payload = proof_record["payload"]
        if (
            proof_record["recordSha256"] != proof_record_sha256
            or proof_payload.get("operationId") != plan["operationId"]
            or proof_payload.get("operationClass") != plan["operationClass"]
            or proof_payload.get("planSha256") != plan["planSha256"]
            or proof_payload.get("location") != stage.location
            or proof_payload.get("stageKey") != stage.stage_key
            or proof_payload.get("consumedCurrentRecordSha256")
            != consumed_digest
            or not isinstance(proof_payload.get("controllerProof"), Mapping)
            or sha256(
                canonical_bytes(dict(proof_payload["controllerProof"]))
            ) != proof_payload.get("controllerProofSha256")
        ):
            raise NativeBoundaryV27Error(
                "V27 persisted launch-pre-effect proof was rebound"
            )
    steps = (
        (
            "SupervisorLaunchPreEffectFailedCurrentV1",
            "launch-pre-effect-failed",
            None,
        ),
        (
            "SupervisorTerminalCurrentV3",
            "supervisor-terminal",
            "launch-pre-effect-never-created",
        ),
        (
            "SupervisorOuterLossDrainPendingCurrentV5",
            "outer-loss-drain-pending",
            None,
        ),
        (
            "SupervisorOuterLossQuarantinedCurrentV4",
            "outer-loss-quarantined-current",
            None,
        ),
    )
    current_identity = (
        str(current["kind"]), str(current["payload"].get("state"))
    )
    identities = [(kind, state) for kind, state, _branch in steps]
    start = -1 if current["kind"] == "SupervisorLaunchSlotConsumedCurrentV1" else (
        identities.index(current_identity)
        if current_identity in identities
        else -2
    )
    if start == -2:
        raise NativeBoundaryV27Error(
            "V27 launch-pre-effect recovery current is outside its exact chain"
        )
    for kind, state, branch in steps[start + 1 :]:
        current = _install_effect_current_kind_v27(
            current_path,
            history,
            key,
            kind,
            _outer_current_payload_v27(
                plan,
                stage,
                state=state,
                predecessor=current,
                consumed_record_sha256=consumed_digest,
                result=None,
                result_kind=None,
                failure_evidence_sha256=None,
                terminal_branch=branch,
                launch_pre_effect_failed_sha256=proof_record_sha256,
            ),
            expected=current,
        )
        _effect_fault(f"location-{stage.location}-{state}")
    return dict(current)


def _advance_authenticated_unresolved_loss_v27(
    *,
    current_path: Path,
    history: Path,
    objects: Path,
    key: bytes,
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    current: Mapping[str, Any],
    recovered: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Close a post-cutoff supervisor loss without claiming no effect.

    The worker may relay retirement bytes, but the controller authenticates the
    controller-only arena/intent/receipt chain before returning
    ``controllerRetirement``.  That proof becomes an immutable object before
    the first unresolved-current CAS.  Pending/Proved recovery consumes only
    this object and never launches, signals, or synthesizes a result envelope.
    """

    chain_kinds = {kind for kind, _state in _AUTHENTICATED_UNRESOLVED_CHAIN_V27}
    if current["kind"] in chain_kinds:
        current_payload = current["payload"]
        evidence_digest = str(current_payload["lossEvidenceRecordSha256"])
        evidence = _read_effect_record(
            objects / f"{evidence_digest.removeprefix('sha256:')}.json",
            key,
            expected_kind="AuthenticatedSupervisorLossEvidenceV1",
        )
        evidence_payload = evidence["payload"]
        if (
            evidence["recordSha256"] != evidence_digest
            or evidence_payload.get("operationId") != plan["operationId"]
            or evidence_payload.get("operationClass") != plan["operationClass"]
            or evidence_payload.get("planSha256") != plan["planSha256"]
            or evidence_payload.get("location") != stage.location
            or evidence_payload.get("stageKey") != stage.stage_key
            or evidence_payload.get("lossReason") != current_payload.get("lossReason")
            or evidence_payload.get("lossEvidenceSha256")
            != current_payload.get("lossEvidenceSha256")
            or evidence_payload.get("controllerRetirementSha256")
            != current_payload.get("controllerRetirementSha256")
            or evidence_payload.get("placementMask")
            != current_payload.get("placementMask")
        ):
            raise NativeBoundaryV27Error(
                "V27 authenticated supervisor-loss evidence was rebound"
            )
        immutable_loss_fields = {
            "lossReason": evidence_payload["lossReason"],
            "lossEvidenceSha256": evidence_payload["lossEvidenceSha256"],
            "lossEvidenceRecordSha256": evidence["recordSha256"],
            "controllerRetirementSha256": evidence_payload[
                "controllerRetirementSha256"
            ],
            "placementMask": evidence_payload["placementMask"],
        }
    else:
        if recovered is None or not _is_native_supervisor_loss_v27(recovered):
            raise NativeBoundaryV27Error(
                "V27 unresolved loss transition lacks authenticated evidence"
            )
        if set(recovered) != {"nativeSupervisorLoss", "controllerRetirement"}:
            raise NativeBoundaryV27Error(
                "V27 unresolved loss lacks controller-authenticated retirement"
            )
        loss = recovered["nativeSupervisorLoss"]
        retirement = recovered["controllerRetirement"]
        if not isinstance(retirement, Mapping):
            raise NativeBoundaryV27Error(
                "V27 unresolved loss retirement evidence changed"
            )
        placement_mask = retirement.get("placementMask")
        if (
            not isinstance(placement_mask, int)
            or isinstance(placement_mask, bool)
            or not 0 <= placement_mask <= 63
        ):
            raise NativeBoundaryV27Error(
                "V27 unresolved loss placement mask changed"
            )
        decoded_retirement = _decode_controller_retirement_v27(
            retirement, placement_mask
        )
        if decoded_retirement != dict(retirement):
            raise NativeBoundaryV27Error(
                "V27 unresolved loss retirement projection changed"
            )
        retirement_sha256 = sha256(canonical_bytes(dict(retirement)))
        evidence = _effect_sign(
            "AuthenticatedSupervisorLossEvidenceV1",
            {
                "schemaVersion": 27,
                "profile": PROFILE,
                "operationId": plan["operationId"],
                "operationClass": plan["operationClass"],
                "planSha256": plan["planSha256"],
                "location": stage.location,
                "stageKey": stage.stage_key,
                "stageKind": stage.stage_kind,
                "originCurrentRecordSha256": current["recordSha256"],
                "lossReason": loss["reason"],
                "lossEvidenceSha256": loss["evidenceSha256"],
                "controllerRetirementSha256": retirement_sha256,
                "placementMask": placement_mask,
            },
            key,
        )
        _publish_effect_object(
            objects
            / f"{str(evidence['recordSha256']).removeprefix('sha256:')}.json",
            evidence,
            key,
            phase=f"location-{stage.location}-authenticated-supervisor-loss",
        )
        _effect_fault(
            f"location-{stage.location}-authenticated-supervisor-loss-written"
        )
        evidence_payload = evidence["payload"]
        immutable_loss_fields = {
            "lossReason": loss["reason"],
            "lossEvidenceSha256": loss["evidenceSha256"],
            "lossEvidenceRecordSha256": evidence["recordSha256"],
            "controllerRetirementSha256": retirement_sha256,
            "placementMask": placement_mask,
        }

    identities = list(_AUTHENTICATED_UNRESOLVED_CHAIN_V27)
    current_identity = (
        str(current["kind"]), str(current["payload"].get("state"))
    )
    start = identities.index(current_identity) if current_identity in identities else -1
    consumed_digest = str(
        current["recordSha256"]
        if current["kind"] == "SupervisorLaunchSlotConsumedCurrentV1"
        else current["payload"].get("consumedCurrentRecordSha256")
    )
    if not _DIGEST.fullmatch(consumed_digest):
        raise NativeBoundaryV27Error(
            "V27 unresolved loss lost its consumed-current identity"
        )
    for kind, state in identities[start + 1 :]:
        next_payload = {
            **_outer_current_payload_v27(
                plan,
                stage,
                state=state,
                predecessor=current,
                consumed_record_sha256=consumed_digest,
                result=None,
                result_kind=None,
                failure_evidence_sha256=None,
            ),
            **immutable_loss_fields,
        }
        current = _install_effect_current_kind_v27(
            current_path,
            history,
            key,
            kind,
            next_payload,
            expected=current,
        )
        _effect_fault(f"location-{stage.location}-{state}")
    if current["kind"] != "UnresolvedTerminalCurrentV3":
        raise NativeBoundaryV27Error(
            "V27 authenticated supervisor loss did not reach unresolved terminal"
        )
    return dict(current)


def _close_admitted_nonpublic_current_v27(
    *,
    current_path: Path,
    history: Path,
    objects: Path,
    key: bytes,
    manifest: NativeBoundaryManifestV27,
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    current: Mapping[str, Any],
    action_recovery: Any,
) -> dict[str, Any]:
    """Close each historical admitted family without inventing an effect.

    These currents are intentionally not result predecessors.  A genuine
    authenticated native-loss recovery may join the existing unresolved chain;
    otherwise an immutable kind-specific closure records that no recovery
    action was authorized and moves once to the common non-public quarantine.
    There is no signal, container call, readback, result envelope, or replay.
    """

    kind = str(current["kind"])
    terminal_reasons = {
        "NormalMissResolvedCurrentV4": "normal-miss-resolved-nonpublic",
        "LateCutoffUnresolvedCurrentV3": "late-cutoff-unresolved-nonpublic",
        "CreatorReturnPermanentlyQuarantinedCurrentV2": (
            "creator-return-permanently-quarantined"
        ),
    }
    if kind in terminal_reasons:
        raise NativeBoundaryV27Error(
            f"V27 {terminal_reasons[kind]} is an exact final non-public current"
        )
    closure_reasons = {
        "TakeoverKillAttemptConsumedCurrentV1": (
            "takeover-kill-consumed-no-replay"
        ),
        "NormalMissPendingCurrentV4": "normal-miss-pending-no-publication",
        "BootChangedUnresolvedCurrentV2": "boot-changed-cross-boot-unresolved",
        "LateCutoffContinuationCurrentV2": (
            "late-cutoff-continuation-no-restart"
        ),
        "LateNormalPendingRawCurrentV1": (
            "late-normal-raw-without-terminal-receipt"
        ),
    }
    if kind not in closure_reasons:
        raise NativeBoundaryV27Error(
            "V27 admitted non-public current has no exact closure"
        )
    recovered = None
    if callable(action_recovery):
        recovered = action_recovery(manifest, plan, stage)
    if recovered is not None and _is_native_supervisor_loss_v27(recovered):
        return _advance_authenticated_unresolved_loss_v27(
            current_path=current_path,
            history=history,
            objects=objects,
            key=key,
            plan=plan,
            stage=stage,
            current=current,
            recovered=recovered,
        )
    closure = _effect_sign(
        "AdmittedOuterRecoveryClosureV1",
        {
            "schemaVersion": 27,
            "profile": PROFILE,
            "operationId": plan["operationId"],
            "operationClass": plan["operationClass"],
            "planSha256": plan["planSha256"],
            "location": stage.location,
            "stageKey": stage.stage_key,
            "originCurrentKind": kind,
            "originCurrentRecordSha256": current["recordSha256"],
            "closureReason": closure_reasons[kind],
            "authorizedRecoveryAction": "none-no-replay",
            "publicResultEligibility": "none",
        },
        key,
    )
    _publish_effect_object(
        objects / f"{str(closure['recordSha256']).removeprefix('sha256:')}.json",
        closure,
        key,
        phase=f"location-{stage.location}-{closure_reasons[kind]}",
    )
    _effect_fault(f"location-{stage.location}-{closure_reasons[kind]}-written")
    consumed_digest = str(current["payload"].get("consumedCurrentRecordSha256"))
    _digest(consumed_digest, "admitted non-public consumed current")
    quarantined = _install_effect_current_kind_v27(
        current_path,
        history,
        key,
        "SupervisorOuterLossQuarantinedCurrentV4",
        {
            **_outer_current_payload_v27(
                plan,
                stage,
                state="outer-loss-quarantined-current",
                predecessor=current,
                consumed_record_sha256=consumed_digest,
                result=None,
                result_kind=None,
                failure_evidence_sha256=None,
            ),
            "reason": closure_reasons[kind],
            "nonPublicClosureRecordSha256": closure["recordSha256"],
        },
        expected=current,
    )
    return dict(quarantined)


def _complete_literal_stage_v27(
    *,
    current_path: Path,
    history: Path,
    objects: Path,
    key: bytes,
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    consumed: Mapping[str, Any],
    result: Mapping[str, Any],
) -> dict[str, Any]:
    receipt_payload = {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "planSha256": plan["planSha256"],
        "location": stage.location,
        "stageKey": stage.stage_key,
        "consumedCurrentRecordSha256": consumed["recordSha256"],
        "stageResultRecordSha256": result["recordSha256"],
    }
    receipt = _effect_sign("StageActionReceiptV1", receipt_payload, key)
    receipt_path = objects / f"{receipt['recordSha256'].removeprefix('sha256:')}.json"
    _publish_effect_object(
        receipt_path,
        receipt,
        key,
        phase=f"location-{stage.location}-receipt-object",
    )
    _effect_fault(f"location-{stage.location}-receipt-object-written")
    completed = _install_effect_current_kind_v27(
        current_path,
        history,
        key,
        "StageCurrentV3",
        _literal_stage_current_payload_v27(
            plan,
            stage,
            state="completion",
            predecessor=consumed,
            result_record_sha256=str(result["recordSha256"]),
            receipt_record_sha256=str(receipt["recordSha256"]),
        ),
        expected=consumed,
    )
    _effect_fault(f"location-{stage.location}-completion-current-installed")
    return completed


def _terminal_observation_from_literal_done_v27(
    objects: Path,
    current: Mapping[str, Any],
    key: bytes,
) -> dict[str, Any]:
    result_digest = current["payload"].get("resultRecordSha256")
    if not isinstance(result_digest, str) or not _DIGEST.fullmatch(result_digest):
        raise NativeBoundaryV27Error("V27 Done current has no terminal result")
    result = _read_effect_record(
        objects / f"{result_digest.removeprefix('sha256:')}.json",
        key,
        expected_kind="StageActionResultV1",
    )
    terminal = result["payload"].get("terminalObservation")
    if not isinstance(terminal, dict):
        raise NativeBoundaryV27Error("V27 Done stage has no terminal observation")
    return dict(terminal)


_NATIVE_PAYLOAD_STAGE_KIND_V27: Final = "payload-terminal"
_NATIVE_STAGE_PLAN_FIELDS_V27: Final = {
    "schemaVersion",
    "profile",
    "operationId",
    "operationClass",
    "effectPlanSha256",
    "stageLocation",
    "stageKey",
    "stageKind",
    "actionKind",
    "repositoryPath",
    "repositoryCustody",
    "argv",
    "imageReference",
    "imageDigest",
    "networkMode",
    "pullPolicy",
    "environment",
    "requestKeyId",
    "stagePlanSha256",
}


def _effect_target_id_v27(plan: Mapping[str, Any]) -> str:
    argv = plan["argv"]
    if len(argv) >= 3 and argv[1] == "update":
        candidate = argv[2]
    elif len(argv) >= 4 and argv[1:3] == ["comments", "add"]:
        candidate = argv[3]
    else:
        raise NativeBoundaryV27Error(
            "V27 effect argv has no exact protected read-back target"
        )
    if not isinstance(candidate, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", candidate
    ):
        raise NativeBoundaryV27Error("V27 effect target id is invalid")
    return candidate


def _reference_read_back_argv_v27(
    plan: Mapping[str, Any], ordinal: int
) -> list[str]:
    """Build only the registered task-2 templates for internal test fixtures.

    The production controller replaces this reference path with the separately
    authenticated, descriptor-pinned read-back plan before execution.
    """

    if type(ordinal) is not int or not 0 <= ordinal < len(_READ_BACK_STEP_SPECS_V27):
        raise NativeBoundaryV27Error("V27 read-back ordinal is invalid")
    target = _effect_target_id_v27(plan)
    database = "/workspace/.beads/embeddeddolt/startup_factory"
    expected_ordinal, _requirement, shape, _data_shape = _READ_BACK_STEP_SPECS_V27[
        ordinal
    ]
    if expected_ordinal != ordinal:
        raise NativeBoundaryV27Error("V27 registered read-back ordinal changed")
    substitutions = {"$B": "/usr/local/bin/bd", "$E": database, "$ID": target}
    return [substitutions.get(item, item) for item in shape]


def _native_argv_for_literal_stage_v27(
    plan: Mapping[str, Any], stage: LiteralStageV27
) -> list[str] | None:
    if stage.stage_kind != _NATIVE_PAYLOAD_STAGE_KIND_V27:
        return None
    if stage.stage_key == "effect-payload-terminal":
        return list(plan["argv"])
    match = re.fullmatch(r"reader-([0-3])-payload-terminal", stage.stage_key)
    if match is not None:
        ordinal = int(match.group(1))
        protected = plan.get("readBackPlan")
        if protected is not None:
            verified = validate_descriptor_pinned_read_back_plan_v27(protected)
            return list(verified["steps"][ordinal]["argv"])
        return _reference_read_back_argv_v27(plan, ordinal)
    commands = plan.get("preparationCommands")
    if not isinstance(commands, list):
        raise NativeBoundaryV27Error(
            "V27 preparation stage plan has no protected command schedule"
        )
    if plan["operationClass"] == "create-preparation":
        prefixes = ("binary-proof", "initialize", "status-write", "status-read")
        for ordinal, prefix in enumerate(prefixes):
            if stage.stage_key == f"{prefix}-payload-terminal":
                return list(commands[ordinal])
    elif (
        plan["operationClass"] == "reattest-preparation"
        and stage.stage_key == "status-read-payload-terminal"
    ):
        return list(commands[0])
    raise NativeBoundaryV27Error("V27 preparation payload coordinate is invalid")


def _native_stage_plan_digest_v27(value: Mapping[str, Any]) -> str:
    return sha256(
        _READ_BACK_STAGE_PLAN_DOMAIN_V27
        + canonical_bytes(
            {key: item for key, item in value.items() if key != "stagePlanSha256"}
        )
    )


def derive_native_stage_action_plan_v27(
    manifest: NativeBoundaryManifestV27,
    plan_value: Any,
    stage: LiteralStageV27,
) -> dict[str, Any] | None:
    plan = validate_supervised_effect_plan_v27(plan_value, manifest)
    schedule = literal_stage_schedule_v27(plan["operationClass"])
    if (
        type(stage) is not LiteralStageV27
        or stage.location < 1
        or stage.location > len(schedule)
        or stage != schedule[stage.location - 1]
    ):
        raise NativeBoundaryV27Error("V27 native stage coordinate is not literal")
    argv = _native_argv_for_literal_stage_v27(plan, stage)
    if argv is None:
        return None
    value: dict[str, Any] = {
        "schemaVersion": 27,
        "profile": PROFILE,
        "operationId": plan["operationId"],
        "operationClass": plan["operationClass"],
        "effectPlanSha256": plan["planSha256"],
        "stageLocation": stage.location,
        "stageKey": stage.stage_key,
        "stageKind": stage.stage_kind,
        "actionKind": stage.action_kind,
        "repositoryPath": plan["repositoryPath"],
        "repositoryCustody": None,
        "argv": argv,
        "imageReference": plan["imageReference"],
        "imageDigest": plan["imageDigest"],
        "networkMode": plan["networkMode"],
        "pullPolicy": plan["pullPolicy"],
        "environment": dict(plan["environment"]),
        "requestKeyId": sha256(
            b"startup-factory/beads/v27/reference-request-key-id\0"
            + canonical_bytes(
                {
                    "launchCoreSha256": plan["launchCoreSha256"],
                    "operatorGeneration": plan["operatorGeneration"],
                    "configEpoch": plan["configEpoch"],
                    "keyEpoch": plan["keyEpoch"],
                    "effectPlanSha256": plan["planSha256"],
                    "stageLocation": stage.location,
                }
            )
        ),
        "stagePlanSha256": None,
    }
    value["stagePlanSha256"] = _native_stage_plan_digest_v27(value)
    return value


def validate_native_stage_action_plan_v27(
    value: Any, manifest: NativeBoundaryManifestV27
) -> dict[str, Any]:
    data = _closed(value, _NATIVE_STAGE_PLAN_FIELDS_V27, "V27 native stage plan")
    if data["schemaVersion"] != 27 or data["profile"] != PROFILE:
        raise NativeBoundaryV27Error("V27 native stage plan profile changed")
    if not isinstance(data["operationId"], str) or not _EFFECT_OPERATION_ID.fullmatch(
        data["operationId"]
    ):
        raise NativeBoundaryV27Error("V27 native stage operation id is invalid")
    if data["operationClass"] not in _EFFECT_CLASSES:
        raise NativeBoundaryV27Error("V27 native stage operation class is invalid")
    _digest(data["effectPlanSha256"], "native stage effectPlanSha256")
    _digest(data["requestKeyId"], "native stage requestKeyId")
    schedule = literal_stage_schedule_v27(str(data["operationClass"]))
    location = data["stageLocation"]
    if type(location) is not int or not 1 <= location <= len(schedule):
        raise NativeBoundaryV27Error("V27 native stage location is invalid")
    stage = schedule[location - 1]
    if (
        data["stageKey"], data["stageKind"], data["actionKind"]
    ) != (stage.stage_key, stage.stage_kind, stage.action_kind):
        raise NativeBoundaryV27Error("V27 native stage coordinate changed")
    if stage.stage_kind != _NATIVE_PAYLOAD_STAGE_KIND_V27:
        raise NativeBoundaryV27Error("V27 native launch is outside payload-terminal")
    _absolute(data["repositoryPath"], "native stage repositoryPath")
    custody = data["repositoryCustody"]
    if custody is not None:
        custody = validate_repository_custody_binding_v27(
            custody, repository_path=str(data["repositoryPath"])
        )
    argv = data["argv"]
    if (
        not isinstance(argv, list)
        or not 1 <= len(argv) <= 64
        or argv[0] != "/usr/local/bin/bd"
        or any(
            not isinstance(item, str)
            or not item
            or "\0" in item
            or len(item.encode("utf-8")) > 4096
            for item in argv
        )
    ):
        raise NativeBoundaryV27Error("V27 native stage argv is invalid")
    if (
        data["imageReference"] != manifest.image_reference
        or data["imageDigest"] != manifest.image_digest
        or data["networkMode"] != "none"
        or data["pullPolicy"] != "never"
        or data["environment"]
        != {
            "BD_JSON_ENVELOPE": "1",
            "HOME": "/run/startup-factory/home",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        }
        or data["stagePlanSha256"] != _native_stage_plan_digest_v27(data)
    ):
        raise NativeBoundaryV27Error("V27 native stage policy/digest changed")
    return {
        **data,
        "argv": list(argv),
        "environment": dict(data["environment"]),
        "repositoryCustody": custody,
    }


def _decode_cgroup_stat_evidence_v27(
    value: Any, label: str
) -> dict[str, int]:
    if (
        not isinstance(value, Mapping)
        or set(value) < {"nr_descendants", "nr_dying_descendants"}
        or any(
            not isinstance(name, str)
            or (
                name not in {"nr_descendants", "nr_dying_descendants"}
                and re.fullmatch(
                    r"nr_(?:dying_)?subsys_[a-z][a-z0-9_]{0,31}", name
                ) is None
            )
            or type(counter) is not int
            or not 0 <= counter <= (1 << 64) - 1
            for name, counter in value.items()
        )
    ):
        raise NativeBoundaryV27Error(f"V27 {label} cgroup.stat changed")
    live = {
        name.removeprefix("nr_subsys_")
        for name in value
        if name.startswith("nr_subsys_")
    }
    dying = {
        name.removeprefix("nr_dying_subsys_")
        for name in value
        if name.startswith("nr_dying_subsys_")
    }
    if live != dying:
        raise NativeBoundaryV27Error(f"V27 {label} cgroup.stat pairs changed")
    return {str(name): int(counter) for name, counter in value.items()}


def _decode_controller_retirement_v27(value: Any, placement_mask: int) -> dict[str, Any]:
    fields = {
        "schemaVersion", "visibleDescendants", "placementMask",
        "controllerTrackedPlacementMask", "initControllers",
        "preRemovalCgroupStat", "terminalCgroupStat",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeBoundaryV27Error("V27 controller retirement receipt shape changed")
    pre_removal = _decode_cgroup_stat_evidence_v27(
        value["preRemovalCgroupStat"], "pre-removal"
    )
    terminal = _decode_cgroup_stat_evidence_v27(
        value["terminalCgroupStat"], "terminal"
    )
    if (
        value["schemaVersion"] != 27
        or type(value["visibleDescendants"]) is not int
        or not 0 <= value["visibleDescendants"] <= 8
        or type(value["placementMask"]) is not int
        or type(value["controllerTrackedPlacementMask"]) is not int
        or value["placementMask"] != placement_mask
        or value["controllerTrackedPlacementMask"] != placement_mask
        or value["initControllers"] not in ([], ["cpu", "memory", "pids"])
        or pre_removal["nr_descendants"] != value["visibleDescendants"]
        or terminal["nr_descendants"] != 0
    ):
        raise NativeBoundaryV27Error("V27 controller retirement receipt is invalid")
    return {
        **dict(value),
        "preRemovalCgroupStat": pre_removal,
        "terminalCgroupStat": terminal,
    }


def _decode_native_stage_result_v27(
    value: Any, *, require_discriminants: bool = False
) -> dict[str, Any]:
    base_fields = {"exitCode", "stdout", "stderr", "lifecycle", "placementMask"}
    discriminants = {
        "resultKind", "resultPredecessorKind", "failureEvidenceSha256"
    }
    admitted = {
        frozenset(base_fields),
        frozenset(base_fields | {"controllerRetirement"}),
    }
    if not require_discriminants:
        admitted |= {
            frozenset(base_fields | discriminants),
            frozenset(base_fields | discriminants | {"controllerRetirement"}),
        }
    else:
        admitted = {
            frozenset(base_fields | discriminants),
            frozenset(base_fields | discriminants | {"controllerRetirement"}),
        }
    if not isinstance(value, Mapping) or set(value) not in admitted:
        raise NativeBoundaryV27Error("V27 native stage result shape is invalid")
    decoded_discriminants: tuple[str, str, str | None] | None = None
    if discriminants <= set(value):
        decoded_discriminants = _stage_result_discriminants_v27(value)
    result_kind = (
        None if decoded_discriminants is None else decoded_discriminants[0]
    )
    if (
        type(value["exitCode"]) is not int
        or not -255 <= value["exitCode"] <= 255
        or type(value["placementMask"]) is not int
        or (
            result_kind is None
            and value["placementMask"] not in _LIFECYCLE_RECOVERY_MASKS_V27
        )
        or (
            result_kind is not None
            and not _placement_mask_matches_result_v27(
                value["placementMask"], result_kind
            )
        )
        or list(value["lifecycle"]) != list(_EFFECT_LIFECYCLE)
        or any(
            not isinstance(value[field], bytes)
            or len(value[field]) > MAX_CANONICAL_BYTES // 2
            for field in ("stdout", "stderr")
        )
    ):
        raise NativeBoundaryV27Error("V27 native stage result is outside policy")
    result = {
        "exitCode": value["exitCode"],
        "stdoutBase64": base64.b64encode(value["stdout"]).decode("ascii"),
        "stderrBase64": base64.b64encode(value["stderr"]).decode("ascii"),
        "stdoutSha256": sha256(value["stdout"]),
        "stderrSha256": sha256(value["stderr"]),
        "lifecycle": list(value["lifecycle"]),
        "placementMask": value["placementMask"],
    }
    if decoded_discriminants is not None:
        result_kind, predecessor_kind, failure_evidence = decoded_discriminants
        result.update(
            {
                "resultKind": result_kind,
                "resultPredecessorKind": predecessor_kind,
                "failureEvidenceSha256": failure_evidence,
            }
        )
    elif require_discriminants:
        raise NativeBoundaryV27Error(
            "V27 production native stage omitted result discriminants"
        )
    if "controllerRetirement" in value:
        result["controllerRetirement"] = _decode_controller_retirement_v27(
            value["controllerRetirement"], value["placementMask"]
        )
    return result


def _retirement_identity_v27(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "device", "gid", "inode", "mode", "nlink", "uid"
    }:
        raise NativeBoundaryV27Error(f"V27 {label} identity shape changed")
    if (
        any(type(value[field]) is not int or value[field] < 0 for field in (
            "device", "gid", "inode", "nlink", "uid"
        ))
        or not isinstance(value["mode"], str)
        or re.fullmatch(r"[0-7]{4}", value["mode"]) is None
        or value["nlink"] < 1
    ):
        raise NativeBoundaryV27Error(f"V27 {label} identity is invalid")
    return dict(value)


def _retirement_payload_identity_v27(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "device", "gid", "inode", "mode", "uid"
    }:
        raise NativeBoundaryV27Error(
            "V27 controller payload identity shape changed"
        )
    if (
        any(type(value[field]) is not int or value[field] < 0 for field in (
            "device", "gid", "inode", "uid"
        ))
        or not isinstance(value["mode"], str)
        or re.fullmatch(r"[0-7]{4}", value["mode"]) is None
    ):
        raise NativeBoundaryV27Error(
            "V27 controller payload identity is invalid"
        )
    return dict(value)


def _decode_controller_retirement_intent_v27(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schemaVersion", "payloadIdentity", "placementMask",
        "visibleDescendants", "initControllers", "preRemovalCgroupStat",
        "removalPlan",
    }:
        raise NativeBoundaryV27Error(
            "V27 controller retirement intent shape changed"
        )
    mask = value["placementMask"]
    removal = value["removalPlan"]
    if (
        value["schemaVersion"] != 27
        or type(mask) is not int
        or mask not in _LIFECYCLE_RECOVERY_MASKS_V27
        or type(value["visibleDescendants"]) is not int
        or not 0 <= value["visibleDescendants"] <= 8
        or not isinstance(value["initControllers"], list)
        or value["initControllers"] not in (
            [], list(_DELEGATED_CONTROLLERS_V27)
        )
        or not isinstance(removal, list)
        or len(removal) > 8
    ):
        raise NativeBoundaryV27Error(
            "V27 controller retirement intent is invalid"
        )
    payload_identity = _retirement_payload_identity_v27(
        value["payloadIdentity"]
    )
    pre_removal = _decode_cgroup_stat_evidence_v27(
        value["preRemovalCgroupStat"], "pre-removal"
    )
    if pre_removal["nr_descendants"] != value["visibleDescendants"]:
        raise NativeBoundaryV27Error(
            "V27 controller retirement pre-removal count changed"
        )
    decoded: list[dict[str, Any]] = []
    leaf_ordinals: set[int] = set()
    split_names: set[str] = set()
    for item in removal:
        if not isinstance(item, Mapping) or set(item) != {
            "parent", "name", "identity"
        }:
            raise NativeBoundaryV27Error(
                "V27 controller retirement removal row changed"
            )
        parent = item["parent"]
        name = item["name"]
        if parent == "payload":
            match = re.fullmatch(r"lifecycle-([0-5])", str(name))
            if match is None:
                raise NativeBoundaryV27Error(
                    "V27 controller retirement lifecycle row changed"
                )
            leaf_ordinals.add(int(match.group(1)))
        elif parent == "lifecycle-1":
            if name != "runtime" and (
                not isinstance(name, str)
                or _SPLIT_PAYLOAD_NAME_V27.fullmatch(name) is None
            ):
                raise NativeBoundaryV27Error(
                    "V27 controller retirement split row changed"
                )
            split_names.add(str(name))
        else:
            raise NativeBoundaryV27Error(
                "V27 controller retirement parent changed"
            )
        decoded.append(
            {
                "parent": parent,
                "name": str(name),
                "identity": _retirement_identity_v27(
                    item["identity"], "controller removal row"
                ),
            }
        )
    if (
        len(leaf_ordinals) != sum(
            item["parent"] == "payload" for item in decoded
        )
        or mask != sum(1 << ordinal for ordinal in leaf_ordinals)
        or bool(split_names) and 1 not in leaf_ordinals
        or value["visibleDescendants"] != len(decoded)
    ):
        raise NativeBoundaryV27Error(
            "V27 controller retirement topology does not bind its mask"
        )
    return {
        "schemaVersion": 27,
        "payloadIdentity": payload_identity,
        "placementMask": mask,
        "visibleDescendants": value["visibleDescendants"],
        "initControllers": list(value["initControllers"]),
        "preRemovalCgroupStat": pre_removal,
        "removalPlan": decoded,
    }


def _stage_result_observation_v27(
    objects: Path, key: bytes, stage_key: str
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for name in os.listdir(objects):
        if not re.fullmatch(r"[0-9a-f]{64}\.json", name):
            raise NativeBoundaryV27Error("V27 stage-object directory has an unexpected entry")
        record = _read_effect_record(objects / name, key)
        if record["kind"] == "StageActionResultV1" and record["payload"].get(
            "stageKey"
        ) == stage_key:
            matches.append(record)
    if len(matches) != 1:
        raise NativeBoundaryV27Error(
            f"V27 terminal aggregation requires one {stage_key} result"
        )
    observation = matches[0]["payload"].get("observation")
    if not isinstance(observation, dict):
        raise NativeBoundaryV27Error("V27 stored native stage observation changed")
    return observation


_ISSUE_V112_REQUIRED_FIELDS: Final = {
    "id", "title", "priority", "created_at", "updated_at"
}
_ISSUE_V112_ALLOWED_FIELDS: Final = _ISSUE_V112_REQUIRED_FIELDS | {
    "description", "design", "acceptance_criteria", "notes", "spec_id",
    "status", "issue_type", "assignee", "owner", "estimated_minutes",
    "created_by", "started_at", "closed_at", "close_reason",
    "closed_by_session", "due_at", "defer_until", "external_ref",
    "source_system", "metadata", "compaction_level", "compacted_at",
    "compacted_at_commit", "original_size", "labels", "dependencies",
    "comments", "sender", "ephemeral", "no_history", "wisp_type",
    "pinned", "is_template", "bonded_from", "await_type", "await_id",
    "timeout", "waiters", "source_formula", "source_location", "mol_type",
    "work_type", "event_kind", "actor", "target", "payload",
}
_ISSUE_V112_INTERNAL_FIELDS: Final = {
    "sender", "ephemeral", "no_history", "wisp_type", "pinned",
    "is_template", "bonded_from",
    "await_type", "await_id", "timeout", "waiters", "source_formula",
    "source_location", "mol_type", "work_type", "event_kind", "actor",
    "target", "payload",
}
_ISSUE_V112_STRING_FIELDS: Final = {
    "description", "design", "acceptance_criteria", "notes", "spec_id",
    "status", "issue_type", "assignee", "owner", "created_by",
    "close_reason", "closed_by_session", "source_system", "sender",
    "wisp_type", "await_type", "await_id", "source_formula",
    "source_location", "mol_type", "work_type", "event_kind", "actor",
    "target", "payload",
}
_ISSUE_V112_NULLABLE_STRING_FIELDS: Final = {
    "external_ref", "compacted_at_commit",
}
_ISSUE_V112_NULLABLE_TIMESTAMP_FIELDS: Final = {
    "started_at", "closed_at", "due_at", "defer_until", "compacted_at",
}
_ISSUE_V112_INTEGER_FIELDS: Final = {"compaction_level", "original_size", "timeout"}
_ISSUE_V112_BOOLEAN_FIELDS: Final = {
    "ephemeral", "no_history", "pinned", "is_template",
}
_RFC3339_V112 = re.compile(
    r"\A(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?P<fraction>\.[0-9]{1,9})?"
    r"(?P<zone>Z|(?P<zone_sign>[+-])(?P<zone_hour>[0-9]{2}):"
    r"(?P<zone_minute>[0-9]{2}))\Z"
)
_BEADS_ID_V112 = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _bounded_v112_string(value: Any, label: str, *, maximum: int = 65_536) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or "\0" in value
    ):
        raise NativeBoundaryV27Error(f"V27 {label} is not a bounded string")
    return value


def _timestamp_v112(value: Any, label: str) -> str:
    result = _bounded_v112_string(value, label, maximum=64)
    match = _RFC3339_V112.fullmatch(result)
    if match is None:
        raise NativeBoundaryV27Error(f"V27 {label} is not canonical RFC3339")
    year = int(match.group("year"))
    month = int(match.group("month"))
    day = int(match.group("day"))
    hour = int(match.group("hour"))
    minute = int(match.group("minute"))
    second = int(match.group("second"))
    if month < 1 or month > 12:
        raise NativeBoundaryV27Error(f"V27 {label} has an impossible calendar month")
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    month_days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if (
        day < 1
        or day > month_days[month - 1]
        or hour > 23
        or minute > 59
        or second > 59
    ):
        raise NativeBoundaryV27Error(f"V27 {label} has an impossible calendar time")
    fraction = match.group("fraction")
    if fraction is not None and fraction.endswith("0"):
        raise NativeBoundaryV27Error(
            f"V27 {label} is not the canonical RFC3339Nano fraction"
        )
    if match.group("zone") != "Z":
        zone_hour = int(match.group("zone_hour"))
        zone_minute = int(match.group("zone_minute"))
        if zone_hour > 23 or zone_minute > 59:
            raise NativeBoundaryV27Error(f"V27 {label} has an impossible UTC offset")
        if zone_hour == 0 and zone_minute == 0:
            raise NativeBoundaryV27Error(
                f"V27 {label} must use Z for the canonical zero UTC offset"
            )
    return result


def _signed_int64_v112(
    value: Any,
    label: str,
    *,
    minimum: int = _SIGNED_INT64_MIN,
    maximum: int = _SIGNED_INT64_MAX,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise NativeBoundaryV27Error(f"V27 {label} is outside signed int64")
    return value


def _issue_string_array_v112(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(
            not isinstance(item, str)
            or not item
            or "\0" in item
            or len(item.encode("utf-8")) > 65_536
            for item in value
        )
    ):
        raise NativeBoundaryV27Error(f"V27 {label} is not a string array")
    return list(value)


def _issue_dependency_v112(value: Any, label: str) -> None:
    required = {"issue_id", "depends_on_id", "type", "created_at"}
    allowed = required | {"created_by", "metadata", "thread_id"}
    if not isinstance(value, dict) or required - set(value) or set(value) - allowed:
        raise NativeBoundaryV27Error(f"V27 {label} shape changed")
    for field in ("issue_id", "depends_on_id"):
        identity = _bounded_v112_string(value[field], f"{label}.{field}", maximum=128)
        if _BEADS_ID_V112.fullmatch(identity) is None:
            raise NativeBoundaryV27Error(f"V27 {label}.{field} grammar changed")
    _bounded_v112_string(value["type"], f"{label}.type", maximum=128)
    _timestamp_v112(value["created_at"], f"{label}.created_at")
    for field in ("created_by", "metadata", "thread_id"):
        if field in value:
            _bounded_v112_string(value[field], f"{label}.{field}")


def _issue_comment_v112(value: Any, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "id", "issue_id", "author", "text", "created_at"
    }:
        raise NativeBoundaryV27Error(f"V27 {label} shape changed")
    for field in ("id", "issue_id"):
        identity = _bounded_v112_string(value[field], f"{label}.{field}", maximum=128)
        if _BEADS_ID_V112.fullmatch(identity) is None:
            raise NativeBoundaryV27Error(f"V27 {label}.{field} grammar changed")
    _bounded_v112_string(value["author"], f"{label}.author")
    _bounded_v112_string(value["text"], f"{label}.text")
    _timestamp_v112(value["created_at"], f"{label}.created_at")


def _issue_bond_ref_v112(value: Any, label: str) -> None:
    if (
        not isinstance(value, dict)
        or not {"source_id", "bond_type"} <= set(value)
        or set(value) - {"source_id", "bond_type", "bond_point"}
    ):
        raise NativeBoundaryV27Error(f"V27 {label} shape changed")
    _bounded_v112_string(value["source_id"], f"{label}.source_id", maximum=128)
    _bounded_v112_string(value["bond_type"], f"{label}.bond_type", maximum=128)
    if "bond_point" in value:
        _bounded_v112_string(value["bond_point"], f"{label}.bond_point", maximum=128)


def _issue_v112(
    value: Any,
    label: str,
    *,
    extra_fields: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NativeBoundaryV27Error(f"V27 {label} is not an IssueV112 object")
    allowed = _ISSUE_V112_ALLOWED_FIELDS | set(extra_fields)
    missing = _ISSUE_V112_REQUIRED_FIELDS - set(value)
    extra = set(value) - allowed
    if missing or extra:
        raise NativeBoundaryV27Error(
            f"V27 {label} has a non-exact IssueV112 member set"
        )
    issue_id = _bounded_v112_string(value["id"], f"{label}.id", maximum=128)
    if _BEADS_ID_V112.fullmatch(issue_id) is None:
        raise NativeBoundaryV27Error(f"V27 {label}.id grammar changed")
    _bounded_v112_string(value["title"], f"{label}.title")
    _signed_int64_v112(value["priority"], f"{label}.priority", minimum=0, maximum=4)
    _timestamp_v112(value["created_at"], f"{label}.created_at")
    _timestamp_v112(value["updated_at"], f"{label}.updated_at")
    for field in _ISSUE_V112_STRING_FIELDS:
        if field in value:
            _bounded_v112_string(value[field], f"{label}.{field}")
    for field in _ISSUE_V112_NULLABLE_STRING_FIELDS:
        if field in value and value[field] is not None:
            if not isinstance(value[field], str) or "\0" in value[field] or len(
                value[field].encode("utf-8")
            ) > 65_536:
                raise NativeBoundaryV27Error(f"V27 {label}.{field} is invalid")
    if "estimated_minutes" in value and value["estimated_minutes"] is not None:
        _signed_int64_v112(
            value["estimated_minutes"], f"{label}.estimated_minutes", minimum=0
        )
    for field in _ISSUE_V112_NULLABLE_TIMESTAMP_FIELDS:
        if field in value and value[field] is not None:
            _timestamp_v112(value[field], f"{label}.{field}")
    for field in _ISSUE_V112_INTEGER_FIELDS:
        if field in value:
            _signed_int64_v112(value[field], f"{label}.{field}")
    for field in _ISSUE_V112_BOOLEAN_FIELDS:
        if field in value and type(value[field]) is not bool:
            raise NativeBoundaryV27Error(f"V27 {label}.{field} is not boolean")
    if "metadata" in value and len(canonical_bytes(value["metadata"])) > 65_536:
        raise NativeBoundaryV27Error(f"V27 {label}.metadata is oversized")
    if "labels" in value:
        labels = _issue_string_array_v112(value["labels"], f"{label}.labels")
        if (
            labels != sorted(labels, key=lambda item: item.encode("utf-8"))
            or len(labels) != len(set(labels))
        ):
            raise NativeBoundaryV27Error(f"V27 {label}.labels are noncanonical")
    if "waiters" in value:
        _issue_string_array_v112(value["waiters"], f"{label}.waiters")
    if "dependencies" in value:
        if not isinstance(value["dependencies"], list):
            raise NativeBoundaryV27Error(f"V27 {label}.dependencies is not an array")
        for ordinal, dependency in enumerate(value["dependencies"]):
            _issue_dependency_v112(dependency, f"{label}.dependencies[{ordinal}]")
    if "comments" in value:
        if not isinstance(value["comments"], list):
            raise NativeBoundaryV27Error(f"V27 {label}.comments is not an array")
        for ordinal, comment in enumerate(value["comments"]):
            _issue_comment_v112(comment, f"{label}.comments[{ordinal}]")
    if "bonded_from" in value:
        if not isinstance(value["bonded_from"], list):
            raise NativeBoundaryV27Error(f"V27 {label}.bonded_from is not an array")
        for ordinal, bond in enumerate(value["bonded_from"]):
            _issue_bond_ref_v112(bond, f"{label}.bonded_from[{ordinal}]")
    for field in _ISSUE_V112_INTERNAL_FIELDS:
        if field in value and value[field] not in (None, False, "", [], {}):
            raise NativeBoundaryV27Error(
                f"V27 {label}.{field} is outside the supported regular domain"
            )
    return dict(value)


def _read_back_envelope_v27(raw: bytes, ordinal: int) -> Any:
    value = _beads_wire_value_v112(raw, f"reader {ordinal} envelope")
    if (
        not isinstance(value, dict)
        or set(value) != {"data", "schema_version"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise NativeBoundaryV27Error(
            f"V27 reader {ordinal} envelope is not exact schema version 1"
        )
    return value["data"]


def decode_beads_read_back_outputs_v27(
    raw_reads: Any, *, target_id: str
) -> dict[str, Any]:
    """Decode the four distinct pinned bd-v1.1.2 result schemas.

    This performs semantic joins only.  It deliberately does not infer
    physical equality from unrelated command stdout; physical equality belongs
    to independently captured raw store manifests in the stage engine.
    """

    if (
        not isinstance(raw_reads, list)
        or len(raw_reads) != 4
        or any(type(item) is not bytes for item in raw_reads)
        or not isinstance(target_id, str)
        or _BEADS_ID_V112.fullmatch(target_id) is None
    ):
        raise NativeBoundaryV27Error("V27 four-reader input is malformed")
    data = [_read_back_envelope_v27(raw, ordinal) for ordinal, raw in enumerate(raw_reads)]
    if not isinstance(data[0], list) or len(data[0]) != 1:
        raise NativeBoundaryV27Error("V27 reader 0 must return exactly one issue")
    issue = _issue_v112(
        data[0][0],
        "reader 0 issue",
        extra_fields={"dependency_count", "dependent_count", "comment_count", "parent"},
    )
    if issue["id"] != target_id:
        raise NativeBoundaryV27Error("V27 reader 0 returned another issue")
    for field in ("dependency_count", "dependent_count", "comment_count"):
        _signed_int64_v112(
            issue.get(field), f"reader 0 {field}", minimum=0, maximum=262_144
        )
    if "parent" in issue and issue["parent"] is not None:
        parent = _bounded_v112_string(issue["parent"], "reader 0 parent", maximum=128)
        if _BEADS_ID_V112.fullmatch(parent) is None:
            raise NativeBoundaryV27Error("V27 reader 0 parent grammar changed")
    status = _bounded_v112_string(issue.get("status"), "reader 0 status")

    labels = data[1]
    if (
        not isinstance(labels, list)
        or any(not isinstance(item, str) or not item for item in labels)
        or labels != sorted(labels, key=lambda item: item.encode("utf-8"))
        or len(labels) != len(set(labels))
        or labels != issue.get("labels", [])
    ):
        raise NativeBoundaryV27Error("V27 reader 1 labels do not exactly join reader 0")

    comments = data[2]
    comment_fields = {"id", "issue_id", "author", "text", "created_at"}
    if not isinstance(comments, list) or len(comments) != issue["comment_count"]:
        raise NativeBoundaryV27Error("V27 reader 2 comment count changed")
    comment_order: list[tuple[str, str]] = []
    comment_ids: list[str] = []
    for ordinal, comment in enumerate(comments):
        if not isinstance(comment, dict) or set(comment) != comment_fields:
            raise NativeBoundaryV27Error("V27 reader 2 comment shape changed")
        comment_id = _bounded_v112_string(
            comment["id"], f"reader 2 comment {ordinal} id", maximum=128
        )
        if _BEADS_ID_V112.fullmatch(comment_id) is None or comment["issue_id"] != target_id:
            raise NativeBoundaryV27Error("V27 reader 2 comment identity changed")
        _bounded_v112_string(comment["author"], f"reader 2 comment {ordinal} author")
        _bounded_v112_string(comment["text"], f"reader 2 comment {ordinal} text")
        created = _timestamp_v112(
            comment["created_at"], f"reader 2 comment {ordinal} created_at"
        )
        comment_order.append((created, comment_id))
        comment_ids.append(comment_id)
    if comment_order != sorted(comment_order) or len(comment_ids) != len(set(comment_ids)):
        raise NativeBoundaryV27Error("V27 reader 2 comments are duplicated or unordered")

    dependencies = data[3]
    if not isinstance(dependencies, list) or len(dependencies) != issue["dependency_count"]:
        raise NativeBoundaryV27Error("V27 reader 3 dependency count changed")
    dependency_projection: list[dict[str, str]] = []
    seen_dependencies: set[tuple[str, str]] = set()
    for ordinal, dependency in enumerate(dependencies):
        row = _issue_v112(
            dependency,
            f"reader 3 dependency {ordinal}",
            extra_fields={"dependency_type"},
        )
        dependency_type = _bounded_v112_string(
            row.get("dependency_type"),
            f"reader 3 dependency {ordinal} type",
            maximum=128,
        )
        identity = (row["id"], dependency_type)
        if identity in seen_dependencies or row["id"] == target_id:
            raise NativeBoundaryV27Error("V27 reader 3 dependency identity changed")
        seen_dependencies.add(identity)
        dependency_projection.append(
            {"dependencyType": dependency_type, "id": row["id"]}
        )
    if dependency_projection != sorted(
        dependency_projection,
        key=lambda item: (item["id"].encode("utf-8"), item["dependencyType"].encode("utf-8")),
    ):
        raise NativeBoundaryV27Error("V27 reader 3 dependencies are unordered")

    return {
        "commentIds": comment_ids,
        "dependencies": dependency_projection,
        "labels": list(labels),
        "projection": {
            "id": target_id,
            "revision": issue["updated_at"],
            "status": status,
        },
    }


def _physical_scan_observation_v27(
    objects: Path,
    key: bytes,
    stage_key: str,
    *,
    capture_ordinal: str,
) -> dict[str, Any]:
    observation = _stage_result_observation_v27(objects, key, stage_key)
    if set(observation) != {"physicalStoreScan"}:
        raise NativeBoundaryV27Error(
            f"V27 {stage_key} is not an independent physical store scan"
        )
    scan = observation["physicalStoreScan"]
    if not isinstance(scan, dict) or set(scan) != {
        "schemaVersion",
        "captureOrdinal",
        "entryCount",
        "repositoryAncestry",
        "repositoryAncestrySha256",
        "rawProjection",
        "rawProjectionSha256",
        "normalizedProjection",
        "normalizedProjectionSha256",
        "stableProjection",
        "stableProjectionSha256",
        "normalizationProfile",
        "normalizedTransitionPaths",
    }:
        raise NativeBoundaryV27Error(
            f"V27 {stage_key} physical store scan shape changed"
        )
    if (
        scan["schemaVersion"] != 27
        or scan["captureOrdinal"] != capture_ordinal
        or type(scan["entryCount"]) is not int
        or not 1 <= scan["entryCount"] <= 262_144
        or scan["normalizationProfile"]
        != "beads-v1.1.2-noms-manifest-transition-only-v1"
        or not isinstance(scan["repositoryAncestry"], list)
        or not isinstance(scan["rawProjection"], dict)
        or not isinstance(scan["normalizedProjection"], dict)
        or not isinstance(scan["stableProjection"], dict)
        or not isinstance(scan["normalizedTransitionPaths"], list)
        or scan["repositoryAncestrySha256"]
        != sha256(canonical_bytes(scan["repositoryAncestry"]))
        or scan["rawProjectionSha256"]
        != sha256(canonical_bytes(scan["rawProjection"]))
        or scan["normalizedProjectionSha256"]
        != sha256(canonical_bytes(scan["normalizedProjection"]))
        or scan["stableProjectionSha256"]
        != sha256(canonical_bytes(scan["stableProjection"]))
    ):
        raise NativeBoundaryV27Error(
            f"V27 {stage_key} physical store scan identity changed"
        )
    _digest(scan["rawProjectionSha256"], f"{stage_key} rawProjectionSha256")
    _digest(
        scan["repositoryAncestrySha256"],
        f"{stage_key} repositoryAncestrySha256",
    )
    _digest(
        scan["normalizedProjectionSha256"],
        f"{stage_key} normalizedProjectionSha256",
    )
    return dict(scan)


_APPROVED_NOMS_MANIFEST_V112 = re.compile(
    r"\A\.beads/embeddeddolt/[a-z][a-z0-9_]{0,31}/\.dolt/noms/manifest\Z"
)


def _physical_identity_v27(
    metadata: os.stat_result,
    *,
    path: str,
    entry_type: str,
) -> dict[str, Any]:
    return {
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "linkCount": metadata.st_nlink,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "path": path,
        "type": entry_type,
        "uid": metadata.st_uid,
    }


def _same_physical_identity_v27(
    left: os.stat_result, right: os.stat_result
) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_uid,
        left.st_gid,
        left.st_mode,
        left.st_nlink,
        left.st_size,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_uid,
        right.st_gid,
        right.st_mode,
        right.st_nlink,
        right.st_size,
    )


def _open_pinned_repository_v27(
    repository: Path,
) -> tuple[int, list[dict[str, Any]]]:
    if not repository.is_absolute() or str(repository) != os.path.normpath(str(repository)):
        raise NativeBoundaryV27Error(
            "V27 physical scan repository path is not normalized absolute"
        )
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open("/", flags)
    except OSError as exc:
        raise NativeBoundaryV27Error("V27 physical scan cannot pin filesystem root") from exc
    ancestry = [
        _physical_identity_v27(
            os.fstat(descriptor), path="/", entry_type="directory"
        )
    ]
    traversed = PurePosixPath("/")
    try:
        for component in repository.parts[1:]:
            if component in {"", ".", ".."} or "/" in component or "\0" in component:
                raise NativeBoundaryV27Error(
                    "V27 physical scan repository component is invalid"
                )
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise NativeBoundaryV27Error(
                    "V27 physical scan cannot pin repository ancestry"
                ) from exc
            metadata = os.fstat(child)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(child)
                raise NativeBoundaryV27Error(
                    "V27 physical scan ancestry contains a non-directory"
                )
            os.close(descriptor)
            descriptor = child
            traversed /= component
            ancestry.append(
                _physical_identity_v27(
                    metadata, path=traversed.as_posix(), entry_type="directory"
                )
            )
        return descriptor, ancestry
    except Exception:
        os.close(descriptor)
        raise


def _rebind_physical_ancestry_v27(
    repository: Path, expected: list[dict[str, Any]]
) -> int:
    descriptor, observed = _open_pinned_repository_v27(repository)
    if len(observed) != len(expected):
        os.close(descriptor)
        raise NativeBoundaryV27Error(
            "V27 physical scan repository ancestry changed during traversal"
        )
    for index, (before, after) in enumerate(zip(expected, observed)):
        # A shared ancestor's link count can legitimately change when an
        # unrelated sibling directory is created.  Its path/dev/inode/owner/
        # mode binding must remain exact; the repository leaf is fully exact.
        compared_before = dict(before)
        compared_after = dict(after)
        if index < len(expected) - 1:
            compared_before.pop("linkCount", None)
            compared_after.pop("linkCount", None)
        if canonical_bytes(compared_before) != canonical_bytes(compared_after):
            os.close(descriptor)
            raise NativeBoundaryV27Error(
                "V27 physical scan repository ancestry changed during traversal"
            )
    return descriptor


def _capture_physical_store_scan_v27(
    repository_path: str,
    *,
    capture_ordinal: str,
) -> dict[str, Any]:
    """Build one descriptor-relative raw and narrowly normalized store manifest."""

    repository = Path(repository_path)
    repository_fd, ancestry = _open_pinned_repository_v27(repository)
    directory_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        store_fd = os.open(".beads", directory_flags, dir_fd=repository_fd)
    except OSError as exc:
        os.close(repository_fd)
        raise NativeBoundaryV27Error("V27 physical scan store is unavailable") from exc
    store_metadata = os.fstat(store_fd)
    if not stat.S_ISDIR(store_metadata.st_mode):
        os.close(store_fd)
        os.close(repository_fd)
        raise NativeBoundaryV27Error("V27 physical scan store root is unsafe")

    raw_entries: list[dict[str, Any]] = [
        _physical_identity_v27(
            store_metadata, path=".beads", entry_type="directory"
        )
    ]
    normalized_entries: list[dict[str, Any]] = [dict(raw_entries[0])]
    normalized_transition_paths: list[str] = []
    total_bytes = 0

    def visit(directory_fd: int, relative: PurePosixPath) -> None:
        nonlocal total_bytes
        try:
            children = sorted(os.listdir(directory_fd), key=os.fsencode)
        except OSError as exc:
            raise NativeBoundaryV27Error(
                "V27 physical scan cannot enumerate the store"
            ) from exc
        for name in children:
            if (
                not isinstance(name, str)
                or not name
                or name in {".", ".."}
                or "/" in name
                or "\0" in name
            ):
                raise NativeBoundaryV27Error(
                    "V27 physical scan entry name is invalid"
                )
            child_relative = relative / name
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise NativeBoundaryV27Error(
                    "V27 physical scan entry identity is unavailable"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise NativeBoundaryV27Error(
                    "V27 physical scan refuses symlinked store entries"
                )
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise NativeBoundaryV27Error(
                        "V27 physical scan cannot pin a store directory"
                    ) from exc
                opened = os.fstat(child_fd)
                if not _same_physical_identity_v27(metadata, opened):
                    os.close(child_fd)
                    raise NativeBoundaryV27Error(
                        "V27 physical scan directory changed during open"
                    )
                directory_entry = _physical_identity_v27(
                    opened,
                    path=child_relative.as_posix(),
                    entry_type="directory",
                )
                raw_entries.append(directory_entry)
                normalized_entries.append(dict(directory_entry))
                visit(child_fd, child_relative)
                after = os.fstat(child_fd)
                os.close(child_fd)
                rebound = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    not _same_physical_identity_v27(opened, after)
                    or not _same_physical_identity_v27(opened, rebound)
                ):
                    raise NativeBoundaryV27Error(
                        "V27 physical scan directory binding changed during traversal"
                    )
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise NativeBoundaryV27Error(
                    "V27 physical scan refuses non-regular or linked store entries"
                )
            if not 0 <= metadata.st_size <= MAX_CANONICAL_BYTES:
                raise NativeBoundaryV27Error(
                    "V27 physical scan entry exceeds the byte cap"
                )
            total_bytes += metadata.st_size
            if total_bytes > 64 * 1024 * 1024:
                raise NativeBoundaryV27Error(
                    "V27 physical scan exceeds the aggregate byte cap"
                )
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(descriptor)
                    if (
                        opened.st_dev != metadata.st_dev
                        or opened.st_ino != metadata.st_ino
                        or opened.st_mode != metadata.st_mode
                        or opened.st_uid != metadata.st_uid
                        or opened.st_gid != metadata.st_gid
                        or opened.st_nlink != metadata.st_nlink
                        or opened.st_size != metadata.st_size
                    ):
                        raise NativeBoundaryV27Error(
                            "V27 physical scan entry changed during capture"
                        )
                    raw = _pread_exact_bounded_v27(
                        descriptor,
                        opened.st_size,
                        "physical store entry",
                    )
                    after = os.fstat(descriptor)
                    if not _same_physical_identity_v27(opened, after):
                        raise NativeBoundaryV27Error(
                            "V27 physical scan entry changed after content read"
                        )
                finally:
                    os.close(descriptor)
            except OSError as exc:
                raise NativeBoundaryV27Error(
                    "V27 physical scan cannot open a store entry"
                ) from exc
            rebound = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not _same_physical_identity_v27(opened, rebound):
                raise NativeBoundaryV27Error(
                    "V27 physical scan entry final-name binding changed"
                )
            raw_entry = {
                **_physical_identity_v27(
                    opened,
                    path=child_relative.as_posix(),
                    entry_type="file",
                ),
                "sha256": sha256(raw),
                "size": opened.st_size,
            }
            raw_entries.append(raw_entry)
            if _APPROVED_NOMS_MANIFEST_V112.fullmatch(child_relative.as_posix()):
                normalized_transition_paths.append(child_relative.as_posix())
                normalized_entries.append(
                    {
                        **raw_entry,
                        "device": "approved-v1.1.2-noms-manifest-volatile",
                        "inode": "approved-v1.1.2-noms-manifest-volatile",
                    }
                )
            else:
                normalized_entries.append(dict(raw_entry))
            if len(raw_entries) > 16_384:
                raise NativeBoundaryV27Error(
                    "V27 physical scan exceeds the entry cap"
                )
        final_children = sorted(os.listdir(directory_fd), key=os.fsencode)
        if final_children != children:
            raise NativeBoundaryV27Error(
                "V27 physical scan directory name set changed during traversal"
            )

    try:
        visit(store_fd, PurePosixPath(".beads"))
        if not _same_physical_identity_v27(store_metadata, os.fstat(store_fd)):
            raise NativeBoundaryV27Error(
                "V27 physical scan store root changed during traversal"
            )
        rebound_repository_fd = _rebind_physical_ancestry_v27(repository, ancestry)
        try:
            rebound_store_fd = os.open(
                ".beads", directory_flags, dir_fd=rebound_repository_fd
            )
            try:
                if not _same_physical_identity_v27(
                    store_metadata, os.fstat(rebound_store_fd)
                ):
                    raise NativeBoundaryV27Error(
                        "V27 physical scan store final binding changed"
                    )
            finally:
                os.close(rebound_store_fd)
        finally:
            os.close(rebound_repository_fd)
        # The raw ancestry evidence is retained and revalidated within every
        # scan. Rolling joins compare the descriptor-pinned store projection;
        # shared ancestors are not part of Beads store contents.
        raw_projection = {"entries": raw_entries}
        normalized_projection = {"entries": normalized_entries}
        stable_projection = {
            "entries": [
                {
                    key: value
                    for key, value in entry.items()
                    if key not in {"device", "inode"}
                }
                for entry in normalized_entries
            ]
        }
        ancestry_bytes = canonical_bytes(ancestry)
        raw_bytes = canonical_bytes(raw_projection)
        normalized_bytes = canonical_bytes(normalized_projection)
        stable_bytes = canonical_bytes(stable_projection)
        return {
            "physicalStoreScan": {
                "schemaVersion": 27,
                "captureOrdinal": capture_ordinal,
                "entryCount": len(raw_entries),
                "repositoryAncestry": ancestry,
                "repositoryAncestrySha256": sha256(ancestry_bytes),
                "rawProjection": raw_projection,
                "rawProjectionSha256": sha256(raw_bytes),
                "normalizedProjection": normalized_projection,
                "normalizedProjectionSha256": sha256(normalized_bytes),
                "stableProjection": stable_projection,
                "stableProjectionSha256": sha256(stable_bytes),
                "normalizationProfile": (
                    "beads-v1.1.2-noms-manifest-transition-only-v1"
                ),
                "normalizedTransitionPaths": normalized_transition_paths,
            }
        }
    finally:
        os.close(store_fd)
        os.close(repository_fd)


def _physical_equality_evidence_v27(
    objects: Path, key: bytes
) -> dict[str, Any]:
    """Bind adjacent repeatability and the full cross-window no-effect join."""

    pairs = (
        ("effect-post", "effect-raw-observation-a", "effect-raw-observation-b"),
        *(
            (
                f"reader-{ordinal}",
                f"reader-{ordinal}-raw-observation-a",
                f"reader-{ordinal}-raw-observation-b",
            )
            for ordinal in range(4)
        ),
        ("tail-pre", "tail-after-observation-a", "tail-after-observation-b"),
    )
    passes: list[bool] = []
    bindings: list[dict[str, Any]] = []
    scans: dict[str, dict[str, Any]] = {}
    for window, stage_a, stage_b in pairs:
        scan_a = _physical_scan_observation_v27(
            objects, key, stage_a, capture_ordinal="a"
        )
        scan_b = _physical_scan_observation_v27(
            objects, key, stage_b, capture_ordinal="b"
        )
        passed = (
            scan_a["entryCount"] == scan_b["entryCount"]
            and scan_a["normalizedProjectionSha256"]
            == scan_b["normalizedProjectionSha256"]
        )
        passes.append(passed)
        scans[window] = scan_b
        bindings.append(
            {
                "window": window,
                "entryCountA": scan_a["entryCount"],
                "entryCountB": scan_b["entryCount"],
                "rawProjectionSha256A": scan_a["rawProjectionSha256"],
                "rawProjectionSha256B": scan_b["rawProjectionSha256"],
                "normalizedProjectionSha256A": scan_a[
                    "normalizedProjectionSha256"
                ],
                "normalizedProjectionSha256B": scan_b[
                    "normalizedProjectionSha256"
                ],
                "repeatable": passed,
            }
        )
    tail_pre_a = _physical_scan_observation_v27(
        objects, key, "tail-after-observation-a", capture_ordinal="a"
    )
    rolling_scans = [
        scans["effect-post"],
        *(scans[f"reader-{ordinal}"] for ordinal in range(4)),
        tail_pre_a,
    ]
    rolling_bindings: list[dict[str, Any]] = []
    rolling_passes: list[bool] = []
    rolling_names = (
        "effect-post-b->reader-0-b",
        "reader-0-b->reader-1-b",
        "reader-1-b->reader-2-b",
        "reader-2-b->reader-3-b",
        "reader-3-b->tail-pre-a",
    )
    for name, left, right in zip(
        rolling_names, rolling_scans, rolling_scans[1:]
    ):
        passed = (
            left["entryCount"] == right["entryCount"]
            and left["stableProjectionSha256"]
            == right["stableProjectionSha256"]
        )
        rolling_passes.append(passed)
        rolling_bindings.append(
            {
                "join": name,
                "leftEntryCount": left["entryCount"],
                "leftNormalizedProjectionSha256": left[
                    "normalizedProjectionSha256"
                ],
                "leftRawProjectionSha256": left["rawProjectionSha256"],
                "leftStableProjectionSha256": left[
                    "stableProjectionSha256"
                ],
                "rightEntryCount": right["entryCount"],
                "rightNormalizedProjectionSha256": right[
                    "normalizedProjectionSha256"
                ],
                "rightRawProjectionSha256": right["rawProjectionSha256"],
                "rightStableProjectionSha256": right[
                    "stableProjectionSha256"
                ],
                "unchanged": passed,
            }
        )
    rolling_digest = sha256(canonical_bytes(rolling_bindings))
    cross_pass = all(rolling_passes)
    return {
        "physicalEqualityPasses": [passes[0], passes[-1]],
        "repeatabilityPasses": passes,
        "repeatabilityEvidenceSha256": sha256(canonical_bytes(bindings)),
        "rollingJoinPasses": rolling_passes,
        "rollingJoinEvidenceSha256": rolling_digest,
        "crossWindowNoEffect": cross_pass,
        "crossWindowNoEffectEvidenceSha256": rolling_digest,
    }


def _same_normalized_scan_v27(
    left: Mapping[str, Any], right: Mapping[str, Any], *, stable: bool = False
) -> bool:
    digest = "stableProjectionSha256" if stable else "normalizedProjectionSha256"
    return (
        left.get("entryCount") == right.get("entryCount")
        and left.get(digest) == right.get(digest)
    )


def _enforce_physical_scan_join_v27(
    objects: Path,
    key: bytes,
    operation_class: str,
    stage_key: str,
    observation: Mapping[str, Any],
) -> None:
    current = observation.get("physicalStoreScan")
    if not isinstance(current, Mapping):
        raise NativeBoundaryV27Error("V27 current physical scan is malformed")
    repeatability_predecessor: str | None = None
    rolling_predecessor: str | None = None
    if stage_key == "effect-raw-observation-b":
        repeatability_predecessor = "effect-raw-observation-a"
    else:
        reader_b = re.fullmatch(r"reader-([0-3])-raw-observation-b", stage_key)
        if reader_b is not None:
            ordinal = int(reader_b.group(1))
            repeatability_predecessor = f"reader-{ordinal}-raw-observation-a"
            rolling_predecessor = (
                "effect-raw-observation-b"
                if ordinal == 0
                else f"reader-{ordinal - 1}-raw-observation-b"
            )
        elif (
            stage_key == "tail-after-observation-a"
            and operation_class
            not in {"create-preparation", "reattest-preparation"}
        ):
            rolling_predecessor = "reader-3-raw-observation-b"
        elif stage_key == "tail-after-observation-b":
            repeatability_predecessor = "tail-after-observation-a"
    for relation, predecessor in (
        ("repeatability", repeatability_predecessor),
        ("rolling", rolling_predecessor),
    ):
        if predecessor is None:
            continue
        prior = _physical_scan_observation_v27(
            objects,
            key,
            predecessor,
            capture_ordinal=("a" if predecessor.endswith("-a") else "b"),
        )
        if not _same_normalized_scan_v27(
            prior, current, stable=(relation == "rolling")
        ):
            raise NativeBoundaryV27Error(
                f"V27 {relation} physical join changed at {stage_key}: "
                f"{predecessor}={prior.get('normalizedProjectionSha256')} "
                f"count={prior.get('entryCount')}, "
                f"current={current.get('normalizedProjectionSha256')} "
                f"count={current.get('entryCount')}"
            )


def _aggregate_literal_terminal_v27(
    objects: Path, key: bytes, plan: Mapping[str, Any]
) -> dict[str, Any]:
    effect = _stage_result_observation_v27(objects, key, "effect-payload-terminal")
    reads = [
        _stage_result_observation_v27(objects, key, f"reader-{ordinal}-payload-terminal")
        for ordinal in range(4)
    ]
    try:
        read_raw = [base64.b64decode(item["stdoutBase64"], validate=True) for item in reads]
        decoded = decode_beads_read_back_outputs_v27(
            read_raw, target_id=_effect_target_id_v27(plan)
        )
        stdout = base64.b64decode(effect["stdoutBase64"], validate=True)
        stderr = base64.b64decode(effect["stderrBase64"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise NativeBoundaryV27Error("V27 stored native stage bytes are invalid") from exc
    physical = _physical_equality_evidence_v27(objects, key)
    return {
        "exitCode": effect["exitCode"],
        "stdoutSha256": sha256(stdout),
        "stderrSha256": sha256(stderr),
        "readBackSha256": sha256(canonical_bytes(decoded)),
        "readBackProjection": decoded["projection"],
        "readBacksSha256": [sha256(item) for item in read_raw],
        **physical,
        "independentReadCount": 4,
        "lifecycle": list(_EFFECT_LIFECYCLE),
        "observedByNativeSupervisor": True,
    }


def _literal_segment_observation_v27(
    objects: Path,
    key: bytes,
    schedule: tuple[LiteralStageV27, ...],
    *,
    start_location: int,
    end_location: int,
) -> dict[str, Any]:
    payload_stages = [
        stage
        for stage in schedule[start_location - 1 : end_location]
        if stage.stage_kind == _NATIVE_PAYLOAD_STAGE_KIND_V27
    ]
    if len(payload_stages) == 0:
        result_digests: list[str] = []
        for stage in schedule[start_location - 1 : end_location]:
            matches = [
                record
                for name in os.listdir(objects)
                if re.fullmatch(r"[0-9a-f]{64}\.json", name)
                for record in [_read_effect_record(objects / name, key)]
                if record["kind"] == "StageActionResultV1"
                and record["payload"].get("stageKey") == stage.stage_key
            ]
            if len(matches) != 1:
                raise NativeBoundaryV27Error(
                    "V27 local segment is missing an exact stage result"
                )
            result_digests.append(str(matches[0]["recordSha256"]))
        return {
            "schemaVersion": 27,
            "profile": PROFILE,
            "segmentState": "local-actions-completed",
            "stageStart": start_location,
            "stageEnd": end_location,
            "stageResultRecordSha256": result_digests,
        }
    if len(payload_stages) != 1:
        raise NativeBoundaryV27Error(
            "V27 nonterminal segment must contain one exact native payload stage"
        )
    stage = payload_stages[0]
    observation = _stage_result_observation_v27(objects, key, stage.stage_key)
    required = {
        "exitCode", "stdoutBase64", "stderrBase64", "stdoutSha256",
        "stderrSha256", "lifecycle", "placementMask", "resultKind",
        "resultPredecessorKind", "failureEvidenceSha256",
    }
    if set(observation) not in {
        frozenset(required), frozenset(required | {"controllerRetirement"})
    }:
        raise NativeBoundaryV27Error("V27 segment native observation changed")
    return {
        "schemaVersion": 27,
        "profile": PROFILE,
        "segmentState": "command-completed",
        "stageStart": start_location,
        "stageEnd": end_location,
        "payloadStageKey": stage.stage_key,
        **observation,
        "observedByNativeSupervisor": True,
    }


def _aggregate_preparation_terminal_v27(
    objects: Path, key: bytes, plan: Mapping[str, Any]
) -> dict[str, Any]:
    operation_class = str(plan["operationClass"])
    stage_keys = (
        (
            "binary-proof-payload-terminal",
            "initialize-payload-terminal",
            "status-write-payload-terminal",
            "status-read-payload-terminal",
        )
        if operation_class == "create-preparation"
        else ("status-read-payload-terminal",)
    )
    commands = [
        _stage_result_observation_v27(objects, key, stage_key)
        for stage_key in stage_keys
    ]
    command_fields = {
            "exitCode", "stdoutBase64", "stderrBase64", "stdoutSha256",
            "stderrSha256", "lifecycle", "placementMask", "resultKind",
            "resultPredecessorKind", "failureEvidenceSha256",
    }
    if any(
        set(command) not in {
            frozenset(command_fields),
            frozenset(command_fields | {"controllerRetirement"}),
        }
        for command in commands
    ):
        raise NativeBoundaryV27Error("V27 preparation command evidence changed")
    return {
        "schemaVersion": 27,
        "profile": PROFILE,
        "preparationState": "sequence-completed",
        "operationClass": operation_class,
        "commandCount": len(commands),
        "commandStages": list(stage_keys),
        "commandResultsSha256": [
            sha256(canonical_bytes(command)) for command in commands
        ],
        "observedByNativeSupervisor": True,
    }


def _decode_preparation_terminal_v27(value: Any) -> dict[str, Any]:
    fields = {
        "schemaVersion", "profile", "preparationState", "operationClass",
        "commandCount", "commandStages", "commandResultsSha256",
        "observedByNativeSupervisor",
    }
    data = _closed(value, fields, "V27 preparation terminal")
    expected_stages = (
        [
            "binary-proof-payload-terminal",
            "initialize-payload-terminal",
            "status-write-payload-terminal",
            "status-read-payload-terminal",
        ]
        if data["operationClass"] == "create-preparation"
        else ["status-read-payload-terminal"]
        if data["operationClass"] == "reattest-preparation"
        else None
    )
    if (
        data["schemaVersion"] != 27
        or data["profile"] != PROFILE
        or data["preparationState"] != "sequence-completed"
        or data["observedByNativeSupervisor"] is not True
        or expected_stages is None
        or data["commandCount"] != len(expected_stages)
        or data["commandStages"] != expected_stages
        or not isinstance(data["commandResultsSha256"], list)
        or len(data["commandResultsSha256"]) != len(expected_stages)
    ):
        raise NativeBoundaryV27Error("V27 preparation terminal binding changed")
    for digest in data["commandResultsSha256"]:
        _digest(digest, "preparation command result")
    return dict(data)


def _decode_stage_action_output_v27(value: Any) -> dict[str, Any]:
    base = {"evidenceSha256", "observation", "terminalObservation"}
    result_fields = {
        "resultKind", "resultPredecessorKind", "failureEvidenceSha256"
    }
    if not isinstance(value, Mapping) or set(value) not in {
        frozenset(base), frozenset(base | result_fields)
    }:
        raise NativeBoundaryV27Error(
            "V27 literal stage action result has an unknown or missing field"
        )
    data = dict(value)
    if not result_fields <= set(data):
        data.update(
            {
                "resultKind": "success",
                "resultPredecessorKind": _RESULT_KINDS["success"],
                "failureEvidenceSha256": None,
            }
        )
    _stage_result_discriminants_v27(data)
    return data


def _execute_stage_action_result_v27(
    *,
    manifest: NativeBoundaryManifestV27,
    plan: Mapping[str, Any],
    stage: LiteralStageV27,
    schedule: tuple[LiteralStageV27, ...],
    predecessor: Mapping[str, Any],
    objects: Path,
    key: bytes,
    action_executor: Any,
    predecessor_after_action: Any = None,
) -> dict[str, Any]:
    try:
        observed = action_executor(manifest, plan, stage)
    except _NativeLaunchPreEffectFailedV27:
        raise
    except Exception as exc:
        raise NativeBoundaryV27Error(
            f"V27 stage {stage.stage_key} action failed after consumption: {exc}"
        ) from exc
    action = _decode_stage_action_output_v27(observed)
    _digest(action["evidenceSha256"], "stage evidenceSha256")
    if not isinstance(action["observation"], Mapping):
        raise NativeBoundaryV27Error("V27 stage observation is not an object")
    is_done = stage.location == len(schedule)
    if is_done:
        if action["terminalObservation"] is None:
            raise NativeBoundaryV27Error("V27 Done action has no terminal observation")
        if plan["operationClass"] in {"create-preparation", "reattest-preparation"}:
            terminal = _decode_preparation_terminal_v27(action["terminalObservation"])
        else:
            terminal = _decode_supervisor_result(action["terminalObservation"])
    else:
        if action["terminalObservation"] is not None:
            raise NativeBoundaryV27Error(
                "non-Done V27 action has future terminal evidence"
            )
        terminal = None
    result_predecessor = (
        predecessor_after_action()
        if callable(predecessor_after_action)
        else predecessor
    )
    if not isinstance(result_predecessor, Mapping):
        raise NativeBoundaryV27Error(
            "V27 stage action result predecessor is unavailable"
        )
    result = _effect_sign(
        "StageActionResultV1",
        {
            "schemaVersion": 27,
            "profile": PROFILE,
            "operationId": plan["operationId"],
            "operationClass": plan["operationClass"],
            "planSha256": plan["planSha256"],
            "location": stage.location,
            "stageKey": stage.stage_key,
            "stageKind": stage.stage_kind,
            "actionKind": stage.action_kind,
            "predecessorCurrentRecordSha256": result_predecessor["recordSha256"],
            "evidenceSha256": action["evidenceSha256"],
            "observation": dict(action["observation"]),
            "terminalObservation": terminal,
            "resultKind": action["resultKind"],
            "resultPredecessorKind": action["resultPredecessorKind"],
            "failureEvidenceSha256": action["failureEvidenceSha256"],
        },
        key,
    )
    result_path = objects / (
        str(result["recordSha256"]).removeprefix("sha256:") + ".json"
    )
    _publish_effect_object(
        result_path,
        result,
        key,
        phase=f"location-{stage.location}-result-object",
    )
    _effect_fault(f"location-{stage.location}-result-object-written")
    return result


def execute_literal_stage_schedule_v27(
    state_root: Path,
    key: bytes,
    manifest: NativeBoundaryManifestV27,
    value: Any,
    *,
    action_executor: Any,
    action_recovery: Any = None,
    start_location: int = 1,
    end_location: int | None = None,
    require_native_events: bool = False,
) -> dict[str, Any]:
    """Execute one contiguous literal schedule; every row performs its action once."""

    plan = validate_supervised_effect_plan_v27(value, manifest)
    if not callable(action_executor):
        raise NativeBoundaryV27Error("V27 literal schedule has no action executor")
    schedule = literal_stage_schedule_v27(str(plan["operationClass"]))
    if end_location is None:
        end_location = len(schedule)
    if (
        type(start_location) is not int
        or type(end_location) is not int
        or not 1 <= start_location <= end_location <= len(schedule)
    ):
        raise NativeBoundaryV27Error("V27 literal segment bounds are invalid")
    operation, history, objects = _effect_state_paths(state_root, plan["operationId"])
    current_path = operation / "current.json"
    with _effect_lock(operation / "operation.lock"):
        current: dict[str, Any] | None = None
        safely_repaired_consumed: str | None = None
        if current_path.exists():
            current = _read_effect_record(current_path, key)
        entry_current_record_sha256 = (
            None if current is None else str(current["recordSha256"])
        )
        while True:
            if current is None:
                if start_location != 1:
                    raise NativeBoundaryV27Error(
                        "V27 literal segment expected an existing predecessor"
                    )
                current = _install_effect_current_kind_v27(
                    current_path,
                    history,
                    key,
                    "StageCurrentV3",
                    _bootstrap_stage_current_payload_v27(plan),
                    expected=None,
                )
                _effect_fault("location-0-bootstrap-terminal")
                continue
            stage, state = _validate_literal_stage_current_v27(current, plan, schedule)
            launch_failure_evidence = current["payload"].get(
                "launchPreEffectFailedSha256"
            )
            if launch_failure_evidence is not None:
                current = _advance_launch_pre_effect_failure_v27(
                    current_path=current_path,
                    history=history,
                    objects=objects,
                    key=key,
                    plan=plan,
                    stage=stage,
                    current=current,
                    proof=None,
                )
                raise NativeBoundaryV27Error(
                    f"V27 stage {stage.stage_key} launch-pre-effect failure "
                    "remains durably quarantined and non-public"
                )
            if state == "bootstrap-terminal":
                if start_location != 1:
                    raise NativeBoundaryV27Error(
                        "V27 literal segment cannot skip its bootstrap successor"
                    )
                next_stage = schedule[0]
                current = _install_effect_current_kind_v27(
                    current_path,
                    history,
                    key,
                    "StageCurrentV3",
                    _literal_stage_current_payload_v27(
                        plan, next_stage, state="ready", predecessor=current
                    ),
                    expected=current,
                )
                _effect_fault(f"location-{next_stage.location}-ready")
                continue
            if state == "completion":
                if stage.location == end_location:
                    if end_location != len(schedule):
                        return _literal_segment_observation_v27(
                            objects,
                            key,
                            schedule,
                            start_location=start_location,
                            end_location=end_location,
                        )
                    return _terminal_observation_from_literal_done_v27(objects, current, key)
                if stage.location >= end_location:
                    raise NativeBoundaryV27Error(
                        "V27 literal segment current passed its authorized suffix"
                    )
                if stage.location < start_location - 1:
                    raise NativeBoundaryV27Error(
                        "V27 literal segment skipped an authorized predecessor"
                    )
                if stage.location == start_location - 1:
                    pass
                elif stage.location < start_location:
                    raise NativeBoundaryV27Error(
                        "V27 literal segment predecessor is not contiguous"
                    )
                next_stage = schedule[stage.location]
                next_ready_payload = _literal_stage_current_payload_v27(
                    plan,
                    next_stage,
                    state="ready",
                    predecessor=current,
                )
                if (
                    current["recordSha256"] == entry_current_record_sha256
                    and start_location <= stage.location
                    and stage.location
                    in INCOMPLETE_TAILS_V27[str(plan["operationClass"])]
                ):
                    candidate = _effect_sign("StageCurrentV3", next_ready_payload, key)
                    candidate_path = history / (
                        str(candidate["recordSha256"]).removeprefix("sha256:")
                        + ".json"
                    )
                    if not candidate_path.exists():
                        quarantined = {
                            **_literal_stage_current_payload_v27(
                                plan,
                                stage,
                                state="outer-loss-quarantined-current",
                                predecessor=current,
                            ),
                            "reason": "missing-durable-next-stage-evidence",
                        }
                        _install_effect_current_kind_v27(
                            current_path,
                            history,
                            key,
                            "SupervisorOuterLossQuarantinedCurrentV4",
                            quarantined,
                            expected=current,
                        )
                        raise NativeBoundaryV27Error(
                            "V27 incomplete tail has no durable next-stage object; "
                            "operation is quarantined without synthesis"
                        )
                current = _install_effect_current_kind_v27(
                    current_path,
                    history,
                    key,
                    "StageCurrentV3",
                    next_ready_payload,
                    expected=current,
                )
                _effect_fault(f"location-{next_stage.location}-ready")
                continue
            if state == "ready":
                if not start_location <= stage.location <= end_location:
                    raise NativeBoundaryV27Error(
                        "V27 literal ready current is outside the authorized segment"
                    )
                current = _install_effect_current_kind_v27(
                    current_path,
                    history,
                    key,
                    "StageCurrentV3",
                    _literal_stage_current_payload_v27(
                        plan, stage, state="intent-current", predecessor=current
                    ),
                    expected=current,
                )
                _effect_fault(f"location-{stage.location}-intent-current")
                continue
            if state == "launch-slot-reserved":
                reserved = current
                current = _install_effect_current_kind_v27(
                    current_path,
                    history,
                    key,
                    "SupervisorLaunchSlotConsumedCurrentV1",
                    _outer_current_payload_v27(
                        plan,
                        stage,
                        state="launch-slot-consumed",
                        predecessor=reserved,
                        consumed_record_sha256=reserved["recordSha256"],
                        result=None,
                        result_kind=None,
                        failure_evidence_sha256=None,
                    ),
                    expected=reserved,
                )
                safely_repaired_consumed = str(current["recordSha256"])
                _effect_fault(f"location-{stage.location}-launch-consumed-current")
                continue
            if state == "intent-current":
                if not start_location <= stage.location <= end_location:
                    raise NativeBoundaryV27Error(
                        "V27 literal intent current is outside the authorized segment"
                    )
                is_done = stage.location == len(schedule)
                native_payload = stage.stage_kind == _NATIVE_PAYLOAD_STAGE_KIND_V27
                if native_payload:
                    current = _install_effect_current_kind_v27(
                        current_path,
                        history,
                        key,
                        "SupervisorLaunchSlotReservedCurrentV1",
                        _outer_current_payload_v27(
                            plan,
                            stage,
                            state="launch-slot-reserved",
                            predecessor=current,
                            consumed_record_sha256=current["recordSha256"],
                            result=None,
                            result_kind=None,
                            failure_evidence_sha256=None,
                        ),
                        expected=current,
                    )
                    _effect_fault(f"location-{stage.location}-launch-slot-reserved")
                    reserved = current
                    current = _install_effect_current_kind_v27(
                        current_path,
                        history,
                        key,
                        "SupervisorLaunchSlotConsumedCurrentV1",
                        _outer_current_payload_v27(
                            plan,
                            stage,
                            state="launch-slot-consumed",
                            predecessor=reserved,
                            consumed_record_sha256=reserved["recordSha256"],
                            result=None,
                            result_kind=None,
                            failure_evidence_sha256=None,
                        ),
                        expected=reserved,
                    )
                    _effect_fault(f"location-{stage.location}-launch-consumed-current")
                # Local schedule rows are controller actions, not supervisor
                # launches.  They retain the causal StageCurrent lineage and
                # may repair an already-durable result, but never fabricate a
                # native launch/result envelope.  Only the five (or four/one
                # preparation) payload-terminal coordinates enter the named
                # supervisor lifecycle.
                result = _matching_stage_action_result_v27(
                    objects, key, plan, stage, str(current["recordSha256"])
                )
                if (
                    not native_payload
                    and result is None
                    and current["recordSha256"] == entry_current_record_sha256
                ):
                    # A prior process reached the write-ahead intent but left
                    # no authenticated result.  The local action may already
                    # have happened; repeating it would manufacture certainty.
                    # Retain the truthful StageCurrent and require operator
                    # recovery evidence rather than inventing a supervisor
                    # failure current for a non-native row.
                    if not callable(action_recovery):
                        raise NativeBoundaryV27Error(
                            f"V27 local stage {stage.stage_key} has an uncertain "
                            "intent and cannot replay without durable result evidence"
                        )
                    recovered = action_recovery(manifest, plan, stage)
                    if recovered is None or _is_native_supervisor_loss_v27(recovered):
                        raise NativeBoundaryV27Error(
                            f"V27 local stage {stage.stage_key} cannot replay; "
                            "recovery supplied no exact durable action evidence"
                        )
                    result = _execute_stage_action_result_v27(
                        manifest=manifest,
                        plan=plan,
                        stage=stage,
                        schedule=schedule,
                        predecessor=current,
                        objects=objects,
                        key=key,
                        action_executor=(
                            lambda _manifest, _plan, _stage: recovered
                        ),
                    )
                if result is None:
                    sequencer: _NativeOuterEventSequencerV27 | None = None
                    event_token = None
                    if native_payload and require_native_events:
                        sequencer = _NativeOuterEventSequencerV27(
                            current_path=current_path,
                            history=history,
                            objects=objects,
                            key=key,
                            plan=plan,
                            stage=stage,
                            consumed=current,
                        )
                        event_token = _NATIVE_OUTER_EVENT_HANDLER_V27.set(
                            sequencer
                        )
                    try:
                        try:
                            result = _execute_stage_action_result_v27(
                                manifest=manifest,
                                plan=plan,
                                stage=stage,
                                schedule=schedule,
                                predecessor=(
                                    current if sequencer is None else sequencer.current
                                ),
                                objects=objects,
                                key=key,
                                action_executor=action_executor,
                                predecessor_after_action=(
                                    None
                                    if sequencer is None
                                    else lambda: sequencer.current
                                ),
                            )
                        except _NativeLaunchUnresolvedV27 as exc:
                            if (
                                sequencer is None
                                or sequencer.next_index != 0
                                or sequencer.pending is not None
                            ):
                                raise NativeBoundaryV27Error(
                                    "V27 pre-effect proof failure crossed a native event"
                                ) from exc
                            _advance_authenticated_unresolved_loss_v27(
                                current_path=current_path,
                                history=history,
                                objects=objects,
                                key=key,
                                plan=plan,
                                stage=stage,
                                current=current,
                                recovered=exc.recovered,
                            )
                            raise NativeBoundaryV27Error(
                                f"V27 stage {stage.stage_key} pre-effect proof "
                                "is authentically unresolved and non-public"
                            ) from exc
                        except _NativeLaunchPreEffectFailedV27 as exc:
                            if (
                                sequencer is None
                                or sequencer.next_index != 0
                                or sequencer.pending is not None
                            ):
                                raise NativeBoundaryV27Error(
                                    "V27 launch failure is not a proved "
                                    "never-created pre-effect branch"
                                ) from exc
                            current = _advance_launch_pre_effect_failure_v27(
                                current_path=current_path,
                                history=history,
                                objects=objects,
                                key=key,
                                plan=plan,
                                stage=stage,
                                current=current,
                                proof=exc.proof,
                            )
                            raise NativeBoundaryV27Error(
                                f"V27 stage {stage.stage_key} launch was never "
                                "created and is durably quarantined"
                            ) from exc
                    finally:
                        if event_token is not None:
                            _NATIVE_OUTER_EVENT_HANDLER_V27.reset(event_token)
                    if sequencer is not None:
                        current = sequencer.require_complete(
                            str(result["payload"].get("resultKind"))
                        )
                        # The action result is created after the event runner
                        # returns; bind it to the last truthful native current.
                        if (
                            result["payload"].get(
                                "predecessorCurrentRecordSha256"
                            )
                            != current["recordSha256"]
                        ):
                            raise NativeBoundaryV27Error(
                                "V27 native result does not follow its event chain"
                            )
                terminal_current = current
                if native_payload:
                    terminal_current = _advance_outer_result_chain_v27(
                        current_path=current_path,
                        history=history,
                        objects=objects,
                        key=key,
                        plan=plan,
                        stage=stage,
                        current=current,
                        result=result,
                        require_native_events=require_native_events,
                    )
                elif result["payload"].get("resultKind") != "success":
                    raise NativeBoundaryV27Error(
                        "V27 local schedule action cannot mint a native failure envelope"
                    )
                current = _complete_literal_stage_v27(
                    current_path=current_path,
                    history=history,
                    objects=objects,
                    key=key,
                    plan=plan,
                    stage=stage,
                    consumed=terminal_current,
                    result=result,
                )
                continue
            if current["kind"] in {
                kind for kind, _state in _AUTHENTICATED_UNRESOLVED_CHAIN_V27
            }:
                current = _advance_authenticated_unresolved_loss_v27(
                    current_path=current_path,
                    history=history,
                    objects=objects,
                    key=key,
                    plan=plan,
                    stage=stage,
                    current=current,
                    recovered=None,
                )
                raise NativeBoundaryV27Error(
                    "V27 authenticated supervisor loss remains a non-public "
                    "unresolved terminal and cannot replay"
                )
            if current["kind"] in _NONPUBLIC_RECOVERY_STATES_V27:
                current = _close_admitted_nonpublic_current_v27(
                    current_path=current_path,
                    history=history,
                    objects=objects,
                    key=key,
                    manifest=manifest,
                    plan=plan,
                    stage=stage,
                    current=current,
                    action_recovery=action_recovery,
                )
                raise NativeBoundaryV27Error(
                    "V27 admitted recovery current reached an exact non-public "
                    "terminal without effect replay"
                )
            if current["kind"] == "SupervisorOuterLossDrainPendingCurrentV5":
                payload = current["payload"]
                result_digest = payload.get("resultRecordSha256")
                current = _install_effect_current_kind_v27(
                    current_path,
                    history,
                    key,
                    "SupervisorOuterLossQuarantinedCurrentV4",
                    _outer_current_payload_v27(
                        plan,
                        stage,
                        state="outer-loss-quarantined-current",
                        predecessor=current,
                        consumed_record_sha256=str(
                            payload["consumedCurrentRecordSha256"]
                        ),
                        result=(
                            None
                            if result_digest is None
                            else {"recordSha256": result_digest}
                        ),
                        result_kind=payload.get("resultKind"),
                        failure_evidence_sha256=payload.get(
                            "failureEvidenceSha256"
                        ),
                        result_envelope_record_sha256=payload.get(
                            "resultEnvelopeRecordSha256"
                        ),
                        launch_pre_effect_failed_sha256=payload.get(
                            "launchPreEffectFailedSha256"
                        ),
                    ),
                    expected=current,
                )
                raise NativeBoundaryV27Error(
                    "V27 outer-loss drain completed as a non-public quarantine"
                )
            if not start_location <= stage.location <= end_location:
                raise NativeBoundaryV27Error(
                    "V27 literal consumed current is outside the authorized segment"
                )
            consumed_digest = str(
                current["recordSha256"]
                if current["kind"] == "SupervisorLaunchSlotConsumedCurrentV1"
                else current["payload"].get("consumedCurrentRecordSha256")
            )
            result = _matching_stage_action_result_v27(
                objects, key, plan, stage, consumed_digest
            )
            if (
                result is None
                and current["kind"] == "SupervisorTerminalCurrentV3"
            ):
                # Native StageActionResult is signed only after the causal
                # terminal current is durable.  A crash after publishing that
                # result but before StageCurrent completion must reopen the
                # exact terminal-predecessor object, never ask the worker to
                # manufacture a second observation or replay the payload.
                result = _matching_stage_action_result_v27(
                    objects,
                    key,
                    plan,
                    stage,
                    str(current["recordSha256"]),
                )
            if (
                result is None
                and current["kind"] == "SupervisorLaunchSlotConsumedCurrentV1"
                and safely_repaired_consumed == current["recordSha256"]
            ):
                result = _execute_stage_action_result_v27(
                    manifest=manifest,
                    plan=plan,
                    stage=stage,
                    schedule=schedule,
                    predecessor=current,
                    objects=objects,
                    key=key,
                    action_executor=action_executor,
                )
            if result is None and callable(action_recovery):
                try:
                    recovered = action_recovery(manifest, plan, stage)
                except _NativeLaunchPreEffectFailedV27 as exc:
                    try:
                        current = _advance_launch_pre_effect_failure_v27(
                            current_path=current_path,
                            history=history,
                            objects=objects,
                            key=key,
                            plan=plan,
                            stage=stage,
                            current=current,
                            proof=exc.proof,
                        )
                    except NativeBoundaryV27Error as binding_error:
                        # A controller-authenticated proof can still have been
                        # swapped from another consumed current.  Only this
                        # layer owns the exact StageCurrent predecessor, so a
                        # failed final join is ambiguity, never never-created.
                        loss = _native_supervisor_loss_v27(
                            reason="dead-holder-without-terminal",
                            evidence_sha256=sha256(
                                b"startup-factory/beads/v27/rebound-pre-effect-proof\0"
                                + canonical_bytes(
                                    {
                                        "operationId": plan["operationId"],
                                        "stageLocation": stage.location,
                                        "operationPlanSha256": plan["planSha256"],
                                        "consumedCurrentRecordSha256": (
                                            current["recordSha256"]
                                            if current["kind"]
                                            == "SupervisorLaunchSlotConsumedCurrentV1"
                                            else current["payload"].get(
                                                "consumedCurrentRecordSha256"
                                            )
                                        ),
                                        "proofSha256": sha256(
                                            canonical_bytes(
                                                dict(exc.proof or {})
                                            )
                                        ),
                                    }
                                )
                            ),
                        )
                        proof_retirement = (
                            exc.proof.get("proof", {}).get(
                                "controllerRetirement"
                            )
                            if isinstance(exc.proof, Mapping)
                            and isinstance(exc.proof.get("proof"), Mapping)
                            else None
                        )
                        if not isinstance(proof_retirement, Mapping):
                            raise NativeBoundaryV27Error(
                                "V27 rebound pre-effect proof lost its "
                                "controller retirement"
                            ) from binding_error
                        _advance_authenticated_unresolved_loss_v27(
                            current_path=current_path,
                            history=history,
                            objects=objects,
                            key=key,
                            plan=plan,
                            stage=stage,
                            current=current,
                            recovered={
                                **loss,
                                "controllerRetirement": dict(proof_retirement),
                            },
                        )
                        raise NativeBoundaryV27Error(
                            f"V27 stage {stage.stage_key} recovered a rebound "
                            "pre-effect proof and closed as unresolved"
                        ) from binding_error
                    raise NativeBoundaryV27Error(
                        f"V27 stage {stage.stage_key} recovered an exact "
                        "pre-effect proof and remains non-public"
                    ) from exc
                if recovered is not None:
                    if _is_native_supervisor_loss_v27(recovered):
                        _advance_authenticated_unresolved_loss_v27(
                            current_path=current_path,
                            history=history,
                            objects=objects,
                            key=key,
                            plan=plan,
                            stage=stage,
                            current=current,
                            recovered=recovered,
                        )
                        raise NativeBoundaryV27Error(
                            f"V27 consumed stage {stage.stage_key} reached an "
                            "authenticated unresolved terminal after supervisor loss"
                        )
                    action = _decode_stage_action_output_v27(recovered)
                    _digest(action["evidenceSha256"], "recovered stage evidenceSha256")
                    if (
                        not isinstance(action["observation"], Mapping)
                        or action["terminalObservation"] is not None
                    ):
                        raise NativeBoundaryV27Error(
                            "V27 recovered stage action result is invalid"
                        )
                    if require_native_events and current["kind"] in {
                        "SupervisorResultEnvelopeStoredCurrentV4",
                        "SupervisorResultHandoffAttemptConsumedCurrentV4",
                        "SupervisorResultHandoffReceiptedCurrentV4",
                        "SupervisorTerminalReceiptStoredCurrentV4",
                    }:
                        # Recovery's credentialed worker packet is the genuine
                        # handoff receipt.  Close that effect-free suffix before
                        # signing StageActionResult so its predecessor is the
                        # exact native TerminalCurrent, never a stale attempt.
                        current = _repair_credentialed_handoff_suffix_v27(
                            current_path=current_path,
                            history=history,
                            objects=objects,
                            key=key,
                            plan=plan,
                            stage=stage,
                            current=current,
                            observation=action["observation"],
                        )
                    result_payload = {
                        "schemaVersion": 27,
                        "profile": PROFILE,
                        "operationId": plan["operationId"],
                        "operationClass": plan["operationClass"],
                        "planSha256": plan["planSha256"],
                        "location": stage.location,
                        "stageKey": stage.stage_key,
                        "stageKind": stage.stage_kind,
                        "actionKind": stage.action_kind,
                        "predecessorCurrentRecordSha256": current["recordSha256"],
                        "evidenceSha256": action["evidenceSha256"],
                        "observation": dict(action["observation"]),
                        "terminalObservation": None,
                        "resultKind": action["resultKind"],
                        "resultPredecessorKind": action["resultPredecessorKind"],
                        "failureEvidenceSha256": action["failureEvidenceSha256"],
                    }
                    result = _effect_sign("StageActionResultV1", result_payload, key)
                    result_path = objects / (
                        result["recordSha256"].removeprefix("sha256:") + ".json"
                    )
                    _publish_effect_object(
                        result_path,
                        result,
                        key,
                        phase=f"location-{stage.location}-recovered-result-object",
                    )
            if result is not None:
                try:
                    terminal_current = _advance_outer_result_chain_v27(
                        current_path=current_path,
                        history=history,
                        objects=objects,
                        key=key,
                        plan=plan,
                        stage=stage,
                        current=current,
                        result=result,
                        require_native_events=require_native_events,
                    )
                except NativeBoundaryV27Error as exc:
                    if (
                        not require_native_events
                        or "missing native event prefix" not in str(exc)
                    ):
                        raise
                    result_kind, _predecessor_kind, failure_evidence = (
                        _stage_result_discriminants_v27(result["payload"])
                    )
                    pending = _install_effect_current_kind_v27(
                        current_path,
                        history,
                        key,
                        "SupervisorOuterLossDrainPendingCurrentV5",
                        _outer_current_payload_v27(
                            plan,
                            stage,
                            state="outer-loss-drain-pending",
                            predecessor=current,
                            consumed_record_sha256=consumed_digest,
                            result=result,
                            result_kind=result_kind,
                            failure_evidence_sha256=failure_evidence,
                        ),
                        expected=current,
                    )
                    _install_effect_current_kind_v27(
                        current_path,
                        history,
                        key,
                        "SupervisorOuterLossQuarantinedCurrentV4",
                        _outer_current_payload_v27(
                            plan,
                            stage,
                            state="outer-loss-quarantined-current",
                            predecessor=pending,
                            consumed_record_sha256=consumed_digest,
                            result=result,
                            result_kind=result_kind,
                            failure_evidence_sha256=failure_evidence,
                        ),
                        expected=pending,
                    )
                    raise NativeBoundaryV27Error(
                        "V27 native event prefix is incomplete; durable result "
                        "is forensic-only and the stage is quarantined"
                    ) from exc
                current = _complete_literal_stage_v27(
                    current_path=current_path,
                    history=history,
                    objects=objects,
                    key=key,
                    plan=plan,
                    stage=stage,
                    consumed=terminal_current,
                    result=result,
                )
                continue
            quarantined_payload = {
                **_literal_stage_current_payload_v27(
                    plan,
                    stage,
                    state="outer-loss-quarantined-current",
                    predecessor=current,
                ),
                "reason": "consumed-action-without-durable-result",
            }
            _install_effect_current_kind_v27(
                current_path,
                history,
                key,
                "SupervisorOuterLossQuarantinedCurrentV4",
                quarantined_payload,
                expected=current,
            )
            raise NativeBoundaryV27Error(
                f"V27 consumed stage {stage.stage_key} is durably quarantined and never replayed"
            )


def _load_effect_result(
    objects: Path, current: Mapping[str, Any], key: bytes
) -> dict[str, Any]:
    result_digest = current["payload"].get("resultRecordSha256")
    if not isinstance(result_digest, str) or not _DIGEST.fullmatch(result_digest):
        raise NativeBoundaryV27Error("V27 Done current has no exact result object")
    envelope = _read_effect_record(
        objects / f"{result_digest.removeprefix('sha256:')}.json",
        key,
        expected_kind="SupervisorResultEnvelopeV4",
    )
    return dict(envelope["payload"]["observation"])


def _recover_stored_effect_result_v27(
    *,
    current_path: Path,
    history: Path,
    objects: Path,
    current: Mapping[str, Any],
    plan: Mapping[str, Any],
    key: bytes,
    done: int,
) -> dict[str, Any] | None:
    candidates: list[dict[str, Any]] = []
    try:
        names = tuple(os.listdir(objects))
    except OSError as exc:
        raise NativeBoundaryV27Error(
            f"cannot inspect V27 result-object recovery set: {exc}"
        ) from exc
    for name in names:
        if not re.fullmatch(r"[0-9a-f]{64}\.json", name):
            raise NativeBoundaryV27Error(
                "V27 result-object directory contains an unexpected entry"
            )
        envelope = _read_effect_record(
            objects / name,
            key,
            expected_kind="SupervisorResultEnvelopeV4",
        )
        payload = envelope["payload"]
        if (
            payload.get("operationId") == plan["operationId"]
            and payload.get("operationClass") == plan["operationClass"]
            and payload.get("planSha256") == plan["planSha256"]
            and payload.get("predecessorCurrentRecordSha256")
            == current["recordSha256"]
        ):
            candidates.append(envelope)
    if not candidates:
        return None
    if len(candidates) != 1:
        raise NativeBoundaryV27Error(
            "V27 recovery found multiple authenticated supervisor results"
        )
    result = candidates[0]
    result_current = _install_stage_current(
        current_path,
        history,
        key,
        _stage_current_payload(
            plan,
            generation=3,
            location=done - 1,
            state="result-stored-current",
            predecessor=current,
            result_record_sha256=result["recordSha256"],
        ),
        expected=current,
    )
    completed = _install_stage_current(
        current_path,
        history,
        key,
        _stage_current_payload(
            plan,
            generation=4,
            location=done,
            state="completion",
            predecessor=result_current,
            result_record_sha256=result["recordSha256"],
        ),
        expected=result_current,
    )
    return _load_effect_result(objects, completed, key)


def execute_supervised_effect_v27(
    state_root: Path,
    key: bytes,
    manifest: NativeBoundaryManifestV27,
    value: Any,
    *,
    runner: Any = None,
    start_location: int = 1,
    end_location: int | None = None,
) -> dict[str, Any]:
    plan = validate_supervised_effect_plan_v27(value, manifest)
    if runner is None:
        runner = run_native_stage_action_v27
    custody_profile_factory = getattr(
        runner, "repository_custody_profile_v27", None
    )
    repository_custody_profile = (
        custody_profile_factory(plan)
        if callable(custody_profile_factory)
        else None
    )
    operation, _history, objects = _effect_state_paths(
        state_root, plan["operationId"]
    )

    def execute_stage(
        stage_manifest: NativeBoundaryManifestV27,
        effect_plan: Mapping[str, Any],
        stage: LiteralStageV27,
    ) -> dict[str, Any]:
        (
            stage_record,
            controller_repository,
            snapshot_root,
            _retained_root,
            custody,
        ) = _ensure_controller_repository_stage_v27(
            operation,
            objects,
            key,
            effect_plan,
            profile=repository_custody_profile,
        )

        def publication_prerequisite_sha256() -> str | None:
            if effect_plan["operationClass"] in {
                "create-preparation", "reattest-preparation"
            }:
                return None
            snapshot_records = []
            for snapshot_ordinal in range(4):
                snapshot_record, _snapshot_repository = (
                    _reopen_controller_read_snapshot_v27(
                        custody=custody,
                        snapshots=snapshot_root,
                        key=key,
                        plan=effect_plan,
                        stage_record=stage_record,
                        ordinal=snapshot_ordinal,
                    )
                )
                snapshot_records.append(snapshot_record["recordSha256"])
            terminal_join = _aggregate_literal_terminal_v27(
                objects, key, effect_plan
            )
            return sha256(
                b"startup-factory/beads/v27/repository-publication-prerequisite\0"
                + canonical_bytes(
                    {
                        "operationId": effect_plan["operationId"],
                        "planSha256": effect_plan["planSha256"],
                        "snapshotRecordSha256": snapshot_records,
                        "terminalJoinSha256": sha256(
                            canonical_bytes(terminal_join)
                        ),
                    }
                )
            )
        stage_plan = derive_native_stage_action_plan_v27(
            stage_manifest, effect_plan, stage
        )
        if stage_plan is not None:
            reader = re.fullmatch(
                r"reader-([0-3])-payload-terminal", stage.stage_key
            )
            if reader is None:
                native_repository = controller_repository
            else:
                _snapshot_record, native_repository = (
                    _reopen_controller_read_snapshot_v27(
                        custody=custody,
                        snapshots=snapshot_root,
                        key=key,
                        plan=effect_plan,
                        stage_record=stage_record,
                        ordinal=int(reader.group(1)),
                    )
                )
            base_stage_plan = stage_plan
            request_key = _derive_native_request_key_v27(key, effect_plan, stage)
            authorized_stage_plan: dict[str, Any] | None = None

            def persist_grant_intent(
                binding: Mapping[str, Any],
                private_manifest: Mapping[str, Any],
            ) -> None:
                nonlocal authorized_stage_plan
                authorized_stage_plan = {
                    **base_stage_plan,
                    "repositoryPath": str(native_repository),
                    "repositoryCustody": dict(binding),
                    "requestKeyId": sha256(request_key),
                    "stagePlanSha256": None,
                }
                authorized_stage_plan["stagePlanSha256"] = (
                    _native_stage_plan_digest_v27(authorized_stage_plan)
                )
                validate_native_stage_action_plan_v27(
                    authorized_stage_plan, stage_manifest
                )
                _load_or_publish_controller_record_v27(
                    custody / f"repository-access-{stage.location}.json",
                    key,
                    "ControllerRepositoryAccessIntentV1",
                    {
                        "schemaVersion": 27,
                        "profile": PROFILE,
                        "operationId": effect_plan["operationId"],
                        "operationClass": effect_plan["operationClass"],
                        "planSha256": effect_plan["planSha256"],
                        "stageLocation": stage.location,
                        "stageKey": stage.stage_key,
                        "stagePlan": authorized_stage_plan,
                        "stagePlanSha256": authorized_stage_plan[
                            "stagePlanSha256"
                        ],
                        "repositoryCustodyBindingSha256": binding[
                            "bindingSha256"
                        ],
                        "privateManifestSha256": private_manifest[
                            "manifestSha256"
                        ],
                        "grantedManifestSha256": binding[
                            "manifestSha256"
                        ],
                        "requestKeyDerivation": {
                            "launchCoreSha256": effect_plan[
                                "launchCoreSha256"
                            ],
                            "operatorGeneration": effect_plan[
                                "operatorGeneration"
                            ],
                            "configEpoch": effect_plan["configEpoch"],
                            "keyEpoch": effect_plan["keyEpoch"],
                            "operationId": effect_plan["operationId"],
                            "effectPlanSha256": effect_plan["planSha256"],
                            "stageLocation": stage.location,
                            "stageKey": stage.stage_key,
                        },
                    },
                    phase=f"repository-access-{stage.location}-intent",
                )

            repository_custody: dict[str, Any] | None = None
            if repository_custody_profile is None:
                if runner is run_native_stage_action_v27:
                    raise NativeBoundaryV27Error(
                        "production V27 native execution lacks repository custody"
                    )
                # Injected/offline runners do not cross the controller/worker
                # UID boundary.  They still receive only the controller-owned
                # staged path, never the producer repository.
                authorized_stage_plan = {
                    **base_stage_plan,
                    "repositoryPath": str(native_repository),
                    "repositoryCustody": None,
                    "requestKeyId": sha256(request_key),
                    "stagePlanSha256": None,
                }
                authorized_stage_plan["stagePlanSha256"] = (
                    _native_stage_plan_digest_v27(authorized_stage_plan)
                )
                validate_native_stage_action_plan_v27(
                    authorized_stage_plan, stage_manifest
                )
            else:
                repository_custody = _grant_repository_custody_v27(
                    path=native_repository,
                    stage_record=stage_record,
                    stage=stage,
                    before_grant=persist_grant_intent,
                    admitted_leaf_names=(
                        _authenticated_repository_custody_leaf_names_v27(
                            state_root, key
                        )
                    ),
                )
            if authorized_stage_plan is None or (
                repository_custody_profile is not None
                and repository_custody is None
            ):
                raise NativeBoundaryV27Error(
                    "V27 repository custody grant lacked durable authority"
                )
            stage_plan = authorized_stage_plan
            token = _NATIVE_REQUEST_KEY_V27.set(request_key)
            try:
                try:
                    raw_result = runner(stage_manifest, stage_plan)
                finally:
                    if repository_custody is not None:
                        receipt_factory = getattr(
                            runner,
                            "repository_custody_release_receipt_v27",
                            None,
                        )
                        if not callable(receipt_factory):
                            raise NativeBoundaryV27Error(
                                "V27 production custody lacks a release probe"
                            )
                        _effect_fault(
                            f"repository-access-{stage.location}-before-release-probe"
                        )
                        release_receipt = receipt_factory(stage_plan)
                        _effect_fault(
                            f"repository-access-{stage.location}-release-probed"
                        )
                        _persist_repository_post_manifest_v27(
                            custody=custody,
                            key=key,
                            plan=stage_plan,
                            repository_custody=repository_custody,
                            release_receipt=release_receipt,
                        )
                        revoked = _revoke_repository_custody_v27(
                            repository_custody,
                            release_receipt,
                            request_key,
                        )
                        _load_or_publish_controller_record_v27(
                            custody / f"repository-release-{stage.location}.json",
                            key,
                            "ControllerRepositoryReleaseReceiptV1",
                            {
                                "schemaVersion": 27,
                                "profile": PROFILE,
                                "operationId": effect_plan["operationId"],
                                "planSha256": effect_plan["planSha256"],
                                "stageLocation": stage.location,
                                "stagePlanSha256": stage_plan[
                                    "stagePlanSha256"
                                ],
                                "repositoryCustodyBindingSha256": (
                                    repository_custody["bindingSha256"]
                                ),
                                "postManifestSha256": release_receipt[
                                    "postRepositoryManifestSha256"
                                ],
                                "revokedManifestSha256": revoked[
                                    "manifestSha256"
                                ],
                            },
                            phase=f"repository-access-{stage.location}-release",
                        )
            finally:
                _NATIVE_REQUEST_KEY_V27.reset(token)
            observation = _decode_native_stage_result_v27(
                raw_result, require_discriminants=True
            )
            return {
                "evidenceSha256": str(stage_plan["stagePlanSha256"]),
                "observation": observation,
                "terminalObservation": None,
                "resultKind": observation["resultKind"],
                "resultPredecessorKind": observation[
                    "resultPredecessorKind"
                ],
                "failureEvidenceSha256": observation[
                    "failureEvidenceSha256"
                ],
            }
        terminal: dict[str, Any] | None = None
        observation: dict[str, Any]
        snapshot_stage = re.fullmatch(r"reader-([0-3])-snapshot", stage.stage_key)
        if snapshot_stage is not None:
            ordinal = int(snapshot_stage.group(1))
            snapshot_record, _snapshot_repository = (
                _ensure_controller_read_snapshot_v27(
                    custody=custody,
                    effect=controller_repository,
                    snapshots=snapshot_root,
                    key=key,
                    plan=effect_plan,
                    stage_record=stage_record,
                    ordinal=ordinal,
                )
            )
            snapshot_payload = snapshot_record["payload"]
            observation = {
                "controllerSnapshot": {
                    "ordinal": ordinal,
                    "snapshotIdentitySha256": snapshot_payload[
                        "snapshotIdentitySha256"
                    ],
                    "snapshotRecordSha256": snapshot_record["recordSha256"],
                    "sourceStageContentSha256": snapshot_payload[
                        "sourceStageContentSha256"
                    ],
                    "snapshotContentSha256": snapshot_payload[
                        "snapshotContentSha256"
                    ],
                }
            }
        elif stage.stage_kind in {
            "checkpoint-candidate-stored", "installation-intent-stored"
        }:
            prerequisite_sha256 = publication_prerequisite_sha256()
            candidate = _ensure_repository_publication_candidate_v27(
                custody=custody,
                effect=controller_repository,
                key=key,
                plan=effect_plan,
                stage_record=stage_record,
                publication_prerequisite_sha256=prerequisite_sha256,
            )
            observation = {
                "repositoryPublicationCandidate": {
                    "recordSha256": candidate["recordSha256"],
                    "candidateStageTreeSha256": candidate["payload"][
                        "candidateStageTreeSha256"
                    ],
                    "candidateStageContentSha256": candidate["payload"][
                        "candidateStageContentSha256"
                    ],
                    "candidateStageRootIdentitySha256": candidate["payload"][
                        "candidateStageRootIdentitySha256"
                    ],
                }
            }
        elif stage.stage_kind == "stage-identity-reopened":
            candidate = _reopen_repository_publication_candidate_v27(
                custody=custody,
                effect=controller_repository,
                key=key,
                plan=effect_plan,
                stage_record=stage_record,
                publication_prerequisite_sha256=None,
            )
            observation = {
                "repositoryStageIdentityReopened": {
                    "candidateRecordSha256": candidate["recordSha256"],
                    "repositoryStageRecordSha256": stage_record[
                        "recordSha256"
                    ],
                }
            }
        elif stage.stage_kind == "host-install-transition" or (
            stage.stage_kind == "repository-current-cas"
            and effect_plan["operationClass"]
            in {"claim-cas", "ordinary", "receipt-comment"}
        ):
            prerequisite_sha256 = publication_prerequisite_sha256()
            publication = _publish_controller_repository_candidate_v27(
                custody=custody,
                effect=controller_repository,
                key=key,
                plan=effect_plan,
                stage_record=stage_record,
                publication_prerequisite_sha256=prerequisite_sha256,
            )
            observation = {
                "repositoryPublicationReceipt": {
                    "recordSha256": publication["recordSha256"],
                    "publishedContentSha256": publication["payload"][
                        "publishedContentSha256"
                    ],
                    "retainedPreviousContentSha256": publication["payload"][
                        "retainedPreviousContentSha256"
                    ],
                }
            }
        elif stage.stage_kind == "installed-identity-observed":
            publication = _publish_controller_repository_candidate_v27(
                custody=custody,
                effect=controller_repository,
                key=key,
                plan=effect_plan,
                stage_record=stage_record,
                publication_prerequisite_sha256=None,
            )
            observation = {
                "installedRepositoryIdentity": {
                    "publicationReceiptSha256": publication["recordSha256"],
                    "treeSha256": publication["payload"][
                        "publishedTreeSha256"
                    ],
                    "rootIdentitySha256": publication["payload"][
                        "publishedRootIdentitySha256"
                    ],
                }
            }
        elif stage.stage_kind == "host-cleanup-retired":
            cleanup = _retire_controller_previous_tree_v27(
                custody=custody,
                retained=_retained_root,
                key=key,
                plan=effect_plan,
                stage_record=stage_record,
            )
            observation = {
                "controllerCleanupRetirement": {
                    "recordSha256": cleanup["recordSha256"],
                    "publicationReceiptSha256": cleanup["payload"][
                        "publicationReceiptSha256"
                    ],
                    "retainedRootIdentitySha256": cleanup["payload"][
                        "retainedRootIdentitySha256"
                    ],
                }
            }
        reader_scan = re.fullmatch(
            r"reader-[0-3]-raw-observation-([ab])", stage.stage_key
        )
        if snapshot_stage is not None or stage.stage_kind in {
            "checkpoint-candidate-stored",
            "installation-intent-stored",
            "stage-identity-reopened",
            "host-install-transition",
            "installed-identity-observed",
            "host-cleanup-retired",
        } or (
            stage.stage_kind == "repository-current-cas"
            and effect_plan["operationClass"]
            in {"claim-cas", "ordinary", "receipt-comment"}
        ):
            pass
        elif reader_scan is not None:
            reader_ordinal = int(stage.stage_key.split("-")[1])
            _snapshot_record, snapshot_repository = (
                _reopen_controller_read_snapshot_v27(
                    custody=custody,
                    snapshots=snapshot_root,
                    key=key,
                    plan=effect_plan,
                    stage_record=stage_record,
                    ordinal=reader_ordinal,
                )
            )
            observation = _capture_physical_store_scan_v27(
                str(snapshot_repository),
                capture_ordinal=reader_scan.group(1),
            )
        elif stage.stage_key in {
            "effect-raw-observation-a",
            "tail-after-observation-a",
        }:
            observation = _capture_physical_store_scan_v27(
                str(controller_repository),
                capture_ordinal="a",
            )
        elif stage.stage_key in {
            "effect-raw-observation-b",
            "tail-after-observation-b",
        }:
            observation = _capture_physical_store_scan_v27(
                str(controller_repository),
                capture_ordinal="b",
            )
        else:
            observation = {
                "stageKey": stage.stage_key,
                "stageKind": stage.stage_kind,
                "actionKind": stage.action_kind,
            }
        if "physicalStoreScan" in observation:
            _enforce_physical_scan_join_v27(
                objects,
                key,
                str(effect_plan["operationClass"]),
                stage.stage_key,
                observation,
            )
        if stage.stage_kind in {"operation-done", "preparation-done"}:
            if effect_plan["operationClass"] in {
                "create-preparation", "reattest-preparation"
            }:
                terminal = _aggregate_preparation_terminal_v27(
                    objects, key, effect_plan
                )
            else:
                terminal = {
                    "nativeObservation": _aggregate_literal_terminal_v27(
                        objects, key, effect_plan
                    )
                }
        local_evidence = sha256(
            b"startup-factory/beads/v27/local-stage\0"
            + canonical_bytes(
                {
                    "effectPlanSha256": effect_plan["planSha256"],
                    "stageLocation": stage.location,
                    "stageKey": stage.stage_key,
                    "stageKind": stage.stage_kind,
                    "actionKind": stage.action_kind,
                    "observation": observation,
                    "terminalObservation": terminal,
                }
            )
        )
        return {
            "evidenceSha256": local_evidence,
            "observation": observation,
            "terminalObservation": terminal,
        }

    def recover_stage(
        stage_manifest: NativeBoundaryManifestV27,
        effect_plan: Mapping[str, Any],
        stage: LiteralStageV27,
    ) -> dict[str, Any] | None:
        base_stage_plan = derive_native_stage_action_plan_v27(
            stage_manifest, effect_plan, stage
        )
        if base_stage_plan is None:
            # Local rows have no payload/native effect.  Their production
            # actions are bounded reads, deterministic causal receipts, or
            # terminal aggregation.  Re-opening an intent therefore repairs
            # the exact no-effect suffix without inventing native authority;
            # physical scans still revalidate all bound identities and joins.
            return execute_stage(stage_manifest, effect_plan, stage)
        recovery = getattr(runner, "recover", None)
        if not callable(recovery):
            return None
        (
            stage_record,
            controller_repository,
            snapshot_root,
            _retained_root,
            custody,
        ) = _ensure_controller_repository_stage_v27(
            operation,
            objects,
            key,
            effect_plan,
            profile=repository_custody_profile,
        )
        reader = re.fullmatch(
            r"reader-([0-3])-payload-terminal", stage.stage_key
        )
        if reader is None:
            native_repository = controller_repository
        else:
            _snapshot_record, native_repository = (
                _reopen_controller_read_snapshot_v27(
                    custody=custody,
                    snapshots=snapshot_root,
                    key=key,
                    plan=effect_plan,
                    stage_record=stage_record,
                    ordinal=int(reader.group(1)),
                )
            )
        request_key = _derive_native_request_key_v27(key, effect_plan, stage)
        if repository_custody_profile is None:
            stage_plan = {
                **base_stage_plan,
                "repositoryPath": str(native_repository),
                "repositoryCustody": None,
                "requestKeyId": sha256(request_key),
                "stagePlanSha256": None,
            }
            stage_plan["stagePlanSha256"] = _native_stage_plan_digest_v27(
                stage_plan
            )
        else:
            intent_path = custody / f"repository-access-{stage.location}.json"
            _finalize_controller_record_link_prefix_v27(intent_path)
            intent = _read_effect_record(
                intent_path,
                key,
                expected_kind="ControllerRepositoryAccessIntentV1",
            )
            payload = intent["payload"]
            stage_plan = payload.get("stagePlan")
            if (
                not isinstance(stage_plan, Mapping)
                or payload.get("operationId") != effect_plan["operationId"]
                or payload.get("planSha256") != effect_plan["planSha256"]
                or payload.get("stageLocation") != stage.location
                or payload.get("stageKey") != stage.stage_key
                or payload.get("stagePlanSha256")
                != stage_plan.get("stagePlanSha256")
                or stage_plan.get("repositoryPath") != str(native_repository)
                or stage_plan.get("requestKeyId") != sha256(request_key)
            ):
                raise NativeBoundaryV27Error(
                    "V27 repository custody recovery intent changed"
                )
            stage_plan = dict(stage_plan)
        validate_native_stage_action_plan_v27(stage_plan, stage_manifest)
        token = _NATIVE_REQUEST_KEY_V27.set(request_key)
        try:
            raw_result = recovery(stage_manifest, stage_plan)
        finally:
            _NATIVE_REQUEST_KEY_V27.reset(token)
        if _is_native_supervisor_loss_v27(raw_result):
            return raw_result
        observation = _decode_native_stage_result_v27(
            raw_result, require_discriminants=True
        )
        return {
            "evidenceSha256": str(stage_plan["stagePlanSha256"]),
            "observation": observation,
            "terminalObservation": None,
            "resultKind": observation["resultKind"],
            "resultPredecessorKind": observation["resultPredecessorKind"],
            "failureEvidenceSha256": observation["failureEvidenceSha256"],
        }

    return execute_literal_stage_schedule_v27(
        state_root,
        key,
        manifest,
        plan,
        action_executor=execute_stage,
        action_recovery=recover_stage,
        start_location=start_location,
        end_location=end_location,
        require_native_events=True,
    )


def _sealed_plan_descriptor_v27(raw: bytes) -> int:
    if not sys.platform.startswith("linux") or not hasattr(os, "memfd_create"):
        raise NativeBoundaryV27Error(
            "production V27 supervisor execution requires Linux sealed memfd support"
        )
    descriptor = os.memfd_create(
        "startup-factory-v27-plan",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        _write_all_v27(descriptor, raw)
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _sealed_request_key_descriptor_v27(
    protected_material: bytes,
) -> tuple[int, bytearray]:
    if type(protected_material) is not bytes or len(protected_material) != 32:
        raise NativeBoundaryV27Error(
            "V27 derived request key must be exactly 32 bytes"
        )
    material = bytearray(protected_material)
    descriptor = os.memfd_create(
        "startup-factory-v27-request-key",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        _write_all_v27(descriptor, bytes(material))
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, material
    except Exception:
        for index in range(len(material)):
            material[index] = 0
        os.close(descriptor)
        raise


def consume_sealed_request_key_descriptor_v27(
    descriptor: int, request_key_id: str
) -> bytes:
    """Read one controller-issued sealed request key and bind its identity."""

    metadata = os.fstat(descriptor)
    expected_seals = (
        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != 32
        or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != expected_seals
    ):
        raise NativeBoundaryV27Error(
            "V27 transferred request-key descriptor is not exactly sealed"
        )
    material = _pread_exact_bounded_v27(
        descriptor, 32, "transferred request key"
    )
    if sha256(material) != request_key_id:
        raise NativeBoundaryV27Error(
            "V27 transferred request-key descriptor digest changed"
        )
    return material


_NATIVE_CGROUP_ROLES_V27: Final = (
    "worker-directory",
    "payload-directory",
    "payload-events",
    "payload-kill",
)


def _native_cgroup_descriptor_binding_v27(
    role: str, descriptor: int
) -> dict[str, Any]:
    metadata = os.fstat(descriptor)
    entry_type = (
        "directory"
        if stat.S_ISDIR(metadata.st_mode)
        else "file"
        if stat.S_ISREG(metadata.st_mode)
        else "unsupported"
    )
    return {
        "role": role,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "type": entry_type,
        "accessMode": fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE,
    }


def _native_cgroup_descriptors_v27(
    custody: Any,
    plan: Mapping[str, Any],
    *,
    process_cgroup_reader: Any = None,
) -> tuple[int, int, int, int]:
    """Validate and duplicate controller-issued cgroup descriptor custody."""

    if not isinstance(custody, Mapping) or set(custody) != {
        "binding", "descriptors"
    }:
        raise NativeBoundaryV27Error(
            "native worker has no controller-issued cgroup custody"
        )
    binding = custody["binding"]
    descriptors = custody["descriptors"]
    fields = {
        "schemaVersion", "workerSessionNonce", "workerPid", "operationId",
        "stageLocation", "stagePlanSha256", "payloadName", "transferNonce",
        "workerCgroupRelative", "descriptors",
    }
    if (
        not isinstance(binding, Mapping)
        or set(binding) != fields
        or not isinstance(descriptors, tuple)
        or len(descriptors) != len(_NATIVE_CGROUP_ROLES_V27)
        or any(type(item) is not int or item < 0 for item in descriptors)
    ):
        raise NativeBoundaryV27Error("native cgroup custody shape changed")
    expected_name = (
        f"payload-{plan['operationId']}-s{plan['stageLocation']}-"
        f"{str(plan['stagePlanSha256']).removeprefix('sha256:')[:16]}"
    )
    if (
        binding["schemaVersion"] != 27
        or binding["workerPid"] != os.getpid()
        or binding["operationId"] != plan["operationId"]
        or binding["stageLocation"] != plan["stageLocation"]
        or binding["stagePlanSha256"] != plan["stagePlanSha256"]
        or binding["payloadName"] != expected_name
        or not isinstance(binding["workerCgroupRelative"], str)
        or Path(binding["workerCgroupRelative"]).name != "worker"
        or not isinstance(binding["workerSessionNonce"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", binding["workerSessionNonce"])
        or not isinstance(binding["transferNonce"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", binding["transferNonce"])
        or not isinstance(binding["descriptors"], list)
    ):
        raise NativeBoundaryV27Error("native cgroup custody identity changed")
    observed = [
        _native_cgroup_descriptor_binding_v27(role, descriptor)
        for role, descriptor in zip(_NATIVE_CGROUP_ROLES_V27, descriptors)
    ]
    expected_access = [os.O_RDONLY, os.O_RDONLY, os.O_RDONLY, os.O_WRONLY]
    if (
        observed != binding["descriptors"]
        or [item["type"] for item in observed]
        != ["directory", "directory", "file", "file"]
        or [item["accessMode"] for item in observed] != expected_access
        or len({(item["device"], item["inode"]) for item in observed}) != 4
        or any(item["device"] != observed[1]["device"] for item in observed)
    ):
        raise NativeBoundaryV27Error(
            "native cgroup custody descriptor identity changed"
        )
    reader = (
        (lambda: Path("/proc/self/cgroup").read_bytes())
        if process_cgroup_reader is None
        else process_cgroup_reader
    )
    relative = _unified_cgroup_relative_v27(reader())
    if relative != binding["workerCgroupRelative"]:
        raise NativeBoundaryV27Error(
            "native worker is not in the controller-issued worker cgroup"
        )
    duplicates: list[int] = []
    try:
        for descriptor in descriptors:
            duplicates.append(os.dup(descriptor))
        return tuple(duplicates)  # type: ignore[return-value]
    except OSError as exc:
        for duplicate in reversed(duplicates):
            os.close(duplicate)
        raise NativeBoundaryV27Error(
            f"cannot duplicate controller-issued cgroup custody: {exc}"
        ) from exc


def _credentialed_supervisor_handshake_v27(
    channel: socket.socket,
    process: subprocess.Popen[bytes],
    control_descriptors: tuple[int, int],
    placement_mediator: Any,
    event_mediator: Any,
    result_offer_mediator: Any,
    stage_plan_sha256: str,
    request_key_bytes: bytes,
) -> int:
    channel.settimeout(10.0)
    channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    event_sequence = 0

    def mediate_native_event(
        event: str,
        phase: str,
        observation: Mapping[str, Any],
        evidence: str | None = None,
    ) -> Mapping[str, Any]:
        nonlocal event_sequence
        event_sequence += 1
        validated_observation = _validate_native_event_observation_v27(
            event, phase, observation
        )
        expected_evidence = _native_event_evidence_v27(
            stage_plan_sha256=stage_plan_sha256,
            sequence=event_sequence,
            event=event,
            phase=phase,
            observation=validated_observation,
        )
        if evidence is None:
            evidence = expected_evidence
        elif evidence != expected_evidence:
            raise NativeBoundaryV27Error(
                "V27 native event evidence does not bind its observation"
            )
        response = event_mediator(
            {
                "schemaVersion": 27,
                "stagePlanSha256": stage_plan_sha256,
                "sequence": event_sequence,
                "event": event,
                "phase": phase,
                "eventObservation": validated_observation,
                "eventEvidenceSha256": evidence,
            }
        )
        if not isinstance(response, Mapping) or not isinstance(
            response.get("authorityRecordSha256"), str
        ):
            raise NativeBoundaryV27Error(
                "V27 native event mediation returned no authority record"
            )
        return response

    running_observation = {
        "supervisorPid": process.pid,
        "pidfdTerminal": process.poll() is not None,
        "fd11IdentityRevalidated": True,
        "controlPeek": "eagain",
    }
    mediate_native_event("supervisor-running", "before", running_observation)
    mediate_native_event("supervisor-running", "after", running_observation)
    mediate_native_event(
        "run-authorization-consumed",
        "before",
        {
            "releaseSendCount": 0,
            "cgroupDescriptorCount": len(control_descriptors),
            "sendmsgReturn": None,
        },
    )
    rights = array.array("i", control_descriptors)
    if channel.sendmsg(
        [b"RELEASE\n"],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
    ) != len(b"RELEASE\n"):
        raise NativeBoundaryV27Error(
            "V27 cgroup-control descriptor release was truncated"
        )
    mediate_native_event(
        "run-authorization-consumed",
        "after",
        {
            "releaseSendCount": 1,
            "cgroupDescriptorCount": len(control_descriptors),
            "sendmsgReturn": len(b"RELEASE\n"),
        },
    )
    credential_size = struct.calcsize("3i")

    def receive(label: str) -> bytes:
        packet, ancillary, flags, _address = channel.recvmsg(
            512, socket.CMSG_SPACE(credential_size)
        )
        credentials: list[tuple[int, int, int]] = []
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if len(payload) != credential_size:
                    raise NativeBoundaryV27Error(f"V27 {label} credentials are truncated")
                credentials.append(struct.unpack("3i", payload))
            else:
                raise NativeBoundaryV27Error(f"V27 {label} ancillary data changed")
        if (
            not packet
            or flags & (getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0))
            or credentials != [(process.pid, os.geteuid(), os.getegid())]
        ):
            raise NativeBoundaryV27Error(f"V27 {label} sender identity changed")
        return packet

    if receive("SetupReady") != b"SETUPREADY\n":
        raise NativeBoundaryV27Error("V27 SetupReady payload changed")
    acknowledged_before = {
        "ackSendCount": 0,
        "sendReturn": None,
        "pidfdTerminal": process.poll() is not None,
        "fd11IdentityRevalidated": True,
        "controlPeek": "eagain",
    }
    mediate_native_event(
        "run-acknowledged", "before", acknowledged_before
    )
    channel.sendall(b"ACK\n")
    mediate_native_event(
        "run-acknowledged",
        "after",
        {
            **acknowledged_before,
            "ackSendCount": 1,
            "sendReturn": len(b"ACK\n"),
        },
    )
    seen_ordinals: set[int] = set()
    authorized_result_offer: dict[str, Any] | None = None
    while True:
        packet = receive("placement control")
        native_event = re.fullmatch(
            rb"EVENT ([1-9][0-9]*) (before|after) ([a-z][a-z0-9-]{0,63}) "
            rb"([0-9a-f]{2,8192}) ([0-9a-f]{64}) ([0-9a-f]{64})\n",
            packet,
        )
        if native_event is not None:
            observed_sequence = int(native_event.group(1))
            event = native_event.group(3).decode("ascii")
            phase = native_event.group(2).decode("ascii")
            try:
                observation_raw = bytes.fromhex(
                    native_event.group(4).decode("ascii")
                )
                observation_value = _strict_probe_json(observation_raw + b"\n")
            except (ValueError, NativeBoundaryV27Error) as exc:
                raise NativeBoundaryV27Error(
                    "V27 native event observation framing changed"
                ) from exc
            observation = _validate_native_event_observation_v27(
                event, phase, observation_value
            )
            evidence = "sha256:" + native_event.group(5).decode("ascii")
            body = {
                "schemaVersion": 27,
                "stagePlanSha256": stage_plan_sha256,
                "sequence": observed_sequence,
                "event": event,
                "phase": phase,
                "eventObservation": observation,
                "eventEvidenceSha256": evidence,
            }
            if (
                observed_sequence != event_sequence + 1
                or evidence != _native_event_evidence_v27(
                    stage_plan_sha256=stage_plan_sha256,
                    sequence=observed_sequence,
                    event=event,
                    phase=phase,
                    observation=observation,
                )
                or not hmac.compare_digest(
                    "hmac-sha256:" + native_event.group(6).decode("ascii"),
                    _native_event_hmac_v27(request_key_bytes, body),
                )
            ):
                raise NativeBoundaryV27Error(
                    "V27 supervisor event authentication or sequence changed"
                )
            response = mediate_native_event(
                event, phase, observation, evidence
            )
            authority = str(response["authorityRecordSha256"])
            ack_hmac = str(response.get("ackHmac", ""))
            control_action = response.get("controlAction")
            control_authority = response.get("controlAuthorityRecordSha256")
            capture_binding = response.get("creatorCaptureBinding")
            expected_capture_binding = (
                event == "creator-return-ready" and phase == "before"
            )
            if (
                not _DIGEST.fullmatch(authority)
                or not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", ack_hmac)
                or control_action not in {"continue", "revoke"}
                or (
                    control_action == "continue"
                    and control_authority is not None
                )
                or (
                    control_action == "revoke"
                    and (
                        (event, phase)
                        not in {
                            ("native-creator-created", "after"),
                            ("release-consumed-current", "before"),
                        }
                        or not isinstance(control_authority, str)
                        or not _DIGEST.fullmatch(control_authority)
                    )
                )
                or (
                    expected_capture_binding
                    and (
                        not isinstance(capture_binding, Mapping)
                        or set(capture_binding) != {
                            "capturePreparationRecordSha256",
                            "returnAuthorizationRecordSha256",
                            "creatorReturnCurrentRecordSha256",
                        }
                        or not all(
                            isinstance(item, str) and _DIGEST.fullmatch(item)
                            for item in capture_binding.values()
                        )
                    )
                )
                or (not expected_capture_binding and capture_binding is not None)
            ):
                raise NativeBoundaryV27Error(
                    "V27 supervisor event ACK binding changed"
                )
            control_wire = (
                "-"
                if control_authority is None
                else str(control_authority).removeprefix("sha256:")
            )
            capture_wires = (
                tuple(
                    str(capture_binding[field]).removeprefix("sha256:")
                    for field in (
                        "capturePreparationRecordSha256",
                        "returnAuthorizationRecordSha256",
                        "creatorReturnCurrentRecordSha256",
                    )
                )
                if expected_capture_binding
                else ("-", "-", "-")
            )
            acknowledgement = (
                f"EVENT-ACK {observed_sequence} {phase} {event} "
                f"{authority.removeprefix('sha256:')} "
                f"{ack_hmac.removeprefix('hmac-sha256:')} "
                f"{control_action} {control_wire} "
                f"{capture_wires[0]} {capture_wires[1]} "
                f"{capture_wires[2]}\n"
            ).encode("ascii")
            if channel.send(acknowledgement) != len(acknowledgement):
                raise NativeBoundaryV27Error(
                    "V27 supervisor event ACK was truncated"
                )
            continue
        result_offer = re.fullmatch(
            rb"RESULT-OFFER ([0-9a-f]{64}) ([a-z][a-z0-9-]{0,63}) "
            rb"([a-z][a-z0-9-]{0,95}) (-|[0-9a-f]{64}) "
            rb"((?:0|[1-9][0-9]*)) ([0-9a-f]{64})\n",
            packet,
        )
        if result_offer is not None:
            failure_wire = result_offer.group(4).decode("ascii")
            candidate = {
                "schemaVersion": 27,
                "protocol": "startup-factory/beads-native-worker/v27",
                "status": "result-offer",
                "stagePlanSha256": stage_plan_sha256,
                "nativeResultSha256": (
                    "sha256:" + result_offer.group(1).decode("ascii")
                ),
                "resultKind": result_offer.group(2).decode("ascii"),
                "resultPredecessorKind": result_offer.group(3).decode("ascii"),
                "failureEvidenceSha256": (
                    None if failure_wire == "-" else "sha256:" + failure_wire
                ),
                "placementMask": int(result_offer.group(5)),
            }
            validate_result_envelope_v4(
                {
                    "resultKind": candidate["resultKind"],
                    "predecessorKind": candidate["resultPredecessorKind"],
                    "failureEvidenceSha256": candidate["failureEvidenceSha256"],
                }
            )
            if not _placement_mask_matches_result_v27(
                candidate["placementMask"], candidate["resultKind"]
            ):
                raise NativeBoundaryV27Error(
                    "V27 native result offer placement mask changed"
                )
            expected_offer_hmac = hmac.new(
                request_key_bytes,
                _NATIVE_RESULT_OFFER_DOMAIN_V27 + canonical_bytes(candidate),
                hashlib.sha256,
            ).hexdigest()
            if (
                not hmac.compare_digest(
                    result_offer.group(6).decode("ascii"), expected_offer_hmac
                )
                or not callable(result_offer_mediator)
            ):
                raise NativeBoundaryV27Error(
                    "V27 native result offer authentication changed"
                )
            response = result_offer_mediator(candidate)
            response_fields = {
                "schemaVersion", "protocol", "action", "stagePlanSha256",
                "nativeResultSha256", "authorizationRecordSha256", "ackHmac",
            }
            if (
                not isinstance(response, Mapping)
                or set(response) != response_fields
                or response.get("schemaVersion") != 27
                or response.get("protocol")
                != "startup-factory/beads-native-worker/v27"
                or response.get("action") != "ACK-RESULT-OFFER"
                or response.get("stagePlanSha256") != stage_plan_sha256
                or response.get("nativeResultSha256")
                != candidate["nativeResultSha256"]
                or not isinstance(response.get("authorizationRecordSha256"), str)
                or not _DIGEST.fullmatch(response["authorizationRecordSha256"])
            ):
                raise NativeBoundaryV27Error(
                    "V27 native result offer authorization identity changed"
                )
            ack_body = {
                key: response[key]
                for key in response_fields
                if key != "ackHmac"
            }
            expected_ack_hmac = "hmac-sha256:" + hmac.new(
                request_key_bytes,
                _NATIVE_RESULT_OFFER_ACK_DOMAIN_V27 + canonical_bytes(ack_body),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(
                str(response.get("ackHmac")), expected_ack_hmac
            ):
                raise NativeBoundaryV27Error(
                    "V27 native result offer authorization HMAC changed"
                )
            acknowledgement = (
                "RESULT-OFFER-ACK "
                f"{str(candidate['nativeResultSha256']).removeprefix('sha256:')} "
                f"{str(response['authorizationRecordSha256']).removeprefix('sha256:')} "
                f"{str(response['ackHmac']).removeprefix('hmac-sha256:')}\n"
            ).encode("ascii")
            if channel.send(acknowledgement) != len(acknowledgement):
                raise NativeBoundaryV27Error(
                    "V27 native result offer authorization was truncated"
                )
            authorized_result_offer = dict(candidate)
            continue
        terminal = re.fullmatch(rb"CONTROL-DONE ((?:0|[1-9][0-9]*))\n", packet)
        if terminal is not None:
            placement_mask = int(terminal.group(1))
            observed_mask = sum(1 << ordinal for ordinal in seen_ordinals)
            if (
                authorized_result_offer is None
                or
                placement_mask != observed_mask
                or not _placement_mask_matches_result_v27(
                    placement_mask,
                    None
                    if authorized_result_offer is None
                    else authorized_result_offer["resultKind"],
                )
            ):
                raise NativeBoundaryV27Error(
                    "V27 lifecycle placement terminal mask changed"
                )
            break
        match = re.fullmatch(
            rb"PLACE ([1-9][0-9]*) ((?:0|[1-9][0-9]*)) ([0-5]) ([0-9a-f]{64})\n",
            packet,
        )
        if match is None:
            raise NativeBoundaryV27Error("V27 placement control payload changed")
        child_pid = int(match.group(1))
        ordinal = int(match.group(3))
        nonce = match.group(4).decode("ascii")
        observed_mask = sum(1 << item for item in seen_ordinals)
        if ordinal in seen_ordinals or not _lifecycle_placement_transition_allowed_v27(
            observed_mask, ordinal
        ):
            raise NativeBoundaryV27Error(
                "V27 lifecycle placement ordinal reordered or replayed"
            )
        placement = placement_mediator(
            {
                "supervisorPid": process.pid,
                "childPid": child_pid,
                "childStartTime": match.group(2).decode("ascii"),
                "ordinal": ordinal,
                "placementNonce": nonce,
            }
        )
        if (
            not isinstance(placement, Mapping)
            or placement.get("workerPid") != child_pid
            or placement.get("ordinal") != ordinal
            or placement.get("placementNonce") != nonce
        ):
            raise NativeBoundaryV27Error(
                "V27 controller lifecycle placement evidence changed"
            )
        acknowledgement = f"PLACED {child_pid} {ordinal} {nonce}\n".encode("ascii")
        if channel.send(acknowledgement) != len(acknowledgement):
            raise NativeBoundaryV27Error(
                "V27 lifecycle placement acknowledgement was truncated"
            )
        seen_ordinals.add(ordinal)
    channel.settimeout(None)
    return placement_mask


_NATIVE_LAUNCHER_SOURCE_FDS_V27 = tuple(range(64, 76))


def _pre_popen_source_descriptor_preflight_v27(
    launcher_path: Path, sources: Mapping[int, int]
) -> None:
    """Prove the complete source-FD table before making the launch call."""

    if (
        not launcher_path.is_absolute()
        or type(sources) is not dict
        or tuple(sorted(sources)) != _NATIVE_LAUNCHER_SOURCE_FDS_V27
    ):
        raise NativeBoundaryV27Error(
            "V27 pre-Popen source descriptor table changed"
        )
    identities: list[tuple[int, int]] = []
    for source in sources.values():
        if type(source) is not int or source < 0:
            raise NativeBoundaryV27Error(
                "V27 pre-Popen source descriptor changed"
            )
        try:
            metadata = os.fstat(source)
        except OSError as exc:
            raise NativeBoundaryV27Error(
                "V27 pre-Popen source descriptor is unavailable"
            ) from exc
        identities.append((metadata.st_dev, metadata.st_ino))
    if len(set(identities)) != len(identities):
        raise NativeBoundaryV27Error(
            "V27 pre-Popen source descriptor identity was aliased"
        )


def _invoke_native_launcher_v27(
    launcher_path: Path,
    sources: Mapping[int, int],
    *,
    after_start: Any = None,
    timeout: int = 150,
    drain_on_failure: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Invoke the installed launcher with its exact, closed source-FD table.

    This is the only production path that constructs launcher custody.  It has
    deliberately no argv, environment, cwd, or ``preexec_fn`` customization.
    Tests exercise this function with a genuine compiled launcher and child.
    """

    if (
        type(sources) is not dict
        or tuple(sorted(sources)) != _NATIVE_LAUNCHER_SOURCE_FDS_V27
        or any(type(value) is not int or value < 0 for value in sources.values())
    ):
        raise NativeBoundaryV27Error("V27 launcher source descriptor table changed")
    if not launcher_path.is_absolute():
        raise NativeBoundaryV27Error("V27 launcher path must be absolute")
    occupied: list[int] = []
    try:
        for target in _NATIVE_LAUNCHER_SOURCE_FDS_V27:
            try:
                fcntl.fcntl(target, fcntl.F_GETFD)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise NativeBoundaryV27Error(
                        f"cannot inspect V27 launcher source descriptor {target}"
                    ) from exc
            else:
                raise NativeBoundaryV27Error(
                    f"V27 fixed source descriptor {target} is already occupied"
                )
        for target in _NATIVE_LAUNCHER_SOURCE_FDS_V27:
            os.dup2(sources[target], target, inheritable=True)
            occupied.append(target)

        def close_child_endpoint_and_continue(
            process: subprocess.Popen[bytes],
        ) -> None:
            os.close(71)
            occupied.remove(71)
            if after_start is not None:
                after_start(process)

        argv = [str(launcher_path), "--startup-factory-launch-v27"]
        return _run_bounded_process_v27(
            argv,
            timeout=timeout,
            pass_fds=_NATIVE_LAUNCHER_SOURCE_FDS_V27,
            drain_on_failure=drain_on_failure,
            after_start=close_child_endpoint_and_continue,
            executable=str(launcher_path),
        )
    finally:
        for descriptor in reversed(occupied):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _reopen_authenticated_fd10_result_v27(
    result_dir: int,
    request_key: bytes,
    request_key_id: str,
    *,
    expected_stdout: bytes | None = None,
    filename: str = "result.json",
) -> tuple[bytes, bytes]:
    if filename not in {"result.json", ".result.json.tmp"}:
        raise NativeBoundaryV27Error("V27 result object name changed")
    directory_metadata = os.fstat(result_dir)
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
    ):
        raise NativeBoundaryV27Error("V27 protected result directory identity changed")
    try:
        stored_result_fd = os.open(
            filename,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=result_dir,
        )
    except FileNotFoundError as exc:
        raise NativeBoundaryV27Error(
            "V27 consumed launch has no durable FD10 result; quarantine required"
        ) from exc
    try:
        stored_metadata = os.fstat(stored_result_fd)
        if (
            not stat.S_ISREG(stored_metadata.st_mode)
            or stored_metadata.st_uid != os.geteuid()
            or stored_metadata.st_nlink != 1
            or stat.S_IMODE(stored_metadata.st_mode) != 0o600
            or not 1 <= stored_metadata.st_size <= MAX_CANONICAL_BYTES
        ):
            raise NativeBoundaryV27Error(
                "V27 protected result object identity changed"
            )
        stored_envelope = _pread_exact_bounded_v27(
            stored_result_fd,
            stored_metadata.st_size,
            "protected supervisor result",
        )
    finally:
        os.close(stored_result_fd)
    if expected_stdout is not None and stored_envelope != expected_stdout:
        raise NativeBoundaryV27Error(
            "V27 stdout differs from the fsync-durable FD10 result"
        )
    envelope = _strict_probe_json(stored_envelope)
    if (
        set(envelope) != {"requestKeyId", "result", "resultHmac"}
        or envelope["requestKeyId"] != request_key_id
        or not isinstance(envelope["result"], dict)
    ):
        raise NativeBoundaryV27Error(
            "V27 authenticated supervisor result envelope is invalid"
        )
    result_raw = canonical_bytes(envelope["result"])
    expected_result = "hmac-sha256:" + hmac.new(
        request_key,
        b"startup-factory/beads/v27/result\0" + result_raw,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(str(envelope["resultHmac"]), expected_result):
        raise NativeBoundaryV27Error(
            "V27 supervisor result HMAC authentication failed"
        )
    return stored_envelope, result_raw


def _native_stage_result_path_v27(
    plan: Mapping[str, Any], *, runtime_root: Path | None = None
) -> Path:
    root = (
        Path(f"/run/user/{os.geteuid()}") / "startup-factory-beads-results"
        if runtime_root is None
        else runtime_root
    )
    return root / (
        str(plan["operationId"])
        + "-" + str(plan["stageLocation"])
        + "-" + str(plan["stagePlanSha256"]).removeprefix("sha256:")
    )


def _result_arena_body_v27(
    plan: Mapping[str, Any], result_metadata: os.stat_result,
    lock_metadata: os.stat_result,
) -> dict[str, Any]:
    return {
        "schemaVersion": 27,
        "operationId": plan["operationId"],
        "stageLocation": plan["stageLocation"],
        "stagePlanSha256": plan["stagePlanSha256"],
        "requestKeyId": plan["requestKeyId"],
        "payloadName": (
            f"payload-{plan['operationId']}-s{plan['stageLocation']}-"
            f"{str(plan['stagePlanSha256']).removeprefix('sha256:')[:16]}"
        ),
        "resultDirectory": {
            "device": result_metadata.st_dev,
            "gid": result_metadata.st_gid,
            "inode": result_metadata.st_ino,
            "mode": f"{stat.S_IMODE(result_metadata.st_mode):04o}",
            "uid": result_metadata.st_uid,
        },
        "operationLock": _operation_lock_projection_v27(lock_metadata),
    }


def _validate_result_arena_request_v27(
    value: Any, plan: Mapping[str, Any], request_key: bytes
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"arena", "requestKeyHmac"}
        or not isinstance(value["arena"], Mapping)
    ):
        raise NativeBoundaryV27Error("V27 result arena request shape changed")
    arena = dict(value["arena"])
    if set(arena) != {
        "schemaVersion", "operationId", "stageLocation", "stagePlanSha256",
        "requestKeyId", "payloadName", "resultDirectory", "operationLock",
    } or (
        arena["schemaVersion"] != 27
        or arena["operationId"] != plan["operationId"]
        or arena["stageLocation"] != plan["stageLocation"]
        or arena["stagePlanSha256"] != plan["stagePlanSha256"]
        or arena["requestKeyId"] != plan["requestKeyId"]
        or type(request_key) is not bytes
        or sha256(request_key) != plan["requestKeyId"]
    ):
        raise NativeBoundaryV27Error("V27 result arena request binding changed")
    _retirement_payload_identity_v27(arena["resultDirectory"])
    _retirement_identity_v27(arena["operationLock"], "result arena lock")
    expected = "hmac-sha256:" + hmac.new(
        request_key,
        _RESULT_ARENA_REQUEST_DOMAIN_V27 + canonical_bytes(arena),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(str(value["requestKeyHmac"]), expected):
        raise NativeBoundaryV27Error("V27 result arena request HMAC failed")
    return {"arena": arena, "requestKeyHmac": expected}


def prepare_native_stage_result_arena_v27(
    manifest: NativeBoundaryManifestV27,
    value: Any,
    request_key: bytes,
    *,
    runtime_root: Path | None = None,
    phase_hook: Any = None,
) -> dict[str, Any]:
    """Prepare and fsync the exact FD10 arena before any payload cgroup."""

    plan = validate_native_stage_action_plan_v27(value, manifest)
    if type(request_key) is not bytes or sha256(request_key) != plan["requestKeyId"]:
        raise NativeBoundaryV27Error("V27 result arena request key changed")
    hook = phase_hook if callable(phase_hook) else lambda _phase: None
    root = (
        Path(f"/run/user/{os.geteuid()}") / "startup-factory-beads-results"
        if runtime_root is None else runtime_root
    )
    root.mkdir(mode=0o700, exist_ok=True)
    root_metadata = os.lstat(root)
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise NativeBoundaryV27Error("V27 result root mode changed")
    root_fd = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )
    result_dir = lock_fd = -1
    try:
        result_path = _native_stage_result_path_v27(plan, runtime_root=root)
        try:
            os.mkdir(result_path.name, 0o700, dir_fd=root_fd)
            hook("result-arena:directory-created")
            os.fsync(root_fd)
            hook("result-arena:parent-fsynced")
        except FileExistsError:
            pass
        result_dir = os.open(
            result_path.name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        result_metadata = os.fstat(result_dir)
        if (
            not stat.S_ISDIR(result_metadata.st_mode)
            or result_metadata.st_uid != os.geteuid()
            or result_metadata.st_gid != os.getegid()
            or stat.S_IMODE(result_metadata.st_mode) != 0o700
        ):
            raise NativeBoundaryV27Error(
                "V27 protected result directory identity changed"
            )
        lock_fd = _open_durable_operation_lock_v27(
            result_dir, phase_hook=phase_hook
        )
        arena = _result_arena_body_v27(
            plan, result_metadata, os.fstat(lock_fd)
        )
        request_hmac = "hmac-sha256:" + hmac.new(
            request_key,
            _RESULT_ARENA_REQUEST_DOMAIN_V27 + canonical_bytes(arena),
            hashlib.sha256,
        ).hexdigest()
        return {"arena": arena, "requestKeyHmac": request_hmac}
    finally:
        for descriptor in (lock_fd, result_dir, root_fd):
            if descriptor >= 0:
                os.close(descriptor)


def persist_controller_result_arena_v27(
    manifest: NativeBoundaryManifestV27,
    value: Any,
    arena_envelope: Any,
    *,
    runtime_root: Path | None = None,
    phase_hook: Any = None,
) -> str:
    """Persist a controller-authenticated ACK without exposing its key."""

    plan = validate_native_stage_action_plan_v27(value, manifest)
    if (
        not isinstance(arena_envelope, Mapping)
        or set(arena_envelope) != {"arena", "requestKeyHmac", "controllerHmac"}
        or not isinstance(arena_envelope["arena"], Mapping)
        or re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", str(
            arena_envelope["requestKeyHmac"]
        )) is None
        or re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", str(
            arena_envelope["controllerHmac"]
        )) is None
    ):
        raise NativeBoundaryV27Error("V27 controller result arena ACK changed")
    root = (
        Path(f"/run/user/{os.geteuid()}") / "startup-factory-beads-results"
        if runtime_root is None else runtime_root
    )
    result_path = _native_stage_result_path_v27(plan, runtime_root=root)
    result_dir = lock_fd = -1
    try:
        result_dir = os.open(
            result_path,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        lock_fd = os.open(
            "operation.lock",
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=result_dir,
        )
        expected_arena = _result_arena_body_v27(
            plan, os.fstat(result_dir), os.fstat(lock_fd)
        )
        if dict(arena_envelope["arena"]) != expected_arena:
            raise NativeBoundaryV27Error(
                "V27 controller result arena ACK identity changed"
            )
        raw = canonical_bytes(dict(arena_envelope))
        _persist_atomic_retirement_artifact_v27(
            result_dir,
            "arena.json",
            raw,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            phase_hook=phase_hook,
        )
        return sha256(raw)
    finally:
        for descriptor in (lock_fd, result_dir):
            if descriptor >= 0:
                os.close(descriptor)


def _decode_native_result_json_v27(result_raw: bytes) -> dict[str, Any]:
    envelope = _strict_probe_json(
        result_raw if result_raw.endswith(b"\n") else result_raw + b"\n"
    )
    if set(envelope) != {
        "exitCode", "failureEvidenceSha256", "lifecycle", "placementMask",
        "resultKind", "resultPredecessorKind", "stderrBase64", "stdoutBase64",
    }:
        raise NativeBoundaryV27Error("native V27 stage result schema changed")
    try:
        decoded = {
            "exitCode": envelope["exitCode"],
            "lifecycle": envelope["lifecycle"],
            "placementMask": envelope["placementMask"],
            "stderr": base64.b64decode(envelope["stderrBase64"], validate=True),
            "stdout": base64.b64decode(envelope["stdoutBase64"], validate=True),
            "resultKind": envelope["resultKind"],
            "resultPredecessorKind": envelope["resultPredecessorKind"],
            "failureEvidenceSha256": envelope["failureEvidenceSha256"],
        }
    except (TypeError, ValueError) as exc:
        raise NativeBoundaryV27Error(
            "native V27 stage result base64 is invalid"
        ) from exc
    _decode_native_stage_result_v27(decoded, require_discriminants=True)
    return decoded


def _native_supervisor_loss_v27(
    *, reason: str, evidence_sha256: str
) -> dict[str, Any]:
    """Return one closed internal loss observation for consumed-stage recovery."""

    if reason not in {
        "authenticated-controller-loss",
        "dead-holder-without-terminal",
    }:
        raise NativeBoundaryV27Error("native V27 supervisor loss reason changed")
    _digest(evidence_sha256, "native supervisor loss evidenceSha256")
    return {
        "nativeSupervisorLoss": {
            "schemaVersion": 27,
            "reason": reason,
            "evidenceSha256": evidence_sha256,
        }
    }


def _is_native_supervisor_loss_v27(value: Any) -> bool:
    if (
        not isinstance(value, Mapping)
        or set(value) not in {
            frozenset({"nativeSupervisorLoss"}),
            frozenset({"nativeSupervisorLoss", "_controllerRetirementChain"}),
            frozenset({"nativeSupervisorLoss", "controllerRetirement"}),
        }
    ):
        return False
    loss = value["nativeSupervisorLoss"]
    if not isinstance(loss, Mapping) or set(loss) != {
        "schemaVersion", "reason", "evidenceSha256"
    }:
        return False
    if loss.get("schemaVersion") != 27 or loss.get("reason") not in {
        "authenticated-controller-loss",
        "dead-holder-without-terminal",
    }:
        return False
    evidence = loss.get("evidenceSha256")
    return isinstance(evidence, str) and _DIGEST.fullmatch(evidence) is not None


def _operation_lock_projection_v27(metadata: os.stat_result) -> dict[str, Any]:
    return {
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "nlink": metadata.st_nlink,
        "uid": metadata.st_uid,
    }


def _reopen_authenticated_fd10_disposition_v27(
    result_dir: int,
    request_key: bytes,
    plan: Mapping[str, Any],
    operation_lock: os.stat_result,
    *,
    filename: str = "disposition.json",
) -> dict[str, Any]:
    if filename not in {"disposition.json", ".disposition.json.tmp"}:
        raise NativeBoundaryV27Error("V27 disposition object name changed")
    try:
        descriptor = os.open(
            filename,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=result_dir,
        )
    except FileNotFoundError as exc:
        raise NativeBoundaryV27Error(
            "V27 authenticated loss disposition disappeared"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= MAX_CANONICAL_BYTES
        ):
            raise NativeBoundaryV27Error(
                "V27 protected loss disposition identity changed"
            )
        raw = _pread_exact_bounded_v27(
            descriptor, metadata.st_size, "protected loss disposition"
        )
    finally:
        os.close(descriptor)
    envelope = _strict_probe_json(raw)
    if set(envelope) != {"disposition", "dispositionHmac"} or not isinstance(
        envelope.get("disposition"), Mapping
    ):
        raise NativeBoundaryV27Error(
            "V27 authenticated loss disposition envelope is invalid"
        )
    disposition = dict(envelope["disposition"])
    if set(disposition) != {
        "disposition", "operationId", "operationLock", "requestKeyId",
        "schemaVersion", "stageLocation", "stagePlanSha256",
    } or (
        disposition["disposition"] != "controller-lost-payload-drained"
        or disposition["operationId"] != plan["operationId"]
        or disposition["operationLock"]
        != _operation_lock_projection_v27(operation_lock)
        or disposition["requestKeyId"] != plan["requestKeyId"]
        or disposition["schemaVersion"] != 27
        or disposition["stageLocation"] != plan["stageLocation"]
        or disposition["stagePlanSha256"] != plan["stagePlanSha256"]
    ):
        raise NativeBoundaryV27Error(
            "V27 authenticated loss disposition binding changed"
        )
    body = canonical_bytes(disposition)
    expected = "hmac-sha256:" + hmac.new(
        request_key,
        b"startup-factory/beads/v27/disposition\0" + body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(str(envelope["dispositionHmac"]), expected):
        raise NativeBoundaryV27Error(
            "V27 authenticated loss disposition HMAC failed"
        )
    return _native_supervisor_loss_v27(
        reason="authenticated-controller-loss",
        evidence_sha256=sha256(raw),
    )


def _reopen_request_authenticated_result_arena_v27(
    result_dir: int,
    request_key: bytes,
    plan: Mapping[str, Any],
    operation_lock: os.stat_result,
) -> str:
    descriptor = -1
    try:
        descriptor = os.open(
            "arena.json",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=result_dir,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= MAX_CANONICAL_BYTES
        ):
            raise NativeBoundaryV27Error(
                "V27 controller result arena identity changed"
            )
        raw = _pread_exact_bounded_v27(
            descriptor, metadata.st_size, "controller result arena"
        )
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NativeBoundaryV27Error(
                "V27 controller result arena is malformed"
            ) from exc
        if (
            not isinstance(value, Mapping)
            or set(value) != {"arena", "requestKeyHmac", "controllerHmac"}
            or canonical_bytes(dict(value)) != raw
            or re.fullmatch(
                r"hmac-sha256:[0-9a-f]{64}", str(value["controllerHmac"])
            ) is None
        ):
            raise NativeBoundaryV27Error(
                "V27 controller result arena envelope changed"
            )
        verified = _validate_result_arena_request_v27(
            {
                "arena": value["arena"],
                "requestKeyHmac": value["requestKeyHmac"],
            },
            plan,
            request_key,
        )
        actual = _result_arena_body_v27(
            plan, os.fstat(result_dir), operation_lock
        )
        if verified["arena"] != actual:
            raise NativeBoundaryV27Error(
                "V27 controller result arena descriptor binding changed"
            )
        return sha256(raw)
    except FileNotFoundError as exc:
        raise NativeBoundaryV27Error(
            "V27 controller-authenticated result arena is absent"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _reopen_controller_retirement_chain_for_relay_v27(
    result_dir: int,
) -> dict[str, Any]:
    """Relay canonical controller envelopes; worker bytes grant no authority."""

    result: dict[str, Any] = {}
    for kind, filename in (
        ("arena", "arena.json"),
        ("intent", "controller-retirement.intent.json"),
        ("receipt", "controller-retirement.json"),
    ):
        descriptor = -1
        try:
            descriptor = os.open(
                filename,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=result_dir,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_gid != os.getegid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or not 1 <= metadata.st_size <= MAX_CANONICAL_BYTES
            ):
                raise NativeBoundaryV27Error(
                    f"V27 durable controller {kind} relay identity changed"
                )
            raw = _pread_exact_bounded_v27(
                descriptor, metadata.st_size, f"controller {kind} relay"
            )
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise NativeBoundaryV27Error(
                    f"V27 durable controller {kind} relay is malformed"
                ) from exc
            if not isinstance(value, Mapping) or canonical_bytes(dict(value)) != raw:
                raise NativeBoundaryV27Error(
                    f"V27 durable controller {kind} relay is noncanonical"
                )
            result[kind] = dict(value)
        except FileNotFoundError as exc:
            raise NativeBoundaryV27Error(
                f"V27 durable controller {kind} relay is absent"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return result


def _reopen_controller_pre_effect_proof_for_relay_v27(
    result_dir: int,
    plan: Mapping[str, Any],
    *,
    filename: str = "pre-effect-proof.json",
) -> dict[str, Any]:
    """Relay a canonical controller proof; worker-readable bytes are not auth."""

    descriptor = -1
    try:
        descriptor = os.open(
            filename,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=result_dir,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink not in {1, 2}
            or not 1 <= metadata.st_size <= MAX_CANONICAL_BYTES
        ):
            raise NativeBoundaryV27Error(
                "V27 durable controller pre-effect proof relay identity changed"
            )
        raw = _pread_exact_bounded_v27(
            descriptor, metadata.st_size, "controller pre-effect proof relay"
        )
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NativeBoundaryV27Error(
                "V27 durable controller pre-effect proof relay is malformed"
            ) from exc
        if (
            not isinstance(value, Mapping)
            or set(value) != {"proof", "controllerHmac"}
            or not isinstance(value["proof"], Mapping)
            or canonical_bytes(dict(value)) != raw
            or re.fullmatch(
                r"hmac-sha256:[0-9a-f]{64}", str(value["controllerHmac"])
            ) is None
            or value["proof"].get("operationId") != plan["operationId"]
            or value["proof"].get("stageLocation") != plan["stageLocation"]
            or value["proof"].get("stagePlanSha256") != plan["stagePlanSha256"]
            or value["proof"].get("requestKeyId") != plan["requestKeyId"]
        ):
            raise NativeBoundaryV27Error(
                "V27 durable controller pre-effect proof relay binding changed"
            )
        return dict(value)
    except FileNotFoundError as exc:
        raise NativeBoundaryV27Error(
            "V27 durable controller pre-effect proof relay is absent"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _persist_atomic_retirement_artifact_v27(
    result_dir: int,
    final_name: str,
    raw: bytes,
    *,
    owner_uid: int,
    owner_gid: int,
    phase_hook: Any = None,
) -> None:
    """Crash-close one bounded artifact via a fixed recoverable temp name."""

    if final_name not in {
        "arena.json", "controller-custody.json",
        "controller-retirement.intent.json",
        "controller-retirement.json",
        "pre-effect-proof.json",
    } or not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_CANONICAL_BYTES:
        raise NativeBoundaryV27Error("V27 retirement artifact request is invalid")
    temp_name = "." + final_name + ".tmp"
    hook = phase_hook if callable(phase_hook) else lambda _phase: None

    def inspect(
        descriptor: int, *, label: str, allow_created_half_state: bool = False
    ) -> tuple[bytes, os.stat_result]:
        metadata = os.fstat(descriptor)
        created_half_state = (
            allow_created_half_state
            and metadata.st_size == 0
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_nlink == 1
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (
                not created_half_state
                and (
                    metadata.st_uid != owner_uid
                    or metadata.st_gid != owner_gid
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink not in {1, 2}
                )
            )
            or metadata.st_size > len(raw)
        ):
            raise NativeBoundaryV27Error(
                f"V27 durable retirement {label} identity changed"
            )
        content = _pread_exact_bounded_v27(
            descriptor, metadata.st_size, f"retirement {label}"
        ) if metadata.st_size else b""
        return content, metadata

    final_fd = temp_fd = -1
    try:
        try:
            final_fd = os.open(
                final_name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=result_dir,
            )
        except FileNotFoundError:
            pass
        if final_fd >= 0:
            final_bytes, final_metadata = inspect(final_fd, label="artifact")
            if final_bytes != raw:
                raise NativeBoundaryV27Error(
                    "V27 durable retirement artifact bytes changed"
                )
            try:
                temp_fd = os.open(
                    temp_name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=result_dir,
                )
            except FileNotFoundError:
                temp_fd = -1
            if temp_fd >= 0:
                partial, temp_metadata = inspect(
                    temp_fd, label="temporary artifact"
                )
                if (
                    raw[:len(partial)] != partial
                    or (temp_metadata.st_dev, temp_metadata.st_ino)
                    != (final_metadata.st_dev, final_metadata.st_ino)
                    or final_metadata.st_nlink != 2
                    or temp_metadata.st_nlink != 2
                ):
                    raise NativeBoundaryV27Error(
                        "V27 retirement installed temporary is not the final hardlink"
                    )
                os.close(temp_fd)
                temp_fd = -1
                os.unlink(temp_name, dir_fd=result_dir)
            os.fsync(result_dir)
            return

        try:
            temp_fd = os.open(
                temp_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=result_dir,
            )
            hook(final_name + ":temp-created-unnormalized")
            if os.geteuid() == 0:
                os.fchown(temp_fd, owner_uid, owner_gid)
            os.fchmod(temp_fd, 0o600)
            hook(final_name + ":temp-created")
        except FileExistsError:
            temp_fd = os.open(
                temp_name,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=result_dir,
            )
        partial, metadata = inspect(
            temp_fd,
            label="temporary artifact",
            allow_created_half_state=True,
        )
        if (
            metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            if partial or metadata.st_nlink != 1 or os.geteuid() != 0:
                raise NativeBoundaryV27Error(
                    "V27 retirement temporary owner/mode half-state is unsafe"
                )
            os.fchown(temp_fd, owner_uid, owner_gid)
            os.fchmod(temp_fd, 0o600)
        if raw[:len(partial)] != partial:
            raise NativeBoundaryV27Error(
                "V27 retirement temporary bytes are not an exact prefix"
            )
        os.ftruncate(temp_fd, 0)
        os.lseek(temp_fd, 0, os.SEEK_SET)
        _write_all_v27(temp_fd, raw)
        hook(final_name + ":bytes-written")
        os.fsync(temp_fd)
        hook(final_name + ":file-fsynced")
        os.close(temp_fd)
        temp_fd = -1
        try:
            os.link(
                temp_name,
                final_name,
                src_dir_fd=result_dir,
                dst_dir_fd=result_dir,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise NativeBoundaryV27Error(
                "V27 retirement final appeared before no-replace install"
            ) from exc
        hook(final_name + ":installed")
        os.unlink(temp_name, dir_fd=result_dir)
        hook(final_name + ":temporary-unlinked")
        os.fsync(result_dir)
        hook(final_name + ":directory-fsynced")
    except OSError as exc:
        raise NativeBoundaryV27Error(
            f"cannot persist V27 retirement artifact: {exc}"
        ) from exc
    finally:
        for descriptor in (temp_fd, final_fd):
            if descriptor >= 0:
                os.close(descriptor)


def persist_controller_retirement_artifact_v27(
    manifest: NativeBoundaryManifestV27,
    value: Any,
    artifact_kind: str,
    artifact: Any,
    *,
    runtime_root: Path | None = None,
    phase_hook: Any = None,
) -> dict[str, Any]:
    """Worker-side fsync persistence for controller-observed retirement state."""

    plan = validate_native_stage_action_plan_v27(value, manifest)
    payload_name = (
        f"payload-{plan['operationId']}-s{plan['stageLocation']}-"
        f"{str(plan['stagePlanSha256']).removeprefix('sha256:')[:16]}"
    )
    if artifact_kind == "pre-effect-proof":
        if (
            not isinstance(artifact, Mapping)
            or set(artifact) != {"proof", "controllerHmac"}
            or not isinstance(artifact["proof"], Mapping)
            or re.fullmatch(
                r"hmac-sha256:[0-9a-f]{64}", str(artifact["controllerHmac"])
            ) is None
        ):
            raise NativeBoundaryV27Error(
                "V27 controller pre-effect proof envelope changed"
            )
        proof = artifact["proof"]
        proof_fields = {
            "schemaVersion", "operationId", "stageLocation",
            "stagePlanSha256", "requestKeyId", "payloadName",
            "arenaRecordSha256", "consumedCurrentRecordSha256",
            "workerFailure", "firstEmptyObservation",
            "secondEmptyObservation", "controllerRetirement",
            "controllerRetirementSha256",
        }
        if (
            set(proof) != proof_fields
            or proof["schemaVersion"] != 27
            or proof["operationId"] != plan["operationId"]
            or proof["stageLocation"] != plan["stageLocation"]
            or proof["stagePlanSha256"] != plan["stagePlanSha256"]
            or proof["requestKeyId"] != plan["requestKeyId"]
            or proof["payloadName"] != payload_name
            or not _DIGEST.fullmatch(str(proof["arenaRecordSha256"]))
            or not _DIGEST.fullmatch(
                str(proof["consumedCurrentRecordSha256"])
            )
            or not _DIGEST.fullmatch(
                str(proof["controllerRetirementSha256"])
            )
            or not isinstance(proof["workerFailure"], Mapping)
            or not isinstance(proof["firstEmptyObservation"], Mapping)
            or not isinstance(proof["secondEmptyObservation"], Mapping)
            or not isinstance(proof["controllerRetirement"], Mapping)
            or sha256(canonical_bytes(dict(proof["controllerRetirement"])))
            != proof["controllerRetirementSha256"]
        ):
            raise NativeBoundaryV27Error(
                "V27 controller pre-effect proof binding changed"
            )
        decoded = dict(proof)
        final_name = "pre-effect-proof.json"
    elif (
        not isinstance(artifact, Mapping)
        or set(artifact) != {"artifact", "controllerHmac"}
        or not isinstance(artifact["artifact"], Mapping)
        or re.fullmatch(
            r"hmac-sha256:[0-9a-f]{64}", str(artifact["controllerHmac"])
        ) is None
    ):
        raise NativeBoundaryV27Error(
            "V27 controller retirement authentication envelope changed"
        )
    if artifact_kind != "pre-effect-proof":
        signed = dict(artifact["artifact"])
    else:
        signed = {}
    if artifact_kind != "pre-effect-proof" and (
        set(signed) != {
            "schemaVersion", "kind", "operationId", "stageLocation",
            "stagePlanSha256", "requestKeyId", "payloadName", "payloadIdentity",
            "arenaRecordSha256", "predecessorArtifactSha256", "body",
        }
        or signed["schemaVersion"] != 27
        or signed["kind"] != artifact_kind
        or signed["operationId"] != plan["operationId"]
        or signed["stageLocation"] != plan["stageLocation"]
        or signed["stagePlanSha256"] != plan["stagePlanSha256"]
        or signed["requestKeyId"] != plan["requestKeyId"]
        or signed["payloadName"] != payload_name
    ):
        raise NativeBoundaryV27Error(
            "V27 controller retirement authentication binding changed"
        )
    if artifact_kind != "pre-effect-proof":
        _retirement_payload_identity_v27(signed["payloadIdentity"])
    if artifact_kind == "pre-effect-proof":
        pass
    elif artifact_kind == "intent":
        decoded = _decode_controller_retirement_intent_v27(signed["body"])
        if signed["payloadIdentity"] != decoded["payloadIdentity"]:
            raise NativeBoundaryV27Error(
                "V27 retirement intent payload identity changed"
            )
        final_name = "controller-retirement.intent.json"
    elif artifact_kind == "receipt":
        body = signed["body"]
        if not isinstance(body, Mapping) or type(
            body.get("placementMask")
        ) is not int:
            raise NativeBoundaryV27Error(
                "V27 controller retirement receipt is invalid"
            )
        decoded = _decode_controller_retirement_v27(
            body, body["placementMask"]
        )
        final_name = "controller-retirement.json"
    else:
        raise NativeBoundaryV27Error(
            "V27 controller retirement artifact kind changed"
        )
    raw = canonical_bytes(dict(artifact))
    result_path = _native_stage_result_path_v27(plan, runtime_root=runtime_root)
    result_dir = os.open(
        result_path,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(result_dir)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise NativeBoundaryV27Error(
                "V27 retirement result directory identity changed"
            )
        _persist_atomic_retirement_artifact_v27(
            result_dir,
            final_name,
            raw,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            phase_hook=phase_hook,
        )
    finally:
        os.close(result_dir)
    return decoded


def _promote_terminal_temporary_v27(
    result_dir: int, temporary_name: str, final_name: str
) -> None:
    """Install one authenticated full temp without replacing any final."""

    try:
        os.link(
            temporary_name,
            final_name,
            src_dir_fd=result_dir,
            dst_dir_fd=result_dir,
            follow_symlinks=False,
        )
    except FileExistsError:
        temporary = os.stat(
            temporary_name, dir_fd=result_dir, follow_symlinks=False
        )
        final = os.stat(final_name, dir_fd=result_dir, follow_symlinks=False)
        if (
            temporary.st_dev,
            temporary.st_ino,
            temporary.st_nlink,
            final.st_dev,
            final.st_ino,
            final.st_nlink,
        ) != (
            final.st_dev,
            final.st_ino,
            2,
            final.st_dev,
            final.st_ino,
            2,
        ):
            raise NativeBoundaryV27Error(
                "V27 terminal temporary conflicts with installed final"
            )
    os.unlink(temporary_name, dir_fd=result_dir)
    os.fsync(result_dir)


_NATIVE_CREATOR_ARTIFACT_DOMAIN_V27: Final = (
    b"startup-factory/beads/v27/native-creator-artifact/v1\0"
)
_NATIVE_CREATOR_ARTIFACT_SPECS_V27: Final = (
    (
        ".native-creator-atomic-capture.v1",
        "NativePostReturnAtomicCaptureV1",
        "NativePostReturnCapturePreparationV1",
    ),
    (
        ".native-creator-join-result.v2",
        "CreatorJoinResultV2",
        "NativePostReturnAtomicCaptureV1",
    ),
    (
        ".native-creator-post-return.v2",
        "CreatorPostReturnObservationV2",
        "CreatorJoinResultV2",
    ),
    (
        ".native-creator-lifetime.v4",
        "CreatorThreadLifetimeReceiptV4",
        "CreatorPostReturnObservationV2",
    ),
    (
        ".native-allocation-gate-release.v1",
        "NativeAllocationGateReleaseReceiptV1",
        "CreatorThreadLifetimeReceiptV4",
    ),
)
_NATIVE_CREATOR_ARTIFACT_NAMES_V27: Final = frozenset(
    item[0] for item in _NATIVE_CREATOR_ARTIFACT_SPECS_V27
)
_NATIVE_CREATOR_ARTIFACT_COMMON_FIELDS_V27: Final = frozenset(
    {
        "artifactKind", "capturePreparationRecordSha256",
        "capturePreparationSha256", "creationNonceSha256",
        "creatorHandleConsumed", "creatorReturnCurrentRecordSha256",
        "joinOwnerTokenSha256", "operationId", "payload",
        "predecessorKind", "predecessorSha256", "requestKeyId",
        "returnAuthorizationRecordSha256", "returnSentinel",
        "schemaVersion", "sequence", "slotGeneration", "stageLocation",
        "stagePlanSha256", "taskSetSha256",
    }
)
_NATIVE_CREATOR_ARTIFACT_PAYLOAD_FIELDS_V27: Final = (
    frozenset(
        {
            "allocationGateHeld", "bootIdSha256", "captureMonotonicNs",
            "capturePreparationSha256", "capturePrepareMonotonicNs",
            "captureWritersSha256", "creatorStartTicks",
            "creatorTaskBytesSha256", "creatorTid", "fd11GetfdErrno",
            "fd7GetfdErrno", "joinOwnerTokenSha256", "pthreadJoinRc",
            "resultFdIdentitySha256", "returnSentinel", "slotGeneration",
            "taskSetSha256",
        }
    ),
    frozenset(
        {
            "atomicCaptureSha256", "creatorHandleConsumed",
            "joinOwnerTokenSha256", "pthreadJoinCount", "pthreadJoinRc",
            "returnSentinel", "slotGeneration",
        }
    ),
    frozenset(
        {
            "atomicCaptureSha256", "capturePreparationSha256",
            "creatorHandleConsumed", "joinResultSha256", "taskSetSha256",
        }
    ),
    frozenset(
        {
            "allocationGateHeld", "atomicCaptureSha256",
            "creatorHandleConsumed", "creatorTaskAbsent",
            "joinResultSha256", "postReturnObservationSha256",
            "proofFd11Closed", "proofFd7Closed", "pthreadJoinRc",
            "returnSentinel",
        }
    ),
    frozenset(
        {
            "allocationGateHeld", "allocationGateReleaseCount",
            "lifetimeSha256", "releaseMonotonicNs",
        }
    ),
)


def _validate_native_creator_artifact_payload_v27(
    sequence: int,
    payload: Any,
    artifact_digests: list[str],
    predecessor_sha256: str,
    capture_preparation_sha256: str,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or set(payload) != set(
        _NATIVE_CREATOR_ARTIFACT_PAYLOAD_FIELDS_V27[sequence]
    ):
        raise NativeBoundaryV27Error(
            "V27 native creator artifact payload shape changed"
        )
    value = dict(payload)
    sentinel = value.get("returnSentinel")
    if "returnSentinel" in value and sentinel not in {
        "creator-positive-sentinel",
        "creator-abort-sentinel",
    }:
        raise NativeBoundaryV27Error(
            "V27 native creator artifact sentinel changed"
        )
    if sequence == 0:
        if not (
            value["allocationGateHeld"] is True
            and type(value["capturePrepareMonotonicNs"]) is int
            and type(value["captureMonotonicNs"]) is int
            and 0 < value["capturePrepareMonotonicNs"] <= value["captureMonotonicNs"]
            and type(value["creatorTid"]) is int and value["creatorTid"] > 1
            and re.fullmatch(r"[1-9][0-9]*", str(value["creatorStartTicks"]))
            and value["fd7GetfdErrno"] == errno.EBADF
            and value["fd11GetfdErrno"] == errno.EBADF
            and value["pthreadJoinRc"] == 0
            and value["slotGeneration"] == 1
            and value["capturePreparationSha256"]
            == capture_preparation_sha256
        ):
            raise NativeBoundaryV27Error(
                "V27 native atomic capture values changed"
            )
        digest_fields = {
            "bootIdSha256", "capturePreparationSha256",
            "captureWritersSha256", "creatorTaskBytesSha256",
            "joinOwnerTokenSha256", "resultFdIdentitySha256",
            "taskSetSha256",
        }
    elif sequence == 1:
        if not (
            value["atomicCaptureSha256"] == predecessor_sha256
            and value["creatorHandleConsumed"] is True
            and value["pthreadJoinCount"] == 1
            and value["pthreadJoinRc"] == 0
            and value["slotGeneration"] == 1
        ):
            raise NativeBoundaryV27Error(
                "V27 native join result values changed"
            )
        digest_fields = {"atomicCaptureSha256", "joinOwnerTokenSha256"}
    elif sequence == 2:
        if not (
            value["atomicCaptureSha256"] == artifact_digests[0]
            and value["joinResultSha256"] == predecessor_sha256
            and value["creatorHandleConsumed"] is True
        ):
            raise NativeBoundaryV27Error(
                "V27 native post-return observation values changed"
            )
        digest_fields = {
            "atomicCaptureSha256", "capturePreparationSha256",
            "joinResultSha256", "taskSetSha256",
        }
    elif sequence == 3:
        if not (
            value["allocationGateHeld"] is True
            and value["atomicCaptureSha256"] == artifact_digests[0]
            and value["joinResultSha256"] == artifact_digests[1]
            and value["postReturnObservationSha256"] == predecessor_sha256
            and value["creatorHandleConsumed"] is True
            and value["creatorTaskAbsent"] is True
            and value["proofFd7Closed"] is True
            and value["proofFd11Closed"] is True
            and value["pthreadJoinRc"] == 0
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator lifetime values changed"
            )
        digest_fields = {
            "atomicCaptureSha256", "joinResultSha256",
            "postReturnObservationSha256",
        }
    else:
        if not (
            value["allocationGateHeld"] is False
            and value["allocationGateReleaseCount"] == 1
            and value["lifetimeSha256"] == predecessor_sha256
            and type(value["releaseMonotonicNs"]) is int
            and value["releaseMonotonicNs"] > 0
        ):
            raise NativeBoundaryV27Error(
                "V27 native allocation-gate release values changed"
            )
        digest_fields = {"lifetimeSha256"}
    for field in digest_fields:
        _digest(value[field], f"native creator artifact {field}")
    return value


def _is_native_creator_artifact_crash_prefix_v27(
    raw: bytes, kind: str, plan: Mapping[str, Any]
) -> bool:
    """Admit only a syntactically unfinished prefix of the fixed C writer."""

    fixed_prefix = (
        '{"artifact":{"artifactKind":'
        + json.dumps(kind, ensure_ascii=True, separators=(",", ":"))
        + ',"capturePreparationRecordSha256":'
    ).encode("ascii")
    if fixed_prefix.startswith(raw):
        return True
    if not raw.startswith(fixed_prefix) or raw.endswith(b"\n"):
        return False
    try:
        decoded = _strict_probe_json(raw + b"\n")
    except NativeBoundaryV27Error:
        decoded = None
    if decoded is not None:
        # write_all may die after the last canonical byte but before its LF.
        return canonical_bytes(decoded) == raw
    try:
        text = raw.decode("utf-8", "strict")
        json.JSONDecoder().raw_decode(text)
    except UnicodeDecodeError:
        return False
    except json.JSONDecodeError as exc:
        # A writer interruption can end at the parser cursor, or inside the
        # final string token.  Syntax failures before the byte frontier are
        # substitutions, not recoverable crash prefixes.
        return exc.pos >= len(text) - 1 or (
            exc.msg.startswith("Unterminated string")
            and '"' not in text[exc.pos + 1 :]
        )
    return False


def _reopen_native_creator_artifacts_v27(
    result_dir: int,
    request_key: bytes,
    plan: Mapping[str, Any],
    names: set[str],
    *,
    return_binding: bool = False,
) -> Any:
    """Authenticate the fixed writer chain or classify an exact crash prefix."""

    present = names & set(_NATIVE_CREATOR_ARTIFACT_NAMES_V27)
    if not present:
        return {"status": "absent", "binding": None} if return_binding else "absent"
    if present != set(_NATIVE_CREATOR_ARTIFACT_NAMES_V27):
        ordered_names = [item[0] for item in _NATIVE_CREATOR_ARTIFACT_SPECS_V27]
        prefix_length = len(present)
        if present != set(ordered_names[:prefix_length]):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact reservation has a hole"
            )
        # The C writer reserves names 0..4 before writing byte one.  A crash
        # while reserving can therefore leave only an exact empty name prefix;
        # a nonempty file before all five names exist is not a writer prefix.
        for filename in ordered_names[:prefix_length]:
            try:
                descriptor = os.open(
                    filename,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=result_dir,
                )
            except OSError as exc:
                raise NativeBoundaryV27Error(
                    "V27 native creator reservation no-follow open failed"
                ) from exc
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_gid != os.getegid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink != 1
                    or metadata.st_size != 0
                ):
                    raise NativeBoundaryV27Error(
                        "V27 native creator reservation prefix changed"
                    )
            finally:
                os.close(descriptor)
        result = {"status": "partial", "binding": None, "artifactDigests": []}
        return result if return_binding else "partial"
    artifact_digests: list[str] = []
    artifact_payloads: list[dict[str, Any]] = []
    common_binding: dict[str, Any] | None = None
    incomplete = False
    previous_digest: str | None = None
    for sequence, (filename, kind, predecessor_kind) in enumerate(
        _NATIVE_CREATOR_ARTIFACT_SPECS_V27
    ):
        try:
            descriptor = os.open(
                filename,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=result_dir,
            )
        except OSError as exc:
            raise NativeBoundaryV27Error(
                "V27 native creator artifact no-follow open failed"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_gid != os.getegid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or not 0 <= metadata.st_size <= 4096
            ):
                raise NativeBoundaryV27Error(
                    "V27 native creator artifact identity changed"
                )
            raw = _pread_exact_bounded_v27(
                descriptor, metadata.st_size, "native creator artifact"
            ) if metadata.st_size else b""
        finally:
            os.close(descriptor)
        if incomplete:
            if raw:
                raise NativeBoundaryV27Error(
                    "V27 native creator artifacts are reordered"
                )
            continue
        if not raw:
            incomplete = True
            continue
        try:
            envelope = _strict_probe_json(raw)
        except NativeBoundaryV27Error:
            if _is_native_creator_artifact_crash_prefix_v27(raw, kind, plan):
                incomplete = True
                continue
            raise
        if (
            set(envelope) != {"artifact", "artifactHmac"}
            or not isinstance(envelope["artifact"], Mapping)
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact envelope changed"
            )
        artifact = dict(envelope["artifact"])
        if (
            set(artifact) != set(_NATIVE_CREATOR_ARTIFACT_COMMON_FIELDS_V27)
            or artifact["artifactKind"] != kind
            or artifact["operationId"] != plan["operationId"]
            or artifact["predecessorKind"] != predecessor_kind
            or artifact["requestKeyId"] != plan["requestKeyId"]
            or artifact["schemaVersion"] != 27
            or artifact["sequence"] != sequence
            or artifact["stageLocation"] != plan["stageLocation"]
            or artifact["stagePlanSha256"] != plan["stagePlanSha256"]
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact binding changed"
            )
        predecessor_sha256 = str(artifact["predecessorSha256"])
        _digest(predecessor_sha256, "native creator artifact predecessor")
        if sequence == 0 and predecessor_sha256 != artifact[
            "capturePreparationRecordSha256"
        ]:
            raise NativeBoundaryV27Error(
                "V27 native capture predecessor lacks controller preparation"
            )
        if sequence > 0 and predecessor_sha256 != previous_digest:
            raise NativeBoundaryV27Error(
                "V27 native creator artifact predecessor changed"
            )
        artifact_raw = canonical_bytes(artifact)
        expected_hmac = "hmac-sha256:" + hmac.new(
            request_key,
            _NATIVE_CREATOR_ARTIFACT_DOMAIN_V27 + artifact_raw,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(str(envelope["artifactHmac"]), expected_hmac):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact HMAC changed"
            )
        artifact_payload = _validate_native_creator_artifact_payload_v27(
            sequence,
            artifact["payload"],
            artifact_digests,
            predecessor_sha256,
            str(artifact["capturePreparationSha256"]),
        )
        candidate_binding = {
            field: artifact[field]
            for field in (
                "capturePreparationRecordSha256",
                "capturePreparationSha256", "creationNonceSha256",
                "creatorHandleConsumed", "creatorReturnCurrentRecordSha256",
                "joinOwnerTokenSha256", "operationId", "requestKeyId",
                "returnAuthorizationRecordSha256", "returnSentinel",
                "slotGeneration", "stageLocation", "stagePlanSha256",
                "taskSetSha256",
            )
        }
        for digest_field in (
            "capturePreparationRecordSha256", "capturePreparationSha256",
            "creationNonceSha256", "creatorReturnCurrentRecordSha256",
            "joinOwnerTokenSha256", "requestKeyId",
            "returnAuthorizationRecordSha256", "stagePlanSha256",
            "taskSetSha256",
        ):
            _digest(candidate_binding[digest_field], digest_field)
        if (
            candidate_binding["creatorHandleConsumed"] is not True
            or candidate_binding["slotGeneration"] != 1
            or candidate_binding["returnSentinel"] not in {
                "creator-positive-sentinel", "creator-abort-sentinel"
            }
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact common semantics changed"
            )
        inner_common = {
            0: {
                "capturePreparationSha256": "capturePreparationSha256",
                "joinOwnerTokenSha256": "joinOwnerTokenSha256",
                "returnSentinel": "returnSentinel",
                "slotGeneration": "slotGeneration",
                "taskSetSha256": "taskSetSha256",
            },
            1: {
                "joinOwnerTokenSha256": "joinOwnerTokenSha256",
                "returnSentinel": "returnSentinel",
                "slotGeneration": "slotGeneration",
            },
            2: {
                "capturePreparationSha256": "capturePreparationSha256",
                "taskSetSha256": "taskSetSha256",
            },
            3: {"returnSentinel": "returnSentinel"},
            4: {},
        }[sequence]
        if any(
            artifact_payload[inner] != candidate_binding[outer]
            for inner, outer in inner_common.items()
        ):
            raise NativeBoundaryV27Error(
                "V27 native creator artifact inner/common binding changed"
            )
        if common_binding is None:
            common_binding = candidate_binding
        elif candidate_binding != common_binding:
            raise NativeBoundaryV27Error(
                "V27 native creator artifact semantic join changed"
            )
        previous_digest = sha256(raw)
        artifact_digests.append(previous_digest)
        artifact_payloads.append(artifact_payload)
    status = "partial" if incomplete else "complete"
    projection = None
    if status == "complete":
        if common_binding is None or len(artifact_payloads) != 5:
            raise NativeBoundaryV27Error(
                "V27 native creator artifact projection is incomplete"
            )
        projection = {
            **common_binding,
            "artifactDigests": list(artifact_digests),
            "atomicCapture": artifact_payloads[0],
            "joinResult": artifact_payloads[1],
            "postReturnObservation": artifact_payloads[2],
            "lifetime": artifact_payloads[3],
            "gateReleaseReceipt": artifact_payloads[4],
            "creatorIdentity": {
                "creatorTidPresent": True,
                "creatorTid": artifact_payloads[0]["creatorTid"],
                "creatorStartTicksPresent": True,
                "creatorStartTicks": artifact_payloads[0][
                    "creatorStartTicks"
                ],
            },
        }
    result = {
        "status": status,
        "binding": projection,
        "artifactDigests": artifact_digests,
    }
    return result if return_binding else status


def recover_durable_native_stage_result_v27(
    manifest: NativeBoundaryManifestV27,
    value: Any,
    request_key: bytes,
    *,
    runtime_root: Path | None = None,
) -> dict[str, Any]:
    """Authenticate an exact fsync-durable FD10 result without launching."""

    plan = validate_native_stage_action_plan_v27(value, manifest)
    if type(request_key) is not bytes or sha256(request_key) != plan["requestKeyId"]:
        raise NativeBoundaryV27Error(
            "V27 recovery request key differs from stage requestKeyId"
        )
    result_path = _native_stage_result_path_v27(plan, runtime_root=runtime_root)
    result_dir = lock_fd = -1
    try:
        result_dir = os.open(
            result_path,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        lock_fd = os.open(
            "operation.lock",
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=result_dir,
        )
        lock = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock.st_mode)
            or lock.st_uid != os.geteuid()
            or stat.S_IMODE(lock.st_mode) != 0o600
            or lock.st_nlink != 1
            or try_operation_lock_v27(lock_fd) != ("acquired", 0)
        ):
            raise NativeBoundaryV27Error(
                "V27 durable result recovery lock is unavailable"
            )
        _reopen_request_authenticated_result_arena_v27(
            result_dir, request_key, plan, lock
        )
        names = set(os.listdir(result_dir))
        allowed = {
            "operation.lock", "arena.json", ".arena.json.tmp",
            "result.json", ".result.json.tmp",
            "disposition.json", ".disposition.json.tmp", "evidence",
            "controller-retirement.intent.json",
            ".controller-retirement.intent.json.tmp",
            "controller-retirement.json",
            ".controller-retirement.json.tmp",
            "pre-effect-proof.json", ".pre-effect-proof.json.tmp",
            *_NATIVE_CREATOR_ARTIFACT_NAMES_V27,
        }
        if "operation.lock" not in names or not names.issubset(allowed):
            raise NativeBoundaryV27Error(
                "V27 durable result recovery directory has unexpected state"
            )
        native_creator_artifacts = _reopen_native_creator_artifacts_v27(
            result_dir, request_key, plan, names, return_binding=True
        )
        native_creator_artifact_state = native_creator_artifacts["status"]
        result_names = names & {"result.json", ".result.json.tmp"}
        disposition_names = names & {
            "disposition.json", ".disposition.json.tmp"
        }
        pre_effect_names = names & {
            "pre-effect-proof.json", ".pre-effect-proof.json.tmp"
        }
        if sum(bool(item) for item in (
            result_names, disposition_names, pre_effect_names
        )) > 1:
            raise NativeBoundaryV27Error(
                "V27 durable FD10 terminal XOR contains conflicting outcomes"
            )

        def recover_one(
            candidates: set[str], temporary_name: str, final_name: str,
            authenticate: Any,
        ) -> bool:
            if final_name in candidates and temporary_name in candidates:
                _promote_terminal_temporary_v27(
                    result_dir, temporary_name, final_name
                )
                return True
            if final_name in candidates:
                return True
            if temporary_name not in candidates:
                return False
            try:
                authenticate(temporary_name)
            except NativeBoundaryV27Error:
                # The holder is dead and no authenticated effect observation
                # exists.  Preserve the exact partial/tampered bytes and let
                # the consumed-current path install one loss quarantine CAS.
                return False
            _promote_terminal_temporary_v27(
                result_dir, temporary_name, final_name
            )
            return True

        result_ready = recover_one(
            result_names,
            ".result.json.tmp",
            "result.json",
            lambda filename: _reopen_authenticated_fd10_result_v27(
                result_dir,
                request_key,
                str(plan["requestKeyId"]),
                filename=filename,
            ),
        )
        disposition_ready = recover_one(
            disposition_names,
            ".disposition.json.tmp",
            "disposition.json",
            lambda filename: _reopen_authenticated_fd10_disposition_v27(
                result_dir,
                request_key,
                plan,
                lock,
                filename=filename,
            ),
        )
        pre_effect_ready = recover_one(
            pre_effect_names,
            ".pre-effect-proof.json.tmp",
            "pre-effect-proof.json",
            lambda filename: _reopen_controller_pre_effect_proof_for_relay_v27(
                result_dir, plan, filename=filename
            ),
        )
        rebound_names = set(os.listdir(result_dir))
        if not rebound_names.issubset(allowed):
            raise NativeBoundaryV27Error(
                "V27 durable result recovery directory changed under lock"
            )
        if result_ready and (
            "result.json" not in rebound_names
            or ".result.json.tmp" in rebound_names
        ):
            raise NativeBoundaryV27Error(
                "V27 durable result promotion did not rebind"
            )
        if disposition_ready and (
            "disposition.json" not in rebound_names
            or ".disposition.json.tmp" in rebound_names
        ):
            raise NativeBoundaryV27Error(
                "V27 durable disposition promotion did not rebind"
            )
        if pre_effect_ready and (
            "pre-effect-proof.json" not in rebound_names
            or ".pre-effect-proof.json.tmp" in rebound_names
        ):
            raise NativeBoundaryV27Error(
                "V27 durable pre-effect proof promotion did not rebind"
            )
        if disposition_ready:
            if native_creator_artifact_state != "absent":
                raise NativeBoundaryV27Error(
                    "V27 loss disposition conflicts with creator artifacts"
                )
            loss = _reopen_authenticated_fd10_disposition_v27(
                result_dir, request_key, plan, lock
            )
            loss["_controllerRetirementChain"] = (
                _reopen_controller_retirement_chain_for_relay_v27(result_dir)
            )
            return loss
        if pre_effect_ready:
            if native_creator_artifact_state != "absent":
                raise NativeBoundaryV27Error(
                    "V27 pre-effect proof conflicts with creator artifacts"
                )
            return {
                "nativeLaunchPreEffectProof": (
                    _reopen_controller_pre_effect_proof_for_relay_v27(
                        result_dir, plan
                    )
                ),
                "_controllerRetirementChain": (
                    _reopen_controller_retirement_chain_for_relay_v27(result_dir)
                ),
            }
        if not result_ready:
            loss = _native_supervisor_loss_v27(
                reason="dead-holder-without-terminal",
                evidence_sha256=sha256(
                    b"startup-factory/beads/v27/dead-holder-without-terminal\0"
                    + canonical_bytes(
                        {
                            "operationId": plan["operationId"],
                            "operationLock": _operation_lock_projection_v27(lock),
                            "requestKeyId": plan["requestKeyId"],
                            "stageLocation": plan["stageLocation"],
                            "stagePlanSha256": plan["stagePlanSha256"],
                        }
                    )
                ),
            )
            loss["_controllerRetirementChain"] = (
                _reopen_controller_retirement_chain_for_relay_v27(result_dir)
            )
            return loss
        _stored, result_raw = _reopen_authenticated_fd10_result_v27(
            result_dir, request_key, str(plan["requestKeyId"])
        )
        decoded = _decode_native_result_json_v27(result_raw)
        requires_creator_artifacts = decoded["resultKind"] in {
            "success", "revoke-verified-no-effect"
        }
        if (
            requires_creator_artifacts
            and native_creator_artifact_state != "complete"
        ) or (
            not requires_creator_artifacts
            and native_creator_artifact_state != "absent"
        ):
            raise NativeBoundaryV27Error(
                "V27 terminal result and native creator artifact chain differ"
            )
        if requires_creator_artifacts:
            expected_sentinel = (
                "creator-positive-sentinel"
                if decoded["resultKind"] == "success"
                else "creator-abort-sentinel"
            )
            if (
                native_creator_artifacts["binding"] is None
                or native_creator_artifacts["binding"]["returnSentinel"]
                != expected_sentinel
            ):
                raise NativeBoundaryV27Error(
                    "V27 terminal result and creator return sentinel differ"
                )
        decoded["_controllerRetirementChain"] = (
            _reopen_controller_retirement_chain_for_relay_v27(result_dir)
        )
        if requires_creator_artifacts:
            decoded["_nativeCreatorArtifactBinding"] = (
                native_creator_artifacts["binding"]
            )
        return decoded
    finally:
        for descriptor in (lock_fd, result_dir):
            if descriptor >= 0:
                os.close(descriptor)


def _open_durable_operation_lock_v27(
    result_dir: int, *, phase_hook: Any = None
) -> int:
    """Open the descriptor-pinned, policy-labelled FD5 operation lock."""

    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    hook = phase_hook if callable(phase_hook) else lambda _phase: None
    try:
        try:
            descriptor = os.open(
                "operation.lock",
                flags | os.O_EXCL,
                0o600,
                dir_fd=result_dir,
            )
            hook("result-arena:operation-lock-created")
        except FileExistsError:
            descriptor = os.open(
                "operation.lock",
                os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=result_dir,
            )
    except OSError as exc:
        raise NativeBoundaryV27Error(
            "V27 durable operation lock is unavailable"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise NativeBoundaryV27Error(
                "V27 durable operation lock identity changed"
            )
        if try_operation_lock_v27(descriptor) != ("acquired", 0):
            raise NativeBoundaryV27Error(
                "V27 durable operation lock did not acquire"
            )
        os.fsync(descriptor)
        hook("result-arena:operation-lock-fsynced")
        os.fsync(result_dir)
        hook("result-arena:directory-fsynced")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _production_supervisor_custody_v27(
    manifest: NativeBoundaryManifestV27,
    plan: Mapping[str, Any],
    plan_payload: bytes,
    request_key_bytes: bytes,
    cgroup_custody: Any,
    placement_mediator: Any,
    event_mediator: Any,
    result_offer_mediator: Any,
) -> tuple[subprocess.CompletedProcess[bytes], bytes]:
    """Launch through the native fixed-source trampoline; Python has no preexec."""

    if sha256(request_key_bytes) != plan["requestKeyId"]:
        raise NativeBoundaryV27Error(
            "V27 derived request key differs from stage requestKeyId"
        )
    key_fd, request_key = _sealed_request_key_descriptor_v27(request_key_bytes)
    try:
        plan_raw = _authenticated_native_plan_v27(plan_payload, bytes(request_key))
    finally:
        for index in range(len(request_key)):
            request_key[index] = 0
    plan_fd = _sealed_plan_descriptor_v27(plan_raw)
    controller_socket, child_socket = socket.socketpair(
        socket.AF_UNIX,
        socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0),
    )
    controller_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    child_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    if not hasattr(os, "pidfd_open"):
        raise NativeBoundaryV27Error("V27 fixed custody requires pidfd_open")
    controller_pidfd = os.pidfd_open(os.getpid(), 0)
    worker_cgroup = payload_cgroup = -1
    payload_events = payload_kill = -1
    result_path: Path | None = None
    result_dir = operation_lock = evidence_fd = launcher_fd = executable_fd = -1
    try:
        (
            worker_cgroup,
            payload_cgroup,
            payload_events,
            payload_kill,
        ) = _native_cgroup_descriptors_v27(
            cgroup_custody,
            plan,
        )
        runtime_root = Path(f"/run/user/{os.geteuid()}") / "startup-factory-beads-results"
        runtime_root.mkdir(mode=0o700, exist_ok=True)
        runtime_metadata = os.lstat(runtime_root)
        if (
            not stat.S_ISDIR(runtime_metadata.st_mode)
            or runtime_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(runtime_metadata.st_mode) != 0o700
        ):
            raise NativeBoundaryV27Error("V27 result root mode changed")
        result_path = _native_stage_result_path_v27(plan, runtime_root=runtime_root)
        result_preexisted = False
        try:
            result_path.mkdir(mode=0o700)
        except FileExistsError:
            result_preexisted = True
        result_dir = os.open(
            result_path,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0),
        )
        result_metadata = os.fstat(result_dir)
        result_link_metadata = os.lstat(result_path)
        if (
            not stat.S_ISDIR(result_metadata.st_mode)
            or result_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(result_metadata.st_mode) != 0o700
            or (result_metadata.st_dev, result_metadata.st_ino)
            != (result_link_metadata.st_dev, result_link_metadata.st_ino)
        ):
            raise NativeBoundaryV27Error(
                "V27 protected result directory identity changed"
            )
        operation_lock = _open_durable_operation_lock_v27(result_dir)
        result_names = set(os.listdir(result_dir))
        if "arena.json" not in result_names:
            raise NativeBoundaryV27Error(
                "V27 controller-authenticated result arena ACK is absent"
            )
        if result_names & {
            ".result.json.tmp", "disposition.json", ".disposition.json.tmp"
        }:
            raise NativeBoundaryV27Error(
                "V27 terminal half-state requires recovery and cannot relaunch"
            )
        if result_preexisted and "result.json" in result_names:
            stored_envelope, result_raw = _reopen_authenticated_fd10_result_v27(
                result_dir,
                request_key_bytes,
                str(plan["requestKeyId"]),
            )
            expected_evidence = hmac.new(
                request_key_bytes,
                b"startup-factory/beads/v27/evidence\0" + plan_raw[40:72],
                hashlib.sha256,
            ).digest()
            return (
                subprocess.CompletedProcess(
                    [str(manifest.launcher_path), "--startup-factory-launch-v27"],
                    0,
                    stdout=result_raw + b"\n",
                    stderr=b"",
                ),
                expected_evidence,
            )
        try:
            evidence_fd = os.open(
                "evidence",
                os.O_RDWR | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=result_dir,
            )
        except FileExistsError:
            evidence_fd = os.open(
                "evidence",
                os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=result_dir,
            )
            evidence_metadata = os.fstat(evidence_fd)
            if (
                not stat.S_ISREG(evidence_metadata.st_mode)
                or evidence_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(evidence_metadata.st_mode) != 0o600
                or evidence_metadata.st_nlink != 1
                or evidence_metadata.st_size != 0
            ):
                raise NativeBoundaryV27Error(
                    "V27 pre-execution evidence half-state changed"
                )
        launcher_fd = os.open(
            f"/proc/self/task/{threading.get_native_id()}/stat",
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        executable_fd = os.open(
            manifest.supervisor_path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        sources: dict[int, int] = {
            64: plan_fd,
            65: key_fd,
            66: operation_lock,
            67: controller_pidfd,
            68: worker_cgroup,
            69: payload_cgroup,
            70: controller_socket.fileno(),
            71: child_socket.fileno(),
            72: result_dir,
            73: launcher_fd,
            74: evidence_fd,
            75: executable_fd,
        }
        handshake_errors: list[BaseException] = []
        handshake_masks: list[int] = []
        handshake_threads: list[threading.Thread] = []
        def release_and_handshake(process: subprocess.Popen[bytes]) -> None:
            def run_handshake() -> None:
                try:
                    handshake_masks.append(_credentialed_supervisor_handshake_v27(
                        controller_socket,
                        process,
                        (payload_events, payload_kill),
                        placement_mediator,
                        event_mediator,
                        result_offer_mediator,
                        str(plan["stagePlanSha256"]),
                        request_key_bytes,
                    ))
                except BaseException as exc:
                    handshake_errors.append(exc)
                    try:
                        process.kill()
                    except OSError:
                        pass
            thread = threading.Thread(target=run_handshake, daemon=True)
            handshake_threads.append(thread)
            thread.start()

        try:
            _pre_popen_source_descriptor_preflight_v27(
                manifest.launcher_path, sources
            )
        except NativeBoundaryV27Error as exc:
            classification = {
                "classification": "pre-popen-descriptor-preflight-failed",
                "setupStep": "source-descriptor-preflight",
                "failureKind": "policy-rejection",
                "executablePathSha256": sha256(
                    str(manifest.launcher_path).encode("utf-8")
                ),
                "errno": None,
                "processCreated": False,
            }
            evidence_sha256 = sha256(
                b"startup-factory/beads/v27/launch-pre-effect-failed\0"
                + canonical_bytes(classification)
            )
            raise _NativeLaunchPreEffectFailedV27(
                evidence_sha256, classification
            ) from exc
        completed = _invoke_native_launcher_v27(
            manifest.launcher_path,
            sources,
            after_start=release_and_handshake,
        )
        for thread in handshake_threads:
            thread.join(timeout=1.0)
        if any(thread.is_alive() for thread in handshake_threads):
            raise NativeBoundaryV27Error("V27 placement mediator did not terminate")
        if handshake_errors:
            raise NativeBoundaryV27Error(
                f"V27 placement mediator failed: {handshake_errors[0]}"
            ) from handshake_errors[0]
        if len(handshake_masks) != 1:
            raise NativeBoundaryV27Error(
                "V27 placement mediator has no exact terminal mask"
            )
        os.lseek(evidence_fd, 0, os.SEEK_SET)
        evidence = os.read(evidence_fd, 4096)
        if len(evidence) != 32:
            raise NativeBoundaryV27Error(
                "V27 actual supervisor evidence HMAC has the wrong length"
            )
        key_material = bytearray(os.pread(key_fd, 32, 0))
        try:
            if len(key_material) != 32 or os.pread(key_fd, 1, 32) != b"":
                raise NativeBoundaryV27Error(
                    "V27 parent key custody changed before result verification"
                )
            expected_evidence = hmac.new(
                bytes(key_material),
                b"startup-factory/beads/v27/evidence\0" + plan_raw[40:72],
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(evidence, expected_evidence):
                raise NativeBoundaryV27Error(
                    "V27 supervisor evidence HMAC does not bind the plan commitment"
                )
            _stored_envelope, result_raw = _reopen_authenticated_fd10_result_v27(
                result_dir,
                bytes(key_material),
                str(plan["requestKeyId"]),
                expected_stdout=completed.stdout,
            )
            decoded_result = _strict_probe_json(result_raw)
            if (
                decoded_result.get("placementMask") != handshake_masks[0]
                or not _placement_mask_matches_result_v27(
                    handshake_masks[0], decoded_result.get("resultKind")
                )
            ):
                raise NativeBoundaryV27Error(
                    "V27 durable lifecycle placement result changed"
                )
        finally:
            for index in range(len(key_material)):
                key_material[index] = 0
        completed = subprocess.CompletedProcess(
            completed.args,
            completed.returncode,
            stdout=result_raw + b"\n",
            stderr=completed.stderr,
        )
        return completed, evidence
    finally:
        controller_socket.close()
        child_socket.close()
        for descriptor in (
            plan_fd,
            key_fd,
            controller_pidfd,
            worker_cgroup,
            payload_cgroup,
            payload_events,
            payload_kill,
            result_dir,
            operation_lock,
            evidence_fd,
            launcher_fd,
            executable_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        # FD10 evidence is deliberately retained.  Stage suffix recovery must
        # reopen these exact bytes; deleting here would turn a process death
        # between FD10 fsync and StageActionResult publication into ambiguity.


def _encode_native_stage_plan_v27(plan: Mapping[str, Any]) -> bytes:
    fields = (
        str(plan["operationId"]),
        str(plan["effectPlanSha256"]),
        str(plan["stagePlanSha256"]),
        str(plan["stageLocation"]),
        str(plan["stageKey"]),
        str(plan["stageKind"]),
        str(plan["actionKind"]),
        str(plan["imageReference"]),
        str(plan["repositoryPath"]),
        sha256(canonical_bytes(plan["repositoryCustody"])),
    )
    encoded = bytearray(b"SFV27P2\0")
    for field in fields:
        raw = field.encode("utf-8")
        encoded.extend(struct.pack("!I", len(raw)))
        encoded.extend(raw)
    encoded.extend(struct.pack("!I", len(plan["argv"])))
    for item in plan["argv"]:
        raw = str(item).encode("utf-8")
        encoded.extend(struct.pack("!I", len(raw)))
        encoded.extend(raw)
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise NativeBoundaryV27Error("native V27 stage binary plan is oversized")
    return bytes(encoded)


def _authenticated_native_plan_v27(payload: bytes, key: bytes) -> bytes:
    if len(key) != 32 or not payload or len(payload) > MAX_CANONICAL_BYTES:
        raise NativeBoundaryV27Error("native V27 plan HMAC input is invalid")
    return b"".join(
        (
            b"SFV27A1\0",
            hashlib.sha256(key).digest(),
            hmac.new(
                key,
                b"startup-factory/beads/v27/plan\0" + payload,
                hashlib.sha256,
            ).digest(),
            struct.pack("!I", len(payload)),
            payload,
        )
    )


def run_native_stage_action_v27(
    manifest: NativeBoundaryManifestV27,
    value: Any,
    *,
    process_runner: Any = None,
    cgroup_custody: Any = None,
    placement_mediator: Any = None,
    event_mediator: Any = None,
    result_offer_mediator: Any = None,
) -> dict[str, Any]:
    plan = validate_native_stage_action_plan_v27(value, manifest)
    plan_raw = _encode_native_stage_plan_v27(plan)
    production_runner = process_runner is None
    if production_runner:
        if not callable(placement_mediator):
            raise NativeBoundaryV27Error(
                "native V27 production stage lacks controller placement mediation"
            )
        if not callable(event_mediator):
            raise NativeBoundaryV27Error(
                "native V27 production stage lacks controller event mediation"
            )
        if not callable(result_offer_mediator):
            raise NativeBoundaryV27Error(
                "native V27 production stage lacks controller result-offer mediation"
            )
        request_key = _NATIVE_REQUEST_KEY_V27.get()
        if request_key is None or sha256(request_key) != plan["requestKeyId"]:
            raise NativeBoundaryV27Error(
                "native V27 stage lacks the retained derived request key"
            )
        completed, _evidence = _production_supervisor_custody_v27(
            manifest,
            plan,
            plan_raw,
            request_key,
            cgroup_custody,
            placement_mediator,
            event_mediator,
            result_offer_mediator,
        )
    else:
        handle = tempfile.TemporaryFile()
        try:
            handle.write(plan_raw)
            handle.flush()
            handle.seek(0)
            descriptor = handle.fileno()
            argv = [str(manifest.supervisor_path), "--startup-factory-execute-v27"]
            completed = process_runner(
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/",
                env=_fixed_worker_environment_v27(),
                timeout=120,
                check=False,
                pass_fds=(descriptor,),
                preexec_fn=lambda: os.dup2(descriptor, 3),
            )
        finally:
            handle.close()
    if completed.returncode != 0:
        raise NativeBoundaryV27Error(
            f"native V27 stage supervisor failed rc={completed.returncode}"
        )
    return _decode_native_result_json_v27(completed.stdout)


INTERNAL_SCHEMA_NAMES: Final = tuple(dict.fromkeys((
    "DescriptorPinnedReadBackPlanV27",
    "NativeStageActionPlanV27",
    "PreparationSequenceOperationV27",
    "StageActionReceiptV1",
    "StageActionResultV1",
    "NativeOuterEventIntentV1",
    "NativeCreatorCreationIntentV1",
    "NativeCreatorPreCreateFailureV2",
    "NativeCreatorCreationReceiptV1",
    "NativeCreatorJoinOwnershipReceiptV1",
    "CreatorAbortWakeDecisionV1",
    "CreatorAbortWakeAttemptV1",
    "CreatorAbortWakeReturnV1",
    "CreatorAbortWakeReceiptV1",
    "CreatorAbortJoinAttemptV1",
    "CreatorAbortJoinReturnV1",
    "CreatorAbortJoinReceiptV1",
    "NativePostReturnCapturePreparationV1",
    "NativePostReturnAtomicCaptureV1",
    "CreatorJoinResultV2",
    "CreatorPostReturnObservationV2",
    "CreatorThreadLifetimeReceiptV4",
    "AdmittedOuterRecoveryClosureV1",
    "SupervisorLaunchPreEffectProofV1",
    "ParentChildSocketSourceCloseReceiptV1",
    "SELinuxRawContextExpectationV1",
    "SupervisorResultEnvelopeV4",
    "SupervisorTerminalCurrentV3",
    "RecoveryOperationLockAttemptV6",
    "PriorRecoveryAttemptPrefixV2",
    "PriorRecoveryAttemptResultV3",
    "OldRecoveryAttemptInertReceiptV2",
    "SupervisorLaunchPreEffectFailedCurrentV1",
    "SupervisorLaunchSlotReservedCurrentV1",
    "SupervisorLaunchSlotConsumedCurrentV1",
    "SupervisorRunningCurrentV1",
    "SupervisorRunAuthorizationConsumedCurrentV1",
    "SupervisorRunAcknowledgedCurrentV1",
    "NativeCreatorCreationConsumedCurrentV1",
    "SupervisorPreCreateFailedCurrentV1",
    "SupervisorCreateFailedNoThreadCurrentV1",
    "NativeCreatorCreatedCurrentV1",
    "CreatorLifetimeClosedCurrentV5",
    "SupervisorResultEnvelopeStoredCurrentV4",
    "SupervisorResultHandoffAttemptConsumedCurrentV4",
    "SupervisorResultHandoffReceiptedCurrentV4",
    "SupervisorTerminalReceiptStoredCurrentV4",
    "SupervisorOuterLossDrainPendingCurrentV5",
    "SupervisorOuterLossQuarantinedCurrentV4",
) + CURRENT_UNION_V27))


def internal_schema_fixture_v27() -> bytes:
    return canonical_bytes(
        {
            "schemaVersion": 27,
            "profile": PROFILE,
            "internalSchemas": sorted(INTERNAL_SCHEMA_NAMES),
            "publicSurface": {"types": 92, "exports": 33, "controllerOperations": 30},
            "versions": {
                "systemd": SYSTEMD_VERSION,
                "podman": PODMAN_VERSION,
                "conmon": CONMON_VERSION,
            },
            "launchPlan": reference_launch_plan_v27(),
            "operationLock": operation_lock_contract_v27(),
            "hmacDomains": {
                name: domain[:-1].decode("ascii") + "\\0"
                for name, domain in HMAC_DOMAINS_V27.items()
            },
            "currentUnionV27": list(CURRENT_UNION_V27),
            "doneCurrents": {
                "claim-cas": 76,
                "ordinary": 76,
                "receipt-comment": 77,
                "create-preparation": 63,
                "reattest-preparation": 24,
            },
            "incompleteLocations": {
                "claim-cas": [70, 75],
                "ordinary": [70, 75],
                "receipt-comment": [70, 76],
                "create-preparation": [53, 62],
                "reattest-preparation": [14, 23],
            },
            "resultKinds": sorted(_RESULT_KINDS),
            "recoveryKinds": [
                "nonacquired-clean-closed",
                "acquired-clean-closed",
                "lost-before-call-result",
                "lost-after-nonacquired-result",
                "lost-after-acquired-result-before-acquisition",
                "acquired-holder-lost",
            ],
        }
    )


# Intentionally no public re-export surface.
__all__: tuple[str, ...] = ()
